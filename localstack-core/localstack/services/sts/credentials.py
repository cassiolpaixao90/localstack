import base64
import copy
import dataclasses
import hashlib
import json
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from moto.iam.models import iam_backends

from localstack.aws.accounts import (
    ACCOUNT_OFFSET,
    AWS_ACCESS_KEY_ALPHABET,
    extract_account_id_from_access_key_id,
)
from localstack.services.sts.models import CredentialSession, SessionConfig, sts_stores

_CREDENTIALS_LOCK = threading.RLock()
_MAX_TRUST_POLICY_BYTES = 16_384
_MAX_PRINCIPAL_TAGS = 50
_MAX_WEB_IDENTITY_TOKEN_BYTES = 50_000
_MIN_DURATION_SECONDS = 900
_MAX_DURATION_SECONDS = 43_200
DEFAULT_DURATION_SECONDS = 3_600
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ROLE_SESSION_NAME_RE = re.compile(r"^[\w+=,.@-]{2,64}$")
_SECRET_ACCESS_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+="
_SESSION_TOKEN_BYTES = 192


class CredentialIssueError(ValueError):
    """Raised when the trust boundary for issuing a role session cannot be satisfied."""


@dataclasses.dataclass(frozen=True)
class IssuedSession:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str
    assumed_role_id: str
    role_id: str


@dataclasses.dataclass(frozen=True)
class WebIdentityClaims:
    pool_id: str
    pool_account_id: str
    pool_region: str
    issuer: str
    subject: str
    authenticated: bool
    provider_names: tuple[str, ...]
    principal_tags: dict[str, str]


def issue_role_session(
    *,
    account_id: str,
    region: str,
    partition: str,
    role_arn: str,
    role_session_name: str,
    duration_seconds: int = DEFAULT_DURATION_SECONDS,
    principal_tags: dict[str, str] | None = None,
    provider_name: str | None = None,
    subject: str | None = None,
) -> IssuedSession:
    """Issue one natively registered temporary role session without network I/O."""
    if not isinstance(account_id, str) or _ACCOUNT_ID_RE.fullmatch(account_id) is None:
        raise CredentialIssueError("Invalid account id")
    if (
        not isinstance(duration_seconds, int)
        or isinstance(duration_seconds, bool)
        or not _MIN_DURATION_SECONDS <= duration_seconds <= _MAX_DURATION_SECONDS
    ):
        raise CredentialIssueError("Invalid session duration")
    if (
        not isinstance(role_session_name, str)
        or _ROLE_SESSION_NAME_RE.fullmatch(role_session_name) is None
    ):
        raise CredentialIssueError("Invalid role session name")
    principal_tags = _principal_tags(principal_tags)

    with _CREDENTIALS_LOCK:
        iam_backend = iam_backends[account_id][partition]
        role = _resolve_role(iam_backend, role_arn, account_id, partition)
        role_id = role.id
        policy_document = copy.deepcopy(role.assume_role_policy_document)
        _assert_same_role(
            iam_backend, role_arn=role_arn, role_id=role_id, policy_document=policy_document
        )

        access_key_id = _generate_access_key_id(account_id)
        secret_access_key = "".join(secrets.choice(_SECRET_ACCESS_KEY_ALPHABET) for _ in range(40))
        session_token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
        expiration = datetime.now(UTC) + timedelta(seconds=duration_seconds)
        role_name = role_arn.rsplit("/", 1)[1]
        assumed_role_arn = (
            f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/{role_session_name}"
        )
        assumed_role_id = f"{role_id}:{role_session_name}"
        store = sts_stores[account_id][region]
        store.credential_sessions[access_key_id] = CredentialSession(
            access_key_id=access_key_id,
            secret_access_key_hash=_sha256(secret_access_key),
            session_token_hash=_sha256(session_token),
            expiration=expiration,
            role_arn=role_arn,
            assumed_role_arn=assumed_role_arn,
            assumed_role_id=assumed_role_id,
            account_id=account_id,
            partition=partition,
            principal_tags=dict(principal_tags),
            provider_name=provider_name,
            subject=subject,
        )
        if principal_tags:
            store.sessions[access_key_id] = SessionConfig(
                iam_context={},
                tags={
                    key.lower(): {"Key": key, "Value": value}
                    for key, value in principal_tags.items()
                },
                transitive_tags=[],
            )
        try:
            _assert_same_role(
                iam_backend, role_arn=role_arn, role_id=role_id, policy_document=policy_document
            )
        except CredentialIssueError:
            store.credential_sessions.pop(access_key_id, None)
            store.sessions.pop(access_key_id, None)
            raise
        return IssuedSession(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
            assumed_role_arn=assumed_role_arn,
            assumed_role_id=assumed_role_id,
            role_id=role_id,
        )


def revoke_role_session(access_key_id: str, *, account_id: str | None = None) -> None:
    """Revoke one natively issued temporary credential without exposing its secret."""
    if not isinstance(access_key_id, str) or not access_key_id:
        return
    if account_id is None:
        account_id = _account_id_from_key(access_key_id)
        if account_id is None:
            return
    with _CREDENTIALS_LOCK:
        bundle = sts_stores.get(account_id)
        if bundle is None:
            return
        for store in bundle.values():
            store.credential_sessions.pop(access_key_id, None)
            store.sessions.pop(access_key_id, None)


def resolve_session(
    access_key_id: str,
    *,
    account_id: str | None = None,
    region: str | None = None,
    now: datetime | None = None,
) -> CredentialSession | None:
    """Return the registered session for one access key, pruning it when expired."""
    if not isinstance(access_key_id, str) or not access_key_id:
        return None
    if account_id is None:
        account_id = _account_id_from_key(access_key_id)
        if account_id is None:
            return None
    bundle = sts_stores.get(account_id)
    if bundle is None:
        return None
    store = bundle.get(region) if region else None
    if store is None:
        store = next(iter(bundle.values()), None)
    if store is None:
        return None
    with _CREDENTIALS_LOCK:
        session = store.credential_sessions.get(access_key_id)
        if session is None:
            return None
        current = datetime.now(UTC) if now is None else now
        if _expiration_timestamp(session.expiration) <= _expiration_timestamp(current):
            store.credential_sessions.pop(access_key_id, None)
            store.sessions.pop(access_key_id, None)
            return None
        return session


def verify_web_identity_token(token: str, *, partition: str) -> WebIdentityClaims:
    """Verify an OpenID token issued by a local Cognito Identity pool, failing closed."""
    # imported lazily so the STS service does not depend on Cognito Identity at load time
    from localstack.services.cognito_identity.models import (
        cognito_identity_stores,
        resolve_pool_location,
    )
    from localstack.services.cognito_identity.openid import (
        OpenIdTokenError,
        decode_unverified_claims,
        identity_issuer,
        verify_pool_open_id_token,
    )

    if not isinstance(token, str) or not 1 <= len(token) <= _MAX_WEB_IDENTITY_TOKEN_BYTES:
        raise CredentialIssueError("Invalid web identity token")
    try:
        unverified = decode_unverified_claims(token)
    except OpenIdTokenError as error:
        raise CredentialIssueError("Invalid web identity token") from error
    pool_id = unverified.get("aud")
    issuer = unverified.get("iss")
    if not isinstance(pool_id, str) or not isinstance(issuer, str):
        raise CredentialIssueError("Invalid web identity token claims")
    location = resolve_pool_location(pool_id)
    if location is None:
        raise CredentialIssueError("Web identity token issuer is not a local identity pool")
    pool_account_id, pool_region = location
    try:
        if issuer != identity_issuer(partition, pool_region):
            raise CredentialIssueError("Web identity token issuer is not trusted")
    except OpenIdTokenError as error:
        raise CredentialIssueError("Web identity token issuer is not trusted") from error
    with cognito_identity_stores.lock:
        bundle = cognito_identity_stores.get(pool_account_id)
        store = bundle.get(pool_region) if bundle is not None else None
    if store is None:
        raise CredentialIssueError("Web identity token issuer is not a local identity pool")
    try:
        claims = verify_pool_open_id_token(
            store,
            token=token,
            partition=partition,
            region=pool_region,
            pool_id=pool_id,
        )
    except OpenIdTokenError as error:
        raise CredentialIssueError("Invalid web identity token") from error
    amr = claims["amr"]
    return WebIdentityClaims(
        pool_id=pool_id,
        pool_account_id=pool_account_id,
        pool_region=pool_region,
        issuer=issuer,
        subject=claims["sub"],
        authenticated=amr[0] == "authenticated",
        provider_names=tuple(amr[1:]),
        principal_tags=dict(claims.get("principal_tags") or {}),
    )


def _generate_access_key_id(account_id: str) -> str:
    """Generate an LSIA access key embedding the account id.

    Inverse of `extract_account_id_from_access_key_id`: the account id is encoded
    base32 with `ACCOUNT_OFFSET`, and char 12 carries the parity bit.
    """
    account = int(account_id)
    account_id_part = (account // 2 + ACCOUNT_OFFSET).to_bytes(5, byteorder="big")
    encoded = base64.b32encode(account_id_part).decode()
    parity_offset = 16 if account % 2 else 0
    parity_char = AWS_ACCESS_KEY_ALPHABET[parity_offset + secrets.randbelow(16)]
    suffix = "".join(secrets.choice(AWS_ACCESS_KEY_ALPHABET) for _ in range(7))
    return f"LSIA{encoded}{parity_char}{suffix}"


def _account_id_from_key(access_key_id: str) -> str | None:
    if len(access_key_id) < 20 or not (
        access_key_id.startswith("LSIA") or access_key_id.startswith("LKIA")
    ):
        return None
    return extract_account_id_from_access_key_id(access_key_id)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _expiration_timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def _resolve_role(iam_backend, role_arn: str, account_id: str, partition: str):
    prefix = f"arn:{partition}:iam::{account_id}:role/"
    if not isinstance(role_arn, str) or not role_arn.startswith(prefix):
        raise CredentialIssueError("Role is outside the identity-pool account")
    try:
        role = iam_backend.get_role_by_arn(role_arn)
    except Exception as error:
        raise CredentialIssueError("Configured role does not exist") from error
    if role.arn != role_arn or role.account_id != account_id or role.partition != partition:
        raise CredentialIssueError("Configured role does not match")
    return role


def _assert_same_role(
    iam_backend, *, role_arn: str, role_id: str, policy_document: str | dict[str, Any]
) -> None:
    try:
        current = iam_backend.get_role_by_arn(role_arn)
    except Exception as error:
        raise CredentialIssueError("Configured role changed during issuance") from error
    if current.id != role_id or current.assume_role_policy_document != policy_document:
        raise CredentialIssueError("Configured role changed during issuance")


def _validate_trust_policy(value: Any, pool_id: str, amr: str) -> None:
    policy = _policy_document(value)
    if set(policy) - {"Statement", "Version"}:
        raise CredentialIssueError("Unsupported trust policy fields")
    if policy.get("Version", "2008-10-17") not in {"2008-10-17", "2012-10-17"}:
        raise CredentialIssueError("Unsupported trust policy version")
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or len(statements) != 1:
        raise CredentialIssueError("Trust policy must contain one bounded statement")
    statement = statements[0]
    if not isinstance(statement, dict) or set(statement) - {
        "Action",
        "Condition",
        "Effect",
        "Principal",
        "Sid",
    }:
        raise CredentialIssueError("Invalid trust statement")
    if statement.get("Effect") != "Allow":
        raise CredentialIssueError("Trust statement must allow the enhanced flow")
    if "Sid" in statement and (
        not isinstance(statement["Sid"], str) or not 1 <= len(statement["Sid"]) <= 128
    ):
        raise CredentialIssueError("Invalid trust statement identifier")
    if _singleton(statement.get("Action")) != "sts:AssumeRoleWithWebIdentity":
        raise CredentialIssueError("Invalid trust action")
    principal = statement.get("Principal")
    if (
        not isinstance(principal, dict)
        or set(principal) != {"Federated"}
        or _singleton(principal.get("Federated")) != "cognito-identity.amazonaws.com"
    ):
        raise CredentialIssueError("Invalid federated principal")
    condition = statement.get("Condition")
    if not isinstance(condition, dict) or set(condition) not in (
        {"StringEquals", "ForAnyValue:StringLike"},
        {"StringEquals", "ForAnyValue:StringEquals"},
    ):
        raise CredentialIssueError("Invalid trust conditions")
    audience = condition.get("StringEquals")
    if (
        not isinstance(audience, dict)
        or set(audience) != {"cognito-identity.amazonaws.com:aud"}
        or _singleton(audience.get("cognito-identity.amazonaws.com:aud")) != pool_id
    ):
        raise CredentialIssueError("Trust audience does not match the identity pool")
    amr_operator = (
        "ForAnyValue:StringLike"
        if "ForAnyValue:StringLike" in condition
        else "ForAnyValue:StringEquals"
    )
    auth_method = condition.get(amr_operator)
    if (
        not isinstance(auth_method, dict)
        or set(auth_method) != {"cognito-identity.amazonaws.com:amr"}
        or _singleton(auth_method.get("cognito-identity.amazonaws.com:amr")) != amr
    ):
        raise CredentialIssueError("Trust authentication method does not match")


def _policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not 2 <= len(value) <= _MAX_TRUST_POLICY_BYTES:
        raise CredentialIssueError("Invalid trust policy")
    try:
        decoded = unquote(value)
        policy = json.loads(decoded, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as error:
        raise CredentialIssueError("Invalid trust policy") from error
    if not isinstance(policy, dict):
        raise CredentialIssueError("Invalid trust policy")
    return policy


def _singleton(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if len(value) == 1 else None
    return value


def _principal_tags(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > _MAX_PRINCIPAL_TAGS:
        raise CredentialIssueError("Invalid principal tags")
    result: dict[str, str] = {}
    seen_keys: set[str] = set()
    for key, tag_value in value.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(tag_value, str)
            or not 1 <= len(tag_value) <= 256
            or key.lower() in seen_keys
        ):
            raise CredentialIssueError("Invalid principal tags")
        seen_keys.add(key.lower())
        result[key] = tag_value
    return dict(sorted(result.items()))


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result
