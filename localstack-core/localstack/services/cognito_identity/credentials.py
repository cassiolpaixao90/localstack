import base64
import copy
import dataclasses
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from datetime import datetime
from typing import Any
from urllib.parse import unquote

from moto.iam.models import iam_backends
from moto.sts.models import sts_backends

from localstack.services.sts.models import sts_stores

_CREDENTIALS_LOCK = threading.RLock()
_INTERNAL_TOKEN_SECRET = secrets.token_bytes(32)
_MAX_INTERNAL_TOKEN_BYTES = 4_096
_INTERNAL_TOKEN_TTL_SECONDS = 60
_MAX_TRUST_POLICY_BYTES = 16_384
_MAX_PRINCIPAL_TAGS = 50
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CredentialIssueError(ValueError):
    """Raised when the enhanced-flow trust boundary cannot be satisfied."""


@dataclasses.dataclass(frozen=True)
class IssuedCredentials:
    access_key_id: str
    secret_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str
    role_id: str


def issue_enhanced_flow_credentials(
    *,
    account_id: str,
    region: str,
    partition: str,
    role_arn: str,
    identity_pool_id: str,
    identity_id: str,
    amr: str,
    provider_names: list[str],
    principal_tags: dict[str, str] | None = None,
) -> IssuedCredentials:
    """Validate one role and issue a registered Moto STS session without network I/O."""
    if amr not in {"authenticated", "unauthenticated"}:
        raise CredentialIssueError("Invalid authentication method")
    if len(provider_names) > 10 or any(
        not isinstance(name, str) or not 1 <= len(name) <= 128 for name in provider_names
    ):
        raise CredentialIssueError("Invalid login providers")
    principal_tags = _principal_tags(principal_tags)

    with _CREDENTIALS_LOCK:
        iam_backend = iam_backends[account_id][partition]
        role = _resolve_role(iam_backend, role_arn, account_id, partition)
        role_id = role.id
        policy_document = copy.deepcopy(role.assume_role_policy_document)
        _validate_trust_policy(policy_document, identity_pool_id, amr)

        token = _internal_web_identity_token(
            audience=identity_pool_id,
            amr=amr,
            subject=identity_id,
            provider_names=provider_names,
            principal_tags=principal_tags,
        )
        _assert_same_role(
            iam_backend,
            role_arn=role_arn,
            role_id=role_id,
            policy_document=policy_document,
        )
        existing_access_keys = dict(iam_backend.access_keys)
        role_session_name = _role_session_name(identity_id)
        assumed_role = _assume_role_with_internal_token(
            token=token,
            account_id=account_id,
            region=region,
            partition=partition,
            role_arn=role_arn,
            role_session_name=role_session_name,
            expected_audience=identity_pool_id,
            expected_amr=amr,
            expected_subject=identity_id,
            expected_provider_names=provider_names,
            expected_principal_tags=principal_tags,
        )
        expected_assumed_role_arn = (
            f"arn:{partition}:sts::{account_id}:assumed-role/"
            f"{role_arn.rsplit('/', 1)[1]}/{role_session_name}"
        )
        if (
            assumed_role.access_key_id in existing_access_keys
            or assumed_role.account_id != account_id
            or assumed_role.arn != expected_assumed_role_arn
        ):
            revoke_sts_credentials(
                account_id=account_id,
                partition=partition,
                access_key_id=assumed_role.access_key_id,
            )
            if previous_key := existing_access_keys.get(assumed_role.access_key_id):
                iam_backend.access_keys[assumed_role.access_key_id] = previous_key
            raise CredentialIssueError("STS returned an inconsistent credential session")
        try:
            _assert_same_role(
                iam_backend,
                role_arn=role_arn,
                role_id=role_id,
                policy_document=policy_document,
            )
        except CredentialIssueError:
            revoke_sts_credentials(
                account_id=account_id,
                partition=partition,
                access_key_id=assumed_role.access_key_id,
            )
            raise
        if principal_tags:
            sts_stores[account_id][region].sessions[assumed_role.access_key_id] = {
                "iam_context": {},
                "tags": {
                    key.lower(): {"Key": key, "Value": value}
                    for key, value in principal_tags.items()
                },
                "transitive_tags": [],
            }
        return IssuedCredentials(
            access_key_id=assumed_role.access_key_id,
            secret_key=assumed_role.secret_access_key,
            session_token=assumed_role.session_token,
            expiration=assumed_role.expiration,
            assumed_role_arn=assumed_role.arn,
            role_id=role_id,
        )


def revoke_sts_credentials(*, account_id: str, partition: str, access_key_id: str) -> None:
    """Revoke one locally-issued temporary credential without exposing its secret."""
    if not isinstance(access_key_id, str) or not access_key_id:
        return
    with _CREDENTIALS_LOCK:
        iam_backends[account_id][partition].access_keys.pop(access_key_id, None)
        backend = sts_backends[account_id][partition]
        backend.assumed_roles[:] = [
            role for role in backend.assumed_roles if role.access_key_id != access_key_id
        ]
        bundle = sts_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                store.sessions.pop(access_key_id, None)


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


def _internal_web_identity_token(
    *,
    audience: str,
    amr: str,
    subject: str,
    provider_names: list[str],
    principal_tags: dict[str, str],
) -> str:
    now = int(time.time())
    claims = {
        "amr": amr,
        "aud": audience,
        "exp": now + _INTERNAL_TOKEN_TTL_SECONDS,
        "iat": now,
        "nonce": secrets.token_urlsafe(16),
        "provider": sorted(provider_names),
        "principal_tags": principal_tags,
        "sub": subject,
        "v": 1,
    }
    payload = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signature = _b64url(hmac.digest(_INTERNAL_TOKEN_SECRET, payload.encode(), hashlib.sha256))
    token = f"{payload}.{signature}"
    if len(token) > _MAX_INTERNAL_TOKEN_BYTES:
        raise CredentialIssueError("Internal web identity token is too large")
    return token


def _assume_role_with_internal_token(
    *,
    token: str,
    account_id: str,
    region: str,
    partition: str,
    role_arn: str,
    role_session_name: str,
    expected_audience: str,
    expected_amr: str,
    expected_subject: str,
    expected_provider_names: list[str],
    expected_principal_tags: dict[str, str],
):
    claims = _verified_internal_token(token)
    expected = {
        "amr": expected_amr,
        "aud": expected_audience,
        "provider": sorted(expected_provider_names),
        "principal_tags": expected_principal_tags,
        "sub": expected_subject,
    }
    if any(claims.get(key) != value for key, value in expected.items()):
        raise CredentialIssueError("Internal web identity token is not bound to this request")
    backend = sts_backends[account_id][partition]
    return backend.assume_role_with_web_identity(
        region_name=region,
        role_session_name=role_session_name,
        role_arn=role_arn,
        policy=None,
        duration=3_600,
        external_id=None,
    )


def _verified_internal_token(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or not 1 <= len(token) <= _MAX_INTERNAL_TOKEN_BYTES:
        raise CredentialIssueError("Invalid internal web identity token")
    parts = token.split(".")
    if len(parts) != 2 or any(_B64URL_RE.fullmatch(part) is None for part in parts):
        raise CredentialIssueError("Invalid internal web identity token")
    payload, provided_signature = parts
    expected_signature = _b64url(
        hmac.digest(_INTERNAL_TOKEN_SECRET, payload.encode(), hashlib.sha256)
    )
    if not hmac.compare_digest(provided_signature, expected_signature):
        raise CredentialIssueError("Invalid internal web identity token signature")
    try:
        claims = json.loads(_b64url_decode(payload), object_pairs_hook=_reject_duplicate_json_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise CredentialIssueError("Invalid internal web identity token") from error
    now = int(time.time())
    if (
        not isinstance(claims, dict)
        or set(claims)
        != {"amr", "aud", "exp", "iat", "nonce", "principal_tags", "provider", "sub", "v"}
        or claims.get("v") != 1
        or not _integer(claims.get("iat"))
        or not _integer(claims.get("exp"))
        or claims["iat"] > now
        or claims["exp"] <= now
        or claims["exp"] - claims["iat"] > _INTERNAL_TOKEN_TTL_SECONDS
        or not isinstance(claims.get("nonce"), str)
        or not 16 <= len(claims["nonce"]) <= 128
    ):
        raise CredentialIssueError("Invalid internal web identity token claims")
    _principal_tags(claims["principal_tags"])
    return claims


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


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _role_session_name(identity_id: str) -> str:
    value = identity_id.replace(":", "-")
    if not 2 <= len(value) <= 64 or re.fullmatch(r"[A-Za-z0-9_+=,.@-]+", value) is None:
        raise CredentialIssueError("Identity cannot be represented as an STS session")
    return value


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result
