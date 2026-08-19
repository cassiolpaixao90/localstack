import copy
import dataclasses
import re
import threading
from datetime import datetime

from moto.iam.models import iam_backends
from moto.sts.models import sts_backends

from localstack.services.sts.credentials import (
    CredentialIssueError,
    _assert_same_role,
    _principal_tags,
    _resolve_role,
    _validate_trust_policy,
    issue_role_session,
    revoke_role_session,
)

_CREDENTIALS_LOCK = threading.RLock()


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
    """Validate one role and issue a registered native STS session without network I/O."""
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
        _assert_same_role(
            iam_backend, role_arn=role_arn, role_id=role_id, policy_document=policy_document
        )
        session = issue_role_session(
            account_id=account_id,
            region=region,
            partition=partition,
            role_arn=role_arn,
            role_session_name=_role_session_name(identity_id),
            principal_tags=principal_tags,
            provider_name="cognito-identity.amazonaws.com",
            subject=identity_id,
        )
        try:
            _assert_same_role(
                iam_backend, role_arn=role_arn, role_id=role_id, policy_document=policy_document
            )
        except CredentialIssueError:
            revoke_role_session(session.access_key_id, account_id=account_id)
            raise
        return IssuedCredentials(
            access_key_id=session.access_key_id,
            secret_key=session.secret_access_key,
            session_token=session.session_token,
            expiration=session.expiration,
            assumed_role_arn=session.assumed_role_arn,
            role_id=role_id,
        )


def revoke_sts_credentials(*, account_id: str, partition: str, access_key_id: str) -> None:
    """Revoke one locally-issued temporary credential without exposing its secret."""
    if not isinstance(access_key_id, str) or not access_key_id:
        return
    with _CREDENTIALS_LOCK:
        # drop Moto leftovers of sessions issued before native issuance existed
        iam_backends[account_id][partition].access_keys.pop(access_key_id, None)
        backend = sts_backends[account_id][partition]
        backend.assumed_roles[:] = [
            role for role in backend.assumed_roles if role.access_key_id != access_key_id
        ]
    revoke_role_session(access_key_id, account_id=account_id)


def _role_session_name(identity_id: str) -> str:
    value = identity_id.replace(":", "-")
    if not 2 <= len(value) <= 64 or re.fullmatch(r"[A-Za-z0-9_+=,.@-]+", value) is None:
        raise CredentialIssueError("Identity cannot be represented as an STS session")
    return value
