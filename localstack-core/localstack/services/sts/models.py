import dataclasses
from datetime import datetime
from typing import Any, TypedDict

from localstack.aws.api.sts import Tag
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class SessionConfig(TypedDict):
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag]
    # list of lowercase transitive tag keys
    transitive_tags: list[str]
    # other stored context variables
    iam_context: dict[str, Any]


@dataclasses.dataclass
class CredentialSession:
    """Natively issued temporary role session. Secrets are only stored as SHA-256 hashes."""

    access_key_id: str
    secret_access_key_hash: str
    session_token_hash: str
    expiration: datetime
    role_arn: str
    assumed_role_arn: str
    assumed_role_id: str
    account_id: str
    partition: str
    principal_tags: dict[str, str] = dataclasses.field(default_factory=dict)
    provider_name: str | None = None
    subject: str | None = None


class STSStore(BaseStore):
    # maps access key ids to tagging config for the session they belong to
    sessions: dict[str, SessionConfig] = CrossRegionAttribute(default=dict)
    # maps access key ids to natively issued temporary credential sessions
    credential_sessions: dict[str, CredentialSession] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
