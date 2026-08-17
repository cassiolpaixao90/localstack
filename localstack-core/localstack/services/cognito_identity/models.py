import dataclasses
from datetime import datetime
from typing import Any

from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    LocalAttribute,
)


@dataclasses.dataclass
class CognitoIdentity:
    identity_id: str
    pool_id: str
    created_at: datetime
    updated_at: datetime
    enabled: bool = True
    authenticated: bool = False
    logins: dict[str, str] = dataclasses.field(default_factory=dict)
    developer_user_identifiers: set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass
class CredentialSession:
    access_key_id: str
    identity_id: str
    pool_id: str
    role_arn: str
    assumed_role_arn: str
    account_id: str
    partition: str
    issued_at: datetime
    expires_at: datetime
    authenticated: bool
    provider_names: tuple[str, ...] = ()
    principal_tags: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PrincipalTagAttributeMap:
    use_defaults: bool
    principal_tags: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class IdentityPool:
    pool_id: str
    name: str
    account_id: str
    region: str
    allow_unauthenticated_identities: bool
    allow_classic_flow: bool
    created_at: datetime
    updated_at: datetime
    supported_login_providers: dict[str, str] = dataclasses.field(default_factory=dict)
    developer_provider_name: str | None = None
    open_id_connect_provider_arns: list[str] = dataclasses.field(default_factory=list)
    cognito_identity_providers: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    saml_provider_arns: list[str] = dataclasses.field(default_factory=list)
    tags: dict[str, str] = dataclasses.field(default_factory=dict)
    roles: dict[str, str] = dataclasses.field(default_factory=dict)
    role_mappings: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    principal_tag_attribute_maps: dict[str, PrincipalTagAttributeMap] = dataclasses.field(
        default_factory=dict
    )
    identity_ids: set[str] = dataclasses.field(default_factory=set)


class CognitoIdentityStore(BaseStore):
    POOL_LOCATIONS: dict[str, tuple[str, str]] = CrossAccountAttribute(default=dict)
    IDENTITY_LOCATIONS: dict[str, tuple[str, str, str]] = CrossAccountAttribute(default=dict)
    identity_pools: dict[str, IdentityPool] = LocalAttribute(default=dict)
    identities: dict[str, CognitoIdentity] = LocalAttribute(default=dict)
    login_identities: dict[tuple[str, str, str], str] = LocalAttribute(default=dict)
    developer_identities: dict[tuple[str, str, str], str] = LocalAttribute(default=dict)
    credential_sessions: dict[str, CredentialSession] = LocalAttribute(default=dict)
    pagination_secret: bytes = LocalAttribute(default=b"")
    open_id_signing_key_id: str = LocalAttribute(default="")
    open_id_signing_private_key: bytes = LocalAttribute(default=b"")
    open_id_signing_jwk: dict[str, str] = LocalAttribute(default=dict)


cognito_identity_stores = AccountRegionBundle("cognito-identity", CognitoIdentityStore)


def resolve_pool_location(pool_id: str) -> tuple[str, str] | None:
    """Resolve a public identity-pool ID without depending on request credentials."""
    with cognito_identity_stores.lock:
        locations = cognito_identity_stores._universal.get("POOL_LOCATIONS", {})
        return locations.get(pool_id)


def resolve_identity_location(identity_id: str) -> tuple[str, str, str] | None:
    """Resolve a public identity ID without depending on request credentials."""
    with cognito_identity_stores.lock:
        locations = cognito_identity_stores._universal.get("IDENTITY_LOCATIONS", {})
        return locations.get(identity_id)
