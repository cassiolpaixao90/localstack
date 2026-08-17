import base64
import dataclasses
import hashlib
import hmac
from datetime import datetime

from localstack.services.cognito_idp.classic_ui import ClassicUICustomization
from localstack.services.cognito_idp.client_configuration import AnalyticsConfiguration
from localstack.services.cognito_idp.custom_auth import CustomAuthState
from localstack.services.cognito_idp.device_srp import DeviceSrpSession
from localstack.services.cognito_idp.imported_password_hashes import verify_imported_password
from localstack.services.cognito_idp.mfa_passwordless import MfaPasswordlessState
from localstack.services.cognito_idp.pool_configuration import PoolConfiguration
from localstack.services.cognito_idp.provisioned_limits import ProvisionedLimitState
from localstack.services.cognito_idp.provisioned_rate_enforcement import ProvisionedRateLimitState
from localstack.services.cognito_idp.user_import_models import UserImportState
from localstack.services.cognito_idp.user_pool_replicas import UserPoolReplicaTopology
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    LocalAttribute,
)

PBKDF2_ITERATIONS = 310_000


@dataclasses.dataclass(frozen=True)
class PasswordHash:
    algorithm: str
    iterations: int
    salt: str
    digest: str

    @classmethod
    def from_password(cls, password: str) -> "PasswordHash":
        salt = __import__("secrets").token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS, dklen=32)
        return cls(
            algorithm="pbkdf2-sha256",
            iterations=PBKDF2_ITERATIONS,
            salt=base64.b64encode(salt).decode(),
            digest=base64.b64encode(digest).decode(),
        )

    def verify(self, candidate: str) -> bool:
        if self.algorithm.startswith("imported:"):
            return verify_imported_password(
                candidate,
                self.algorithm.removeprefix("imported:"),
                self.digest,
            )
        if self.algorithm != "pbkdf2-sha256" or self.iterations < PBKDF2_ITERATIONS:
            return False
        salt = base64.b64decode(self.salt, validate=True)
        expected = base64.b64decode(self.digest, validate=True)
        actual = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode(), salt, self.iterations, dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)

    @property
    def is_imported(self) -> bool:
        return self.algorithm.startswith("imported:")

    def to_dict(self) -> dict[str, str | int]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class CognitoDevice:
    device_key: str
    device_group_key: str
    salt: str
    verifier: str
    name: str | None
    remembered_status: str
    created_at: datetime
    updated_at: datetime
    last_authenticated_at: datetime


@dataclasses.dataclass
class FederatedIdentity:
    provider_name: str
    provider_attribute_name: str
    provider_attribute_value: str
    created_at: datetime


@dataclasses.dataclass
class WebAuthnCredential:
    credential_id: str
    public_key_pem: bytes
    algorithm: int
    sign_count: int
    relying_party_id: str
    friendly_name: str
    authenticator_attachment: str | None
    authenticator_transports: list[str]
    created_at: datetime
    version: str


@dataclasses.dataclass
class CognitoUser:
    username: str
    sub: str
    password: PasswordHash
    status: str
    enabled: bool
    created_at: datetime
    updated_at: datetime
    srp_salt: str = ""
    srp_verifier: str = ""
    software_token_mfa_secret: str | None = None
    software_token_mfa_pending_secret: str | None = None
    software_token_mfa_pending_expires_at: datetime | None = None
    software_token_mfa_enabled: bool = False
    software_token_mfa_preferred: bool = False
    software_token_mfa_last_step: int | None = None
    email_mfa_enabled: bool = False
    email_mfa_preferred: bool = False
    sms_mfa_enabled: bool = False
    sms_mfa_preferred: bool = False
    tokens_valid_after: int = 0
    temporary_password_expires_at: datetime | None = None
    attributes: dict[str, str] = dataclasses.field(default_factory=dict)
    pending_attribute_updates: dict[str, str] = dataclasses.field(default_factory=dict)
    password_history: list[PasswordHash] = dataclasses.field(default_factory=list)
    devices: dict[str, CognitoDevice] = dataclasses.field(default_factory=dict)
    federated_identities: list[FederatedIdentity] = dataclasses.field(default_factory=list)
    web_authn_credentials: dict[str, WebAuthnCredential] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class UserPoolClientSecret:
    secret_id: str
    encrypted_value: str
    created_at: datetime


@dataclasses.dataclass
class UserPoolClient:
    client_id: str
    name: str
    created_at: datetime
    updated_at: datetime
    # Legacy persisted state only. New clients keep all secret material AES-GCM encrypted.
    secret: str | None
    explicit_auth_flows: list[str]
    analytics_configuration: AnalyticsConfiguration | None = None
    enable_propagate_additional_user_context_data: bool = False
    prevent_user_existence_errors: str = "LEGACY"
    access_token_validity: int = 1
    access_token_validity_unit: str = "hours"
    id_token_validity: int = 1
    id_token_validity_unit: str = "hours"
    refresh_token_validity: int = 30
    refresh_token_validity_unit: str = "days"
    allowed_oauth_flows_user_pool_client: bool = False
    allowed_oauth_flows: list[str] = dataclasses.field(default_factory=list)
    allowed_oauth_scopes: list[str] = dataclasses.field(default_factory=list)
    callback_urls: list[str] = dataclasses.field(default_factory=list)
    logout_urls: list[str] = dataclasses.field(default_factory=list)
    default_redirect_uri: str | None = None
    supported_identity_providers: list[str] = dataclasses.field(default_factory=lambda: ["COGNITO"])
    enable_token_revocation: bool = True
    refresh_token_rotation_enabled: bool = False
    refresh_token_rotation_grace_seconds: int = 0
    auth_session_validity: int = 3
    read_attributes: list[str] | None = None
    write_attributes: list[str] | None = None
    primary_secret: UserPoolClientSecret | None = None
    additional_secrets: dict[str, UserPoolClientSecret] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class UserPoolDomain:
    domain: str
    local_hostname: str
    user_pool_id: str
    account_id: str
    region: str
    managed_login_version: int
    created_at: datetime
    updated_at: datetime


@dataclasses.dataclass
class CognitoGroup:
    name: str
    description: str | None
    role_arn: str | None
    precedence: int | None
    created_at: datetime
    updated_at: datetime
    members: set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass
class CognitoResourceServer:
    identifier: str
    name: str
    scopes: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class CognitoIdentityProvider:
    pool_id: str
    provider_name: str
    provider_type: str
    provider_details: dict[str, str]
    encrypted_client_secret: str
    attribute_mapping: dict[str, str]
    idp_identifiers: list[str]
    created_at: datetime
    updated_at: datetime
    discovery_document: dict[str, object] | None = None
    discovery_expires_at: datetime | None = None
    jwks_document: dict[str, object] | None = None
    jwks_expires_at: datetime | None = None


@dataclasses.dataclass
class RiskConfiguration:
    client_id: str | None
    account_takeover: dict | None
    compromised_credentials: dict | None
    risk_exceptions: dict | None
    updated_at: datetime


@dataclasses.dataclass
class ManagedLoginAsset:
    resource_id: str
    category: str
    color_mode: str
    extension: str
    content: bytes


@dataclasses.dataclass
class ManagedLoginBranding:
    branding_id: str
    client_id: str
    use_cognito_provided_values: bool
    settings: dict
    assets: dict[str, ManagedLoginAsset]
    created_at: datetime
    updated_at: datetime


@dataclasses.dataclass
class CognitoTerms:
    terms_id: str
    client_id: str
    terms_name: str
    terms_source: str
    enforcement: str
    links: dict[str, str]
    created_at: datetime
    updated_at: datetime
    version: str


@dataclasses.dataclass
class AuthEvent:
    event_id: str
    pool_id: str
    client_id: str
    username: str
    created_at: datetime
    event_response: str
    challenge_responses: list[dict[str, str]]
    context_data: dict[str, str]
    additional_user_context_propagated: bool = False
    risk_level: str = "Low"
    risk_decision: str = "NoRisk"
    compromised_credentials_detected: bool = False
    feedback_value: str | None = None
    feedback_provider: str | None = None
    feedback_date: datetime | None = None


@dataclasses.dataclass
class UserPool:
    pool_id: str
    name: str
    arn: str
    created_at: datetime
    updated_at: datetime
    access_signing_key_id: str
    access_signing_private_key_pem: bytes
    access_signing_jwk: dict[str, str]
    id_signing_key_id: str
    id_signing_private_key_pem: bytes
    id_signing_jwk: dict[str, str]
    mfa_configuration: str = "OFF"
    software_token_mfa_enabled: bool = False
    email_mfa_configuration: dict | None = None
    sms_mfa_configuration: dict | None = None
    user_pool_tier: str = "ESSENTIALS"
    web_authn_configuration: dict[str, str] | None = None
    allow_admin_create_user_only: bool = False
    account_recovery_setting: dict | None = None
    auto_verified_attributes: list[str] | None = None
    alias_attributes: list[str] | None = None
    username_attributes: list[str] | None = None
    username_case_sensitive: bool = True
    password_policy: dict | None = None
    schema_attributes: list[dict] | None = None
    email_verification_message: str | None = None
    email_verification_subject: str | None = None
    sms_verification_message: str | None = None
    verification_message_template: dict | None = None
    email_configuration: dict | None = None
    sms_configuration: dict | None = None
    invite_message_template: dict | None = None
    lambda_config: dict | None = None
    pool_configuration: PoolConfiguration = dataclasses.field(default_factory=PoolConfiguration)
    saml_signing_certificate: str | None = None
    device_tracking_enabled: bool = False
    challenge_required_on_new_device: bool = False
    device_only_remembered_on_user_prompt: bool = False
    clients: dict[str, UserPoolClient] = dataclasses.field(default_factory=dict)
    users: dict[str, CognitoUser] = dataclasses.field(default_factory=dict)
    username_index: dict[str, str] = dataclasses.field(default_factory=dict)
    alias_index: dict[str, str] = dataclasses.field(default_factory=dict)
    identity_indexes_initialized: bool = False
    groups: dict[str, CognitoGroup] = dataclasses.field(default_factory=dict)
    resource_servers: dict[str, CognitoResourceServer] = dataclasses.field(default_factory=dict)
    identity_providers: dict[str, CognitoIdentityProvider] = dataclasses.field(default_factory=dict)
    risk_configurations: dict[str, RiskConfiguration] = dataclasses.field(default_factory=dict)
    managed_login_branding: dict[str, ManagedLoginBranding] = dataclasses.field(
        default_factory=dict
    )
    terms: dict[str, CognitoTerms] = dataclasses.field(default_factory=dict)
    ui_customizations: dict[str, ClassicUICustomization] = dataclasses.field(default_factory=dict)
    tags: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class RefreshSession:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    auth_time: int
    origin_jti: str
    expires_at: datetime
    device_key: str | None = None
    scopes: list[str] = dataclasses.field(default_factory=lambda: ["aws.cognito.signin.user.admin"])
    revoked: bool = False
    reuse_detected: bool = False
    generation: int = 0
    rotated_at: datetime | None = None
    retry_grace_expires_at: datetime | None = None
    replacement_hash: str | None = None
    replacement_scopes: list[str] | None = None
    encrypted_replacement_token: str | None = None


@dataclasses.dataclass
class BrowserTransaction:
    token_hash: str
    pool_id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    state: str | None
    nonce: str | None
    code_challenge: str
    csrf_hash: str | None
    created_at: datetime
    expires_at: datetime
    failed_attempts: int = 0
    response_type: str = "code"
    language: str | None = None
    signup_username: str | None = None


@dataclasses.dataclass
class AuthorizationCode:
    token_hash: str
    pool_id: str
    client_id: str
    redirect_uri: str
    username: str
    scopes: list[str]
    nonce: str | None
    created_at: datetime
    expires_at: datetime
    code_challenge: str


@dataclasses.dataclass
class FederationTransaction:
    token_hash: str
    browser_transaction_hash: str
    pool_id: str
    client_id: str
    provider_name: str
    redirect_uri: str
    encrypted_code_verifier: str
    nonce_hash: str
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass
class SamlReplay:
    token_hash: str
    pool_id: str
    expires_at: datetime


@dataclasses.dataclass
class BrowserSession:
    token_hash: str
    pool_id: str
    username: str
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass
class SrpSession:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    shared_key: str
    secret_block_hash: str
    user_not_found: bool
    created_at: datetime
    expires_at: datetime
    device_key: str | None = None
    auth_context: dict[str, str] = dataclasses.field(default_factory=dict)
    client_metadata: dict[str, str] = dataclasses.field(default_factory=dict)
    custom_auth: bool = False


@dataclasses.dataclass
class NewPasswordSession:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    required_attributes: list[str]
    created_at: datetime
    expires_at: datetime
    device_key: str | None = None
    client_metadata: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class MfaSession:
    token_hash: str
    pool_id: str
    client_id: str | None
    username: str
    kind: str
    encrypted_secret: str | None
    created_at: datetime
    expires_at: datetime
    device_key: str | None = None
    client_metadata: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class WebAuthnChallenge:
    token_hash: str
    challenge_hash: str
    pool_id: str
    client_id: str
    username: str
    kind: str
    relying_party_id: str
    credential_versions: dict[str, str]
    created_at: datetime
    expires_at: datetime
    synthetic: bool = False
    client_metadata: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class UserCode:
    key: str
    pool_id: str
    client_id: str
    username: str
    purpose: str
    attribute_name: str | None
    code_hash: str
    created_at: datetime
    expires_at: datetime
    failed_attempts: int = 0
    reservation_id: str | None = None
    pending: bool = False


@dataclasses.dataclass
class LoginAttemptWindow:
    key: str
    pool_id: str
    attempts: int
    expires_at: datetime


@dataclasses.dataclass
class PendingDevice:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    device_group_key: str
    created_at: datetime
    expires_at: datetime


class CognitoIdpStore(BaseStore):
    POOL_LOCATIONS: dict[str, tuple[str, str]] = CrossAccountAttribute(default=dict)
    DOMAIN_LOCATIONS: dict[str, tuple[str, str]] = CrossAccountAttribute(default=dict)
    user_pools: dict[str, UserPool] = LocalAttribute(default=dict)
    user_pool_domains: dict[str, UserPoolDomain] = LocalAttribute(default=dict)
    refresh_sessions: dict[str, RefreshSession] = LocalAttribute(default=dict)
    browser_transactions: dict[str, BrowserTransaction] = LocalAttribute(default=dict)
    authorization_codes: dict[str, AuthorizationCode] = LocalAttribute(default=dict)
    federation_transactions: dict[str, FederationTransaction] = LocalAttribute(default=dict)
    saml_replays: dict[str, SamlReplay] = LocalAttribute(default=dict)
    browser_sessions: dict[str, BrowserSession] = LocalAttribute(default=dict)
    srp_sessions: dict[str, SrpSession] = LocalAttribute(default=dict)
    new_password_sessions: dict[str, NewPasswordSession] = LocalAttribute(default=dict)
    mfa_sessions: dict[str, MfaSession] = LocalAttribute(default=dict)
    device_srp_sessions: dict[str, DeviceSrpSession] = LocalAttribute(default=dict)
    web_authn_challenges: dict[str, WebAuthnChallenge] = LocalAttribute(default=dict)
    user_codes: dict[str, UserCode] = LocalAttribute(default=dict)
    login_attempt_windows: dict[str, LoginAttemptWindow] = LocalAttribute(default=dict)
    pending_devices: dict[str, PendingDevice] = LocalAttribute(default=dict)
    friendly_device_names: dict[tuple[str, str], str] = LocalAttribute(default=dict)
    auth_events: dict[str, AuthEvent] = LocalAttribute(default=dict)
    log_delivery_configurations: dict[str, list[dict]] = LocalAttribute(default=dict)
    user_import_jobs: UserImportState = LocalAttribute(default=UserImportState)
    custom_auth: CustomAuthState = LocalAttribute(default=CustomAuthState)
    mfa_passwordless: MfaPasswordlessState = LocalAttribute(default=MfaPasswordlessState)
    provisioned_limits: ProvisionedLimitState = LocalAttribute(default=ProvisionedLimitState)
    provisioned_rate_limits: ProvisionedRateLimitState = LocalAttribute(
        default=ProvisionedRateLimitState
    )
    user_pool_replicas: dict[str, UserPoolReplicaTopology] = LocalAttribute(default=dict)


cognito_idp_stores = AccountRegionBundle("cognito-idp", CognitoIdpStore)


def resolve_pool_location(pool_id: str) -> tuple[str, str] | None:
    """Resolve a public pool ID without requiring an AWS request identity."""
    with cognito_idp_stores.lock:
        locations = cognito_idp_stores._universal.get("POOL_LOCATIONS", {})
        return locations.get(pool_id)


def resolve_domain_location(hostname: str) -> tuple[str, str] | None:
    """Resolve a public local managed-login hostname without AWS request identity."""
    if not isinstance(hostname, str):
        return None
    canonical_hostname = hostname.lower().rstrip(".")
    with cognito_idp_stores.lock:
        locations = cognito_idp_stores._universal.get("DOMAIN_LOCATIONS", {})
        return locations.get(canonical_hostname)
