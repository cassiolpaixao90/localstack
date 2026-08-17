import base64
import contextlib
import copy
import dataclasses
import functools
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import struct
import threading
import time
import unicodedata
import uuid
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit

import botocore.loaders
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.aws.connect import connect_to
from localstack.services.cognito_idp.auth_factors import (
    AuthFactorsError,
    admin_auth_factors_response,
)
from localstack.services.cognito_idp.classic_ui import (
    ClassicUIError,
    apply_classic_ui_update,
    customization_response,
    inherited_customization,
    safe_image_path,
    validate_classic_ui_update,
)
from localstack.services.cognito_idp.client_configuration import (
    AnalyticsConfiguration,
    ClientConfigurationError,
    ClientScope,
    analytics_resolvers,
    normalize_explicit_auth_flows,
    parse_analytics_configuration,
    revalidate_analytics_configuration,
    validate_propagate_additional_context,
)
from localstack.services.cognito_idp.client_metadata_contract import (
    ClientMetadataError,
    normalize_client_metadata,
)
from localstack.services.cognito_idp.custom_auth import (
    CustomAuthError,
    CustomAuthManager,
    CustomAuthOutcome,
    CustomChallengeResult,
)
from localstack.services.cognito_idp.device_srp import (
    DeviceSrpError,
    consume_device_srp_session,
    normalize_device_verifier,
    reserve_device_srp_session,
    start_device_srp,
    verify_device_password,
)
from localstack.services.cognito_idp.friendly_device_names import (
    FriendlyDeviceNameError,
    FriendlyDeviceNames,
    normalize_friendly_device_name,
)
from localstack.services.cognito_idp.image_validation import (
    ImageValidationError,
)
from localstack.services.cognito_idp.image_validation import (
    validate_jpeg as validate_jpeg_image,
)
from localstack.services.cognito_idp.list_users_query import (
    ListUsersQueryError,
    ListUsersQueryPager,
)
from localstack.services.cognito_idp.log_delivery import (
    CognitoIdpLogDeliveryProvider,
    emit_auth_event,
    emit_notification_error,
)
from localstack.services.cognito_idp.lambda_triggers import (
    LambdaTriggerError,
    TriggerIdentity,
    invoke_authentication_trigger,
    invoke_custom_message,
    invoke_pre_token_generation,
    invoke_user_migration,
    parse_lambda_configuration,
)
from localstack.services.cognito_idp.mfa_passwordless import (
    EmailMfaConfiguration,
    MfaPasswordlessEngine,
    MfaPasswordlessError,
    OtpDeliveryRequest,
    PoolAuthPolicy,
    SmsMfaConfiguration,
    UserAuthState,
    available_recovery_attributes,
    set_user_mfa_preferences,
    validate_pool_auth_policy,
)
from localstack.services.cognito_idp.models import (
    AuthEvent,
    CognitoDevice,
    CognitoGroup,
    CognitoIdentityProvider,
    CognitoIdpStore,
    CognitoResourceServer,
    CognitoTerms,
    CognitoUser,
    FederatedIdentity,
    ManagedLoginAsset,
    ManagedLoginBranding,
    MfaSession,
    NewPasswordSession,
    PasswordHash,
    PendingDevice,
    RefreshSession,
    RiskConfiguration,
    SrpSession,
    UserCode,
    UserPool,
    UserPoolClient,
    UserPoolClientSecret,
    UserPoolDomain,
    WebAuthnChallenge,
    WebAuthnCredential,
    cognito_idp_stores,
    resolve_pool_location,
)
from localstack.services.cognito_idp.notification_delivery import (
    NotificationCommitError,
    NotificationConfigurationError,
    NotificationDeliveryError,
    NotificationDispatcher,
    NotificationRequest,
    NotificationReservation,
    NotificationTemplates,
    validate_local_resources,
    validate_notification_configuration,
)
from localstack.services.cognito_idp.pool_configuration import (
    AttributeUpdatePlan,
    PoolConfiguration,
    PoolConfigurationError,
    PoolIdentity,
    assert_password_not_reused,
    assert_pool_delete_allowed,
    commit_verified_attribute,
    invoke_pre_sign_up,
    parse_pool_configuration,
    plan_attribute_updates,
    revalidate_customer_managed_key,
    rotate_password_history,
)
from localstack.services.cognito_idp.provisioned_limits import (
    DEFAULT_API_CATEGORY_LIMITS,
    ProvisionedLimitError,
)
from localstack.services.cognito_idp.provisioned_limits import (
    get_provisioned_limit as get_local_provisioned_limit,
)
from localstack.services.cognito_idp.provisioned_limits import (
    update_provisioned_limit as update_local_provisioned_limit,
)
from localstack.services.cognito_idp.provisioned_rate_enforcement import (
    ProvisionedRateLimitError,
    adjustable_category_for_operation,
    consume_provisioned_capacity,
)
from localstack.services.cognito_idp.replica_data_plane import (
    ReplicaDataPlaneError,
    resolve_regional_pool,
)
from localstack.services.cognito_idp.saml import (
    SamlFederationError,
    generate_saml_encryption_material,
    saml_metadata,
    saml_signing_certificate,
)
from localstack.services.cognito_idp.tokens import (
    decode_jwt_segment,
    generate_signing_key,
    public_key_from_jwk,
    sign_jwt,
)
from localstack.services.cognito_idp.user_import import ImportJobError, get_user_import_jobs
from localstack.services.cognito_idp.user_pool_replicas import (
    UserPoolReplicaError,
    UserPoolReplicaTopology,
    create_replica,
    delete_replica,
    list_replicas,
    reconcile_replica,
    update_replica,
)
from localstack.services.cognito_idp.user_pool_summaries import user_pool_summary
from localstack.services.cognito_idp.webauthn import (
    WebAuthnError,
    authentication_response,
    canonical_credential_id,
    credential_challenge_hash,
    registration_response,
    response_credential_id,
)

_MAX_PAGE_TOKEN_BYTES = 512
_PROPAGATED_CONTEXT_MARKER = "__localstack_additional_user_context_propagated"
_MAX_REFRESH_SESSIONS_PER_STORE = 4096
_MAX_REFRESH_SESSIONS_PER_POOL = 1024
_MAX_REFRESH_SESSIONS_PER_USER_CLIENT = 64
_MAX_AUTH_CHALLENGE_SESSIONS = 512
_MAX_USER_POOLS_PER_ACCOUNT_REGION = 1_000
_MAX_CLIENTS_PER_POOL = 1_000
_MAX_GROUPS_PER_POOL = 10_000
_MAX_GROUP_MEMBERSHIPS_PER_USER = 100
_MAX_USERS_PER_POOL = 10_000
_MAX_USER_CODES_PER_STORE = 4096
_MAX_USER_CODE_ATTEMPTS = 5
_MAX_DEVICES_PER_USER = 10
_MAX_PENDING_DEVICES_PER_STORE = 4096
_MAX_PENDING_DEVICES_PER_USER = 4
_MAX_RESOURCE_SERVERS_PER_POOL = 25
_MAX_TAGS_PER_POOL = 50
_MAX_CUSTOM_ATTRIBUTES_PER_POOL = 50
_MAX_CUSTOM_ATTRIBUTES_PER_REQUEST = 25
_MAX_CLIENT_SECRETS = 2
_MAX_AUTH_EVENTS_PER_USER = 100
_MAX_AUTH_EVENTS_PER_STORE = 10_000
_MAX_IDENTITY_PROVIDERS_PER_POOL = 300
_MAX_FEDERATED_IDENTITIES_PER_USER = 5
_MAX_WEB_AUTHN_CREDENTIALS_PER_USER = 20
_MAX_WEB_AUTHN_CHALLENGES_PER_STORE = 4096
_MAX_WEB_AUTHN_CHALLENGES_PER_USER = 5
_MAX_MANAGED_LOGIN_ASSETS = 40
_MAX_MANAGED_LOGIN_ASSET_BYTES = 1_000_000
_MAX_MANAGED_LOGIN_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_MANAGED_LOGIN_SETTINGS_BYTES = 256 * 1024
_MAX_MANAGED_LOGIN_BRANDING_PER_POOL = 20
_MAX_TERMS_PER_POOL = 40
_MAX_TERM_LINKS = 13
_PROVISIONED_LIMIT_ACCOUNT_MAXIMA = dict.fromkeys(DEFAULT_API_CATEGORY_LIMITS, 1000000)
_WEB_AUTHN_CHALLENGE_TTL = timedelta(minutes=3)
_LOCAL_COMPROMISED_PASSWORD_HASHES = frozenset(
    {
        "0e44ce7308af2b3de5232e4616403ce7d49ba2aec83f79c196409556422a4927",
        "3875034e17855bac03a3cc9e107b1d28a9b44313d381c3335588525b4e70b55b",
        "a109e36947ad56de1dca1cc49f0ef8ac9ad9a7b1aa0df41fb3c4cb73c1ff01ea",
    }
)
_MAX_SCHEMA_NUMBER = Decimal(2**1023)
_USER_CODE_TTL = timedelta(hours=1)
_AUTH_CHALLENGE_TTL = timedelta(minutes=5)
_PENDING_DEVICE_TTL = timedelta(minutes=5)
_PASSWORD_CLAIM_MAX_SKEW = timedelta(minutes=5)
_TOTP_STEP_SECONDS = 30
_LOCAL_DOMAIN_SUFFIX = ".localhost.localstack.cloud"
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_URL_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")
_POOL_LOCKS_GUARD = threading.RLock()
_POOL_GUARDS_CONDITION = threading.Condition(_POOL_LOCKS_GUARD)
_POOL_LOCKS: dict[str, tuple[threading.RLock, int]] = {}
_ACTIVE_POOL_GUARDS = 0
_POOL_SNAPSHOT_ACTIVE = False

_SRP_N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
_SRP_G = 2


def _srp_pad_hex(value: int) -> str:
    encoded = format(value, "x")
    if len(encoded) % 2:
        encoded = f"0{encoded}"
    if encoded[0] in "89abcdefABCDEF":
        encoded = f"00{encoded}"
    return encoded


def _srp_hex_hash(value: str) -> str:
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


_SRP_K = int(_srp_hex_hash(f"{_srp_pad_hex(_SRP_N)}{_srp_pad_hex(_SRP_G)}"), 16)


@contextlib.contextmanager
def _pool_guard(pool_id: str):
    global _ACTIVE_POOL_GUARDS
    with _POOL_GUARDS_CONDITION:
        while _POOL_SNAPSHOT_ACTIVE:
            _POOL_GUARDS_CONDITION.wait()
        lock, users = _POOL_LOCKS.get(pool_id, (threading.RLock(), 0))
        _POOL_LOCKS[pool_id] = (lock, users + 1)
        _ACTIVE_POOL_GUARDS += 1
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _POOL_GUARDS_CONDITION:
            current_lock, current_users = _POOL_LOCKS[pool_id]
            if current_lock is lock and current_users == 1:
                _POOL_LOCKS.pop(pool_id)
            else:
                _POOL_LOCKS[pool_id] = (current_lock, current_users - 1)
            _ACTIVE_POOL_GUARDS -= 1
            if _ACTIVE_POOL_GUARDS == 0:
                _POOL_GUARDS_CONDITION.notify_all()


@contextlib.contextmanager
def quiesce_pool_guards_for_snapshot():
    global _POOL_SNAPSHOT_ACTIVE
    with _POOL_GUARDS_CONDITION:
        while _POOL_SNAPSHOT_ACTIVE:
            _POOL_GUARDS_CONDITION.wait()
        _POOL_SNAPSHOT_ACTIVE = True
        while _ACTIVE_POOL_GUARDS:
            _POOL_GUARDS_CONDITION.wait()
    try:
        yield
    finally:
        with _POOL_GUARDS_CONDITION:
            _POOL_SNAPSHOT_ACTIVE = False
            _POOL_GUARDS_CONDITION.notify_all()


class _MfaOtpDeliveryAdapter:
    def __init__(
        self,
        context: RequestContext,
        pool_id: str,
        configuration: Any,
        templates: NotificationTemplates,
        *,
        expected_username: str | None = None,
        expected_user_sub: str | None = None,
    ):
        self.context = context
        self.pool_id = pool_id
        self.configuration = configuration
        self.expected_username = expected_username
        self.expected_user_sub = expected_user_sub
        self.dispatcher = NotificationDispatcher(
            configuration, templates, failure_reporter=emit_notification_error
        )
        self.resource_snapshot: str | None = None

    def deliver_otp(
        self,
        request: OtpDeliveryRequest,
        reservation_id: str,
        *,
        commit: Callable[[str], bool],
        rollback: Callable[[str], None],
    ) -> str:
        self.resource_snapshot = validate_local_resources(
            self.context, self.pool_id, self.configuration
        )
        return self.dispatcher.deliver_reserved(
            self.context,
            NotificationRequest(
                pool_id=request.pool_id,
                purpose=request.purpose,
                medium=request.medium,
                destination=request.destination,
                secret=request.secret,
                username=request.username,
            ),
            NotificationReservation(reservation_id),
            commit=commit,
            rollback=rollback,
            pre_commit=self._pre_commit,
        )

    def _pre_commit(self) -> None:
        _revalidate_notification_resources(
            self.context,
            self.pool_id,
            self.configuration,
            self.resource_snapshot or "",
        )
        if self.expected_username is None:
            return
        with _pool_guard(self.pool_id):
            with cognito_idp_stores.lock:
                pool = self.context_provider_store().user_pools.get(self.pool_id)
                user = pool.users.get(self.expected_username) if pool is not None else None
                if (
                    user is None
                    or self.expected_user_sub is None
                    or not hmac.compare_digest(user.sub, self.expected_user_sub)
                ):
                    raise NotificationCommitError()

    def context_provider_store(self) -> CognitoIdpStore:
        return cognito_idp_stores[self.context.account_id][self.context.region]


class CognitoIdpProvider(CognitoIdpLogDeliveryProvider):
    service = "cognito-idp"

    def __getattribute__(self, name: str):
        attribute = super().__getattribute__(name)
        operation = getattr(attribute, "operation", None)
        if not isinstance(operation, str):
            return attribute

        @functools.wraps(attribute)
        def governed_handler(*args, **kwargs):
            context = args[0] if args else kwargs.get("context")
            if not isinstance(context, RequestContext):
                return attribute(*args, **kwargs)
            request = args[1] if len(args) > 1 and isinstance(args[1], dict) else None
            if request is None:
                request = kwargs.get("request")
            if not isinstance(request, dict):
                request = {key: value for key, value in kwargs.items() if key != "context"}
            with self._governed_request(context, request, operation):
                return attribute(*args, **kwargs)

        return governed_handler

    def get_store(self, context: RequestContext) -> CognitoIdpStore:
        region = getattr(context, "_cognito_primary_region", context.region)
        return cognito_idp_stores[context.account_id][region]

    @contextlib.contextmanager
    def _governed_request(self, context: RequestContext, request: ServiceRequest, operation: str):
        self._consume_provisioned_rate(context, operation)
        with cognito_idp_stores.lock:
            pool_id = self._request_pool_id(context, request)
        guard = _pool_guard(pool_id) if pool_id is not None else contextlib.nullcontext()
        with guard:
            primary_region = self._resolve_replica_request(context, request, operation)
        previous = getattr(context, "_cognito_primary_region", None)
        if primary_region is not None:
            context._cognito_primary_region = primary_region
        try:
            yield
        finally:
            if previous is None:
                context.__dict__.pop("_cognito_primary_region", None)
            else:
                context._cognito_primary_region = previous

    def _consume_provisioned_rate(self, context: RequestContext, operation: str) -> None:
        try:
            category = adjustable_category_for_operation(operation)
            if category is None:
                return
            store = cognito_idp_stores[context.account_id][context.region]
            limit = store.provisioned_limits.values.get(
                (context.account_id, context.region, category),
                DEFAULT_API_CATEGORY_LIMITS[category],
            )
            consume_provisioned_capacity(
                store.provisioned_rate_limits,
                account_id=context.account_id,
                region=context.region,
                category=category,
                provisioned_limit=limit,
            )
        except ProvisionedRateLimitError as error:
            exception = CommonServiceException(
                error.code, str(error), status_code=400, sender_fault=True
            )
            exception.retry_after_seconds = error.retry_after_seconds
            raise exception from error

    def _resolve_replica_request(
        self, context: RequestContext, request: ServiceRequest, operation: str
    ) -> str | None:
        if operation in {
            "CreateUserPoolReplica",
            "DeleteUserPoolReplica",
            "ListUserPoolReplicas",
            "UpdateUserPoolReplica",
        }:
            return None
        with cognito_idp_stores.lock:
            pool_id = self._request_pool_id(context, request)
            if pool_id is None:
                return None
            location = cognito_idp_stores._universal.get("POOL_LOCATIONS", {}).get(pool_id)
            if location is None or location[0] != context.account_id:
                return None
            primary_region = location[1]
            primary_store = cognito_idp_stores[context.account_id][primary_region]
            pool = primary_store.user_pools.get(pool_id)
            topology = primary_store.user_pool_replicas.get(pool_id)
            if pool is None or context.region == primary_region:
                return primary_region
            if topology is None:
                _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
            try:
                resolve_regional_pool(
                    topology,
                    pool,
                    serving_region=context.region,
                    operation=_replica_operation_class(operation, request),
                    dns_suffix=_partition_dns_suffix(context.partition),
                )
            except ReplicaDataPlaneError as error:
                _error(error.code, str(error))
            return primary_region

    def _request_pool_id(self, context: RequestContext, request: ServiceRequest) -> str | None:
        pool_id = request.get("UserPoolId")
        if isinstance(pool_id, str):
            return pool_id
        token = request.get("AccessToken")
        if isinstance(token, str):
            if not 1 <= len(token) <= 16 * 1024:
                return None
            try:
                segments = token.split(".")
                if len(segments) != 3 or any(not segment for segment in segments):
                    return None
                claims = decode_jwt_segment(segments[1])
                issuer = claims.get("iss")
                if isinstance(issuer, str):
                    return issuer.rsplit("/", 1)[-1]
            except (IndexError, TypeError, ValueError, json.JSONDecodeError):
                return None
        client_id = request.get("ClientId")
        if isinstance(client_id, str):
            for pool_id, location in cognito_idp_stores._universal.get(
                "POOL_LOCATIONS", {}
            ).items():
                if location[0] != context.account_id:
                    continue
                pool = cognito_idp_stores[context.account_id][location[1]].user_pools.get(pool_id)
                if pool is not None and client_id in pool.clients:
                    return pool_id
        return None

    def _deliver_reserved_user_code(
        self,
        context: RequestContext,
        *,
        pool_id: str,
        user_sub: str,
        username: str,
        purpose: str,
        notification_purpose: str,
        attribute_name: str,
        destination: str,
        medium: str,
        code: str,
        reservation: NotificationReservation,
        configuration: Any,
        templates: NotificationTemplates,
    ) -> None:
        dispatcher = NotificationDispatcher(
            configuration, templates, failure_reporter=emit_notification_error
        )
        request = NotificationRequest(
            pool_id=pool_id,
            purpose=notification_purpose,
            medium=medium,
            destination=destination,
            secret=code,
            username=username,
        )

        def rollback(reservation_id: str) -> None:
            with _pool_guard(pool_id):
                _rollback_user_code(
                    self.get_store(context), pool_id, username, purpose, reservation_id
                )

        def commit(reservation_id: str) -> bool:
            with _pool_guard(pool_id):
                store = self.get_store(context)
                pool = store.user_pools.get(pool_id)
                user = pool.users.get(username) if pool is not None else None
                if user is None or not hmac.compare_digest(user.sub, user_sub):
                    return False
                return _commit_user_code(store, pool_id, username, purpose, reservation_id)

        try:
            resource_snapshot = validate_local_resources(context, pool_id, configuration)
            dispatcher.deliver_reserved(
                context,
                request,
                reservation,
                commit=commit,
                rollback=rollback,
                pre_commit=lambda: _revalidate_notification_resources(
                    context, pool_id, configuration, resource_snapshot
                ),
            )
        except NotificationConfigurationError as error:
            rollback(reservation.reservation_id)
            _error(getattr(error, "code", "InvalidParameterException"), str(error))
        except NotificationDeliveryError as error:
            _error(error.code, str(error))
        except NotificationCommitError as error:
            _error("CodeDeliveryFailureException", str(error))

    def _customize_reserved_user_code(
        self,
        context: RequestContext,
        *,
        pool: UserPool,
        client: UserPoolClient,
        user: CognitoUser,
        purpose: str,
        reservation: NotificationReservation,
        trigger_source: str,
        client_metadata: dict[str, str],
        templates: NotificationTemplates,
    ) -> NotificationTemplates:
        try:
            return _invoke_custom_message_templates(
                context,
                pool,
                client,
                user,
                trigger_source,
                client_metadata,
                templates,
            )
        except CommonServiceException:
            with _pool_guard(pool.pool_id):
                _rollback_user_code(
                    self.get_store(context),
                    pool.pool_id,
                    user.username,
                    purpose,
                    reservation.reservation_id,
                )
            raise

    def _deliver_admin_invitations(
        self,
        context: RequestContext,
        *,
        pool_id: str,
        username: str,
        password: str,
        targets: list[tuple[str, str]],
        configuration: Any,
        templates: NotificationTemplates,
    ) -> None:
        dispatcher = NotificationDispatcher(
            configuration, templates, failure_reporter=emit_notification_error
        )
        try:
            resource_snapshot = validate_local_resources(context, pool_id, configuration)
            for medium, destination in targets:
                dispatcher.deliver(
                    context,
                    NotificationRequest(
                        pool_id=pool_id,
                        purpose="admin_invitation",
                        medium=medium,
                        destination=destination,
                        secret=password,
                        username=username,
                    ),
                )
            _revalidate_notification_resources(context, pool_id, configuration, resource_snapshot)
        except NotificationConfigurationError as error:
            _error(getattr(error, "code", "InvalidParameterException"), str(error))
        except NotificationDeliveryError as error:
            _error(error.code, str(error))

    @contextlib.contextmanager
    def _locked_client(self, context: RequestContext, client_id: Any):
        with cognito_idp_stores.lock:
            client, pool = self._find_client(context, client_id)
            pool_id = pool.pool_id
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                client, pool = self._find_client(context, client_id)
                if pool.pool_id != pool_id:
                    _error("ResourceNotFoundException", "User pool client changed identity")
            yield client, pool

    @contextlib.contextmanager
    def _locked_pool(self, context: RequestContext, pool_id: Any):
        pool_id = _pool_id(pool_id)
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                pool = self.get_store(context).user_pools.get(pool_id)
            if pool is None:
                _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
            yield pool

    @contextlib.contextmanager
    def _locked_replica_topology(self, context: RequestContext, pool_id: Any):
        pool_id = _pool_id(pool_id)
        with cognito_idp_stores.lock:
            location = cognito_idp_stores._universal.get("POOL_LOCATIONS", {}).get(pool_id)
        if location is None or location[0] != context.account_id:
            _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
        primary_region = location[1]
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                primary_store = cognito_idp_stores[context.account_id][primary_region]
                pool = primary_store.user_pools.get(pool_id)
                if pool is None:
                    _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
                topology = primary_store.user_pool_replicas.get(pool_id)
                if topology is None:
                    topology = UserPoolReplicaTopology(
                        account_id=context.account_id,
                        partition=pool.arn.split(":", 2)[1],
                        pool_id=pool_id,
                        primary_region=primary_region,
                    )
            yield pool, topology, primary_store

    @contextlib.contextmanager
    def _locked_access_token_user(self, context: RequestContext, token: Any):
        pool, user = self._access_token_user(context, token)
        pool_id, user_sub = pool.pool_id, user.sub
        with _pool_guard(pool_id):
            current_pool, current_user = self._access_token_user(context, token)
            if current_pool.pool_id != pool_id or not hmac.compare_digest(
                current_user.sub, user_sub
            ):
                _error("NotAuthorizedException", "Invalid access token")
            yield current_pool, current_user

    @contextlib.contextmanager
    def _locked_access_token_client_user(self, context: RequestContext, token: Any):
        pool, user = self._access_token_user(context, token)
        claims = decode_jwt_segment(token.split(".")[1])
        client_id = claims["client_id"]
        pool_id, user_sub = pool.pool_id, user.sub
        with _pool_guard(pool_id):
            current_pool, current_user = self._access_token_user(context, token)
            current_client = current_pool.clients.get(client_id)
            if (
                current_pool.pool_id != pool_id
                or current_client is None
                or not hmac.compare_digest(current_user.sub, user_sub)
            ):
                _error("NotAuthorizedException", "Invalid access token")
            yield current_pool, current_client, current_user

    @handler("CreateUserPool", expand=False)
    def create_user_pool(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AccountRecoverySetting",
                "AdminCreateUserConfig",
                "AliasAttributes",
                "AutoVerifiedAttributes",
                "DeletionProtection",
                "DeviceConfiguration",
                "EmailConfiguration",
                "EmailVerificationMessage",
                "EmailVerificationSubject",
                "IssuerConfiguration",
                "KeyConfiguration",
                "LambdaConfig",
                "MfaConfiguration",
                "Policies",
                "PoolName",
                "Schema",
                "SmsAuthenticationMessage",
                "SmsVerificationMessage",
                "SmsConfiguration",
                "UserAttributeUpdateSettings",
                "UserPoolAddOns",
                "UsernameAttributes",
                "UsernameConfiguration",
                "UserPoolTags",
                "UserPoolTier",
                "VerificationMessageTemplate",
            },
        )
        name = _required_string(request, "PoolName", minimum=1, maximum=128)
        admin_configuration = _admin_create_user_configuration(request.get("AdminCreateUserConfig"))
        device_configuration = _device_configuration(request.get("DeviceConfiguration"))
        tags = _user_pool_tags(request.get("UserPoolTags"))
        security_configuration = _user_pool_security_configuration(
            request, context=context, include_create_only=True
        )
        _revalidate_pool_key(context, security_configuration["pool_configuration"])
        now = _now()
        access_key_id, access_private_key, access_jwk = generate_signing_key()
        id_key_id, id_private_key, id_jwk = generate_signing_key()
        with cognito_idp_stores.lock:
            store = self.get_store(context)
            if len(store.user_pools) >= _MAX_USER_POOLS_PER_ACCOUNT_REGION:
                _error("LimitExceededException", "User pool quota exceeded")
            while True:
                pool_id = (
                    f"{context.region}_"
                    f"{secrets.token_urlsafe(9).replace('-', 'A').replace('_', 'B')}"
                )
                if pool_id not in store.POOL_LOCATIONS:
                    break
            pool = UserPool(
                pool_id=pool_id,
                name=name,
                arn=f"arn:{context.partition}:cognito-idp:{context.region}:{context.account_id}:userpool/{pool_id}",
                created_at=now,
                updated_at=now,
                access_signing_key_id=access_key_id,
                access_signing_private_key_pem=access_private_key,
                access_signing_jwk=access_jwk,
                id_signing_key_id=id_key_id,
                id_signing_private_key_pem=id_private_key,
                id_signing_jwk=id_jwk,
                allow_admin_create_user_only=admin_configuration["allow_admin_create_user_only"],
                invite_message_template=admin_configuration["invite_message_template"],
                tags=tags,
                **device_configuration,
                **security_configuration,
            )
            _validate_pool_auth_policy(pool)
            store.user_pools[pool_id] = pool
            store.POOL_LOCATIONS[pool_id] = (context.account_id, context.region)
        return {"UserPool": _pool_response(pool)}

    @handler("DescribeUserPool", expand=False)
    def describe_user_pool(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            response = _pool_response(pool)
            primary_region = getattr(context, "_cognito_primary_region", context.region)
            if context.region != primary_region:
                response["Arn"] = (
                    f"arn:{context.partition}:cognito-idp:{context.region}:"
                    f"{context.account_id}:userpool/{pool.pool_id}"
                )
                topology = self.get_store(context).user_pool_replicas.get(pool.pool_id)
                replica = topology.secondary if topology is not None else None
                if replica is not None and replica.region_name == context.region:
                    response.update(copy.deepcopy(replica.regional_configuration))
            return {"UserPool": response}

    @handler("AddCustomAttributes", expand=False)
    def add_custom_attributes(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"CustomAttributes", "UserPoolId"})
        additions = _schema_attributes(request.get("CustomAttributes"), custom_only=True)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            existing = pool.schema_attributes or []
            existing_names = {_schema_attribute_storage_name(attribute) for attribute in existing}
            addition_names = {_schema_attribute_storage_name(attribute) for attribute in additions}
            if existing_names & addition_names:
                _error("InvalidParameterException", "Schema attribute already exists")
            existing_custom_count = sum(
                _schema_attribute_storage_name(attribute) not in _STANDARD_SCHEMA_ATTRIBUTES
                for attribute in existing
            )
            if existing_custom_count + len(additions) > _MAX_CUSTOM_ATTRIBUTES_PER_POOL:
                _error("LimitExceededException", "Custom attribute quota exceeded")
            pool.schema_attributes = [*existing, *copy.deepcopy(additions)]
            pool.updated_at = _now()
        return {}

    @handler("GetCSVHeader", expand=False)
    def get_csv_header(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserPoolId"})
        pool_id = request.get("UserPoolId")
        try:
            header = get_user_import_jobs(context.account_id, context.region).get_csv_header(
                pool_id
            )
        except ImportJobError as error:
            _error(error.code, error.message)
        return {"UserPoolId": pool_id, "CSVHeader": header}

    @handler("CreateUserImportJob", expand=False)
    def create_user_import_job(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"CloudWatchLogsRoleArn", "JobName", "PasswordHashingAlgorithm", "UserPoolId"},
        )
        try:
            job = get_user_import_jobs(context.account_id, context.region).create_job(
                request.get("UserPoolId"),
                request.get("JobName"),
                request.get("CloudWatchLogsRoleArn"),
                request.get("PasswordHashingAlgorithm"),
            )
        except ImportJobError as error:
            _error(error.code, error.message)
        return {"UserImportJob": job}

    @handler("DescribeUserImportJob", expand=False)
    def describe_user_import_job(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"JobId", "UserPoolId"})
        try:
            job = get_user_import_jobs(context.account_id, context.region).describe_job(
                request.get("UserPoolId"), request.get("JobId")
            )
        except ImportJobError as error:
            _error(error.code, error.message)
        return {"UserImportJob": job}

    @handler("ListUserImportJobs", expand=False)
    def list_user_import_jobs(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "PaginationToken", "UserPoolId"})
        try:
            return get_user_import_jobs(context.account_id, context.region).list_jobs(
                request.get("UserPoolId"),
                max_results=request.get("MaxResults"),
                pagination_token=request.get("PaginationToken"),
            )
        except ImportJobError as error:
            _error(error.code, error.message)

    @handler("StartUserImportJob", expand=False)
    def start_user_import_job(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"JobId", "UserPoolId"})
        try:
            job = get_user_import_jobs(context.account_id, context.region).start_job(
                request.get("UserPoolId"), request.get("JobId")
            )
        except ImportJobError as error:
            _error(error.code, error.message)
        return {"UserImportJob": job}

    @handler("StopUserImportJob", expand=False)
    def stop_user_import_job(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"JobId", "UserPoolId"})
        try:
            job = get_user_import_jobs(context.account_id, context.region).stop_job(
                request.get("UserPoolId"), request.get("JobId")
            )
        except ImportJobError as error:
            _error(error.code, error.message)
        return {"UserImportJob": job}

    @handler("UpdateUserPool", expand=False)
    def update_user_pool(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AccountRecoverySetting",
                "AdminCreateUserConfig",
                "AutoVerifiedAttributes",
                "DeletionProtection",
                "DeviceConfiguration",
                "EmailConfiguration",
                "EmailVerificationMessage",
                "EmailVerificationSubject",
                "IssuerConfiguration",
                "KeyConfiguration",
                "LambdaConfig",
                "MfaConfiguration",
                "Policies",
                "PoolName",
                "SmsAuthenticationMessage",
                "SmsVerificationMessage",
                "SmsConfiguration",
                "UserPoolId",
                "UserPoolTags",
                "UserPoolTier",
                "UserAttributeUpdateSettings",
                "UserPoolAddOns",
                "VerificationMessageTemplate",
            },
        )
        if set(request) == {"UserPoolId"}:
            _error("InvalidParameterException", "No user pool updates supplied")
        primary_region = getattr(context, "_cognito_primary_region", context.region)
        if context.region != primary_region:
            security_configuration = _user_pool_security_configuration(
                request, context=context, include_create_only=False
            )
            regional_configuration = {}
            for request_field, storage_field in (
                ("EmailConfiguration", "email_configuration"),
                ("LambdaConfig", "lambda_config"),
                ("SmsConfiguration", "sms_configuration"),
            ):
                if request_field in request:
                    regional_configuration[request_field] = copy.deepcopy(
                        security_configuration[storage_field]
                    )
            with self._locked_pool(context, request.get("UserPoolId")) as pool:
                topology = self.get_store(context).user_pool_replicas.get(pool.pool_id)
                replica = topology.secondary if topology is not None else None
                if replica is None or replica.region_name != context.region:
                    _error("ResourceNotFoundException", "User pool replica does not exist")
                replica.regional_configuration.update(regional_configuration)
                pool.updated_at = _now()
            return {}
        security_configuration = _user_pool_security_configuration(
            request, context=context, include_create_only=False
        )
        _revalidate_pool_key(context, security_configuration["pool_configuration"])
        device_configuration = _device_configuration(request.get("DeviceConfiguration"))
        admin_configuration = _admin_create_user_configuration(request.get("AdminCreateUserConfig"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            name = (
                _required_string(request, "PoolName", minimum=1, maximum=128)
                if "PoolName" in request
                else pool.name
            )
            tags = (
                _user_pool_tags(request["UserPoolTags"]) if "UserPoolTags" in request else pool.tags
            )
            prospective = copy.copy(pool)
            for field, value in security_configuration.items():
                setattr(prospective, field, value)
            _validate_pool_auth_policy(prospective)
            pool.name = name
            pool.allow_admin_create_user_only = admin_configuration["allow_admin_create_user_only"]
            pool.invite_message_template = admin_configuration["invite_message_template"]
            pool.tags = tags
            for field, value in {**device_configuration, **security_configuration}.items():
                setattr(pool, field, value)
            pool.updated_at = _now()
        return {}

    @handler("ListUserPools", expand=False)
    def list_user_pools(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken"})
        max_results = request.get("MaxResults", 60)
        if (
            not isinstance(max_results, int)
            or isinstance(max_results, bool)
            or not 1 <= max_results <= 60
        ):
            _error("InvalidParameterException", "MaxResults must be between 1 and 60")
        after = _decode_page_token(request.get("NextToken"), "pools")
        with cognito_idp_stores.lock:
            store = self.get_store(context)
            pools = sorted(store.user_pools.values(), key=lambda item: item.pool_id)
            page, next_token = _page_after(pools, max_results, after, lambda item: item.pool_id)
            summaries = []
            for pool in page:
                topology = store.user_pool_replicas.get(pool.pool_id)
                replica = reconcile_replica(topology) if topology is not None else None
                summary = user_pool_summary(
                    pool,
                    replica_regions=[] if replica is None else [replica.region_name],
                )
                summary["Status"] = "Enabled"
                summaries.append(summary)
            response = {"UserPools": summaries}
        if next_token is not None:
            response["NextToken"] = _encode_page_token("pools", next_token)
        return response

    @handler("CreateUserPoolReplica", expand=False)
    def create_user_pool_replica(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"RegionName", "UserPoolId", "UserPoolTags"})
        with self._locked_replica_topology(context, request.get("UserPoolId")) as (
            _,
            topology,
            primary_store,
        ):
            try:
                response = create_replica(
                    topology,
                    caller_region=context.region,
                    eligible=True,
                    region_name=request.get("RegionName"),
                    tags=request.get("UserPoolTags"),
                )
            except UserPoolReplicaError as error:
                _error(error.code, str(error))
            with cognito_idp_stores.lock:
                primary_store.user_pool_replicas[topology.pool_id] = topology
            return response

    @handler("ListUserPoolReplicas", expand=False)
    def list_user_pool_replicas(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"NextToken", "UserPoolId"})
        with self._locked_replica_topology(context, request.get("UserPoolId")) as (
            pool,
            topology,
            _,
        ):
            try:
                return list_replicas(
                    topology,
                    next_token=request.get("NextToken"),
                    signing_key=pool.id_signing_private_key_pem,
                )
            except UserPoolReplicaError as error:
                _error(error.code, str(error))

    @handler("UpdateUserPoolReplica", expand=False)
    def update_user_pool_replica(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"RegionName", "Status", "UserPoolId"})
        with self._locked_replica_topology(context, request.get("UserPoolId")) as (
            _,
            topology,
            _,
        ):
            try:
                return update_replica(
                    topology,
                    caller_region=context.region,
                    region_name=request.get("RegionName"),
                    status=request.get("Status"),
                )
            except UserPoolReplicaError as error:
                _error(error.code, str(error))

    @handler("DeleteUserPoolReplica", expand=False)
    def delete_user_pool_replica(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"RegionName", "UserPoolId"})
        with self._locked_replica_topology(context, request.get("UserPoolId")) as (
            _,
            topology,
            _,
        ):
            try:
                return delete_replica(
                    topology,
                    caller_region=context.region,
                    region_name=request.get("RegionName"),
                )
            except UserPoolReplicaError as error:
                _error(error.code, str(error))

    @handler("GetProvisionedLimit", expand=False)
    def get_provisioned_limit(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"LimitDefinition"})
        with cognito_idp_stores.lock:
            try:
                return get_local_provisioned_limit(
                    self.get_store(context).provisioned_limits,
                    account_id=context.account_id,
                    region=context.region,
                    definition=request.get("LimitDefinition"),
                )
            except ProvisionedLimitError as error:
                _error(error.code, str(error))

    @handler("UpdateProvisionedLimit", expand=False)
    def update_provisioned_limit(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"LimitDefinition", "RequestedLimitValue"})
        with cognito_idp_stores.lock:
            try:
                return update_local_provisioned_limit(
                    self.get_store(context).provisioned_limits,
                    account_id=context.account_id,
                    region=context.region,
                    definition=request.get("LimitDefinition"),
                    requested_value=request.get("RequestedLimitValue"),
                    account_maxima=_PROVISIONED_LIMIT_ACCOUNT_MAXIMA,
                )
            except ProvisionedLimitError as error:
                _error(error.code, str(error))

    @handler("DeleteUserPool", expand=False)
    def delete_user_pool(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            try:
                assert_pool_delete_allowed(pool.pool_configuration)
            except PoolConfigurationError as error:
                _error(error.code, str(error))
            get_user_import_jobs(context.account_id, context.region).cleanup_pool(pool.pool_id)
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                store.user_pools.pop(pool.pool_id, None)
                store.user_pool_replicas.pop(pool.pool_id, None)
                if store.POOL_LOCATIONS.get(pool.pool_id) == (
                    context.account_id,
                    context.region,
                ):
                    store.POOL_LOCATIONS.pop(pool.pool_id, None)
                for domain_name, domain in list(store.user_pool_domains.items()):
                    if domain.user_pool_id != pool.pool_id:
                        continue
                    store.user_pool_domains.pop(domain_name, None)
                    if store.DOMAIN_LOCATIONS.get(domain.local_hostname) == (
                        context.account_id,
                        context.region,
                    ):
                        store.DOMAIN_LOCATIONS.pop(domain.local_hostname, None)
                store.refresh_sessions = {
                    key: session
                    for key, session in store.refresh_sessions.items()
                    if session.pool_id != pool.pool_id
                }
                _remove_oauth_browser_state(store, pool.pool_id)
                _remove_auth_challenge_state(store, pool_id=pool.pool_id)
                _mfa_passwordless_engine(store, pool).cleanup(pool_id=pool.pool_id)
                store.user_codes = {
                    key: state
                    for key, state in store.user_codes.items()
                    if state.pool_id != pool.pool_id
                }
                store.login_attempt_windows = {
                    key: window
                    for key, window in store.login_attempt_windows.items()
                    if window.pool_id != pool.pool_id
                }
                store.auth_events = {
                    key: event
                    for key, event in store.auth_events.items()
                    if event.pool_id != pool.pool_id
                }
                store.log_delivery_configurations.pop(pool.pool_id, None)
                FriendlyDeviceNames(
                    store.friendly_device_names, lock=cognito_idp_stores.lock
                ).remove_pool(pool.pool_id)
        return {}

    @handler("CreateUserPoolDomain", expand=False)
    def create_user_pool_domain(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Domain", "ManagedLoginVersion", "UserPoolId"})
        domain_name = _domain_name(request.get("Domain"))
        managed_login_version = _managed_login_version(request.get("ManagedLoginVersion"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            local_hostname = _local_domain_hostname(domain_name)
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                if any(
                    domain.user_pool_id == pool.pool_id
                    for domain in store.user_pool_domains.values()
                ):
                    _error(
                        "InvalidParameterException",
                        f"User pool {pool.pool_id} already has a prefix domain",
                    )
                if local_hostname in store.DOMAIN_LOCATIONS:
                    _error("InvalidParameterException", f"Domain {domain_name} already exists")
                now = _now()
                domain = UserPoolDomain(
                    domain=domain_name,
                    local_hostname=local_hostname,
                    user_pool_id=pool.pool_id,
                    account_id=context.account_id,
                    region=context.region,
                    managed_login_version=managed_login_version,
                    created_at=now,
                    updated_at=now,
                )
                store.user_pool_domains[domain_name] = domain
                store.DOMAIN_LOCATIONS[local_hostname] = (context.account_id, context.region)
                pool.updated_at = now
        return {"ManagedLoginVersion": managed_login_version}

    @handler("DescribeUserPoolDomain", expand=False)
    def describe_user_pool_domain(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Domain"})
        domain_name = _domain_name(request.get("Domain"))
        with cognito_idp_stores.lock:
            domain = self._domain(context, domain_name)
            return {"DomainDescription": _domain_response(domain)}

    @handler("UpdateUserPoolDomain", expand=False)
    def update_user_pool_domain(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Domain", "ManagedLoginVersion", "UserPoolId"})
        domain_name = _domain_name(request.get("Domain"))
        managed_login_version = _managed_login_version(request.get("ManagedLoginVersion"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            with cognito_idp_stores.lock:
                domain = self._domain(context, domain_name)
                if domain.user_pool_id != pool.pool_id:
                    _error("ResourceNotFoundException", f"Domain {domain_name} does not exist")
                if domain.managed_login_version != managed_login_version:
                    _remove_oauth_browser_state(self.get_store(context), pool.pool_id)
                domain.managed_login_version = managed_login_version
                domain.updated_at = pool.updated_at = _now()
        return {"ManagedLoginVersion": managed_login_version}

    @handler("DeleteUserPoolDomain", expand=False)
    def delete_user_pool_domain(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Domain", "UserPoolId"})
        domain_name = _domain_name(request.get("Domain"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                domain = self._domain(context, domain_name)
                if domain.user_pool_id != pool.pool_id:
                    _error("ResourceNotFoundException", f"Domain {domain_name} does not exist")
                store.user_pool_domains.pop(domain_name, None)
                if store.DOMAIN_LOCATIONS.get(domain.local_hostname) == (
                    context.account_id,
                    context.region,
                ):
                    store.DOMAIN_LOCATIONS.pop(domain.local_hostname, None)
                _remove_oauth_browser_state(store, pool.pool_id)
                pool.updated_at = _now()
        return {}

    @handler("GetUICustomization", expand=False)
    def get_ui_customization(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client_id = _ui_customization_client_id(request.get("ClientId"))
            if client_id != "ALL":
                self._client(pool, client_id)
            _require_user_pool_domain(self.get_store(context), pool.pool_id)
            item = inherited_customization(pool.ui_customizations, client_id)
            return {
                "UICustomization": (
                    customization_response(pool.pool_id, item) if item is not None else {}
                )
            }

    @handler("SetUICustomization", expand=False)
    def set_ui_customization(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"CSS", "ClientId", "ImageFile", "UserPoolId"})
        try:
            css, image = validate_classic_ui_update(
                css=request.get("CSS", ""),
                image=request.get("ImageFile", b""),
                css_supplied=True,
                image_supplied=True,
            )
        except ClassicUIError as error:
            _error("InvalidParameterException", str(error))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client_id = _ui_customization_client_id(request.get("ClientId"))
            if client_id != "ALL":
                self._client(pool, client_id)
            _require_user_pool_domain(self.get_store(context), pool.pool_id)
            now = _now()
            current = pool.ui_customizations.get(client_id)
            item = apply_classic_ui_update(
                current,
                client_id=client_id,
                css=css,
                image=image,
                css_supplied=True,
                image_supplied=True,
                image_url=None,
                now=now,
            )
            if item.image is not None:
                item.image_url = safe_image_path(
                    pool.pool_id,
                    client_id,
                    item.css_version,
                    item.image_extension or "",
                )
            pool.ui_customizations[client_id] = item
            pool.updated_at = now
            return {"UICustomization": customization_response(pool.pool_id, item)}

    @handler("CreateManagedLoginBranding", expand=False)
    def create_managed_login_branding(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"Assets", "ClientId", "Settings", "UseCognitoProvidedValues", "UserPoolId"},
        )
        use_defaults, settings, assets = _managed_login_branding_update(request, creating=True)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            if client.client_id in pool.managed_login_branding:
                _error(
                    "ManagedLoginBrandingExistsException",
                    "A managed login branding style already exists for this app client",
                )
            if len(pool.managed_login_branding) >= _MAX_MANAGED_LOGIN_BRANDING_PER_POOL:
                _error("LimitExceededException", "Managed login branding quota exceeded")
            now = _now()
            branding = ManagedLoginBranding(
                branding_id=str(uuid.uuid4()),
                client_id=client.client_id,
                use_cognito_provided_values=use_defaults,
                settings=settings or {},
                assets=_managed_login_asset_map(assets or [], existing={}),
                created_at=now,
                updated_at=now,
            )
            pool.managed_login_branding[client.client_id] = branding
            pool.updated_at = now
            return {"ManagedLoginBranding": _managed_login_branding_response(pool, branding)}

    @handler("DescribeManagedLoginBranding", expand=False)
    def describe_managed_login_branding(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"ManagedLoginBrandingId", "ReturnMergedResources", "UserPoolId"}
        )
        merged = _optional_boolean(request, "ReturnMergedResources", False)
        branding_id = _uuid4(request.get("ManagedLoginBrandingId"), "ManagedLoginBrandingId")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            branding = _managed_login_branding_by_id(pool, branding_id)
            return {
                "ManagedLoginBranding": _managed_login_branding_response(
                    pool, branding, merged=merged
                )
            }

    @handler("DescribeManagedLoginBrandingByClient", expand=False)
    def describe_managed_login_branding_by_client(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "ReturnMergedResources", "UserPoolId"})
        merged = _optional_boolean(request, "ReturnMergedResources", False)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            branding = pool.managed_login_branding.get(client.client_id)
            if branding is None:
                _error("ResourceNotFoundException", "Managed login branding not found")
            return {
                "ManagedLoginBranding": _managed_login_branding_response(
                    pool, branding, merged=merged
                )
            }

    @handler("UpdateManagedLoginBranding", expand=False)
    def update_managed_login_branding(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "Assets",
                "ManagedLoginBrandingId",
                "Settings",
                "UseCognitoProvidedValues",
                "UserPoolId",
            },
        )
        branding_id = _uuid4(request.get("ManagedLoginBrandingId"), "ManagedLoginBrandingId")
        use_defaults, settings, assets = _managed_login_branding_update(request, creating=False)
        if not ({"Assets", "Settings", "UseCognitoProvidedValues"} & set(request)):
            _error("InvalidParameterException", "No branding updates supplied")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            branding = _managed_login_branding_by_id(pool, branding_id)
            if use_defaults:
                next_settings: dict[str, Any] = {}
                next_assets: dict[str, ManagedLoginAsset] = {}
            else:
                next_settings = (
                    _deep_merge(branding.settings, settings)
                    if settings is not None
                    else copy.deepcopy(branding.settings)
                )
                next_assets = (
                    _managed_login_asset_map(assets, existing=branding.assets)
                    if assets is not None
                    else copy.deepcopy(branding.assets)
                )
            if len(next_assets) > _MAX_MANAGED_LOGIN_ASSETS:
                _error("LimitExceededException", "Managed login asset quota exceeded")
            branding.use_cognito_provided_values = use_defaults
            branding.settings = next_settings
            branding.assets = next_assets
            branding.updated_at = pool.updated_at = _now()
            return {"ManagedLoginBranding": _managed_login_branding_response(pool, branding)}

    @handler("DeleteManagedLoginBranding", expand=False)
    def delete_managed_login_branding(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ManagedLoginBrandingId", "UserPoolId"})
        branding_id = _uuid4(request.get("ManagedLoginBrandingId"), "ManagedLoginBrandingId")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            branding = _managed_login_branding_by_id(pool, branding_id)
            pool.managed_login_branding.pop(branding.client_id, None)
            pool.updated_at = _now()
        return {}

    @handler("CreateTerms", expand=False)
    def create_terms(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "ClientId",
                "Enforcement",
                "Links",
                "TermsName",
                "TermsSource",
                "UserPoolId",
            },
        )
        terms_name, source, enforcement, links = _terms_values(request, creating=True)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            if any(
                item.client_id == client.client_id and item.terms_name == terms_name
                for item in pool.terms.values()
            ):
                _error("TermsExistsException", "Terms already exist for this app client")
            if len(pool.terms) >= _MAX_TERMS_PER_POOL:
                _error("LimitExceededException", "Terms quota exceeded")
            now = _now()
            item = CognitoTerms(
                terms_id=str(uuid.uuid4()),
                client_id=client.client_id,
                terms_name=terms_name,
                terms_source=source,
                enforcement=enforcement,
                links=links,
                created_at=now,
                updated_at=now,
                version=str(uuid.uuid4()),
            )
            pool.terms[item.terms_id] = item
            pool.updated_at = now
            return {"Terms": _terms_response(pool, item)}

    @handler("DescribeTerms", expand=False)
    def describe_terms(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"TermsId", "UserPoolId"})
        terms_id = _uuid4(request.get("TermsId"), "TermsId")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return {"Terms": _terms_response(pool, _terms(pool, terms_id))}

    @handler("UpdateTerms", expand=False)
    def update_terms(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"Enforcement", "Links", "TermsId", "TermsName", "TermsSource", "UserPoolId"},
        )
        terms_id = _uuid4(request.get("TermsId"), "TermsId")
        if not ({"Enforcement", "Links", "TermsName", "TermsSource"} & set(request)):
            _error("InvalidParameterException", "No terms updates supplied")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            item = _terms(pool, terms_id)
            terms_name, source, enforcement, links = _terms_values(
                request, creating=False, current=item
            )
            if terms_name != item.terms_name and any(
                candidate.terms_id != item.terms_id
                and candidate.client_id == item.client_id
                and candidate.terms_name == terms_name
                for candidate in pool.terms.values()
            ):
                _error("TermsExistsException", "Terms already exist for this app client")
            item.terms_name = terms_name
            item.terms_source = source
            item.enforcement = enforcement
            item.links = links
            item.updated_at = pool.updated_at = _now()
            item.version = str(uuid.uuid4())
            return {"Terms": _terms_response(pool, item)}

    @handler("DeleteTerms", expand=False)
    def delete_terms(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"TermsId", "UserPoolId"})
        terms_id = _uuid4(request.get("TermsId"), "TermsId")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            _terms(pool, terms_id)
            pool.terms.pop(terms_id, None)
            pool.updated_at = _now()
        return {}

    @handler("ListTerms", expand=False)
    def list_terms(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken", "UserPoolId"})
        maximum = request.get("MaxResults", 60)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 60:
            _error("InvalidParameterException", "MaxResults must be between 1 and 60")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            kind = "terms"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            items = sorted(pool.terms.values(), key=lambda item: item.terms_id)
            page, next_after = _page_after(items, maximum, after, lambda item: item.terms_id)
            response: ServiceResponse = {"Terms": [_terms_description(item) for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("CreateResourceServer", expand=False)
    def create_resource_server(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Identifier", "Name", "Scopes", "UserPoolId"})
        identifier = _resource_server_identifier(request.get("Identifier"))
        name = _resource_server_name(request.get("Name"))
        scopes = _resource_server_scopes(request.get("Scopes"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            if identifier in pool.resource_servers:
                _error("InvalidParameterException", "Resource server already exists")
            if len(pool.resource_servers) >= _MAX_RESOURCE_SERVERS_PER_POOL:
                _error("LimitExceededException", "Resource server quota exceeded")
            server = CognitoResourceServer(identifier=identifier, name=name, scopes=scopes)
            pool.resource_servers[identifier] = server
            pool.updated_at = _now()
            return {"ResourceServer": _resource_server_response(pool, server)}

    @handler("DescribeResourceServer", expand=False)
    def describe_resource_server(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Identifier", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            server = _resource_server(pool, request.get("Identifier"))
            return {"ResourceServer": _resource_server_response(pool, server)}

    @handler("UpdateResourceServer", expand=False)
    def update_resource_server(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Identifier", "Name", "Scopes", "UserPoolId"})
        identifier = _resource_server_identifier(request.get("Identifier"))
        name = _resource_server_name(request.get("Name"))
        scopes = _resource_server_scopes(request.get("Scopes"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            server = _resource_server(pool, identifier)
            server.name = name
            server.scopes = scopes
            pool.updated_at = _now()
            return {"ResourceServer": _resource_server_response(pool, server)}

    @handler("DeleteResourceServer", expand=False)
    def delete_resource_server(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Identifier", "UserPoolId"})
        identifier = _resource_server_identifier(request.get("Identifier"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            _resource_server(pool, identifier)
            pool.resource_servers.pop(identifier)
            pool.updated_at = _now()
        return {}

    @handler("ListResourceServers", expand=False)
    def list_resource_servers(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken", "UserPoolId"})
        max_results = request.get("MaxResults", 50)
        if (
            not isinstance(max_results, int)
            or isinstance(max_results, bool)
            or not 1 <= max_results <= 50
        ):
            _error("InvalidParameterException", "MaxResults must be between 1 and 50")
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            kind = "resource-servers"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            servers = sorted(pool.resource_servers.values(), key=lambda server: server.identifier)
            page, next_after = _page_after(
                servers, max_results, after, lambda server: server.identifier
            )
            response: ServiceResponse = {
                "ResourceServers": [_resource_server_response(pool, server) for server in page]
            }
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn", "Tags"})
        pool = self._pool_for_resource_arn(context, request.get("ResourceArn"))
        tags = _user_pool_tags(request.get("Tags"))
        with self._locked_pool(context, pool.pool_id) as current_pool:
            merged = {**current_pool.tags, **tags}
            if len(merged) > _MAX_TAGS_PER_POOL:
                _error("LimitExceededException", "User pool tag quota exceeded")
            current_pool.tags = merged
            current_pool.updated_at = _now()
        return {}

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn", "TagKeys"})
        pool = self._pool_for_resource_arn(context, request.get("ResourceArn"))
        tag_keys = _tag_keys(request.get("TagKeys"))
        with self._locked_pool(context, pool.pool_id) as current_pool:
            for tag_key in tag_keys:
                current_pool.tags.pop(tag_key, None)
            current_pool.updated_at = _now()
        return {}

    @handler("ListTagsForResource", expand=False)
    def list_tags_for_resource(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn"})
        pool = self._pool_for_resource_arn(context, request.get("ResourceArn"))
        with self._locked_pool(context, pool.pool_id) as current_pool:
            return {"Tags": dict(sorted(current_pool.tags.items()))}

    @handler("CreateUserPoolClient", expand=False)
    def create_user_pool_client(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AccessTokenValidity",
                "AllowedOAuthFlows",
                "AllowedOAuthFlowsUserPoolClient",
                "AllowedOAuthScopes",
                "AnalyticsConfiguration",
                "AuthSessionValidity",
                "CallbackURLs",
                "ClientSecret",
                "ClientName",
                "DefaultRedirectURI",
                "EnablePropagateAdditionalUserContextData",
                "EnableTokenRevocation",
                "ExplicitAuthFlows",
                "GenerateSecret",
                "IdTokenValidity",
                "LogoutURLs",
                "PreventUserExistenceErrors",
                "RefreshTokenValidity",
                "RefreshTokenRotation",
                "ReadAttributes",
                "SupportedIdentityProviders",
                "TokenValidityUnits",
                "UserPoolId",
                "WriteAttributes",
            },
        )
        analytics_configuration = (
            _client_analytics_configuration(context, request["AnalyticsConfiguration"])
            if "AnalyticsConfiguration" in request
            else None
        )
        enable_propagate_context = _propagate_additional_user_context_data(
            request.get("EnablePropagateAdditionalUserContextData"),
            has_client_secret=(
                request.get("GenerateSecret") is True or request.get("ClientSecret") is not None
            ),
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            if len(pool.clients) >= _MAX_CLIENTS_PER_POOL:
                _error("LimitExceededException", "User pool client quota exceeded")
            name = _required_string(request, "ClientName", minimum=1, maximum=128)
            auth_flows = _auth_flows(request.get("ExplicitAuthFlows"))
            generate_secret = request.get("GenerateSecret", False)
            if not isinstance(generate_secret, bool):
                _error("InvalidParameterException", "GenerateSecret must be a boolean")
            supplied_secret = request.get("ClientSecret")
            if supplied_secret is not None:
                supplied_secret = _client_secret_value(supplied_secret)
                if generate_secret:
                    _error(
                        "InvalidParameterException",
                        "ClientSecret and GenerateSecret cannot both be supplied",
                    )
            creation_secret = (
                supplied_secret
                if supplied_secret is not None
                else _generate_client_secret()
                if generate_secret
                else None
            )
            validity_units = _token_validity_units(request.get("TokenValidityUnits"))
            if request.get("RefreshTokenValidity") == 0:
                validity_units["RefreshToken"] = "days"
            access_validity = _token_validity(
                request,
                "AccessTokenValidity",
                default=1,
                unit=validity_units["AccessToken"],
                minimum_seconds=5 * 60,
                maximum_seconds=24 * 60 * 60,
            )
            id_validity = _token_validity(
                request,
                "IdTokenValidity",
                default=1,
                unit=validity_units["IdToken"],
                minimum_seconds=5 * 60,
                maximum_seconds=24 * 60 * 60,
            )
            refresh_validity = _token_validity(
                request,
                "RefreshTokenValidity",
                default=30,
                unit=validity_units["RefreshToken"],
                minimum_seconds=60 * 60,
                maximum_seconds=10 * 365 * 24 * 60 * 60,
                zero_means_default=True,
            )
            oauth = _oauth_client_configuration(request, pool=pool)
            rotation_enabled, rotation_grace = _refresh_token_rotation(
                request.get("RefreshTokenRotation")
            )
            prevent_user_existence_errors = _prevent_user_existence_errors(
                request.get("PreventUserExistenceErrors")
            )
            now = _now()
            client = UserPoolClient(
                client_id=secrets.token_urlsafe(19).replace("-", "a").replace("_", "b"),
                name=name,
                created_at=now,
                updated_at=now,
                secret=None,
                explicit_auth_flows=auth_flows,
                analytics_configuration=analytics_configuration,
                enable_propagate_additional_user_context_data=enable_propagate_context,
                prevent_user_existence_errors=prevent_user_existence_errors,
                access_token_validity=access_validity,
                access_token_validity_unit=validity_units["AccessToken"],
                id_token_validity=id_validity,
                id_token_validity_unit=validity_units["IdToken"],
                refresh_token_validity=refresh_validity,
                refresh_token_validity_unit=validity_units["RefreshToken"],
                refresh_token_rotation_enabled=rotation_enabled,
                refresh_token_rotation_grace_seconds=rotation_grace,
                auth_session_validity=_auth_session_validity(
                    request.get("AuthSessionValidity"), default=3
                ),
                **oauth,
            )
            if creation_secret is not None:
                secret_id = _primary_client_secret_id(client)
                client.primary_secret = UserPoolClientSecret(
                    secret_id=secret_id,
                    encrypted_value=_encrypt_client_state(
                        pool,
                        creation_secret,
                        f"client-secret:{client.client_id}:{secret_id}",
                    ),
                    created_at=now,
                )
            pool.clients[client.client_id] = client
            pool.updated_at = now
            return {
                "UserPoolClient": _client_response(pool, client, creation_secret=creation_secret)
            }

    @handler("DescribeUserPoolClient", expand=False)
    def describe_user_pool_client(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            return {"UserPoolClient": _client_response(pool, client)}

    @handler("ListUserPoolClients", expand=False)
    def list_user_pool_clients(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            max_results = request.get("MaxResults", 60)
            if (
                not isinstance(max_results, int)
                or isinstance(max_results, bool)
                or not 1 <= max_results <= 60
            ):
                _error("InvalidParameterException", "MaxResults must be between 1 and 60")
            after = _decode_page_token(request.get("NextToken"), f"clients:{pool.pool_id}")
            clients = sorted(pool.clients.values(), key=lambda item: item.client_id)
            page, next_token = _page_after(clients, max_results, after, lambda item: item.client_id)
            response = {
                "UserPoolClients": [
                    {
                        "ClientId": client.client_id,
                        "ClientName": client.name,
                        "UserPoolId": pool.pool_id,
                    }
                    for client in page
                ]
            }
            if next_token is not None:
                response["NextToken"] = _encode_page_token(f"clients:{pool.pool_id}", next_token)
            return response

    @handler("UpdateUserPoolClient", expand=False)
    def update_user_pool_client(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AllowedOAuthFlows",
                "AccessTokenValidity",
                "AllowedOAuthFlowsUserPoolClient",
                "AllowedOAuthScopes",
                "AnalyticsConfiguration",
                "AuthSessionValidity",
                "CallbackURLs",
                "ClientId",
                "ClientName",
                "DefaultRedirectURI",
                "EnablePropagateAdditionalUserContextData",
                "EnableTokenRevocation",
                "ExplicitAuthFlows",
                "IdTokenValidity",
                "LogoutURLs",
                "PreventUserExistenceErrors",
                "ReadAttributes",
                "RefreshTokenValidity",
                "RefreshTokenRotation",
                "SupportedIdentityProviders",
                "TokenValidityUnits",
                "UserPoolId",
                "WriteAttributes",
            },
        )
        pool_id = request.get("UserPoolId")
        client_id = request.get("ClientId")
        with self._locked_pool(context, pool_id) as pool:
            current_client = self._client(pool, client_id)
            expected_updated_at = current_client.updated_at
            has_client_secret = _client_has_secret(current_client)
        analytics_configuration = (
            _client_analytics_configuration(context, request["AnalyticsConfiguration"])
            if "AnalyticsConfiguration" in request
            else None
        )
        enable_propagate_context = _propagate_additional_user_context_data(
            request.get("EnablePropagateAdditionalUserContextData"),
            has_client_secret=has_client_secret,
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            if client.updated_at != expected_updated_at:
                _error(
                    "ResourceConflictException",
                    "User pool client changed during analytics validation",
                )
            oauth = _oauth_client_configuration(request, pool=pool)
            name = (
                _required_string(request, "ClientName", minimum=1, maximum=128)
                if "ClientName" in request
                else client.name
            )
            explicit_auth_flows = (
                _auth_flows(request["ExplicitAuthFlows"])
                if "ExplicitAuthFlows" in request
                else _auth_flows(None)
            )
            prevent_user_existence_errors = (
                _prevent_user_existence_errors(request["PreventUserExistenceErrors"])
                if "PreventUserExistenceErrors" in request
                else _prevent_user_existence_errors(None)
            )
            validity_units = _token_validity_units(request.get("TokenValidityUnits"))
            if request.get("RefreshTokenValidity") == 0:
                validity_units["RefreshToken"] = "days"
            access_validity = _token_validity(
                request,
                "AccessTokenValidity",
                default=1,
                unit=validity_units["AccessToken"],
                minimum_seconds=5 * 60,
                maximum_seconds=24 * 60 * 60,
            )
            id_validity = _token_validity(
                request,
                "IdTokenValidity",
                default=1,
                unit=validity_units["IdToken"],
                minimum_seconds=5 * 60,
                maximum_seconds=24 * 60 * 60,
            )
            refresh_validity = _token_validity(
                request,
                "RefreshTokenValidity",
                default=30,
                unit=validity_units["RefreshToken"],
                minimum_seconds=60 * 60,
                maximum_seconds=10 * 365 * 24 * 60 * 60,
                zero_means_default=True,
            )
            rotation_enabled, rotation_grace = _refresh_token_rotation(
                request.get("RefreshTokenRotation")
            )
            client.name = name
            client.explicit_auth_flows = explicit_auth_flows
            client.analytics_configuration = analytics_configuration
            client.enable_propagate_additional_user_context_data = enable_propagate_context
            client.prevent_user_existence_errors = prevent_user_existence_errors
            client.access_token_validity = access_validity
            client.access_token_validity_unit = validity_units["AccessToken"]
            client.id_token_validity = id_validity
            client.id_token_validity_unit = validity_units["IdToken"]
            client.refresh_token_validity = refresh_validity
            client.refresh_token_validity_unit = validity_units["RefreshToken"]
            client.refresh_token_rotation_enabled = rotation_enabled
            client.refresh_token_rotation_grace_seconds = rotation_grace
            client.auth_session_validity = _auth_session_validity(
                request.get("AuthSessionValidity"),
                default=getattr(client, "auth_session_validity", 3),
            )
            for field, value in oauth.items():
                setattr(client, field, value)
            client.updated_at = pool.updated_at = _now()
            return {"UserPoolClient": _client_response(pool, client)}

    @handler("DeleteUserPoolClient", expand=False)
    def delete_user_pool_client(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            pool.clients.pop(client.client_id, None)
            pool.managed_login_branding.pop(client.client_id, None)
            pool.ui_customizations.pop(client.client_id, None)
            pool.terms = {
                terms_id: item
                for terms_id, item in pool.terms.items()
                if item.client_id != client.client_id
            }
            pool.updated_at = _now()
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                store.refresh_sessions = {
                    key: session
                    for key, session in store.refresh_sessions.items()
                    if session.client_id != client.client_id
                }
                store.browser_transactions = {
                    key: transaction
                    for key, transaction in store.browser_transactions.items()
                    if transaction.client_id != client.client_id
                }
                store.authorization_codes = {
                    key: code
                    for key, code in store.authorization_codes.items()
                    if code.client_id != client.client_id
                }
                store.federation_transactions = {
                    key: transaction
                    for key, transaction in store.federation_transactions.items()
                    if transaction.client_id != client.client_id
                }
                _remove_auth_challenge_state(store, client_id=client.client_id)
                CustomAuthManager(
                    store.custom_auth, lambda _: b"cleanup-only-custom-auth-key" * 2
                ).cleanup_client(pool.pool_id, client.client_id)
                _mfa_passwordless_engine(store, pool, client).cleanup_client(
                    pool_id=pool.pool_id, client_id=client.client_id
                )
                store.user_codes = {
                    key: state
                    for key, state in store.user_codes.items()
                    if state.client_id != client.client_id
                }
        return {}

    @handler("GetSigningCertificate", expand=False)
    def get_signing_certificate(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return {"Certificate": saml_signing_certificate(pool)}

    @handler("CreateIdentityProvider", expand=False)
    def create_identity_provider(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AttributeMapping",
                "IdpIdentifiers",
                "ProviderDetails",
                "ProviderName",
                "ProviderType",
                "UserPoolId",
            },
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            name = _identity_provider_name(request.get("ProviderName"))
            if name in pool.identity_providers:
                _error("DuplicateProviderException", f"Identity provider {name} already exists")
            if len(pool.identity_providers) >= _MAX_IDENTITY_PROVIDERS_PER_POOL:
                _error("LimitExceededException", "Identity provider quota exceeded")
            provider_type = request.get("ProviderType")
            if provider_type not in {
                "OIDC",
                "SAML",
                "Google",
                "Facebook",
                "LoginWithAmazon",
                "SignInWithApple",
            }:
                _error("InvalidParameterException", "Unsupported identity provider type")
            if (
                provider_type
                in {
                    "Google",
                    "Facebook",
                    "LoginWithAmazon",
                    "SignInWithApple",
                }
                and name != provider_type
            ):
                _error(
                    "InvalidParameterException",
                    "Social identity-provider name must match ProviderType",
                )
            details, secret = _identity_provider_details(
                provider_type, request.get("ProviderDetails")
            )
            if provider_type == "SAML" and details["EncryptedResponses"] == "true":
                secret, certificate = generate_saml_encryption_material(name)
                details["ActiveEncryptionCertificate"] = certificate
            mapping = _identity_provider_attribute_mapping(
                pool, request.get("AttributeMapping"), provider_type=provider_type
            )
            identifiers = _identity_provider_identifiers(pool, name, request.get("IdpIdentifiers"))
            metadata = None
            if provider_type == "SAML":
                try:
                    metadata = saml_metadata(details)
                except SamlFederationError as error:
                    _error("InvalidParameterException", str(error))
                if metadata["want_authn_requests_signed"] and (
                    details.get("RequestSigningAlgorithm") != "rsa-sha256"
                ):
                    _error(
                        "InvalidParameterException",
                        "SAML metadata requires signed AuthnRequests",
                    )
            now = _now()
            provider = CognitoIdentityProvider(
                pool_id=pool.pool_id,
                provider_name=name,
                provider_type=provider_type,
                provider_details=details,
                encrypted_client_secret=_encrypt_client_state(
                    pool, secret, f"identity-provider-secret:{name}"
                ),
                attribute_mapping=mapping,
                idp_identifiers=identifiers,
                created_at=now,
                updated_at=now,
                discovery_document=metadata,
                discovery_expires_at=(now + timedelta(hours=6) if metadata else None),
            )
            pool.identity_providers[name] = provider
            pool.updated_at = now
            return {"IdentityProvider": _identity_provider_response(pool, provider)}

    @handler("DescribeIdentityProvider", expand=False)
    def describe_identity_provider(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ProviderName", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            provider = _identity_provider(pool, request.get("ProviderName"))
            return {"IdentityProvider": _identity_provider_response(pool, provider)}

    @handler("UpdateIdentityProvider", expand=False)
    def update_identity_provider(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AttributeMapping",
                "IdpIdentifiers",
                "ProviderDetails",
                "ProviderName",
                "UserPoolId",
            },
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            provider = _identity_provider(pool, request.get("ProviderName"))
            if "ProviderDetails" in request:
                details, secret = _identity_provider_details(
                    provider.provider_type, request.get("ProviderDetails")
                )
                if provider.provider_type == "SAML" and details["EncryptedResponses"] == "true":
                    if provider.provider_details.get("EncryptedResponses") == "true":
                        secret = _identity_provider_client_secret(pool, provider)
                        details["ActiveEncryptionCertificate"] = provider.provider_details[
                            "ActiveEncryptionCertificate"
                        ]
                    else:
                        secret, certificate = generate_saml_encryption_material(
                            provider.provider_name
                        )
                        details["ActiveEncryptionCertificate"] = certificate
            else:
                details = dict(provider.provider_details)
                secret = _identity_provider_client_secret(pool, provider)
            mapping = (
                _identity_provider_attribute_mapping(
                    pool,
                    request.get("AttributeMapping"),
                    provider_type=provider.provider_type,
                )
                if "AttributeMapping" in request
                else dict(provider.attribute_mapping)
            )
            identifiers = (
                _identity_provider_identifiers(
                    pool, provider.provider_name, request.get("IdpIdentifiers")
                )
                if "IdpIdentifiers" in request
                else list(provider.idp_identifiers)
            )
            metadata = provider.discovery_document if provider.provider_type == "SAML" else None
            metadata_expires_at = (
                provider.discovery_expires_at if provider.provider_type == "SAML" else None
            )
            if provider.provider_type == "SAML" and "ProviderDetails" in request:
                try:
                    metadata = saml_metadata(details)
                except SamlFederationError as error:
                    _error("InvalidParameterException", str(error))
                if metadata["want_authn_requests_signed"] and (
                    details.get("RequestSigningAlgorithm") != "rsa-sha256"
                ):
                    _error(
                        "InvalidParameterException",
                        "SAML metadata requires signed AuthnRequests",
                    )
                metadata_expires_at = _now() + timedelta(hours=6)
            now = _now()
            provider.provider_details = details
            provider.encrypted_client_secret = _encrypt_client_state(
                pool, secret, f"identity-provider-secret:{provider.provider_name}"
            )
            provider.attribute_mapping = mapping
            provider.idp_identifiers = identifiers
            provider.discovery_document = metadata
            provider.discovery_expires_at = metadata_expires_at
            provider.jwks_document = None
            provider.jwks_expires_at = None
            provider.updated_at = pool.updated_at = now
            return {"IdentityProvider": _identity_provider_response(pool, provider)}

    @handler("DeleteIdentityProvider", expand=False)
    def delete_identity_provider(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ProviderName", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            provider = _identity_provider(pool, request.get("ProviderName"))
            pool.identity_providers.pop(provider.provider_name, None)
            pool.updated_at = _now()
        return {}

    @handler("ListIdentityProviders", expand=False)
    def list_identity_providers(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            limit = _list_limit(request.get("MaxResults"))
            kind = f"identity-providers:{pool.pool_id}"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            providers = sorted(
                pool.identity_providers.values(), key=lambda item: item.provider_name
            )
            page, next_after = _page_after(providers, limit, after, lambda item: item.provider_name)
            response = {"Providers": [_identity_provider_description(item) for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("GetIdentityProviderByIdentifier", expand=False)
    def get_identity_provider_by_identifier(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdpIdentifier", "UserPoolId"})
        identifier = _required_string(request, "IdpIdentifier", minimum=1, maximum=40)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            matches = [
                provider
                for provider in pool.identity_providers.values()
                if identifier in provider.idp_identifiers
            ]
            if len(matches) != 1:
                _error("ResourceNotFoundException", "Identity provider identifier does not exist")
            return {"IdentityProvider": _identity_provider_response(pool, matches[0])}

    @handler("AdminLinkProviderForUser", expand=False)
    def admin_link_provider_for_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"DestinationUser", "SourceUser", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            destination = _provider_user_identifier(request.get("DestinationUser"))
            source = _provider_user_identifier(request.get("SourceUser"))
            if destination["ProviderName"] != "Cognito":
                _error(
                    "InvalidParameterException",
                    "Only Cognito destination users are implemented",
                )
            user = self._user(pool, destination["ProviderAttributeValue"])
            provider = _identity_provider(pool, source["ProviderName"])
            source_attribute = source["ProviderAttributeName"]
            if (
                provider.provider_type
                in {
                    "Google",
                    "Facebook",
                    "LoginWithAmazon",
                    "SignInWithApple",
                }
                and source_attribute != "Cognito_Subject"
            ):
                _error(
                    "InvalidParameterException",
                    "Social providers require ProviderAttributeName Cognito_Subject",
                )
            if source_attribute != "Cognito_Subject" and source_attribute not in {
                *provider.attribute_mapping,
            }:
                _error("InvalidParameterException", "Source attribute is not mapped by the IdP")
            if any(
                definition.get("Mutable") is False and name in user.attributes
                for name, definition in _schema_definitions(pool).items()
                if name.startswith(("custom:", "dev:"))
            ):
                _error("InvalidParameterException", "Destination user has immutable attributes")
            identity_key = _federated_identity_key(
                source["ProviderName"],
                source_attribute,
                source["ProviderAttributeValue"],
            )
            for candidate in pool.users.values():
                for identity in candidate.federated_identities:
                    if (
                        _federated_identity_key(
                            identity.provider_name,
                            identity.provider_attribute_name,
                            identity.provider_attribute_value,
                        )
                        == identity_key
                    ):
                        if candidate is user:
                            return {}
                        _error("AliasExistsException", "Federated identity is already linked")
            if len(user.federated_identities) >= _MAX_FEDERATED_IDENTITIES_PER_USER:
                _error("LimitExceededException", "Federated identity quota exceeded")
            user.federated_identities.append(
                FederatedIdentity(
                    provider_name=source["ProviderName"],
                    provider_attribute_name=source_attribute,
                    provider_attribute_value=source["ProviderAttributeValue"],
                    created_at=_now(),
                )
            )
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminDisableProviderForUser", expand=False)
    def admin_disable_provider_for_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"User", "UserPoolId"})
        identifier = _provider_user_identifier(request.get("User"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            if identifier["ProviderName"] == "Cognito":
                if identifier["ProviderAttributeName"] != "Cognito_Subject":
                    _error(
                        "InvalidParameterException",
                        "Cognito users require ProviderAttributeName Cognito_Subject",
                    )
                user = self._user(pool, identifier["ProviderAttributeValue"])
                user.enabled = False
                user.tokens_valid_after = int(time.time())
                user.updated_at = pool.updated_at = _now()
                return {}
            _identity_provider(pool, identifier["ProviderName"])
            key = _federated_identity_key(
                identifier["ProviderName"],
                identifier["ProviderAttributeName"],
                identifier["ProviderAttributeValue"],
            )
            matches = []
            for user in pool.users.values():
                for position, identity in enumerate(user.federated_identities):
                    if (
                        _federated_identity_key(
                            identity.provider_name,
                            identity.provider_attribute_name,
                            identity.provider_attribute_value,
                        )
                        == key
                    ):
                        matches.append((user, position))
            if len(matches) != 1:
                _error("UserNotFoundException", "Federated identity link does not exist")
            user, position = matches[0]
            user.federated_identities.pop(position)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminCreateUser", expand=False)
    def admin_create_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "ClientMetadata",
                "DesiredDeliveryMediums",
                "ForceAliasCreation",
                "MessageAction",
                "TemporaryPassword",
                "UserAttributes",
                "UserPoolId",
                "Username",
                "ValidationData",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        validation_data = _attributes(request.get("ValidationData"))
        force_alias = request.get("ForceAliasCreation", False)
        if not isinstance(force_alias, bool):
            _error("InvalidParameterException", "ForceAliasCreation must be a boolean")
        message_action = request.get("MessageAction")
        if message_action not in (None, "RESEND", "SUPPRESS"):
            _error("InvalidParameterException", "Invalid MessageAction")
        desired_mediums = _desired_delivery_mediums(request.get("DesiredDeliveryMediums"))
        attributes = _attributes(request.get("UserAttributes"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            username = _casefold_identity(
                pool, _required_string(request, "Username", minimum=1, maximum=128)
            )
            _normalize_user_attributes(pool, attributes)
            pre_sign_up_arn = pool.pool_configuration.lambda_arn("PreSignUp")
            trigger_pool = pool
        _invoke_pre_sign_up_trigger(
            context,
            trigger_pool,
            client_id="CLIENT_ID_NOT_APPLICABLE",
            username=username,
            trigger_source="PreSignUp_AdminCreateUser",
            user_attributes=attributes,
            validation_data=validation_data,
            client_metadata=client_metadata,
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            if pool.pool_configuration.lambda_arn("PreSignUp") != pre_sign_up_arn:
                _error("ResourceConflictException", "PreSignUp configuration changed")
            username = _casefold_identity(
                pool, _required_string(request, "Username", minimum=1, maximum=128)
            )
            password = (
                _required_string(request, "TemporaryPassword", minimum=6, maximum=256)
                if request.get("TemporaryPassword") is not None
                else f"Aa1!{secrets.token_urlsafe(18)}"
            )
            _validate_password(pool, password)
            now = _now()
            _normalize_user_attributes(pool, attributes)
            password_hash, srp_salt, srp_verifier = _password_credentials(
                pool.pool_id, username, password
            )
            existing = _resolve_pool_user(pool, username)
            if message_action == "RESEND":
                if existing is None or existing.status != "FORCE_CHANGE_PASSWORD":
                    _error(
                        "UserNotFoundException",
                        "A pending administrator-created user is required for RESEND",
                    )
                if attributes and attributes != existing.attributes:
                    _error(
                        "InvalidParameterException",
                        "RESEND cannot replace user attributes",
                    )
                previous_credentials = (
                    existing.password,
                    existing.srp_salt,
                    existing.srp_verifier,
                    list(existing.password_history),
                    existing.temporary_password_expires_at,
                    existing.updated_at,
                )
                _set_user_password_credentials(pool, existing, password)
                existing.temporary_password_expires_at = now + timedelta(
                    days=_temporary_password_validity_days(pool)
                )
                existing.updated_at = pool.updated_at = now
                user = existing
                created = False
            else:
                if len(pool.users) >= _MAX_USERS_PER_POOL:
                    _error("LimitExceededException", "User quota exceeded")
                _validate_initial_user_attributes(pool, username, attributes, administrator=True)
                if _identity_conflict(pool, username) is not None:
                    _error("UsernameExistsException", "User account already exists")
                previous_credentials = None
                created = True
            user = (
                CognitoUser(
                    username=username,
                    sub=str(uuid.uuid4()),
                    password=password_hash,
                    status="FORCE_CHANGE_PASSWORD",
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                    srp_salt=srp_salt,
                    srp_verifier=srp_verifier,
                    temporary_password_expires_at=now
                    + timedelta(days=_temporary_password_validity_days(pool)),
                    attributes=attributes,
                )
                if created
                else user
            )
            if created:
                transfers = _alias_transfer_owners(pool, user, attributes, force=force_alias)
                affected = {owner.username: owner for owner, _, _ in transfers}
                for owner in affected.values():
                    _remove_user_identity_indexes(pool, owner)
                for owner, name, value in transfers:
                    if owner.attributes.get(name) == value:
                        owner.attributes[f"{name}_verified"] = "false"
                        owner.updated_at = now
                for owner in affected.values():
                    _add_user_identity_indexes(pool, owner)
                pool.users[username] = user
                _add_user_identity_indexes(pool, user)
            invitation_mediums = desired_mediums
            if "DesiredDeliveryMediums" not in request:
                invitation_mediums = (
                    ["SMS"]
                    if "phone_number" in user.attributes and pool.sms_configuration is not None
                    else []
                )
            targets = (
                []
                if message_action == "SUPPRESS"
                else _invitation_targets(user, invitation_mediums)
            )
            pool_id, user_sub = pool.pool_id, user.sub
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
            response = {"User": _user_response(user)}
        if targets:
            try:
                self._deliver_admin_invitations(
                    context,
                    pool_id=pool_id,
                    username=username,
                    password=password,
                    targets=targets,
                    configuration=configuration,
                    templates=templates,
                )
            except CommonServiceException:
                with _pool_guard(pool_id):
                    pool = self.get_store(context).user_pools.get(pool_id)
                    current = pool.users.get(username) if pool is not None else None
                    if current is not None and hmac.compare_digest(current.sub, user_sub):
                        if created:
                            _remove_user_identity_indexes(pool, current)
                            pool.users.pop(username, None)
                        elif previous_credentials is not None and current.updated_at == now:
                            (
                                current.password,
                                current.srp_salt,
                                current.srp_verifier,
                                current.password_history,
                                current.temporary_password_expires_at,
                                current.updated_at,
                            ) = previous_credentials
                raise
        return response

    @handler("AdminSetUserPassword", expand=False)
    def admin_set_user_password(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Password", "Permanent", "UserPoolId", "Username"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            password = _required_string(request, "Password", minimum=6, maximum=256)
            _validate_password(pool, password)
            _set_user_password_credentials(pool, user, password)
            permanent = request.get("Permanent") is True
            now = _now()
            user.status = "CONFIRMED" if permanent else "FORCE_CHANGE_PASSWORD"
            user.temporary_password_expires_at = (
                None if permanent else now + timedelta(days=_temporary_password_validity_days(pool))
            )
            user.updated_at = now
        return {}

    @handler("CreateGroup", expand=False)
    def create_group(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"Description", "GroupName", "Precedence", "RoleArn", "UserPoolId"}
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            name = _group_name(request.get("GroupName"))
            if name in pool.groups:
                _error("GroupExistsException", f"Group {name} already exists")
            if len(pool.groups) >= _MAX_GROUPS_PER_POOL:
                _error("LimitExceededException", "Group quota exceeded")
            now = _now()
            group = CognitoGroup(
                name=name,
                description=_group_description(request.get("Description")),
                role_arn=_group_role_arn(request.get("RoleArn")),
                precedence=_group_precedence(request.get("Precedence")),
                created_at=now,
                updated_at=now,
            )
            pool.groups[name] = group
            pool.updated_at = now
            return {"Group": _group_response(group)}

    @handler("GetGroup", expand=False)
    def get_group(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"GroupName", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return {"Group": _group_response(_group(pool, request.get("GroupName")))}

    @handler("UpdateGroup", expand=False)
    def update_group(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"Description", "GroupName", "Precedence", "RoleArn", "UserPoolId"}
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            group = _group(pool, request.get("GroupName"))
            if "Description" in request:
                group.description = _group_description(request["Description"])
            if "RoleArn" in request:
                group.role_arn = _group_role_arn(request["RoleArn"])
            if "Precedence" in request:
                group.precedence = _group_precedence(request["Precedence"])
            group.updated_at = pool.updated_at = _now()
            return {"Group": _group_response(group)}

    @handler("DeleteGroup", expand=False)
    def delete_group(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"GroupName", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            group = _group(pool, request.get("GroupName"))
            pool.groups.pop(group.name)
            pool.updated_at = _now()
        return {}

    @handler("ListGroups", expand=False)
    def list_groups(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Limit", "NextToken", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            limit = _list_limit(request.get("Limit"))
            kind = "groups"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            groups = sorted(pool.groups.values(), key=lambda group: group.name)
            page, next_after = _page_after(groups, limit, after, lambda group: group.name)
            response: ServiceResponse = {"Groups": [_group_response(group) for group in page]}
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("AdminAddUserToGroup", expand=False)
    def admin_add_user_to_group(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"GroupName", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            group = _group(pool, request.get("GroupName"))
            if user.username not in group.members:
                membership_count = sum(
                    user.username in candidate.members for candidate in pool.groups.values()
                )
                if membership_count >= _MAX_GROUP_MEMBERSHIPS_PER_USER:
                    _error("LimitExceededException", "Group membership quota exceeded")
                group.members.add(user.username)
                group.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminRemoveUserFromGroup", expand=False)
    def admin_remove_user_from_group(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"GroupName", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            group = _group(pool, request.get("GroupName"))
            group.members.discard(user.username)
            group.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminListGroupsForUser", expand=False)
    def admin_list_groups_for_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Limit", "NextToken", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            limit = _list_limit(request.get("Limit"))
            kind = f"user-groups:{user.username}"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            groups = sorted(
                (group for group in pool.groups.values() if user.username in group.members),
                key=lambda group: group.name,
            )
            page, next_after = _page_after(groups, limit, after, lambda group: group.name)
            response: ServiceResponse = {"Groups": [_group_response(group) for group in page]}
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("ListUsersInGroup", expand=False)
    def list_users_in_group(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"GroupName", "Limit", "NextToken", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            group = _group(pool, request.get("GroupName"))
            limit = _list_limit(request.get("Limit"))
            kind = f"group-users:{group.name}"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            users = sorted(
                (pool.users[name] for name in group.members if name in pool.users),
                key=lambda user: user.username,
            )
            page, next_after = _page_after(users, limit, after, lambda user: user.username)
            response: ServiceResponse = {"Users": [_user_response(user) for user in page]}
            if next_after is not None:
                response["NextToken"] = _encode_bound_page_token(pool, kind, next_after)
            return response

    @handler("AdminGetUser", expand=False)
    def admin_get_user(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return _admin_user_response(self._user(pool, request.get("Username")))

    @handler("ListUsers", expand=False)
    def list_users(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"AttributesToGet", "Filter", "Limit", "PaginationToken", "UserPoolId"}
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            attributes_to_get = _attributes_to_get(request.get("AttributesToGet"))
            records = [_list_users_query_record(user) for user in pool.users.values()]
            scope = json.dumps(
                [pool.pool_id, attributes_to_get], separators=(",", ":"), sort_keys=True
            )
            pager = ListUsersQueryPager(
                secret=hashlib.sha256(
                    pool.id_signing_private_key_pem + b"\0list-users-query-v1"
                ).digest()
            )
            try:
                page, next_token = pager.page(
                    records,
                    scope=scope,
                    filter_text=request.get("Filter"),
                    limit=request.get("Limit", 60),
                    pagination_token=request.get("PaginationToken"),
                )
            except ListUsersQueryError as error:
                _error("InvalidParameterException", str(error))
            response: ServiceResponse = {
                "Users": [
                    _listed_user_response(pool.users[record["Username"]], attributes_to_get)
                    for record in page
                ]
            }
            if next_token is not None:
                response["PaginationToken"] = next_token
            return response

    @handler("AdminDeleteUser", expand=False)
    def admin_delete_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            with cognito_idp_stores.lock:
                _remove_user_state(self.get_store(context), pool, user.username)
            _remove_user_identity_indexes(pool, user)
            pool.users.pop(user.username)
            pool.updated_at = _now()
        return {}

    @handler("AdminEnableUser", expand=False)
    def admin_enable_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            user.enabled = True
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminDisableUser", expand=False)
    def admin_disable_user(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            user.enabled = False
            user.updated_at = pool.updated_at = _now()
            with cognito_idp_stores.lock:
                _invalidate_user_tokens(self.get_store(context), pool, user)
        return {}

    @handler("AdminUpdateUserAttributes", expand=False)
    def admin_update_user_attributes(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserAttributes", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            attributes = _attributes(request.get("UserAttributes"))
            if not attributes:
                _error("InvalidParameterException", "UserAttributes must not be empty")
            _normalize_user_attributes(pool, attributes)
            _validate_schema_mutation(
                pool,
                user,
                set(attributes),
                administrator=True,
                attribute_values=attributes,
            )
            prospective = dict(user.attributes)
            for name in ("email", "phone_number"):
                if name in attributes and attributes[name] != user.attributes.get(name):
                    prospective.pop(f"{name}_verified", None)
            prospective.update(attributes)
            _replace_user_attributes(pool, user, prospective)
            for name in attributes:
                user.pending_attribute_updates.pop(name, None)
                if name in {"email", "phone_number"}:
                    _remove_user_code(
                        self.get_store(context), pool, user.username, f"attribute:{name}"
                    )
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminDeleteUserAttributes", expand=False)
    def admin_delete_user_attributes(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserAttributeNames", "Username", "UserPoolId"})
        names = _attribute_names(request.get("UserAttributeNames"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            _validate_schema_mutation(pool, user, set(names), deleting=True, administrator=True)
            prospective = dict(user.attributes)
            for name in names:
                prospective.pop(name, None)
                if name in {"email", "phone_number"}:
                    prospective.pop(f"{name}_verified", None)
                    user.pending_attribute_updates.pop(name, None)
                    _remove_user_code(
                        self.get_store(context), pool, user.username, f"attribute:{name}"
                    )
            _replace_user_attributes(pool, user, prospective)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminConfirmSignUp", expand=False)
    def admin_confirm_sign_up(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            if user.status != "UNCONFIRMED":
                _error("NotAuthorizedException", "User cannot be confirmed in its current state")
            attributes = dict(user.attributes)
            _alias_transfer_owners(pool, user, attributes, force=False)
            _remove_user_code(self.get_store(context), pool, user.username, "signup")
            _remove_user_identity_indexes(pool, user)
            user.status = "CONFIRMED"
            _add_user_identity_indexes(pool, user)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminResetUserPassword", expand=False)
    def admin_reset_user_password(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            if not user.enabled:
                _error("NotAuthorizedException", "User is disabled")
            if "email" not in user.attributes and "phone_number" not in user.attributes:
                _error("InvalidParameterException", "User has no recovery delivery attribute")
            _ensure_user_code_capacity(
                self.get_store(context), pool, user.username, ["forgot"], _now()
            )
            try:
                recovery_attributes = available_recovery_attributes(
                    _validate_pool_auth_policy(pool), _user_auth_state(pool, user)
                )
            except MfaPasswordlessError as error:
                _error(error.code, str(error))
            if not recovery_attributes:
                attribute_name, medium, destination = _notification_target(user)
            else:
                attribute_name, medium, destination = _notification_target(
                    user, recovery_attributes[0]
                )
            reservation, code = _reserve_user_code(
                self.get_store(context), pool, "*", user, "forgot", None, _now()
            )
            user.status = "RESET_REQUIRED"
            user.updated_at = pool.updated_at = _now()
            with cognito_idp_stores.lock:
                _invalidate_user_tokens(self.get_store(context), pool, user)
            pool_id, user_sub, username = pool.pool_id, user.sub, user.username
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
        self._deliver_reserved_user_code(
            context,
            pool_id=pool_id,
            user_sub=user_sub,
            username=username,
            purpose="forgot",
            notification_purpose="forgot_password",
            attribute_name=attribute_name,
            destination=destination,
            medium=medium,
            code=code,
            reservation=reservation,
            configuration=configuration,
            templates=templates,
        )
        return {}

    @handler("SignUp", expand=False)
    def sign_up(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "ClientId",
                "ClientMetadata",
                "Password",
                "SecretHash",
                "UserAttributes",
                "UserContextData",
                "Username",
                "ValidationData",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        _analytics_metadata(request.get("AnalyticsMetadata"))
        _user_context_data(request.get("UserContextData"))
        validation_data = _attributes(request.get("ValidationData"))
        attributes = _self_service_attributes(request.get("UserAttributes"))
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            if pool.allow_admin_create_user_only:
                _error("NotAuthorizedException", "Sign-up is disabled for this user pool")
            supplied_username = _required_string(request, "Username", minimum=1, maximum=128)
            username = _casefold_identity(pool, supplied_username)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            password = _required_string(request, "Password", minimum=6, maximum=256)
            _validate_password(pool, password)
            if len(pool.users) >= _MAX_USERS_PER_POOL:
                _error("LimitExceededException", "User quota exceeded")
            _normalize_user_attributes(pool, attributes)
            _validate_initial_user_attributes(pool, username, attributes)
            _assert_identity_available(pool, username, attributes)
            pre_sign_up_arn = pool.pool_configuration.lambda_arn("PreSignUp")
            trigger_pool = pool
            client_id = client.client_id
        pre_sign_up = _invoke_pre_sign_up_trigger(
            context,
            trigger_pool,
            client_id=client_id,
            username=username,
            trigger_source="PreSignUp_SignUp",
            user_attributes=attributes,
            validation_data=validation_data,
            client_metadata=client_metadata,
        )
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            if pool.pool_configuration.lambda_arn("PreSignUp") != pre_sign_up_arn:
                _error("ResourceConflictException", "PreSignUp configuration changed")
            if pool.allow_admin_create_user_only:
                _error("NotAuthorizedException", "Sign-up is disabled for this user pool")
            supplied_username = _required_string(request, "Username", minimum=1, maximum=128)
            username = _casefold_identity(pool, supplied_username)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            password = _required_string(request, "Password", minimum=6, maximum=256)
            _validate_password(pool, password)
            if len(pool.users) >= _MAX_USERS_PER_POOL:
                _error("LimitExceededException", "User quota exceeded")
            _normalize_user_attributes(pool, attributes)
            _validate_initial_user_attributes(pool, username, attributes)
            _assert_identity_available(pool, username, attributes)
            if pre_sign_up.auto_verify_email:
                if "email" not in attributes:
                    _error(
                        "InvalidLambdaResponseException", "PreSignUp cannot verify missing email"
                    )
                attributes["email_verified"] = "true"
            if pre_sign_up.auto_verify_phone:
                if "phone_number" not in attributes:
                    _error(
                        "InvalidLambdaResponseException",
                        "PreSignUp cannot verify missing phone_number",
                    )
                attributes["phone_number_verified"] = "true"
            now = _now()
            password_hash, srp_salt, srp_verifier = _password_credentials(
                pool.pool_id, username, password
            )
            user = CognitoUser(
                username=username,
                sub=str(uuid.uuid4()),
                password=password_hash,
                status="CONFIRMED" if pre_sign_up.auto_confirm_user else "UNCONFIRMED",
                enabled=True,
                created_at=now,
                updated_at=now,
                srp_salt=srp_salt,
                srp_verifier=srp_verifier,
                attributes=attributes,
            )
            if not pre_sign_up.auto_confirm_user:
                attribute_name, medium, destination = _notification_target(user)
                delivery = _delivery_details(user, attribute_name)
                reservation, code = _reserve_user_code(
                    self.get_store(context), pool, client.client_id, user, "signup", None, now
                )
            pool.users[username] = user
            _add_user_identity_indexes(pool, user)
            pool.updated_at = now
            pool_id, user_sub = pool.pool_id, user.sub
            if not pre_sign_up.auto_confirm_user:
                configuration = _notification_configuration(context, pool)
                templates = _notification_templates(pool)
        if pre_sign_up.auto_confirm_user:
            _invoke_post_confirmation(
                context,
                pool,
                client,
                user,
                "PostConfirmation_ConfirmSignUp",
                client_metadata=client_metadata,
            )
            return {"UserConfirmed": True, "UserSub": user_sub}
        templates = self._customize_reserved_user_code(
            context,
            pool=pool,
            client=client,
            user=user,
            purpose="signup",
            reservation=reservation,
            trigger_source="CustomMessage_SignUp",
            client_metadata=client_metadata,
            templates=templates,
        )
        self._deliver_reserved_user_code(
            context,
            pool_id=pool_id,
            user_sub=user_sub,
            username=username,
            purpose="signup",
            notification_purpose="signup_confirmation",
            attribute_name=attribute_name,
            destination=destination,
            medium=medium,
            code=code,
            reservation=reservation,
            configuration=configuration,
            templates=templates,
        )
        return {
            "CodeDeliveryDetails": delivery,
            "UserConfirmed": False,
            "UserSub": user_sub,
        }

    @handler("ConfirmSignUp", expand=False)
    def confirm_sign_up(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "ClientId",
                "ClientMetadata",
                "ConfirmationCode",
                "ForceAliasCreation",
                "SecretHash",
                "UserContextData",
                "Username",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        _analytics_metadata(request.get("AnalyticsMetadata"))
        _user_context_data(request.get("UserContextData"))
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            username = _required_string(request, "Username", minimum=1, maximum=128)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            force_alias = request.get("ForceAliasCreation", False)
            if not isinstance(force_alias, bool):
                _error("InvalidParameterException", "ForceAliasCreation must be a boolean")
            user = _resolve_pool_user(pool, username)
            if user is None:
                if client.prevent_user_existence_errors == "ENABLED":
                    _synthetic_user_code_work(pool, client.client_id, username, "signup")
                    _error("CodeMismatchException", "Invalid verification code")
                _error("UserNotFoundException", "User does not exist")
            if user.status != "UNCONFIRMED":
                _error("NotAuthorizedException", "User cannot be confirmed in its current state")
            attributes = dict(user.attributes)
            verified_on_confirmation = set(pool.auto_verified_attributes or [])
            try:
                verified_on_confirmation.add(_delivery_details(user)["AttributeName"])
            except CommonServiceException:
                pass
            for name in verified_on_confirmation:
                if name in attributes:
                    attributes[f"{name}_verified"] = "true"
            transfers = _alias_transfer_owners(pool, user, attributes, force=force_alias)
            code = _required_string(request, "ConfirmationCode", minimum=1, maximum=2048)
            _verify_user_code(
                self.get_store(context),
                pool,
                client.client_id,
                user.username,
                "signup",
                code,
                _now(),
            )
            _apply_confirmed_aliases(pool, user, attributes, transfers)
            user.updated_at = pool.updated_at = _now()
        _invoke_post_confirmation(
            context,
            pool,
            client,
            user,
            "PostConfirmation_ConfirmSignUp",
            client_metadata=client_metadata,
        )
        return {}

    @handler("ResendConfirmationCode", expand=False)
    def resend_confirmation_code(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "ClientId",
                "ClientMetadata",
                "SecretHash",
                "UserContextData",
                "Username",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        _analytics_metadata(request.get("AnalyticsMetadata"))
        _user_context_data(request.get("UserContextData"))
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            username = _required_string(request, "Username", minimum=1, maximum=128)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            user = _resolve_pool_user(pool, username)
            if user is None:
                if client.prevent_user_existence_errors == "ENABLED":
                    return {"CodeDeliveryDetails": _generic_delivery_details()}
                _error("UserNotFoundException", "User does not exist")
            if user.status != "UNCONFIRMED":
                _error("InvalidParameterException", "User is already confirmed")
            attribute_name, medium, destination = _notification_target(user)
            delivery = _delivery_details(user, attribute_name)
            reservation, code = _reserve_user_code(
                self.get_store(context), pool, client.client_id, user, "signup", None, _now()
            )
            pool_id, user_sub = pool.pool_id, user.sub
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
            response_delivery = (
                _generic_delivery_details()
                if client.prevent_user_existence_errors == "ENABLED"
                else delivery
            )
        templates = self._customize_reserved_user_code(
            context,
            pool=pool,
            client=client,
            user=user,
            purpose="signup",
            reservation=reservation,
            trigger_source="CustomMessage_ResendCode",
            client_metadata=client_metadata,
            templates=templates,
        )
        self._deliver_reserved_user_code(
            context,
            pool_id=pool_id,
            user_sub=user_sub,
            username=user.username,
            purpose="signup",
            notification_purpose="resend_confirmation",
            attribute_name=attribute_name,
            destination=destination,
            medium=medium,
            code=code,
            reservation=reservation,
            configuration=configuration,
            templates=templates,
        )
        return {"CodeDeliveryDetails": response_delivery}

    @handler("ForgotPassword", expand=False)
    def forgot_password(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "ClientId",
                "ClientMetadata",
                "SecretHash",
                "UserContextData",
                "Username",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        _analytics_metadata(request.get("AnalyticsMetadata"))
        _user_context_data(request.get("UserContextData"))
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            username = _required_string(request, "Username", minimum=1, maximum=128)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            user = _resolve_pool_user(pool, username)
            if user is None or not user.enabled or user.status != "CONFIRMED":
                if client.prevent_user_existence_errors == "ENABLED":
                    _synthetic_user_code_work(pool, client.client_id, username, "forgot")
                    return {"CodeDeliveryDetails": _generic_delivery_details()}
                if user is None:
                    _error("UserNotFoundException", "User does not exist")
                _error("InvalidParameterException", "User is not eligible for password recovery")
            try:
                recovery_attributes = available_recovery_attributes(
                    _validate_pool_auth_policy(pool), _user_auth_state(pool, user)
                )
            except MfaPasswordlessError as error:
                _error(error.code, str(error))
            if not recovery_attributes:
                if client.prevent_user_existence_errors == "ENABLED":
                    _synthetic_user_code_work(pool, client.client_id, username, "forgot")
                    return {"CodeDeliveryDetails": _generic_delivery_details()}
                _error("InvalidParameterException", "User has no valid recovery mechanism")
            attribute_name, medium, destination = _notification_target(user, recovery_attributes[0])
            delivery = _delivery_details(user, attribute_name)
            reservation, code = _reserve_user_code(
                self.get_store(context), pool, client.client_id, user, "forgot", None, _now()
            )
            pool_id, user_sub = pool.pool_id, user.sub
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
            response_delivery = (
                _generic_delivery_details()
                if client.prevent_user_existence_errors == "ENABLED"
                else delivery
            )
        templates = self._customize_reserved_user_code(
            context,
            pool=pool,
            client=client,
            user=user,
            purpose="forgot",
            reservation=reservation,
            trigger_source="CustomMessage_ForgotPassword",
            client_metadata=client_metadata,
            templates=templates,
        )
        self._deliver_reserved_user_code(
            context,
            pool_id=pool_id,
            user_sub=user_sub,
            username=user.username,
            purpose="forgot",
            notification_purpose="forgot_password",
            attribute_name=attribute_name,
            destination=destination,
            medium=medium,
            code=code,
            reservation=reservation,
            configuration=configuration,
            templates=templates,
        )
        return {"CodeDeliveryDetails": response_delivery}

    @handler("ConfirmForgotPassword", expand=False)
    def confirm_forgot_password(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "ClientId",
                "ClientMetadata",
                "ConfirmationCode",
                "Password",
                "SecretHash",
                "UserContextData",
                "Username",
            },
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        _analytics_metadata(request.get("AnalyticsMetadata"))
        _user_context_data(request.get("UserContextData"))
        with self._locked_client(context, request.get("ClientId")) as (client, pool):
            username = _required_string(request, "Username", minimum=1, maximum=128)
            self._verify_secret_hash(pool, client, username, request.get("SecretHash"))
            password = _required_string(request, "Password", minimum=6, maximum=256)
            _validate_password(pool, password)
            code = _required_string(request, "ConfirmationCode", minimum=1, maximum=2048)
            user = _resolve_pool_user(pool, username)
            if user is None or not user.enabled:
                _synthetic_user_code_work(pool, client.client_id, username, "forgot")
                _error("CodeMismatchException", "Invalid verification code")
            _assert_user_password_not_reused(pool, user, password)
            _verify_user_code(
                self.get_store(context), pool, client.client_id, username, "forgot", code, _now()
            )
            _set_user_password_credentials(pool, user, password)
            user.status = "CONFIRMED"
            user.updated_at = pool.updated_at = _now()
            with cognito_idp_stores.lock:
                _invalidate_user_tokens(self.get_store(context), pool, user)
        _invoke_post_confirmation(
            context,
            pool,
            client,
            user,
            "PostConfirmation_ConfirmForgotPassword",
            client_metadata=client_metadata,
        )
        return {}

    @handler("GetUser", expand=False)
    def get_user(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken"})
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            _,
            client,
            user,
        ):
            return _self_user_response(user, _readable_user_attributes(client, user))

    @handler("ChangePassword", expand=False)
    def change_password(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "PreviousPassword", "ProposedPassword"})
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            previous = _required_string(request, "PreviousPassword", minimum=1, maximum=256)
            proposed = _required_string(request, "ProposedPassword", minimum=6, maximum=256)
            if not user.password.verify(previous):
                _error("NotAuthorizedException", "Incorrect username or password")
            _validate_password(pool, proposed)
            _set_user_password_credentials(pool, user, proposed)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("UpdateUserAttributes", expand=False)
    def update_user_attributes(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "UserAttributes"})
        attributes = _self_service_attributes(request.get("UserAttributes"))
        if not attributes:
            _error("InvalidParameterException", "UserAttributes must not be empty")
        deliveries: list[dict[str, str]] = []
        notifications: list[dict[str, Any]] = []
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            _normalize_user_attributes(pool, attributes)
            _authorize_client_attribute_writes(client, set(attributes))
            _validate_schema_mutation(pool, user, set(attributes), attribute_values=attributes)
            try:
                plan = plan_attribute_updates(
                    user.attributes,
                    attributes,
                    pool.pool_configuration,
                    pending=user.pending_attribute_updates,
                )
            except PoolConfigurationError as error:
                _error(error.code, str(error))
            verification_attributes = [
                attribute_name
                for attribute_name in ("email", "phone_number")
                if attribute_name in attributes
            ]
            _ensure_user_code_capacity(
                self.get_store(context),
                pool,
                user.username,
                [f"attribute:{name}" for name in verification_attributes],
                _now(),
            )
            for attribute_name in ("email", "phone_number"):
                if attribute_name not in attributes:
                    continue
                reservation, code = _reserve_user_code(
                    self.get_store(context),
                    pool,
                    "",
                    user,
                    f"attribute:{attribute_name}",
                    attribute_name,
                    _now(),
                )
                notifications.append(
                    {
                        "attribute_name": attribute_name,
                        "purpose": f"attribute:{attribute_name}",
                        "reservation": reservation,
                        "code": code,
                    }
                )
            _replace_user_attributes(pool, user, plan.attributes)
            user.pending_attribute_updates = dict(plan.pending)
            for attribute_name in verification_attributes:
                value = user.pending_attribute_updates.get(
                    attribute_name, user.attributes.get(attribute_name)
                )
                deliveries.append(_delivery_details_for_value(attribute_name, value))
            for notification in notifications:
                value = user.pending_attribute_updates.get(
                    notification["attribute_name"],
                    user.attributes.get(notification["attribute_name"]),
                )
                _, medium, destination = _notification_target_for_value(
                    notification["attribute_name"], value
                )
                notification["medium"] = medium
                notification["destination"] = destination
            user.updated_at = pool.updated_at = _now()
            pool_id, user_sub, username = pool.pool_id, user.sub, user.username
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
        for notification in notifications:
            self._deliver_reserved_user_code(
                context,
                pool_id=pool_id,
                user_sub=user_sub,
                username=username,
                purpose=notification["purpose"],
                notification_purpose="attribute_verification",
                attribute_name=notification["attribute_name"],
                destination=notification["destination"],
                medium=notification["medium"],
                code=notification["code"],
                reservation=notification["reservation"],
                configuration=configuration,
                templates=templates,
            )
        response: ServiceResponse = {}
        if deliveries:
            response["CodeDeliveryDetailsList"] = deliveries
        return response

    @handler("DeleteUserAttributes", expand=False)
    def delete_user_attributes(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "UserAttributeNames"})
        names = _attribute_names(request.get("UserAttributeNames"))
        if {"email_verified", "phone_number_verified"} & set(names):
            _error("InvalidParameterException", "Verification attributes are read-only")
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            _authorize_client_attribute_writes(client, set(names))
            _validate_schema_mutation(pool, user, set(names), deleting=True)
            prospective = dict(user.attributes)
            for name in names:
                prospective.pop(name, None)
                if name in {"email", "phone_number"}:
                    prospective.pop(f"{name}_verified", None)
                    user.pending_attribute_updates.pop(name, None)
                    _remove_user_code(
                        self.get_store(context), pool, user.username, f"attribute:{name}"
                    )
            _replace_user_attributes(pool, user, prospective)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("GetUserAttributeVerificationCode", expand=False)
    def get_user_attribute_verification_code(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "AttributeName"})
        attribute_name = _verifiable_attribute(request.get("AttributeName"))
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            value = user.pending_attribute_updates.get(
                attribute_name, user.attributes.get(attribute_name)
            )
            if value is None:
                _error("InvalidParameterException", f"User has no {attribute_name} attribute")
            reservation, code = _reserve_user_code(
                self.get_store(context),
                pool,
                "",
                user,
                f"attribute:{attribute_name}",
                attribute_name,
                _now(),
            )
            details = _delivery_details_for_value(attribute_name, value)
            _, medium, destination = _notification_target_for_value(attribute_name, value)
            pool_id, user_sub, username = pool.pool_id, user.sub, user.username
            configuration = _notification_configuration(context, pool)
            templates = _notification_templates(pool)
        self._deliver_reserved_user_code(
            context,
            pool_id=pool_id,
            user_sub=user_sub,
            username=username,
            purpose=f"attribute:{attribute_name}",
            notification_purpose="attribute_verification",
            attribute_name=attribute_name,
            destination=destination,
            medium=medium,
            code=code,
            reservation=reservation,
            configuration=configuration,
            templates=templates,
        )
        return {"CodeDeliveryDetails": details}

    @handler("VerifyUserAttribute", expand=False)
    def verify_user_attribute(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "AttributeName", "Code"})
        attribute_name = _verifiable_attribute(request.get("AttributeName"))
        code = _required_string(request, "Code", minimum=1, maximum=2048)
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            if attribute_name in user.pending_attribute_updates:
                try:
                    plan = commit_verified_attribute(
                        AttributeUpdatePlan(
                            attributes=dict(user.attributes),
                            pending=dict(user.pending_attribute_updates),
                        ),
                        attribute_name,
                    )
                except PoolConfigurationError as error:
                    _error(error.code, str(error))
                prospective = plan.attributes
            else:
                plan = None
                prospective = dict(user.attributes)
                prospective[f"{attribute_name}_verified"] = "true"
            _alias_transfer_owners(pool, user, prospective, force=False)
            _verify_user_code(
                self.get_store(context),
                pool,
                "",
                user.username,
                f"attribute:{attribute_name}",
                code,
                _now(),
            )
            _replace_user_attributes(pool, user, prospective)
            if plan is not None:
                user.pending_attribute_updates = dict(plan.pending)
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("GlobalSignOut", expand=False)
    def global_sign_out(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            with cognito_idp_stores.lock:
                _invalidate_user_tokens(self.get_store(context), pool, user)
        return {}

    @handler("AdminUserGlobalSignOut", expand=False)
    def admin_user_global_sign_out(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            with cognito_idp_stores.lock:
                _invalidate_user_tokens(self.get_store(context), pool, user)
        return {}

    @handler("DeleteUser", expand=False)
    def delete_user(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            with cognito_idp_stores.lock:
                _remove_user_state(self.get_store(context), pool, user.username)
                _remove_user_identity_indexes(pool, user)
                pool.users.pop(user.username, None)
                pool.updated_at = _now()
        return {}

    @handler("AdminForgetDevice", expand=False)
    def admin_forget_device(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"DeviceKey", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            device_key = _device_key(request.get("DeviceKey"))
            if user.devices.pop(device_key, None) is None:
                _error("ResourceNotFoundException", "Device does not exist")
            with cognito_idp_stores.lock:
                _remove_device_auth_state(
                    self.get_store(context), pool.pool_id, user.username, device_key
                )
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("AdminGetDevice", expand=False)
    def admin_get_device(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"DeviceKey", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            return {"Device": _device_response(_user_device(user, request.get("DeviceKey")))}

    @handler("AdminListDevices", expand=False)
    def admin_list_devices(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Limit", "PaginationToken", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            return _list_devices_response(
                pool,
                user,
                request.get("Limit"),
                request.get("PaginationToken"),
                f"admin-devices:{user.username}",
            )

    @handler("AdminUpdateDeviceStatus", expand=False)
    def admin_update_device_status(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"DeviceKey", "DeviceRememberedStatus", "Username", "UserPoolId"},
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            _update_device_status(user, request)
            if request.get("DeviceRememberedStatus") == "not_remembered":
                with cognito_idp_stores.lock:
                    _remove_device_challenges(
                        self.get_store(context), pool.pool_id, user.username, request["DeviceKey"]
                    )
            pool.updated_at = _now()
        return {}

    @handler("ConfirmDevice", expand=False)
    def confirm_device(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"AccessToken", "DeviceKey", "DeviceName", "DeviceSecretVerifierConfig"}
        )
        device_key = _device_key(request.get("DeviceKey"))
        salt, verifier = _device_verifier_configuration(request.get("DeviceSecretVerifierConfig"))
        name = request.get("DeviceName")
        if name is not None and (not isinstance(name, str) or not 1 <= len(name) <= 1024):
            _error("InvalidParameterException", "Invalid DeviceName")
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            with cognito_idp_stores.lock:
                pending = self.get_store(context).pending_devices.pop(_token_hash(device_key), None)
                if (
                    pending is None
                    or pending.expires_at <= _now()
                    or pending.pool_id != pool.pool_id
                    or pending.username != user.username
                    or pending.client_id != client.client_id
                ):
                    _error("ResourceNotFoundException", "Device does not exist")
                if len(user.devices) >= _MAX_DEVICES_PER_USER:
                    _error("LimitExceededException", "Device quota exceeded")
                now = _now()
                remembered_status = (
                    "not_remembered" if pool.device_only_remembered_on_user_prompt else "remembered"
                )
                user.devices[device_key] = CognitoDevice(
                    device_key=device_key,
                    device_group_key=pending.device_group_key,
                    salt=salt,
                    verifier=verifier,
                    name=name,
                    remembered_status=remembered_status,
                    created_at=now,
                    updated_at=now,
                    last_authenticated_at=now,
                )
                user.updated_at = pool.updated_at = now
        return {"UserConfirmationNecessary": pool.device_only_remembered_on_user_prompt}

    @handler("ForgetDevice", expand=False)
    def forget_device(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "DeviceKey"})
        device_key = _device_key(request.get("DeviceKey"))
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            if user.devices.pop(device_key, None) is None:
                _error("ResourceNotFoundException", "Device does not exist")
            with cognito_idp_stores.lock:
                _remove_device_auth_state(
                    self.get_store(context), pool.pool_id, user.username, device_key
                )
            user.updated_at = pool.updated_at = _now()
        return {}

    @handler("GetDevice", expand=False)
    def get_device(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "DeviceKey"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            return {"Device": _device_response(_user_device(user, request.get("DeviceKey")))}

    @handler("ListDevices", expand=False)
    def list_devices(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "Limit", "PaginationToken"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            return _list_devices_response(
                pool,
                user,
                request.get("Limit"),
                request.get("PaginationToken"),
                f"self-devices:{user.username}",
            )

    @handler("UpdateDeviceStatus", expand=False)
    def update_device_status(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "DeviceKey", "DeviceRememberedStatus"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            _update_device_status(user, request)
            if request.get("DeviceRememberedStatus") == "not_remembered":
                with cognito_idp_stores.lock:
                    _remove_device_challenges(
                        self.get_store(context), pool.pool_id, user.username, request["DeviceKey"]
                    )
            pool.updated_at = _now()
        return {}

    @handler("AdminSetUserSettings", expand=False)
    def admin_set_user_settings(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MFAOptions", "Username", "UserPoolId"})
        _legacy_mfa_options(request.get("MFAOptions"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            self._user(pool, request.get("Username"))
        return {}

    @handler("SetUserSettings", expand=False)
    def set_user_settings(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "MFAOptions"})
        _legacy_mfa_options(request.get("MFAOptions"))
        with self._locked_access_token_user(context, request.get("AccessToken")):
            pass
        return {}

    @handler("GetUserAuthFactors", expand=False)
    def get_user_auth_factors(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            return _auth_factors_response(pool, user)

    @handler("AdminGetUserAuthFactors", expand=False)
    def admin_get_user_auth_factors(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return _auth_factors_response(pool, self._user(pool, request.get("Username")))

    @handler("AdminInitiateAuth", expand=False)
    def admin_initiate_auth(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "AuthFlow",
                "AuthParameters",
                "ClientId",
                "ClientMetadata",
                "ContextData",
                "Session",
                "UserPoolId",
            },
        )
        for unsupported in ("Session",):
            value = request.get(unsupported)
            if value is not None and value != "" and value != {}:
                _error("InvalidParameterException", f"{unsupported} is not implemented")
        context_data = _admin_auth_context(request.get("ContextData"))
        context_data.update(_analytics_metadata(request.get("AnalyticsMetadata")))
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        pool_id = _pool_id(request.get("UserPoolId"))
        flow = request.get("AuthFlow")
        parameters = request.get("AuthParameters")
        if not isinstance(parameters, dict):
            _error("InvalidParameterException", "AuthParameters is required")
        if flow == "CUSTOM_AUTH":
            return self._start_custom_auth(
                context,
                pool_id,
                request.get("ClientId"),
                parameters,
                auth_context=context_data,
            )
        if flow == "USER_AUTH":
            return self._start_user_auth_choice(
                context,
                pool_id,
                request.get("ClientId"),
                parameters,
                auth_context=context_data,
                client_metadata=client_metadata,
            )
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, request.get("ClientId"))
            if flow == "ADMIN_USER_PASSWORD_AUTH":
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "PASSWORD", "SECRET_HASH", "USERNAME"}
                )
                if "ALLOW_ADMIN_USER_PASSWORD_AUTH" not in client.explicit_auth_flows:
                    _error(
                        "InvalidParameterException",
                        "ADMIN_USER_PASSWORD_AUTH flow not enabled for this client",
                    )
                return self._password_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    allow_force_change=True,
                    auth_context=context_data,
                    client_metadata=client_metadata,
                    record_event=True,
                )
            if flow == "USER_SRP_AUTH":
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "SECRET_HASH", "SRP_A", "USERNAME"}
                )
                if "ALLOW_USER_SRP_AUTH" not in client.explicit_auth_flows:
                    _error("InvalidParameterException", "USER_SRP_AUTH flow not enabled")
                return self._start_srp_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=context_data,
                    client_metadata=client_metadata,
                )
            if flow in {"REFRESH_TOKEN", "REFRESH_TOKEN_AUTH"}:
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "REFRESH_TOKEN", "SECRET_HASH"}
                )
                if "ALLOW_REFRESH_TOKEN_AUTH" not in client.explicit_auth_flows:
                    _error("InvalidParameterException", "REFRESH_TOKEN_AUTH flow not enabled")
                return {
                    "AuthenticationResult": self._refresh_auth(context, pool, client, parameters)
                }
            _error("InvalidParameterException", f"Unsupported admin authentication flow: {flow}")

    @handler("AdminListUserAuthEvents", expand=False)
    def admin_list_user_auth_events(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            maximum = request.get("MaxResults", 60)
            if not isinstance(maximum, int) or isinstance(maximum, bool) or not 0 <= maximum <= 60:
                _error("InvalidParameterException", "MaxResults must be between 0 and 60")
            maximum = maximum or 60
            kind = f"auth-events:{user.username}"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            events = sorted(
                (
                    event
                    for event in self.get_store(context).auth_events.values()
                    if event.pool_id == pool.pool_id and event.username == user.username
                ),
                key=lambda event: (event.created_at, event.event_id),
                reverse=True,
            )
            start = 0
            if after is not None:
                matching = next(
                    (index for index, event in enumerate(events) if event.event_id == after), None
                )
                if matching is None:
                    _error("InvalidParameterException", "Invalid pagination token")
                start = matching + 1
            page = events[start : start + maximum]
            response: ServiceResponse = {
                "AuthEvents": [_auth_event_response(event) for event in page]
            }
            if start + len(page) < len(events):
                response["NextToken"] = _encode_bound_page_token(pool, kind, page[-1].event_id)
            return response

    @handler("AdminUpdateAuthEventFeedback", expand=False)
    def admin_update_auth_event_feedback(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"EventId", "FeedbackValue", "Username", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            event = _auth_event(
                self.get_store(context), pool, user.username, request.get("EventId")
            )
            _set_auth_event_feedback(event, request.get("FeedbackValue"), "Admin")
            return {}

    @handler("UpdateAuthEventFeedback", expand=False)
    def update_auth_event_feedback(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"EventId", "FeedbackToken", "FeedbackValue", "Username", "UserPoolId"},
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            event = _auth_event(
                self.get_store(context), pool, user.username, request.get("EventId")
            )
            expected = _auth_event_feedback_token(pool, event)
            supplied = request.get("FeedbackToken")
            if not isinstance(supplied, str) or not hmac.compare_digest(expected, supplied):
                _error("NotAuthorizedException", "Invalid feedback token")
            _set_auth_event_feedback(event, request.get("FeedbackValue"), "User")
            return {}

    @handler("DescribeRiskConfiguration", expand=False)
    def describe_risk_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client_id = request.get("ClientId")
            if client_id is not None and client_id != "ALL":
                self._client(pool, client_id)
            return {"RiskConfiguration": _risk_configuration_response(pool, client_id)}

    @handler("SetRiskConfiguration", expand=False)
    def set_risk_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AccountTakeoverRiskConfiguration",
                "ClientId",
                "CompromisedCredentialsRiskConfiguration",
                "RiskExceptionConfiguration",
                "UserPoolId",
            },
        )
        if request.get("AccountTakeoverRiskConfiguration") is not None:
            _error(
                "InvalidParameterException",
                "AccountTakeoverRiskConfiguration requires an unavailable proprietary risk engine",
            )
        compromised = _compromised_credentials_configuration(
            request.get("CompromisedCredentialsRiskConfiguration")
        )
        exceptions = _risk_exception_configuration(request.get("RiskExceptionConfiguration"))
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client_id = request.get("ClientId")
            if client_id is not None and client_id != "ALL":
                self._client(pool, client_id)
            key = client_id or "ALL"
            now = _now()
            if compromised is None and exceptions is None:
                pool.risk_configurations.pop(key, None)
            else:
                pool.risk_configurations[key] = RiskConfiguration(
                    client_id=client_id,
                    account_takeover=None,
                    compromised_credentials=compromised,
                    risk_exceptions=exceptions,
                    updated_at=now,
                )
            pool.updated_at = now
            return {"RiskConfiguration": _risk_configuration_response(pool, client_id)}

    @handler("InitiateAuth", expand=False)
    def initiate_auth(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "AnalyticsMetadata",
                "AuthFlow",
                "AuthParameters",
                "ClientId",
                "ClientMetadata",
                "UserContextData",
            },
        )
        raw_user_context = request.get("UserContextData")
        analytics_context = _analytics_metadata(request.get("AnalyticsMetadata"))
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        with cognito_idp_stores.lock:
            client, pool = self._find_client(context, request.get("ClientId"))
            pool_id = pool.pool_id
            user_context = _runtime_user_context(client, raw_user_context)
            user_context.update(analytics_context)
        flow = request.get("AuthFlow")
        parameters = request.get("AuthParameters")
        if not isinstance(parameters, dict):
            _error("InvalidParameterException", "AuthParameters is required")
        if flow == "CUSTOM_AUTH":
            return self._start_custom_auth(
                context,
                pool_id,
                request.get("ClientId"),
                parameters,
                auth_context=user_context,
            )
        if flow == "USER_AUTH":
            return self._start_user_auth_choice(
                context,
                pool_id,
                request.get("ClientId"),
                parameters,
                auth_context=user_context,
                client_metadata=client_metadata,
            )
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                client, pool = self._find_client(context, request.get("ClientId"))
                if pool.pool_id != pool_id:
                    _error("ResourceNotFoundException", "User pool client changed identity")
            if flow == "USER_PASSWORD_AUTH":
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "PASSWORD", "SECRET_HASH", "USERNAME"}
                )
                if "ALLOW_USER_PASSWORD_AUTH" not in client.explicit_auth_flows:
                    _error(
                        "InvalidParameterException",
                        "USER_PASSWORD_AUTH flow not enabled for this client",
                    )
                return self._password_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=user_context,
                    client_metadata=client_metadata,
                    record_event=True,
                )
            if flow == "USER_SRP_AUTH":
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "SECRET_HASH", "SRP_A", "USERNAME"}
                )
                if "ALLOW_USER_SRP_AUTH" not in client.explicit_auth_flows:
                    _error(
                        "InvalidParameterException",
                        "USER_SRP_AUTH flow not enabled for this client",
                    )
                return self._start_srp_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=user_context,
                    client_metadata=client_metadata,
                )
            if flow in ("REFRESH_TOKEN_AUTH", "REFRESH_TOKEN"):
                _reject_unsupported_fields(
                    parameters, {"DEVICE_KEY", "REFRESH_TOKEN", "SECRET_HASH"}
                )
                if "ALLOW_REFRESH_TOKEN_AUTH" not in client.explicit_auth_flows:
                    _error(
                        "InvalidParameterException",
                        "REFRESH_TOKEN_AUTH flow not enabled for this client",
                    )
                result = self._refresh_auth(context, pool, client, parameters)
                return {"AuthenticationResult": result}
            _error("InvalidParameterException", f"Unsupported authentication flow: {flow}")

    @handler("RespondToAuthChallenge", expand=False)
    def respond_to_auth_challenge(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"ChallengeName", "ChallengeResponses", "ClientId", "ClientMetadata", "Session"},
        )
        client_metadata = (
            _client_metadata(request["ClientMetadata"]) if "ClientMetadata" in request else None
        )
        with cognito_idp_stores.lock:
            client, pool = self._find_client(context, request.get("ClientId"))
            pool_id = pool.pool_id
        responses = request.get("ChallengeResponses")
        if not isinstance(responses, dict):
            _error("InvalidParameterException", "ChallengeResponses is required")
        challenge_name = request.get("ChallengeName")
        if challenge_name == "CUSTOM_CHALLENGE":
            return self._respond_custom_auth(
                context,
                pool_id,
                request.get("ClientId"),
                responses,
                request.get("Session"),
                client_metadata=client_metadata,
            )
        if challenge_name == "PASSWORD_VERIFIER" and _is_custom_srp_session(
            self.get_store(context), request.get("Session")
        ):
            return self._complete_custom_srp_auth(
                context,
                pool_id,
                request.get("ClientId"),
                responses,
                request.get("Session"),
                client_metadata=client_metadata,
            )
        if challenge_name in {
            "EMAIL_OTP",
            "PASSWORD",
            "PASSWORD_SRP",
            "SELECT_CHALLENGE",
            "SELECT_MFA_TYPE",
            "SMS_MFA",
            "SMS_OTP",
        }:
            return self._respond_user_auth_choice(
                context,
                pool_id,
                request.get("ClientId"),
                challenge_name,
                responses,
                request.get("Session"),
                client_metadata=client_metadata,
            )
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                client, pool = self._find_client(context, request.get("ClientId"))
                if pool.pool_id != pool_id:
                    _error("NotAuthorizedException", "Invalid authentication session")
            if challenge_name == "PASSWORD_VERIFIER":
                return self._complete_srp_auth(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "DEVICE_SRP_AUTH":
                return self._start_device_srp_auth(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "DEVICE_PASSWORD_VERIFIER":
                return self._complete_device_srp_auth(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "NEW_PASSWORD_REQUIRED":
                return self._complete_new_password(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "SOFTWARE_TOKEN_MFA":
                return self._complete_software_token_mfa(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "MFA_SETUP":
                return self._complete_mfa_setup(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            if challenge_name == "WEB_AUTHN":
                return self._complete_web_authn_auth(
                    context,
                    pool,
                    client,
                    responses,
                    request.get("Session"),
                    client_metadata=client_metadata,
                )
            _error("InvalidParameterException", f"Unsupported challenge: {challenge_name}")

    @handler("AdminRespondToAuthChallenge", expand=False)
    def admin_respond_to_auth_challenge(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "ChallengeName",
                "ChallengeResponses",
                "ClientId",
                "ClientMetadata",
                "Session",
                "UserPoolId",
            },
        )
        pool_id = _pool_id(request.get("UserPoolId"))
        with cognito_idp_stores.lock:
            _, client_pool = self._find_client(context, request.get("ClientId"))
        if client_pool.pool_id != pool_id:
            _error("NotAuthorizedException", "Invalid authentication session")
        return super().__getattribute__("respond_to_auth_challenge")(
            context,
            {key: value for key, value in request.items() if key != "UserPoolId"},
        )

    @handler("SetUserPoolMfaConfig", expand=False)
    def set_user_pool_mfa_config(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "EmailMfaConfiguration",
                "MfaConfiguration",
                "SmsMfaConfiguration",
                "SoftwareTokenMfaConfiguration",
                "UserPoolId",
                "WebAuthnConfiguration",
            },
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            configuration = request.get("MfaConfiguration", pool.mfa_configuration)
            if configuration not in {"OFF", "ON", "OPTIONAL"}:
                _error("InvalidParameterException", "Invalid MfaConfiguration")
            software_enabled = pool.software_token_mfa_enabled
            if "SoftwareTokenMfaConfiguration" in request:
                software = request.get("SoftwareTokenMfaConfiguration")
                if (
                    not isinstance(software, dict)
                    or set(software) != {"Enabled"}
                    or not isinstance(software["Enabled"], bool)
                ):
                    _error("InvalidParameterException", "Invalid SoftwareTokenMfaConfiguration")
                software_enabled = software["Enabled"]
            web_authn = (
                _web_authn_configuration(request.get("WebAuthnConfiguration"))
                if "WebAuthnConfiguration" in request
                else pool.web_authn_configuration
            )
            email_mfa = _email_mfa_configuration(
                request.get("EmailMfaConfiguration"),
                current=pool.email_mfa_configuration,
                supplied="EmailMfaConfiguration" in request,
            )
            sms_mfa = _sms_mfa_configuration(
                request.get("SmsMfaConfiguration"),
                current=pool.sms_mfa_configuration,
                supplied="SmsMfaConfiguration" in request,
            )
            if sms_mfa is not None and sms_mfa.get("SmsConfiguration") is not None:
                try:
                    validate_notification_configuration(None, sms_mfa["SmsConfiguration"], context)
                except NotificationConfigurationError as error:
                    _error("InvalidParameterException", str(error))
            prospective = copy.copy(pool)
            prospective.mfa_configuration = configuration
            prospective.software_token_mfa_enabled = software_enabled
            prospective.web_authn_configuration = web_authn
            prospective.email_mfa_configuration = email_mfa
            prospective.sms_mfa_configuration = sms_mfa
            _validate_pool_auth_policy(prospective)
            pool.mfa_configuration = configuration
            pool.software_token_mfa_enabled = software_enabled
            pool.web_authn_configuration = web_authn
            pool.email_mfa_configuration = email_mfa
            pool.sms_mfa_configuration = sms_mfa
            pool.updated_at = _now()
            return _mfa_config_response(pool)

    @handler("GetUserPoolMfaConfig", expand=False)
    def get_user_pool_mfa_config(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            return _mfa_config_response(pool)

    @handler("StartWebAuthnRegistration", expand=False)
    def start_web_authn_registration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken"})
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            configuration = _require_web_authn_configuration(pool)
            if len(user.web_authn_credentials) >= _MAX_WEB_AUTHN_CREDENTIALS_PER_USER:
                _error("LimitExceededException", "WebAuthn credential quota exceeded")
            challenge_bytes = secrets.token_bytes(32)
            challenge = _base64_url(challenge_bytes)
            challenge_hash = hashlib.sha256(challenge_bytes).hexdigest()
            now = _now()
            store = self.get_store(context)
            with cognito_idp_stores.lock:
                if not _reserve_web_authn_challenge(store, pool.pool_id, user.username, now):
                    _error("LimitExceededException", "WebAuthn challenge quota exceeded")
                while challenge_hash in store.web_authn_challenges:
                    challenge_bytes = secrets.token_bytes(32)
                    challenge = _base64_url(challenge_bytes)
                    challenge_hash = hashlib.sha256(challenge_bytes).hexdigest()
                store.web_authn_challenges[challenge_hash] = WebAuthnChallenge(
                    token_hash=challenge_hash,
                    challenge_hash=challenge_hash,
                    pool_id=pool.pool_id,
                    client_id=client.client_id,
                    username=user.username,
                    kind="registration",
                    relying_party_id=configuration["RelyingPartyId"],
                    credential_versions={},
                    created_at=now,
                    expires_at=now + _WEB_AUTHN_CHALLENGE_TTL,
                )
            credentials = sorted(
                user.web_authn_credentials.values(), key=lambda item: item.credential_id
            )
            return {
                "CredentialCreationOptions": {
                    "authenticatorSelection": {
                        "requireResidentKey": True,
                        "residentKey": "required",
                        "userVerification": configuration["UserVerification"],
                    },
                    "challenge": challenge,
                    "excludeCredentials": [
                        {
                            "id": credential.credential_id,
                            "transports": list(credential.authenticator_transports),
                            "type": "public-key",
                        }
                        for credential in credentials
                    ],
                    "pubKeyCredParams": [
                        {"alg": -7, "type": "public-key"},
                        {"alg": -257, "type": "public-key"},
                    ],
                    "rp": {
                        "id": configuration["RelyingPartyId"],
                        "name": configuration["RelyingPartyId"],
                    },
                    "timeout": 60_000,
                    "user": {
                        "displayName": user.username,
                        "id": _base64_url(user.sub.encode()),
                        "name": user.username,
                    },
                }
            }

    @handler("CompleteWebAuthnRegistration", expand=False)
    def complete_web_authn_registration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "Credential"})
        credential_input = request.get("Credential")
        try:
            challenge_hash = credential_challenge_hash(credential_input, string_input=False)
        except WebAuthnError:
            _error("WebAuthnCredentialNotSupportedException", "Invalid WebAuthn credential")
        with self._locked_access_token_client_user(context, request.get("AccessToken")) as (
            pool,
            client,
            user,
        ):
            store = self.get_store(context)
            with cognito_idp_stores.lock:
                challenge = store.web_authn_challenges.get(challenge_hash)
                now = _now()
                if challenge is None:
                    _error("WebAuthnChallengeNotFoundException", "WebAuthn challenge expired")
                if challenge.expires_at <= now:
                    store.web_authn_challenges.pop(challenge_hash, None)
                    _error("WebAuthnChallengeNotFoundException", "WebAuthn challenge expired")
                if (
                    challenge.kind != "registration"
                    or challenge.pool_id != pool.pool_id
                    or challenge.client_id != client.client_id
                    or challenge.username != user.username
                ):
                    _error("WebAuthnClientMismatchException", "WebAuthn client mismatch")
                # A caller with another valid access token must not be able to
                # consume the victim's public registration challenge. Once the
                # binding is proven, invalid same-client responses remain one-use.
                store.web_authn_challenges.pop(challenge_hash, None)
            configuration = _require_web_authn_configuration(pool)
            if configuration["RelyingPartyId"] != challenge.relying_party_id:
                _error("WebAuthnRelyingPartyMismatchException", "WebAuthn RP changed")
            try:
                registered = registration_response(
                    credential_input,
                    challenge_hash=challenge.challenge_hash,
                    relying_party_id=challenge.relying_party_id,
                    user_verification=configuration["UserVerification"],
                )
            except WebAuthnError as error:
                code = (
                    "WebAuthnOriginNotAllowedException"
                    if "origin" in str(error).lower()
                    else "WebAuthnRelyingPartyMismatchException"
                    if "relying party" in str(error).lower()
                    else "WebAuthnCredentialNotSupportedException"
                )
                _error(code, str(error))
            if len(user.web_authn_credentials) >= _MAX_WEB_AUTHN_CREDENTIALS_PER_USER:
                _error("LimitExceededException", "WebAuthn credential quota exceeded")
            if any(
                registered.credential_id in candidate.web_authn_credentials
                for candidate in pool.users.values()
            ):
                _error("InvalidParameterException", "WebAuthn credential already exists")
            user.web_authn_credentials[registered.credential_id] = WebAuthnCredential(
                credential_id=registered.credential_id,
                public_key_pem=registered.public_key_pem,
                algorithm=registered.algorithm,
                sign_count=registered.sign_count,
                relying_party_id=challenge.relying_party_id,
                friendly_name="Passkey",
                authenticator_attachment=registered.authenticator_attachment,
                authenticator_transports=registered.authenticator_transports,
                created_at=now,
                version=str(uuid.uuid4()),
            )
            user.updated_at = pool.updated_at = now
            return {}

    @handler("ListWebAuthnCredentials", expand=False)
    def list_web_authn_credentials(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "MaxResults", "NextToken"})
        with self._locked_access_token_user(context, request.get("AccessToken")) as (
            pool,
            user,
        ):
            maximum = request.get("MaxResults", 20)
            if not isinstance(maximum, int) or isinstance(maximum, bool) or not 0 <= maximum <= 20:
                _error("InvalidParameterException", "MaxResults must be between 0 and 20")
            maximum = maximum or 20
            kind = f"web-authn:{user.sub}"
            after = _decode_bound_page_token(pool, request.get("NextToken"), kind)
            credentials = sorted(
                user.web_authn_credentials.values(),
                key=lambda item: (item.created_at, item.credential_id),
            )
            start = 0
            if after is not None:
                index = next(
                    (
                        position
                        for position, credential in enumerate(credentials)
                        if credential.version == after
                    ),
                    None,
                )
                if index is None:
                    _error("InvalidParameterException", "Invalid pagination token")
                start = index + 1
            page = credentials[start : start + maximum]
            response: ServiceResponse = {
                "Credentials": [_web_authn_credential_response(item) for item in page]
            }
            if start + len(page) < len(credentials):
                response["NextToken"] = _encode_bound_page_token(pool, kind, page[-1].version)
            return response

    @handler("DeleteWebAuthnCredential", expand=False)
    def delete_web_authn_credential(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "CredentialId"})
        try:
            credential_id = canonical_credential_id(request.get("CredentialId"))
        except WebAuthnError:
            _error("InvalidParameterException", "Invalid WebAuthn credential ID")
        with self._locked_access_token_user(context, request.get("AccessToken")) as (
            pool,
            user,
        ):
            if user.web_authn_credentials.pop(credential_id, None) is None:
                _error("InvalidParameterException", "WebAuthn credential does not exist")
            user.updated_at = pool.updated_at = _now()
            return {}

    @handler("AssociateSoftwareToken", expand=False)
    def associate_software_token(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccessToken", "Session"})
        access_token, raw_session = request.get("AccessToken"), request.get("Session")
        if (access_token is None) == (raw_session is None):
            _error("InvalidParameterException", "Provide exactly one of AccessToken or Session")
        client_id: str | None = None
        if access_token is not None:
            guard = self._locked_access_token_user(context, access_token)
        else:
            session = _consume_auth_session(self.get_store(context), "mfa_sessions", raw_session)
            if session is None or session.kind != "MFA_SETUP" or session.expires_at <= _now():
                _error("NotAuthorizedException", "Invalid authentication session")
            client_id = session.client_id
            guard = self._locked_pool(context, session.pool_id)
        with guard as locked:
            if access_token is not None:
                pool, user = locked
            else:
                pool = locked
                user = pool.users.get(session.username)
            if user is None or not user.enabled:
                _error("NotAuthorizedException", "Invalid authentication session")
            if not pool.software_token_mfa_enabled:
                _error("SoftwareTokenMFANotFoundException", "Software token MFA is not enabled")
            secret = base64.b32encode(secrets.token_bytes(20)).rstrip(b"=").decode()
            encrypted_secret = _encrypt_totp_secret(pool, secret)
            if access_token is not None:
                user.software_token_mfa_pending_secret = encrypted_secret
                user.software_token_mfa_pending_expires_at = _now() + _AUTH_CHALLENGE_TTL
                user.updated_at = _now()
                return {"SecretCode": secret}
            next_session = self._create_mfa_session(
                context,
                pool,
                user,
                client_id=client_id,
                kind="TOTP_VERIFY",
                encrypted_secret=encrypted_secret,
                device_key=session.device_key,
                client_metadata=session.client_metadata,
            )
            return {"SecretCode": secret, "Session": next_session}

    @handler("VerifySoftwareToken", expand=False)
    def verify_software_token(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"AccessToken", "FriendlyDeviceName", "Session", "UserCode"}
        )
        friendly_name_supplied = "FriendlyDeviceName" in request
        try:
            friendly_name = (
                normalize_friendly_device_name(request.get("FriendlyDeviceName"))
                if friendly_name_supplied
                else None
            )
        except FriendlyDeviceNameError as error:
            _error("InvalidParameterException", str(error))
        access_token, raw_session = request.get("AccessToken"), request.get("Session")
        if (access_token is None) == (raw_session is None):
            _error("InvalidParameterException", "Provide exactly one of AccessToken or Session")
        client_id: str | None = None
        if access_token is not None:
            guard = self._locked_access_token_user(context, access_token)
        else:
            session = _consume_auth_session(self.get_store(context), "mfa_sessions", raw_session)
            if session is None or session.kind != "TOTP_VERIFY" or session.expires_at <= _now():
                _error("NotAuthorizedException", "Invalid authentication session")
            client_id = session.client_id
            guard = self._locked_pool(context, session.pool_id)
        with guard as locked:
            if access_token is not None:
                pool, user = locked
                encrypted_secret = user.software_token_mfa_pending_secret
                expires_at = user.software_token_mfa_pending_expires_at
                user.software_token_mfa_pending_secret = None
                user.software_token_mfa_pending_expires_at = None
                if encrypted_secret is None or expires_at is None or expires_at <= _now():
                    _error("NotAuthorizedException", "Invalid software token association")
            else:
                pool = locked
                user = pool.users.get(session.username)
                encrypted_secret = session.encrypted_secret
                if user is None or not user.enabled or encrypted_secret is None:
                    _error("NotAuthorizedException", "Invalid authentication session")
            secret = _decrypt_totp_secret(pool, encrypted_secret)
            matched_step = _verify_totp_code(secret, request.get("UserCode"), time.time())
            if matched_step is None:
                _error("CodeMismatchException", "Invalid software token code")
            user.software_token_mfa_secret = encrypted_secret
            user.software_token_mfa_enabled = True
            user.software_token_mfa_last_step = matched_step
            user.updated_at = _now()
            with cognito_idp_stores.lock:
                names = FriendlyDeviceNames(
                    self.get_store(context).friendly_device_names,
                    lock=cognito_idp_stores.lock,
                )
                names.remove_user(pool.pool_id, user.username)
                if friendly_name_supplied:
                    names.set(pool.pool_id, user.username, friendly_name)
            response: ServiceResponse = {"Status": "SUCCESS"}
            if client_id is not None:
                response["Session"] = self._create_mfa_session(
                    context,
                    pool,
                    user,
                    client_id=client_id,
                    kind="MFA_SETUP_COMPLETE",
                    device_key=session.device_key,
                    client_metadata=session.client_metadata,
                )
            return response

    @handler("SetUserMFAPreference", expand=False)
    def set_user_mfa_preference(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"AccessToken", "EmailMfaSettings", "SMSMfaSettings", "SoftwareTokenMfaSettings"},
        )
        with self._locked_access_token_user(context, request.get("AccessToken")) as (pool, user):
            _apply_mfa_preferences(pool, user, request)
        return {}

    @handler("AdminSetUserMFAPreference", expand=False)
    def admin_set_user_mfa_preference(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "EmailMfaSettings",
                "SMSMfaSettings",
                "SoftwareTokenMfaSettings",
                "Username",
                "UserPoolId",
            },
        )
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            user = self._user(pool, request.get("Username"))
            _apply_mfa_preferences(pool, user, request)
        return {}

    @handler("RevokeToken", expand=False)
    def revoke_token(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "ClientSecret", "Token"})
        with cognito_idp_stores.lock:
            client, pool = self._find_client(context, request.get("ClientId"))
            pool_id = pool.pool_id
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                client, pool = self._find_client(context, request.get("ClientId"))
                if pool.pool_id != pool_id:
                    _error("ResourceNotFoundException", "User pool client changed identity")
            if not client.enable_token_revocation:
                _error(
                    "UnsupportedOperationException",
                    "Token revocation is disabled for this user pool client",
                )
            _verify_client_secret(pool, client, request.get("ClientSecret"))
            token = _required_string(request, "Token", minimum=1, maximum=4096)
            with cognito_idp_stores.lock:
                sessions = self.get_store(context).refresh_sessions
                session = sessions.get(_token_hash(token))
                if (
                    session is not None
                    and session.pool_id == pool.pool_id
                    and session.client_id == client.client_id
                ):
                    for family_session in sessions.values():
                        if (
                            family_session.pool_id == pool.pool_id
                            and family_session.client_id == client.client_id
                            and family_session.origin_jti == session.origin_jti
                        ):
                            family_session.revoked = True
        return {}

    @handler("GetTokensFromRefreshToken", expand=False)
    def get_tokens_from_refresh_token(
        self,
        context: RequestContext,
        request: ServiceRequest,
        _requested_scopes: list[str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"ClientId", "ClientMetadata", "ClientSecret", "DeviceKey", "RefreshToken"}
        )
        client_metadata = _client_metadata(request.get("ClientMetadata"))
        token = _required_string(request, "RefreshToken", minimum=1, maximum=4096)
        with cognito_idp_stores.lock:
            client, pool = self._find_client(context, request.get("ClientId"))
            pool_id = pool.pool_id
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, request.get("ClientId"))
            _verify_client_secret(pool, client, request.get("ClientSecret"))
            now = _now()
            token_hash = _token_hash(token)
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                session = store.refresh_sessions.get(token_hash)
                if session is not None and session.revoked and session.reuse_detected:
                    _error("RefreshTokenReuseException", "Refresh token family was revoked")
                if (
                    session is None
                    or session.pool_id != pool.pool_id
                    or session.client_id != client.client_id
                    or session.expires_at <= now
                    or session.revoked
                ):
                    _error("NotAuthorizedException", "Invalid refresh token")
                if _requested_scopes is not None and (
                    not _requested_scopes or not set(_requested_scopes) <= set(session.scopes)
                ):
                    _error("InvalidParameterException", "Invalid refresh token scope")
                user = pool.users.get(session.username)
                if (
                    user is None
                    or not user.enabled
                    or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
                ):
                    _error("NotAuthorizedException", "Invalid refresh token")
                refresh_device_key = _validate_refresh_device(
                    pool, user, session, request.get("DeviceKey")
                )

                if not client.refresh_token_rotation_enabled:
                    issued_scopes = (
                        session.scopes if _requested_scopes is None else _requested_scopes
                    )
                    return {
                        "AuthenticationResult": self._authentication_result(
                            context,
                            pool,
                            client,
                            user,
                            include_refresh=False,
                            auth_time=session.auth_time,
                            origin_jti=session.origin_jti,
                            scopes=issued_scopes,
                            filter_oauth_attributes=_refresh_session_uses_oauth_scopes(session),
                            client_metadata=client_metadata,
                            token_trigger_source="TokenGeneration_RefreshTokens",
                        )
                    }

                if session.rotated_at is not None:
                    if (
                        _requested_scopes is not None
                        and session.replacement_scopes is not None
                        and _requested_scopes != session.replacement_scopes
                    ):
                        _error("InvalidParameterException", "Refresh retry scope changed")
                    grace_expires_at = session.retry_grace_expires_at or session.rotated_at
                    replacement = (
                        store.refresh_sessions.get(session.replacement_hash)
                        if session.replacement_hash is not None
                        else None
                    )
                    if (
                        now <= grace_expires_at
                        and session.encrypted_replacement_token is not None
                        and replacement is not None
                        and not replacement.revoked
                        and replacement.rotated_at is None
                    ):
                        result = self._authentication_result(
                            context,
                            pool,
                            client,
                            user,
                            include_refresh=False,
                            auth_time=session.auth_time,
                            origin_jti=session.origin_jti,
                            scopes=session.replacement_scopes or session.scopes,
                            filter_oauth_attributes=_refresh_session_uses_oauth_scopes(session),
                            client_metadata=client_metadata,
                            token_trigger_source="TokenGeneration_RefreshTokens",
                        )
                        result["RefreshToken"] = _decrypt_client_state(
                            pool,
                            session.encrypted_replacement_token,
                            f"refresh-retry:{session.token_hash}",
                        )
                        return {"AuthenticationResult": result}
                    for family_session in store.refresh_sessions.values():
                        if (
                            family_session.pool_id == pool.pool_id
                            and family_session.client_id == client.client_id
                            and family_session.origin_jti == session.origin_jti
                        ):
                            family_session.revoked = True
                            family_session.reuse_detected = True
                    _error(
                        "RefreshTokenReuseException",
                        "Refresh token reuse detected; token family revoked",
                    )

                issued_scopes = session.scopes if _requested_scopes is None else _requested_scopes
                result = self._authentication_result(
                    context,
                    pool,
                    client,
                    user,
                    include_refresh=True,
                    auth_time=session.auth_time,
                    origin_jti=session.origin_jti,
                    scopes=issued_scopes,
                    filter_oauth_attributes=_refresh_session_uses_oauth_scopes(session),
                    device_key=refresh_device_key,
                    client_metadata=client_metadata,
                    token_trigger_source="TokenGeneration_RefreshTokens",
                )
                replacement_token = result["RefreshToken"]
                replacement_hash = _token_hash(replacement_token)
                replacement = store.refresh_sessions[replacement_hash]
                replacement.generation = session.generation + 1
                session.rotated_at = now
                session.retry_grace_expires_at = now + timedelta(
                    seconds=client.refresh_token_rotation_grace_seconds
                )
                session.replacement_hash = replacement_hash
                session.replacement_scopes = list(issued_scopes)
                session.encrypted_replacement_token = _encrypt_client_state(
                    pool,
                    replacement_token,
                    f"refresh-retry:{session.token_hash}",
                )
                return {"AuthenticationResult": result}

    @handler("AddUserPoolClientSecret", expand=False)
    def add_user_pool_client_secret(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "ClientSecret", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            if not _client_secret_values(pool, client):
                _error(
                    "InvalidParameterException",
                    "Client secrets can only be added to confidential app clients",
                )
            if len(_client_secret_values(pool, client)) >= _MAX_CLIENT_SECRETS:
                _error("LimitExceededException", "App clients support at most two secrets")
            supplied = request.get("ClientSecret")
            value = (
                _client_secret_value(supplied)
                if supplied is not None
                else _generate_client_secret()
            )
            if any(
                hmac.compare_digest(value, current)
                for current in _client_secret_values(pool, client)
            ):
                _error("InvalidParameterException", "Client secret values must be unique")
            secret_id = secrets.token_urlsafe(18)
            now = _now()
            client.additional_secrets[secret_id] = UserPoolClientSecret(
                secret_id=secret_id,
                encrypted_value=_encrypt_client_state(
                    pool, value, f"client-secret:{client.client_id}:{secret_id}"
                ),
                created_at=now,
            )
            client.updated_at = pool.updated_at = now
            descriptor = {
                "ClientSecretCreateDate": now,
                "ClientSecretId": secret_id,
            }
            if supplied is None:
                descriptor["ClientSecretValue"] = value
            return {"ClientSecretDescriptor": descriptor}

    @handler("DeleteUserPoolClientSecret", expand=False)
    def delete_user_pool_client_secret(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "ClientSecretId", "UserPoolId"})
        secret_id = _required_string(request, "ClientSecretId", minimum=1, maximum=128)
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            descriptors = _client_secret_descriptors(client)
            if secret_id not in {item["ClientSecretId"] for item in descriptors}:
                _error("ResourceNotFoundException", "Client secret does not exist")
            if len(descriptors) <= 1:
                _error("LimitExceededException", "The last client secret cannot be deleted")
            if secret_id == _primary_client_secret_id(client):
                client.secret = None
                client.primary_secret = None
            else:
                client.additional_secrets.pop(secret_id, None)
            client.updated_at = pool.updated_at = _now()
            return {}

    @handler("ListUserPoolClientSecrets", expand=False)
    def list_user_pool_client_secrets(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ClientId", "NextToken", "UserPoolId"})
        with self._locked_pool(context, request.get("UserPoolId")) as pool:
            client = self._client(pool, request.get("ClientId"))
            if request.get("NextToken") is not None:
                _decode_bound_page_token(
                    pool,
                    request.get("NextToken"),
                    f"client-secrets:{client.client_id}",
                )
            return {"ClientSecrets": _client_secret_descriptors(client)}

    def get_jwks(self, context: RequestContext, user_pool_id: str) -> dict[str, Any]:
        pool_id = _pool_id(user_pool_id)
        with _pool_guard(pool_id):
            with cognito_idp_stores.lock:
                location = cognito_idp_stores._universal.get("POOL_LOCATIONS", {}).get(pool_id)
                if location is None or location[0] != context.account_id:
                    _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
                store = cognito_idp_stores[context.account_id][location[1]]
                pool = store.user_pools.get(pool_id)
                if pool is None:
                    _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
                if context.region != location[1]:
                    topology = store.user_pool_replicas.get(pool_id)
                    if topology is None:
                        _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
                    try:
                        return resolve_regional_pool(
                            topology,
                            pool,
                            serving_region=context.region,
                            operation="JWKS",
                            dns_suffix=_partition_dns_suffix(context.partition),
                        ).jwks()
                    except ReplicaDataPlaneError as error:
                        _error(error.code, str(error))
                return {"keys": [dict(pool.access_signing_jwk), dict(pool.id_signing_jwk)]}

    def get_jwks_for_pool_id(self, user_pool_id: str) -> dict[str, Any]:
        """Return public keys for the unsigned Cognito discovery endpoint."""
        with cognito_idp_stores.lock:
            location = resolve_pool_location(user_pool_id)
            if location is None:
                _error("ResourceNotFoundException", f"User pool {user_pool_id} does not exist")
            account_id, region = location
            pool = cognito_idp_stores[account_id][region].user_pools.get(user_pool_id)
            if pool is None:
                _error("ResourceNotFoundException", f"User pool {user_pool_id} does not exist")
            return {"keys": [dict(pool.access_signing_jwk), dict(pool.id_signing_jwk)]}

    def issue_oauth_tokens(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: str,
        username: str,
        scopes: list[str],
        nonce: str | None,
    ) -> dict[str, Any]:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            user = self._user(pool, username)
            if (
                not client.allowed_oauth_flows_user_pool_client
                or "code" not in client.allowed_oauth_flows
                or not scopes
                or not set(scopes) <= set(client.allowed_oauth_scopes)
                or not user.enabled
                or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
            ):
                _error("NotAuthorizedException", "Invalid OAuth authorization code")
            return self._authentication_result(
                context,
                pool,
                client,
                user,
                include_refresh=True,
                scopes=scopes,
                nonce=nonce,
                filter_oauth_attributes=True,
            )

    def federated_sign_in(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: str,
        provider_name: str,
        claims: dict[str, Any],
        provider_version: datetime | None = None,
    ) -> str:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            provider = _identity_provider(pool, provider_name)
            if provider_version is not None and provider.updated_at != provider_version:
                _error("NotAuthorizedException", "Identity provider changed during sign-in")
            if provider.provider_name not in client.supported_identity_providers:
                _error("NotAuthorizedException", "Identity provider is not enabled for client")
            subject = claims.get("sub")
            if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
                _error("NotAuthorizedException", "OIDC subject is missing")
            mapped_attributes = {}
            for destination, source in provider.attribute_mapping.items():
                if destination == "username" or source not in claims:
                    continue
                raw_value = claims[source]
                if isinstance(raw_value, bool):
                    value = "true" if raw_value else "false"
                elif isinstance(raw_value, (str, int, float)) and not isinstance(raw_value, bool):
                    value = str(raw_value)
                else:
                    _error("InvalidParameterException", f"OIDC claim {source} is not scalar")
                if not 1 <= len(value) <= _MAX_ATTRIBUTE_VALUE_CHARACTERS:
                    _error("InvalidParameterException", f"OIDC claim {source} exceeds bounds")
                mapped_attributes[destination] = value

            matches = []
            for candidate in pool.users.values():
                for identity in candidate.federated_identities:
                    if identity.provider_name != provider.provider_name:
                        continue
                    source_value = (
                        subject
                        if identity.provider_attribute_name == "Cognito_Subject"
                        else mapped_attributes.get(identity.provider_attribute_name)
                    )
                    if source_value is not None and hmac.compare_digest(
                        identity.provider_attribute_value, source_value
                    ):
                        matches.append(candidate)
                        break
            if len(matches) > 1:
                _error("NotAuthorizedException", "Federated identity link is ambiguous")
            if matches:
                user = matches[0]
            else:
                user = next(
                    (
                        candidate
                        for candidate in pool.users.values()
                        if any(
                            identity.provider_name == provider.provider_name
                            and identity.provider_attribute_name == "Cognito_Subject"
                            and hmac.compare_digest(identity.provider_attribute_value, subject)
                            for identity in candidate.federated_identities
                        )
                    ),
                    None,
                )
            now = _now()
            if user is None:
                if len(pool.users) >= _MAX_USERS_PER_POOL:
                    _error("LimitExceededException", "User quota exceeded")
                username = _federated_username(provider.provider_name, subject)
                if username in pool.users:
                    _error("AliasExistsException", "Federated username already exists")
                _validate_initial_user_attributes(
                    pool, username, mapped_attributes, administrator=True
                )
                password, salt, verifier = _password_credentials(
                    pool.pool_id, username, secrets.token_urlsafe(48)
                )
                user = CognitoUser(
                    username=username,
                    sub=str(uuid.uuid4()),
                    password=password,
                    status="EXTERNAL_PROVIDER",
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                    srp_salt=salt,
                    srp_verifier=verifier,
                    attributes=dict(mapped_attributes),
                )
                pool.users[username] = user
                _add_user_identity_indexes(pool, user)
            else:
                if not user.enabled:
                    _error("NotAuthorizedException", "Federated user is disabled")
                _validate_schema_mutation(
                    pool,
                    user,
                    set(mapped_attributes),
                    administrator=True,
                    attribute_values=mapped_attributes,
                )
                prospective = dict(user.attributes)
                prospective.update(mapped_attributes)
                _replace_user_attributes(pool, user, prospective)
            if not any(
                identity.provider_name == provider.provider_name
                and identity.provider_attribute_name == "Cognito_Subject"
                and hmac.compare_digest(identity.provider_attribute_value, subject)
                for identity in user.federated_identities
            ):
                if len(user.federated_identities) >= _MAX_FEDERATED_IDENTITIES_PER_USER:
                    _error("LimitExceededException", "Federated identity quota exceeded")
                user.federated_identities.append(
                    FederatedIdentity(
                        provider_name=provider.provider_name,
                        provider_attribute_name="Cognito_Subject",
                        provider_attribute_value=subject,
                        created_at=now,
                    )
                )
            user.updated_at = pool.updated_at = now
            return user.username

    def refresh_oauth_tokens(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: str,
        refresh_token: str,
        requested_scopes: list[str] | None,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            with cognito_idp_stores.lock:
                session = self.get_store(context).refresh_sessions.get(_token_hash(refresh_token))
            if (
                session is None
                or session.revoked
                or session.expires_at <= _now()
                or session.pool_id != pool.pool_id
                or session.client_id != client.client_id
                or (
                    requested_scopes is not None
                    and (not requested_scopes or not set(requested_scopes) <= set(session.scopes))
                )
            ):
                _error("NotAuthorizedException", "Invalid refresh token")
        return self.get_tokens_from_refresh_token(
            context,
            {
                "ClientId": client_id,
                **({"ClientSecret": client_secret} if client_secret is not None else {}),
                "RefreshToken": refresh_token,
            },
            _requested_scopes=requested_scopes,
        )["AuthenticationResult"]

    def _start_user_auth_choice(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: Any,
        parameters: dict[str, Any],
        *,
        auth_context: dict[str, str],
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            parameters,
            {
                "DEVICE_KEY",
                "PASSWORD",
                "PREFERRED_CHALLENGE",
                "SECRET_HASH",
                "SRP_A",
                "USERNAME",
            },
        )
        username = _required_string(parameters, "USERNAME", minimum=1, maximum=128)
        preferred = parameters.get("PREFERRED_CHALLENGE")
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            if "ALLOW_USER_AUTH" not in client.explicit_auth_flows:
                _error("InvalidParameterException", "USER_AUTH flow not enabled")
            self._verify_secret_hash(pool, client, username, parameters.get("SECRET_HASH"))
            if preferred == "PASSWORD" and "PASSWORD" in parameters:
                return self._password_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=auth_context,
                    client_metadata=client_metadata,
                    record_event=True,
                )
            if preferred == "PASSWORD_SRP" and "SRP_A" in parameters:
                return self._start_srp_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=auth_context,
                    client_metadata=client_metadata,
                )
            if preferred == "WEB_AUTHN":
                return self._start_web_authn_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    client_metadata=client_metadata,
                )
            user = _resolve_pool_user(pool, username)
            if user is not None and not user.enabled:
                user = None
            canonical = user.username if user is not None else username
            policy = _validate_pool_auth_policy(pool)
            user_state = _user_auth_state(pool, user) if user is not None else None
            engine = _mfa_passwordless_engine(self.get_store(context), pool, client)
            sender = _mfa_otp_sender(
                context,
                pool,
                purpose=preferred,
                expected_user=user,
            )
            prevent = client.prevent_user_existence_errors == "ENABLED"
            captured_client_id = client.client_id
        try:
            return engine.start_user_auth(
                policy=policy,
                user=user_state,
                pool_id=pool_id,
                client_id=captured_client_id,
                preferred_challenge=preferred,
                prevent_user_existence_errors=prevent,
                client_metadata=client_metadata or {},
                sender=sender,
                now=_now(),
                username=canonical,
            )
        except MfaPasswordlessError as error:
            _error(error.code, str(error))
        except NotificationConfigurationError as error:
            _error(getattr(error, "code", "InvalidParameterException"), str(error))
        except NotificationDeliveryError as error:
            _error(error.code, str(error))
        except NotificationCommitError as error:
            _error("CodeDeliveryFailureException", str(error))

    def _respond_user_auth_choice(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: Any,
        challenge_name: str,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        allowed = {
            "ANSWER",
            "DEVICE_KEY",
            "EMAIL_OTP_CODE",
            "PASSWORD",
            "SECRET_HASH",
            "SMS_MFA_CODE",
            "SMS_OTP_CODE",
            "SRP_A",
            "USERNAME",
        }
        _reject_unsupported_fields(responses, allowed)
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
            user = _resolve_pool_user(pool, username)
            canonical = user.username if user is not None else username
            policy = _validate_pool_auth_policy(pool)
            user_state = _user_auth_state(pool, user) if user is not None else None
            engine = _mfa_passwordless_engine(self.get_store(context), pool, client)
            sender = _mfa_otp_sender(
                context,
                pool,
                purpose=(
                    "EMAIL_MFA"
                    if challenge_name == "SELECT_MFA_TYPE"
                    and responses.get("ANSWER") == "EMAIL_OTP"
                    else responses.get("ANSWER")
                ),
                expected_user=user,
            )
            captured_client_id = client.client_id
        try:
            if challenge_name == "SELECT_CHALLENGE":
                answer = responses.get("ANSWER")
                result = engine.respond_select_challenge(
                    policy=policy,
                    user=user_state,
                    session=raw_session,
                    answer=answer,
                    username=canonical,
                    pool_id=pool_id,
                    client_id=captured_client_id,
                    sender=sender,
                    now=_now(),
                )
                if answer in {"PASSWORD", "PASSWORD_SRP", "WEB_AUTHN"}:
                    engine.consume_primary_challenge(
                        challenge_name=answer,
                        session=result["Session"],
                        username=canonical,
                        pool_id=pool_id,
                        client_id=captured_client_id,
                        now=_now(),
                    )
                    return self._continue_selected_primary_auth(
                        context,
                        pool_id,
                        captured_client_id,
                        answer,
                        responses,
                        client_metadata=client_metadata,
                    )
                return result
            if challenge_name == "SELECT_MFA_TYPE":
                if user_state is None:
                    _error("NotAuthorizedException", "Invalid authentication session")
                return engine.respond_select_mfa(
                    policy=policy,
                    user=user_state,
                    session=raw_session,
                    answer=responses.get("ANSWER"),
                    username=canonical,
                    pool_id=pool_id,
                    client_id=captured_client_id,
                    sender=sender,
                    now=_now(),
                )
            if challenge_name in {"EMAIL_OTP", "SMS_OTP", "SMS_MFA"}:
                completion = engine.complete_otp(
                    challenge_name=challenge_name,
                    session=raw_session,
                    username=canonical,
                    response_code={
                        "EMAIL_OTP": "EMAIL_OTP_CODE",
                        "SMS_OTP": "SMS_OTP_CODE",
                        "SMS_MFA": "SMS_MFA_CODE",
                    }[challenge_name],
                    response_value=responses.get(
                        {
                            "EMAIL_OTP": "EMAIL_OTP_CODE",
                            "SMS_OTP": "SMS_OTP_CODE",
                            "SMS_MFA": "SMS_MFA_CODE",
                        }[challenge_name]
                    ),
                    pool_id=pool_id,
                    client_id=captured_client_id,
                    now=_now(),
                )
                return self._finish_otp_auth(
                    context,
                    pool_id,
                    captured_client_id,
                    completion,
                    device_key=responses.get("DEVICE_KEY"),
                    client_metadata=client_metadata,
                )
            if challenge_name in {"PASSWORD", "PASSWORD_SRP"}:
                engine.consume_primary_challenge(
                    challenge_name=challenge_name,
                    session=raw_session,
                    username=canonical,
                    pool_id=pool_id,
                    client_id=captured_client_id,
                    now=_now(),
                )
                return self._continue_selected_primary_auth(
                    context,
                    pool_id,
                    captured_client_id,
                    challenge_name,
                    responses,
                    client_metadata=client_metadata,
                )
        except MfaPasswordlessError as error:
            _error(error.code, str(error))
        except NotificationConfigurationError as error:
            _error(getattr(error, "code", "InvalidParameterException"), str(error))
        except NotificationDeliveryError as error:
            _error(error.code, str(error))
        except NotificationCommitError as error:
            _error("CodeDeliveryFailureException", str(error))
        _error("InvalidParameterException", f"Unsupported USER_AUTH challenge: {challenge_name}")

    def _continue_selected_primary_auth(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: str,
        challenge_name: str,
        responses: dict[str, Any],
        *,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            if challenge_name == "PASSWORD":
                return self._password_auth(
                    context,
                    pool,
                    client,
                    responses,
                    auth_context={},
                    client_metadata=client_metadata,
                    record_event=True,
                )
            if challenge_name == "PASSWORD_SRP":
                return self._start_srp_auth(
                    context,
                    pool,
                    client,
                    responses,
                    auth_context={},
                    client_metadata=client_metadata,
                )
            if challenge_name == "WEB_AUTHN":
                return self._start_web_authn_auth(
                    context, pool, client, responses, client_metadata=client_metadata
                )
        _error("InvalidParameterException", "Invalid selected primary challenge")

    def _finish_otp_auth(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: str,
        completion: Any,
        *,
        device_key: Any,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            user = pool.users.get(completion.username)
            if user is None or not user.enabled:
                _error("NotAuthorizedException", "Invalid authentication session")
            if completion.verified_attribute is not None:
                user.attributes[f"{completion.verified_attribute}_verified"] = "true"
            if completion.confirm_user and user.status == "UNCONFIRMED":
                user.status = "CONFIRMED"
            user.updated_at = pool.updated_at = _now()
            return {
                "AuthenticationResult": self._authentication_result(
                    context,
                    pool,
                    client,
                    user,
                    include_refresh=True,
                    device_key=_optional_auth_device_key(
                        device_key if device_key is not None else completion.device_key
                    ),
                    client_metadata=(
                        completion.client_metadata if client_metadata is None else client_metadata
                    ),
                )
            }

    def _password_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        parameters: dict[str, Any],
        *,
        allow_force_change: bool = False,
        auth_context: dict[str, str] | None = None,
        client_metadata: dict[str, str] | None = None,
        record_event: bool = False,
    ) -> ServiceResponse:
        username = parameters.get("USERNAME")
        password = parameters.get("PASSWORD")
        if (
            not isinstance(username, str)
            or not 1 <= len(username) <= 128
            or not isinstance(password, str)
            or not 1 <= len(password) <= 256
        ):
            _error("InvalidParameterException", "USERNAME and PASSWORD are required")
        device_key = _optional_auth_device_key(parameters.get("DEVICE_KEY"))
        auth_context = auth_context or {}
        risk_level, risk_decision, blocked, compromised = _evaluate_local_auth_risk(
            pool, client, password, auth_context.get("IpAddress")
        )
        if blocked:
            if record_event:
                _record_auth_event(
                    context,
                    self.get_store(context),
                    pool,
                    client,
                    username,
                    False,
                    auth_context,
                    risk_level,
                    risk_decision,
                    compromised,
                )
            _error("NotAuthorizedException", "Authentication blocked by risk configuration")
        user = _resolve_pool_user(pool, username)
        password_valid = user.password.verify(password) if user else _dummy_password_check(password)
        if (
            user is None
            or not password_valid
            or not user.enabled
            or _temporary_password_expired(user, _now())
            or user.status
            not in ({"CONFIRMED", "FORCE_CHANGE_PASSWORD"} if allow_force_change else {"CONFIRMED"})
        ):
            if record_event:
                _record_auth_event(
                    context,
                    self.get_store(context),
                    pool,
                    client,
                    username,
                    False,
                    auth_context,
                    risk_level,
                    risk_decision,
                    compromised,
                )
            _error("NotAuthorizedException", "Incorrect username or password")
        try:
            self._verify_secret_hash(pool, client, username, parameters.get("SECRET_HASH"))
        except CommonServiceException:
            if record_event:
                _record_auth_event(
                    context,
                    self.get_store(context),
                    pool,
                    client,
                    username,
                    False,
                    auth_context,
                    risk_level,
                    risk_decision,
                    compromised,
                )
            raise
        if user.password.is_imported:
            password_hash, srp_salt, srp_verifier = _password_credentials(
                pool.pool_id, user.username, password
            )
            user.password = password_hash
            user.srp_salt = srp_salt
            user.srp_verifier = srp_verifier
            user.updated_at = pool.updated_at = _now()
        if allow_force_change and user.status == "FORCE_CHANGE_PASSWORD":
            return self._new_password_challenge(
                context,
                pool,
                client,
                user,
                device_key=device_key,
                client_metadata=client_metadata,
            )
        result = self._post_primary_auth(
            context,
            pool,
            client,
            user,
            device_key=device_key,
            client_metadata=client_metadata,
        )
        if record_event and "AuthenticationResult" in result:
            _record_auth_event(
                context,
                self.get_store(context),
                pool,
                client,
                username,
                True,
                auth_context,
                risk_level,
                risk_decision,
                compromised,
            )
        return result

    def _start_custom_auth(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: Any,
        parameters: dict[str, Any],
        *,
        auth_context: dict[str, str],
        initial_history: list[CustomChallengeResult] | None = None,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            parameters, {"CHALLENGE_NAME", "SECRET_HASH", "SRP_A", "USERNAME"}
        )
        username = _required_string(parameters, "USERNAME", minimum=1, maximum=128)
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            if "ALLOW_CUSTOM_AUTH" not in client.explicit_auth_flows:
                _error("InvalidParameterException", "CUSTOM_AUTH flow not enabled")
            challenge_name = parameters.get("CHALLENGE_NAME")
            if challenge_name is not None or "SRP_A" in parameters:
                if challenge_name != "SRP_A" or "SRP_A" not in parameters:
                    _error("InvalidParameterException", "Invalid CUSTOM_AUTH SRP parameters")
                return self._start_srp_auth(
                    context,
                    pool,
                    client,
                    parameters,
                    auth_context=auth_context,
                    custom_auth=True,
                )
            self._verify_secret_hash(pool, client, username, parameters.get("SECRET_HASH"))
            user = _resolve_pool_user(pool, username)
            if user is None:
                if client.prevent_user_existence_errors != "ENABLED":
                    _error("UserNotFoundException", "User does not exist")
                canonical_username = username
                user_not_found = True
                user_attributes = _synthetic_custom_auth_attributes(pool, username)
                expected_sub = None
            else:
                if not user.enabled or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}:
                    _error("NotAuthorizedException", "Incorrect username or password")
                canonical_username = user.username
                user_not_found = False
                user_attributes = _trigger_user_attributes(user)
                expected_sub = user.sub
            _, _, blocked, _ = _evaluate_local_auth_risk(
                pool, client, None, auth_context.get("IpAddress")
            )
            if blocked:
                _error("NotAuthorizedException", "Authentication blocked by risk configuration")
            pool_snapshot = copy.copy(pool)
            pool_snapshot.lambda_config = dict(pool.lambda_config or {})
            state = self.get_store(context).custom_auth
            state_secret = bytes(pool.id_signing_private_key_pem)
            captured_client_id = client.client_id
        manager = CustomAuthManager(state, lambda _: state_secret)
        try:
            outcome = manager.start(
                region=context.region,
                pool_id=pool_id,
                client_id=captured_client_id,
                username=canonical_username,
                user_attributes=user_attributes,
                user_not_found=user_not_found,
                invoke=_custom_auth_trigger_invoker(context, pool_snapshot),
                initial_history=initial_history,
                client_metadata=client_metadata,
            )
        except CustomAuthError as error:
            _error(error.code, error.message)
        return self._finish_custom_auth(
            context,
            outcome,
            pool_id=pool_id,
            client_id=captured_client_id,
            expected_sub=expected_sub,
            client_metadata=client_metadata,
        )

    def _respond_custom_auth(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: Any,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(responses, {"ANSWER", "SECRET_HASH", "USERNAME"})
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        answer = responses.get("ANSWER")
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            if "ALLOW_CUSTOM_AUTH" not in client.explicit_auth_flows:
                _error("InvalidParameterException", "CUSTOM_AUTH flow not enabled")
            self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
            user = _resolve_pool_user(pool, username)
            if user is None:
                if client.prevent_user_existence_errors != "ENABLED":
                    _error("NotAuthorizedException", "Invalid authentication session")
                canonical_username = username
                expected_sub = None
            else:
                canonical_username = user.username
                expected_sub = user.sub
            pool_snapshot = copy.copy(pool)
            pool_snapshot.lambda_config = dict(pool.lambda_config or {})
            state = self.get_store(context).custom_auth
            state_secret = bytes(pool.id_signing_private_key_pem)
            captured_client_id = client.client_id
        manager = CustomAuthManager(state, lambda _: state_secret)
        try:
            outcome = manager.respond(
                region=context.region,
                session_token=raw_session,
                challenge_answer=answer,
                client_metadata=client_metadata,
                invoke=_custom_auth_trigger_invoker(context, pool_snapshot),
                expected_pool_id=pool_id,
                expected_client_id=captured_client_id,
                expected_username=canonical_username,
            )
        except CustomAuthError as error:
            _error(error.code, error.message)
        return self._finish_custom_auth(
            context,
            outcome,
            pool_id=pool_id,
            client_id=captured_client_id,
            expected_sub=expected_sub,
            client_metadata=client_metadata,
        )

    def _complete_custom_srp_auth(
        self,
        context: RequestContext,
        pool_id: str,
        client_id: Any,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            verified = self._complete_srp_auth(
                context,
                pool,
                client,
                responses,
                raw_session,
                client_metadata=client_metadata,
                defer_custom_auth=True,
            )
        return self._start_custom_auth(
            context,
            pool_id,
            client_id,
            {
                "SECRET_HASH": responses.get("SECRET_HASH"),
                "USERNAME": verified["_CustomAuthUsername"],
            },
            auth_context=verified["_CustomAuthContext"],
            initial_history=[
                CustomChallengeResult("SRP_A", True),
                CustomChallengeResult("PASSWORD_VERIFIER", True),
            ],
            client_metadata=client_metadata,
        )

    def _finish_custom_auth(
        self,
        context: RequestContext,
        outcome: CustomAuthOutcome,
        *,
        pool_id: str,
        client_id: str,
        expected_sub: str | None,
        client_metadata: dict[str, str] | None,
    ) -> ServiceResponse:
        if not outcome.issue_tokens:
            return {
                "ChallengeName": "CUSTOM_CHALLENGE",
                "ChallengeParameters": dict(outcome.challenge_parameters or {}),
                "Session": outcome.session,
            }
        if expected_sub is None:
            _error("NotAuthorizedException", "Incorrect username or password")
        with self._locked_pool(context, pool_id) as pool:
            client = self._client(pool, client_id)
            user = _resolve_pool_user(pool, outcome.username)
            if (
                user is None
                or not user.enabled
                or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
                or not hmac.compare_digest(user.sub, expected_sub)
            ):
                _error("NotAuthorizedException", "Invalid authentication session")
            return self._post_primary_auth(
                context,
                pool,
                client,
                user,
                client_metadata=client_metadata,
            )

    def _post_primary_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        user: CognitoUser,
        *,
        device_key: str | None = None,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        device = user.devices.get(device_key) if device_key is not None else None
        email_enabled = getattr(user, "email_mfa_enabled", False)
        sms_enabled = getattr(user, "sms_mfa_enabled", False)
        if pool.mfa_configuration == "ON":
            email_enabled = email_enabled or bool(
                pool.email_mfa_configuration and user.attributes.get("email")
            )
            sms_enabled = sms_enabled or bool(
                (pool.sms_mfa_configuration or pool.sms_configuration)
                and user.attributes.get("phone_number")
            )
        message_mfa_enabled = email_enabled or sms_enabled
        message_mfa_preferred = getattr(user, "email_mfa_preferred", False) or getattr(
            user, "sms_mfa_preferred", False
        )
        if (
            pool.mfa_configuration != "OFF"
            and message_mfa_enabled
            and (message_mfa_preferred or not user.software_token_mfa_enabled)
        ):
            state = dataclasses.replace(
                _user_auth_state(pool, user),
                email_mfa_enabled=email_enabled,
                sms_mfa_enabled=sms_enabled,
            )
            purpose = (
                "EMAIL_MFA"
                if state.email_mfa_preferred or (email_enabled and not sms_enabled)
                else "SMS_MFA"
                if state.sms_mfa_preferred or (sms_enabled and not email_enabled)
                else None
            )
            try:
                return _mfa_passwordless_engine(self.get_store(context), pool, client).start_mfa(
                    policy=_validate_pool_auth_policy(pool),
                    user=state,
                    pool_id=pool.pool_id,
                    client_id=client.client_id,
                    client_metadata=client_metadata or {},
                    sender=_mfa_otp_sender(context, pool, purpose=purpose, expected_user=user),
                    now=_now(),
                    device_key=device_key,
                )
            except MfaPasswordlessError as error:
                _error(error.code, str(error))
            except NotificationConfigurationError as error:
                _error(getattr(error, "code", "InvalidParameterException"), str(error))
            except NotificationDeliveryError as error:
                _error(error.code, str(error))
            except NotificationCommitError as error:
                _error("CodeDeliveryFailureException", str(error))
        if (
            pool.mfa_configuration != "OFF"
            and pool.software_token_mfa_enabled
            and user.software_token_mfa_enabled
        ):
            challenge_name = "SOFTWARE_TOKEN_MFA"
        elif pool.mfa_configuration == "ON":
            challenge_name = "MFA_SETUP"
        else:
            return {
                "AuthenticationResult": self._authentication_result(
                    context,
                    pool,
                    client,
                    user,
                    include_refresh=True,
                    device_key=device_key,
                    client_metadata=client_metadata,
                )
            }
        if (
            pool.challenge_required_on_new_device
            and device is not None
            and device.remembered_status == "remembered"
        ):
            challenge_name = "DEVICE_SRP_AUTH"
        session = self._create_mfa_session(
            context,
            pool,
            user,
            client_id=client.client_id,
            kind=challenge_name,
            device_key=device_key,
            client_metadata=client_metadata,
        )
        parameters = {"USER_ID_FOR_SRP": user.username, "USERNAME": user.username}
        if challenge_name == "DEVICE_SRP_AUTH":
            parameters["DEVICE_KEY"] = device_key
        if challenge_name == "MFA_SETUP":
            available = []
            if pool.software_token_mfa_enabled:
                available.append("SOFTWARE_TOKEN_MFA")
            if pool.email_mfa_configuration is not None:
                available.append("EMAIL_OTP")
            if pool.sms_mfa_configuration is not None or pool.sms_configuration is not None:
                available.append("SMS_MFA")
            parameters["MFAS_CAN_SETUP"] = json.dumps(available)
        return {
            "ChallengeName": challenge_name,
            "ChallengeParameters": parameters,
            "Session": session,
        }

    def _create_mfa_session(
        self,
        context: RequestContext,
        pool: UserPool,
        user: CognitoUser,
        *,
        client_id: str | None,
        kind: str,
        encrypted_secret: str | None = None,
        device_key: str | None = None,
        client_metadata: dict[str, str] | None = None,
    ) -> str:
        raw_session = secrets.token_urlsafe(48)
        token_hash = _token_hash(raw_session)
        now = _now()
        with cognito_idp_stores.lock:
            store = self.get_store(context)
            _prune_auth_challenge_sessions(store, now)
            store.mfa_sessions[token_hash] = MfaSession(
                token_hash=token_hash,
                pool_id=pool.pool_id,
                client_id=client_id,
                username=user.username,
                kind=kind,
                encrypted_secret=encrypted_secret,
                created_at=now,
                expires_at=now + _AUTH_CHALLENGE_TTL,
                device_key=device_key,
                client_metadata=dict(client_metadata or {}),
            )
        return raw_session

    def _start_device_srp_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(responses, {"DEVICE_KEY", "SECRET_HASH", "SRP_A", "USERNAME"})
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        device_key = _device_key(responses.get("DEVICE_KEY"))
        session = _consume_bound_mfa_session(
            self.get_store(context),
            raw_session,
            kind="DEVICE_SRP_AUTH",
            pool_id=pool.pool_id,
            client_id=client.client_id,
            username=username,
            device_key=device_key,
        )
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        user = _resolve_pool_user(pool, username)
        device = user.devices.get(device_key) if user is not None else None
        if (
            user is None
            or not user.enabled
            or not pool.device_tracking_enabled
            or device is None
            or device.remembered_status != "remembered"
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        try:
            started = start_device_srp(
                pool_id=pool.pool_id,
                client_id=client.client_id,
                username=user.username,
                device_key=device.device_key,
                device_group_key=device.device_group_key,
                salt=device.salt,
                verifier=device.verifier,
                public_a=responses.get("SRP_A"),
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
            with cognito_idp_stores.lock:
                _prune_auth_challenge_sessions(self.get_store(context), _now())
                reserve_device_srp_session(
                    self.get_store(context).device_srp_sessions,
                    started,
                    maximum=_MAX_AUTH_CHALLENGE_SESSIONS,
                )
        except DeviceSrpError as error:
            _error(error.code, str(error))
        return {
            "ChallengeName": "DEVICE_PASSWORD_VERIFIER",
            "ChallengeParameters": started.challenge_parameters,
            "Session": started.session_token,
        }

    def _complete_device_srp_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            responses,
            {
                "DEVICE_KEY",
                "PASSWORD_CLAIM_SECRET_BLOCK",
                "PASSWORD_CLAIM_SIGNATURE",
                "SECRET_HASH",
                "TIMESTAMP",
                "USERNAME",
            },
        )
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        device_key = _device_key(responses.get("DEVICE_KEY"))
        with cognito_idp_stores.lock:
            try:
                session = consume_device_srp_session(
                    self.get_store(context).device_srp_sessions,
                    raw_session,
                    pool_id=pool.pool_id,
                    client_id=client.client_id,
                    username=username,
                    device_key=device_key,
                )
            except DeviceSrpError as error:
                _error(error.code, str(error))
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        user = _resolve_pool_user(pool, username)
        device = user.devices.get(device_key) if user is not None else None
        if (
            user is None
            or not user.enabled
            or not pool.device_tracking_enabled
            or device is None
            or device.remembered_status != "remembered"
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        try:
            verify_device_password(
                session,
                device_group_key=device.device_group_key,
                secret_block=responses.get("PASSWORD_CLAIM_SECRET_BLOCK"),
                timestamp=responses.get("TIMESTAMP"),
                signature=responses.get("PASSWORD_CLAIM_SIGNATURE"),
            )
        except DeviceSrpError as error:
            _error(error.code, str(error))
        now = _now()
        device.last_authenticated_at = now
        device.updated_at = user.updated_at = pool.updated_at = now
        return {
            "AuthenticationResult": self._authentication_result(
                context,
                pool,
                client,
                user,
                include_refresh=True,
                device_key=device_key,
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
        }

    def _complete_software_token_mfa(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            responses, {"SECRET_HASH", "SOFTWARE_TOKEN_MFA_CODE", "USERNAME"}
        )
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        session = _consume_auth_session(self.get_store(context), "mfa_sessions", raw_session)
        if (
            session is None
            or session.kind != "SOFTWARE_TOKEN_MFA"
            or session.expires_at <= _now()
            or session.pool_id != pool.pool_id
            or session.client_id != client.client_id
            or not hmac.compare_digest(session.username.encode(), username.encode())
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        user = _resolve_pool_user(pool, username)
        if (
            user is None
            or not user.enabled
            or pool.mfa_configuration == "OFF"
            or not pool.software_token_mfa_enabled
            or not user.software_token_mfa_enabled
            or user.software_token_mfa_secret is None
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        secret = _decrypt_totp_secret(pool, user.software_token_mfa_secret)
        matched_step = _verify_totp_code(
            secret, responses.get("SOFTWARE_TOKEN_MFA_CODE"), time.time()
        )
        if matched_step is None or (
            user.software_token_mfa_last_step is not None
            and matched_step <= user.software_token_mfa_last_step
        ):
            _error("CodeMismatchException", "Invalid software token code")
        user.software_token_mfa_last_step = matched_step
        user.updated_at = _now()
        return {
            "AuthenticationResult": self._authentication_result(
                context,
                pool,
                client,
                user,
                include_refresh=True,
                device_key=session.device_key,
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
        }

    def _complete_mfa_setup(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(responses, {"SECRET_HASH", "USERNAME"})
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        session = _consume_auth_session(self.get_store(context), "mfa_sessions", raw_session)
        if (
            session is None
            or session.kind != "MFA_SETUP_COMPLETE"
            or session.expires_at <= _now()
            or session.pool_id != pool.pool_id
            or session.client_id != client.client_id
            or not hmac.compare_digest(session.username.encode(), username.encode())
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        user = _resolve_pool_user(pool, username)
        if user is None or not user.enabled or not user.software_token_mfa_enabled:
            _error("NotAuthorizedException", "Invalid authentication session")
        return {
            "AuthenticationResult": self._authentication_result(
                context,
                pool,
                client,
                user,
                include_refresh=True,
                device_key=session.device_key,
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
        }

    def _access_token_user(
        self, context: RequestContext, token: Any
    ) -> tuple[UserPool, CognitoUser]:
        if not isinstance(token, str) or not 1 <= len(token) <= 16 * 1024:
            _error("NotAuthorizedException", "Invalid access token")
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            _error("NotAuthorizedException", "Invalid access token")
        try:
            header = decode_jwt_segment(parts[0])
            claims = decode_jwt_segment(parts[1])
            signature = base64.b64decode(
                parts[2] + "=" * (-len(parts[2]) % 4), altchars=b"-_", validate=True
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            _error("NotAuthorizedException", "Invalid access token")
        issuer = claims.get("iss")
        pool_id = issuer.rsplit("/", 1)[-1] if isinstance(issuer, str) and "/" in issuer else None
        with cognito_idp_stores.lock:
            pool = self.get_store(context).user_pools.get(pool_id)
        if (
            pool is None
            or header != {"alg": "RS256", "kid": pool.access_signing_key_id, "typ": "JWT"}
            or issuer
            != f"https://cognito-idp.{context.region}.{_partition_dns_suffix(context.partition)}/{pool.pool_id}"
            or claims.get("token_use") != "access"
            or not isinstance(claims.get("scope"), str)
            or "aws.cognito.signin.user.admin" not in claims["scope"].split()
            or not isinstance(claims.get("iat"), int)
            or isinstance(claims.get("iat"), bool)
            or not isinstance(claims.get("exp"), int)
            or isinstance(claims.get("exp"), bool)
            or claims["exp"] <= int(time.time())
            or not isinstance(claims.get("client_id"), str)
            or claims["client_id"] not in pool.clients
            or not isinstance(claims.get("username"), str)
            or not isinstance(claims.get("sub"), str)
        ):
            _error("NotAuthorizedException", "Invalid access token")
        try:
            public_key_from_jwk(pool.access_signing_jwk).verify(
                signature,
                f"{parts[0]}.{parts[1]}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError, TypeError):
            _error("NotAuthorizedException", "Invalid access token")
        user = pool.users.get(claims["username"])
        if (
            user is None
            or not user.enabled
            or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
            or not hmac.compare_digest(user.sub, claims["sub"])
            or claims["iat"] < user.tokens_valid_after
        ):
            _error("NotAuthorizedException", "Invalid access token")
        return pool, user

    def _start_web_authn_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        parameters: dict[str, Any],
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        username = _required_string(parameters, "USERNAME", minimum=1, maximum=128)
        self._verify_secret_hash(pool, client, username, parameters.get("SECRET_HASH"))
        configuration = _require_web_authn_configuration(pool)
        user = _resolve_pool_user(pool, username)
        active_credentials = (
            {
                credential_id: credential
                for credential_id, credential in user.web_authn_credentials.items()
                if credential.relying_party_id == configuration["RelyingPartyId"]
            }
            if user is not None
            else {}
        )
        synthetic = (
            user is None or not user.enabled or user.status != "CONFIRMED" or not active_credentials
        )
        if synthetic and client.prevent_user_existence_errors != "ENABLED":
            _error("NotAuthorizedException", "Invalid authentication request")
        challenge_bytes = secrets.token_bytes(32)
        challenge = _base64_url(challenge_bytes)
        challenge_hash = hashlib.sha256(challenge_bytes).hexdigest()
        raw_session = secrets.token_urlsafe(48)
        session_hash = _token_hash(raw_session)
        now = _now()
        credential_versions = {
            credential.credential_id: credential.version
            for credential in active_credentials.values()
        }
        store = self.get_store(context)
        with cognito_idp_stores.lock:
            if not _reserve_web_authn_challenge(store, pool.pool_id, username, now):
                _error("LimitExceededException", "WebAuthn challenge quota exceeded")
            while session_hash in store.web_authn_challenges or any(
                existing.challenge_hash == challenge_hash
                for existing in store.web_authn_challenges.values()
            ):
                challenge_bytes = secrets.token_bytes(32)
                challenge = _base64_url(challenge_bytes)
                challenge_hash = hashlib.sha256(challenge_bytes).hexdigest()
                raw_session = secrets.token_urlsafe(48)
                session_hash = _token_hash(raw_session)
            store.web_authn_challenges[session_hash] = WebAuthnChallenge(
                token_hash=session_hash,
                challenge_hash=challenge_hash,
                pool_id=pool.pool_id,
                client_id=client.client_id,
                username=username,
                kind="authentication",
                relying_party_id=configuration["RelyingPartyId"],
                credential_versions=credential_versions,
                created_at=now,
                expires_at=now + _WEB_AUTHN_CHALLENGE_TTL,
                synthetic=synthetic,
                client_metadata=dict(client_metadata or {}),
            )
        request_options = {
            # Registration requires resident keys. An empty allow-list lets the
            # authenticator select the passkey and keeps PUE-enabled responses
            # indistinguishable for missing, disabled and unregistered users.
            "allowCredentials": [],
            "challenge": challenge,
            "rpId": configuration["RelyingPartyId"],
            "timeout": 180_000,
            "userVerification": configuration["UserVerification"],
        }
        return {
            "AvailableChallenges": ["WEB_AUTHN"],
            "ChallengeName": "WEB_AUTHN",
            "ChallengeParameters": {
                "CREDENTIAL_REQUEST_OPTIONS": json.dumps(
                    request_options, separators=(",", ":"), sort_keys=True
                )
            },
            "Session": raw_session,
        }

    def _complete_web_authn_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        _reject_unsupported_fields(responses, {"CREDENTIAL", "SECRET_HASH", "USERNAME"})
        username = _required_string(responses, "USERNAME", minimum=1, maximum=128)
        if not isinstance(raw_session, str) or not 20 <= len(raw_session) <= 2048:
            _error("NotAuthorizedException", "Invalid WebAuthn authentication session")
        store = self.get_store(context)
        with cognito_idp_stores.lock:
            challenge = store.web_authn_challenges.pop(_token_hash(raw_session), None)
        now = _now()
        if (
            challenge is None
            or challenge.kind != "authentication"
            or challenge.expires_at <= now
            or challenge.pool_id != pool.pool_id
            or challenge.client_id != client.client_id
            or not hmac.compare_digest(challenge.username.encode(), username.encode())
        ):
            _error("NotAuthorizedException", "Invalid WebAuthn authentication session")
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        configuration = _require_web_authn_configuration(pool)
        user = _resolve_pool_user(pool, username)
        credential_input = responses.get("CREDENTIAL")
        try:
            supplied_challenge_hash = credential_challenge_hash(credential_input, string_input=True)
        except WebAuthnError:
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        if (
            user is None
            or not user.enabled
            or user.status != "CONFIRMED"
            or challenge.synthetic
            or configuration["RelyingPartyId"] != challenge.relying_party_id
            or not hmac.compare_digest(
                supplied_challenge_hash.encode(), challenge.challenge_hash.encode()
            )
        ):
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        try:
            candidate_id = response_credential_id(credential_input, string_input=True)
        except WebAuthnError:
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        credential = user.web_authn_credentials.get(candidate_id)
        if (
            credential is None
            or challenge.credential_versions.get(candidate_id) != credential.version
            or credential.relying_party_id != challenge.relying_party_id
        ):
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        try:
            verified_id, sign_count = authentication_response(
                credential_input,
                challenge_hash=challenge.challenge_hash,
                relying_party_id=challenge.relying_party_id,
                user_verification=configuration["UserVerification"],
                public_key_pem=credential.public_key_pem,
                algorithm=credential.algorithm,
                expected_user_handle=user.sub.encode(),
            )
        except WebAuthnError:
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        if not hmac.compare_digest(verified_id.encode(), credential.credential_id.encode()):
            _error("NotAuthorizedException", "Invalid WebAuthn credential")
        if (credential.sign_count != 0 or sign_count != 0) and (
            sign_count <= credential.sign_count
        ):
            _error("NotAuthorizedException", "WebAuthn signature counter replay detected")
        credential.sign_count = sign_count
        user.updated_at = pool.updated_at = now
        if configuration["FactorConfiguration"] == "MULTI_FACTOR_WITH_USER_VERIFICATION":
            return {
                "AuthenticationResult": self._authentication_result(
                    context,
                    pool,
                    client,
                    user,
                    include_refresh=True,
                    client_metadata=(
                        challenge.client_metadata if client_metadata is None else client_metadata
                    ),
                )
            }
        return self._post_primary_auth(
            context,
            pool,
            client,
            user,
            client_metadata=(
                challenge.client_metadata if client_metadata is None else client_metadata
            ),
        )

    def _start_srp_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        parameters: dict[str, Any],
        *,
        auth_context: dict[str, str] | None = None,
        client_metadata: dict[str, str] | None = None,
        custom_auth: bool = False,
    ) -> ServiceResponse:
        username = parameters.get("USERNAME")
        if not isinstance(username, str) or not 1 <= len(username) <= 128:
            _error("InvalidParameterException", "USERNAME is required")
        self._verify_secret_hash(pool, client, username, parameters.get("SECRET_HASH"))
        device_key = _optional_auth_device_key(parameters.get("DEVICE_KEY"))
        public_a = _srp_public_value(parameters.get("SRP_A"), "SRP_A")

        user = _resolve_pool_user(pool, username)
        hidden_user = (
            user is None
            or not user.enabled
            or user.status not in {"CONFIRMED", "FORCE_CHANGE_PASSWORD"}
            or _temporary_password_expired(user, _now())
            or not user.srp_salt
            or not user.srp_verifier
        )
        if hidden_user and client.prevent_user_existence_errors != "ENABLED":
            if user is None:
                _error("UserNotFoundException", "User does not exist")
            _error("NotAuthorizedException", "Incorrect username or password")
        if hidden_user:
            salt, verifier = _synthetic_srp_credentials(pool, username)
        else:
            salt, verifier = user.srp_salt, user.srp_verifier

        verifier_value = _srp_stored_value(verifier, "SRP verifier")
        private_b = secrets.randbelow(_SRP_N - 2) + 1
        public_b = (_SRP_K * verifier_value + pow(_SRP_G, private_b, _SRP_N)) % _SRP_N
        if public_b == 0:
            _error("NotAuthorizedException", "Invalid authentication parameters")
        scrambling = int(_srp_hex_hash(f"{_srp_pad_hex(public_a)}{_srp_pad_hex(public_b)}"), 16)
        if scrambling == 0:
            _error("NotAuthorizedException", "Invalid authentication parameters")
        shared_secret = pow(
            (public_a * pow(verifier_value, scrambling, _SRP_N)) % _SRP_N,
            private_b,
            _SRP_N,
        )
        if shared_secret == 0:
            _error("NotAuthorizedException", "Invalid authentication parameters")
        shared_key = _srp_hkdf(shared_secret, scrambling)
        secret_block = secrets.token_bytes(32)
        session = secrets.token_urlsafe(48)
        now = _now()
        session_hash = _token_hash(session)
        with cognito_idp_stores.lock:
            store = self.get_store(context)
            _prune_auth_challenge_sessions(store, now)
            store.srp_sessions[session_hash] = SrpSession(
                token_hash=session_hash,
                pool_id=pool.pool_id,
                client_id=client.client_id,
                username=username,
                shared_key=base64.b64encode(shared_key).decode(),
                secret_block_hash=hashlib.sha256(secret_block).hexdigest(),
                user_not_found=hidden_user,
                created_at=now,
                expires_at=now + _AUTH_CHALLENGE_TTL,
                device_key=device_key,
                auth_context=dict(auth_context or {}),
                client_metadata=dict(client_metadata or {}),
                custom_auth=custom_auth,
            )
        return {
            "ChallengeName": "PASSWORD_VERIFIER",
            "ChallengeParameters": {
                "SALT": salt,
                "SECRET_BLOCK": base64.b64encode(secret_block).decode(),
                "SRP_B": _srp_pad_hex(public_b),
                "USER_ID_FOR_SRP": username,
                "USERNAME": username,
            },
            "Session": session,
        }

    def _complete_srp_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
        defer_custom_auth: bool = False,
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            responses,
            {
                "PASSWORD_CLAIM_SECRET_BLOCK",
                "PASSWORD_CLAIM_SIGNATURE",
                "DEVICE_KEY",
                "SECRET_HASH",
                "TIMESTAMP",
                "USERNAME",
            },
        )
        username = responses.get("USERNAME")
        if not isinstance(username, str) or not 1 <= len(username) <= 128:
            _error("InvalidParameterException", "USERNAME is required")
        session = _consume_auth_session(self.get_store(context), "srp_sessions", raw_session)
        now = _now()
        if (
            session is None
            or session.expires_at <= now
            or session.pool_id != pool.pool_id
            or session.client_id != client.client_id
            or not hmac.compare_digest(session.username.encode(), username.encode())
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        if session.custom_auth is not defer_custom_auth:
            _error("NotAuthorizedException", "Invalid authentication session")
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        response_device_key = _optional_auth_device_key(responses.get("DEVICE_KEY"))
        if (
            session.device_key is not None
            and response_device_key is not None
            and not hmac.compare_digest(session.device_key, response_device_key)
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        device_key = response_device_key or session.device_key

        risk_level, risk_decision, blocked, compromised = _evaluate_local_auth_risk(
            pool, client, None, session.auth_context.get("IpAddress")
        )
        if blocked:
            _record_auth_event(
                context,
                self.get_store(context),
                pool,
                client,
                username,
                False,
                session.auth_context,
                risk_level,
                risk_decision,
                compromised,
            )
            _error("NotAuthorizedException", "Authentication blocked by risk configuration")

        secret_block = _strict_base64(
            responses.get("PASSWORD_CLAIM_SECRET_BLOCK"), "PASSWORD_CLAIM_SECRET_BLOCK", 32
        )
        if not hmac.compare_digest(
            hashlib.sha256(secret_block).hexdigest(), session.secret_block_hash
        ):
            _error("NotAuthorizedException", "Invalid authentication response")
        timestamp = _password_claim_timestamp(responses.get("TIMESTAMP"))
        if abs(now - timestamp) > _PASSWORD_CLAIM_MAX_SKEW:
            _error("NotAuthorizedException", "Invalid authentication response")
        signature = _strict_base64(
            responses.get("PASSWORD_CLAIM_SIGNATURE"), "PASSWORD_CLAIM_SIGNATURE", 32
        )
        shared_key = base64.b64decode(session.shared_key, validate=True)
        expected = hmac.new(
            shared_key,
            _pool_short_id(pool.pool_id).encode()
            + username.encode()
            + secret_block
            + responses["TIMESTAMP"].encode(),
            hashlib.sha256,
        ).digest()
        signature_valid = hmac.compare_digest(expected, signature)
        user = _resolve_pool_user(pool, username)
        if (
            not signature_valid
            or session.user_not_found
            or user is None
            or not user.enabled
            or user.status not in {"CONFIRMED", "FORCE_CHANGE_PASSWORD"}
            or _temporary_password_expired(user, now)
        ):
            _record_auth_event(
                context,
                self.get_store(context),
                pool,
                client,
                username,
                False,
                session.auth_context,
                risk_level,
                risk_decision,
                compromised,
            )
            _error("NotAuthorizedException", "Incorrect username or password")
        if defer_custom_auth:
            if user.status != "CONFIRMED":
                _error("NotAuthorizedException", "Incorrect username or password")
            return {
                "_CustomAuthContext": dict(session.auth_context),
                "_CustomAuthUsername": user.username,
            }
        if user.status == "FORCE_CHANGE_PASSWORD":
            result = self._new_password_challenge(
                context,
                pool,
                client,
                user,
                device_key=device_key,
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
        else:
            result = self._post_primary_auth(
                context,
                pool,
                client,
                user,
                device_key=device_key,
                client_metadata=(
                    session.client_metadata if client_metadata is None else client_metadata
                ),
            )
        _record_auth_event(
            context,
            self.get_store(context),
            pool,
            client,
            username,
            True,
            session.auth_context,
            risk_level,
            risk_decision,
            compromised,
        )
        return result

    def _new_password_challenge(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        user: CognitoUser,
        *,
        device_key: str | None = None,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        raw_session = secrets.token_urlsafe(48)
        session_hash = _token_hash(raw_session)
        now = _now()
        required_attributes = sorted(_required_schema_attributes(pool) - set(user.attributes))
        with cognito_idp_stores.lock:
            store = self.get_store(context)
            _prune_auth_challenge_sessions(store, now)
            store.new_password_sessions[session_hash] = NewPasswordSession(
                token_hash=session_hash,
                pool_id=pool.pool_id,
                client_id=client.client_id,
                username=user.username,
                required_attributes=required_attributes,
                created_at=now,
                expires_at=now + _AUTH_CHALLENGE_TTL,
                device_key=device_key,
                client_metadata=dict(client_metadata or {}),
            )
        return {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ChallengeParameters": {
                "USER_ID_FOR_SRP": user.username,
                "requiredAttributes": json.dumps(required_attributes, separators=(",", ":")),
                "userAttributes": json.dumps(user.attributes, separators=(",", ":")),
            },
            "Session": raw_session,
        }

    def _complete_new_password(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        responses: dict[str, Any],
        raw_session: Any,
        *,
        client_metadata: dict[str, str] | None = None,
    ) -> ServiceResponse:
        if unsupported := sorted(
            field
            for field in responses
            if field not in {"DEVICE_KEY", "NEW_PASSWORD", "SECRET_HASH", "USERNAME"}
            and not field.startswith("userAttributes.")
        ):
            _error("InvalidParameterException", f"Unsupported request fields: {unsupported}")
        username = responses.get("USERNAME")
        if not isinstance(username, str) or not 1 <= len(username) <= 128:
            _error("InvalidParameterException", "USERNAME is required")
        session = _consume_auth_session(
            self.get_store(context), "new_password_sessions", raw_session
        )
        now = _now()
        if (
            session is None
            or session.expires_at <= now
            or session.pool_id != pool.pool_id
            or session.client_id != client.client_id
            or not hmac.compare_digest(session.username.encode(), username.encode())
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        self._verify_secret_hash(pool, client, username, responses.get("SECRET_HASH"))
        response_device_key = _optional_auth_device_key(responses.get("DEVICE_KEY"))
        if (
            session.device_key is not None
            and response_device_key is not None
            and not hmac.compare_digest(session.device_key, response_device_key)
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        user = _resolve_pool_user(pool, username)
        if user is None or not user.enabled or user.status != "FORCE_CHANGE_PASSWORD":
            _error("NotAuthorizedException", "Invalid authentication session")
        password = _required_string(responses, "NEW_PASSWORD", minimum=6, maximum=256)
        _validate_password(pool, password)
        supplied_attributes = [
            {"Name": field.removeprefix("userAttributes."), "Value": value}
            for field, value in responses.items()
            if field.startswith("userAttributes.")
        ]
        attributes = _attributes(supplied_attributes)
        if missing := set(session.required_attributes) - set(attributes) - set(user.attributes):
            _error("InvalidParameterException", f"Missing required attributes: {sorted(missing)}")
        _validate_schema_mutation(pool, user, set(attributes), attribute_values=attributes)
        _set_user_password_credentials(pool, user, password)
        user.attributes.update(attributes)
        user.status = "CONFIRMED"
        user.temporary_password_expires_at = None
        user.updated_at = pool.updated_at = now
        return self._post_primary_auth(
            context,
            pool,
            client,
            user,
            device_key=response_device_key or session.device_key,
            client_metadata=(
                session.client_metadata if client_metadata is None else client_metadata
            ),
        )

    def _refresh_auth(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        if client.refresh_token_rotation_enabled:
            _error(
                "InvalidParameterException",
                "REFRESH_TOKEN_AUTH is unavailable when refresh token rotation is enabled",
            )
        token = parameters.get("REFRESH_TOKEN")
        if not isinstance(token, str) or not 1 <= len(token) <= 4096:
            _error("InvalidParameterException", "REFRESH_TOKEN is required")
        with cognito_idp_stores.lock:
            session = self.get_store(context).refresh_sessions.get(_token_hash(token))
        if (
            session is None
            or session.revoked
            or session.pool_id != pool.pool_id
            or session.client_id != client.client_id
            or session.expires_at <= _now()
        ):
            _error("NotAuthorizedException", "Invalid refresh token")
        user = pool.users.get(session.username)
        if (
            user is None
            or not user.enabled
            or user.status not in {"CONFIRMED", "EXTERNAL_PROVIDER"}
        ):
            _error("NotAuthorizedException", "Invalid refresh token")
        _validate_refresh_device(pool, user, session, parameters.get("DEVICE_KEY"))
        self._verify_secret_hash(pool, client, user.username, parameters.get("SECRET_HASH"))
        return self._authentication_result(
            context,
            pool,
            client,
            user,
            include_refresh=False,
            auth_time=session.auth_time,
            origin_jti=session.origin_jti,
            scopes=session.scopes,
        )

    def _authentication_result(
        self,
        context: RequestContext,
        pool: UserPool,
        client: UserPoolClient,
        user: CognitoUser,
        *,
        include_refresh: bool,
        auth_time: int | None = None,
        origin_jti: str | None = None,
        scopes: list[str] | None = None,
        nonce: str | None = None,
        filter_oauth_attributes: bool = False,
        device_key: str | None = None,
        client_metadata: dict[str, str] | None = None,
        token_trigger_source: str = "TokenGeneration_Authentication",
    ) -> dict[str, Any]:
        issued_at = max(int(time.time()), user.tokens_valid_after)
        auth_time = issued_at if auth_time is None else auth_time
        origin_jti = str(uuid.uuid4()) if origin_jti is None else origin_jti
        scopes = ["aws.cognito.signin.user.admin"] if scopes is None else list(scopes)
        active_scopes = _active_oauth_scopes(pool)
        scopes = [scope for scope in scopes if scope in active_scopes]
        issuer = (
            f"https://cognito-idp.{context.region}.{_partition_dns_suffix(context.partition)}"
            f"/{pool.pool_id}"
        )
        id_ttl = _validity_seconds(client.id_token_validity, client.id_token_validity_unit)
        access_ttl = _validity_seconds(
            client.access_token_validity, client.access_token_validity_unit
        )
        readable_attributes = _readable_user_attributes(client, user)
        token_attributes = (
            _oauth_user_attributes(readable_attributes, scopes)
            if filter_oauth_attributes
            else readable_attributes
        )
        group_claims = _group_token_claims(pool, user)
        token_attributes, group_claims = _pre_token_generation_overrides(
            context,
            pool,
            client,
            user,
            token_attributes,
            group_claims,
            client_metadata=client_metadata,
            trigger_source=token_trigger_source,
        )
        common = {
            "auth_time": auth_time,
            "iss": issuer,
            "origin_jti": origin_jti,
            "sub": user.sub,
            **group_claims,
        }
        id_claims = {
            **token_attributes,
            **common,
            "aud": client.client_id,
            "cognito:username": user.username,
            "event_id": str(uuid.uuid4()),
            "exp": issued_at + id_ttl,
            "jti": str(uuid.uuid4()),
            "token_use": "id",
        }
        if identities := _federated_identity_claims(pool, user):
            id_claims["identities"] = identities
        if nonce is not None:
            id_claims["nonce"] = nonce
        result = {
            "AccessToken": sign_jwt(
                pool.access_signing_private_key_pem,
                pool.access_signing_key_id,
                {
                    **common,
                    "client_id": client.client_id,
                    "event_id": str(uuid.uuid4()),
                    "exp": issued_at + access_ttl,
                    "jti": str(uuid.uuid4()),
                    "scope": " ".join(scopes),
                    "token_use": "access",
                    "username": user.username,
                },
                now=issued_at,
            ),
            "ExpiresIn": access_ttl,
            "IdToken": sign_jwt(
                pool.id_signing_private_key_pem,
                pool.id_signing_key_id,
                id_claims,
                now=issued_at,
            ),
            "TokenType": "Bearer",
        }
        new_device_metadata = None
        refresh_device_key = None
        if include_refresh and pool.device_tracking_enabled:
            if device_key is not None and device_key in user.devices:
                refresh_device_key = device_key
            else:
                new_device_metadata = _new_device_metadata(
                    self.get_store(context), pool, client, user
                )
                refresh_device_key = new_device_metadata["DeviceKey"]
        if include_refresh:
            refresh_token = secrets.token_urlsafe(48)
            refresh_hash = _token_hash(refresh_token)
            with cognito_idp_stores.lock:
                store = self.get_store(context)
                if not _prune_refresh_sessions(
                    store,
                    pool.pool_id,
                    client.client_id,
                    user.username,
                    _now(),
                ):
                    _error("LimitExceededException", "Refresh-session limit exceeded")
                store.refresh_sessions[refresh_hash] = RefreshSession(
                    token_hash=refresh_hash,
                    pool_id=pool.pool_id,
                    client_id=client.client_id,
                    username=user.username,
                    auth_time=auth_time,
                    origin_jti=origin_jti,
                    expires_at=_now()
                    + timedelta(
                        seconds=_validity_seconds(
                            client.refresh_token_validity,
                            client.refresh_token_validity_unit,
                        )
                    ),
                    device_key=refresh_device_key,
                    scopes=list(scopes),
                )
            result["RefreshToken"] = refresh_token
            if new_device_metadata is not None:
                result["NewDeviceMetadata"] = new_device_metadata
        return result

    def _verify_secret_hash(
        self,
        pool: UserPool,
        client: UserPoolClient,
        username: str,
        supplied: Any,
    ) -> None:
        values = _client_secret_values(pool, client)
        if not values:
            return
        if not isinstance(supplied, str) or not any(
            hmac.compare_digest(
                base64.b64encode(
                    hmac.new(
                        value.encode(),
                        f"{username}{client.client_id}".encode(),
                        hashlib.sha256,
                    ).digest()
                ).decode(),
                supplied,
            )
            for value in values
        ):
            _error("NotAuthorizedException", "Unable to verify secret hash for client")

    def _pool(self, context: RequestContext, pool_id: Any) -> UserPool:
        if not isinstance(pool_id, str) or not pool_id:
            _error("InvalidParameterException", "UserPoolId is required")
        pool = self.get_store(context).user_pools.get(pool_id)
        if pool is None:
            _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
        return pool

    def _pool_for_resource_arn(self, context: RequestContext, value: Any) -> UserPool:
        if not isinstance(value, str) or not 20 <= len(value) <= 2048:
            _error("InvalidParameterException", "Invalid ResourceArn")
        with cognito_idp_stores.lock:
            for pool in self.get_store(context).user_pools.values():
                if hmac.compare_digest(pool.arn, value):
                    return pool
        _error("ResourceNotFoundException", "User pool resource does not exist")

    def _domain(self, context: RequestContext, domain_name: str) -> UserPoolDomain:
        local_hostname = _local_domain_hostname(domain_name)
        location = self.get_store(context).DOMAIN_LOCATIONS.get(local_hostname)
        if location != (context.account_id, context.region):
            _error("ResourceNotFoundException", f"Domain {domain_name} does not exist")
        domain = self.get_store(context).user_pool_domains.get(domain_name)
        if domain is None:
            _error("ResourceNotFoundException", f"Domain {domain_name} does not exist")
        return domain

    @staticmethod
    def _client(pool: UserPool, client_id: Any) -> UserPoolClient:
        if not isinstance(client_id, str) or not client_id:
            _error("InvalidParameterException", "ClientId is required")
        client = pool.clients.get(client_id)
        if client is None:
            _error("ResourceNotFoundException", f"User pool client {client_id} does not exist")
        return client

    @staticmethod
    def _user(pool: UserPool, username: Any) -> CognitoUser:
        if not isinstance(username, str) or not username:
            _error("InvalidParameterException", "Username is required")
        user = _resolve_pool_user(pool, username)
        if user is None:
            _error("UserNotFoundException", "User does not exist")
        return user

    def _find_client(
        self, context: RequestContext, client_id: Any
    ) -> tuple[UserPoolClient, UserPool]:
        if not isinstance(client_id, str) or not client_id:
            _error("InvalidParameterException", "ClientId is required")
        for pool in self.get_store(context).user_pools.values():
            if client := pool.clients.get(client_id):
                return client, pool
        _error("ResourceNotFoundException", f"User pool client {client_id} does not exist")


def _now() -> datetime:
    return datetime.now(UTC)


_REPLICA_AUTH_OPERATIONS = {
    "AdminInitiateAuth",
    "AdminRespondToAuthChallenge",
    "InitiateAuth",
    "RespondToAuthChallenge",
}
_REPLICA_TOKEN_OPERATIONS = {
    "GetTokensFromRefreshToken",
    "RevokeToken",
}
_REPLICA_READ_PREFIXES = ("Describe", "Get", "List")
_REPLICA_MUTATING_GET_OPERATIONS = {"GetUserAttributeVerificationCode"}
_REGIONAL_CONFIGURATION_FIELDS = {
    "EmailConfiguration",
    "LambdaConfig",
    "SmsConfiguration",
    "UserPoolId",
}


def _replica_operation_class(operation: str, request: ServiceRequest | None = None) -> str:
    if operation in _REPLICA_AUTH_OPERATIONS:
        return "AUTHENTICATE"
    if operation in _REPLICA_TOKEN_OPERATIONS:
        return "TOKEN"
    if operation == "UpdateUserPool" and request is not None:
        supplied = set(request)
        if "UserPoolId" in supplied and supplied <= _REGIONAL_CONFIGURATION_FIELDS:
            return "CONFIG_WRITE"
    if operation in _REPLICA_MUTATING_GET_OPERATIONS:
        return "USER_WRITE"
    if operation.startswith(_REPLICA_READ_PREFIXES):
        return "READ"
    return "USER_WRITE"


def _casefold_identity(pool: UserPool, value: str) -> str:
    return value if getattr(pool, "username_case_sensitive", True) else value.casefold()


def _normalize_user_attributes(pool: UserPool, attributes: dict[str, str]) -> None:
    if getattr(pool, "username_case_sensitive", True):
        return
    for name in ("email", "preferred_username"):
        if name in attributes:
            attributes[name] = attributes[name].casefold()


def _active_user_aliases(pool: UserPool, user: CognitoUser) -> dict[str, str]:
    return _active_alias_values(pool, user.attributes, user.status)


def _active_alias_values(pool: UserPool, attributes: dict[str, str], status: str) -> dict[str, str]:
    result: dict[str, str] = {}
    configured = set(getattr(pool, "alias_attributes", None) or [])
    for name in configured & {"email", "phone_number"}:
        value = attributes.get(name)
        if value and attributes.get(f"{name}_verified") == "true":
            result[name] = value
    preferred = attributes.get("preferred_username")
    if "preferred_username" in configured and preferred and status != "UNCONFIRMED":
        result["preferred_username"] = preferred
    return result


def _alias_index_key(pool: UserPool, value: str) -> str:
    return _casefold_identity(pool, value)


def _ensure_identity_indexes(pool: UserPool) -> None:
    if getattr(pool, "identity_indexes_initialized", False) and len(
        getattr(pool, "username_index", {})
    ) == len(pool.users):
        return
    username_index: dict[str, str] = {}
    alias_index: dict[str, str] = {}
    for user in pool.users.values():
        username_key = _casefold_identity(pool, user.username)
        if username_key in username_index or username_key in alias_index:
            _error("InvalidParameterException", "User pool contains ambiguous identities")
        username_index[username_key] = user.username
        for alias in _active_user_aliases(pool, user).values():
            key = _alias_index_key(pool, alias)
            if key in username_index or key in alias_index:
                _error("InvalidParameterException", "User pool contains ambiguous aliases")
            alias_index[key] = user.username
    pool.username_index = username_index
    pool.alias_index = alias_index
    pool.identity_indexes_initialized = True


def _identity_conflict(
    pool: UserPool, value: str, user: CognitoUser | None = None
) -> CognitoUser | None:
    _ensure_identity_indexes(pool)
    key = _casefold_identity(pool, value)
    owner_name = pool.username_index.get(key) or pool.alias_index.get(key)
    if owner_name is None or (user is not None and owner_name == user.username):
        return None
    return pool.users.get(owner_name)


def _assert_identity_available(
    pool: UserPool,
    username: str,
    attributes: dict[str, str],
    *,
    user: CognitoUser | None = None,
) -> None:
    if conflict := _identity_conflict(pool, username, user):
        del conflict
        _error("UsernameExistsException", "User account already exists")
    status = user.status if user else "CONFIRMED"
    for value in _active_alias_values(pool, attributes, status).values():
        if _identity_conflict(pool, value, user) is not None:
            _error("AliasExistsException", "Alias already exists")


def _remove_user_identity_indexes(pool: UserPool, user: CognitoUser) -> None:
    _ensure_identity_indexes(pool)
    username_key = _casefold_identity(pool, user.username)
    if pool.username_index.get(username_key) == user.username:
        pool.username_index.pop(username_key, None)
    for alias in _active_user_aliases(pool, user).values():
        key = _alias_index_key(pool, alias)
        if pool.alias_index.get(key) == user.username:
            pool.alias_index.pop(key, None)


def _add_user_identity_indexes(pool: UserPool, user: CognitoUser) -> None:
    _ensure_identity_indexes(pool)
    pool.username_index[_casefold_identity(pool, user.username)] = user.username
    for alias in _active_user_aliases(pool, user).values():
        pool.alias_index[_alias_index_key(pool, alias)] = user.username


def _resolve_pool_user(pool: UserPool, username: str) -> CognitoUser | None:
    _ensure_identity_indexes(pool)
    key = _casefold_identity(pool, username)
    canonical = pool.username_index.get(key) or pool.alias_index.get(key)
    return pool.users.get(canonical) if canonical is not None else None


def _alias_transfer_owners(
    pool: UserPool,
    user: CognitoUser,
    attributes: dict[str, str],
    *,
    force: bool,
) -> list[tuple[CognitoUser, str, str]]:
    _ensure_identity_indexes(pool)
    transfers: list[tuple[CognitoUser, str, str]] = []
    for name, value in _active_alias_values(pool, attributes, "CONFIRMED").items():
        key = _alias_index_key(pool, value)
        username_owner = pool.username_index.get(key)
        if username_owner is not None and username_owner != user.username:
            _error("AliasExistsException", "Alias conflicts with an existing username")
        owner_name = pool.alias_index.get(key)
        if owner_name is None or owner_name == user.username:
            continue
        owner = pool.users.get(owner_name)
        if owner is None:
            _error("InvalidParameterException", "Alias index is inconsistent")
        if not force:
            _error("AliasExistsException", "Alias already exists")
        transfers.append((owner, name, value))
    return transfers


def _apply_confirmed_aliases(
    pool: UserPool,
    user: CognitoUser,
    attributes: dict[str, str],
    transfers: list[tuple[CognitoUser, str, str]],
) -> None:
    affected = {owner.username: owner for owner, _, _ in transfers}
    _remove_user_identity_indexes(pool, user)
    for owner in affected.values():
        _remove_user_identity_indexes(pool, owner)
    for owner, name, value in transfers:
        if owner.attributes.get(name) == value:
            owner.attributes[f"{name}_verified"] = "false"
            owner.updated_at = _now()
    user.attributes = attributes
    user.status = "CONFIRMED"
    for owner in affected.values():
        _add_user_identity_indexes(pool, owner)
    _add_user_identity_indexes(pool, user)


def _replace_user_attributes(pool: UserPool, user: CognitoUser, attributes: dict[str, str]) -> None:
    _normalize_user_attributes(pool, attributes)
    _alias_transfer_owners(pool, user, attributes, force=False)
    _remove_user_identity_indexes(pool, user)
    user.attributes = attributes
    _add_user_identity_indexes(pool, user)


def _error(code: str, message: str):
    raise CommonServiceException(code, message, status_code=400, sender_fault=True)


def _reject_unsupported_fields(request: ServiceRequest, allowed: set[str]) -> None:
    if unsupported := sorted(set(request) - allowed):
        _error("InvalidParameterException", f"Unsupported request fields: {unsupported}")


def _required_string(request: ServiceRequest, key: str, *, minimum: int, maximum: int) -> str:
    value = request.get(key)
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _error(
            "InvalidParameterException",
            f"{key} length must be between {minimum} and {maximum}",
        )
    return value


def _client_secret_value(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 24 <= len(value) <= 64
        or re.fullmatch(r"[\w+]+", value) is None
    ):
        _error("InvalidParameterException", "Invalid ClientSecret")
    return value


def _generate_client_secret() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    return "".join(secrets.choice(alphabet) for _ in range(40))


def _refresh_token_rotation(value: Any) -> tuple[bool, int]:
    if value is None:
        return False, 0
    if not isinstance(value, dict) or set(value) - {"Feature", "RetryGracePeriodSeconds"}:
        _error("InvalidParameterException", "Invalid RefreshTokenRotation")
    feature = value.get("Feature")
    if feature not in {"ENABLED", "DISABLED"}:
        _error("InvalidParameterException", "Invalid refresh token rotation feature")
    grace = value.get("RetryGracePeriodSeconds", 0)
    if not isinstance(grace, int) or isinstance(grace, bool) or not 0 <= grace <= 60:
        _error("InvalidParameterException", "RetryGracePeriodSeconds must be between 0 and 60")
    return feature == "ENABLED", grace


@functools.cache
def _partition_dns_suffix(partition: str) -> str:
    endpoint_data = botocore.loaders.create_loader().load_data("endpoints")
    for partition_data in endpoint_data["partitions"]:
        if partition_data.get("partition") != partition:
            continue
        suffix = partition_data.get("dnsSuffix")
        if isinstance(suffix, str) and suffix:
            return suffix
        break
    _error("InvalidParameterException", f"Unknown AWS partition: {partition}")


def _oauth_client_configuration(
    request: ServiceRequest,
    *,
    pool: UserPool,
    existing: UserPoolClient | None = None,
) -> dict[str, Any]:
    enabled = _boolean_field(
        request,
        "AllowedOAuthFlowsUserPoolClient",
        existing.allowed_oauth_flows_user_pool_client if existing else False,
    )
    flows = _oauth_flows(
        request.get("AllowedOAuthFlows", list(existing.allowed_oauth_flows) if existing else [])
    )
    scopes = _oauth_scopes(
        request.get("AllowedOAuthScopes", list(existing.allowed_oauth_scopes) if existing else []),
        pool,
    )
    callback_urls = _oauth_urls(
        request.get("CallbackURLs", list(existing.callback_urls) if existing else []),
        "CallbackURLs",
    )
    logout_urls = _oauth_urls(
        request.get("LogoutURLs", list(existing.logout_urls) if existing else []),
        "LogoutURLs",
    )
    default_redirect_uri = request.get(
        "DefaultRedirectURI", existing.default_redirect_uri if existing else None
    )
    if default_redirect_uri is not None:
        if not isinstance(default_redirect_uri, str):
            _error("InvalidParameterException", "DefaultRedirectURI must be a string")
        _validate_oauth_url(default_redirect_uri, "DefaultRedirectURI")
        if default_redirect_uri not in callback_urls:
            _error("InvalidParameterException", "DefaultRedirectURI must be a CallbackURL")

    supported_identity_providers = _supported_identity_providers(
        request.get(
            "SupportedIdentityProviders",
            list(existing.supported_identity_providers) if existing else ["COGNITO"],
        ),
        pool,
    )
    enable_token_revocation = _boolean_field(
        request,
        "EnableTokenRevocation",
        existing.enable_token_revocation if existing else True,
    )
    read_attributes = _read_attributes(
        request.get(
            "ReadAttributes",
            None if existing is None else existing.read_attributes,
        )
    )
    write_attributes = _client_attributes(
        request.get(
            "WriteAttributes",
            None if existing is None else existing.write_attributes,
        ),
        "WriteAttributes",
    )

    if enabled:
        if not flows:
            _error("InvalidParameterException", "AllowedOAuthFlows is required")
        if not callback_urls:
            _error("InvalidParameterException", "CallbackURLs are required for the code flow")
    elif flows or scopes or callback_urls or logout_urls or default_redirect_uri is not None:
        _error(
            "InvalidParameterException",
            "OAuth configuration requires AllowedOAuthFlowsUserPoolClient=true",
        )

    return {
        "allowed_oauth_flows_user_pool_client": enabled,
        "allowed_oauth_flows": flows,
        "allowed_oauth_scopes": scopes,
        "callback_urls": callback_urls,
        "logout_urls": logout_urls,
        "default_redirect_uri": default_redirect_uri,
        "supported_identity_providers": supported_identity_providers,
        "enable_token_revocation": enable_token_revocation,
        "read_attributes": read_attributes,
        "write_attributes": write_attributes,
    }


_OIDC_PROFILE_ATTRIBUTES = {
    "address",
    "birthdate",
    "family_name",
    "gender",
    "given_name",
    "locale",
    "middle_name",
    "name",
    "nickname",
    "picture",
    "preferred_username",
    "profile",
    "updated_at",
    "website",
    "zoneinfo",
}
_STANDARD_CLIENT_ATTRIBUTES = _OIDC_PROFILE_ATTRIBUTES | {
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
}
_STANDARD_SCHEMA_ATTRIBUTES = _OIDC_PROFILE_ATTRIBUTES | {"email", "phone_number", "sub"}


def _read_attributes(value: Any) -> list[str] | None:
    return _client_attributes(value, "ReadAttributes")


def _client_attributes(value: Any, field: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not 1 <= len(value) <= 50:
        _error("InvalidParameterException", f"{field} must contain 1 to 50 attributes")
    result = []
    for attribute in value:
        if (
            not isinstance(attribute, str)
            or not 1 <= len(attribute) <= 64
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in attribute)
            or len(attribute.encode("utf-8")) > 128
            or attribute in result
        ):
            _error("InvalidParameterException", f"Invalid {field}")
        result.append(attribute)
    return result


def _readable_user_attributes(client: UserPoolClient, user: CognitoUser) -> dict[str, str]:
    allowed = (
        set(_STANDARD_CLIENT_ATTRIBUTES)
        if client.read_attributes is None
        else set(client.read_attributes)
    )
    if "oidc:profile" in allowed:
        allowed.update(_OIDC_PROFILE_ATTRIBUTES)
    return {name: value for name, value in user.attributes.items() if name in allowed}


def _authorize_client_attribute_writes(client: UserPoolClient, attribute_names: set[str]) -> None:
    writable = (
        set(_STANDARD_CLIENT_ATTRIBUTES)
        if client.write_attributes is None
        else set(client.write_attributes)
    )
    if "oidc:profile" in writable:
        writable.update(_OIDC_PROFILE_ATTRIBUTES)
    if denied := sorted(attribute_names - writable):
        _error(
            "NotAuthorizedException",
            f"Client is not authorized to write attributes: {denied}",
        )


def _oauth_user_attributes(attributes: dict[str, str], scopes: list[str]) -> dict[str, str]:
    oidc_scopes = set(scopes) & {"email", "phone", "profile"}
    if not oidc_scopes:
        return dict(attributes)
    allowed = set()
    if "profile" in oidc_scopes:
        allowed.update(_OIDC_PROFILE_ATTRIBUTES)
        allowed.update(name for name in attributes if name.startswith("custom:"))
    if "email" in oidc_scopes:
        allowed.update({"email", "email_verified"})
    if "phone" in oidc_scopes:
        allowed.update({"phone_number", "phone_number_verified"})
    return {name: value for name, value in attributes.items() if name in allowed}


def _boolean_field(request: ServiceRequest, key: str, default: bool) -> bool:
    value = request.get(key, default)
    if not isinstance(value, bool):
        _error("InvalidParameterException", f"{key} must be a boolean")
    return value


def _oauth_flows(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        _error("InvalidParameterException", "AllowedOAuthFlows must be a list of strings")
    if len(value) > 3 or len(set(value)) != len(value):
        _error("InvalidParameterException", "Invalid AllowedOAuthFlows")
    if unknown := set(value) - {"code", "implicit"}:
        _error("InvalidParameterException", f"OAuth flows not implemented: {sorted(unknown)}")
    return list(value)


def _oauth_scopes(value: Any, pool: UserPool) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 50
        or not all(isinstance(item, str) and 1 <= len(item) <= 256 for item in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", "Invalid AllowedOAuthScopes")
    allowed = _active_oauth_scopes(pool)
    if unknown := set(value) - allowed:
        _error("InvalidParameterException", f"Unknown OAuth scopes: {sorted(unknown)}")
    if set(value) & {"email", "phone", "profile"} and "openid" not in value:
        _error("InvalidParameterException", "email, phone, and profile require openid")
    return list(value)


def _active_oauth_scopes(pool: UserPool) -> set[str]:
    allowed = {"aws.cognito.signin.user.admin", "email", "openid", "phone", "profile"}
    allowed.update(
        f"{server.identifier}/{scope_name}"
        for server in pool.resource_servers.values()
        for scope_name in server.scopes
    )
    return allowed


def _oauth_urls(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or not all(isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", f"Invalid {field}")
    for url in value:
        _validate_oauth_url(url, field)
    return list(value)


def _validate_oauth_url(value: str, field: str) -> None:
    if (
        not 1 <= len(value) <= 1024
        or "\\" in value
        or "%0a" in value.lower()
        or "%0d" in value.lower()
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        _error("InvalidParameterException", f"Invalid {field} URL")
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
    except ValueError:
        _error("InvalidParameterException", f"Invalid {field} URL")
    del parsed_port
    if (
        not parsed.scheme
        or not _URL_SCHEME_PATTERN.fullmatch(parsed.scheme)
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        _error("InvalidParameterException", f"Invalid {field} URL")
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    if scheme not in {"http", "https"}:
        return
    _error("InvalidParameterException", f"Invalid {field} URL")


def _supported_identity_providers(value: Any, pool: UserPool) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
        or len(set(value)) != len(value)
        or not all(isinstance(item, str) and 1 <= len(item) <= 32 for item in value)
    ):
        _error("InvalidParameterException", "Invalid SupportedIdentityProviders")
    available = {"COGNITO", *pool.identity_providers}
    if unknown := sorted(set(value) - available):
        _error("InvalidParameterException", f"Unknown identity providers: {unknown}")
    return list(value)


def _identity_provider_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 32
        or value.strip() != value
        or value.startswith("_")
        or value.endswith("_")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or value in {"COGNITO", "Cognito"}
    ):
        _error("InvalidParameterException", "Invalid identity provider name")
    return value


def _identity_provider(pool: UserPool, value: Any) -> CognitoIdentityProvider:
    name = _identity_provider_name(value)
    provider = pool.identity_providers.get(name)
    if provider is None:
        _error("ResourceNotFoundException", f"Identity provider {name} does not exist")
    return provider


def _identity_provider_endpoint_url(value: Any, field: str, *, issuer: bool = False) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        _error("InvalidParameterException", f"Invalid OIDC {field}")
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
    except ValueError:
        _error("InvalidParameterException", f"Invalid OIDC {field}")
    del parsed_port
    if (
        parsed.scheme not in {"https", "http"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (
            issuer
            and (parsed.query or (parsed.path not in {"", "/"} and parsed.path.endswith("/")))
        )
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        _error("InvalidParameterException", f"Invalid OIDC {field}")
    return value.rstrip("/") if issuer else value


def _oidc_provider_details(value: Any) -> tuple[dict[str, str], str]:
    allowed = {
        "attributes_request_method",
        "attributes_url",
        "attributes_url_add_attributes",
        "authorize_scopes",
        "authorize_url",
        "client_id",
        "client_secret",
        "jwks_uri",
        "oidc_issuer",
        "token_url",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        _error("InvalidParameterException", "Invalid OIDC ProviderDetails")
    client_id = value.get("client_id")
    client_secret = value.get("client_secret")
    scopes = value.get("authorize_scopes")
    issuer = value.get("oidc_issuer")
    if (
        not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 128
        or not isinstance(client_secret, str)
        or not 1 <= len(client_secret) <= 2048
        or not isinstance(scopes, str)
        or not 1 <= len(scopes) <= 1024
        or not isinstance(issuer, str)
    ):
        _error("InvalidParameterException", "OIDC client, secret, scopes, and issuer are required")
    scope_values = scopes.split()
    if (
        "openid" not in scope_values
        or len(scope_values) > 50
        or len(scope_values) != len(set(scope_values))
        or any(len(scope) > 128 or not _safe_oidc_token(scope) for scope in scope_values)
    ):
        _error("InvalidParameterException", "Invalid OIDC authorize_scopes")
    method = value.get("attributes_request_method", "GET")
    if method != "GET":
        _error("InvalidParameterException", "Only OIDC userInfo GET is implemented")
    add_attributes = value.get("attributes_url_add_attributes", "false")
    if add_attributes != "false":
        _error("InvalidParameterException", "OIDC attributes_url_add_attributes is unsupported")
    result = {
        "attributes_request_method": "GET",
        "attributes_url_add_attributes": "false",
        "authorize_scopes": " ".join(scope_values),
        "client_id": client_id,
        "oidc_issuer": _identity_provider_endpoint_url(issuer, "oidc_issuer", issuer=True),
    }
    endpoint_fields = ("attributes_url", "authorize_url", "jwks_uri", "token_url")
    supplied_endpoints = [field for field in endpoint_fields if field in value]
    if supplied_endpoints and len(supplied_endpoints) != len(endpoint_fields):
        _error("InvalidParameterException", "All explicit OIDC endpoints must be supplied together")
    for field in endpoint_fields:
        if field in value:
            result[field] = _identity_provider_endpoint_url(value[field], field)
    return result, client_secret


_SOCIAL_PROVIDER_ENDPOINTS = {
    "Google": {
        "attributes_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "attributes_url_add_attributes": "false",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "oidc_issuer": "https://accounts.google.com",
        "token_request_method": "POST",
        "token_url": "https://oauth2.googleapis.com/token",
    },
    "Facebook": {
        "attributes_url_add_attributes": "true",
        "token_request_method": "GET",
    },
    "LoginWithAmazon": {
        "attributes_url": "https://api.amazon.com/user/profile",
        "attributes_url_add_attributes": "false",
        "authorize_url": "https://www.amazon.com/ap/oa",
        "token_request_method": "POST",
        "token_url": "https://api.amazon.com/auth/o2/token",
    },
    "SignInWithApple": {
        "attributes_url_add_attributes": "false",
        "authorize_url": "https://appleid.apple.com/auth/authorize",
        "jwks_uri": "https://appleid.apple.com/auth/keys",
        "oidc_issuer": "https://appleid.apple.com",
        "token_request_method": "POST",
        "token_url": "https://appleid.apple.com/auth/token",
    },
}


def _identity_provider_details(provider_type: str, value: Any) -> tuple[dict[str, str], str]:
    if provider_type == "OIDC":
        return _oidc_provider_details(value)
    if provider_type == "SAML":
        return _saml_provider_details(value), ""
    return _social_provider_details(provider_type, value)


def _saml_provider_details(value: Any) -> dict[str, str]:
    allowed = {
        "EncryptedResponses",
        "IDPInit",
        "IDPSignout",
        "MetadataFile",
        "MetadataURL",
        "RequestSigningAlgorithm",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        _error("InvalidParameterException", "Invalid SAML ProviderDetails")
    metadata_file = value.get("MetadataFile")
    metadata_url = value.get("MetadataURL")
    if (metadata_file is None) == (metadata_url is None):
        _error(
            "InvalidParameterException",
            "Exactly one of MetadataFile or MetadataURL is required",
        )
    if metadata_file is not None and (
        not isinstance(metadata_file, str) or not 1 <= len(metadata_file) <= 256 * 1024
    ):
        _error("InvalidParameterException", "Invalid SAML MetadataFile")
    if metadata_url is not None:
        metadata_url = _identity_provider_endpoint_url(metadata_url, "MetadataURL")
    result = {
        "IDPInit": _provider_boolean(value.get("IDPInit", "false"), "IDPInit"),
        "IDPSignout": _provider_boolean(value.get("IDPSignout", "false"), "IDPSignout"),
        "EncryptedResponses": _provider_boolean(
            value.get("EncryptedResponses", "false"), "EncryptedResponses"
        ),
    }
    for field in ("IDPInit", "IDPSignout"):
        if result[field] == "true":
            _error(
                "InvalidParameterException",
                f"SAML {field}=true is not executable in this implementation",
            )
    signing = value.get("RequestSigningAlgorithm")
    if signing not in {None, "rsa-sha256"}:
        _error("InvalidParameterException", "Invalid SAML RequestSigningAlgorithm")
    if signing is not None:
        result["RequestSigningAlgorithm"] = signing
    result["MetadataFile" if metadata_file is not None else "MetadataURL"] = (
        metadata_file if metadata_file is not None else metadata_url
    )
    return result


def _provider_boolean(value: Any, field: str) -> str:
    if value not in {"true", "false"}:
        _error("InvalidParameterException", f"Invalid {field}")
    return value


def _social_provider_details(provider_type: str, value: Any) -> tuple[dict[str, str], str]:
    if provider_type not in _SOCIAL_PROVIDER_ENDPOINTS or not isinstance(value, dict):
        _error("InvalidParameterException", "Invalid social ProviderDetails")
    common = {"authorize_scopes", "client_id"}
    if provider_type == "SignInWithApple":
        allowed = common | {"key_id", "private_key", "team_id"}
        secret_field = "private_key"
    elif provider_type == "Facebook":
        allowed = common | {"api_version", "client_secret"}
        secret_field = "client_secret"
    else:
        allowed = common | {"client_secret"}
        secret_field = "client_secret"
    if set(value) - allowed:
        _error("InvalidParameterException", "Invalid social ProviderDetails")
    client_id = value.get("client_id")
    scopes = value.get("authorize_scopes")
    secret = value.get(secret_field)
    if (
        not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 256
        or not isinstance(scopes, str)
        or not 1 <= len(scopes) <= 1024
        or not isinstance(secret, str)
        or not 1 <= len(secret) <= 16 * 1024
    ):
        _error("InvalidParameterException", "Missing social provider credentials")
    delimiter = "," if provider_type == "Facebook" else None
    scope_values = (
        [item.strip() for item in scopes.split(",")] if delimiter == "," else scopes.split()
    )
    if (
        not scope_values
        or len(scope_values) > 50
        or len(scope_values) != len(set(scope_values))
        or any(not item or len(item) > 128 or not _safe_oidc_token(item) for item in scope_values)
    ):
        _error("InvalidParameterException", "Invalid social authorize_scopes")
    details = {
        **_SOCIAL_PROVIDER_ENDPOINTS[provider_type],
        "authorize_scopes": (", ".join(scope_values) if delimiter else " ".join(scope_values)),
        "client_id": client_id,
    }
    if provider_type == "Facebook":
        api_version = value.get("api_version")
        if (
            not isinstance(api_version, str)
            or re.fullmatch(r"v[1-9][0-9]?\.0", api_version) is None
        ):
            _error("InvalidParameterException", "Invalid Facebook api_version")
        details.update(
            {
                "api_version": api_version,
                "attributes_url": f"https://graph.facebook.com/{api_version}/me?fields=",
                "authorize_url": f"https://www.facebook.com/{api_version}/dialog/oauth",
                "token_url": f"https://graph.facebook.com/{api_version}/oauth/access_token",
            }
        )
    elif provider_type == "SignInWithApple":
        key_id = value.get("key_id")
        team_id = value.get("team_id")
        if not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in (key_id, team_id)):
            _error("InvalidParameterException", "Invalid Sign in with Apple identifiers")
        try:
            private_key = serialization.load_pem_private_key(secret.encode(), password=None)
        except (TypeError, ValueError):
            _error("InvalidParameterException", "Invalid Sign in with Apple private_key")
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP256R1
        ):
            _error("InvalidParameterException", "Apple private_key must use P-256")
        details.update({"key_id": key_id, "team_id": team_id})
    return details, secret


def _safe_oidc_token(value: str) -> bool:
    return bool(value) and all(0x21 <= ord(character) <= 0x7E for character in value)


def _identity_provider_attribute_mapping(
    pool: UserPool, value: Any, *, provider_type: str = "OIDC"
) -> dict[str, str]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or len(value) > 32:
        _error("InvalidParameterException", "Invalid identity provider AttributeMapping")
    allowed_attributes = {
        "username",
        *_STANDARD_CLIENT_ATTRIBUTES,
        *_schema_definitions(pool),
    }
    result = {}
    for destination, claim in value.items():
        if (
            not isinstance(destination, str)
            or destination not in allowed_attributes
            or destination in {"sub", "email_verified", "phone_number_verified"}
            or not isinstance(claim, str)
            or not 1 <= len(claim) <= 128
            or not _safe_oidc_token(claim)
        ):
            _error("InvalidParameterException", "Invalid identity provider AttributeMapping")
        result[destination] = claim
    subject_claim = {
        "Facebook": "id",
        "LoginWithAmazon": "user_id",
        "SAML": "NameID",
    }.get(provider_type, "sub")
    result.setdefault("username", subject_claim)
    return result


def _user_context_data(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"EncodedData", "IpAddress"}:
        _error("InvalidParameterException", "Invalid UserContextData")
    return _admin_auth_context(value)


def _runtime_user_context(client: UserPoolClient, value: Any) -> dict[str, str]:
    result = _user_context_data(value)
    if (
        getattr(client, "enable_propagate_additional_user_context_data", False)
        and isinstance(value, dict)
        and isinstance(value.get("EncodedData"), str)
    ):
        result[_PROPAGATED_CONTEXT_MARKER] = "true"
    return result


def _analytics_metadata(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) != {"AnalyticsEndpointId"}:
        _error("InvalidParameterException", "Invalid AnalyticsMetadata")
    endpoint_id = value.get("AnalyticsEndpointId")
    if not isinstance(endpoint_id, str) or len(endpoint_id) > 131_072:
        _error("InvalidParameterException", "Invalid AnalyticsEndpointId")
    return {"AnalyticsEndpointId": endpoint_id}


def _identity_provider_identifiers(pool: UserPool, provider_name: str, value: Any) -> list[str]:
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or len(value) > 50
        or len(set(value)) != len(value)
        or not all(
            isinstance(item, str)
            and 1 <= len(item) <= 40
            and all(character.isalnum() or character in "_ +=.@-" for character in item)
            for item in value
        )
    ):
        _error("InvalidParameterException", "Invalid IdpIdentifiers")
    used = {
        identifier
        for provider in pool.identity_providers.values()
        if provider.provider_name != provider_name
        for identifier in provider.idp_identifiers
    }
    if used & set(value):
        _error("DuplicateProviderException", "Identity provider identifier is already in use")
    return list(value)


def _identity_provider_client_secret(pool: UserPool, provider: CognitoIdentityProvider) -> str:
    return _decrypt_client_state(
        pool,
        provider.encrypted_client_secret,
        f"identity-provider-secret:{provider.provider_name}",
    )


def _identity_provider_response(
    pool: UserPool, provider: CognitoIdentityProvider
) -> dict[str, Any]:
    details = dict(provider.provider_details)
    if provider.provider_type in {
        "OIDC",
        "Google",
        "Facebook",
        "LoginWithAmazon",
    }:
        details["client_secret"] = _identity_provider_client_secret(pool, provider)
    return {
        "AttributeMapping": dict(provider.attribute_mapping),
        "CreationDate": provider.created_at,
        "IdpIdentifiers": list(provider.idp_identifiers),
        "LastModifiedDate": provider.updated_at,
        "ProviderDetails": details,
        "ProviderName": provider.provider_name,
        "ProviderType": provider.provider_type,
        "UserPoolId": provider.pool_id,
    }


def _identity_provider_description(provider: CognitoIdentityProvider) -> dict[str, Any]:
    return {
        "CreationDate": provider.created_at,
        "LastModifiedDate": provider.updated_at,
        "ProviderName": provider.provider_name,
        "ProviderType": provider.provider_type,
    }


def _provider_user_identifier(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) - {
        "ProviderAttributeName",
        "ProviderAttributeValue",
        "ProviderName",
    }:
        _error("InvalidParameterException", "Invalid provider user identifier")
    result = {}
    for field, maximum in (
        ("ProviderName", 32),
        ("ProviderAttributeName", 128),
        ("ProviderAttributeValue", 2048),
    ):
        item = value.get(field)
        if not isinstance(item, str) or not 1 <= len(item) <= maximum or not _safe_oidc_token(item):
            _error("InvalidParameterException", f"Invalid {field}")
        result[field] = item
    return result


def _federated_identity_key(provider: str, attribute: str, value: str) -> str:
    return hashlib.sha256(f"{provider}\0{attribute}\0{value}".encode()).hexdigest()


def _federated_username(provider: str, subject: str) -> str:
    candidate = f"{provider}_{subject}"
    if len(candidate) <= 128 and all(
        ord(character) >= 0x20 and ord(character) != 0x7F for character in candidate
    ):
        return candidate
    return f"{provider}_{hashlib.sha256(subject.encode()).hexdigest()}"[:128]


def _federated_identity_claims(pool: UserPool, user: CognitoUser) -> list[dict[str, Any]]:
    claims = []
    for identity in sorted(
        user.federated_identities,
        key=lambda item: (
            item.provider_name,
            item.provider_attribute_name,
            item.provider_attribute_value,
        ),
    ):
        provider = pool.identity_providers.get(identity.provider_name)
        if provider is None:
            continue
        claims.append(
            {
                "dateCreated": int(identity.created_at.timestamp() * 1000),
                "issuer": provider.provider_details.get("oidc_issuer")
                or (
                    provider.discovery_document.get("entity_id", "")
                    if provider.discovery_document
                    else ""
                ),
                "primary": False,
                "providerName": provider.provider_name,
                "providerType": provider.provider_type,
                "userId": identity.provider_attribute_value,
            }
        )
    return claims


def _domain_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not _DOMAIN_PATTERN.fullmatch(value)
        or any(reserved in value for reserved in ("amazon", "aws", "cognito"))
    ):
        _error("InvalidParameterException", "Invalid prefix domain")
    return value


def _managed_login_version(value: Any) -> int:
    version = 1 if value is None else value
    if not isinstance(version, int) or isinstance(version, bool) or version not in {1, 2}:
        _error("InvalidParameterException", "ManagedLoginVersion must be 1 or 2")
    return version


def _local_domain_hostname(domain_name: str) -> str:
    return f"{domain_name}{_LOCAL_DOMAIN_SUFFIX}"


def _ui_customization_client_id(value: Any) -> str:
    client_id = "ALL" if value is None else value
    if (
        not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 128
        or re.fullmatch(r"[\w+]+", client_id) is None
    ):
        _error("InvalidParameterException", "Invalid UI customization ClientId")
    return client_id


def _require_user_pool_domain(store: CognitoIdpStore, pool_id: str) -> None:
    with cognito_idp_stores.lock:
        if not any(domain.user_pool_id == pool_id for domain in store.user_pool_domains.values()):
            _error(
                "InvalidParameterException",
                "A user pool domain is required for classic UI customization",
            )


def _pool_id(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        _error("InvalidParameterException", "UserPoolId is required")
    return value


def _encode_page_token(kind: str, after: str) -> str:
    payload = json.dumps(
        {"after": after, "kind": kind}, separators=(",", ":"), sort_keys=True
    ).encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _decode_page_token(value: Any, expected_kind: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PAGE_TOKEN_BYTES:
        _error("InvalidParameterException", "Invalid pagination token")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if len(raw) > _MAX_PAGE_TOKEN_BYTES:
            raise ValueError
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        _error("InvalidParameterException", "Invalid pagination token")
    if (
        not isinstance(payload, dict)
        or set(payload) != {"after", "kind"}
        or payload.get("kind") != expected_kind
        or not isinstance(payload.get("after"), str)
        or not 1 <= len(payload["after"]) <= 128
    ):
        _error("InvalidParameterException", "Invalid pagination token")
    return payload["after"]


def _page_after(items: list, limit: int, after: str | None, key):
    start = 0
    if after is not None:
        while start < len(items) and key(items[start]) <= after:
            start += 1
    page = items[start : start + limit]
    has_more = start + len(page) < len(items)
    next_after = key(page[-1]) if page and has_more else None
    return page, next_after


def _list_limit(value: Any) -> int:
    result = 60 if value is None else value
    if not isinstance(result, int) or isinstance(result, bool) or not 0 <= result <= 60:
        _error("InvalidParameterException", "Limit must be between 0 and 60")
    return result


def _encode_bound_page_token(pool: UserPool, kind: str, after: str) -> str:
    payload = json.dumps(
        {"after": after, "kind": kind, "pool": pool.pool_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signature = (
        base64.urlsafe_b64encode(
            hmac.new(pool.access_signing_private_key_pem, body.encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{body}.{signature}"


def _decode_bound_page_token(pool: UserPool, value: Any, expected_kind: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or value.count(".") != 1:
        _error("InvalidParameterException", "Invalid pagination token")
    body, supplied_signature = value.split(".")
    expected_signature = (
        base64.urlsafe_b64encode(
            hmac.new(pool.access_signing_private_key_pem, body.encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    if not hmac.compare_digest(expected_signature, supplied_signature):
        _error("InvalidParameterException", "Invalid pagination token")
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_", validate=True)
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        _error("InvalidParameterException", "Invalid pagination token")
    if (
        not isinstance(payload, dict)
        or set(payload) != {"after", "kind", "pool"}
        or payload.get("kind") != expected_kind
        or payload.get("pool") != pool.pool_id
        or not isinstance(payload.get("after"), str)
        or not 1 <= len(payload["after"]) <= 128
    ):
        _error("InvalidParameterException", "Invalid pagination token")
    return payload["after"]


_VALIDITY_UNIT_SECONDS = {
    "seconds": 1,
    "minutes": 60,
    "hours": 60 * 60,
    "days": 24 * 60 * 60,
}


def _token_validity_units(value: Any) -> dict[str, str]:
    result = {
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days",
    }
    if value is None:
        return result
    if not isinstance(value, dict) or not set(value) <= set(result):
        _error("InvalidParameterException", "Invalid TokenValidityUnits")
    for token_type, unit in value.items():
        if unit not in _VALIDITY_UNIT_SECONDS:
            _error("InvalidParameterException", f"Invalid validity unit for {token_type}")
        result[token_type] = unit
    return result


def _validity_seconds(value: int, unit: str) -> int:
    return value * _VALIDITY_UNIT_SECONDS[unit]


def _token_validity(
    request: ServiceRequest,
    key: str,
    *,
    default: int,
    unit: str,
    minimum_seconds: int,
    maximum_seconds: int,
    zero_means_default: bool = False,
) -> int:
    value = request.get(key, default)
    if zero_means_default and value == 0:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum_seconds:
        _error("InvalidParameterException", f"Invalid {key}")
    seconds = _validity_seconds(value, unit)
    if not minimum_seconds <= seconds <= maximum_seconds:
        _error("InvalidParameterException", f"Invalid {key} duration")
    return value


def _auth_flows(value: Any) -> list[str]:
    try:
        return list(normalize_explicit_auth_flows(value))
    except ClientConfigurationError as error:
        _error("InvalidParameterException", str(error))


def _client_analytics_configuration(context: RequestContext, value: Any) -> AnalyticsConfiguration:
    connection = connect_to(
        aws_access_key_id=context.account_id,
        region_name=context.region,
    )
    project_resolver, role_resolver = analytics_resolvers(connection)
    try:
        configuration = parse_analytics_configuration(
            value,
            scope=ClientScope(
                partition=context.partition,
                region=context.region,
                account_id=context.account_id,
            ),
            project_resolver=project_resolver,
            role_resolver=role_resolver,
        )
        revalidate_analytics_configuration(
            configuration,
            project_resolver=project_resolver,
            role_resolver=role_resolver,
        )
        return configuration
    except ClientConfigurationError as error:
        _error("InvalidParameterException", str(error))


def _propagate_additional_user_context_data(value: Any, *, has_client_secret: bool) -> bool:
    try:
        return validate_propagate_additional_context(
            value,
            has_client_secret=has_client_secret,
        )
    except ClientConfigurationError as error:
        _error("InvalidParameterException", str(error))


def _prevent_user_existence_errors(value: Any) -> str:
    result = "LEGACY" if value is None else value
    if result not in {"ENABLED", "LEGACY"}:
        _error(
            "InvalidParameterException",
            "PreventUserExistenceErrors must be ENABLED or LEGACY",
        )
    return result


def _pool_short_id(pool_id: str) -> str:
    _, separator, short_id = pool_id.partition("_")
    if not separator or not short_id:
        _error("InvalidParameterException", "Invalid user pool ID")
    return short_id


def _password_credentials(
    pool_id: str, username: str, password: str
) -> tuple[PasswordHash, str, str]:
    while True:
        salt_value = int.from_bytes(secrets.token_bytes(16), "big")
        if salt_value:
            break
    salt = _srp_pad_hex(salt_value)
    username_password_hash = hashlib.sha256(
        f"{_pool_short_id(pool_id)}{username}:{password}".encode()
    ).hexdigest()
    private_x = int(_srp_hex_hash(f"{salt}{username_password_hash}"), 16)
    verifier = pow(_SRP_G, private_x, _SRP_N)
    if verifier == 0:
        _error("InvalidPasswordException", "Unable to derive password credentials")
    return PasswordHash.from_password(password), salt, _srp_pad_hex(verifier)


def _synthetic_srp_credentials(pool: UserPool, username: str) -> tuple[str, str]:
    key = pool.access_signing_private_key_pem
    salt_value = (
        int.from_bytes(
            hmac.new(key, f"srp-salt:{username}".encode(), hashlib.sha256).digest()[:16],
            "big",
        )
        or 1
    )
    salt = _srp_pad_hex(salt_value)
    synthetic_hash = hmac.new(key, f"srp-password:{username}".encode(), hashlib.sha256).hexdigest()
    private_x = int(_srp_hex_hash(f"{salt}{synthetic_hash}"), 16)
    verifier = pow(_SRP_G, private_x, _SRP_N)
    return salt, _srp_pad_hex(verifier)


def _srp_public_value(value: Any, field: str) -> int:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or re.fullmatch(r"[0-9a-fA-F]+", value) is None
    ):
        _error("InvalidParameterException", f"Invalid {field}")
    result = int(value, 16)
    if not 0 < result < _SRP_N or result % _SRP_N == 0:
        _error("InvalidParameterException", f"Invalid {field}")
    return result


def _srp_stored_value(value: str, field: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        _error("NotAuthorizedException", f"Invalid {field}")
    result = int(value, 16)
    if not 0 < result < _SRP_N:
        _error("NotAuthorizedException", f"Invalid {field}")
    return result


def _srp_hkdf(shared_secret: int, scrambling: int) -> bytes:
    ikm = bytes.fromhex(_srp_pad_hex(shared_secret))
    salt = bytes.fromhex(_srp_pad_hex(scrambling))
    pseudo_random_key = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(pseudo_random_key, b"Caldera Derived Key\x01", hashlib.sha256).digest()[:16]


_PASSWORD_CLAIM_TIMESTAMP_PATTERN = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"([1-9]|[12][0-9]|3[01]) ([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) UTC ([0-9]{4})$"
)
_PASSWORD_CLAIM_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_PASSWORD_CLAIM_MONTHS = {
    month: number
    for number, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        1,
    )
}


def _password_claim_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        _error("NotAuthorizedException", "Invalid authentication response")
    match = _PASSWORD_CLAIM_TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        _error("NotAuthorizedException", "Invalid authentication response")
    weekday, month, day, hour, minute, second, year = match.groups()
    try:
        result = datetime(
            int(year),
            _PASSWORD_CLAIM_MONTHS[month],
            int(day),
            int(hour),
            int(minute),
            int(second),
            tzinfo=UTC,
        )
    except ValueError:
        _error("NotAuthorizedException", "Invalid authentication response")
    if _PASSWORD_CLAIM_WEEKDAYS[result.weekday()] != weekday:
        _error("NotAuthorizedException", "Invalid authentication response")
    return result


def _strict_base64(value: Any, field: str, expected_bytes: int) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        _error("NotAuthorizedException", f"Invalid {field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        _error("NotAuthorizedException", f"Invalid {field}")
    if len(decoded) != expected_bytes:
        _error("NotAuthorizedException", f"Invalid {field}")
    return decoded


def _group_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(unicodedata.category(character)[0] not in "LMSNP" for character in value)
    ):
        _error("InvalidParameterException", "Invalid GroupName")
    return value


def _auth_session_validity(value: Any, *, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not 3 <= value <= 15:
        _error("InvalidParameterException", "AuthSessionValidity must be between 3 and 15")
    return value


def _resource_server_identifier(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        _error("InvalidParameterException", "Invalid resource server Identifier")
    if any(
        not (code == 0x21 or 0x23 <= code <= 0x5B or 0x5D <= code <= 0x7E)
        for code in map(ord, value)
    ):
        _error("InvalidParameterException", "Invalid resource server Identifier")
    return value


def _resource_server_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or not re.fullmatch(r"[\w\s+=,.@-]+", value)
    ):
        _error("InvalidParameterException", "Invalid resource server Name")
    return value


def _resource_server_scopes(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, list) or len(value) > 100:
        _error("InvalidParameterException", "Invalid resource server Scopes")
    scopes: dict[str, str] = {}
    for scope in value:
        if not isinstance(scope, dict) or set(scope) != {"ScopeDescription", "ScopeName"}:
            _error("InvalidParameterException", "Invalid resource server scope")
        scope_name, description = scope["ScopeName"], scope["ScopeDescription"]
        if not isinstance(scope_name, str) or not 1 <= len(scope_name) <= 256:
            _error("InvalidParameterException", "Invalid resource server scope name")
        if any(
            not (
                code == 0x21 or 0x23 <= code <= 0x2E or 0x30 <= code <= 0x5B or 0x5D <= code <= 0x7E
            )
            for code in map(ord, scope_name)
        ):
            _error("InvalidParameterException", "Invalid resource server scope name")
        if (
            not isinstance(description, str)
            or not 1 <= len(description) <= 256
            or scope_name in scopes
        ):
            _error("InvalidParameterException", "Invalid resource server scope")
        scopes[scope_name] = description
    return scopes


def _resource_server(pool: UserPool, value: Any) -> CognitoResourceServer:
    server = pool.resource_servers.get(_resource_server_identifier(value))
    if server is None:
        _error("ResourceNotFoundException", "Resource server does not exist")
    return server


def _tag_key(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value.lower().startswith("aws:")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        _error("InvalidParameterException", "Invalid tag key")
    return value


def _user_pool_tags(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        _error("InvalidParameterException", "UserPoolTags must be a map")
    if len(value) > _MAX_TAGS_PER_POOL:
        _error("LimitExceededException", "User pool tag quota exceeded")
    result: dict[str, str] = {}
    for raw_key, tag_value in value.items():
        key = _tag_key(raw_key)
        if (
            not isinstance(tag_value, str)
            or len(tag_value) > 256
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in tag_value)
        ):
            _error("InvalidParameterException", "Invalid tag value")
        result[key] = tag_value
    return result


def _tag_keys(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_TAGS_PER_POOL
        or not all(isinstance(key, str) for key in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", "Invalid TagKeys")
    return [_tag_key(key) for key in value]


def _admin_create_user_only(value: Any) -> bool:
    return _admin_create_user_configuration(value)["allow_admin_create_user_only"]


def _admin_create_user_configuration(value: Any) -> dict[str, Any]:
    if value is None:
        return {
            "allow_admin_create_user_only": False,
            "invite_message_template": None,
        }
    if not isinstance(value, dict) or set(value) - {
        "AllowAdminCreateUserOnly",
        "InviteMessageTemplate",
    }:
        _error("InvalidParameterException", "Invalid AdminCreateUserConfig")
    allow_admin = value.get("AllowAdminCreateUserOnly", False)
    if not isinstance(allow_admin, bool):
        _error("InvalidParameterException", "Invalid AdminCreateUserConfig")
    invite = value.get("InviteMessageTemplate")
    if invite is not None:
        if not isinstance(invite, dict) or set(invite) - {
            "EmailMessage",
            "EmailSubject",
            "SMSMessage",
        }:
            _error("InvalidParameterException", "Invalid InviteMessageTemplate")
        _verification_message(
            invite.get("EmailMessage"), "InviteMessageTemplate.EmailMessage", maximum=20_000
        )
        _optional_text(
            invite.get("EmailSubject"), "InviteMessageTemplate.EmailSubject", maximum=140
        )
        _verification_message(
            invite.get("SMSMessage"), "InviteMessageTemplate.SMSMessage", maximum=140
        )
    return {
        "allow_admin_create_user_only": allow_admin,
        "invite_message_template": copy.deepcopy(invite),
    }


def _device_configuration(value: Any) -> dict[str, bool]:
    if value is None:
        return {
            "challenge_required_on_new_device": False,
            "device_only_remembered_on_user_prompt": False,
            "device_tracking_enabled": False,
        }
    allowed = {"ChallengeRequiredOnNewDevice", "DeviceOnlyRememberedOnUserPrompt"}
    if not isinstance(value, dict) or not value or set(value) - allowed:
        _error("InvalidParameterException", "Invalid DeviceConfiguration")
    if any(not isinstance(setting, bool) for setting in value.values()):
        _error("InvalidParameterException", "Invalid DeviceConfiguration")
    return {
        "challenge_required_on_new_device": value.get("ChallengeRequiredOnNewDevice", False),
        "device_only_remembered_on_user_prompt": value.get(
            "DeviceOnlyRememberedOnUserPrompt", False
        ),
        "device_tracking_enabled": True,
    }


def _user_pool_security_configuration(
    request: ServiceRequest, *, context: RequestContext, include_create_only: bool
) -> dict[str, Any]:
    pool_configuration = _native_pool_configuration(request, context)
    policies = _password_policy(request.get("Policies"))
    result: dict[str, Any] = {
        "account_recovery_setting": _account_recovery_setting(
            request.get("AccountRecoverySetting")
        ),
        "auto_verified_attributes": _attribute_choice_list(
            request.get("AutoVerifiedAttributes"),
            "AutoVerifiedAttributes",
            {"email", "phone_number"},
            maximum=2,
        ),
        "email_verification_message": _verification_message(
            request.get("EmailVerificationMessage"), "EmailVerificationMessage", maximum=20_000
        ),
        "email_verification_subject": _optional_text(
            request.get("EmailVerificationSubject"),
            "EmailVerificationSubject",
            maximum=140,
        ),
        "email_configuration": _notification_configuration_field(
            request.get("EmailConfiguration"), None, context, "email"
        ),
        "lambda_config": (
            dict(pool_configuration.lambda_config)
            if "LambdaConfig" in pool_configuration.configured_fields
            else None
        ),
        "mfa_configuration": _mfa_configuration(request.get("MfaConfiguration")),
        "password_policy": policies,
        "pool_configuration": pool_configuration,
        "sms_verification_message": _verification_message(
            request.get("SmsVerificationMessage"), "SmsVerificationMessage", maximum=140
        ),
        "sms_configuration": _notification_configuration_field(
            None, request.get("SmsConfiguration"), context, "sms"
        ),
        "verification_message_template": _verification_message_template(
            request.get("VerificationMessageTemplate")
        ),
    }
    if "UserPoolTier" in request:
        tier = request.get("UserPoolTier")
        if tier not in {"LITE", "ESSENTIALS", "PLUS"}:
            _error("InvalidParameterException", "Invalid UserPoolTier")
        result["user_pool_tier"] = tier
    if include_create_only:
        alias_attributes = _attribute_choice_list(
            request.get("AliasAttributes"),
            "AliasAttributes",
            {"email", "phone_number", "preferred_username"},
            maximum=3,
        )
        username_attributes = _attribute_choice_list(
            request.get("UsernameAttributes"),
            "UsernameAttributes",
            {"email", "phone_number"},
            maximum=2,
        )
        if alias_attributes is not None and username_attributes is not None:
            _error(
                "InvalidParameterException",
                "AliasAttributes and UsernameAttributes are mutually exclusive",
            )
        result["schema_attributes"] = _schema_attributes(request.get("Schema"))
        result["alias_attributes"] = alias_attributes
        result["username_attributes"] = username_attributes
        result["username_case_sensitive"] = _username_case_sensitive(
            request.get("UsernameConfiguration")
        )
    return result


def _native_pool_configuration(
    request: ServiceRequest, context: RequestContext
) -> PoolConfiguration:
    identity = PoolIdentity(
        partition=context.partition,
        region=context.region,
        account_id=context.account_id,
    )
    try:
        return parse_pool_configuration(
            request,
            identity=identity,
            kms_key_validator=lambda arn: _local_kms_key_snapshot(context, arn),
        )
    except PoolConfigurationError as error:
        _error(error.code, str(error))


def _local_kms_key_snapshot(context: RequestContext, key_arn: str) -> str:
    response = connect_to(
        aws_access_key_id=context.account_id,
        region_name=context.region,
    ).kms.describe_key(KeyId=key_arn)
    metadata = response.get("KeyMetadata")
    if (
        not isinstance(metadata, dict)
        or metadata.get("Arn") != key_arn
        or metadata.get("Enabled") is not True
        or metadata.get("KeyState") != "Enabled"
        or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
    ):
        raise ValueError("KMS key is not enabled for encryption")
    return json.dumps(
        {
            "Arn": metadata.get("Arn"),
            "Enabled": metadata.get("Enabled"),
            "KeyId": metadata.get("KeyId"),
            "KeyState": metadata.get("KeyState"),
            "KeyUsage": metadata.get("KeyUsage"),
            "Origin": metadata.get("Origin"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _revalidate_pool_key(context: RequestContext, configuration: PoolConfiguration) -> None:
    try:
        revalidate_customer_managed_key(
            configuration, lambda arn: _local_kms_key_snapshot(context, arn)
        )
    except PoolConfigurationError as error:
        _error(error.code, str(error))


def _notification_configuration_field(
    email: Any, sms: Any, context: RequestContext, field: str
) -> dict[str, Any] | None:
    try:
        validate_notification_configuration(email, sms, context)
    except NotificationConfigurationError as error:
        _error("InvalidParameterException", str(error))
    value = email if field == "email" else sms
    return copy.deepcopy(value)


def _account_recovery_setting(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"RecoveryMechanisms"}:
        _error("InvalidParameterException", "Invalid AccountRecoverySetting")
    mechanisms = value.get("RecoveryMechanisms")
    if not isinstance(mechanisms, list) or not 1 <= len(mechanisms) <= 2:
        _error("InvalidParameterException", "Invalid AccountRecoverySetting")
    allowed = {"admin_only", "verified_email", "verified_phone_number"}
    if any(
        not isinstance(item, dict)
        or set(item) != {"Name", "Priority"}
        or item.get("Name") not in allowed
        or not isinstance(item.get("Priority"), int)
        or isinstance(item.get("Priority"), bool)
        for item in mechanisms
    ):
        _error("InvalidParameterException", "Invalid account recovery mechanism")
    names = [item["Name"] for item in mechanisms]
    priorities = [item["Priority"] for item in mechanisms]
    if (
        len(names) != len(set(names))
        or sorted(priorities) != list(range(1, len(mechanisms) + 1))
        or ("admin_only" in names and (len(names) != 1 or priorities != [1]))
    ):
        _error("InvalidParameterException", "Invalid account recovery priorities")
    return copy.deepcopy(value)


def _attribute_choice_list(
    value: Any, field: str, allowed: set[str], *, maximum: int
) -> list[str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= maximum
        or not all(isinstance(item, str) for item in value)
        or len(value) != len(set(value))
        or set(value) - allowed
    ):
        _error("InvalidParameterException", f"Invalid {field}")
    return list(value)


def _username_case_sensitive(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, dict) or set(value) != {"CaseSensitive"}:
        _error("InvalidParameterException", "Invalid UsernameConfiguration")
    case_sensitive = value.get("CaseSensitive")
    if not isinstance(case_sensitive, bool):
        _error("InvalidParameterException", "CaseSensitive must be a boolean")
    return case_sensitive


def _password_policy(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not value or set(value) - {"PasswordPolicy", "SignInPolicy"}:
        _error("InvalidParameterException", "Invalid Policies")
    sign_in_policy = value.get("SignInPolicy")
    if sign_in_policy is not None:
        factors = (
            sign_in_policy.get("AllowedFirstAuthFactors")
            if isinstance(sign_in_policy, dict)
            else None
        )
        if (
            not isinstance(factors, list)
            or not factors
            or len(factors) != len(set(factors))
            or not all(isinstance(item, str) for item in factors)
            or set(factors) - {"EMAIL_OTP", "PASSWORD", "SMS_OTP", "WEB_AUTHN"}
            or ("WEB_AUTHN" in factors and len(factors) == 1)
        ):
            _error(
                "InvalidParameterException",
                "Invalid AllowedFirstAuthFactors",
            )
    policy = value.get("PasswordPolicy", {})
    allowed = {
        "MinimumLength",
        "PasswordHistorySize",
        "RequireLowercase",
        "RequireNumbers",
        "RequireSymbols",
        "RequireUppercase",
        "TemporaryPasswordValidityDays",
    }
    if not isinstance(policy, dict) or not set(policy) <= allowed:
        _error("InvalidParameterException", "Unsupported PasswordPolicy fields")
    minimum = policy.get("MinimumLength", 8)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or not 6 <= minimum <= 99:
        _error("InvalidParameterException", "Invalid password MinimumLength")
    temporary_validity = policy.get("TemporaryPasswordValidityDays", 7)
    if (
        not isinstance(temporary_validity, int)
        or isinstance(temporary_validity, bool)
        or not 0 <= temporary_validity <= 365
    ):
        _error("InvalidParameterException", "Invalid TemporaryPasswordValidityDays")
    history_size = policy.get("PasswordHistorySize", 0)
    if (
        not isinstance(history_size, int)
        or isinstance(history_size, bool)
        or not 0 <= history_size <= 24
    ):
        _error("InvalidParameterException", "Invalid PasswordHistorySize")
    if temporary_validity == 0:
        policy = {**policy, "TemporaryPasswordValidityDays": 7}
        value = {**value, "PasswordPolicy": policy}
    for field in allowed - {
        "MinimumLength",
        "PasswordHistorySize",
        "TemporaryPasswordValidityDays",
    }:
        if field in policy and not isinstance(policy[field], bool):
            _error("InvalidParameterException", f"Invalid password policy {field}")
    return copy.deepcopy(value)


def _schema_attributes(value: Any, *, custom_only: bool = False) -> list[dict[str, Any]] | None:
    if value is None:
        if custom_only:
            _error("InvalidParameterException", "CustomAttributes is required")
        return None
    maximum = _MAX_CUSTOM_ATTRIBUTES_PER_REQUEST if custom_only else 50
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        _error(
            "InvalidParameterException",
            f"Schema must contain 1 to {maximum} attributes",
        )
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for attribute in value:
        if not isinstance(attribute, dict):
            _error("InvalidParameterException", "Invalid Schema attribute")
        allowed = {
            "AttributeDataType",
            "DeveloperOnlyAttribute",
            "Mutable",
            "Name",
            "NumberAttributeConstraints",
            "Required",
            "StringAttributeConstraints",
        }
        if not set(attribute) <= allowed or "Name" not in attribute:
            _error("InvalidParameterException", "Unsupported Schema attribute fields")
        name = attribute["Name"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 20
            or name.startswith(("custom:", "dev:"))
            or not all(unicodedata.category(character)[0] in "LMSNP" for character in name)
            or name in seen
        ):
            _error("InvalidParameterException", "Invalid Schema attribute Name")
        is_standard = name in _STANDARD_SCHEMA_ATTRIBUTES
        if custom_only and is_standard:
            _error("InvalidParameterException", "Standard attributes cannot be added")
        data_type = attribute.get("AttributeDataType", "String")
        if data_type not in {"String", "Number", "DateTime", "Boolean"}:
            _error("InvalidParameterException", "Invalid Schema AttributeDataType")
        if is_standard and data_type != "String":
            _error("InvalidParameterException", "Standard attributes must be String")
        for field in ("DeveloperOnlyAttribute", "Mutable", "Required"):
            if field in attribute and not isinstance(attribute[field], bool):
                _error("InvalidParameterException", f"Invalid Schema attribute {field}")
        if is_standard and attribute.get("DeveloperOnlyAttribute") is True:
            _error("InvalidParameterException", "Standard attributes cannot be developer-only")
        if not is_standard and attribute.get("Required") is True:
            _error("InvalidParameterException", "Custom attributes cannot be required")
        _validate_attribute_constraints(attribute, data_type)
        seen.add(name)
        result.append(copy.deepcopy(attribute))
    return result


def _validate_attribute_constraints(attribute: dict[str, Any], data_type: str) -> None:
    string_constraints = attribute.get("StringAttributeConstraints")
    number_constraints = attribute.get("NumberAttributeConstraints")
    if string_constraints is not None:
        if data_type != "String":
            _error("InvalidParameterException", "String constraints require a String attribute")
        minimum, maximum = _string_attribute_bounds(string_constraints)
        if minimum > maximum:
            _error("InvalidParameterException", "Invalid StringAttributeConstraints range")
    if number_constraints is not None:
        if data_type != "Number":
            _error("InvalidParameterException", "Number constraints require a Number attribute")
        minimum, maximum = _number_attribute_bounds(number_constraints)
        if minimum > maximum:
            _error("InvalidParameterException", "Invalid NumberAttributeConstraints range")


def _string_attribute_bounds(value: Any) -> tuple[int, int]:
    if not isinstance(value, dict) or not set(value) <= {"MaxLength", "MinLength"}:
        _error("InvalidParameterException", "Invalid StringAttributeConstraints")

    def parse(field: str, default: int) -> int:
        raw = value.get(field)
        if raw is None:
            return default
        if not isinstance(raw, str) or re.fullmatch(r"[0-9]+", raw) is None:
            _error("InvalidParameterException", f"Invalid {field}")
        parsed = int(raw)
        if not 0 <= parsed <= _MAX_ATTRIBUTE_VALUE_CHARACTERS:
            _error("InvalidParameterException", f"Invalid {field}")
        return parsed

    return parse("MinLength", 0), parse("MaxLength", _MAX_ATTRIBUTE_VALUE_CHARACTERS)


def _number_attribute_bounds(value: Any) -> tuple[Decimal, Decimal]:
    if not isinstance(value, dict) or not set(value) <= {"MaxValue", "MinValue"}:
        _error("InvalidParameterException", "Invalid NumberAttributeConstraints")

    def parse(field: str, default: str) -> Decimal:
        raw = value.get(field)
        if raw is None:
            raw = default
        if not isinstance(raw, str) or not raw or len(raw) > 131_072:
            _error("InvalidParameterException", f"Invalid {field}")
        try:
            parsed = Decimal(raw)
        except InvalidOperation:
            _error("InvalidParameterException", f"Invalid {field}")
        if not parsed.is_finite() or abs(parsed) > _MAX_SCHEMA_NUMBER:
            _error("InvalidParameterException", f"Invalid {field}")
        return parsed

    maximum = str(_MAX_SCHEMA_NUMBER)
    return parse("MinValue", f"-{maximum}"), parse("MaxValue", maximum)


def _mfa_configuration(value: Any) -> str:
    result = "OFF" if value is None else value
    if result not in {"OFF", "ON", "OPTIONAL"}:
        _error("InvalidParameterException", "Invalid MfaConfiguration")
    return result


def _optional_text(value: Any, field: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        _error("InvalidParameterException", f"Invalid {field}")
    return value


def _verification_message(value: Any, field: str, *, maximum: int) -> str | None:
    result = _optional_text(value, field, maximum=maximum)
    if result is not None and "{####}" not in result:
        _error("InvalidParameterException", f"{field} must contain {{####}}")
    return result


def _verification_message_template(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    allowed = {"DefaultEmailOption", "EmailMessage", "EmailSubject", "SmsMessage"}
    if not isinstance(value, dict) or not set(value) <= allowed:
        _error("InvalidParameterException", "Unsupported VerificationMessageTemplate fields")
    if value.get("DefaultEmailOption", "CONFIRM_WITH_CODE") != "CONFIRM_WITH_CODE":
        _error("InvalidParameterException", "Only CONFIRM_WITH_CODE is implemented")
    _verification_message(value.get("EmailMessage"), "EmailMessage", maximum=20_000)
    _optional_text(value.get("EmailSubject"), "EmailSubject", maximum=140)
    _verification_message(value.get("SmsMessage"), "SmsMessage", maximum=140)
    return copy.deepcopy(value)


def _lambda_config(value: Any, context: RequestContext) -> dict[str, str] | None:
    if value is None:
        return None
    allowed = {
        "CreateAuthChallenge",
        "DefineAuthChallenge",
        "PostConfirmation",
        "PreTokenGeneration",
        "VerifyAuthChallengeResponse",
    }
    if not isinstance(value, dict) or not value or not set(value) <= allowed:
        _error("InvalidParameterException", "Unsupported LambdaConfig triggers")
    prefix = f"arn:{context.partition}:lambda:{context.region}:{context.account_id}:function:"
    for trigger, function_arn in value.items():
        if (
            not isinstance(function_arn, str)
            or not function_arn.startswith(prefix)
            or not 1 <= len(function_arn.removeprefix(prefix)) <= 140
            or any(character.isspace() for character in function_arn)
        ):
            _error("InvalidParameterException", f"Invalid LambdaConfig {trigger} ARN")
    return dict(value)


def _device_key(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 55
        or not re.fullmatch(r"[\w-]+_[0-9a-f-]+", value)
    ):
        _error("InvalidParameterException", "Invalid DeviceKey")
    return value


def _optional_auth_device_key(value: Any) -> str | None:
    if value is None:
        return None
    return _device_key(value)


def _device_verifier_configuration(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"PasswordVerifier", "Salt"}:
        _error("InvalidParameterException", "Invalid DeviceSecretVerifierConfig")
    try:
        return normalize_device_verifier(value.get("Salt"), value.get("PasswordVerifier"))
    except DeviceSrpError as error:
        _error(error.code, str(error))


def _legacy_mfa_options(value: Any) -> None:
    if value != []:
        _error(
            "InvalidParameterException",
            "SMS MFA user settings are not implemented; use software token MFA preferences",
        )


def _self_service_attributes(value: Any) -> dict[str, str]:
    attributes = _attributes(value)
    if {"email_verified", "phone_number_verified"} & set(attributes):
        _error("InvalidParameterException", "Verification attributes are read-only")
    return attributes


def _schema_attribute_storage_name(definition: dict[str, Any]) -> str:
    name = definition["Name"]
    if name.startswith(("custom:", "dev:")):
        return name
    if name in _STANDARD_SCHEMA_ATTRIBUTES:
        return name
    prefix = "dev:" if definition.get("DeveloperOnlyAttribute") is True else "custom:"
    return f"{prefix}{name}"


def _schema_definitions(pool: UserPool) -> dict[str, dict[str, Any]]:
    return {
        _schema_attribute_storage_name(definition): definition
        for definition in pool.schema_attributes or []
    }


def _required_schema_attributes(pool: UserPool) -> set[str]:
    return {
        name
        for name, definition in _schema_definitions(pool).items()
        if definition.get("Required") is True
    }


def _validate_initial_user_attributes(
    pool: UserPool,
    username: str,
    attributes: dict[str, str],
    *,
    administrator: bool = False,
) -> None:
    if (
        not administrator
        and "preferred_username" in attributes
        and "preferred_username" in set(getattr(pool, "alias_attributes", None) or [])
    ):
        _error(
            "InvalidParameterException",
            "preferred_username alias cannot be supplied during sign-up",
        )
    aliases = set(getattr(pool, "alias_attributes", None) or [])
    if "email" in aliases and "@" in username:
        _error("InvalidParameterException", "Username cannot have email format in this pool")
    if "phone_number" in aliases and re.fullmatch(r"\+[1-9][0-9]{1,14}", username):
        _error("InvalidParameterException", "Username cannot have phone-number format in this pool")
    username_attributes = set(pool.username_attributes or [])
    selected_username_attribute = None
    if "email" in username_attributes and "@" in username:
        selected_username_attribute = "email"
    elif "phone_number" in username_attributes and re.fullmatch(r"\+[1-9][0-9]{1,14}", username):
        selected_username_attribute = "phone_number"
    if username_attributes:
        if selected_username_attribute is None:
            _error(
                "InvalidParameterException",
                "Username must match a configured username attribute",
            )
        existing = attributes.get(selected_username_attribute)
        if existing is not None and _casefold_identity(pool, existing) != username:
            _error(
                "InvalidParameterException",
                f"Username must match the {selected_username_attribute} attribute",
            )
        attributes[selected_username_attribute] = username
    definitions = _schema_definitions(pool)
    if definitions:
        unknown_custom = {
            name
            for name in attributes
            if name.startswith(("custom:", "dev:")) and name not in definitions
        }
        if unknown_custom:
            _error(
                "InvalidParameterException",
                f"User attributes are not in the pool schema: {sorted(unknown_custom)}",
            )
        if missing := _required_schema_attributes(pool) - set(attributes):
            _error("InvalidParameterException", f"Missing required attributes: {sorted(missing)}")
        if not administrator and any(name.startswith("dev:") for name in attributes):
            _error(
                "NotAuthorizedException", "Developer-only attributes require administrator access"
            )
        _validate_schema_values(definitions, attributes)


def _validate_schema_mutation(
    pool: UserPool,
    user: CognitoUser,
    attribute_names: set[str],
    *,
    deleting: bool = False,
    administrator: bool = False,
    attribute_values: dict[str, str] | None = None,
) -> None:
    definitions = _schema_definitions(pool)
    if not definitions:
        return
    unknown_custom = {
        name
        for name in attribute_names
        if name.startswith(("custom:", "dev:")) and name not in definitions
    }
    if unknown_custom:
        _error(
            "InvalidParameterException",
            f"User attributes are not in the pool schema: {sorted(unknown_custom)}",
        )
    if not administrator and any(name.startswith("dev:") for name in attribute_names):
        _error("NotAuthorizedException", "Developer-only attributes require administrator access")
    for name in attribute_names:
        definition = definitions.get(name)
        if definition is None:
            continue
        if deleting and definition.get("Required") is True:
            _error("InvalidParameterException", f"Required attribute cannot be deleted: {name}")
        if definition.get("Mutable") is False:
            _error("InvalidParameterException", f"Attribute is immutable: {name}")
    if attribute_values is not None:
        _validate_schema_values(definitions, attribute_values)


def _validate_schema_values(
    definitions: dict[str, dict[str, Any]], attributes: dict[str, str]
) -> None:
    for name, value in attributes.items():
        definition = definitions.get(name)
        if definition is None:
            continue
        data_type = definition.get("AttributeDataType", "String")
        if data_type == "String":
            minimum, maximum = _string_attribute_bounds(
                definition.get("StringAttributeConstraints", {})
            )
            valid = minimum <= len(value) <= maximum
        elif data_type == "Number":
            try:
                parsed = Decimal(value)
            except InvalidOperation:
                valid = False
            else:
                minimum, maximum = _number_attribute_bounds(
                    definition.get("NumberAttributeConstraints", {})
                )
                valid = parsed.is_finite() and minimum <= parsed <= maximum
        elif data_type == "Boolean":
            valid = value in {"true", "false"}
        else:
            valid = _valid_datetime_attribute(value)
        if not valid:
            _error("InvalidParameterException", f"Invalid value for schema attribute {name}")


def _valid_datetime_attribute(value: str) -> bool:
    try:
        numeric = Decimal(value)
    except InvalidOperation:
        numeric = None
    if numeric is not None and numeric.is_finite():
        return True
    try:
        datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    except ValueError:
        return False
    return True


def _verifiable_attribute(value: Any) -> str:
    if value not in {"email", "phone_number"}:
        _error("InvalidParameterException", "Only email and phone_number can be verified")
    return value


def _group(pool: UserPool, value: Any) -> CognitoGroup:
    name = _group_name(value)
    group = pool.groups.get(name)
    if group is None:
        _error("ResourceNotFoundException", f"Group {name} does not exist")
    return group


def _group_description(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 2048:
        _error("InvalidParameterException", "Invalid group Description")
    return value or None


_ROLE_ARN_PATTERN = re.compile(r"^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")


def _group_role_arn(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 2048
        or _ROLE_ARN_PATTERN.fullmatch(value) is None
    ):
        _error("InvalidParameterException", "Invalid group RoleArn")
    return value


def _group_precedence(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2**31 - 1:
        _error("InvalidParameterException", "Invalid group Precedence")
    return value


def _attributes_to_get(value: Any) -> list[str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_USER_ATTRIBUTES + 1
        or not all(isinstance(name, str) and 1 <= len(name) <= 32 for name in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", "Invalid AttributesToGet")
    return list(value)


def _attribute_names(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > _MAX_USER_ATTRIBUTES
        or not all(isinstance(name, str) and 1 <= len(name) <= 32 for name in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", "Invalid UserAttributeNames")
    for name in value:
        if name == "sub" or name in _RESERVED_TOKEN_CLAIMS or name.startswith("cognito:"):
            _error("InvalidParameterException", f"User attribute {name} cannot be deleted")
    return list(value)


def _totp_encryption_key(pool: UserPool) -> bytes:
    return hashlib.sha256(b"localstack-cognito-totp\x00" + pool.id_signing_private_key_pem).digest()


def _client_state_encryption_key(pool: UserPool) -> bytes:
    return hashlib.sha256(
        b"localstack-cognito-client-state\x00" + pool.id_signing_private_key_pem
    ).digest()


def _encrypt_client_state(pool: UserPool, value: str, purpose: str) -> str:
    nonce = secrets.token_bytes(12)
    aad = f"{pool.pool_id}:{purpose}".encode()
    ciphertext = AESGCM(_client_state_encryption_key(pool)).encrypt(nonce, value.encode(), aad)
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt_client_state(pool: UserPool, encrypted: str, purpose: str) -> str:
    try:
        payload = base64.b64decode(encrypted, validate=True)
        # AES-GCM authenticates an empty value as nonce + tag (12 + 16 bytes).
        # Identity providers without a client/encryption secret intentionally use
        # that representation, while malformed or truncated state remains rejected.
        if len(payload) < 28:
            raise ValueError
        aad = f"{pool.pool_id}:{purpose}".encode()
        return (
            AESGCM(_client_state_encryption_key(pool))
            .decrypt(payload[:12], payload[12:], aad)
            .decode()
        )
    except (InvalidTag, UnicodeDecodeError, ValueError, TypeError):
        _error("NotAuthorizedException", "Invalid encrypted Cognito client state")


def _client_secret_values(pool: UserPool, client: UserPoolClient) -> list[str]:
    if client.secret is not None:
        legacy_value = client.secret
        secret_id = _primary_client_secret_id(client)
        client.primary_secret = UserPoolClientSecret(
            secret_id=secret_id,
            encrypted_value=_encrypt_client_state(
                pool, legacy_value, f"client-secret:{client.client_id}:{secret_id}"
            ),
            created_at=client.created_at,
        )
        client.secret = None
    values = []
    if client.primary_secret is not None:
        values.append(
            _decrypt_client_state(
                pool,
                client.primary_secret.encrypted_value,
                f"client-secret:{client.client_id}:{client.primary_secret.secret_id}",
            )
        )
    for descriptor in client.additional_secrets.values():
        values.append(
            _decrypt_client_state(
                pool,
                descriptor.encrypted_value,
                f"client-secret:{client.client_id}:{descriptor.secret_id}",
            )
        )
    return values


def prepare_cognito_idp_state_for_snapshot(stores: Any) -> None:
    """Eagerly migrate legacy plaintext client secrets before snapshot serialization."""
    if getattr(stores, "service_name", None) != "cognito-idp":
        raise ValueError("Invalid Cognito IDP persistence store")
    for region_bundle in stores.values():
        for store in region_bundle.values():
            if not isinstance(store, CognitoIdpStore):
                raise ValueError("Invalid Cognito IDP persistence store")
            for pool in store.user_pools.values():
                for client in pool.clients.values():
                    legacy_secret = client.secret
                    if legacy_secret is None:
                        continue
                    if not isinstance(legacy_secret, str) or not 1 <= len(legacy_secret) <= 256:
                        raise ValueError("Invalid legacy Cognito client secret")
                    if client.primary_secret is not None:
                        current = _decrypt_client_state(
                            pool,
                            client.primary_secret.encrypted_value,
                            f"client-secret:{client.client_id}:{client.primary_secret.secret_id}",
                        )
                        if not hmac.compare_digest(current, legacy_secret):
                            raise ValueError("Conflicting legacy Cognito client secret")
                    else:
                        secret_id = _primary_client_secret_id(client)
                        client.primary_secret = UserPoolClientSecret(
                            secret_id=secret_id,
                            encrypted_value=_encrypt_client_state(
                                pool,
                                legacy_secret,
                                f"client-secret:{client.client_id}:{secret_id}",
                            ),
                            created_at=client.created_at,
                        )
                    client.secret = None


def _client_has_secret(client: UserPoolClient) -> bool:
    return (
        client.secret is not None
        or client.primary_secret is not None
        or bool(client.additional_secrets)
    )


def _client_secret_matches(pool: UserPool, client: UserPoolClient, supplied: Any) -> bool:
    values = _client_secret_values(pool, client)
    if not values:
        return supplied is None
    if not isinstance(supplied, str):
        return False
    matched = False
    for value in values:
        matched |= hmac.compare_digest(value, supplied)
    return matched


def _verify_client_secret(pool: UserPool, client: UserPoolClient, supplied: Any) -> None:
    if not _client_secret_matches(pool, client, supplied):
        _error("NotAuthorizedException", "Invalid client secret")


def _encrypt_totp_secret(pool: UserPool, secret: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_totp_encryption_key(pool)).encrypt(
        nonce, secret.encode(), pool.pool_id.encode()
    )
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt_totp_secret(pool: UserPool, encrypted: str) -> str:
    try:
        payload = base64.b64decode(encrypted, validate=True)
        if len(payload) < 29:
            raise ValueError
        return (
            AESGCM(_totp_encryption_key(pool))
            .decrypt(payload[:12], payload[12:], pool.pool_id.encode())
            .decode()
        )
    except (InvalidTag, UnicodeDecodeError, ValueError, TypeError):
        _error("NotAuthorizedException", "Invalid software token configuration")


def _verify_totp_code(secret: str, code: Any, now: float) -> int | None:
    if not isinstance(code, str) or re.fullmatch(r"[0-9]{6}", code) is None:
        return None
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError):
        return None
    current_step = int(now) // _TOTP_STEP_SECONDS
    for step in range(current_step - 1, current_step + 2):
        digest = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        expected = f"{truncated % 1_000_000:06d}"
        if hmac.compare_digest(expected, code):
            return step
    return None


def _apply_software_token_preference(user: CognitoUser, value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"Enabled", "PreferredMfa"}:
        _error("InvalidParameterException", "Invalid SoftwareTokenMfaSettings")
    enabled, preferred = value.get("Enabled"), value.get("PreferredMfa")
    if (
        not isinstance(enabled, bool)
        or not isinstance(preferred, bool)
        or preferred
        and not enabled
    ):
        _error("InvalidParameterException", "Invalid SoftwareTokenMfaSettings")
    if enabled and user.software_token_mfa_secret is None:
        _error("SoftwareTokenMFANotFoundException", "Software token is not associated")
    user.software_token_mfa_enabled = enabled
    user.software_token_mfa_preferred = preferred
    user.updated_at = _now()


def _email_mfa_configuration(
    value: Any, *, current: dict[str, Any] | None, supplied: bool
) -> dict[str, Any] | None:
    if not supplied:
        return copy.deepcopy(current)
    if not isinstance(value, dict) or set(value) - {"Message", "Subject"}:
        _error("InvalidParameterException", "Invalid EmailMfaConfiguration")
    message = value.get(
        "Message",
        (current or {}).get("Message", "Your authentication code is {####}."),
    )
    subject = value.get(
        "Subject",
        (current or {}).get("Subject", "Your authentication code"),
    )
    _verification_message(message, "EmailMfaConfiguration.Message", maximum=20_000)
    _optional_text(subject, "EmailMfaConfiguration.Subject", maximum=1_024)
    return {"Message": message, "Subject": subject}


def _sms_mfa_configuration(
    value: Any, *, current: dict[str, Any] | None, supplied: bool
) -> dict[str, Any] | None:
    if not supplied:
        return copy.deepcopy(current)
    if not isinstance(value, dict) or set(value) - {
        "SmsAuthenticationMessage",
        "SmsConfiguration",
    }:
        _error("InvalidParameterException", "Invalid SmsMfaConfiguration")
    message = value.get(
        "SmsAuthenticationMessage",
        (current or {}).get("SmsAuthenticationMessage", "Your authentication code is {####}."),
    )
    _verification_message(message, "SmsAuthenticationMessage", maximum=140)
    nested = copy.deepcopy(value.get("SmsConfiguration", (current or {}).get("SmsConfiguration")))
    return {
        "SmsAuthenticationMessage": message,
        **({"SmsConfiguration": nested} if nested is not None else {}),
    }


def _pool_recovery_attributes(pool: UserPool) -> tuple[str, ...]:
    setting = pool.account_recovery_setting
    if setting is None:
        return ("phone_number", "email")
    mechanisms = setting.get("RecoveryMechanisms", []) if isinstance(setting, dict) else []
    if any(item.get("Name") == "admin_only" for item in mechanisms if isinstance(item, dict)):
        return ()
    names = {
        "verified_email": "email",
        "verified_phone_number": "phone_number",
    }
    return tuple(
        names[item["Name"]]
        for item in sorted(mechanisms, key=lambda candidate: candidate.get("Priority", 99))
        if isinstance(item, dict) and item.get("Name") in names
    )


def _allowed_first_auth_factors(pool: UserPool) -> frozenset[str]:
    policies = pool.password_policy or {}
    sign_in = policies.get("SignInPolicy", {}) if isinstance(policies, dict) else {}
    factors = sign_in.get("AllowedFirstAuthFactors", ["PASSWORD"])
    return frozenset(factors)


def _pool_auth_policy(pool: UserPool) -> PoolAuthPolicy:
    email = pool.email_mfa_configuration
    sms = pool.sms_mfa_configuration
    if sms is None and pool.sms_configuration is not None and pool.mfa_configuration != "OFF":
        sms = {
            "SmsAuthenticationMessage": "Your authentication code is {####}.",
            "SmsConfiguration": pool.sms_configuration,
        }
    email_delivery = pool.email_configuration or {}
    return PoolAuthPolicy(
        feature_tier=getattr(pool, "user_pool_tier", "ESSENTIALS"),
        email_sending_account=email_delivery.get("EmailSendingAccount", "COGNITO_DEFAULT"),
        sms_delivery_configured=bool(pool.sms_configuration or (sms or {}).get("SmsConfiguration")),
        mfa_configuration=pool.mfa_configuration,
        allowed_first_auth_factors=_allowed_first_auth_factors(pool),
        auto_verified_attributes=frozenset(pool.auto_verified_attributes or []),
        recovery_attributes=_pool_recovery_attributes(pool),
        email_mfa=(
            EmailMfaConfiguration(
                message=email["Message"],
                subject=email["Subject"],
            )
            if email is not None
            else None
        ),
        sms_mfa=(
            SmsMfaConfiguration(
                message=sms["SmsAuthenticationMessage"],
                sms_configuration=copy.deepcopy(
                    sms.get("SmsConfiguration") or pool.sms_configuration
                ),
            )
            if sms is not None
            else None
        ),
        software_token_mfa_enabled=pool.software_token_mfa_enabled,
        web_authn_mfa_enabled=bool(
            pool.web_authn_configuration
            and pool.web_authn_configuration.get("FactorConfiguration")
            == "MULTI_FACTOR_WITH_USER_VERIFICATION"
        ),
    )


def _mfa_passwordless_engine(
    store: CognitoIdpStore,
    pool: UserPool,
    client: UserPoolClient | None = None,
) -> MfaPasswordlessEngine:
    signing_key = hmac.new(
        pool.id_signing_private_key_pem,
        b"localstack-cognito-mfa-passwordless-v1",
        hashlib.sha256,
    ).digest()
    validity = getattr(client, "auth_session_validity", 3) if client is not None else 3
    return MfaPasswordlessEngine(
        signing_key=signing_key,
        state=store.mfa_passwordless,
        challenge_ttl=timedelta(minutes=validity),
    )


def _validate_pool_auth_policy(pool: UserPool) -> PoolAuthPolicy:
    policy = _pool_auth_policy(pool)
    try:
        validate_pool_auth_policy(policy)
    except MfaPasswordlessError as error:
        _error(error.code, str(error))
    return policy


def _user_auth_state(pool: UserPool, user: CognitoUser) -> UserAuthState:
    verified = frozenset(
        attribute
        for attribute in ("email", "phone_number")
        if user.attributes.get(f"{attribute}_verified", "false").casefold() == "true"
    )
    relying_party = (pool.web_authn_configuration or {}).get("RelyingPartyId")
    return UserAuthState(
        username=user.username,
        password_enabled=user.status in {"CONFIRMED", "EXTERNAL_PROVIDER", "FORCE_CHANGE_PASSWORD"},
        attributes=dict(user.attributes),
        verified_attributes=verified,
        email_mfa_enabled=getattr(user, "email_mfa_enabled", False),
        email_mfa_preferred=getattr(user, "email_mfa_preferred", False),
        sms_mfa_enabled=getattr(user, "sms_mfa_enabled", False),
        sms_mfa_preferred=getattr(user, "sms_mfa_preferred", False),
        software_token_mfa_enabled=user.software_token_mfa_enabled,
        software_token_mfa_preferred=user.software_token_mfa_preferred,
        web_authn_enabled=bool(
            user.status in {"CONFIRMED", "EXTERNAL_PROVIDER"}
            and relying_party
            and any(
                credential.relying_party_id == relying_party
                for credential in user.web_authn_credentials.values()
            )
        ),
    )


def _software_mfa_preference(user: CognitoUser, value: Any) -> tuple[bool, bool]:
    if value is None:
        return user.software_token_mfa_enabled, user.software_token_mfa_preferred
    if not isinstance(value, dict) or not value or set(value) - {"Enabled", "PreferredMfa"}:
        _error("InvalidParameterException", "Invalid SoftwareTokenMfaSettings")
    if any(not isinstance(item, bool) for item in value.values()):
        _error("InvalidParameterException", "Invalid SoftwareTokenMfaSettings")
    enabled = value.get("Enabled", user.software_token_mfa_enabled)
    preferred = value.get("PreferredMfa", user.software_token_mfa_preferred)
    if not enabled:
        preferred = False
    if preferred and not enabled:
        _error("InvalidParameterException", "Preferred software token MFA must be enabled")
    if enabled and user.software_token_mfa_secret is None:
        _error("SoftwareTokenMFANotFoundException", "Software token is not associated")
    return enabled, preferred


def _apply_mfa_preferences(pool: UserPool, user: CognitoUser, request: ServiceRequest) -> None:
    policy = _validate_pool_auth_policy(pool)
    software_enabled, software_preferred = _software_mfa_preference(
        user, request.get("SoftwareTokenMfaSettings")
    )
    state = dataclasses.replace(
        _user_auth_state(pool, user),
        software_token_mfa_enabled=software_enabled,
        software_token_mfa_preferred=software_preferred,
    )
    try:
        state = set_user_mfa_preferences(
            policy,
            state,
            sms=request.get("SMSMfaSettings"),
            email=request.get("EmailMfaSettings"),
        )
    except MfaPasswordlessError as error:
        _error(error.code, str(error))
    user.software_token_mfa_enabled = state.software_token_mfa_enabled
    user.software_token_mfa_preferred = state.software_token_mfa_preferred
    user.email_mfa_enabled = state.email_mfa_enabled
    user.email_mfa_preferred = state.email_mfa_preferred
    user.sms_mfa_enabled = state.sms_mfa_enabled
    user.sms_mfa_preferred = state.sms_mfa_preferred
    user.updated_at = pool.updated_at = _now()


def _mfa_config_response(pool: UserPool) -> ServiceResponse:
    response: ServiceResponse = {
        "MfaConfiguration": pool.mfa_configuration,
        "SoftwareTokenMfaConfiguration": {"Enabled": pool.software_token_mfa_enabled},
    }
    if pool.web_authn_configuration is not None:
        response["WebAuthnConfiguration"] = dict(pool.web_authn_configuration)
    if pool.email_mfa_configuration is not None:
        response["EmailMfaConfiguration"] = copy.deepcopy(pool.email_mfa_configuration)
    if pool.sms_mfa_configuration is not None:
        response["SmsMfaConfiguration"] = copy.deepcopy(pool.sms_mfa_configuration)
    return response


def _web_authn_configuration(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {
        "FactorConfiguration",
        "RelyingPartyId",
        "UserVerification",
    }:
        _error("InvalidParameterException", "Invalid WebAuthnConfiguration")
    relying_party_id = value.get("RelyingPartyId")
    if (
        not isinstance(relying_party_id, str)
        or not 1 <= len(relying_party_id) <= 127
        or relying_party_id != relying_party_id.lower()
        or relying_party_id.endswith(".")
        or re.fullmatch(
            r"(?:localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)",
            relying_party_id,
        )
        is None
    ):
        _error("InvalidParameterException", "Invalid WebAuthn relying party ID")
    user_verification = value.get("UserVerification", "preferred")
    if user_verification not in {"preferred", "required"}:
        _error("InvalidParameterException", "Invalid WebAuthn user verification")
    factor = value.get("FactorConfiguration", "SINGLE_FACTOR")
    if factor not in {"SINGLE_FACTOR", "MULTI_FACTOR_WITH_USER_VERIFICATION"}:
        _error("InvalidParameterException", "Invalid WebAuthn factor configuration")
    if factor == "MULTI_FACTOR_WITH_USER_VERIFICATION" and user_verification != "required":
        _error(
            "InvalidParameterException",
            "Multi-factor WebAuthn requires user verification",
        )
    return {
        "FactorConfiguration": factor,
        "RelyingPartyId": relying_party_id,
        "UserVerification": user_verification,
    }


def _require_web_authn_configuration(pool: UserPool) -> dict[str, str]:
    if pool.web_authn_configuration is None:
        _error(
            "WebAuthnConfigurationMissingException",
            "The user pool has no WebAuthn relying party configuration",
        )
    sign_in_policy = (pool.password_policy or {}).get("SignInPolicy")
    if sign_in_policy is None or "WEB_AUTHN" not in sign_in_policy.get(
        "AllowedFirstAuthFactors", []
    ):
        _error("WebAuthnNotEnabledException", "WebAuthn is not enabled for sign-in")
    return pool.web_authn_configuration


def _reserve_web_authn_challenge(
    store: CognitoIdpStore, pool_id: str, username: str, now: datetime
) -> bool:
    for token_hash, challenge in list(store.web_authn_challenges.items()):
        if challenge.expires_at <= now:
            store.web_authn_challenges.pop(token_hash, None)
    matching = sorted(
        (
            challenge
            for challenge in store.web_authn_challenges.values()
            if challenge.pool_id == pool_id and challenge.username == username
        ),
        key=lambda challenge: (
            challenge.created_at,
            challenge.expires_at,
            challenge.token_hash,
        ),
    )
    return (
        len(matching) < _MAX_WEB_AUTHN_CHALLENGES_PER_USER
        and len(store.web_authn_challenges) < _MAX_WEB_AUTHN_CHALLENGES_PER_STORE
    )


_MANAGED_LOGIN_DEFAULT_SETTINGS = {
    "categories": {
        "form": {"location": {"horizontal": "CENTER", "vertical": "CENTER"}},
        "global": {"colorSchemeMode": "LIGHT", "spacingDensity": "REGULAR"},
    },
    "componentClasses": {
        "buttons": {"borderRadius": 8},
        "form": {
            "borderRadius": 8,
            "lightMode": {"backgroundColor": "ffffffff", "borderColor": "c6c6cdff"},
        },
        "pageBackground": {"lightMode": {"color": "f6f7f9ff"}},
        "primaryButton": {
            "lightMode": {"defaults": {"backgroundColor": "0972d3ff", "textColor": "ffffffff"}}
        },
    },
}
_MANAGED_LOGIN_ASSET_EXTENSIONS = {
    "FAVICON_ICO": {"ICO"},
    "FAVICON_SVG": {"SVG"},
    "EMAIL_GRAPHIC": {"JPEG", "PNG", "SVG"},
    "SMS_GRAPHIC": {"JPEG", "PNG", "SVG"},
    "AUTH_APP_GRAPHIC": {"JPEG", "PNG", "SVG"},
    "PASSWORD_GRAPHIC": {"JPEG", "PNG", "SVG"},
    "PASSKEY_GRAPHIC": {"JPEG", "PNG", "SVG"},
    "PAGE_HEADER_LOGO": {"JPEG", "PNG", "SVG"},
    "PAGE_HEADER_BACKGROUND": {"JPEG", "PNG", "SVG"},
    "PAGE_FOOTER_LOGO": {"JPEG", "PNG", "SVG"},
    "PAGE_FOOTER_BACKGROUND": {"JPEG", "PNG", "SVG"},
    "PAGE_BACKGROUND": {"JPEG", "PNG", "SVG"},
    "FORM_BACKGROUND": {"JPEG", "PNG", "SVG"},
    "FORM_LOGO": {"JPEG", "PNG", "SVG"},
    "IDP_BUTTON_ICON": {"ICO", "SVG"},
}
_TERM_LANGUAGES = {
    "bahasa-indonesia",
    "chinese-simplified",
    "chinese-traditional",
    "default",
    "dutch",
    "english",
    "french",
    "german",
    "italian",
    "japanese",
    "korean",
    "portuguese-brazil",
    "spanish",
}


def _optional_boolean(request: dict[str, Any], name: str, default: bool) -> bool:
    value = request.get(name, default)
    if not isinstance(value, bool):
        _error("InvalidParameterException", f"{name} must be a boolean")
    return value


def _uuid4(value: Any, field: str) -> str:
    if not isinstance(value, str):
        _error("InvalidParameterException", f"{field} is required")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        _error("InvalidParameterException", f"Invalid {field}")
    if parsed.version != 4 or str(parsed) != value.lower():
        _error("InvalidParameterException", f"Invalid {field}")
    return str(parsed)


def _managed_login_branding_update(
    request: dict[str, Any], *, creating: bool
) -> tuple[bool, dict[str, Any] | None, list[dict[str, Any]] | None]:
    use_defaults = _optional_boolean(request, "UseCognitoProvidedValues", False)
    if use_defaults and ({"Settings", "Assets"} & set(request)):
        _error(
            "InvalidParameterException",
            "Settings and Assets must be omitted with UseCognitoProvidedValues",
        )
    settings = _managed_login_settings(request.get("Settings")) if "Settings" in request else None
    assets = _managed_login_assets(request.get("Assets")) if "Assets" in request else None
    wire_assets = []
    for item in assets or []:
        encoded_item = {name: value for name, value in item.items() if value is not None}
        if content := encoded_item.get("Bytes"):
            encoded_item["Bytes"] = base64.b64encode(content).decode()
        wire_assets.append(encoded_item)
    estimated = len(
        json.dumps(
            {"Assets": wire_assets, "Settings": settings or {}},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
    )
    if estimated > _MAX_MANAGED_LOGIN_REQUEST_BYTES:
        _error("InvalidParameterException", "Managed login branding request exceeds 2 MiB")
    if creating and use_defaults:
        return True, None, None
    return use_defaults, settings, assets


def _managed_login_settings(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        _error("InvalidParameterException", "Settings must be a non-empty JSON object")
    try:
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        _error("InvalidParameterException", "Settings must contain bounded JSON values")
    if len(encoded.encode()) > _MAX_MANAGED_LOGIN_SETTINGS_BYTES:
        _error("InvalidParameterException", "Managed login settings are too large")
    leaves: list[tuple[tuple[str, ...], Any]] = []

    def walk(item: Any, path: tuple[str, ...], depth: int) -> None:
        if depth > 8 or not isinstance(item, dict) or not item:
            _error("InvalidParameterException", "Unsupported managed login settings")
        for key, nested in item.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 64:
                _error("InvalidParameterException", "Invalid managed login setting name")
            current = (*path, key)
            if isinstance(nested, dict):
                walk(nested, current, depth + 1)
            else:
                leaves.append((current, nested))

    walk(value, (), 0)
    for path, item in leaves:
        _managed_login_setting_leaf(path, item)
    return copy.deepcopy(value)


def _managed_login_setting_leaf(path: tuple[str, ...], value: Any) -> None:
    enums = {
        ("categories", "global", "colorSchemeMode"): {"DARK", "DYNAMIC", "LIGHT"},
        ("categories", "global", "spacingDensity"): {"COMPACT", "REGULAR", "SPACIOUS"},
        ("categories", "form", "location", "horizontal"): {"CENTER", "LEFT", "RIGHT"},
        ("categories", "form", "location", "vertical"): {"BOTTOM", "CENTER", "TOP"},
        ("componentClasses", "form", "logo", "formInclusion"): {"IN", "OUT"},
        ("componentClasses", "form", "logo", "location"): {"CENTER", "LEFT", "RIGHT"},
        ("componentClasses", "form", "logo", "position"): {"BOTTOM", "TOP"},
    }
    if path in enums and value in enums[path]:
        return
    boolean_paths = {
        ("categories", "global", "pageFooter", "enabled"),
        ("categories", "global", "pageHeader", "enabled"),
        ("componentClasses", "form", "backgroundImage", "enabled"),
        ("componentClasses", "form", "logo", "enabled"),
        ("componentClasses", "pageBackground", "image", "enabled"),
    }
    if path in boolean_paths and isinstance(value, bool):
        return
    radius_paths = {
        ("componentClasses", "buttons", "borderRadius"),
        ("componentClasses", "form", "borderRadius"),
        ("componentClasses", "input", "borderRadius"),
    }
    if (
        path in radius_paths
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= 64
    ):
        return
    color_prefixes = {
        ("componentClasses", "form"),
        ("componentClasses", "idpButton"),
        ("componentClasses", "input"),
        ("componentClasses", "inputLabel"),
        ("componentClasses", "link"),
        ("componentClasses", "pageBackground"),
        ("componentClasses", "primaryButton"),
    }
    if (
        len(path) >= 4
        and path[:2] in color_prefixes
        and path[-1]
        in {
            "backgroundColor",
            "borderColor",
            "color",
            "foregroundColor",
            "placeholderColor",
            "textColor",
        }
        and isinstance(value, str)
        and re.fullmatch(r"[0-9a-fA-F]{8}", value)
    ):
        return
    _error(
        "InvalidParameterException",
        f"Unsupported managed login setting: {'.'.join(path)}",
    )


def _managed_login_assets(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_MANAGED_LOGIN_ASSETS:
        _error("InvalidParameterException", "Assets must contain at most 40 items")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {
            "Bytes",
            "Category",
            "ColorMode",
            "Extension",
            "ResourceId",
        }:
            _error("InvalidParameterException", "Invalid managed login asset")
        category = item.get("Category")
        color_mode = item.get("ColorMode")
        extension = item.get("Extension")
        if category not in _MANAGED_LOGIN_ASSET_EXTENSIONS:
            _error("InvalidParameterException", "Invalid managed login asset category")
        if color_mode not in {"LIGHT", "DARK", "DYNAMIC"}:
            _error("InvalidParameterException", "Invalid managed login asset color mode")
        if extension not in _MANAGED_LOGIN_ASSET_EXTENSIONS[category]:
            _error("InvalidParameterException", "Asset extension is incompatible with category")
        key = (category, color_mode)
        if key in seen:
            _error("InvalidParameterException", "Duplicate managed login asset role")
        seen.add(key)
        resource_id = item.get("ResourceId")
        if resource_id is not None and (
            not isinstance(resource_id, str) or re.fullmatch(r"[\w\- ]{1,40}", resource_id) is None
        ):
            _error("InvalidParameterException", "Invalid managed login asset ResourceId")
        content = item.get("Bytes")
        if content is not None:
            if not isinstance(content, (bytes, bytearray)) or len(content) > (
                _MAX_MANAGED_LOGIN_ASSET_BYTES
            ):
                _error("InvalidParameterException", "Invalid managed login asset bytes")
            content = bytes(content)
            _validate_managed_login_image(content, extension)
        result.append(
            {
                "Bytes": content,
                "Category": category,
                "ColorMode": color_mode,
                "Extension": extension,
                "ResourceId": resource_id,
            }
        )
    return result


def _validate_managed_login_image(content: bytes, extension: str) -> None:
    if not content:
        _error("InvalidParameterException", "Managed login asset is empty")
    if extension == "PNG":
        _validate_png(content)
        return
    if extension == "JPEG":
        _validate_jpeg(content)
        return
    if extension == "ICO":
        _validate_ico(content)
        return
    if extension == "WEBP":
        _validate_webp(content)
        return
    if extension == "SVG":
        lowered = content.lower()
        if any(
            marker in lowered
            for marker in (
                b"<!doctype",
                b"<!entity",
                b"<script",
                b"<style",
                b"@import",
                b"javascript:",
                b"url(",
            )
        ):
            _error("InvalidParameterException", "Unsafe SVG managed login asset")
        try:
            root = ET.fromstring(content)
        except (ET.ParseError, ValueError):
            _error("InvalidParameterException", "Invalid SVG managed login asset")
        if root.tag.rsplit("}", 1)[-1].lower() != "svg":
            _error("InvalidParameterException", "Invalid SVG managed login asset")
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1].lower() in {
                "foreignobject",
                "iframe",
                "object",
                "script",
            }:
                _error("InvalidParameterException", "Unsafe SVG managed login asset")
            for name, attribute in element.attrib.items():
                local_name = name.rsplit("}", 1)[-1].lower()
                if (
                    local_name == "style"
                    or local_name.startswith("on")
                    or (local_name in {"href", "src"} and not attribute.startswith("#"))
                ):
                    _error("InvalidParameterException", "Unsafe SVG managed login asset")
        _validate_svg_dimensions(root)
        return
    _error("InvalidParameterException", "Asset bytes do not match Extension")


def _validate_png(content: bytes) -> None:
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        _error("InvalidParameterException", "Invalid PNG managed login asset")
    offset, chunks, saw_header, saw_data, saw_end = 8, 0, False, False, False
    compressed = bytearray()
    expected_size = width = height = channels = 0
    while offset < len(content) and chunks < 128:
        if offset + 12 > len(content):
            break
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        kind = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > _MAX_MANAGED_LOGIN_ASSET_BYTES or end > len(content):
            break
        data = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != expected_crc:
            break
        if chunks == 0:
            if kind != b"IHDR" or length != 13:
                break
            width, height = struct.unpack(">II", data[:8])
            if not 1 <= width <= 4096 or not 1 <= height <= 4096:
                break
            bit_depth, color_type = data[8], data[9]
            channels_by_type = {0: 1, 2: 3, 4: 2, 6: 4}
            channels = channels_by_type.get(color_type, 0)
            if bit_depth != 8 or channels == 0 or data[10:13] != b"\x00\x00\x00":
                break
            expected_size = height * (1 + width * channels)
            if expected_size > 64 * 1024 * 1024:
                break
            saw_header = True
        elif kind == b"IDAT":
            if not saw_header or saw_end:
                break
            saw_data = True
            compressed.extend(data)
        elif kind == b"IEND":
            saw_end = length == 0 and end == len(content)
            offset = end
            break
        offset, chunks = end, chunks + 1
    valid = saw_header and saw_data and saw_end and offset == len(content)
    if valid:
        try:
            decompressor = zlib.decompressobj()
            pixels = decompressor.decompress(bytes(compressed), expected_size + 1)
            if decompressor.unconsumed_tail:
                raise zlib.error("PNG expands beyond its declared dimensions")
            pixels += decompressor.flush()
            valid = (
                decompressor.eof
                and not decompressor.unused_data
                and len(pixels) == expected_size
                and all(pixels[row * (1 + width * channels)] <= 4 for row in range(height))
            )
        except zlib.error:
            valid = False
    if not valid:
        _error("InvalidParameterException", "Invalid PNG managed login asset")


def _validate_jpeg(content: bytes) -> None:
    try:
        validate_jpeg_image(
            content,
            max_width=4096,
            max_height=4096,
            max_pixels=4096 * 4096,
        )
    except ImageValidationError:
        _error("InvalidParameterException", "Invalid JPEG managed login asset")


def _validate_ico(content: bytes) -> None:
    if len(content) < 22 or content[:4] != b"\x00\x00\x01\x00":
        _error("InvalidParameterException", "Invalid ICO managed login asset")
    count = struct.unpack("<H", content[4:6])[0]
    if not 1 <= count <= 32 or len(content) < 6 + 16 * count:
        _error("InvalidParameterException", "Invalid ICO managed login asset")
    for index in range(count):
        entry = content[6 + index * 16 : 22 + index * 16]
        width, height = entry[0] or 256, entry[1] or 256
        size, offset = struct.unpack("<II", entry[8:16])
        if (
            not 1 <= width <= 256
            or not 1 <= height <= 256
            or size == 0
            or (offset < 6 + 16 * count or offset + size > len(content))
        ):
            _error("InvalidParameterException", "Invalid ICO managed login asset")
        payload = content[offset : offset + size]
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            _error(
                "InvalidParameterException",
                "Only PNG-backed ICO managed login assets are implemented",
            )
        _validate_png(payload)


def _validate_webp(content: bytes) -> None:
    if (
        len(content) < 30
        or content[:4] != b"RIFF"
        or content[8:12] != b"WEBP"
        or struct.unpack("<I", content[4:8])[0] + 8 != len(content)
    ):
        _error("InvalidParameterException", "Invalid WEBP managed login asset")
    chunk_type = content[12:16]
    chunk_size = struct.unpack("<I", content[16:20])[0]
    if chunk_size == 0 or 20 + chunk_size > len(content):
        _error("InvalidParameterException", "Invalid WEBP managed login asset")
    data = content[20 : 20 + chunk_size]
    if chunk_type == b"VP8X" and len(data) >= 10:
        width = int.from_bytes(data[4:7], "little") + 1
        height = int.from_bytes(data[7:10], "little") + 1
    elif chunk_type == b"VP8L" and len(data) >= 5 and data[0] == 0x2F:
        dimensions = int.from_bytes(data[1:5], "little")
        width = (dimensions & 0x3FFF) + 1
        height = ((dimensions >> 14) & 0x3FFF) + 1
    elif chunk_type == b"VP8 " and len(data) >= 10 and data[3:6] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[6:8], "little") & 0x3FFF
        height = int.from_bytes(data[8:10], "little") & 0x3FFF
    else:
        _error("InvalidParameterException", "Invalid WEBP managed login asset")
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        _error("InvalidParameterException", "Invalid WEBP managed login dimensions")


def _validate_svg_dimensions(root: ET.Element) -> None:
    def dimension(name: str) -> float | None:
        raw = root.attrib.get(name)
        if raw is None:
            return None
        match = re.fullmatch(r"(?:0|[1-9][0-9]{0,4})(?:\.[0-9]{1,3})?(?:px)?", raw)
        if match is None:
            _error("InvalidParameterException", "Invalid SVG managed login dimensions")
        return float(raw.removesuffix("px"))

    width, height = dimension("width"), dimension("height")
    if width is not None and not 1 <= width <= 4096:
        _error("InvalidParameterException", "Invalid SVG managed login dimensions")
    if height is not None and not 1 <= height <= 4096:
        _error("InvalidParameterException", "Invalid SVG managed login dimensions")
    view_box = root.attrib.get("viewBox")
    if view_box is not None:
        try:
            values = [float(item) for item in view_box.split()]
        except ValueError:
            _error("InvalidParameterException", "Invalid SVG managed login viewBox")
        if (
            len(values) != 4
            or values[2] <= 0
            or values[3] <= 0
            or any(abs(item) > 100_000 for item in values)
        ):
            _error("InvalidParameterException", "Invalid SVG managed login viewBox")


def _managed_login_asset_map(
    assets: list[dict[str, Any]], *, existing: dict[str, ManagedLoginAsset]
) -> dict[str, ManagedLoginAsset]:
    result = copy.deepcopy(existing)
    for item in assets:
        resource_id = item["ResourceId"]
        current = result.get(resource_id) if resource_id is not None else None
        if resource_id is not None and current is None:
            _error("ResourceNotFoundException", "Managed login asset ResourceId not found")
        if current is None:
            current = next(
                (
                    asset
                    for asset in result.values()
                    if asset.category == item["Category"] and asset.color_mode == item["ColorMode"]
                ),
                None,
            )
        content = (
            item["Bytes"]
            if item["Bytes"] is not None
            else (current.content if current is not None else None)
        )
        if content is None:
            _error("InvalidParameterException", "New managed login asset requires Bytes")
        _validate_managed_login_image(content, item["Extension"])
        if any(
            candidate is not current
            and candidate.category == item["Category"]
            and candidate.color_mode == item["ColorMode"]
            for candidate in result.values()
        ):
            _error("InvalidParameterException", "Duplicate managed login asset role")
        target_id = current.resource_id if current is not None else str(uuid.uuid4())
        if current is not None:
            result.pop(current.resource_id, None)
        result[target_id] = ManagedLoginAsset(
            resource_id=target_id,
            category=item["Category"],
            color_mode=item["ColorMode"],
            extension=item["Extension"],
            content=content,
        )
    return result


def _managed_login_branding_by_id(pool: UserPool, branding_id: str) -> ManagedLoginBranding:
    branding = next(
        (
            candidate
            for candidate in pool.managed_login_branding.values()
            if candidate.branding_id == branding_id
        ),
        None,
    )
    if branding is None:
        _error("ResourceNotFoundException", "Managed login branding not found")
    return branding


def _managed_login_branding_response(
    pool: UserPool, branding: ManagedLoginBranding, *, merged: bool = False
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "CreationDate": branding.created_at,
        "LastModifiedDate": branding.updated_at,
        "ManagedLoginBrandingId": branding.branding_id,
        "UseCognitoProvidedValues": branding.use_cognito_provided_values,
        "UserPoolId": pool.pool_id,
    }
    settings = (
        _deep_merge(_MANAGED_LOGIN_DEFAULT_SETTINGS, branding.settings)
        if merged
        else branding.settings
    )
    if settings:
        response["Settings"] = copy.deepcopy(settings)
    if branding.assets:
        response["Assets"] = [
            {
                "Bytes": asset.content,
                "Category": asset.category,
                "ColorMode": asset.color_mode,
                "Extension": asset.extension,
                "ResourceId": asset.resource_id,
            }
            for asset in sorted(branding.assets.values(), key=lambda asset: asset.resource_id)
        ]
    return response


def _deep_merge(original: dict[str, Any], update: dict[str, Any] | None) -> dict[str, Any]:
    result = copy.deepcopy(original)
    for key, value in (update or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _terms_values(
    request: dict[str, Any], *, creating: bool, current: CognitoTerms | None = None
) -> tuple[str, str, str, dict[str, str]]:
    def value(name: str, fallback: Any) -> Any:
        if name in request:
            return request[name]
        if creating:
            _error("InvalidParameterException", f"{name} is required")
        return fallback

    terms_name = value("TermsName", current.terms_name if current else None)
    source = value("TermsSource", current.terms_source if current else None)
    enforcement = value("Enforcement", current.enforcement if current else None)
    links_value = (
        request["Links"]
        if "Links" in request
        else ({} if creating else current.links if current else {})
    )
    if terms_name not in {"privacy-policy", "terms-of-use"}:
        _error("InvalidParameterException", "Invalid TermsName")
    if source != "LINK":
        _error("InvalidParameterException", "Only LINK terms are implemented")
    if enforcement != "NONE":
        _error("InvalidParameterException", "Only NONE terms enforcement is implemented")
    links = _terms_links(links_value)
    return terms_name, source, enforcement, links


def _terms_links(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not 0 <= len(value) <= _MAX_TERM_LINKS:
        _error("InvalidParameterException", "Links must contain at most 13 entries")
    result = {}
    for key, link in value.items():
        if (
            not isinstance(key, str)
            or not key.startswith("cognito:")
            or key.removeprefix("cognito:") not in _TERM_LANGUAGES
        ):
            _error("InvalidParameterException", "Invalid managed-login language")
        if not isinstance(link, str) or not 1 <= len(link) <= 1024:
            _error("InvalidParameterException", "Invalid terms link")
        parsed = urlsplit(link)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or any(character.isspace() for character in link)
        ):
            _error("InvalidParameterException", "Terms links must be safe HTTP(S) URLs")
        result[key] = link
    return dict(sorted(result.items()))


def _terms(pool: UserPool, terms_id: str) -> CognitoTerms:
    item = pool.terms.get(terms_id)
    if item is None:
        _error("ResourceNotFoundException", "Terms not found")
    return item


def _terms_response(pool: UserPool, item: CognitoTerms) -> dict[str, Any]:
    return {
        "ClientId": item.client_id,
        "CreationDate": item.created_at,
        "Enforcement": item.enforcement,
        "LastModifiedDate": item.updated_at,
        "Links": copy.deepcopy(item.links),
        "TermsId": item.terms_id,
        "TermsName": item.terms_name,
        "TermsSource": item.terms_source,
        "UserPoolId": pool.pool_id,
    }


def _terms_description(item: CognitoTerms) -> dict[str, Any]:
    return {
        "CreationDate": item.created_at,
        "Enforcement": item.enforcement,
        "LastModifiedDate": item.updated_at,
        "TermsId": item.terms_id,
        "TermsName": item.terms_name,
    }


def _web_authn_credential_response(credential: WebAuthnCredential) -> dict[str, Any]:
    response = {
        "CreatedAt": credential.created_at,
        "CredentialId": credential.credential_id,
        "FriendlyCredentialName": credential.friendly_name,
        "RelyingPartyId": credential.relying_party_id,
    }
    if credential.authenticator_attachment is not None:
        response["AuthenticatorAttachment"] = credential.authenticator_attachment
    if credential.authenticator_transports:
        response["AuthenticatorTransports"] = list(credential.authenticator_transports)
    return response


def _base64_url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _attributes(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, list):
        _error("InvalidParameterException", "UserAttributes must be a list")
    if len(value) > _MAX_USER_ATTRIBUTES:
        _error(
            "InvalidParameterException",
            f"UserAttributes cannot contain more than {_MAX_USER_ATTRIBUTES} entries",
        )
    result: dict[str, str] = {}
    total_utf8_bytes = 0
    for attribute in value:
        if not isinstance(attribute, dict):
            _error("InvalidParameterException", "Invalid user attribute")
        if set(attribute) != {"Name", "Value"}:
            _error("InvalidParameterException", "User attribute must contain Name and Value")
        name, attribute_value = attribute.get("Name"), attribute.get("Value")
        if not isinstance(name, str) or not isinstance(attribute_value, str):
            _error("InvalidParameterException", "Invalid user attribute")
        try:
            name_bytes = name.encode("utf-8")
            value_bytes = attribute_value.encode("utf-8")
        except UnicodeEncodeError:
            _error("InvalidParameterException", "User attribute must contain valid UTF-8")
        if (
            not 1 <= len(name) <= _MAX_ATTRIBUTE_NAME_CHARACTERS
            or not 1 <= len(name_bytes) <= _MAX_ATTRIBUTE_NAME_UTF8_BYTES
        ):
            _error("InvalidParameterException", "User attribute Name is too large")
        if (
            len(attribute_value) > _MAX_ATTRIBUTE_VALUE_CHARACTERS
            or len(value_bytes) > _MAX_ATTRIBUTE_VALUE_UTF8_BYTES
        ):
            _error("InvalidParameterException", f"User attribute {name} Value is too large")
        total_utf8_bytes += len(name_bytes) + len(value_bytes)
        if total_utf8_bytes > _MAX_ATTRIBUTES_UTF8_BYTES:
            _error("InvalidParameterException", "UserAttributes payload is too large")
        if name in result:
            _error("InvalidParameterException", f"Duplicate user attribute: {name}")
        if name in _RESERVED_TOKEN_CLAIMS or name.startswith("cognito:"):
            _error("InvalidParameterException", f"User attribute {name} is a reserved token claim")
        result[name] = attribute_value
    return result


_MAX_USER_ATTRIBUTES = 32
_MAX_ATTRIBUTE_NAME_CHARACTERS = 32
_MAX_ATTRIBUTE_NAME_UTF8_BYTES = 128
_MAX_ATTRIBUTE_VALUE_CHARACTERS = 2048
_MAX_ATTRIBUTE_VALUE_UTF8_BYTES = 4096
_MAX_ATTRIBUTES_UTF8_BYTES = 16 * 1024


_RESERVED_TOKEN_CLAIMS = {
    "acr",
    "amr",
    "at_hash",
    "aud",
    "auth_time",
    "azp",
    "c_hash",
    "client_id",
    "cognito:groups",
    "cognito:preferred_role",
    "cognito:roles",
    "cognito:username",
    "device_key",
    "event_id",
    "exp",
    "iat",
    "identities",
    "iss",
    "jti",
    "nbf",
    "nonce",
    "origin_jti",
    "scope",
    "sub",
    "token_use",
    "username",
}


def _temporary_password_validity_days(pool: UserPool) -> int:
    return (
        (pool.password_policy or {})
        .get("PasswordPolicy", {})
        .get("TemporaryPasswordValidityDays", 7)
    )


def _temporary_password_expired(user: CognitoUser, now: datetime) -> bool:
    return (
        user.status == "FORCE_CHANGE_PASSWORD"
        and user.temporary_password_expires_at is not None
        and user.temporary_password_expires_at <= now
    )


def _validate_password(pool: UserPool, password: str) -> None:
    configured = (pool.password_policy or {}).get("PasswordPolicy", {})
    minimum = configured.get("MinimumLength", 8)
    requirements = {
        "RequireLowercase": any(character.islower() for character in password),
        "RequireNumbers": any(character.isdigit() for character in password),
        "RequireSymbols": any(not character.isalnum() for character in password),
        "RequireUppercase": any(character.isupper() for character in password),
    }
    if len(password) < minimum or any(
        configured.get(requirement, True) and not satisfied
        for requirement, satisfied in requirements.items()
    ):
        _error("InvalidPasswordException", "Password does not conform to policy")


def _set_user_password_credentials(pool: UserPool, user: CognitoUser, password: str) -> None:
    _assert_user_password_not_reused(pool, user, password)
    previous = user.password
    password_hash, srp_salt, srp_verifier = _password_credentials(
        pool.pool_id, user.username, password
    )
    user.password_history = list(
        rotate_password_history(
            previous,
            user.password_history,
            pool.pool_configuration,
        )
    )
    user.password = password_hash
    user.srp_salt = srp_salt
    user.srp_verifier = srp_verifier


def _assert_user_password_not_reused(pool: UserPool, user: CognitoUser, password: str) -> None:
    try:
        assert_password_not_reused(
            password,
            user.password,
            user.password_history,
            pool.pool_configuration,
        )
    except PoolConfigurationError as error:
        _error(error.code, str(error))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_numeric_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _user_code_key(pool: UserPool, username: str, purpose: str) -> str:
    return hmac.new(
        pool.id_signing_private_key_pem,
        f"user-code-key\x00{pool.pool_id}\x00{username}\x00{purpose}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _user_code_hash(pool: UserPool, client_id: str, username: str, purpose: str, code: str) -> str:
    return hmac.new(
        pool.id_signing_private_key_pem,
        f"user-code\x00{pool.pool_id}\x00{client_id}\x00{username}\x00{purpose}\x00{code}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _prune_user_codes(store: CognitoIdpStore, now: datetime) -> None:
    for key, state in list(store.user_codes.items()):
        if state.expires_at <= now or state.failed_attempts >= _MAX_USER_CODE_ATTEMPTS:
            store.user_codes.pop(key, None)


def _reserve_user_code(
    store: CognitoIdpStore,
    pool: UserPool,
    client_id: str,
    user: CognitoUser,
    purpose: str,
    attribute_name: str | None,
    now: datetime,
) -> tuple[NotificationReservation, str]:
    code = _new_numeric_code()
    reservation_id = secrets.token_urlsafe(32)
    key = _user_code_key(pool, user.username, purpose)
    with cognito_idp_stores.lock:
        _prune_user_codes(store, now)
        if key not in store.user_codes and len(store.user_codes) >= _MAX_USER_CODES_PER_STORE:
            _error("LimitExceededException", "Verification-code quota exceeded")
        store.user_codes[key] = UserCode(
            key=key,
            pool_id=pool.pool_id,
            client_id=client_id,
            username=user.username,
            purpose=purpose,
            attribute_name=attribute_name,
            code_hash=_user_code_hash(pool, client_id, user.username, purpose, code),
            created_at=now,
            expires_at=now + _USER_CODE_TTL,
            reservation_id=reservation_id,
            pending=True,
        )
    return NotificationReservation(reservation_id), code


def _commit_user_code(
    store: CognitoIdpStore,
    pool_id: str,
    username: str,
    purpose: str,
    reservation_id: str,
) -> bool:
    with cognito_idp_stores.lock:
        state = next(
            (
                candidate
                for candidate in store.user_codes.values()
                if candidate.pool_id == pool_id
                and candidate.username == username
                and candidate.purpose == purpose
            ),
            None,
        )
        if (
            state is None
            or not state.pending
            or state.reservation_id is None
            or not hmac.compare_digest(state.reservation_id, reservation_id)
        ):
            return False
        state.pending = False
        state.reservation_id = None
        return True


def _rollback_user_code(
    store: CognitoIdpStore,
    pool_id: str,
    username: str,
    purpose: str,
    reservation_id: str,
) -> None:
    with cognito_idp_stores.lock:
        for key, state in list(store.user_codes.items()):
            if (
                state.pool_id == pool_id
                and state.username == username
                and state.purpose == purpose
                and state.pending
                and state.reservation_id is not None
                and hmac.compare_digest(state.reservation_id, reservation_id)
            ):
                store.user_codes.pop(key, None)
                return


def _ensure_user_code_capacity(
    store: CognitoIdpStore,
    pool: UserPool,
    username: str,
    purposes: list[str],
    now: datetime,
) -> None:
    with cognito_idp_stores.lock:
        _prune_user_codes(store, now)
        existing_keys = set(store.user_codes)
        additional = sum(
            _user_code_key(pool, username, purpose) not in existing_keys for purpose in purposes
        )
        if len(store.user_codes) + additional > _MAX_USER_CODES_PER_STORE:
            _error("LimitExceededException", "Verification-code quota exceeded")


def _verify_user_code(
    store: CognitoIdpStore,
    pool: UserPool,
    client_id: str,
    username: str,
    purpose: str,
    code: str,
    now: datetime,
) -> None:
    key = _user_code_key(pool, username, purpose)
    with cognito_idp_stores.lock:
        state = store.user_codes.get(key)
        if (
            state is None
            or state.pending
            or state.pool_id != pool.pool_id
            or state.client_id not in {client_id, "*"}
            or state.username != username
            or state.purpose != purpose
        ):
            _error("CodeMismatchException", "Invalid verification code")
        if state.expires_at <= now:
            store.user_codes.pop(key, None)
            _error("ExpiredCodeException", "Verification code has expired")
        supplied_hash = _user_code_hash(pool, state.client_id, username, purpose, code)
        if not hmac.compare_digest(state.code_hash, supplied_hash):
            state.failed_attempts += 1
            if state.failed_attempts >= _MAX_USER_CODE_ATTEMPTS:
                store.user_codes.pop(key, None)
            _error("CodeMismatchException", "Invalid verification code")
        store.user_codes.pop(key, None)


def _remove_user_code(store: CognitoIdpStore, pool: UserPool, username: str, purpose: str) -> None:
    with cognito_idp_stores.lock:
        store.user_codes.pop(_user_code_key(pool, username, purpose), None)


def _synthetic_user_code_work(pool: UserPool, client_id: str, username: str, purpose: str) -> None:
    _user_code_hash(pool, client_id, username, purpose, "000000")


def _admin_auth_context(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    allowed = {"EncodedData", "HttpHeaders", "IpAddress", "ServerName", "ServerPath"}
    if not isinstance(value, dict) or set(value) - allowed:
        _error("InvalidParameterException", "Invalid ContextData")
    for field, maximum in (
        ("EncodedData", 131_072),
        ("ServerName", 256),
        ("ServerPath", 2_048),
    ):
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or len(item) > maximum):
            _error("InvalidParameterException", f"Invalid ContextData {field}")
    ip_address = value.get("IpAddress")
    if ip_address is not None:
        if not isinstance(ip_address, str) or len(ip_address) > 64:
            _error("InvalidParameterException", "Invalid ContextData IpAddress")
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            _error("InvalidParameterException", "Invalid ContextData IpAddress")
    headers = value.get("HttpHeaders", [])
    if not isinstance(headers, list) or len(headers) > 25:
        _error("InvalidParameterException", "Invalid ContextData HttpHeaders")
    device_name = None
    for header in headers:
        if (
            not isinstance(header, dict)
            or set(header) != {"headerName", "headerValue"}
            or not all(isinstance(item, str) and len(item) <= 1024 for item in header.values())
        ):
            _error("InvalidParameterException", "Invalid ContextData HttpHeaders")
        if header["headerName"].lower() == "user-agent":
            device_name = header["headerValue"][:128]
    result = {}
    if ip_address is not None:
        result["IpAddress"] = ip_address
    if device_name:
        result["DeviceName"] = device_name
    return result


def _client_metadata(value: Any) -> dict[str, str]:
    try:
        return normalize_client_metadata(value)
    except ClientMetadataError as error:
        _error("InvalidParameterException", str(error))


def _compromised_credentials_configuration(value: Any) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"Actions", "EventFilter"}:
        _error("InvalidParameterException", "Invalid CompromisedCredentialsRiskConfiguration")
    actions = value.get("Actions")
    if (
        not isinstance(actions, dict)
        or set(actions) != {"EventAction"}
        or actions.get("EventAction") not in {"BLOCK", "NO_ACTION"}
    ):
        _error("InvalidParameterException", "Invalid compromised-credentials action")
    event_filter = value.get("EventFilter", ["SIGN_IN"])
    if (
        not isinstance(event_filter, list)
        or not event_filter
        or len(event_filter) > 1
        or len(set(event_filter)) != len(event_filter)
        or set(event_filter) != {"SIGN_IN"}
    ):
        _error("InvalidParameterException", "Invalid compromised-credentials event filter")
    return {"Actions": {"EventAction": actions["EventAction"]}, "EventFilter": list(event_filter)}


def _risk_exception_configuration(value: Any) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"BlockedIPRangeList", "SkippedIPRangeList"}:
        _error("InvalidParameterException", "Invalid RiskExceptionConfiguration")
    result = {}
    for field in ("BlockedIPRangeList", "SkippedIPRangeList"):
        ranges = value.get(field, [])
        if not isinstance(ranges, list) or len(ranges) > 200 or len(set(ranges)) != len(ranges):
            _error("InvalidParameterException", f"Invalid {field}")
        normalized = []
        for item in ranges:
            if not isinstance(item, str) or not 1 <= len(item) <= 64:
                _error("InvalidParameterException", f"Invalid {field}")
            try:
                normalized.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                _error("InvalidParameterException", f"Invalid {field}")
        result[field] = normalized
    return result


def _effective_risk_configuration(
    pool: UserPool, client: UserPoolClient
) -> RiskConfiguration | None:
    return pool.risk_configurations.get(client.client_id) or pool.risk_configurations.get("ALL")


def _evaluate_local_auth_risk(
    pool: UserPool,
    client: UserPoolClient,
    password: Any,
    ip_address: str | None,
) -> tuple[str, str, bool, bool]:
    configuration = _effective_risk_configuration(pool, client)
    if configuration is None:
        return "Low", "NoRisk", False, False
    exceptions = configuration.risk_exceptions or {}
    address = ipaddress.ip_address(ip_address) if ip_address is not None else None
    if address is not None and any(
        address in ipaddress.ip_network(network)
        for network in exceptions.get("SkippedIPRangeList", [])
    ):
        return "Low", "NoRisk", False, False
    if address is not None and any(
        address in ipaddress.ip_network(network)
        for network in exceptions.get("BlockedIPRangeList", [])
    ):
        return "High", "Block", True, False
    compromised = configuration.compromised_credentials
    if (
        compromised is not None
        and "SIGN_IN" in compromised["EventFilter"]
        and compromised["Actions"]["EventAction"] == "BLOCK"
        and isinstance(password, str)
        and hashlib.sha256(password.encode()).hexdigest() in _LOCAL_COMPROMISED_PASSWORD_HASHES
    ):
        return "High", "Block", True, True
    return "Low", "NoRisk", False, False


def _record_auth_event(
    context: RequestContext,
    store: CognitoIdpStore,
    pool: UserPool,
    client: UserPoolClient,
    username: Any,
    succeeded: bool,
    context_data: dict[str, str],
    risk_level: str,
    risk_decision: str,
    compromised_credentials_detected: bool,
) -> None:
    if not isinstance(username, str) or not 1 <= len(username) <= 128:
        return
    with cognito_idp_stores.lock:
        matching = sorted(
            (
                event
                for event in store.auth_events.values()
                if event.pool_id == pool.pool_id and event.username == username
            ),
            key=lambda event: (event.created_at, event.event_id),
        )
        while len(matching) >= _MAX_AUTH_EVENTS_PER_USER:
            store.auth_events.pop(matching.pop(0).event_id, None)
        if len(store.auth_events) >= _MAX_AUTH_EVENTS_PER_STORE:
            oldest = min(
                store.auth_events.values(), key=lambda event: (event.created_at, event.event_id)
            )
            store.auth_events.pop(oldest.event_id, None)
        now = _now()
        event_id = str(uuid.uuid4())
        public_context = {
            key: value for key, value in context_data.items() if key != _PROPAGATED_CONTEXT_MARKER
        }
        event = AuthEvent(
            event_id=event_id,
            pool_id=pool.pool_id,
            client_id=client.client_id,
            username=username,
            created_at=now,
            event_response="Pass" if succeeded else "Fail",
            challenge_responses=[
                {
                    "ChallengeName": "Password",
                    "ChallengeResponse": "Success" if succeeded else "Failure",
                }
            ],
            context_data=public_context,
            additional_user_context_propagated=(
                context_data.get(_PROPAGATED_CONTEXT_MARKER) == "true"
            ),
            risk_level=risk_level,
            risk_decision=risk_decision,
            compromised_credentials_detected=compromised_credentials_detected,
        )
        store.auth_events[event_id] = event
    emit_auth_event(context, event)


def _auth_event(store: CognitoIdpStore, pool: UserPool, username: str, event_id: Any) -> AuthEvent:
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 50:
        _error("InvalidParameterException", "Invalid EventId")
    event = store.auth_events.get(event_id)
    if event is None or event.pool_id != pool.pool_id or event.username != username:
        _error("ResourceNotFoundException", "Authentication event does not exist")
    return event


def _auth_event_feedback_token(pool: UserPool, event: AuthEvent) -> str:
    payload = f"{event.event_id}\x00{event.username}\x00{event.pool_id}".encode()
    return (
        base64.urlsafe_b64encode(
            hmac.new(pool.id_signing_private_key_pem, payload, hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )


def _set_auth_event_feedback(event: AuthEvent, value: Any, provider: str) -> None:
    if value not in {"Valid", "Invalid"}:
        _error("InvalidParameterException", "FeedbackValue must be Valid or Invalid")
    event.feedback_value = value
    event.feedback_provider = provider
    event.feedback_date = _now()


def _auth_event_response(event: AuthEvent) -> dict[str, Any]:
    response = {
        "ChallengeResponses": copy.deepcopy(event.challenge_responses),
        "CreationDate": event.created_at,
        "EventContextData": dict(event.context_data),
        "EventId": event.event_id,
        "EventResponse": event.event_response,
        "EventRisk": {
            "CompromisedCredentialsDetected": event.compromised_credentials_detected,
            "RiskDecision": event.risk_decision,
            "RiskLevel": event.risk_level,
        },
        "EventType": "SignIn",
    }
    if event.feedback_value is not None:
        response["EventFeedback"] = {
            "FeedbackDate": event.feedback_date,
            "FeedbackValue": event.feedback_value,
            "Provider": event.feedback_provider,
        }
    return response


def _risk_configuration_response(pool: UserPool, client_id: str | None) -> dict[str, Any]:
    key = client_id or "ALL"
    configuration = pool.risk_configurations.get(key)
    if configuration is None and client_id is not None:
        configuration = pool.risk_configurations.get("ALL")
    response = {"UserPoolId": pool.pool_id}
    if client_id is not None:
        response["ClientId"] = client_id
    if configuration is None:
        response["LastModifiedDate"] = pool.created_at
        return response
    response["LastModifiedDate"] = configuration.updated_at
    if configuration.compromised_credentials is not None:
        response["CompromisedCredentialsRiskConfiguration"] = copy.deepcopy(
            configuration.compromised_credentials
        )
    if configuration.risk_exceptions is not None:
        response["RiskExceptionConfiguration"] = copy.deepcopy(configuration.risk_exceptions)
    return response


def _prune_refresh_sessions(
    store: CognitoIdpStore,
    pool_id: str,
    client_id: str,
    username: str,
    now: datetime,
) -> bool:
    sessions = store.refresh_sessions
    for session in sessions.values():
        if (
            session.encrypted_replacement_token is not None
            and session.retry_grace_expires_at is not None
            and session.retry_grace_expires_at < now
        ):
            session.encrypted_replacement_token = None
    evictions = {
        token_hash
        for token_hash, session in sessions.items()
        if session.revoked or session.expires_at <= now
    }

    matching = sorted(
        (
            session
            for token_hash, session in sessions.items()
            if token_hash not in evictions
            and session.pool_id == pool_id
            and session.client_id == client_id
            and session.username == username
        ),
        key=lambda session: (session.expires_at, session.token_hash),
    )
    while len(matching) >= _MAX_REFRESH_SESSIONS_PER_USER_CLIENT:
        evictions.add(matching.pop(0).token_hash)

    pool_sessions = sorted(
        (
            session
            for token_hash, session in sessions.items()
            if token_hash not in evictions and session.pool_id == pool_id
        ),
        key=lambda session: (session.expires_at, session.token_hash),
    )
    while len(pool_sessions) >= _MAX_REFRESH_SESSIONS_PER_POOL:
        evictions.add(pool_sessions.pop(0).token_hash)

    if len(sessions) - len(evictions) >= _MAX_REFRESH_SESSIONS_PER_STORE:
        return False
    for token_hash in evictions:
        sessions.pop(token_hash, None)
    return True


def _refresh_session_uses_oauth_scopes(session: RefreshSession) -> bool:
    return session.scopes != ["aws.cognito.signin.user.admin"]


def _validate_refresh_device(
    pool: UserPool, user: CognitoUser, session: RefreshSession, supplied: Any
) -> str | None:
    if not pool.device_tracking_enabled:
        if supplied is not None:
            _device_key(supplied)
        return None
    device_key = _optional_auth_device_key(supplied)
    device = user.devices.get(device_key) if device_key is not None else None
    if (
        device_key is None
        or session.device_key is None
        or not hmac.compare_digest(device_key, session.device_key)
        or device is None
    ):
        _error("NotAuthorizedException", "Invalid refresh token device")
    now = _now()
    device.last_authenticated_at = now
    device.updated_at = user.updated_at = pool.updated_at = now
    return device_key


def _prune_auth_challenge_sessions(store: CognitoIdpStore, now: datetime) -> None:
    collections = (
        store.srp_sessions,
        store.new_password_sessions,
        store.mfa_sessions,
        store.device_srp_sessions,
    )
    for sessions in collections:
        for token_hash, session in list(sessions.items()):
            if session.expires_at <= now:
                sessions.pop(token_hash, None)
    while sum(len(sessions) for sessions in collections) >= max(1, _MAX_AUTH_CHALLENGE_SESSIONS):
        collection = min(
            collections,
            key=lambda sessions: min(
                (
                    (session.created_at, session.expires_at, session.token_hash)
                    for session in sessions.values()
                ),
                default=(datetime.max.replace(tzinfo=UTC), datetime.max.replace(tzinfo=UTC), ""),
            ),
        )
        oldest = min(
            collection.values(),
            key=lambda session: (session.created_at, session.expires_at, session.token_hash),
        )
        collection.pop(oldest.token_hash, None)


def _consume_auth_session(
    store: CognitoIdpStore, collection_name: str, raw_session: Any
) -> SrpSession | NewPasswordSession | MfaSession | None:
    if not isinstance(raw_session, str) or not 1 <= len(raw_session) <= 1024:
        return None
    with cognito_idp_stores.lock:
        collection = getattr(store, collection_name)
        return collection.pop(_token_hash(raw_session), None)


def _consume_bound_mfa_session(
    store: CognitoIdpStore,
    raw_session: Any,
    *,
    kind: str,
    pool_id: str,
    client_id: str,
    username: str,
    device_key: str,
) -> MfaSession:
    if not isinstance(raw_session, str) or not 1 <= len(raw_session) <= 1024:
        _error("NotAuthorizedException", "Invalid authentication session")
    with cognito_idp_stores.lock:
        token_hash = _token_hash(raw_session)
        session = store.mfa_sessions.get(token_hash)
        if session is None:
            _error("NotAuthorizedException", "Invalid authentication session")
        if session.expires_at <= _now():
            store.mfa_sessions.pop(token_hash, None)
            _error("NotAuthorizedException", "Invalid authentication session")
        bindings = (
            (session.kind, kind),
            (session.pool_id, pool_id),
            (session.client_id, client_id),
            (session.username, username),
            (session.device_key, device_key),
        )
        if any(
            not isinstance(expected, str)
            or not hmac.compare_digest(expected.encode(), supplied.encode())
            for expected, supplied in bindings
        ):
            _error("NotAuthorizedException", "Invalid authentication session")
        store.mfa_sessions.pop(token_hash, None)
        return session


def _new_device_metadata(
    store: CognitoIdpStore, pool: UserPool, client: UserPoolClient, user: CognitoUser
) -> dict[str, str]:
    now = _now()
    with cognito_idp_stores.lock:
        for token_hash, pending in list(store.pending_devices.items()):
            if pending.expires_at <= now:
                store.pending_devices.pop(token_hash, None)
        matching = sorted(
            (
                pending
                for pending in store.pending_devices.values()
                if pending.pool_id == pool.pool_id and pending.username == user.username
            ),
            key=lambda pending: (pending.created_at, pending.token_hash),
        )
        while len(matching) >= max(1, _MAX_PENDING_DEVICES_PER_USER):
            store.pending_devices.pop(matching.pop(0).token_hash, None)
        while len(store.pending_devices) >= max(1, _MAX_PENDING_DEVICES_PER_STORE):
            oldest = min(
                store.pending_devices.values(),
                key=lambda pending: (pending.created_at, pending.token_hash),
            )
            store.pending_devices.pop(oldest.token_hash, None)
        region = pool.pool_id.split("_", 1)[0]
        device_key = f"{region}_{uuid.uuid4()}"
        token_hash = _token_hash(device_key)
        device_group_key = secrets.token_urlsafe(16).rstrip("=")
        store.pending_devices[token_hash] = PendingDevice(
            token_hash=token_hash,
            pool_id=pool.pool_id,
            client_id=client.client_id,
            username=user.username,
            device_group_key=device_group_key,
            created_at=now,
            expires_at=now + _PENDING_DEVICE_TTL,
        )
    return {"DeviceGroupKey": device_group_key, "DeviceKey": device_key}


def _remove_auth_challenge_state(
    store: CognitoIdpStore, *, pool_id: str | None = None, client_id: str | None = None
) -> None:
    for collection_name in (
        "srp_sessions",
        "new_password_sessions",
        "mfa_sessions",
        "device_srp_sessions",
        "web_authn_challenges",
    ):
        collection = getattr(store, collection_name)
        setattr(
            store,
            collection_name,
            {
                key: session
                for key, session in collection.items()
                if not (
                    (pool_id is not None and session.pool_id == pool_id)
                    or (client_id is not None and session.client_id == client_id)
                )
            },
        )
    store.pending_devices = {
        key: pending
        for key, pending in store.pending_devices.items()
        if not (
            (pool_id is not None and pending.pool_id == pool_id)
            or (client_id is not None and pending.client_id == client_id)
        )
    }
    if pool_id is not None:
        CustomAuthManager(
            store.custom_auth, lambda _: b"cleanup-only-custom-auth-key" * 2
        ).cleanup_pool(pool_id)


def _is_custom_srp_session(store: CognitoIdpStore, raw_session: Any) -> bool:
    if not isinstance(raw_session, str) or not 20 <= len(raw_session) <= 2048:
        return False
    with cognito_idp_stores.lock:
        session = store.srp_sessions.get(_token_hash(raw_session))
        return session is not None and session.custom_auth


def _remove_user_sessions(store: CognitoIdpStore, pool_id: str, username: str) -> None:
    store.refresh_sessions = {
        key: session
        for key, session in store.refresh_sessions.items()
        if not (session.pool_id == pool_id and session.username == username)
    }
    store.authorization_codes = {
        key: code
        for key, code in store.authorization_codes.items()
        if not (code.pool_id == pool_id and code.username == username)
    }
    store.browser_sessions = {
        key: session
        for key, session in store.browser_sessions.items()
        if not (session.pool_id == pool_id and session.username == username)
    }
    for collection_name in (
        "srp_sessions",
        "new_password_sessions",
        "mfa_sessions",
        "device_srp_sessions",
        "web_authn_challenges",
    ):
        collection = getattr(store, collection_name)
        setattr(
            store,
            collection_name,
            {
                key: session
                for key, session in collection.items()
                if not (session.pool_id == pool_id and session.username == username)
            },
        )
    store.pending_devices = {
        key: pending
        for key, pending in store.pending_devices.items()
        if not (pending.pool_id == pool_id and pending.username == username)
    }
    CustomAuthManager(
        store.custom_auth, lambda _: b"cleanup-only-custom-auth-key" * 2
    ).cleanup_user(pool_id, username)


def _remove_device_challenges(
    store: CognitoIdpStore, pool_id: str, username: str, device_key: str
) -> None:
    store.mfa_sessions = {
        key: session
        for key, session in store.mfa_sessions.items()
        if not (
            session.pool_id == pool_id
            and session.username == username
            and session.device_key == device_key
        )
    }
    store.device_srp_sessions = {
        key: session
        for key, session in store.device_srp_sessions.items()
        if not (
            session.pool_id == pool_id
            and session.username == username
            and session.device_key == device_key
        )
    }


def _remove_device_auth_state(
    store: CognitoIdpStore, pool_id: str, username: str, device_key: str
) -> None:
    _remove_device_challenges(store, pool_id, username, device_key)
    store.refresh_sessions = {
        key: session
        for key, session in store.refresh_sessions.items()
        if not (
            session.pool_id == pool_id
            and session.username == username
            and session.device_key == device_key
        )
    }


def _remove_user_state(store: CognitoIdpStore, pool: UserPool, username: str) -> None:
    _remove_user_sessions(store, pool.pool_id, username)
    _mfa_passwordless_engine(store, pool).cleanup(pool_id=pool.pool_id, username=username)
    store.user_codes = {
        key: state
        for key, state in store.user_codes.items()
        if not (state.pool_id == pool.pool_id and state.username == username)
    }
    store.auth_events = {
        key: event
        for key, event in store.auth_events.items()
        if not (event.pool_id == pool.pool_id and event.username == username)
    }
    FriendlyDeviceNames(store.friendly_device_names, lock=cognito_idp_stores.lock).remove_user(
        pool.pool_id, username
    )
    for group in pool.groups.values():
        group.members.discard(username)


def _invalidate_user_tokens(store: CognitoIdpStore, pool: UserPool, user: CognitoUser) -> None:
    user.tokens_valid_after = max(user.tokens_valid_after + 1, int(time.time()) + 1)
    user.updated_at = pool.updated_at = _now()
    _remove_user_sessions(store, pool.pool_id, user.username)


def _remove_oauth_browser_state(store: CognitoIdpStore, pool_id: str) -> None:
    store.browser_transactions = {
        key: transaction
        for key, transaction in store.browser_transactions.items()
        if transaction.pool_id != pool_id
    }
    store.authorization_codes = {
        key: code for key, code in store.authorization_codes.items() if code.pool_id != pool_id
    }
    store.browser_sessions = {
        key: session
        for key, session in store.browser_sessions.items()
        if session.pool_id != pool_id
    }
    store.federation_transactions = {
        key: transaction
        for key, transaction in store.federation_transactions.items()
        if transaction.pool_id != pool_id
    }
    store.saml_replays = {
        key: replay for key, replay in store.saml_replays.items() if replay.pool_id != pool_id
    }


_DUMMY_PASSWORD = PasswordHash(
    algorithm="pbkdf2-sha256",
    iterations=310_000,
    salt="AAAAAAAAAAAAAAAAAAAAAA==",
    digest="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
)


def _dummy_password_check(password: str) -> bool:
    return _DUMMY_PASSWORD.verify(password)


def _pool_summary(pool: UserPool) -> dict[str, Any]:
    return {
        "CreationDate": pool.created_at,
        "Id": pool.pool_id,
        "LambdaConfig": {},
        "LastModifiedDate": pool.updated_at,
        "Name": pool.name,
        "Status": "Enabled",
    }


def _pool_response(pool: UserPool) -> dict[str, Any]:
    admin_create_user_config: dict[str, Any] = {
        "AllowAdminCreateUserOnly": pool.allow_admin_create_user_only
    }
    if pool.invite_message_template is not None:
        admin_create_user_config["InviteMessageTemplate"] = copy.deepcopy(
            pool.invite_message_template
        )
    response = {
        **_pool_summary(pool),
        "AdminCreateUserConfig": admin_create_user_config,
        "Arn": pool.arn,
        "EstimatedNumberOfUsers": len(pool.users),
        "MfaConfiguration": pool.mfa_configuration,
        "UserPoolTags": dict(sorted(pool.tags.items())),
        "UserPoolTier": pool.user_pool_tier,
    }
    configured = pool.pool_configuration.to_response()
    for name in (
        "DeletionProtection",
        "IssuerConfiguration",
        "KeyConfiguration",
        "SmsAuthenticationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
    ):
        if name in configured:
            response[name] = configured[name]
    if pool.device_tracking_enabled:
        response["DeviceConfiguration"] = {
            "ChallengeRequiredOnNewDevice": pool.challenge_required_on_new_device,
            "DeviceOnlyRememberedOnUserPrompt": pool.device_only_remembered_on_user_prompt,
        }
    optional_fields = {
        "AccountRecoverySetting": pool.account_recovery_setting,
        "AliasAttributes": getattr(pool, "alias_attributes", None),
        "AutoVerifiedAttributes": pool.auto_verified_attributes,
        "EmailConfiguration": pool.email_configuration,
        "EmailVerificationMessage": pool.email_verification_message,
        "EmailVerificationSubject": pool.email_verification_subject,
        "LambdaConfig": pool.lambda_config,
        "Policies": pool.password_policy,
        "SchemaAttributes": _schema_response_attributes(pool.schema_attributes),
        "SmsVerificationMessage": pool.sms_verification_message,
        "SmsConfiguration": pool.sms_configuration,
        "UsernameAttributes": pool.username_attributes,
        "VerificationMessageTemplate": pool.verification_message_template,
    }
    response.update(
        {name: copy.deepcopy(value) for name, value in optional_fields.items() if value is not None}
    )
    response["UsernameConfiguration"] = {
        "CaseSensitive": getattr(pool, "username_case_sensitive", True)
    }
    return response


def _schema_response_attributes(
    attributes: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if attributes is None:
        return None
    result = []
    for attribute in attributes:
        item = copy.deepcopy(attribute)
        item["Name"] = _schema_attribute_storage_name(attribute)
        result.append(item)
    return result


def _resource_server_response(pool: UserPool, server: CognitoResourceServer) -> dict[str, Any]:
    return {
        "Identifier": server.identifier,
        "Name": server.name,
        "Scopes": [
            {"ScopeDescription": description, "ScopeName": scope_name}
            for scope_name, description in server.scopes.items()
        ],
        "UserPoolId": pool.pool_id,
    }


def _user_device(user: CognitoUser, value: Any) -> CognitoDevice:
    device = user.devices.get(_device_key(value))
    if device is None:
        _error("ResourceNotFoundException", "Device does not exist")
    return device


def _device_response(device: CognitoDevice) -> dict[str, Any]:
    response: dict[str, Any] = {
        "DeviceAttributes": [],
        "DeviceCreateDate": device.created_at,
        "DeviceKey": device.device_key,
        "DeviceLastAuthenticatedDate": device.last_authenticated_at,
        "DeviceLastModifiedDate": device.updated_at,
    }
    if device.name is not None:
        response["DeviceAttributes"] = [{"Name": "device_name", "Value": device.name}]
    return response


def _list_devices_response(
    pool: UserPool,
    user: CognitoUser,
    raw_limit: Any,
    raw_token: Any,
    kind: str,
) -> ServiceResponse:
    limit = _list_limit(raw_limit)
    after = _decode_bound_page_token(pool, raw_token, kind)
    devices = sorted(user.devices.values(), key=lambda device: device.device_key)
    page, next_after = _page_after(devices, limit, after, lambda device: device.device_key)
    response: ServiceResponse = {"Devices": [_device_response(device) for device in page]}
    if next_after is not None:
        response["PaginationToken"] = _encode_bound_page_token(pool, kind, next_after)
    return response


def _update_device_status(user: CognitoUser, request: ServiceRequest) -> None:
    device = _user_device(user, request.get("DeviceKey"))
    status = request.get("DeviceRememberedStatus")
    if status not in {"remembered", "not_remembered"}:
        _error("InvalidParameterException", "Invalid DeviceRememberedStatus")
    device.remembered_status = status
    device.updated_at = user.updated_at = _now()


def _client_response(
    pool: UserPool,
    client: UserPoolClient,
    *,
    creation_secret: str | None = None,
) -> dict[str, Any]:
    response = {
        "AccessTokenValidity": client.access_token_validity,
        "AllowedOAuthFlows": list(client.allowed_oauth_flows),
        "AllowedOAuthFlowsUserPoolClient": client.allowed_oauth_flows_user_pool_client,
        "AllowedOAuthScopes": list(client.allowed_oauth_scopes),
        "AuthSessionValidity": getattr(client, "auth_session_validity", 3),
        "CallbackURLs": list(client.callback_urls),
        "ClientId": client.client_id,
        "ClientName": client.name,
        "CreationDate": client.created_at,
        "EnablePropagateAdditionalUserContextData": getattr(
            client, "enable_propagate_additional_user_context_data", False
        ),
        "EnableTokenRevocation": client.enable_token_revocation,
        "ExplicitAuthFlows": list(client.explicit_auth_flows),
        "IdTokenValidity": client.id_token_validity,
        "LastModifiedDate": client.updated_at,
        "LogoutURLs": list(client.logout_urls),
        "PreventUserExistenceErrors": client.prevent_user_existence_errors,
        "RefreshTokenValidity": client.refresh_token_validity,
        "RefreshTokenRotation": {
            "Feature": "ENABLED" if client.refresh_token_rotation_enabled else "DISABLED",
            "RetryGracePeriodSeconds": client.refresh_token_rotation_grace_seconds,
        },
        "SupportedIdentityProviders": list(client.supported_identity_providers),
        "TokenValidityUnits": {
            "AccessToken": client.access_token_validity_unit,
            "IdToken": client.id_token_validity_unit,
            "RefreshToken": client.refresh_token_validity_unit,
        },
        "UserPoolId": pool.pool_id,
    }
    if client.default_redirect_uri is not None:
        response["DefaultRedirectURI"] = client.default_redirect_uri
    if analytics := getattr(client, "analytics_configuration", None):
        response["AnalyticsConfiguration"] = analytics.to_api()
    if client.read_attributes is not None:
        response["ReadAttributes"] = list(client.read_attributes)
    if client.write_attributes is not None:
        response["WriteAttributes"] = list(client.write_attributes)
    if creation_secret is not None:
        response["ClientSecret"] = creation_secret
    return response


def _primary_client_secret_id(client: UserPoolClient) -> str:
    return f"primary-{hashlib.sha256(client.client_id.encode()).hexdigest()[:24]}"


def _client_has_secret(client: UserPoolClient) -> bool:
    return bool(
        client.secret
        or client.primary_secret is not None
        or getattr(client, "additional_secrets", {})
    )


def _client_secret_descriptors(client: UserPoolClient) -> list[dict[str, Any]]:
    descriptors = []
    primary = client.primary_secret
    if primary is not None:
        descriptors.append(
            {
                "ClientSecretCreateDate": primary.created_at,
                "ClientSecretId": primary.secret_id,
            }
        )
    elif client.secret is not None:
        descriptors.append(
            {
                "ClientSecretCreateDate": client.created_at,
                "ClientSecretId": _primary_client_secret_id(client),
            }
        )
    descriptors.extend(
        {
            "ClientSecretCreateDate": secret.created_at,
            "ClientSecretId": secret.secret_id,
        }
        for secret in client.additional_secrets.values()
    )
    return sorted(descriptors, key=lambda item: item["ClientSecretId"])


def _domain_response(domain: UserPoolDomain) -> dict[str, Any]:
    return {
        "AWSAccountId": domain.account_id,
        "CloudFrontDistribution": domain.local_hostname,
        "Domain": domain.domain,
        "ManagedLoginVersion": domain.managed_login_version,
        "Status": "ACTIVE",
        "UserPoolId": domain.user_pool_id,
    }


def _group_response(group: CognitoGroup) -> dict[str, Any]:
    response: dict[str, Any] = {
        "CreationDate": group.created_at,
        "GroupName": group.name,
        "LastModifiedDate": group.updated_at,
    }
    if group.description is not None:
        response["Description"] = group.description
    if group.role_arn is not None:
        response["RoleArn"] = group.role_arn
    if group.precedence is not None:
        response["Precedence"] = group.precedence
    return response


def _group_token_claims(
    pool: UserPool, user: CognitoUser, group_names: list[str] | None = None
) -> dict[str, Any]:
    selected = None if group_names is None else set(group_names)
    groups = sorted(
        (
            group
            for group in pool.groups.values()
            if user.username in group.members and (selected is None or group.name in selected)
        ),
        key=lambda group: (
            group.precedence is None,
            group.precedence if group.precedence is not None else 0,
            group.name,
        ),
    )
    if not groups:
        return {}
    claims: dict[str, Any] = {"cognito:groups": [group.name for group in groups]}
    roles = [group.role_arn for group in groups if group.role_arn is not None]
    if roles:
        claims["cognito:roles"] = roles
    ranked = [
        group for group in groups if group.role_arn is not None and group.precedence is not None
    ]
    if ranked:
        best_precedence = ranked[0].precedence
        best_roles = {group.role_arn for group in ranked if group.precedence == best_precedence}
        if len(best_roles) == 1:
            claims["cognito:preferred_role"] = next(iter(best_roles))
    return claims


def _trigger_user_attributes(user: CognitoUser) -> dict[str, str]:
    return {
        "cognito:user_status": user.status,
        "cognito:username": user.username,
        "sub": user.sub,
        **user.attributes,
    }


def _synthetic_custom_auth_attributes(pool: UserPool, username: str) -> dict[str, str]:
    digest = hmac.new(
        pool.id_signing_private_key_pem,
        b"custom-auth-synthetic-user\x00" + username.encode(),
        hashlib.sha256,
    ).digest()
    synthetic_sub = str(uuid.UUID(bytes=digest[:16]))
    return {
        "cognito:user_status": "CONFIRMED",
        "cognito:username": username,
        "sub": synthetic_sub,
    }


class _ProviderLambdaTriggerExecutor:
    def __init__(self, context: RequestContext, pool: UserPool):
        self.context = context
        self.pool = pool

    def invoke(
        self,
        function_arn: str,
        identity: TriggerIdentity,
        event: dict[str, Any],
        *,
        allow_none: bool = False,
    ) -> dict[str, Any] | None:
        if identity.pool_id != self.pool.pool_id or identity.pool_arn != self.pool.arn:
            _error("InvalidParameterException", "Lambda trigger identity changed")
        return _invoke_lambda_trigger(
            self.context,
            self.pool,
            function_arn,
            event,
            allow_none=allow_none,
        )


def _trigger_identity(
    context: RequestContext,
    pool: UserPool,
    client: UserPoolClient,
    username: str,
) -> TriggerIdentity:
    try:
        return TriggerIdentity(
            partition=context.partition,
            account_id=context.account_id,
            region=context.region,
            pool_id=pool.pool_id,
            client_id=client.client_id,
            username=username,
        )
    except LambdaTriggerError as error:
        _error(error.code, str(error))


def _lambda_trigger_configuration(
    context: RequestContext,
    pool: UserPool,
    client: UserPoolClient,
    username: str,
):
    value = pool.lambda_config
    if not value:
        return None
    try:
        return parse_lambda_configuration(
            value,
            identity=_trigger_identity(context, pool, client, username),
        )
    except LambdaTriggerError as error:
        _error(error.code, str(error))


def _custom_auth_trigger_invoker(
    context: RequestContext, pool: UserPool
) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
    def invoke(trigger: str, event: dict[str, Any]) -> dict[str, Any]:
        function_arn = (pool.lambda_config or {}).get(trigger)
        if function_arn is None:
            _error(
                "InvalidParameterException",
                f"LambdaConfig {trigger} is required for CUSTOM_AUTH",
            )
        return _invoke_lambda_trigger(context, pool, function_arn, event)

    return invoke


def _invoke_lambda_trigger(
    context: RequestContext,
    pool: UserPool,
    function_arn: str,
    event: dict[str, Any],
    *,
    allow_none: bool = False,
) -> dict[str, Any] | None:
    try:
        client = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region
        ).lambda_.request_metadata(source_arn=pool.arn, service_principal="cognito-idp")
        result = client.invoke(
            FunctionName=function_arn,
            InvocationType="RequestResponse",
            Payload=json.dumps(event, separators=(",", ":")).encode(),
        )
        payload = result.get("Payload")
        if hasattr(payload, "read"):
            payload = payload.read()
        if isinstance(payload, bytes):
            if len(payload) > 1_000_000:
                raise ValueError("oversized response")
            payload = payload.decode("utf-8")
        response = json.loads(payload) if isinstance(payload, str) else payload
        status = result.get("StatusCode", 200)
        if result.get("FunctionError") or not isinstance(status, int) or status >= 400:
            raise ValueError("lambda invocation failed")
        if response is None and allow_none:
            return None
        if not isinstance(response, dict):
            raise ValueError("invalid trigger response")
        return response
    except CommonServiceException:
        raise
    except Exception:
        _error("UnexpectedLambdaException", "Lambda trigger invocation failed")


def _invoke_post_confirmation(
    context: RequestContext,
    pool: UserPool,
    client: UserPoolClient,
    user: CognitoUser,
    trigger_source: str,
    *,
    client_metadata: dict[str, str] | None = None,
) -> None:
    function_arn = (pool.lambda_config or {}).get("PostConfirmation")
    if function_arn is None:
        return
    event = {
        "callerContext": {"awsSdkVersion": "localstack", "clientId": client.client_id},
        "region": context.region,
        "request": {
            "clientMetadata": dict(client_metadata or {}),
            "userAttributes": _trigger_user_attributes(user),
        },
        "response": {},
        "triggerSource": trigger_source,
        "userName": user.username,
        "userPoolId": pool.pool_id,
        "version": "1",
    }
    _invoke_lambda_trigger(context, pool, function_arn, event)


def _invoke_custom_message_templates(
    context: RequestContext,
    pool: UserPool,
    client: UserPoolClient,
    user: CognitoUser,
    trigger_source: str,
    client_metadata: dict[str, str],
    templates: NotificationTemplates,
) -> NotificationTemplates:
    configuration = _lambda_trigger_configuration(context, pool, client, user.username)
    function_arn = configuration.lambda_arn("CustomMessage") if configuration else None
    if function_arn is None:
        return templates
    sending_account = (pool.email_configuration or {}).get("EmailSendingAccount", "COGNITO_DEFAULT")
    try:
        result = invoke_custom_message(
            _ProviderLambdaTriggerExecutor(context, pool),
            function_arn=function_arn,
            identity=_trigger_identity(context, pool, client, user.username),
            trigger_source=trigger_source,
            user_attributes=_trigger_user_attributes(user),
            code_parameter="{####}",
            username_parameter=(
                "{username}" if trigger_source == "CustomMessage_AdminCreateUser" else None
            ),
            client_metadata=client_metadata,
            email_sending_account=sending_account,
        )
    except LambdaTriggerError as error:
        _error(error.code, str(error))
    return dataclasses.replace(
        templates,
        verification_email_message=(result.email_message or templates.verification_email_message),
        verification_email_subject=(result.email_subject or templates.verification_email_subject),
        verification_sms_message=(result.sms_message or templates.verification_sms_message),
    )


def _invoke_pre_sign_up_trigger(
    context: RequestContext,
    pool: UserPool,
    *,
    client_id: str,
    username: str,
    trigger_source: str,
    user_attributes: dict[str, str],
    validation_data: dict[str, str],
    client_metadata: dict[str, str],
):
    try:
        return invoke_pre_sign_up(
            pool.pool_configuration,
            lambda arn, event: _invoke_lambda_trigger(context, pool, arn, event),
            identity=PoolIdentity(
                partition=context.partition,
                region=context.region,
                account_id=context.account_id,
            ),
            pool_id=pool.pool_id,
            client_id=client_id,
            username=username,
            trigger_source=trigger_source,
            user_attributes=user_attributes,
            validation_data=validation_data,
            client_metadata=client_metadata,
        )
    except PoolConfigurationError as error:
        _error(error.code, str(error))


def _pre_token_generation_overrides(
    context: RequestContext,
    pool: UserPool,
    client: UserPoolClient,
    user: CognitoUser,
    token_attributes: dict[str, str],
    group_claims: dict[str, Any],
    *,
    client_metadata: dict[str, str] | None = None,
    trigger_source: str = "TokenGeneration_Authentication",
) -> tuple[dict[str, str], dict[str, Any]]:
    function_arn = (pool.lambda_config or {}).get("PreTokenGeneration")
    if function_arn is None:
        return token_attributes, group_claims
    event = {
        "callerContext": {"awsSdkVersion": "localstack", "clientId": client.client_id},
        "region": context.region,
        "request": {
            "clientMetadata": dict(client_metadata or {}),
            "groupConfiguration": {
                "groupsToOverride": list(group_claims.get("cognito:groups", [])),
                "iamRolesToOverride": list(group_claims.get("cognito:roles", [])),
                "preferredRole": group_claims.get("cognito:preferred_role"),
            },
            "userAttributes": _trigger_user_attributes(user),
        },
        "response": {},
        "triggerSource": trigger_source,
        "userName": user.username,
        "userPoolId": pool.pool_id,
        "version": "1",
    }
    returned = _invoke_lambda_trigger(context, pool, function_arn, event)
    response = returned.get("response", {})
    details = response.get("claimsOverrideDetails", {}) if isinstance(response, dict) else None
    if not isinstance(details, dict):
        _error("InvalidLambdaResponseException", "Invalid pre-token trigger response")
    attributes = dict(token_attributes)
    additions = details.get("claimsToAddOrOverride", {})
    suppressions = details.get("claimsToSuppress", [])
    if not isinstance(additions, dict) or not isinstance(suppressions, list):
        _error("InvalidLambdaResponseException", "Invalid pre-token claim overrides")
    for name, value in additions.items():
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not 1 <= len(name) <= 128
            or len(value) > 2048
            or name in _RESERVED_TOKEN_CLAIMS
            or name.startswith("cognito:")
        ):
            _error("InvalidLambdaResponseException", "Invalid pre-token claim override")
        attributes[name] = value
    for name in suppressions:
        if (
            not isinstance(name, str)
            or name in _RESERVED_TOKEN_CLAIMS
            or name.startswith("cognito:")
        ):
            _error("InvalidLambdaResponseException", "Invalid pre-token claim suppression")
        attributes.pop(name, None)
    group_override = details.get("groupOverrideDetails")
    if group_override is not None:
        if not isinstance(group_override, dict):
            _error("InvalidLambdaResponseException", "Invalid group override")
        groups = group_override.get("groupsToOverride")
        if groups is not None:
            memberships = {
                group.name for group in pool.groups.values() if user.username in group.members
            }
            if (
                not isinstance(groups, list)
                or len(groups) > _MAX_GROUP_MEMBERSHIPS_PER_USER
                or not all(isinstance(name, str) for name in groups)
                or len(set(groups)) != len(groups)
                or not set(groups) <= memberships
            ):
                _error("InvalidLambdaResponseException", "Invalid group override")
            group_claims = _group_token_claims(pool, user, groups)
    return attributes, group_claims


def _admin_user_response(user: CognitoUser) -> dict[str, Any]:
    response = _user_response(user)
    result = {
        "Enabled": response["Enabled"],
        "UserAttributes": response["Attributes"],
        "UserCreateDate": response["UserCreateDate"],
        "UserLastModifiedDate": response["UserLastModifiedDate"],
        "Username": response["Username"],
        "UserStatus": response["UserStatus"],
    }
    if user.software_token_mfa_enabled:
        result.setdefault("UserMFASettingList", []).append("SOFTWARE_TOKEN_MFA")
    if getattr(user, "email_mfa_enabled", False):
        result.setdefault("UserMFASettingList", []).append("EMAIL_OTP")
    if getattr(user, "sms_mfa_enabled", False):
        result.setdefault("UserMFASettingList", []).append("SMS_MFA")
    preferred = next(
        (
            name
            for name, enabled in (
                ("SOFTWARE_TOKEN_MFA", user.software_token_mfa_preferred),
                ("EMAIL_OTP", getattr(user, "email_mfa_preferred", False)),
                ("SMS_MFA", getattr(user, "sms_mfa_preferred", False)),
            )
            if enabled
        ),
        None,
    )
    if preferred is not None:
        result["PreferredMfaSetting"] = preferred
    return result


def _auth_factors_response(pool: UserPool, user: CognitoUser) -> ServiceResponse:
    configured = {"PASSWORD"}
    allowed = _allowed_first_auth_factors(pool)
    if "EMAIL_OTP" in allowed and "email" in user.attributes:
        configured.add("EMAIL_OTP")
    if "SMS_OTP" in allowed and "phone_number" in user.attributes:
        configured.add("SMS_OTP")
    if pool.web_authn_configuration is not None and any(
        credential.relying_party_id == pool.web_authn_configuration["RelyingPartyId"]
        for credential in user.web_authn_credentials.values()
    ):
        configured.add("WEB_AUTHN")
    enabled_mfa = set()
    preferred_mfa = None
    if user.software_token_mfa_enabled:
        configured.add("SOFTWARE_TOKEN")
        enabled_mfa.add("SOFTWARE_TOKEN_MFA")
    if getattr(user, "email_mfa_enabled", False):
        enabled_mfa.add("EMAIL_OTP")
    if getattr(user, "sms_mfa_enabled", False):
        enabled_mfa.add("SMS_MFA")
    if user.software_token_mfa_preferred:
        preferred_mfa = "SOFTWARE_TOKEN_MFA"
    elif getattr(user, "email_mfa_preferred", False):
        preferred_mfa = "EMAIL_OTP"
    elif getattr(user, "sms_mfa_preferred", False):
        preferred_mfa = "SMS_MFA"
    try:
        return admin_auth_factors_response(
            user.username,
            configured_factors=configured,
            enabled_mfa_settings=enabled_mfa,
            preferred_mfa_setting=preferred_mfa,
        )
    except AuthFactorsError as error:
        _error(error.code, str(error))


def _self_user_response(
    user: CognitoUser, readable_attributes: dict[str, str] | None = None
) -> dict[str, Any]:
    admin = _admin_user_response(user)
    if readable_attributes is not None:
        admin["UserAttributes"] = [{"Name": "sub", "Value": user.sub}]
        admin["UserAttributes"].extend(
            {"Name": name, "Value": value}
            for name, value in sorted(readable_attributes.items())
            if name != "sub"
        )
    result: dict[str, Any] = {
        "UserAttributes": admin["UserAttributes"],
        "Username": admin["Username"],
    }
    if "UserMFASettingList" in admin:
        result["UserMFASettingList"] = admin["UserMFASettingList"]
    if "PreferredMfaSetting" in admin:
        result["PreferredMfaSetting"] = admin["PreferredMfaSetting"]
    return result


def _delivery_details(user: CognitoUser, attribute_name: str | None = None) -> dict[str, str]:
    if attribute_name is None:
        if "email" in user.attributes:
            attribute_name = "email"
        elif "phone_number" in user.attributes:
            attribute_name = "phone_number"
        else:
            _error(
                "InvalidParameterException",
                "A verified delivery attribute is required",
            )
    value = user.attributes.get(attribute_name)
    if not isinstance(value, str) or not value:
        _error("InvalidParameterException", f"User has no {attribute_name} attribute")
    if attribute_name == "email":
        local, separator, domain = value.partition("@")
        destination = f"{local[:1]}***@{domain}" if separator else "***@***.com"
        medium = "EMAIL"
    else:
        destination = f"***{value[-4:]}"
        medium = "SMS"
    return {
        "AttributeName": attribute_name,
        "DeliveryMedium": medium,
        "Destination": destination,
    }


def _delivery_details_for_value(attribute_name: str, value: Any) -> dict[str, str]:
    if not isinstance(value, str) or not value:
        _error("InvalidParameterException", f"User has no {attribute_name} attribute")
    if attribute_name == "email":
        local, separator, domain = value.partition("@")
        destination = f"{local[:1]}***@{domain}" if separator else "***@***.com"
        medium = "EMAIL"
    elif attribute_name == "phone_number":
        destination = f"***{value[-4:]}"
        medium = "SMS"
    else:
        _error("InvalidParameterException", "Invalid verification attribute")
    return {
        "AttributeName": attribute_name,
        "DeliveryMedium": medium,
        "Destination": destination,
    }


def _notification_target_for_value(attribute_name: str, value: Any) -> tuple[str, str, str]:
    details = _delivery_details_for_value(attribute_name, value)
    return attribute_name, details["DeliveryMedium"], value


def _notification_target(
    user: CognitoUser, attribute_name: str | None = None
) -> tuple[str, str, str]:
    details = _delivery_details(user, attribute_name)
    name = details["AttributeName"]
    return name, details["DeliveryMedium"], user.attributes[name]


def _notification_configuration(context: RequestContext, pool: UserPool) -> Any:
    try:
        return validate_notification_configuration(
            copy.deepcopy(pool.email_configuration),
            copy.deepcopy(pool.sms_configuration),
            context,
        )
    except NotificationConfigurationError as error:
        _error(getattr(error, "code", "InvalidParameterException"), str(error))


def _revalidate_notification_resources(
    context: RequestContext,
    pool_id: str,
    configuration: Any,
    expected_snapshot: str,
) -> None:
    actual_snapshot = validate_local_resources(context, pool_id, configuration)
    if not hmac.compare_digest(actual_snapshot, expected_snapshot):
        raise NotificationConfigurationError(
            "Notification delivery resources changed during delivery"
        )


def _notification_templates(pool: UserPool) -> NotificationTemplates:
    verification = pool.verification_message_template or {}
    invitation = pool.invite_message_template or {}
    return NotificationTemplates(
        verification_email_message=verification.get("EmailMessage")
        or pool.email_verification_message
        or NotificationTemplates.verification_email_message,
        verification_email_subject=verification.get("EmailSubject")
        or pool.email_verification_subject
        or NotificationTemplates.verification_email_subject,
        verification_sms_message=verification.get("SmsMessage")
        or pool.sms_verification_message
        or NotificationTemplates.verification_sms_message,
        invitation_email_message=invitation.get("EmailMessage")
        or NotificationTemplates.invitation_email_message,
        invitation_email_subject=invitation.get("EmailSubject")
        or NotificationTemplates.invitation_email_subject,
        invitation_sms_message=invitation.get("SMSMessage")
        or NotificationTemplates.invitation_sms_message,
    )


def _mfa_otp_sender(
    context: RequestContext,
    pool: UserPool,
    *,
    purpose: Any,
    expected_user: CognitoUser | None,
) -> _MfaOtpDeliveryAdapter:
    sms_configuration = (pool.sms_mfa_configuration or {}).get(
        "SmsConfiguration"
    ) or pool.sms_configuration
    try:
        configuration = validate_notification_configuration(
            copy.deepcopy(pool.email_configuration),
            copy.deepcopy(sms_configuration),
            context,
        )
    except NotificationConfigurationError as error:
        _error(getattr(error, "code", "InvalidParameterException"), str(error))
    templates = _notification_templates(pool)
    if purpose == "EMAIL_MFA" and pool.email_mfa_configuration is not None:
        templates = dataclasses.replace(
            templates,
            verification_email_message=pool.email_mfa_configuration["Message"],
            verification_email_subject=pool.email_mfa_configuration["Subject"],
        )
    elif purpose == "SMS_MFA" and pool.sms_mfa_configuration is not None:
        templates = dataclasses.replace(
            templates,
            verification_sms_message=pool.sms_mfa_configuration["SmsAuthenticationMessage"],
        )
    return _MfaOtpDeliveryAdapter(
        context,
        pool.pool_id,
        configuration,
        templates,
        expected_username=expected_user.username if expected_user is not None else None,
        expected_user_sub=expected_user.sub if expected_user is not None else None,
    )


def _desired_delivery_mediums(value: Any) -> list[str]:
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 2
        or len(value) != len(set(value))
        or not all(isinstance(item, str) for item in value)
        or set(value) - {"EMAIL", "SMS"}
    ):
        _error("InvalidParameterException", "Invalid DesiredDeliveryMediums")
    return list(value)


def _invitation_targets(user: CognitoUser, mediums: list[str]) -> list[tuple[str, str]]:
    attribute = {"EMAIL": "email", "SMS": "phone_number"}
    targets: list[tuple[str, str]] = []
    for medium in mediums:
        destination = user.attributes.get(attribute[medium])
        if not isinstance(destination, str) or not destination:
            _error(
                "InvalidParameterException",
                f"User has no {attribute[medium]} invitation attribute",
            )
        targets.append((medium, destination))
    return targets


def _generic_delivery_details() -> dict[str, str]:
    return {
        "AttributeName": "email",
        "DeliveryMedium": "EMAIL",
        "Destination": "***@***.com",
    }


def _list_users_query_record(user: CognitoUser) -> dict[str, Any]:
    return {
        "Attributes": {**user.attributes, "sub": user.sub},
        "Enabled": user.enabled,
        "Username": user.username,
        "UserStatus": user.status,
    }


def _listed_user_response(user: CognitoUser, attributes_to_get: list[str] | None) -> dict[str, Any]:
    response = _user_response(user)
    if attributes_to_get is not None:
        available = {attribute["Name"]: attribute for attribute in response["Attributes"]}
        missing = set(attributes_to_get) - set(available)
        if missing:
            _error(
                "InvalidParameterException", f"Requested attributes are missing: {sorted(missing)}"
            )
        response["Attributes"] = [available[name] for name in attributes_to_get]
    return response


def _user_response(user: CognitoUser) -> dict[str, Any]:
    attributes = [{"Name": "sub", "Value": user.sub}]
    attributes.extend(
        {"Name": name, "Value": value}
        for name, value in sorted(user.attributes.items())
        if name != "sub"
    )
    return {
        "Attributes": attributes,
        "Enabled": user.enabled,
        "UserCreateDate": user.created_at,
        "UserLastModifiedDate": user.updated_at,
        "Username": user.username,
        "UserStatus": user.status,
    }
