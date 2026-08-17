import base64
import contextlib
import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
import uuid
from contextlib import ExitStack
from datetime import UTC, datetime
from typing import Any

from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.services.cognito_identity.credentials import (
    CredentialIssueError,
    issue_enhanced_flow_credentials,
    revoke_sts_credentials,
)
from localstack.services.cognito_identity.models import (
    CognitoIdentity,
    CognitoIdentityStore,
    CredentialSession,
    IdentityPool,
    PrincipalTagAttributeMap,
    cognito_identity_stores,
    resolve_identity_location,
    resolve_pool_location,
)
from localstack.services.cognito_identity.openid import (
    OpenIdTokenError,
    issue_open_id_token,
    verify_open_id_token,
)
from localstack.services.cognito_identity.tokens import (
    TokenValidationError,
    verify_native_id_token_claims,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.state import StateVisitor

_MAX_PAGE_TOKEN_BYTES = 2_048
_MAX_POOLS_PER_REGION = 1_000
_MAX_IDENTITIES_PER_POOL = 10_000
_MAX_PROVIDER_LIST_ITEMS = 50
_MAX_TAGS = 50
_MAX_LOGINS = 10
_MAX_LOGIN_TOKEN_LENGTH = 50_000
_MAX_CREDENTIAL_SESSIONS_PER_IDENTITY = 64
_MAX_CREDENTIAL_SESSIONS_PER_STORE = 10_000
_MAX_IDENTITIES_BATCH = 60
_MAX_LOGINS_TO_REMOVE = 10
_MAX_LINKED_LOGINS = 20
_DEFAULT_OPEN_ID_TOKEN_SECONDS = 600
_DEFAULT_DEVELOPER_TOKEN_SECONDS = 900
_MAX_OPEN_ID_TOKEN_SECONDS = 86_400
_POOL_NAME_RE = re.compile(r"^[\w\s+=,.@-]+$")
_DEVELOPER_PROVIDER_RE = re.compile(r"^[\w._-]+$")
_LOGIN_PROVIDER_VALUE_RE = re.compile(r"^[\w.;_/-]+$")
_COGNITO_PROVIDER_RE = re.compile(r"^[\w._:/-]+$")
_CLIENT_ID_RE = re.compile(r"^[\w_]+$")
_POOL_ID_RE = re.compile(r"^(?P<region>[\w-]+):(?P<uuid>[0-9a-f-]+)$")
_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>[a-z0-9-]+):iam::(?P<account>\d{12}):"
    r"role/(?P<name>[A-Za-z0-9_+=,.@/-]+)$"
)
_POOL_ARN_RE = re.compile(
    r"^arn:(?P<partition>[a-z0-9-]+):cognito-identity:(?P<region>[a-z0-9-]+):"
    r"(?P<account>\d{12}):identitypool/(?P<pool>[\w-]+:[0-9a-f-]+)$"
)
_POOL_LOCKS_GUARD = threading.RLock()
_POOL_LOCKS: dict[str, tuple[threading.RLock, int]] = {}

_POOL_FIELDS = {
    "AllowClassicFlow",
    "AllowUnauthenticatedIdentities",
    "CognitoIdentityProviders",
    "DeveloperProviderName",
    "IdentityPoolName",
    "IdentityPoolTags",
    "OpenIdConnectProviderARNs",
    "SamlProviderARNs",
    "SupportedLoginProviders",
}


@contextlib.contextmanager
def _pool_guard(pool_id: str):
    with _POOL_LOCKS_GUARD:
        lock, users = _POOL_LOCKS.get(pool_id, (threading.RLock(), 0))
        _POOL_LOCKS[pool_id] = (lock, users + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _POOL_LOCKS_GUARD:
            current_lock, current_users = _POOL_LOCKS[pool_id]
            if current_lock is lock and current_users == 1:
                _POOL_LOCKS.pop(pool_id)
            else:
                _POOL_LOCKS[pool_id] = (current_lock, current_users - 1)


class CognitoIdentityProvider:
    service = "cognito-identity"

    def accept_state_visitor(self, visitor: StateVisitor) -> None:
        visitor.visit(cognito_identity_stores)

    def get_store(self, context: RequestContext) -> CognitoIdentityStore:
        return cognito_identity_stores[context.account_id][context.region]

    @contextlib.contextmanager
    def _locked_owned_pool(self, context: RequestContext, value: Any):
        pool_id = _pool_id(value)
        with _pool_guard(pool_id):
            with cognito_identity_stores.lock:
                pool = self.get_store(context).identity_pools.get(pool_id)
            if pool is None:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            yield pool

    @handler("CreateIdentityPool", expand=False)
    def create_identity_pool(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, _POOL_FIELDS)
        configuration = _pool_configuration(request)
        now = _now()
        with cognito_identity_stores.lock:
            store = self.get_store(context)
            if len(store.identity_pools) >= _MAX_POOLS_PER_REGION:
                _error("LimitExceededException", "Identity pool limit exceeded")
            while True:
                pool_id = f"{context.region}:{uuid.uuid4()}"
                if pool_id not in store.POOL_LOCATIONS:
                    break
            pool = IdentityPool(
                pool_id=pool_id,
                name=configuration.pop("name"),
                account_id=context.account_id,
                region=context.region,
                created_at=now,
                updated_at=now,
                **configuration,
            )
            store.identity_pools[pool_id] = pool
            store.POOL_LOCATIONS[pool_id] = (context.account_id, context.region)
            return _pool_response(pool)

    @handler("DescribeIdentityPool", expand=False)
    def describe_identity_pool(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_owned_pool(context, request.get("IdentityPoolId")) as pool:
            return _pool_response(pool)

    @handler("UpdateIdentityPool", expand=False)
    def update_identity_pool(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, _POOL_FIELDS | {"IdentityPoolId"})
        pool_id = _pool_id(request.get("IdentityPoolId"))
        configuration = _pool_configuration(request)
        with self._locked_owned_pool(context, pool_id) as pool:
            developer_provider_name = configuration["developer_provider_name"]
            if (
                pool.developer_provider_name is not None
                and developer_provider_name is not None
                and developer_provider_name != pool.developer_provider_name
            ):
                _error("InvalidParameterException", "DeveloperProviderName cannot be changed")
            with cognito_identity_stores.lock:
                pool.name = configuration["name"]
                pool.allow_unauthenticated_identities = configuration[
                    "allow_unauthenticated_identities"
                ]
                pool.allow_classic_flow = configuration["allow_classic_flow"]
                pool.supported_login_providers = configuration["supported_login_providers"]
                if "DeveloperProviderName" in request:
                    pool.developer_provider_name = developer_provider_name
                pool.open_id_connect_provider_arns = configuration["open_id_connect_provider_arns"]
                pool.cognito_identity_providers = configuration["cognito_identity_providers"]
                configured_provider_names = {
                    item.get("ProviderName")
                    for item in pool.cognito_identity_providers
                    if isinstance(item.get("ProviderName"), str)
                }
                pool.principal_tag_attribute_maps = {
                    provider_name: mapping
                    for provider_name, mapping in pool.principal_tag_attribute_maps.items()
                    if provider_name in configured_provider_names
                }
                pool.saml_provider_arns = configuration["saml_provider_arns"]
                pool.tags = configuration["tags"]
                pool.updated_at = _now()
                return _pool_response(pool)

    @handler("DeleteIdentityPool", expand=False)
    def delete_identity_pool(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        pool_id = _pool_id(request.get("IdentityPoolId"))
        sessions_to_revoke: list[CredentialSession] = []
        with self._locked_owned_pool(context, pool_id) as pool:
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                identity_ids = set(pool.identity_ids)
                identity_ids.update(
                    identity.identity_id
                    for identity in store.identities.values()
                    if identity.pool_id == pool_id
                )
                for identity_id in identity_ids:
                    sessions_to_revoke.extend(
                        _remove_identity_state_locked(
                            store=store,
                            account_id=context.account_id,
                            region=context.region,
                            pool_id=pool_id,
                            identity_id=identity_id,
                        )
                    )
                for login_key in [key for key in store.login_identities if key[0] == pool_id]:
                    store.login_identities.pop(login_key, None)
                for developer_key in [
                    key for key in store.developer_identities if key[0] == pool_id
                ]:
                    store.developer_identities.pop(developer_key, None)
                for access_key_id, session in list(store.credential_sessions.items()):
                    if session.pool_id != pool_id:
                        continue
                    sessions_to_revoke.append(session)
                    store.credential_sessions.pop(access_key_id, None)
                store.identity_pools.pop(pool_id, None)
                if store.POOL_LOCATIONS.get(pool_id) == (
                    context.account_id,
                    context.region,
                ):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            _remove_cognito_sync_pool_state(context.account_id, context.region, pool_id)
            for session in sessions_to_revoke:
                revoke_sts_credentials(
                    account_id=session.account_id,
                    partition=session.partition,
                    access_key_id=session.access_key_id,
                )
        return {}

    @handler("ListIdentityPools", expand=False)
    def list_identity_pools(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"MaxResults", "NextToken"})
        maximum = request.get("MaxResults")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 60:
            _error("InvalidParameterException", "MaxResults must be between 1 and 60")
        scope = f"pools:{context.account_id}:{context.region}"
        with cognito_identity_stores.lock:
            store = self.get_store(context)
            after = _decode_page_token(store, request.get("NextToken"), scope)
            pools = sorted(store.identity_pools.values(), key=lambda item: item.pool_id)
            page, next_cursor = _page_after(pools, maximum, after, lambda item: item.pool_id)
            response: dict[str, Any] = {
                "IdentityPools": [
                    {"IdentityPoolId": pool.pool_id, "IdentityPoolName": pool.name} for pool in page
                ]
            }
            if next_cursor is not None:
                response["NextToken"] = _encode_page_token(store, scope, next_cursor)
        return response

    @handler("DescribeIdentity", expand=False)
    def describe_identity(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityId"})
        identity_id = _pool_id(request.get("IdentityId"))
        location = _owned_identity_location(context, identity_id)
        _, _, pool_id = location
        with _pool_guard(pool_id):
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                identity = store.identities.get(identity_id)
                if not _identity_matches(
                    store,
                    identity,
                    identity_id=identity_id,
                    pool_id=pool_id,
                    account_id=context.account_id,
                    region=context.region,
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                pool = store.identity_pools[pool_id]
                return _identity_response(identity, pool.developer_provider_name)

    @handler("ListIdentities", expand=False)
    def list_identities(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(
            request, {"HideDisabled", "IdentityPoolId", "MaxResults", "NextToken"}
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        maximum = request.get("MaxResults")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 60:
            _error("InvalidParameterException", "MaxResults must be between 1 and 60")
        hide_disabled = request.get("HideDisabled", False)
        if not isinstance(hide_disabled, bool):
            _error("InvalidParameterException", "HideDisabled must be a boolean")
        with self._locked_owned_pool(context, pool_id) as pool:
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                scope = (
                    f"identities:{context.account_id}:{context.region}:"
                    f"{pool_id}:{int(hide_disabled)}"
                )
                after = _decode_page_token(store, request.get("NextToken"), scope)
                identities = sorted(
                    (
                        identity
                        for identity in store.identities.values()
                        if identity.pool_id == pool.pool_id
                        and identity.identity_id in pool.identity_ids
                        and store.IDENTITY_LOCATIONS.get(identity.identity_id)
                        == (context.account_id, context.region, pool_id)
                        and (not hide_disabled or identity.enabled)
                    ),
                    key=lambda item: item.identity_id,
                )
                page, next_cursor = _page_after(
                    identities, maximum, after, lambda item: item.identity_id
                )
                response: dict[str, Any] = {
                    "IdentityPoolId": pool_id,
                    "Identities": [
                        _identity_response(identity, pool.developer_provider_name)
                        for identity in page
                    ],
                }
                if next_cursor is not None:
                    response["NextToken"] = _encode_page_token(store, scope, next_cursor)
                return response

    @handler("DeleteIdentities", expand=False)
    def delete_identities(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityIdsToDelete"})
        identity_ids = _identity_id_batch(request.get("IdentityIdsToDelete"))
        with cognito_identity_stores.lock:
            locations: dict[str, tuple[str, str, str]] = {}
            for identity_id in identity_ids:
                location = resolve_identity_location(identity_id)
                if location is None or location[:2] != (
                    context.account_id,
                    context.region,
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                locations[identity_id] = location
        sessions_to_revoke: list[CredentialSession] = []
        with ExitStack() as stack:
            for pool_id in sorted({location[2] for location in locations.values()}):
                stack.enter_context(_pool_guard(pool_id))
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                for identity_id, (_, _, pool_id) in locations.items():
                    identity = store.identities.get(identity_id)
                    if not _identity_matches(
                        store,
                        identity,
                        identity_id=identity_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    ):
                        _error(
                            "ResourceNotFoundException",
                            f"Identity {identity_id} does not exist",
                        )
                for identity_id, (_, _, pool_id) in locations.items():
                    sessions_to_revoke.extend(
                        _remove_identity_state_locked(
                            store=store,
                            account_id=context.account_id,
                            region=context.region,
                            pool_id=pool_id,
                            identity_id=identity_id,
                        )
                    )
            for session in sessions_to_revoke:
                revoke_sts_credentials(
                    account_id=session.account_id,
                    partition=session.partition,
                    access_key_id=session.access_key_id,
                )
        return {"UnprocessedIdentityIds": []}

    @handler("GetIdentityPoolRoles", expand=False)
    def get_identity_pool_roles(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId"})
        with self._locked_owned_pool(context, request.get("IdentityPoolId")) as pool:
            return {
                "IdentityPoolId": pool.pool_id,
                "Roles": copy.deepcopy(pool.roles),
                "RoleMappings": copy.deepcopy(pool.role_mappings),
            }

    @handler("SetIdentityPoolRoles", expand=False)
    def set_identity_pool_roles(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId", "RoleMappings", "Roles"})
        roles = _identity_pool_roles(request.get("Roles"), context)
        role_mappings = _identity_pool_role_mappings(request.get("RoleMappings", {}), context)
        with self._locked_owned_pool(context, request.get("IdentityPoolId")) as pool:
            with cognito_identity_stores.lock:
                pool.roles = roles
                pool.role_mappings = role_mappings
                pool.updated_at = _now()
        return {}

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn", "Tags"})
        pool_id = _identity_pool_arn(request.get("ResourceArn"), context)
        if "Tags" not in request or request["Tags"] is None:
            _error("InvalidParameterException", "Tags are required")
        tags = _string_map(
            request.get("Tags"),
            "Tags",
            maximum=_MAX_TAGS,
            key_maximum=128,
            value_maximum=256,
            allow_empty_value=True,
        )
        with self._locked_owned_pool(context, pool_id) as pool:
            with cognito_identity_stores.lock:
                if len(set(pool.tags) | set(tags)) > _MAX_TAGS:
                    _error("LimitExceededException", "Identity pool tag limit exceeded")
                pool.tags.update(tags)
                pool.updated_at = _now()
        return {}

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn", "TagKeys"})
        pool_id = _identity_pool_arn(request.get("ResourceArn"), context)
        tag_keys = _tag_keys(request.get("TagKeys"))
        with self._locked_owned_pool(context, pool_id) as pool:
            with cognito_identity_stores.lock:
                for key in tag_keys:
                    pool.tags.pop(key, None)
                pool.updated_at = _now()
        return {}

    @handler("ListTagsForResource", expand=False)
    def list_tags_for_resource(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"ResourceArn"})
        pool_id = _identity_pool_arn(request.get("ResourceArn"), context)
        with self._locked_owned_pool(context, pool_id) as pool:
            return {"Tags": copy.deepcopy(pool.tags)}

    @handler("GetPrincipalTagAttributeMap", expand=False)
    def get_principal_tag_attribute_map(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityPoolId", "IdentityProviderName"})
        pool_id = _pool_id(request.get("IdentityPoolId"))
        provider_name = _provider_name(request.get("IdentityProviderName"))
        with self._locked_owned_pool(context, pool_id) as pool:
            _require_configured_native_provider(pool, provider_name)
            mapping = pool.principal_tag_attribute_maps.get(
                provider_name, PrincipalTagAttributeMap(use_defaults=True)
            )
            return _principal_tag_map_response(pool_id, provider_name, mapping)

    @handler("SetPrincipalTagAttributeMap", expand=False)
    def set_principal_tag_attribute_map(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"IdentityPoolId", "IdentityProviderName", "PrincipalTags", "UseDefaults"},
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        provider_name = _provider_name(request.get("IdentityProviderName"))
        use_defaults = request.get("UseDefaults", True)
        if not isinstance(use_defaults, bool):
            _error("InvalidParameterException", "UseDefaults must be a boolean")
        if "PrincipalTags" in request and request["PrincipalTags"] is None:
            _error("InvalidParameterException", "Invalid PrincipalTags")
        principal_tags = _string_map(
            request.get("PrincipalTags"),
            "PrincipalTags",
            maximum=50,
            key_maximum=128,
            value_maximum=256,
        )
        if use_defaults == bool(principal_tags):
            _error(
                "InvalidParameterException",
                "UseDefaults requires no PrincipalTags; custom mappings require PrincipalTags",
            )
        mapping = PrincipalTagAttributeMap(
            use_defaults=use_defaults,
            principal_tags=principal_tags,
        )
        with self._locked_owned_pool(context, pool_id) as pool:
            _require_configured_native_provider(pool, provider_name)
            with cognito_identity_stores.lock:
                pool.principal_tag_attribute_maps[provider_name] = mapping
                pool.updated_at = _now()
                return _principal_tag_map_response(pool_id, provider_name, mapping)

    @handler("GetOpenIdToken", expand=False)
    def get_open_id_token(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityId", "Logins"})
        identity_id = _pool_id(request.get("IdentityId"))
        raw_logins = request.get("Logins")
        if raw_logins is not None and not isinstance(raw_logins, dict):
            _error("InvalidParameterException", "Logins must be a map")
        logins = _login_map(raw_logins) if raw_logins else {}
        _, _, pool_id = _owned_identity_location(context, identity_id)
        sessions_to_revoke: list[CredentialSession] = []
        with _pool_guard(pool_id):
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                pool = store.identity_pools.get(pool_id)
                identity = store.identities.get(identity_id)
                if pool is None or not _identity_matches(
                    store,
                    identity,
                    identity_id=identity_id,
                    pool_id=pool_id,
                    account_id=context.account_id,
                    region=context.region,
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                if not pool.allow_classic_flow:
                    _error("NotAuthorizedException", "Basic authentication flow is disabled")
                if not identity.enabled:
                    _error("NotAuthorizedException", "Identity is not active")
                if identity.authenticated and not logins:
                    _error("NotAuthorizedException", "Authenticated identities require Logins")
                configured_providers = copy.deepcopy(pool.cognito_identity_providers)

            verified_logins: dict[str, str] = {}
            if logins:
                with cognito_idp_stores.lock:
                    verified_logins = self._verified_native_logins_locked(
                        owner_account=context.account_id,
                        pool_region=context.region,
                        partition=context.partition,
                        configured_providers=configured_providers,
                        logins=logins,
                    )

            with cognito_identity_stores.lock:
                pool = store.identity_pools.get(pool_id)
                identity = store.identities.get(identity_id)
                if pool is None or not _identity_matches(
                    store,
                    identity,
                    identity_id=identity_id,
                    pool_id=pool_id,
                    account_id=context.account_id,
                    region=context.region,
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                if not identity.enabled or not pool.allow_classic_flow:
                    _error("NotAuthorizedException", "Identity is not active")
                if verified_logins:
                    sessions_to_revoke.extend(
                        _link_or_merge_native_logins_locked(
                            store=store,
                            pool=pool,
                            destination=identity,
                            verified_logins=verified_logins,
                            account_id=context.account_id,
                            region=context.region,
                        )
                    )
                elif identity.authenticated:
                    _error("NotAuthorizedException", "Authenticated identities require Logins")
                elif not pool.allow_unauthenticated_identities:
                    _error(
                        "NotAuthorizedException",
                        "Unauthenticated access is disabled for this identity pool",
                    )
                token = _issue_pool_token_locked(
                    store=store,
                    context=context,
                    pool=pool,
                    identity=identity,
                    duration=_DEFAULT_OPEN_ID_TOKEN_SECONDS,
                )
            _revoke_sessions(sessions_to_revoke)
            return {"IdentityId": identity_id, "Token": token}

    @handler("GetOpenIdTokenForDeveloperIdentity", expand=False)
    def get_open_id_token_for_developer_identity(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {"IdentityId", "IdentityPoolId", "Logins", "PrincipalTags", "TokenDuration"},
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        token_duration = request.get("TokenDuration", _DEFAULT_DEVELOPER_TOKEN_SECONDS)
        if (
            not isinstance(token_duration, int)
            or isinstance(token_duration, bool)
            or not 1 <= token_duration <= _MAX_OPEN_ID_TOKEN_SECONDS
        ):
            _error("InvalidParameterException", "TokenDuration must be between 1 and 86400")
        if "PrincipalTags" in request and request["PrincipalTags"] is None:
            _error("InvalidParameterException", "Invalid PrincipalTags")
        principal_tags = _string_map(
            request.get("PrincipalTags"),
            "PrincipalTags",
            maximum=50,
            key_maximum=128,
            value_maximum=256,
        )
        raw_logins = request.get("Logins")
        if not isinstance(raw_logins, dict) or not raw_logins:
            _error("InvalidParameterException", "Logins must be a non-empty map")
        logins = _login_map(raw_logins)
        requested_identity_id = (
            _pool_id(request["IdentityId"]) if request.get("IdentityId") is not None else None
        )
        sessions_to_revoke: list[CredentialSession] = []

        with self._locked_owned_pool(context, pool_id) as pool:
            developer_provider = _configured_developer_provider(pool)
            developer_identifier, native_logins = _split_developer_logins(
                logins, developer_provider
            )
            configured_providers = copy.deepcopy(pool.cognito_identity_providers)
            verified_logins: dict[str, str] = {}
            if native_logins:
                with cognito_idp_stores.lock:
                    verified_logins = self._verified_native_logins_locked(
                        owner_account=context.account_id,
                        pool_region=context.region,
                        partition=context.partition,
                        configured_providers=configured_providers,
                        logins=native_logins,
                    )

            with cognito_identity_stores.lock:
                store = self.get_store(context)
                pool = store.identity_pools.get(pool_id)
                if pool is None or pool.developer_provider_name != developer_provider:
                    _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
                developer_key = (pool_id, developer_provider, developer_identifier)
                linked_identity_id = store.developer_identities.get(developer_key)
                if requested_identity_id is not None:
                    requested_identity = store.identities.get(requested_identity_id)
                    if not _identity_matches(
                        store,
                        requested_identity,
                        identity_id=requested_identity_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    ):
                        _error(
                            "ResourceNotFoundException",
                            f"Identity {requested_identity_id} does not exist",
                        )
                    if not requested_identity.enabled:
                        _error("NotAuthorizedException", "Identity is not active")
                    if linked_identity_id not in (None, requested_identity_id):
                        _error(
                            "DeveloperUserAlreadyRegisteredException",
                            "Developer user identifier is already registered",
                        )
                    identity = requested_identity
                elif linked_identity_id is not None:
                    identity = store.identities.get(linked_identity_id)
                    if (
                        not _identity_matches(
                            store,
                            identity,
                            identity_id=linked_identity_id,
                            pool_id=pool_id,
                            account_id=context.account_id,
                            region=context.region,
                        )
                        or not identity.enabled
                    ):
                        _error("ResourceConflictException", "Developer identity is not active")
                else:
                    native_identity_ids = sorted(
                        {
                            linked_id
                            for provider_name, subject in verified_logins.items()
                            if (
                                linked_id := store.login_identities.get(
                                    (pool_id, provider_name, subject)
                                )
                            )
                            is not None
                        }
                    )
                    if native_identity_ids:
                        identity = store.identities.get(native_identity_ids[0])
                        if identity is None or not identity.enabled or identity.pool_id != pool_id:
                            _error("ResourceConflictException", "Login identity is not active")
                    else:
                        identity = _create_identity_locked(
                            store=store,
                            pool=pool,
                            account_id=context.account_id,
                            region=context.region,
                            authenticated=True,
                        )

                sessions_to_revoke.extend(
                    _link_or_merge_native_logins_locked(
                        store=store,
                        pool=pool,
                        destination=identity,
                        verified_logins=verified_logins,
                        account_id=context.account_id,
                        region=context.region,
                        reserved_links=int(
                            developer_identifier not in identity.developer_user_identifiers
                        ),
                    )
                )
                if developer_identifier not in identity.developer_user_identifiers:
                    _ensure_link_capacity(identity, 1)
                    identity.developer_user_identifiers.add(developer_identifier)
                    store.developer_identities[developer_key] = identity.identity_id
                identity.authenticated = True
                identity.updated_at = _now()
                token = _issue_pool_token_locked(
                    store=store,
                    context=context,
                    pool=pool,
                    identity=identity,
                    duration=token_duration,
                    principal_tags=principal_tags,
                )
                identity_id = identity.identity_id
            _revoke_sessions(sessions_to_revoke)
            return {"IdentityId": identity_id, "Token": token}

    @handler("LookupDeveloperIdentity", expand=False)
    def lookup_developer_identity(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "DeveloperUserIdentifier",
                "IdentityId",
                "IdentityPoolId",
                "MaxResults",
                "NextToken",
            },
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        identity_id = _pool_id(request["IdentityId"]) if request.get("IdentityId") else None
        developer_identifier = (
            _developer_user_identifier(request["DeveloperUserIdentifier"])
            if request.get("DeveloperUserIdentifier") is not None
            else None
        )
        if identity_id is None and developer_identifier is None:
            _error(
                "InvalidParameterException",
                "IdentityId or DeveloperUserIdentifier is required",
            )
        maximum = request.get("MaxResults", 60)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 60:
            _error("InvalidParameterException", "MaxResults must be between 1 and 60")

        with self._locked_owned_pool(context, pool_id) as pool:
            developer_provider = _configured_developer_provider(pool)
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                if developer_identifier is not None:
                    linked_identity_id = store.developer_identities.get(
                        (pool_id, developer_provider, developer_identifier)
                    )
                    if identity_id is not None and linked_identity_id != identity_id:
                        _error(
                            "ResourceConflictException",
                            "Developer user identifier does not match IdentityId",
                        )
                    if linked_identity_id is None:
                        _error("ResourceNotFoundException", "Developer identity does not exist")
                    identity_id = linked_identity_id
                identity = store.identities.get(identity_id)
                if (
                    not _identity_matches(
                        store,
                        identity,
                        identity_id=identity_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    )
                    or not identity.enabled
                ):
                    _error("ResourceNotFoundException", "Developer identity does not exist")
                identifiers = (
                    [developer_identifier]
                    if developer_identifier is not None
                    else sorted(identity.developer_user_identifiers)
                )
                if not identifiers:
                    _error("ResourceNotFoundException", "Developer identity does not exist")
                scope = (
                    f"developer-identities:{context.account_id}:{context.region}:"
                    f"{pool_id}:{identity_id}"
                )
                after = _decode_page_token(
                    store,
                    request.get("NextToken"),
                    scope,
                    developer_identifier=True,
                )
                page, next_cursor = _page_after(identifiers, maximum, after, lambda item: item)
                response: dict[str, Any] = {
                    "IdentityId": identity_id,
                    "DeveloperUserIdentifierList": page,
                }
                if next_cursor is not None:
                    response["NextToken"] = _encode_page_token(store, scope, next_cursor)
                return response

    @handler("MergeDeveloperIdentities", expand=False)
    def merge_developer_identities(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "DestinationUserIdentifier",
                "DeveloperProviderName",
                "IdentityPoolId",
                "SourceUserIdentifier",
            },
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        provider_name = _developer_provider_name(request.get("DeveloperProviderName"))
        source_identifier = _developer_user_identifier(request.get("SourceUserIdentifier"))
        destination_identifier = _developer_user_identifier(
            request.get("DestinationUserIdentifier")
        )
        if source_identifier == destination_identifier:
            _error("InvalidParameterException", "Source and destination must be different")
        sessions_to_revoke: list[CredentialSession] = []
        with self._locked_owned_pool(context, pool_id) as pool:
            if _configured_developer_provider(pool) != provider_name:
                _error("InvalidParameterException", "DeveloperProviderName does not match")
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                source_id = store.developer_identities.get(
                    (pool_id, provider_name, source_identifier)
                )
                destination_id = store.developer_identities.get(
                    (pool_id, provider_name, destination_identifier)
                )
                if source_id is None or destination_id is None:
                    _error("ResourceNotFoundException", "Developer identity does not exist")
                if source_id == destination_id:
                    _error("ResourceConflictException", "Developer identities are already merged")
                source = store.identities.get(source_id)
                destination = store.identities.get(destination_id)
                if (
                    not _identity_matches(
                        store,
                        source,
                        identity_id=source_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    )
                    or not _identity_matches(
                        store,
                        destination,
                        identity_id=destination_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    )
                    or not source.enabled
                    or not destination.enabled
                ):
                    _error("ResourceNotFoundException", "Developer identity does not exist")
                sessions_to_revoke.extend(
                    _merge_identity_locked(
                        store=store,
                        source=source,
                        destination=destination,
                        account_id=context.account_id,
                        region=context.region,
                    )
                )
            _revoke_sessions(sessions_to_revoke)
            return {"IdentityId": destination_id}

    @handler("UnlinkDeveloperIdentity", expand=False)
    def unlink_developer_identity(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(
            request,
            {
                "DeveloperProviderName",
                "DeveloperUserIdentifier",
                "IdentityId",
                "IdentityPoolId",
            },
        )
        pool_id = _pool_id(request.get("IdentityPoolId"))
        identity_id = _pool_id(request.get("IdentityId"))
        provider_name = _developer_provider_name(request.get("DeveloperProviderName"))
        developer_identifier = _developer_user_identifier(request.get("DeveloperUserIdentifier"))
        sessions_to_revoke: list[CredentialSession] = []
        with self._locked_owned_pool(context, pool_id) as pool:
            if _configured_developer_provider(pool) != provider_name:
                _error("InvalidParameterException", "DeveloperProviderName does not match")
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                identity = store.identities.get(identity_id)
                developer_key = (pool_id, provider_name, developer_identifier)
                if (
                    not _identity_matches(
                        store,
                        identity,
                        identity_id=identity_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    )
                    or store.developer_identities.get(developer_key) != identity_id
                ):
                    _error("ResourceConflictException", "Developer identity link does not match")
                store.developer_identities.pop(developer_key, None)
                identity.developer_user_identifiers.discard(developer_identifier)
                identity.authenticated = bool(
                    identity.logins or identity.developer_user_identifiers
                )
                identity.updated_at = _now()
                sessions_to_revoke.extend(_remove_identity_sessions_locked(store, identity_id))
                if not identity.authenticated:
                    identity.enabled = False
                    _remove_cognito_sync_identity_state(
                        context.account_id,
                        context.region,
                        pool_id,
                        identity_id,
                    )
            _revoke_sessions(sessions_to_revoke)
        return {}

    @handler("GetCredentialsForIdentity", expand=False)
    def get_credentials_for_identity(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unsupported_fields(request, {"CustomRoleArn", "IdentityId", "Logins"})
        custom_role_arn = request.get("CustomRoleArn")
        if custom_role_arn is not None and (
            not isinstance(custom_role_arn, str) or not 20 <= len(custom_role_arn) <= 2048
        ):
            _error("InvalidParameterException", "Invalid CustomRoleArn")
        identity_id = _pool_id(request.get("IdentityId"))
        logins = request.get("Logins")
        if logins is not None and not isinstance(logins, dict):
            _error("InvalidParameterException", "Logins must be a map")
        validated_logins = _login_map(logins) if logins else {}
        location = resolve_identity_location(identity_id)
        if location is None:
            _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
        owner_account, identity_region, pool_id = location
        if owner_account != context.account_id or identity_region != context.region:
            _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")

        with _pool_guard(pool_id):
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                pool = store.identity_pools.get(pool_id)
                identity = store.identities.get(identity_id)
                if (
                    pool is None
                    or identity is None
                    or identity.pool_id != pool_id
                    or store.IDENTITY_LOCATIONS.get(identity_id)
                    != (owner_account, identity_region, pool_id)
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                if not identity.enabled:
                    _error("NotAuthorizedException", "Identity is not active")
                authenticated = identity.authenticated
                configured_providers = copy.deepcopy(pool.cognito_identity_providers)

            if authenticated:
                if not validated_logins:
                    _error(
                        "NotAuthorizedException",
                        "Authenticated identities require their linked Logins",
                    )
                if set(validated_logins) == {"cognito-identity.amazonaws.com"}:
                    with cognito_identity_stores.lock:
                        pool = store.identity_pools.get(pool_id)
                        identity = store.identities.get(identity_id)
                        if pool is None or identity is None or not identity.enabled:
                            _error(
                                "ResourceNotFoundException",
                                f"Identity {identity_id} does not exist",
                            )
                        try:
                            claims = verify_open_id_token(
                                store,
                                token=validated_logins["cognito-identity.amazonaws.com"],
                                partition=context.partition,
                                region=identity_region,
                                pool_id=pool_id,
                                identity_id=identity_id,
                                authenticated=True,
                            )
                        except OpenIdTokenError:
                            _error("NotAuthorizedException", "Invalid identity token")
                        expected_providers = sorted(identity.logins)
                        if identity.developer_user_identifiers:
                            expected_providers.append(_configured_developer_provider(pool))
                        if claims["amr"] != ["authenticated", *sorted(expected_providers)]:
                            _error("NotAuthorizedException", "Identity token links have changed")
                    return self._issue_identity_credentials(
                        context=context,
                        store=store,
                        pool_id=pool_id,
                        identity_id=identity_id,
                        authenticated=True,
                        verified_logins={},
                        identity_token_provider=True,
                        custom_role_arn=custom_role_arn,
                    )
                with cognito_idp_stores.lock:
                    verified_logins, verified_claims = self._verified_native_login_claims_locked(
                        owner_account=owner_account,
                        pool_region=identity_region,
                        partition=context.partition,
                        configured_providers=configured_providers,
                        logins=validated_logins,
                    )
                    return self._issue_identity_credentials(
                        context=context,
                        store=store,
                        pool_id=pool_id,
                        identity_id=identity_id,
                        authenticated=True,
                        verified_logins=verified_logins,
                        verified_claims=verified_claims,
                        custom_role_arn=custom_role_arn,
                    )
            if validated_logins:
                _error("NotAuthorizedException", "Guest identities cannot supply Logins")
            return self._issue_identity_credentials(
                context=context,
                store=store,
                pool_id=pool_id,
                identity_id=identity_id,
                authenticated=False,
                verified_logins={},
                custom_role_arn=custom_role_arn,
            )

    @handler("UnlinkIdentity", expand=False)
    def unlink_identity(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"IdentityId", "Logins", "LoginsToRemove"})
        identity_id = _pool_id(request.get("IdentityId"))
        logins = request.get("Logins")
        if not isinstance(logins, dict) or not logins:
            _error("InvalidParameterException", "Logins must be a non-empty map")
        validated_logins = _login_map(logins)
        logins_to_remove = _login_providers_to_remove(request.get("LoginsToRemove"))
        _, _, pool_id = _owned_identity_location(context, identity_id)
        sessions_to_revoke: list[CredentialSession] = []
        with _pool_guard(pool_id):
            with cognito_identity_stores.lock:
                store = self.get_store(context)
                pool = store.identity_pools.get(pool_id)
                identity = store.identities.get(identity_id)
                if pool is None or not _identity_matches(
                    store,
                    identity,
                    identity_id=identity_id,
                    pool_id=pool_id,
                    account_id=context.account_id,
                    region=context.region,
                ):
                    _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
                if not identity.enabled or not identity.authenticated:
                    _error("NotAuthorizedException", "Identity is not authenticated")
                configured_providers = copy.deepcopy(pool.cognito_identity_providers)

            with cognito_idp_stores.lock:
                verified_logins = self._verified_native_logins_locked(
                    owner_account=context.account_id,
                    pool_region=context.region,
                    partition=context.partition,
                    configured_providers=configured_providers,
                    logins=validated_logins,
                )
                if not set(logins_to_remove).issubset(verified_logins):
                    _error(
                        "NotAuthorizedException",
                        "Every removed login must be validated in Logins",
                    )
                with cognito_identity_stores.lock:
                    pool = store.identity_pools.get(pool_id)
                    identity = store.identities.get(identity_id)
                    if pool is None or not _identity_matches(
                        store,
                        identity,
                        identity_id=identity_id,
                        pool_id=pool_id,
                        account_id=context.account_id,
                        region=context.region,
                    ):
                        _error(
                            "ResourceNotFoundException",
                            f"Identity {identity_id} does not exist",
                        )
                    if any(
                        identity.logins.get(provider_name) != subject
                        or store.login_identities.get((pool_id, provider_name, subject))
                        != identity_id
                        for provider_name, subject in verified_logins.items()
                    ):
                        _error("NotAuthorizedException", "Login is not linked to this identity")
                    remaining_logins = set(identity.logins) - set(logins_to_remove)
                    remains_authenticated = bool(
                        remaining_logins or identity.developer_user_identifiers
                    )
                    if not remains_authenticated and not pool.allow_unauthenticated_identities:
                        _error(
                            "NotAuthorizedException",
                            "The last login cannot be removed when guest access is disabled",
                        )
                    for provider_name in logins_to_remove:
                        subject = identity.logins.pop(provider_name)
                        store.login_identities.pop((pool_id, provider_name, subject), None)
                    identity.authenticated = bool(
                        identity.logins or identity.developer_user_identifiers
                    )
                    identity.updated_at = _now()
                    for access_key_id, session in list(store.credential_sessions.items()):
                        if session.identity_id != identity_id:
                            continue
                        sessions_to_revoke.append(session)
                        store.credential_sessions.pop(access_key_id, None)
            for session in sessions_to_revoke:
                revoke_sts_credentials(
                    account_id=session.account_id,
                    partition=session.partition,
                    access_key_id=session.access_key_id,
                )
        return {}

    def _issue_identity_credentials(
        self,
        *,
        context: RequestContext,
        store: CognitoIdentityStore,
        pool_id: str,
        identity_id: str,
        authenticated: bool,
        verified_logins: dict[str, str],
        verified_claims: dict[str, dict[str, Any]] | None = None,
        identity_token_provider: bool = False,
        custom_role_arn: str | None = None,
    ) -> ServiceResponse:
        now = _now()
        with cognito_identity_stores.lock:
            expired_sessions = _prune_expired_credential_sessions(store, now)
        for session in expired_sessions:
            revoke_sts_credentials(
                account_id=session.account_id,
                partition=session.partition,
                access_key_id=session.access_key_id,
            )

        with cognito_identity_stores.lock:
            pool = store.identity_pools.get(pool_id)
            identity = store.identities.get(identity_id)
            if pool is None or identity is None or identity.pool_id != pool_id:
                _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
            if not identity.enabled or identity.authenticated != authenticated:
                _error("NotAuthorizedException", "Identity is not active")
            if authenticated:
                if not identity_token_provider and any(
                    identity.logins.get(provider_name) != subject
                    or store.login_identities.get((pool_id, provider_name, subject)) != identity_id
                    for provider_name, subject in verified_logins.items()
                ):
                    _error("NotAuthorizedException", "Login is not linked to this identity")
            elif not pool.allow_unauthenticated_identities:
                _error(
                    "NotAuthorizedException",
                    "Unauthenticated access is not supported for this identity pool",
                )
            _ensure_credential_session_capacity(store, identity_id)
            identity_type = "authenticated" if authenticated else "unauthenticated"
            roles_snapshot = copy.deepcopy(pool.roles)
            mappings_snapshot = copy.deepcopy(pool.role_mappings)
            principal_maps_snapshot = copy.deepcopy(pool.principal_tag_attribute_maps)
            principal_tags = _credential_principal_tags(
                pool=pool,
                verified_claims=verified_claims or {},
                identity_token_provider=identity_token_provider,
            )
            if not authenticated and custom_role_arn is not None:
                _error("NotAuthorizedException", "Guest identities cannot select a custom role")
            role_arn = _select_identity_role(
                pool=pool,
                identity=identity,
                authenticated=authenticated,
                verified_claims=verified_claims or {},
                identity_token_provider=identity_token_provider,
                custom_role_arn=custom_role_arn,
                context=context,
            )
            if role_arn is None:
                _error(
                    "InvalidIdentityPoolConfigurationException",
                    f"No {identity_type} role is configured for this identity pool",
                )

        try:
            issued = issue_enhanced_flow_credentials(
                account_id=context.account_id,
                region=context.region,
                partition=context.partition,
                role_arn=role_arn,
                identity_pool_id=pool_id,
                identity_id=identity_id,
                amr=identity_type,
                provider_names=(
                    ["cognito-identity.amazonaws.com"]
                    if identity_token_provider
                    else sorted(verified_logins)
                ),
                principal_tags=principal_tags,
            )
        except CredentialIssueError as error:
            _error("InvalidIdentityPoolConfigurationException", str(error))

        expiration = _utc_datetime(issued.expiration)
        try:
            with cognito_identity_stores.lock:
                pool = store.identity_pools.get(pool_id)
                identity = store.identities.get(identity_id)
                if (
                    pool is None
                    or identity is None
                    or identity.pool_id != pool_id
                    or not identity.enabled
                    or identity.authenticated != authenticated
                    or pool.roles != roles_snapshot
                    or pool.role_mappings != mappings_snapshot
                    or pool.principal_tag_attribute_maps != principal_maps_snapshot
                ):
                    _error("NotAuthorizedException", "Identity changed during credential issuance")
                if (
                    authenticated
                    and not identity_token_provider
                    and any(
                        identity.logins.get(provider_name) != subject
                        or store.login_identities.get((pool_id, provider_name, subject))
                        != identity_id
                        for provider_name, subject in verified_logins.items()
                    )
                ):
                    _error("NotAuthorizedException", "Login changed during credential issuance")
                _ensure_credential_session_capacity(store, identity_id)
                store.credential_sessions[issued.access_key_id] = CredentialSession(
                    access_key_id=issued.access_key_id,
                    identity_id=identity_id,
                    pool_id=pool_id,
                    role_arn=role_arn,
                    assumed_role_arn=issued.assumed_role_arn,
                    account_id=context.account_id,
                    partition=context.partition,
                    issued_at=now,
                    expires_at=expiration,
                    authenticated=authenticated,
                    provider_names=(
                        ("cognito-identity.amazonaws.com",)
                        if identity_token_provider
                        else tuple(sorted(verified_logins))
                    ),
                    principal_tags=copy.deepcopy(principal_tags),
                )
        except BaseException:
            revoke_sts_credentials(
                account_id=context.account_id,
                partition=context.partition,
                access_key_id=issued.access_key_id,
            )
            raise
        return {
            "IdentityId": identity_id,
            "Credentials": {
                "AccessKeyId": issued.access_key_id,
                "SecretKey": issued.secret_key,
                "SessionToken": issued.session_token,
                "Expiration": expiration,
            },
        }

    @handler("GetId", expand=False)
    def get_id(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unsupported_fields(request, {"AccountId", "IdentityPoolId", "Logins"})
        pool_id = _pool_id(request.get("IdentityPoolId"))
        account_id = request.get("AccountId")
        if account_id is not None and (
            not isinstance(account_id, str)
            or not 1 <= len(account_id) <= 15
            or not account_id.isdigit()
        ):
            _error("InvalidParameterException", "AccountId must contain only digits")
        logins = request.get("Logins")
        if logins is not None and not isinstance(logins, dict):
            _error("InvalidParameterException", "Logins must be a map")
        if logins:
            return self._get_authenticated_id(
                context,
                pool_id=pool_id,
                account_id=account_id,
                logins=_login_map(logins),
            )

        with _pool_guard(pool_id):
            location = resolve_pool_location(pool_id)
            if location is None:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            owner_account, pool_region = location
            if account_id is not None and account_id != owner_account:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            if context.region != pool_region:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            with cognito_identity_stores.lock:
                store = cognito_identity_stores[owner_account][pool_region]
                pool = store.identity_pools.get(pool_id)
                if pool is None:
                    _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
                if not pool.allow_unauthenticated_identities:
                    _error(
                        "NotAuthorizedException",
                        "Unauthenticated access is not supported for this identity pool",
                    )
                if len(pool.identity_ids) >= _MAX_IDENTITIES_PER_POOL:
                    _error("LimitExceededException", "Identity pool identity limit exceeded")

            with cognito_identity_stores.lock:
                while True:
                    identity_id = _new_identity_id(pool_region)
                    if (
                        identity_id not in store.IDENTITY_LOCATIONS
                        and identity_id not in store.identities
                    ):
                        break
                now = _now()
                identity = CognitoIdentity(
                    identity_id=identity_id,
                    pool_id=pool_id,
                    created_at=now,
                    updated_at=now,
                )
                store.identities[identity_id] = identity
                pool.identity_ids.add(identity_id)
                store.IDENTITY_LOCATIONS[identity_id] = (
                    owner_account,
                    pool_region,
                    pool_id,
                )
            return {"IdentityId": identity_id}

    def _get_authenticated_id(
        self,
        context: RequestContext,
        *,
        pool_id: str,
        account_id: str | None,
        logins: dict[str, str],
    ) -> ServiceResponse:
        with _pool_guard(pool_id):
            location = resolve_pool_location(pool_id)
            if location is None:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            owner_account, pool_region = location
            if account_id is not None and account_id != owner_account:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            if context.region != pool_region:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            with cognito_identity_stores.lock:
                store = cognito_identity_stores[owner_account][pool_region]
                pool = store.identity_pools.get(pool_id)
                if pool is None:
                    _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
                configured_providers = copy.deepcopy(pool.cognito_identity_providers)

            with cognito_idp_stores.lock:
                verified_logins = self._verified_native_logins_locked(
                    owner_account=owner_account,
                    pool_region=pool_region,
                    partition=context.partition,
                    configured_providers=configured_providers,
                    logins=logins,
                )

                return self._link_authenticated_identity(
                    owner_account=owner_account,
                    pool_region=pool_region,
                    pool_id=pool_id,
                    store=store,
                    verified_logins=verified_logins,
                )

    def _verified_native_logins_locked(
        self,
        *,
        owner_account: str,
        pool_region: str,
        partition: str,
        configured_providers: list[dict[str, Any]],
        logins: dict[str, str],
    ) -> dict[str, str]:
        verified_logins, _ = self._verified_native_login_claims_locked(
            owner_account=owner_account,
            pool_region=pool_region,
            partition=partition,
            configured_providers=configured_providers,
            logins=logins,
        )
        return verified_logins

    def _verified_native_login_claims_locked(
        self,
        *,
        owner_account: str,
        pool_region: str,
        partition: str,
        configured_providers: list[dict[str, Any]],
        logins: dict[str, str],
    ) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
        verified_logins: dict[str, str] = {}
        verified_claims: dict[str, dict[str, Any]] = {}
        for provider_name, token in logins.items():
            candidates = [
                configuration
                for configuration in configured_providers
                if configuration.get("ProviderName") == provider_name
                and isinstance(configuration.get("ClientId"), str)
            ]
            candidates_by_subject: dict[str, dict[str, Any]] = {}
            for configuration in candidates:
                try:
                    claims = verify_native_id_token_claims(
                        account_id=owner_account,
                        region=pool_region,
                        partition=partition,
                        provider_name=provider_name,
                        client_id=configuration["ClientId"],
                        token=token,
                        server_side_token_check=configuration.get("ServerSideTokenCheck", False),
                    )
                    candidates_by_subject[claims["sub"]] = claims
                except TokenValidationError:
                    continue
            if len(candidates_by_subject) != 1:
                _error("NotAuthorizedException", "Invalid login token")
            subject, claims = candidates_by_subject.popitem()
            verified_logins[provider_name] = subject
            verified_claims[provider_name] = claims
        return verified_logins, verified_claims

    def _link_authenticated_identity(
        self,
        *,
        owner_account: str,
        pool_region: str,
        pool_id: str,
        store: CognitoIdentityStore,
        verified_logins: dict[str, str],
    ) -> ServiceResponse:
        with cognito_identity_stores.lock:
            pool = store.identity_pools.get(pool_id)
            if pool is None:
                _error("ResourceNotFoundException", f"Identity pool {pool_id} does not exist")
            login_keys = {
                provider_name: (pool_id, provider_name, subject)
                for provider_name, subject in verified_logins.items()
            }
            linked_identity_ids = {
                store.login_identities[key]
                for key in login_keys.values()
                if key in store.login_identities
            }
            if len(linked_identity_ids) > 1:
                _error(
                    "ResourceConflictException",
                    "The supplied logins belong to different identities",
                )
            if linked_identity_ids:
                identity_id = linked_identity_ids.pop()
                identity = store.identities.get(identity_id)
                if (
                    identity is None
                    or identity.pool_id != pool_id
                    or not identity.enabled
                    or store.IDENTITY_LOCATIONS.get(identity_id)
                    != (owner_account, pool_region, pool_id)
                ):
                    _error("NotAuthorizedException", "Identity is not active")
                if any(
                    provider_name in identity.logins and identity.logins[provider_name] != subject
                    for provider_name, subject in verified_logins.items()
                ):
                    _error(
                        "ResourceConflictException",
                        "The supplied logins conflict with the identity",
                    )
            else:
                if len(pool.identity_ids) >= _MAX_IDENTITIES_PER_POOL:
                    _error("LimitExceededException", "Identity pool identity limit exceeded")
                while True:
                    identity_id = _new_identity_id(pool_region)
                    if (
                        identity_id not in store.IDENTITY_LOCATIONS
                        and identity_id not in store.identities
                    ):
                        break
                now = _now()
                identity = CognitoIdentity(
                    identity_id=identity_id,
                    pool_id=pool_id,
                    created_at=now,
                    updated_at=now,
                    authenticated=True,
                )

            for provider_name, key in login_keys.items():
                linked_identity = store.login_identities.get(key)
                if linked_identity is not None and linked_identity != identity_id:
                    _error(
                        "ResourceConflictException",
                        "The supplied login is already linked to another identity",
                    )

            additional_logins = sum(
                provider_name not in identity.logins for provider_name in verified_logins
            )
            _ensure_link_capacity(identity, additional_logins)

            if identity_id not in store.identities:
                store.identities[identity_id] = identity
                pool.identity_ids.add(identity_id)
                store.IDENTITY_LOCATIONS[identity_id] = (
                    owner_account,
                    pool_region,
                    pool_id,
                )
            identity.authenticated = True
            identity.logins.update(verified_logins)
            identity.updated_at = _now()
            for provider_name, key in login_keys.items():
                store.login_identities[key] = identity_id
            return {"IdentityId": identity_id}


def _now() -> datetime:
    return datetime.now(UTC)


def _new_identity_id(region: str) -> str:
    return f"{region}:{uuid.uuid4()}"


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _prune_expired_credential_sessions(
    store: CognitoIdentityStore, now: datetime
) -> list[CredentialSession]:
    expired: list[CredentialSession] = []
    for access_key_id, session in list(store.credential_sessions.items()):
        if session.expires_at > now:
            continue
        expired.append(session)
        store.credential_sessions.pop(access_key_id, None)
    return expired


def _ensure_credential_session_capacity(store: CognitoIdentityStore, identity_id: str) -> None:
    if len(store.credential_sessions) >= _MAX_CREDENTIAL_SESSIONS_PER_STORE:
        _error("TooManyRequestsException", "Credential session limit exceeded")
    identity_sessions = sum(
        session.identity_id == identity_id for session in store.credential_sessions.values()
    )
    if identity_sessions >= _MAX_CREDENTIAL_SESSIONS_PER_IDENTITY:
        _error("TooManyRequestsException", "Identity credential session limit exceeded")


def _create_identity_locked(
    *,
    store: CognitoIdentityStore,
    pool: IdentityPool,
    account_id: str,
    region: str,
    authenticated: bool,
) -> CognitoIdentity:
    if len(pool.identity_ids) >= _MAX_IDENTITIES_PER_POOL:
        _error("LimitExceededException", "Identity pool identity limit exceeded")
    while True:
        identity_id = _new_identity_id(region)
        if identity_id not in store.IDENTITY_LOCATIONS and identity_id not in store.identities:
            break
    now = _now()
    identity = CognitoIdentity(
        identity_id=identity_id,
        pool_id=pool.pool_id,
        created_at=now,
        updated_at=now,
        authenticated=authenticated,
    )
    store.identities[identity_id] = identity
    pool.identity_ids.add(identity_id)
    store.IDENTITY_LOCATIONS[identity_id] = (account_id, region, pool.pool_id)
    return identity


def _configured_developer_provider(pool: IdentityPool) -> str:
    if pool.developer_provider_name is None:
        _error("InvalidParameterException", "Identity pool has no developer provider")
    return pool.developer_provider_name


def _developer_provider_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or _DEVELOPER_PROVIDER_RE.fullmatch(value) is None
    ):
        _error("InvalidParameterException", "Invalid DeveloperProviderName")
    return value


def _developer_user_identifier(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        _error("InvalidParameterException", "Invalid DeveloperUserIdentifier")
    return value


def _split_developer_logins(
    logins: dict[str, str], developer_provider: str
) -> tuple[str, dict[str, str]]:
    if developer_provider not in logins:
        _error("InvalidParameterException", "Logins must contain the developer provider")
    developer_identifier = _developer_user_identifier(logins[developer_provider])
    return developer_identifier, {
        provider_name: token
        for provider_name, token in logins.items()
        if provider_name != developer_provider
    }


def _ensure_link_capacity(identity: CognitoIdentity, additional: int) -> None:
    if len(identity.logins) + len(identity.developer_user_identifiers) + additional > (
        _MAX_LINKED_LOGINS
    ):
        _error("LimitExceededException", "Linked login limit exceeded")


def _remove_identity_sessions_locked(
    store: CognitoIdentityStore, identity_id: str
) -> list[CredentialSession]:
    sessions: list[CredentialSession] = []
    for access_key_id, session in list(store.credential_sessions.items()):
        if session.identity_id != identity_id:
            continue
        sessions.append(session)
        store.credential_sessions.pop(access_key_id, None)
    return sessions


def _revoke_sessions(sessions: list[CredentialSession]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for session in sessions:
        key = (session.account_id, session.partition, session.access_key_id)
        if key in seen:
            continue
        seen.add(key)
        revoke_sts_credentials(
            account_id=session.account_id,
            partition=session.partition,
            access_key_id=session.access_key_id,
        )


def _merge_identity_locked(
    *,
    store: CognitoIdentityStore,
    source: CognitoIdentity,
    destination: CognitoIdentity,
    account_id: str,
    region: str,
) -> list[CredentialSession]:
    if source.identity_id == destination.identity_id or source.pool_id != destination.pool_id:
        _error("ResourceConflictException", "Identities cannot be merged")
    if any(
        provider_name in destination.logins and destination.logins[provider_name] != subject
        for provider_name, subject in source.logins.items()
    ):
        _error("ResourceConflictException", "Identities contain conflicting provider logins")
    additional_logins = sum(
        provider_name not in destination.logins for provider_name in source.logins
    )
    additional_developers = len(
        source.developer_user_identifiers - destination.developer_user_identifiers
    )
    _ensure_link_capacity(destination, additional_logins + additional_developers)

    sessions = _remove_identity_sessions_locked(store, source.identity_id)
    sessions.extend(_remove_identity_sessions_locked(store, destination.identity_id))
    for provider_name, subject in source.logins.items():
        destination.logins[provider_name] = subject
        store.login_identities[(source.pool_id, provider_name, subject)] = destination.identity_id
    for developer_identifier in source.developer_user_identifiers:
        destination.developer_user_identifiers.add(developer_identifier)
    for key, linked_identity_id in list(store.developer_identities.items()):
        if linked_identity_id == source.identity_id:
            store.developer_identities[key] = destination.identity_id

    source.logins.clear()
    source.developer_user_identifiers.clear()
    source.authenticated = False
    source.enabled = False
    source.updated_at = _now()
    destination.authenticated = bool(destination.logins or destination.developer_user_identifiers)
    destination.updated_at = _now()
    _remove_cognito_sync_identity_state(
        account_id,
        region,
        source.pool_id,
        source.identity_id,
    )
    return sessions


def _link_or_merge_native_logins_locked(
    *,
    store: CognitoIdentityStore,
    pool: IdentityPool,
    destination: CognitoIdentity,
    verified_logins: dict[str, str],
    account_id: str,
    region: str,
    reserved_links: int = 0,
) -> list[CredentialSession]:
    if not verified_logins:
        return []
    if any(
        provider_name in destination.logins and destination.logins[provider_name] != subject
        for provider_name, subject in verified_logins.items()
    ):
        _error("ResourceConflictException", "Identity already has a login for this provider")
    sessions: list[CredentialSession] = []
    source_ids = {
        linked_identity_id
        for provider_name, subject in verified_logins.items()
        if (
            linked_identity_id := store.login_identities.get((pool.pool_id, provider_name, subject))
        )
        is not None
        and linked_identity_id != destination.identity_id
    }
    sources: list[CognitoIdentity] = []
    combined_logins = dict(destination.logins)
    combined_developers = set(destination.developer_user_identifiers)
    for source_id in sorted(source_ids):
        source = store.identities.get(source_id)
        if source is None or not source.enabled or source.pool_id != pool.pool_id:
            _error("ResourceConflictException", "Login is linked to an inactive identity")
        for provider_name, subject in source.logins.items():
            if provider_name in combined_logins and combined_logins[provider_name] != subject:
                _error(
                    "ResourceConflictException",
                    "Identities contain conflicting provider logins",
                )
            combined_logins[provider_name] = subject
        combined_developers.update(source.developer_user_identifiers)
        sources.append(source)
    for provider_name, subject in verified_logins.items():
        if provider_name in combined_logins and combined_logins[provider_name] != subject:
            _error("ResourceConflictException", "Identity already has a login for this provider")
        combined_logins[provider_name] = subject
    if len(combined_logins) + len(combined_developers) + reserved_links > _MAX_LINKED_LOGINS:
        _error("LimitExceededException", "Linked login limit exceeded")

    for source in sources:
        sessions.extend(
            _merge_identity_locked(
                store=store,
                source=source,
                destination=destination,
                account_id=account_id,
                region=region,
            )
        )
    additional = sum(provider_name not in destination.logins for provider_name in verified_logins)
    _ensure_link_capacity(destination, additional)
    changed = False
    for provider_name, subject in verified_logins.items():
        key = (pool.pool_id, provider_name, subject)
        linked_identity_id = store.login_identities.get(key)
        if linked_identity_id not in (None, destination.identity_id):
            _error("ResourceConflictException", "Login is linked to another identity")
        if destination.logins.get(provider_name) != subject:
            changed = True
        destination.logins[provider_name] = subject
        store.login_identities[key] = destination.identity_id
    if changed and not sessions:
        sessions.extend(_remove_identity_sessions_locked(store, destination.identity_id))
    destination.authenticated = True
    destination.updated_at = _now()
    return sessions


def _credential_principal_tags(
    *,
    pool: IdentityPool,
    verified_claims: dict[str, dict[str, Any]],
    identity_token_provider: bool,
) -> dict[str, str]:
    if identity_token_provider:
        return {}
    result: dict[str, str] = {}
    normalized_keys: dict[str, str] = {}
    for provider_name, claims in verified_claims.items():
        mapping = pool.principal_tag_attribute_maps.get(provider_name)
        if mapping is None or mapping.use_defaults:
            continue
        if not isinstance(claims, dict):
            _error("InvalidIdentityPoolConfigurationException", "Invalid principal tag claims")
        for tag_key, claim_name in mapping.principal_tags.items():
            claim_value = claims.get(claim_name)
            if claim_value is None:
                continue
            if (
                not isinstance(tag_key, str)
                or not 1 <= len(tag_key) <= 128
                or not isinstance(claim_name, str)
                or not 1 <= len(claim_name) <= 256
                or not isinstance(claim_value, str)
                or not 1 <= len(claim_value) <= 256
            ):
                _error(
                    "InvalidIdentityPoolConfigurationException",
                    "Invalid principal tag claim",
                )
            normalized = tag_key.lower()
            existing_key = normalized_keys.get(normalized)
            if existing_key is not None and result[existing_key] != claim_value:
                _error(
                    "InvalidIdentityPoolConfigurationException",
                    "Conflicting principal tag claims",
                )
            if existing_key is None:
                normalized_keys[normalized] = tag_key
                result[tag_key] = claim_value
    if len(result) > 50:
        _error("InvalidIdentityPoolConfigurationException", "Too many principal tags")
    return dict(sorted(result.items()))


def _issue_pool_token_locked(
    *,
    store: CognitoIdentityStore,
    context: RequestContext,
    pool: IdentityPool,
    identity: CognitoIdentity,
    duration: int,
    principal_tags: dict[str, str] | None = None,
) -> str:
    provider_names = sorted(identity.logins)
    if identity.developer_user_identifiers:
        provider_names.append(_configured_developer_provider(pool))
    try:
        return issue_open_id_token(
            store,
            partition=context.partition,
            region=context.region,
            pool_id=pool.pool_id,
            identity_id=identity.identity_id,
            authenticated=identity.authenticated,
            provider_names=provider_names,
            duration=duration,
            principal_tags=principal_tags,
        )
    except OpenIdTokenError as error:
        _error("InvalidParameterException", str(error))


def _owned_identity_location(context: RequestContext, identity_id: str) -> tuple[str, str, str]:
    location = resolve_identity_location(identity_id)
    if location is None or location[:2] != (context.account_id, context.region):
        _error("ResourceNotFoundException", f"Identity {identity_id} does not exist")
    return location


def _identity_matches(
    store: CognitoIdentityStore,
    identity: CognitoIdentity | None,
    *,
    identity_id: str,
    pool_id: str,
    account_id: str,
    region: str,
) -> bool:
    pool = store.identity_pools.get(pool_id)
    return bool(
        pool is not None
        and identity is not None
        and identity.pool_id == pool_id
        and identity_id in pool.identity_ids
        and store.IDENTITY_LOCATIONS.get(identity_id) == (account_id, region, pool_id)
    )


def _identity_response(
    identity: CognitoIdentity, developer_provider_name: str | None = None
) -> dict[str, Any]:
    logins = set(identity.logins)
    if identity.developer_user_identifiers and developer_provider_name is not None:
        logins.add(developer_provider_name)
    return {
        "IdentityId": identity.identity_id,
        "Logins": sorted(logins),
        "CreationDate": identity.created_at,
        "LastModifiedDate": identity.updated_at,
    }


def _identity_id_batch(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_IDENTITIES_BATCH
        or len({item for item in value if isinstance(item, str)}) != len(value)
    ):
        _error("InvalidParameterException", "IdentityIdsToDelete must contain 1 to 60 unique IDs")
    return [_pool_id(item) for item in value]


def _remove_identity_state_locked(
    *,
    store: CognitoIdentityStore,
    account_id: str,
    region: str,
    pool_id: str,
    identity_id: str,
) -> list[CredentialSession]:
    pool = store.identity_pools.get(pool_id)
    if pool is not None:
        pool.identity_ids.discard(identity_id)
    store.identities.pop(identity_id, None)
    if store.IDENTITY_LOCATIONS.get(identity_id) == (account_id, region, pool_id):
        store.IDENTITY_LOCATIONS.pop(identity_id, None)
    for login_key, linked_identity_id in list(store.login_identities.items()):
        if linked_identity_id == identity_id:
            store.login_identities.pop(login_key, None)
    for developer_key, linked_identity_id in list(store.developer_identities.items()):
        if linked_identity_id == identity_id:
            store.developer_identities.pop(developer_key, None)
    sessions: list[CredentialSession] = []
    for access_key_id, session in list(store.credential_sessions.items()):
        if session.identity_id != identity_id:
            continue
        sessions.append(session)
        store.credential_sessions.pop(access_key_id, None)
    _remove_cognito_sync_identity_state(account_id, region, pool_id, identity_id)
    return sessions


def _remove_cognito_sync_identity_state(
    account_id: str, region: str, pool_id: str, identity_id: str
) -> None:
    from localstack.services.cognito_sync.models import cognito_sync_stores

    with cognito_sync_stores.lock:
        bundle = cognito_sync_stores.get(account_id)
        sync_store = bundle.get(region) if bundle is not None else None
        if sync_store is None:
            return
        for key in [key for key in sync_store.datasets if key[:2] == (pool_id, identity_id)]:
            sync_store.datasets.pop(key, None)
        for key in [
            key for key in sync_store.dataset_tombstones if key[:2] == (pool_id, identity_id)
        ]:
            sync_store.dataset_tombstones.pop(key, None)
        encoded_scope = json.dumps(
            (pool_id, identity_id), separators=(",", ":"), ensure_ascii=True
        ).encode()
        scope_hash = hashlib.sha256(encoded_scope).hexdigest()
        for digest, session in list(sync_store.sessions.items()):
            if session.scope_hash == scope_hash:
                sync_store.sessions.pop(digest, None)
        device_ids = [
            device_id
            for device_id, device in sync_store.devices.items()
            if device.pool_id == pool_id and device.identity_id == identity_id
        ]
        for device_id in device_ids:
            device = sync_store.devices.pop(device_id)
            sync_store.device_index.pop(
                (device.pool_id, device.identity_id, device.platform, device.token), None
            )
        sync_store.subscriptions = {
            subscription
            for subscription in sync_store.subscriptions
            if subscription[:2] != (pool_id, identity_id)
        }


def _remove_cognito_sync_pool_state(account_id: str, region: str, pool_id: str) -> None:
    from localstack.services.cognito_sync.models import cognito_sync_stores

    with cognito_sync_stores.lock:
        bundle = cognito_sync_stores.get(account_id)
        sync_store = bundle.get(region) if bundle is not None else None
        if sync_store is None:
            return
        for key in [key for key in sync_store.datasets if key[0] == pool_id]:
            sync_store.datasets.pop(key, None)
        for key in [key for key in sync_store.dataset_tombstones if key[0] == pool_id]:
            sync_store.dataset_tombstones.pop(key, None)
        for digest, session in list(sync_store.sessions.items()):
            if session.pool_id == pool_id:
                sync_store.sessions.pop(digest, None)
        for device_id, device in list(sync_store.devices.items()):
            if device.pool_id != pool_id:
                continue
            sync_store.devices.pop(device_id, None)
            sync_store.device_index.pop(
                (device.pool_id, device.identity_id, device.platform, device.token), None
            )
        sync_store.subscriptions = {
            subscription for subscription in sync_store.subscriptions if subscription[0] != pool_id
        }
        sync_store.pool_configurations.pop(pool_id, None)


def _page_secret(store: CognitoIdentityStore, *, create: bool) -> bytes:
    if not store.pagination_secret:
        if not create:
            _error("InvalidParameterException", "Invalid NextToken")
        store.pagination_secret = secrets.token_bytes(32)
    return store.pagination_secret


def _encode_page_token(store: CognitoIdentityStore, scope: str, after: str) -> str:
    payload = json.dumps(
        {"after": after, "scope": scope, "version": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.digest(_page_secret(store, create=True), encoded.encode(), hashlib.sha256)
    ).rstrip(b"=")
    token = f"{encoded}.{signature.decode()}"
    if len(token) > _MAX_PAGE_TOKEN_BYTES:
        _error("InvalidParameterException", "Pagination token is too large")
    return token


def _decode_page_token(
    store: CognitoIdentityStore,
    value: Any,
    scope: str,
    *,
    developer_identifier: bool = False,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PAGE_TOKEN_BYTES:
        _error("InvalidParameterException", "Invalid NextToken")
    parts = value.split(".")
    if len(parts) != 2 or any(re.fullmatch(r"[A-Za-z0-9_-]+", part) is None for part in parts):
        _error("InvalidParameterException", "Invalid NextToken")
    encoded, signature = parts
    expected = base64.urlsafe_b64encode(
        hmac.digest(_page_secret(store, create=False), encoded.encode(), hashlib.sha256)
    ).rstrip(b"=")
    if not hmac.compare_digest(signature.encode(), expected):
        _error("InvalidParameterException", "Invalid NextToken")
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        if len(decoded) > _MAX_PAGE_TOKEN_BYTES:
            raise ValueError
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        _error("InvalidParameterException", "Invalid NextToken")
    if (
        not isinstance(payload, dict)
        or set(payload) != {"after", "scope", "version"}
        or payload.get("scope") != scope
        or payload.get("version") != 1
    ):
        _error("InvalidParameterException", "Invalid NextToken")
    after = payload.get("after")
    if not isinstance(after, str) or (
        not 1 <= len(after) <= 1024
        if developer_identifier
        else _POOL_ID_RE.fullmatch(after) is None
    ):
        _error("InvalidParameterException", "Invalid NextToken")
    return after


def _identity_pool_arn(value: Any, context: RequestContext) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048:
        _error("InvalidParameterException", "Invalid identity pool ARN")
    match = _POOL_ARN_RE.fullmatch(value)
    if match is None:
        _error("InvalidParameterException", "Invalid identity pool ARN")
    pool_id = _pool_id(match.group("pool"))
    if (
        match.group("partition") != context.partition
        or match.group("region") != context.region
        or match.group("account") != context.account_id
    ):
        _error("ResourceNotFoundException", "Identity pool does not exist")
    return pool_id


def _tag_keys(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_TAGS
        or len({item for item in value if isinstance(item, str)}) != len(value)
        or not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in value)
    ):
        _error("InvalidParameterException", "Invalid TagKeys")
    return list(value)


def _provider_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or _COGNITO_PROVIDER_RE.fullmatch(value) is None
    ):
        _error("InvalidParameterException", "Invalid IdentityProviderName")
    return value


def _require_configured_native_provider(pool: IdentityPool, provider_name: str) -> None:
    if not any(
        item.get("ProviderName") == provider_name and isinstance(item.get("ClientId"), str)
        for item in pool.cognito_identity_providers
    ):
        _error("InvalidParameterException", "IdentityProviderName is not configured")


def _principal_tag_map_response(
    pool_id: str, provider_name: str, mapping: PrincipalTagAttributeMap
) -> dict[str, Any]:
    return {
        "IdentityPoolId": pool_id,
        "IdentityProviderName": provider_name,
        "UseDefaults": mapping.use_defaults,
        "PrincipalTags": copy.deepcopy(mapping.principal_tags),
    }


def _login_providers_to_remove(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_LOGINS_TO_REMOVE
        or len({item for item in value if isinstance(item, str)}) != len(value)
    ):
        _error("InvalidParameterException", "Invalid LoginsToRemove")
    return [_provider_name(item) for item in value]


def _error(code: str, message: str):
    raise CommonServiceException(code, message, status_code=400, sender_fault=True)


def _reject_unsupported_fields(request: ServiceRequest, allowed: set[str]) -> None:
    if unsupported := sorted(set(request) - allowed):
        _error("InvalidParameterException", f"Unsupported request fields: {unsupported}")


def _pool_id(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 55:
        _error("InvalidParameterException", "IdentityPoolId is required")
    match = _POOL_ID_RE.fullmatch(value)
    if match is None:
        _error("InvalidParameterException", "Invalid IdentityPoolId")
    try:
        uuid.UUID(match.group("uuid"))
    except ValueError:
        _error("InvalidParameterException", "Invalid IdentityPoolId")
    return value


def _pool_configuration(request: ServiceRequest) -> dict[str, Any]:
    name = request.get("IdentityPoolName")
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 128
        or _POOL_NAME_RE.fullmatch(name) is None
    ):
        _error("InvalidParameterException", "Invalid IdentityPoolName")
    allow_unauthenticated = request.get("AllowUnauthenticatedIdentities")
    if not isinstance(allow_unauthenticated, bool):
        _error("InvalidParameterException", "AllowUnauthenticatedIdentities is required")
    allow_classic = request.get("AllowClassicFlow", False)
    if not isinstance(allow_classic, bool):
        _error("InvalidParameterException", "AllowClassicFlow must be a boolean")

    for field in (
        "CognitoIdentityProviders",
        "DeveloperProviderName",
        "IdentityPoolTags",
        "OpenIdConnectProviderARNs",
        "SamlProviderARNs",
        "SupportedLoginProviders",
    ):
        if field in request and request[field] is None:
            _error("InvalidParameterException", f"Invalid {field}")

    developer_provider = request.get("DeveloperProviderName")
    if "DeveloperProviderName" in request and (
        not isinstance(developer_provider, str)
        or not 1 <= len(developer_provider) <= 128
        or _DEVELOPER_PROVIDER_RE.fullmatch(developer_provider) is None
    ):
        _error("InvalidParameterException", "Invalid DeveloperProviderName")

    supported_login_providers = _string_map(
        request.get("SupportedLoginProviders"),
        "SupportedLoginProviders",
        maximum=10,
        key_maximum=128,
        value_maximum=128,
        value_pattern=_LOGIN_PROVIDER_VALUE_RE,
    )
    open_id_connect_provider_arns = _arn_list(
        request.get("OpenIdConnectProviderARNs"), "OpenIdConnectProviderARNs"
    )
    saml_provider_arns = _arn_list(request.get("SamlProviderARNs"), "SamlProviderARNs")
    if supported_login_providers or open_id_connect_provider_arns or saml_provider_arns:
        raise NotImplementedError(
            "External identity providers require a runtime token verifier and are not implemented"
        )

    return {
        "name": name,
        "allow_unauthenticated_identities": allow_unauthenticated,
        "allow_classic_flow": allow_classic,
        "supported_login_providers": supported_login_providers,
        "developer_provider_name": developer_provider,
        "open_id_connect_provider_arns": open_id_connect_provider_arns,
        "cognito_identity_providers": _cognito_providers(request.get("CognitoIdentityProviders")),
        "saml_provider_arns": saml_provider_arns,
        "tags": _string_map(
            request.get("IdentityPoolTags"),
            "IdentityPoolTags",
            maximum=_MAX_TAGS,
            key_maximum=128,
            value_maximum=256,
            allow_empty_value=True,
        ),
    }


def _identity_pool_roles(value: Any, context: RequestContext) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 2:
        _error("InvalidParameterException", "Invalid Roles")
    roles: dict[str, str] = {}
    for identity_type, role_arn in value.items():
        if identity_type not in {"authenticated", "unauthenticated"}:
            _error("InvalidParameterException", "Invalid identity type in Roles")
        roles[identity_type] = _validated_role_arn(role_arn, context)
    return roles


def _identity_pool_role_mappings(value: Any, context: RequestContext) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or len(value) > 10:
        _error("InvalidParameterException", "Invalid RoleMappings")
    result: dict[str, dict[str, Any]] = {}
    for provider_name, mapping in value.items():
        if not isinstance(provider_name, str) or not 1 <= len(provider_name) <= 128:
            _error("InvalidParameterException", "Invalid identity provider in RoleMappings")
        if not isinstance(mapping, dict) or set(mapping) - {
            "Type",
            "AmbiguousRoleResolution",
            "RulesConfiguration",
        }:
            _error("InvalidParameterException", "Invalid role mapping")
        mapping_type = mapping.get("Type")
        resolution = mapping.get("AmbiguousRoleResolution")
        if mapping_type not in {"Token", "Rules"} or resolution not in {
            "AuthenticatedRole",
            "Deny",
        }:
            _error("InvalidParameterException", "Invalid role mapping type or resolution")
        normalized: dict[str, Any] = {
            "Type": mapping_type,
            "AmbiguousRoleResolution": resolution,
        }
        if mapping_type == "Token":
            if "RulesConfiguration" in mapping:
                _error("InvalidParameterException", "Token role mappings cannot contain rules")
        else:
            configuration = mapping.get("RulesConfiguration")
            if not isinstance(configuration, dict) or set(configuration) != {"Rules"}:
                _error("InvalidParameterException", "RulesConfiguration is required")
            rules = configuration["Rules"]
            if not isinstance(rules, list) or not 1 <= len(rules) <= 25:
                _error("InvalidParameterException", "Role mappings require 1 to 25 rules")
            normalized_rules: list[dict[str, str]] = []
            for rule in rules:
                if not isinstance(rule, dict) or set(rule) != {
                    "Claim",
                    "MatchType",
                    "RoleARN",
                    "Value",
                }:
                    _error("InvalidParameterException", "Invalid role mapping rule")
                claim = rule["Claim"]
                match_type = rule["MatchType"]
                expected = rule["Value"]
                if not isinstance(claim, str) or not 1 <= len(claim) <= 64:
                    _error("InvalidParameterException", "Invalid role mapping claim")
                if match_type not in {"Equals", "Contains", "StartsWith", "NotEqual"}:
                    _error("InvalidParameterException", "Invalid role mapping match type")
                if not isinstance(expected, str) or not 1 <= len(expected) <= 128:
                    _error("InvalidParameterException", "Invalid role mapping value")
                normalized_rules.append(
                    {
                        "Claim": claim,
                        "MatchType": match_type,
                        "RoleARN": _validated_role_arn(rule["RoleARN"], context),
                        "Value": expected,
                    }
                )
            normalized["RulesConfiguration"] = {"Rules": normalized_rules}
        result[provider_name] = normalized
    return result


def _validated_role_arn(value: Any, context: RequestContext) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048:
        _error("InvalidParameterException", "Invalid role ARN")
    match = _ROLE_ARN_RE.fullmatch(value)
    if (
        match is None
        or match.group("partition") != context.partition
        or match.group("account") != context.account_id
        or match.group("name").startswith("/")
        or match.group("name").endswith("/")
        or "//" in match.group("name")
    ):
        _error("InvalidParameterException", "Role ARN must be an IAM role in this account")
    return value


def _select_identity_role(
    *,
    pool: IdentityPool,
    identity: CognitoIdentity,
    authenticated: bool,
    verified_claims: dict[str, dict[str, Any]],
    identity_token_provider: bool,
    custom_role_arn: str | None,
    context: RequestContext,
) -> str | None:
    default_role = pool.roles.get("authenticated" if authenticated else "unauthenticated")
    if not authenticated:
        return default_role
    if custom_role_arn is not None:
        _validated_role_arn(custom_role_arn, context)
    if identity_token_provider:
        if custom_role_arn is not None:
            _error("NotAuthorizedException", "Identity tokens cannot select a custom role")
        if any(
            key == provider_name or key.startswith(f"{provider_name}:")
            for provider_name in identity.logins
            for key in pool.role_mappings
        ):
            _error(
                "NotAuthorizedException",
                "The original provider token is required for configured role mappings",
            )
        return default_role

    selected: list[str] = []
    for provider_name, claims in verified_claims.items():
        audience = claims.get("aud")
        mapping = (
            pool.role_mappings.get(f"{provider_name}:{audience}")
            if isinstance(audience, str)
            else None
        )
        if mapping is None:
            continue
        selected.append(
            _select_mapped_role(
                mapping=mapping,
                claims=claims,
                default_role=default_role,
                custom_role_arn=custom_role_arn,
            )
        )
    if not selected:
        if custom_role_arn is not None:
            _error("NotAuthorizedException", "CustomRoleArn is not allowed by the login token")
        return default_role
    if len(set(selected)) != 1:
        _error("NotAuthorizedException", "Login providers selected conflicting roles")
    return selected[0]


def _select_mapped_role(
    *,
    mapping: dict[str, Any],
    claims: dict[str, Any],
    default_role: str | None,
    custom_role_arn: str | None,
) -> str:
    if mapping["Type"] == "Token":
        raw_roles = claims.get("cognito:roles", [])
        if not isinstance(raw_roles, list) or any(
            not isinstance(role, str) or not role for role in raw_roles
        ):
            _error("NotAuthorizedException", "Invalid cognito:roles claim")
        allowed_roles = list(dict.fromkeys(raw_roles))
        preferred = claims.get("cognito:preferred_role")
        if preferred is not None and (
            not isinstance(preferred, str) or preferred not in allowed_roles
        ):
            _error("NotAuthorizedException", "Invalid cognito:preferred_role claim")
        if custom_role_arn is not None:
            if custom_role_arn not in allowed_roles:
                _error("NotAuthorizedException", "CustomRoleArn is not allowed by the login token")
            return custom_role_arn
        if preferred is not None:
            return preferred
        if len(allowed_roles) == 1:
            return allowed_roles[0]
        return _ambiguous_role(mapping, default_role)

    matching_roles = [
        rule["RoleARN"]
        for rule in mapping["RulesConfiguration"]["Rules"]
        if _mapping_rule_matches(rule, claims)
    ]
    if custom_role_arn is not None:
        if custom_role_arn not in matching_roles:
            _error("NotAuthorizedException", "CustomRoleArn is not allowed by matching rules")
        return custom_role_arn
    if matching_roles:
        return matching_roles[0]
    return _ambiguous_role(mapping, default_role)


def _mapping_rule_matches(rule: dict[str, str], claims: dict[str, Any]) -> bool:
    actual = claims.get(rule["Claim"])
    if not isinstance(actual, str):
        return False
    expected = rule["Value"]
    return {
        "Equals": actual == expected,
        "Contains": expected in actual,
        "StartsWith": actual.startswith(expected),
        "NotEqual": actual != expected,
    }[rule["MatchType"]]


def _ambiguous_role(mapping: dict[str, Any], default_role: str | None) -> str:
    if mapping["AmbiguousRoleResolution"] == "AuthenticatedRole" and default_role is not None:
        return default_role
    _error("NotAuthorizedException", "The role mapping did not resolve an allowed role")


def _login_map(value: dict[Any, Any]) -> dict[str, str]:
    if len(value) > _MAX_LOGINS:
        _error("InvalidParameterException", "Logins cannot contain more than 10 providers")
    result: dict[str, str] = {}
    for provider_name, token in value.items():
        if (
            not isinstance(provider_name, str)
            or not 1 <= len(provider_name) <= 128
            or not isinstance(token, str)
            or not 1 <= len(token) <= _MAX_LOGIN_TOKEN_LENGTH
        ):
            _error("InvalidParameterException", "Invalid Logins")
        result[provider_name] = token
    return result


def _string_map(
    value: Any,
    field: str,
    *,
    maximum: int,
    key_maximum: int,
    value_maximum: int,
    value_pattern: re.Pattern[str] | None = None,
    allow_empty_value: bool = False,
) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > maximum:
        _error("InvalidParameterException", f"Invalid {field}")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= key_maximum
            or not isinstance(item, str)
            or len(item) > value_maximum
            or (not allow_empty_value and not item)
            or (value_pattern is not None and value_pattern.fullmatch(item) is None)
        ):
            _error("InvalidParameterException", f"Invalid {field}")
        result[key] = item
    return result


def _arn_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if (
        not isinstance(value, list)
        or len(value) > _MAX_PROVIDER_LIST_ITEMS
        or not all(isinstance(item, str) and 20 <= len(item) <= 2048 for item in value)
        or len(set(value)) != len(value)
    ):
        _error("InvalidParameterException", f"Invalid {field}")
    return list(value)


def _cognito_providers(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_PROVIDER_LIST_ITEMS:
        _error("InvalidParameterException", "Invalid CognitoIdentityProviders")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {
            "ClientId",
            "ProviderName",
            "ServerSideTokenCheck",
        }:
            _error("InvalidParameterException", "Invalid CognitoIdentityProviders")
        provider_name = item.get("ProviderName")
        client_id = item.get("ClientId")
        server_check = item.get("ServerSideTokenCheck", False)
        if provider_name is not None and (
            not isinstance(provider_name, str)
            or not 1 <= len(provider_name) <= 128
            or _COGNITO_PROVIDER_RE.fullmatch(provider_name) is None
        ):
            _error("InvalidParameterException", "Invalid CognitoIdentityProviders")
        if client_id is not None and (
            not isinstance(client_id, str)
            or not 1 <= len(client_id) <= 128
            or _CLIENT_ID_RE.fullmatch(client_id) is None
        ):
            _error("InvalidParameterException", "Invalid CognitoIdentityProviders")
        if not isinstance(server_check, bool):
            _error("InvalidParameterException", "Invalid CognitoIdentityProviders")
        identity = (provider_name, client_id)
        if identity in seen:
            _error("InvalidParameterException", "Duplicate CognitoIdentityProviders")
        seen.add(identity)
        result.append(copy.deepcopy(item))
    return result


def _pool_response(pool: IdentityPool) -> dict[str, Any]:
    response: dict[str, Any] = {
        "AllowClassicFlow": pool.allow_classic_flow,
        "AllowUnauthenticatedIdentities": pool.allow_unauthenticated_identities,
        "IdentityPoolId": pool.pool_id,
        "IdentityPoolName": pool.name,
    }
    optional = {
        "CognitoIdentityProviders": pool.cognito_identity_providers,
        "DeveloperProviderName": pool.developer_provider_name,
        "IdentityPoolTags": pool.tags,
        "OpenIdConnectProviderARNs": pool.open_id_connect_provider_arns,
        "SamlProviderARNs": pool.saml_provider_arns,
        "SupportedLoginProviders": pool.supported_login_providers,
    }
    response.update(
        {
            name: copy.deepcopy(value)
            for name, value in optional.items()
            if value not in (None, [], {})
        }
    )
    return response


def _page_after(items, maximum: int, after: str | None, key):
    if after is None:
        start = 0
    else:
        start = next((index + 1 for index, item in enumerate(items) if key(item) == after), None)
        if start is None:
            _error("InvalidParameterException", "Invalid NextToken")
    page = items[start : start + maximum]
    if start + len(page) < len(items):
        return page, key(page[-1])
    return page, None
