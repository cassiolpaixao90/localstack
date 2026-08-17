import dataclasses
import re
import threading
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from localstack.services.cognito_idp.provisioned_limits import DEFAULT_API_CATEGORY_LIMITS

MAX_PROVISIONED_RATE_BUCKETS = 10_000
_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
ADJUSTABLE_OPERATION_CATEGORIES = {
    "AdminConfirmSignUp": "UserCreation",
    "AdminCreateUser": "UserCreation",
    "AdminGetDevice": "UserResourceRead",
    "AdminGetUser": "UserRead",
    "AdminGetUserAuthFactors": "UserRead",
    "AdminInitiateAuth": "UserAuthentication",
    "AdminListDevices": "UserResourceRead",
    "AdminListGroupsForUser": "UserResourceRead",
    "AdminListUserAuthEvents": "UserResourceRead",
    "AdminRespondToAuthChallenge": "UserAuthentication",
    "ConfirmSignUp": "UserCreation",
    "FederationCallback": "UserFederation",
    "GetDevice": "UserResourceRead",
    "GetTokensFromRefreshToken": "UserAuthentication",
    "GetUser": "UserRead",
    "GetUserAttributeVerificationCode": "UserResourceRead",
    "InitiateAuth": "UserAuthentication",
    "ListDevices": "UserResourceRead",
    "ManagedLoginAuthentication": "UserAuthentication",
    "ResendConfirmationCode": "UserResourceRead",
    "RespondToAuthChallenge": "UserAuthentication",
    "RevokeToken": "UserToken",
    "SignUp": "UserCreation",
}
# Operations in AWS' non-adjustable quota categories are deliberately exempt
# from *provisioned* capacity. Keeping this closed list makes model upgrades
# fail review instead of silently bypassing the provider boundary.
PROVISIONED_RATE_EXEMPT_OPERATIONS = frozenset(
    """
    AddCustomAttributes AddUserPoolClientSecret AdminAddUserToGroup AdminDeleteUser
    AdminDeleteUserAttributes AdminDisableProviderForUser AdminDisableUser AdminEnableUser
    AdminForgetDevice AdminLinkProviderForUser AdminRemoveUserFromGroup AdminResetUserPassword
    AdminSetUserMFAPreference AdminSetUserPassword AdminSetUserSettings AdminUpdateAuthEventFeedback
    AdminUpdateDeviceStatus AdminUpdateUserAttributes AdminUserGlobalSignOut AssociateSoftwareToken
    ChangePassword CompleteWebAuthnRegistration ConfirmDevice ConfirmForgotPassword CreateGroup
    CreateIdentityProvider CreateManagedLoginBranding CreateResourceServer CreateTerms
    CreateUserImportJob CreateUserPool CreateUserPoolClient CreateUserPoolDomain CreateUserPoolReplica
    DeleteGroup DeleteIdentityProvider DeleteManagedLoginBranding DeleteResourceServer DeleteTerms
    DeleteUser DeleteUserAttributes DeleteUserPool DeleteUserPoolClient DeleteUserPoolClientSecret
    DeleteUserPoolDomain DeleteUserPoolReplica DeleteWebAuthnCredential DescribeIdentityProvider
    DescribeManagedLoginBranding DescribeManagedLoginBrandingByClient DescribeResourceServer
    DescribeRiskConfiguration DescribeTerms DescribeUserImportJob DescribeUserPool
    DescribeUserPoolClient DescribeUserPoolDomain ForgetDevice ForgotPassword GetCSVHeader GetGroup
    GetIdentityProviderByIdentifier GetLogDeliveryConfiguration GetProvisionedLimit
    GetSigningCertificate GetUICustomization GetUserAuthFactors GetUserPoolMfaConfig GlobalSignOut
    ListGroups ListIdentityProviders ListResourceServers ListTagsForResource ListTerms
    ListUserImportJobs ListUserPoolClientSecrets ListUserPoolClients ListUserPoolReplicas
    ListUserPools ListUsers ListUsersInGroup ListWebAuthnCredentials SetLogDeliveryConfiguration
    SetRiskConfiguration SetUICustomization SetUserMFAPreference SetUserPoolMfaConfig
    SetUserSettings StartUserImportJob StartWebAuthnRegistration StopUserImportJob TagResource
    UntagResource UpdateAuthEventFeedback UpdateDeviceStatus UpdateGroup UpdateIdentityProvider
    UpdateManagedLoginBranding UpdateProvisionedLimit UpdateResourceServer UpdateTerms
    UpdateUserAttributes UpdateUserPool UpdateUserPoolClient UpdateUserPoolDomain
    UpdateUserPoolReplica VerifySoftwareToken VerifyUserAttribute
    """.split()
)


class ProvisionedRateLimitError(ValueError):
    def __init__(self, code: str, message: str, *, retry_after_seconds: float | None = None):
        super().__init__(message)
        self.code = code
        self.retry_after_seconds = retry_after_seconds


@dataclasses.dataclass
class ProvisionedRateBucket:
    rate: int
    tokens: Decimal
    updated_at: datetime


@dataclasses.dataclass
class ProvisionedRateLimitState:
    buckets: dict[tuple[str, str, str], ProvisionedRateBucket] = dataclasses.field(
        default_factory=dict
    )
    _lock: Any = dataclasses.field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self.__dict__)
            state.pop("_lock", None)
            return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()

    def cleanup_scope(self, account_id: str, region: str) -> None:
        account_id, region = _scope(account_id, region)
        with self._lock:
            self.buckets = {
                key: bucket
                for key, bucket in self.buckets.items()
                if key[:2] != (account_id, region)
            }


@dataclasses.dataclass(frozen=True)
class ProvisionedRateDecision:
    remaining: float
    limit: int


def adjustable_category_for_operation(operation: Any) -> str | None:
    if not isinstance(operation, str) or not 1 <= len(operation) <= 128:
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid operation name")
    if category := ADJUSTABLE_OPERATION_CATEGORIES.get(operation):
        return category
    if operation in PROVISIONED_RATE_EXEMPT_OPERATIONS:
        return None
    raise ProvisionedRateLimitError(
        "InvalidParameterException", "Operation has no provisioned-rate classification"
    )


def consume_provisioned_capacity(
    state: ProvisionedRateLimitState,
    *,
    account_id: Any,
    region: Any,
    category: Any,
    provisioned_limit: Any,
    cost: Any = 1,
    now: datetime | None = None,
) -> ProvisionedRateDecision:
    if not isinstance(state, ProvisionedRateLimitState):
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid rate-limit state")
    account_id, region = _scope(account_id, region)
    if category not in DEFAULT_API_CATEGORY_LIMITS:
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid API category")
    if (
        not isinstance(provisioned_limit, int)
        or isinstance(provisioned_limit, bool)
        or provisioned_limit < DEFAULT_API_CATEGORY_LIMITS[category]
        or provisioned_limit > 2**31 - 1
    ):
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid provisioned limit")
    if not isinstance(cost, int) or isinstance(cost, bool) or not 1 <= cost <= 1_000_000:
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid capacity cost")
    now = now or datetime.now(UTC)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid rate-limit clock")
    now = now.astimezone(UTC)
    key = (account_id, region, category)
    requested = Decimal(cost)
    with state._lock:
        current = state.buckets.get(key)
        if current is None:
            if len(state.buckets) >= MAX_PROVISIONED_RATE_BUCKETS:
                raise ProvisionedRateLimitError(
                    "LimitExceededException", "Rate-limit bucket quota exceeded"
                )
            candidate = ProvisionedRateBucket(
                rate=provisioned_limit,
                tokens=Decimal(provisioned_limit),
                updated_at=now,
            )
        else:
            if current.updated_at.tzinfo is None or now < current.updated_at.astimezone(UTC):
                raise ProvisionedRateLimitError("InternalError", "Rate-limit clock moved backwards")
            elapsed = Decimal(str((now - current.updated_at.astimezone(UTC)).total_seconds()))
            refilled = min(Decimal(current.rate), current.tokens + elapsed * Decimal(current.rate))
            candidate = ProvisionedRateBucket(
                rate=provisioned_limit,
                tokens=min(refilled, Decimal(provisioned_limit)),
                updated_at=now,
            )
        if candidate.tokens < requested:
            deficit = requested - candidate.tokens
            retry_after = float(deficit / Decimal(candidate.rate))
            state.buckets[key] = candidate
            raise ProvisionedRateLimitError(
                "TooManyRequestsException",
                "Provisioned API rate exceeded",
                retry_after_seconds=retry_after,
            )
        candidate.tokens -= requested
        state.buckets[key] = candidate
        return ProvisionedRateDecision(
            remaining=float(candidate.tokens),
            limit=provisioned_limit,
        )


def _scope(account_id: Any, region: Any) -> tuple[str, str]:
    if (
        not isinstance(account_id, str)
        or re.fullmatch(r"[0-9]{12}", account_id) is None
        or not isinstance(region, str)
        or _REGION_PATTERN.fullmatch(region) is None
    ):
        raise ProvisionedRateLimitError("InvalidParameterException", "Invalid account/Region scope")
    return account_id, region
