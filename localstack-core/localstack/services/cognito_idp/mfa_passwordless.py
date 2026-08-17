"""Isolated Cognito choice-based authentication and OTP challenge state."""

import copy
import dataclasses
import hashlib
import hmac
import json
import re
import secrets
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol

_FIRST_FACTORS = {"EMAIL_OTP", "PASSWORD", "SMS_OTP", "SOFTWARE_TOKEN", "WEB_AUTHN"}
_AUTO_VERIFIED_ATTRIBUTES = {"email", "phone_number"}
_USER_AUTH_CHALLENGES = {"EMAIL_OTP", "PASSWORD", "PASSWORD_SRP", "SMS_OTP", "WEB_AUTHN"}
_OTP_CONTRACTS = {
    "EMAIL_OTP": ("EMAIL", "email", "EMAIL_OTP_CODE"),
    "SMS_MFA": ("SMS", "phone_number", "SMS_MFA_CODE"),
    "SMS_OTP": ("SMS", "phone_number", "SMS_OTP_CODE"),
}
_POOL_ID = re.compile(r"[\w-]+_[0-9A-Za-z]+")
_SMS_CONFIGURATION_FIELDS = {"EumsSms", "ExternalId", "SnsCallerArn", "SnsRegion"}


class MfaPasswordlessError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ChallengeState(Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"


@dataclasses.dataclass(frozen=True)
class EmailMfaConfiguration:
    message: str = "Your authentication code is {####}."
    subject: str = "Your authentication code"


@dataclasses.dataclass(frozen=True)
class SmsMfaConfiguration:
    message: str = "Your authentication code is {####}."
    sms_configuration: dict[str, Any] | None = None


@dataclasses.dataclass(frozen=True)
class PoolAuthPolicy:
    feature_tier: str = "ESSENTIALS"
    email_sending_account: str = "DEVELOPER"
    sms_delivery_configured: bool = True
    mfa_configuration: str = "OFF"
    allowed_first_auth_factors: frozenset[str] = frozenset({"PASSWORD"})
    auto_verified_attributes: frozenset[str] = frozenset()
    recovery_attributes: tuple[str, ...] = ("email", "phone_number")
    email_mfa: EmailMfaConfiguration | None = None
    sms_mfa: SmsMfaConfiguration | None = None
    software_token_mfa_enabled: bool = False
    web_authn_mfa_enabled: bool = False


@dataclasses.dataclass(frozen=True)
class UserAuthState:
    username: str
    password_enabled: bool
    attributes: dict[str, str] = dataclasses.field(default_factory=dict)
    verified_attributes: frozenset[str] = frozenset()
    email_mfa_enabled: bool = False
    email_mfa_preferred: bool = False
    sms_mfa_enabled: bool = False
    sms_mfa_preferred: bool = False
    software_token_mfa_enabled: bool = False
    software_token_mfa_preferred: bool = False
    web_authn_enabled: bool = False


@dataclasses.dataclass(frozen=True)
class OtpDeliveryRequest:
    pool_id: str
    client_id: str
    username: str
    purpose: str
    medium: str
    destination: str
    secret: str
    client_metadata: dict[str, str]


class OtpDeliveryPort(Protocol):
    def deliver_otp(
        self,
        request: OtpDeliveryRequest,
        reservation_id: str,
        *,
        commit: Callable[[str], bool],
        rollback: Callable[[str], None],
    ) -> str: ...


@dataclasses.dataclass(frozen=True)
class AuthChallengeCompletion:
    username: str
    challenge_name: str
    client_metadata: dict[str, str]
    verified_attribute: str | None
    confirm_user: bool
    synthetic: bool
    device_key: str | None


@dataclasses.dataclass
class _AuthSession:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    challenge_name: str
    state: ChallengeState
    created_at: datetime
    expires_at: datetime
    generation: int
    binding: tuple[str, str, str, str]
    client_metadata: dict[str, str]
    synthetic: bool
    available_challenges: tuple[str, ...] = ()
    code_digest: str | None = None
    response_key: str | None = None
    verified_attribute: str | None = None
    confirm_user: bool = False
    device_key: str | None = None
    failed_attempts: int = 0


@dataclasses.dataclass
class MfaPasswordlessState:
    sessions: dict[str, _AuthSession] = dataclasses.field(default_factory=dict)
    generations: dict[tuple[str, str, str, str], int] = dataclasses.field(default_factory=dict)
    _lock: Any = dataclasses.field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            return {
                "generations": dict(self.generations),
                "sessions": copy.deepcopy(self.sessions),
            }

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()


def validate_pool_auth_policy(policy: Any) -> None:
    if not isinstance(policy, PoolAuthPolicy):
        _invalid("Invalid pool authentication policy")
    if policy.feature_tier not in {"ESSENTIALS", "LITE", "PLUS"}:
        _invalid("Invalid UserPoolTier")
    if policy.email_sending_account not in {"COGNITO_DEFAULT", "DEVELOPER"}:
        _invalid("Invalid EmailSendingAccount")
    if not isinstance(policy.sms_delivery_configured, bool):
        _invalid("Invalid SMS delivery configuration state")
    if not isinstance(policy.software_token_mfa_enabled, bool) or not isinstance(
        policy.web_authn_mfa_enabled, bool
    ):
        _invalid("Invalid MFA factor configuration state")
    if policy.mfa_configuration not in {"OFF", "ON", "OPTIONAL"}:
        _invalid("Invalid MfaConfiguration")
    if (
        not isinstance(policy.allowed_first_auth_factors, frozenset)
        or not policy.allowed_first_auth_factors
        or not policy.allowed_first_auth_factors <= _FIRST_FACTORS
        or "SOFTWARE_TOKEN" in policy.allowed_first_auth_factors
    ):
        _invalid("Invalid AllowedFirstAuthFactors")
    if (
        not isinstance(policy.auto_verified_attributes, frozenset)
        or not policy.auto_verified_attributes <= _AUTO_VERIFIED_ATTRIBUTES
    ):
        _invalid("Invalid AutoVerifiedAttributes")
    if (
        not isinstance(policy.recovery_attributes, tuple)
        or len(policy.recovery_attributes) > 2
        or len(set(policy.recovery_attributes)) != len(policy.recovery_attributes)
        or not set(policy.recovery_attributes) <= _AUTO_VERIFIED_ATTRIBUTES
    ):
        _invalid("Invalid AccountRecoverySetting")
    if "EMAIL_OTP" in policy.allowed_first_auth_factors and (
        "email" not in policy.auto_verified_attributes
    ):
        _invalid("EMAIL_OTP requires email AutoVerifiedAttributes")
    if "SMS_OTP" in policy.allowed_first_auth_factors and (
        "phone_number" not in policy.auto_verified_attributes
    ):
        _invalid("SMS_OTP requires phone_number AutoVerifiedAttributes")
    if "WEB_AUTHN" in policy.allowed_first_auth_factors and (
        len(policy.allowed_first_auth_factors) == 1
    ):
        _invalid("WEB_AUTHN must be accompanied by another first factor")
    if policy.mfa_configuration == "ON" and policy.allowed_first_auth_factors & {
        "EMAIL_OTP",
        "SMS_OTP",
    }:
        _invalid("Passwordless OTP is incompatible with required MFA")
    if policy.feature_tier == "LITE" and policy.allowed_first_auth_factors - {"PASSWORD"}:
        raise MfaPasswordlessError(
            "FeatureUnavailableInTierException",
            "Passwordless first factors require the Essentials or Plus tier",
        )

    if policy.email_mfa is not None:
        if not isinstance(policy.email_mfa, EmailMfaConfiguration):
            _invalid("Invalid EmailMfaConfiguration")
        _message(policy.email_mfa.message, "EmailMfaConfiguration.Message", 20_000)
        _text(policy.email_mfa.subject, "EmailMfaConfiguration.Subject", 1_024)
        if policy.feature_tier == "LITE":
            raise MfaPasswordlessError(
                "FeatureUnavailableInTierException",
                "Email MFA requires the Essentials or Plus tier",
            )
        if policy.email_sending_account != "DEVELOPER":
            _invalid("Email MFA requires DEVELOPER email sending")
    if policy.sms_mfa is not None:
        if not isinstance(policy.sms_mfa, SmsMfaConfiguration):
            _invalid("Invalid SmsMfaConfiguration")
        _message(policy.sms_mfa.message, "SmsAuthenticationMessage", 140)
        if policy.sms_mfa.sms_configuration is not None:
            _sms_configuration(policy.sms_mfa.sms_configuration)
        elif not policy.sms_delivery_configured:
            _invalid("SMS MFA requires SMS delivery configuration")
    if policy.mfa_configuration == "ON" and not (
        policy.email_mfa is not None
        or policy.sms_mfa is not None
        or policy.software_token_mfa_enabled
        or policy.web_authn_mfa_enabled
    ):
        _invalid("MFA ON requires an enabled MFA factor")
    if policy.mfa_configuration != "OFF" and policy.recovery_attributes:
        unavailable = set()
        if policy.email_mfa is not None:
            unavailable.add("email")
        if policy.sms_mfa is not None:
            unavailable.add("phone_number")
        if set(policy.recovery_attributes) <= unavailable:
            _invalid("MFA destination cannot be the only account recovery mechanism")


def set_user_mfa_preferences(
    policy: PoolAuthPolicy,
    user: UserAuthState,
    *,
    sms: Any = None,
    email: Any = None,
) -> UserAuthState:
    validate_pool_auth_policy(policy)
    _validate_user(user)
    sms_enabled, sms_preferred = _preference(
        sms, current_enabled=user.sms_mfa_enabled, current_preferred=user.sms_mfa_preferred
    )
    email_enabled, email_preferred = _preference(
        email,
        current_enabled=user.email_mfa_enabled,
        current_preferred=user.email_mfa_preferred,
    )
    if sms_enabled:
        _eligible_destination(policy, user, "phone_number", policy.sms_mfa is not None)
    if email_enabled:
        _eligible_destination(policy, user, "email", policy.email_mfa is not None)
    if sum((sms_preferred, email_preferred, user.software_token_mfa_preferred)) > 1:
        _invalid("Only one MFA factor can be preferred")
    return dataclasses.replace(
        user,
        sms_mfa_enabled=sms_enabled,
        sms_mfa_preferred=sms_preferred,
        email_mfa_enabled=email_enabled,
        email_mfa_preferred=email_preferred,
    )


def available_user_auth_challenges(
    policy: PoolAuthPolicy, user: UserAuthState
) -> list[str]:
    validate_pool_auth_policy(policy)
    _validate_user(user)
    result = []
    if "PASSWORD" in policy.allowed_first_auth_factors and user.password_enabled:
        result.extend(("PASSWORD", "PASSWORD_SRP"))
    otp_eligible = policy.mfa_configuration != "ON" and not (
        policy.mfa_configuration == "OPTIONAL"
        and (
            user.email_mfa_enabled
            or user.sms_mfa_enabled
            or user.software_token_mfa_enabled
        )
    )
    if otp_eligible:
        if "EMAIL_OTP" in policy.allowed_first_auth_factors and _has_destination(user, "email"):
            result.append("EMAIL_OTP")
        if "SMS_OTP" in policy.allowed_first_auth_factors and _has_destination(
            user, "phone_number"
        ):
            result.append("SMS_OTP")
    if "WEB_AUTHN" in policy.allowed_first_auth_factors and user.web_authn_enabled:
        result.append("WEB_AUTHN")
    return result


def available_recovery_attributes(
    policy: PoolAuthPolicy, user: UserAuthState
) -> list[str]:
    """Return verified recovery channels that aren't enabled as the user's MFA factor."""
    validate_pool_auth_policy(policy)
    _validate_user(user)
    blocked = set()
    if user.email_mfa_enabled:
        blocked.add("email")
    if user.sms_mfa_enabled:
        blocked.add("phone_number")
    return [
        attribute
        for attribute in policy.recovery_attributes
        if attribute not in blocked and _has_verified(user, attribute)
    ]


class MfaPasswordlessEngine:
    def __init__(
        self,
        *,
        signing_key: bytes,
        state: MfaPasswordlessState | None = None,
        challenge_ttl: timedelta = timedelta(minutes=5),
        maximum_sessions: int = 10_000,
        maximum_code_attempts: int = 5,
    ):
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            _invalid("Invalid challenge signing key")
        if not timedelta(minutes=3) <= challenge_ttl <= timedelta(minutes=15):
            _invalid("Invalid authentication session validity")
        if not 1 <= maximum_sessions <= 100_000 or not 1 <= maximum_code_attempts <= 10:
            _invalid("Invalid challenge bounds")
        self._signing_key = signing_key
        self._challenge_ttl = challenge_ttl
        self._maximum_sessions = maximum_sessions
        self._maximum_code_attempts = maximum_code_attempts
        self.state = state or MfaPasswordlessState()
        if not isinstance(self.state, MfaPasswordlessState):
            _invalid("Invalid MFA/passwordless state")
        self._sessions = self.state.sessions
        self._generations = self.state.generations
        self._lock = self.state._lock

    def __getstate__(self) -> dict[str, Any]:
        with self._lock:
            state = self.__dict__.copy()
            for transient in ("_generations", "_lock", "_sessions"):
                state.pop(transient, None)
            return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._sessions = self.state.sessions
        self._generations = self.state.generations
        self._lock = self.state._lock

    @property
    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def persisted_tokens(self) -> set[str]:
        with self._lock:
            return set(self._sessions)

    def prune(self, now: datetime) -> int:
        now = _time(now)
        with self._lock:
            before = len(self._sessions)
            self._prune_locked(now)
            return before - len(self._sessions)

    def cleanup(self, *, pool_id: Any, username: Any = None) -> int:
        pool_id, _ = _scope(pool_id, "cleanup")
        if username is not None:
            username = _username(username)
        with self._lock:
            matching = [
                stored
                for stored in self._sessions.values()
                if stored.pool_id == pool_id
                and (username is None or hmac.compare_digest(stored.username, username))
            ]
            for stored in matching:
                self._remove_locked(stored)
            return len(matching)

    def cleanup_client(self, *, pool_id: Any, client_id: Any) -> int:
        pool_id, client_id = _scope(pool_id, client_id)
        with self._lock:
            matching = [
                stored
                for stored in self._sessions.values()
                if stored.pool_id == pool_id and stored.client_id == client_id
            ]
            for stored in matching:
                self._remove_locked(stored)
            return len(matching)

    def start_user_auth(
        self,
        *,
        policy: PoolAuthPolicy,
        user: UserAuthState | None,
        pool_id: Any,
        client_id: Any,
        preferred_challenge: Any,
        prevent_user_existence_errors: bool,
        client_metadata: Any,
        sender: OtpDeliveryPort,
        now: datetime,
        username: Any = None,
        code_factory=None,
    ) -> dict[str, Any]:
        validate_pool_auth_policy(policy)
        pool_id, client_id = _scope(pool_id, client_id)
        metadata = _metadata(client_metadata)
        now = _time(now)
        if not isinstance(prevent_user_existence_errors, bool):
            _invalid("Invalid PreventUserExistenceErrors")
        if user is None:
            username = _username(username)
            if not prevent_user_existence_errors:
                raise MfaPasswordlessError("UserNotFoundException", "User does not exist")
            synthetic = True
            available = _synthetic_challenges(policy)
        else:
            _validate_user(user)
            if username is not None and username != user.username:
                _invalid("Username does not match resolved user")
            username = user.username
            synthetic = False
            available = available_user_auth_challenges(policy, user)
        if not available:
            raise MfaPasswordlessError("NotAuthorizedException", "No available authentication factors")
        if preferred_challenge is None:
            return self._start_primary(
                challenge_name="SELECT_CHALLENGE",
                available=available,
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                metadata=metadata,
                synthetic=synthetic,
                now=now,
            )
        if preferred_challenge not in _USER_AUTH_CHALLENGES or preferred_challenge not in available:
            _invalid("Preferred challenge is not available")
        return self._start_selected(
            challenge_name=preferred_challenge,
            policy=policy,
            user=user,
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=metadata,
            synthetic=synthetic,
            sender=sender,
            now=now,
            code_factory=code_factory,
        )

    def respond_select_challenge(
        self,
        *,
        policy: PoolAuthPolicy,
        user: UserAuthState | None,
        session: Any,
        answer: Any,
        username: Any,
        pool_id: Any,
        client_id: Any,
        sender: OtpDeliveryPort,
        now: datetime,
        code_factory=None,
    ) -> dict[str, Any]:
        validate_pool_auth_policy(policy)
        pool_id, client_id = _scope(pool_id, client_id)
        username = _username(username)
        now = _time(now)
        if answer not in _USER_AUTH_CHALLENGES:
            _invalid("Invalid SELECT_CHALLENGE ANSWER")
        selected = self._consume(
            session=session,
            challenge_name="SELECT_CHALLENGE",
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            now=now,
        )
        if answer not in selected.available_challenges:
            _invalid("Selected challenge is not available")
        if not selected.synthetic:
            _validate_user(user)
            if user.username != username:
                raise MfaPasswordlessError(
                    "NotAuthorizedException", "Invalid authentication session"
                )
        return self._start_selected(
            challenge_name=answer,
            policy=policy,
            user=user,
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=selected.client_metadata,
            synthetic=selected.synthetic,
            sender=sender,
            now=now,
            code_factory=code_factory,
        )

    def consume_primary_challenge(
        self,
        *,
        challenge_name: Any,
        session: Any,
        username: Any,
        pool_id: Any,
        client_id: Any,
        now: datetime,
    ) -> AuthChallengeCompletion:
        if challenge_name not in {"PASSWORD", "PASSWORD_SRP", "WEB_AUTHN"}:
            _invalid("Invalid primary challenge")
        pool_id, client_id = _scope(pool_id, client_id)
        consumed = self._consume(
            session=session,
            challenge_name=challenge_name,
            pool_id=pool_id,
            client_id=client_id,
            username=_username(username),
            now=_time(now),
        )
        if consumed.synthetic:
            raise MfaPasswordlessError("NotAuthorizedException", "Incorrect username or password")
        return _completion(consumed)

    def start_mfa(
        self,
        *,
        policy: PoolAuthPolicy,
        user: UserAuthState,
        pool_id: Any,
        client_id: Any,
        client_metadata: Any,
        sender: OtpDeliveryPort,
        now: datetime,
        device_key: str | None = None,
        code_factory=None,
    ) -> dict[str, Any]:
        validate_pool_auth_policy(policy)
        _validate_user(user)
        device_key = _optional_device_key(device_key)
        if policy.mfa_configuration == "OFF":
            _invalid("MFA is disabled")
        enabled = []
        if user.sms_mfa_enabled:
            _eligible_destination(policy, user, "phone_number", policy.sms_mfa is not None)
            enabled.append("SMS_MFA")
        if user.email_mfa_enabled:
            _eligible_destination(policy, user, "email", policy.email_mfa is not None)
            enabled.append("EMAIL_OTP")
        if not enabled:
            raise MfaPasswordlessError("InvalidParameterException", "User has no enabled MFA factor")
        if user.sms_mfa_preferred:
            challenge = "SMS_MFA"
        elif user.email_mfa_preferred:
            challenge = "EMAIL_OTP"
        elif len(enabled) > 1:
            pool_id, client_id = _scope(pool_id, client_id)
            return self._start_primary(
                challenge_name="SELECT_MFA_TYPE",
                available=enabled,
                pool_id=pool_id,
                client_id=client_id,
                username=user.username,
                metadata=_metadata(client_metadata),
                synthetic=False,
                now=_time(now),
                device_key=device_key,
            )
        else:
            challenge = enabled[0]
        pool_id, client_id = _scope(pool_id, client_id)
        return self._start_otp(
            challenge_name=challenge,
            purpose="SMS_MFA" if challenge == "SMS_MFA" else "EMAIL_MFA",
            policy=policy,
            user=user,
            pool_id=pool_id,
            client_id=client_id,
            username=user.username,
            metadata=_metadata(client_metadata),
            synthetic=False,
            sender=sender,
            now=_time(now),
            code_factory=code_factory,
            mark_verified=True,
            confirm_user=False,
            device_key=device_key,
        )

    def respond_select_mfa(
        self,
        *,
        policy: PoolAuthPolicy,
        user: UserAuthState,
        session: Any,
        answer: Any,
        username: Any,
        pool_id: Any,
        client_id: Any,
        sender: OtpDeliveryPort,
        now: datetime,
        code_factory=None,
    ) -> dict[str, Any]:
        validate_pool_auth_policy(policy)
        _validate_user(user)
        pool_id, client_id = _scope(pool_id, client_id)
        username = _username(username)
        now = _time(now)
        if answer not in {"EMAIL_OTP", "SMS_MFA"}:
            _invalid("Invalid SELECT_MFA_TYPE ANSWER")
        selected = self._consume(
            session=session,
            challenge_name="SELECT_MFA_TYPE",
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            now=now,
        )
        if answer not in selected.available_challenges or user.username != username:
            raise MfaPasswordlessError("NotAuthorizedException", "Invalid authentication session")
        return self._start_otp(
            challenge_name=answer,
            purpose="SMS_MFA" if answer == "SMS_MFA" else "EMAIL_MFA",
            policy=policy,
            user=user,
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=selected.client_metadata,
            synthetic=False,
            sender=sender,
            now=now,
            code_factory=code_factory,
            mark_verified=True,
            confirm_user=False,
            device_key=selected.device_key,
        )

    def complete_otp(
        self,
        *,
        challenge_name: Any,
        session: Any,
        username: Any,
        response_code: Any,
        response_value: Any,
        pool_id: Any,
        client_id: Any,
        now: datetime,
    ) -> AuthChallengeCompletion:
        if challenge_name not in _OTP_CONTRACTS:
            _invalid("Invalid OTP challenge")
        pool_id, client_id = _scope(pool_id, client_id)
        username = _username(username)
        now = _time(now)
        token_hash = _token_hash(session)
        with self._lock:
            self._prune_locked(now)
            stored = self._sessions.get(token_hash)
            if not self._matches(stored, challenge_name, pool_id, client_id, username):
                raise MfaPasswordlessError(
                    "NotAuthorizedException", "Invalid authentication session"
                )
            if response_code != stored.response_key:
                _invalid("Invalid challenge response field")
            valid_code = isinstance(response_value, str) and re.fullmatch(r"[0-9]{6}", response_value)
            actual = self._code_digest(stored, response_value) if valid_code else ""
            if not valid_code or not hmac.compare_digest(stored.code_digest or "", actual):
                stored.failed_attempts += 1
                if stored.failed_attempts >= self._maximum_code_attempts:
                    self._remove_locked(stored)
                raise MfaPasswordlessError("CodeMismatchException", "Invalid verification code")
            if stored.synthetic:
                self._remove_locked(stored)
                raise MfaPasswordlessError("NotAuthorizedException", "Incorrect username or code")
            self._remove_locked(stored)
            return _completion(stored)

    def _start_selected(
        self,
        *,
        challenge_name: str,
        policy: PoolAuthPolicy,
        user: UserAuthState | None,
        pool_id: str,
        client_id: str,
        username: str,
        metadata: dict[str, str],
        synthetic: bool,
        sender: OtpDeliveryPort,
        now: datetime,
        code_factory,
    ) -> dict[str, Any]:
        if challenge_name in {"EMAIL_OTP", "SMS_OTP"}:
            return self._start_otp(
                challenge_name=challenge_name,
                purpose=challenge_name,
                policy=policy,
                user=user,
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                metadata=metadata,
                synthetic=synthetic,
                sender=sender,
                now=now,
                code_factory=code_factory,
                mark_verified=True,
                confirm_user=True,
                device_key=None,
            )
        return self._start_primary(
            challenge_name=challenge_name,
            available=(),
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=metadata,
            synthetic=synthetic,
            now=now,
        )

    def _start_primary(
        self,
        *,
        challenge_name: str,
        available: list[str] | tuple[str, ...],
        pool_id: str,
        client_id: str,
        username: str,
        metadata: dict[str, str],
        synthetic: bool,
        now: datetime,
        device_key: str | None = None,
    ) -> dict[str, Any]:
        raw, stored = self._reserve(
            challenge_name=challenge_name,
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=metadata,
            synthetic=synthetic,
            now=now,
            available=tuple(available),
            device_key=device_key,
        )
        with self._lock:
            stored.state = ChallengeState.ACTIVE
        response: dict[str, Any] = {
            "ChallengeName": challenge_name,
            "ChallengeParameters": {"USERNAME": username},
            "Session": raw,
        }
        if challenge_name == "SELECT_CHALLENGE":
            response["AvailableChallenges"] = list(available)
        elif challenge_name == "SELECT_MFA_TYPE":
            response["ChallengeParameters"]["MFAS_CAN_CHOOSE"] = json.dumps(
                list(available), separators=(",", ":")
            )
        return response

    def _start_otp(
        self,
        *,
        challenge_name: str,
        purpose: str,
        policy: PoolAuthPolicy,
        user: UserAuthState | None,
        pool_id: str,
        client_id: str,
        username: str,
        metadata: dict[str, str],
        synthetic: bool,
        sender: OtpDeliveryPort,
        now: datetime,
        code_factory,
        mark_verified: bool,
        confirm_user: bool,
        device_key: str | None,
    ) -> dict[str, Any]:
        medium, attribute, response_key = _OTP_CONTRACTS[challenge_name]
        if synthetic:
            destination = "unknown@example.invalid" if medium == "EMAIL" else "+10000000000"
        else:
            _validate_user(user)
            if (confirm_user and attribute not in policy.auto_verified_attributes) or not (
                _has_destination(user, attribute)
            ):
                _invalid(f"A valid {attribute} destination is required")
            destination = user.attributes[attribute]
        code = _code(code_factory)
        raw, stored = self._reserve(
            challenge_name=challenge_name,
            pool_id=pool_id,
            client_id=client_id,
            username=username,
            metadata=metadata,
            synthetic=synthetic,
            now=now,
            response_key=response_key,
            verified_attribute=attribute if mark_verified else None,
            confirm_user=confirm_user,
            device_key=device_key,
        )
        stored.code_digest = self._code_digest(stored, code)
        if not synthetic:
            request = OtpDeliveryRequest(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                purpose=purpose,
                medium=medium,
                destination=destination,
                secret=code,
                client_metadata=dict(metadata),
            )
            try:
                message_id = sender.deliver_otp(
                    request,
                    stored.token_hash,
                    commit=lambda reservation_id: self._commit_delivery(
                        stored, reservation_id
                    ),
                    rollback=lambda reservation_id: self._rollback_delivery(
                        stored, reservation_id
                    ),
                )
                if not isinstance(message_id, str) or not 1 <= len(message_id) <= 1_024:
                    raise ValueError("OTP delivery returned an invalid message identifier")
            except Exception:
                self._rollback_delivery(stored, stored.token_hash)
                raise
        elif not self._commit_delivery(stored, stored.token_hash):
            raise MfaPasswordlessError(
                "NotAuthorizedException", "Notification state changed before activation"
            )
        with self._lock:
            if (
                stored.state is not ChallengeState.ACTIVE
                or self._sessions.get(stored.token_hash) is not stored
                or self._generations.get(stored.binding) != stored.generation
            ):
                self._rollback_delivery(stored, stored.token_hash)
                raise MfaPasswordlessError(
                    "NotAuthorizedException", "Notification state changed before activation"
                )
        return {
            "ChallengeName": challenge_name,
            "ChallengeParameters": {
                "CODE_DELIVERY_DELIVERY_MEDIUM": medium,
                "CODE_DELIVERY_DESTINATION": _mask_destination(destination, medium),
                "USERNAME": username,
            },
            "Session": raw,
        }

    def _commit_delivery(self, stored: _AuthSession, reservation_id: str) -> bool:
        with self._lock:
            current = self._sessions.get(stored.token_hash)
            if (
                not isinstance(reservation_id, str)
                or not hmac.compare_digest(reservation_id, stored.token_hash)
                or current is not stored
                or self._generations.get(stored.binding) != stored.generation
            ):
                return False
            stored.state = ChallengeState.ACTIVE
            return True

    def _rollback_delivery(self, stored: _AuthSession, reservation_id: str) -> None:
        with self._lock:
            if not isinstance(reservation_id, str) or not hmac.compare_digest(
                reservation_id, stored.token_hash
            ):
                return
            current = self._sessions.get(stored.token_hash)
            if current is stored:
                self._remove_locked(stored)

    def _reserve(
        self,
        *,
        challenge_name: str,
        pool_id: str,
        client_id: str,
        username: str,
        metadata: dict[str, str],
        synthetic: bool,
        now: datetime,
        available: tuple[str, ...] = (),
        response_key: str | None = None,
        verified_attribute: str | None = None,
        confirm_user: bool = False,
        device_key: str | None = None,
    ) -> tuple[str, _AuthSession]:
        binding = (pool_id, client_id, username, challenge_name)
        raw = secrets.token_urlsafe(48)
        token_hash = _token_hash(raw)
        with self._lock:
            self._prune_locked(now)
            for existing in list(self._sessions.values()):
                if existing.binding == binding:
                    self._remove_locked(existing)
            if len(self._sessions) >= self._maximum_sessions:
                raise MfaPasswordlessError("LimitExceededException", "Challenge session quota exceeded")
            generation = self._generations.get(binding, 0) + 1
            self._generations[binding] = generation
            stored = _AuthSession(
                token_hash=token_hash,
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                challenge_name=challenge_name,
                state=ChallengeState.PENDING,
                created_at=now,
                expires_at=now + self._challenge_ttl,
                generation=generation,
                binding=binding,
                client_metadata=dict(metadata),
                synthetic=synthetic,
                available_challenges=available,
                response_key=response_key,
                verified_attribute=verified_attribute,
                confirm_user=confirm_user,
                device_key=device_key,
            )
            self._sessions[token_hash] = stored
        return raw, stored

    def _consume(
        self,
        *,
        session: Any,
        challenge_name: str,
        pool_id: str,
        client_id: str,
        username: str,
        now: datetime,
    ) -> _AuthSession:
        token_hash = _token_hash(session)
        with self._lock:
            self._prune_locked(now)
            stored = self._sessions.get(token_hash)
            if not self._matches(stored, challenge_name, pool_id, client_id, username):
                raise MfaPasswordlessError(
                    "NotAuthorizedException", "Invalid authentication session"
                )
            self._remove_locked(stored)
            return stored

    @staticmethod
    def _matches(
        stored: _AuthSession | None,
        challenge_name: str,
        pool_id: str,
        client_id: str,
        username: str,
    ) -> bool:
        return bool(
            stored is not None
            and stored.state is ChallengeState.ACTIVE
            and hmac.compare_digest(stored.challenge_name, challenge_name)
            and hmac.compare_digest(stored.pool_id, pool_id)
            and hmac.compare_digest(stored.client_id, client_id)
            and hmac.compare_digest(stored.username, username)
        )

    def _code_digest(self, stored: _AuthSession, code: str) -> str:
        binding = ":".join((*stored.binding, stored.token_hash, code)).encode()
        return hmac.new(self._signing_key, binding, hashlib.sha256).hexdigest()

    def _remove_locked(self, stored: _AuthSession) -> None:
        self._sessions.pop(stored.token_hash, None)
        if self._generations.get(stored.binding) == stored.generation:
            self._generations.pop(stored.binding, None)

    def _prune_locked(self, now: datetime) -> None:
        for stored in list(self._sessions.values()):
            if stored.expires_at <= now:
                self._remove_locked(stored)


def _completion(stored: _AuthSession) -> AuthChallengeCompletion:
    return AuthChallengeCompletion(
        username=stored.username,
        challenge_name=stored.challenge_name,
        client_metadata=dict(stored.client_metadata),
        verified_attribute=stored.verified_attribute,
        confirm_user=stored.confirm_user,
        synthetic=stored.synthetic,
        device_key=stored.device_key,
    )


def _optional_device_key(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        _invalid("Invalid device key")
    return value


def _synthetic_challenges(policy: PoolAuthPolicy) -> list[str]:
    result = []
    if "PASSWORD" in policy.allowed_first_auth_factors:
        result.extend(("PASSWORD", "PASSWORD_SRP"))
    if "EMAIL_OTP" in policy.allowed_first_auth_factors:
        result.append("EMAIL_OTP")
    if "SMS_OTP" in policy.allowed_first_auth_factors:
        result.append("SMS_OTP")
    if "WEB_AUTHN" in policy.allowed_first_auth_factors:
        result.append("WEB_AUTHN")
    return result


def _preference(
    value: Any, *, current_enabled: bool, current_preferred: bool
) -> tuple[bool, bool]:
    if value is None:
        return current_enabled, current_preferred
    if not isinstance(value, dict) or not set(value) <= {"Enabled", "PreferredMfa"} or not value:
        _invalid("Invalid MFA preference")
    if any(not isinstance(item, bool) for item in value.values()):
        _invalid("Invalid MFA preference")
    enabled = value.get("Enabled", current_enabled)
    preferred = value.get("PreferredMfa", current_preferred)
    if value.get("PreferredMfa") is True and not enabled:
        _invalid("A preferred MFA factor must be enabled")
    if not enabled:
        preferred = False
    return enabled, preferred


def _eligible_destination(
    policy: PoolAuthPolicy,
    user: UserAuthState,
    attribute: str,
    configured: bool,
) -> None:
    if not configured:
        _invalid(f"{attribute} MFA factor is not configured")
    if not _has_destination(user, attribute):
        _invalid(f"A valid {attribute} destination is required")


def _has_verified(user: UserAuthState, attribute: str) -> bool:
    return attribute in user.verified_attributes and _has_destination(user, attribute)


def _has_destination(user: UserAuthState, attribute: str) -> bool:
    value = user.attributes.get(attribute)
    if attribute == "email":
        valid = _valid_email(value)
    else:
        valid = isinstance(value, str) and re.fullmatch(r"\+[1-9][0-9]{1,14}", value) is not None
    return bool(valid)


def _validate_user(value: Any) -> None:
    if not isinstance(value, UserAuthState):
        _invalid("Invalid user authentication state")
    _username(value.username)
    if not all(
        isinstance(setting, bool)
        for setting in (
            value.password_enabled,
            value.email_mfa_enabled,
            value.email_mfa_preferred,
            value.sms_mfa_enabled,
            value.sms_mfa_preferred,
            value.software_token_mfa_enabled,
            value.software_token_mfa_preferred,
            value.web_authn_enabled,
        )
    ):
        _invalid("Invalid user factor state")
    if (
        not isinstance(value.attributes, dict)
        or len(value.attributes) > 64
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or len(key) > 128
            or len(item) > 2_048
            for key, item in value.attributes.items()
        )
        or not isinstance(value.verified_attributes, frozenset)
        or not value.verified_attributes <= _AUTO_VERIFIED_ATTRIBUTES
    ):
        _invalid("Invalid user attributes")


def _sms_configuration(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or not value
        or not set(value) <= _SMS_CONFIGURATION_FIELDS
        or len(repr(value)) > 8_192
    ):
        _invalid("Invalid SmsConfiguration")
    caller = value.get("SnsCallerArn")
    eums = value.get("EumsSms")
    if caller is None and not (isinstance(eums, dict) and eums.get("CallerArn")):
        _invalid("SmsConfiguration requires a caller ARN")


def _message(value: Any, field: str, maximum: int) -> None:
    result = _text(value, field, maximum)
    if len(result) < 6 or "{####}" not in result:
        _invalid(f"{field} must contain {{####}}")


def _text(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\x00" in value
        or "\r" in value
    ):
        _invalid(f"Invalid {field}")
    return value


def _scope(pool_id: Any, client_id: Any) -> tuple[str, str]:
    if (
        not isinstance(pool_id, str)
        or not 1 <= len(pool_id) <= 55
        or _POOL_ID.fullmatch(pool_id) is None
        or not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 128
        or re.fullmatch(r"[\w+]+", client_id) is None
    ):
        _invalid("Invalid user pool/client scope")
    return pool_id, client_id


def _username(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or "\x00" in value:
        _invalid("Invalid Username")
    return value


def _metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 20:
        _invalid("Invalid ClientMetadata")
    result = {}
    total = 0
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(item, str)
            or len(item) > 2_048
        ):
            _invalid("Invalid ClientMetadata")
        total += len(key) + len(item)
        result[key] = item
    if total > 10_240:
        _invalid("Invalid ClientMetadata")
    return result


def _code(factory) -> str:
    value = factory() if factory is not None else f"{secrets.randbelow(1_000_000):06d}"
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{6}", value) is None:
        _invalid("Invalid generated OTP code")
    return value


def _token_hash(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 2_048
        or any(character.isspace() for character in value)
    ):
        raise MfaPasswordlessError("NotAuthorizedException", "Invalid authentication session")
    return hashlib.sha256(value.encode()).hexdigest()


def _time(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _invalid("Invalid challenge clock")
    return value


def _mask_destination(_value: str, medium: str) -> str:
    if medium == "EMAIL":
        return "***@***.***"
    return "+***********"


def _valid_email(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) <= 320
        and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value)
    )


def _invalid(message: str) -> None:
    raise MfaPasswordlessError("InvalidParameterException", message)
