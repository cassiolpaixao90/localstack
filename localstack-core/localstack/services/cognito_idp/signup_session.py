import dataclasses
import hashlib
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

MAX_SIGNUP_SESSIONS = 10_000
DEFAULT_SIGNUP_SESSION_TTL = timedelta(minutes=3)
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_POOL_ID = re.compile(r"[\w-]+_[0-9A-Za-z]+")
_CLIENT_ID = re.compile(r"[\w+-]{1,128}")
_SUB = re.compile(r"[0-9A-Za-z-]{1,128}")


class SignupSessionError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class SignupSessionEntry:
    account_id: str
    region: str
    pool_id: str
    client_id: str
    username: str
    user_sub: str
    stage: str
    primary_factor: str | None
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass
class SignupSessionState:
    sessions: dict[str, SignupSessionEntry] = dataclasses.field(default_factory=dict)
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


@dataclasses.dataclass(frozen=True)
class SignupAuthenticationProof:
    username: str
    user_sub: str
    primary_factor: str
    first_sign_in: bool


class SignupSessionManager:
    def __init__(
        self,
        state: SignupSessionState,
        *,
        now=None,
        ttl: timedelta = DEFAULT_SIGNUP_SESSION_TTL,
    ):
        if not isinstance(state, SignupSessionState):
            raise SignupSessionError("Invalid sign-up session state")
        if not isinstance(ttl, timedelta) or not timedelta(minutes=3) <= ttl <= timedelta(
            minutes=15
        ):
            raise SignupSessionError("Invalid authentication-flow session validity")
        self.state = state
        self._now = now or (lambda: datetime.now(UTC))
        self._ttl = ttl

    def issue_signup(self, **topology) -> str:
        scope = _scope(**topology)
        return self._issue(scope, stage="CONFIRM_SIGN_UP", primary_factor=None)

    def confirm_signup(
        self,
        *,
        signup_session: Any,
        primary_factor: Any,
        **topology,
    ) -> str:
        scope = _scope(**topology)
        if primary_factor not in {"EMAIL_OTP", "SMS_OTP"}:
            raise SignupSessionError("Invalid sign-up primary factor")
        now = _utc(self._now())
        if signup_session is not None:
            if not isinstance(signup_session, str) or not 20 <= len(signup_session) <= 2048:
                raise SignupSessionError("Invalid or expired sign-up session")
            with self.state._lock:
                self._prune(now)
                entry = self.state.sessions.pop(_token_hash(signup_session), None)
            if entry is None or entry.expires_at <= now:
                raise SignupSessionError("Invalid or expired sign-up session")
            if entry.stage != "CONFIRM_SIGN_UP" or _entry_scope(entry) != scope:
                raise SignupSessionError("Sign-up session binding mismatch")
        return self._issue(
            scope,
            stage="INITIATE_AUTH",
            primary_factor=primary_factor,
            current=now,
        )

    def consume_for_initiate_auth(
        self,
        *,
        session: Any,
        auth_flow: Any,
        user_has_signed_in: Any = False,
        **topology,
    ) -> SignupAuthenticationProof:
        scope = _scope(**topology)
        if auth_flow != "USER_AUTH":
            raise SignupSessionError("Sign-up continuation is only valid for USER_AUTH")
        if not isinstance(user_has_signed_in, bool):
            raise SignupSessionError("Invalid first-sign-in state")
        if user_has_signed_in:
            raise SignupSessionError("Sign-up continuation is only valid for the first sign-in")
        if not isinstance(session, str) or not 20 <= len(session) <= 2048:
            raise SignupSessionError("Invalid or expired sign-up session")
        now = _utc(self._now())
        with self.state._lock:
            self._prune(now)
            entry = self.state.sessions.pop(_token_hash(session), None)
        if entry is None or entry.expires_at <= now:
            raise SignupSessionError("Invalid or expired sign-up session")
        if entry.stage != "INITIATE_AUTH" or _entry_scope(entry) != scope:
            raise SignupSessionError("Sign-up session binding mismatch")
        if entry.primary_factor not in {"EMAIL_OTP", "SMS_OTP"}:
            raise SignupSessionError("Invalid sign-up session factor")
        return SignupAuthenticationProof(
            username=entry.username,
            user_sub=entry.user_sub,
            primary_factor=entry.primary_factor,
            first_sign_in=True,
        )

    def cleanup_pool(self, pool_id: Any) -> None:
        with self.state._lock:
            self.state.sessions = {
                key: value for key, value in self.state.sessions.items() if value.pool_id != pool_id
            }

    def cleanup_client(self, pool_id: Any, client_id: Any) -> None:
        with self.state._lock:
            self.state.sessions = {
                key: value
                for key, value in self.state.sessions.items()
                if (value.pool_id, value.client_id) != (pool_id, client_id)
            }

    def cleanup_user(self, pool_id: Any, username: Any) -> None:
        with self.state._lock:
            self.state.sessions = {
                key: value
                for key, value in self.state.sessions.items()
                if (value.pool_id, value.username) != (pool_id, username)
            }

    def _issue(
        self,
        scope: tuple[str, ...],
        *,
        stage: str,
        primary_factor: str | None,
        current: datetime | None = None,
    ) -> str:
        now = current or _utc(self._now())
        token = secrets.token_urlsafe(48)
        entry = SignupSessionEntry(
            *scope,
            stage=stage,
            primary_factor=primary_factor,
            created_at=now,
            expires_at=now + self._ttl,
        )
        with self.state._lock:
            self._prune(now)
            if len(self.state.sessions) >= MAX_SIGNUP_SESSIONS:
                raise SignupSessionError("Sign-up session quota exceeded")
            self.state.sessions[_token_hash(token)] = entry
        return token

    def _prune(self, now: datetime) -> None:
        self.state.sessions = {
            key: value for key, value in self.state.sessions.items() if value.expires_at > now
        }


def _scope(
    *,
    account_id: Any,
    region: Any,
    pool_id: Any,
    client_id: Any,
    username: Any,
    user_sub: Any,
) -> tuple[str, ...]:
    if (
        not isinstance(account_id, str)
        or _ACCOUNT_ID.fullmatch(account_id) is None
        or not isinstance(region, str)
        or _REGION.fullmatch(region) is None
        or not isinstance(pool_id, str)
        or _POOL_ID.fullmatch(pool_id) is None
        or not isinstance(client_id, str)
        or _CLIENT_ID.fullmatch(client_id) is None
        or not isinstance(username, str)
        or not 1 <= len(username) <= 128
        or not isinstance(user_sub, str)
        or _SUB.fullmatch(user_sub) is None
    ):
        raise SignupSessionError("Invalid sign-up session scope")
    return account_id, region, pool_id, client_id, username, user_sub


def _entry_scope(entry: SignupSessionEntry) -> tuple[str, ...]:
    return (
        entry.account_id,
        entry.region,
        entry.pool_id,
        entry.client_id,
        entry.username,
        entry.user_sub,
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SignupSessionError("Invalid sign-up session clock")
    return value.astimezone(UTC)
