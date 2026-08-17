import dataclasses
import hashlib
import html
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

MAX_CONFIRMATION_LINKS = 10_000
DEFAULT_CONFIRMATION_LINK_TTL = timedelta(minutes=15)
_LINK_PLACEHOLDER = re.compile(r"\{##([^{}]+)##\}")
_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_POOL_ID = re.compile(r"[\w-]+_[0-9A-Za-z]+")
_CLIENT_ID = re.compile(r"[\w+]{1,128}")
_TEMPLATE_FIELDS = {
    "DefaultEmailOption",
    "EmailMessage",
    "EmailMessageByLink",
    "EmailSubject",
    "EmailSubjectByLink",
    "SmsMessage",
}


class ConfirmationLinkError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class ConfirmationLinkEntry:
    account_id: str
    region: str
    pool_id: str
    client_id: str
    username: str
    created_at: datetime
    expires_at: datetime


@dataclasses.dataclass
class ConfirmationLinkState:
    entries: dict[str, ConfirmationLinkEntry] = dataclasses.field(default_factory=dict)
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
class IssuedConfirmationLink:
    token: str
    url: str
    rendered_message: str
    subject: str | None
    expires_at: datetime


class ConfirmationLinkManager:
    def __init__(
        self,
        state: ConfirmationLinkState,
        *,
        now=None,
        ttl: timedelta = DEFAULT_CONFIRMATION_LINK_TTL,
    ):
        if not isinstance(state, ConfirmationLinkState):
            raise ConfirmationLinkError("Invalid confirmation-link state")
        if not isinstance(ttl, timedelta) or not timedelta(minutes=1) <= ttl <= timedelta(days=1):
            raise ConfirmationLinkError("Invalid confirmation-link TTL")
        self.state = state
        self._now = now or (lambda: datetime.now(UTC))
        self._ttl = ttl

    def issue(
        self,
        *,
        account_id: Any,
        region: Any,
        pool_id: Any,
        client_id: Any,
        username: Any,
        base_url: Any,
        allowed_hostnames: Any,
        template: Any,
    ) -> IssuedConfirmationLink:
        scope = _scope(account_id, region, pool_id, client_id, username)
        normalized = validate_verification_message_template(template)
        if normalized["DefaultEmailOption"] != "CONFIRM_WITH_LINK":
            raise ConfirmationLinkError("Confirmation-link template must use CONFIRM_WITH_LINK")
        endpoint = _owned_https_endpoint(base_url, allowed_hostnames)
        now = _utc_now(self._now())
        token = secrets.token_urlsafe(48)
        token_hash = _token_hash(token)
        entry = ConfirmationLinkEntry(*scope, created_at=now, expires_at=now + self._ttl)
        with self.state._lock:
            self._prune(now)
            self.state.entries = {
                key: value
                for key, value in self.state.entries.items()
                if (value.account_id, value.region, value.pool_id, value.client_id, value.username)
                != scope
            }
            if len(self.state.entries) >= MAX_CONFIRMATION_LINKS:
                raise ConfirmationLinkError("Confirmation-link quota exceeded")
            self.state.entries[token_hash] = entry
        query = urlencode(
            {
                "client_id": client_id,
                "user_name": username,
                "confirmation_code": token,
            }
        )
        url = urlunsplit((endpoint.scheme, endpoint.netloc, "/confirmUser", query, ""))
        message = normalized["EmailMessageByLink"]
        match = _LINK_PLACEHOLDER.search(message)
        link = f'<a href="{html.escape(url, quote=True)}">{html.escape(match.group(1))}</a>'
        rendered = f"{message[: match.start()]}{link}{message[match.end() :]}"
        return IssuedConfirmationLink(
            token=token,
            url=url,
            rendered_message=rendered,
            subject=normalized.get("EmailSubjectByLink"),
            expires_at=entry.expires_at,
        )

    def consume(
        self,
        *,
        token: Any,
        account_id: Any,
        region: Any,
        pool_id: Any,
        client_id: Any,
        username: Any,
    ) -> ConfirmationLinkEntry:
        scope = _scope(account_id, region, pool_id, client_id, username)
        if not isinstance(token, str) or not 20 <= len(token) <= 2048:
            raise ConfirmationLinkError("Invalid or expired confirmation link")
        now = _utc_now(self._now())
        with self.state._lock:
            self._prune(now)
            entry = self.state.entries.pop(_token_hash(token), None)
        if entry is None or entry.expires_at <= now:
            raise ConfirmationLinkError("Invalid or expired confirmation link")
        if (
            entry.account_id,
            entry.region,
            entry.pool_id,
            entry.client_id,
            entry.username,
        ) != scope:
            raise ConfirmationLinkError("Invalid or expired confirmation link")
        return entry

    def cleanup_pool(self, pool_id: Any) -> None:
        if not isinstance(pool_id, str):
            return
        with self.state._lock:
            self.state.entries = {
                key: value for key, value in self.state.entries.items() if value.pool_id != pool_id
            }

    def cleanup_client(self, pool_id: Any, client_id: Any) -> None:
        with self.state._lock:
            self.state.entries = {
                key: value
                for key, value in self.state.entries.items()
                if (value.pool_id, value.client_id) != (pool_id, client_id)
            }

    def cleanup_user(self, pool_id: Any, username: Any) -> None:
        with self.state._lock:
            self.state.entries = {
                key: value
                for key, value in self.state.entries.items()
                if (value.pool_id, value.username) != (pool_id, username)
            }

    def _prune(self, now: datetime) -> None:
        self.state.entries = {
            key: value for key, value in self.state.entries.items() if value.expires_at > now
        }


def validate_verification_message_template(template: Any) -> dict[str, str]:
    if not isinstance(template, dict) or not template or set(template) - _TEMPLATE_FIELDS:
        raise ConfirmationLinkError("Invalid verification message template")
    if any(not isinstance(value, str) for value in template.values()):
        raise ConfirmationLinkError("Invalid verification message template")
    option = template.get("DefaultEmailOption", "CONFIRM_WITH_CODE")
    if option == "CONFIRM_WITH_LINK":
        message = template.get("EmailMessageByLink")
        if (
            not isinstance(message, str)
            or not 6 <= len(message) <= 20_000
            or len(_LINK_PLACEHOLDER.findall(message)) != 1
            or "EmailMessage" in template
            or "EmailSubject" in template
        ):
            raise ConfirmationLinkError("Invalid verification message template")
        subject = template.get("EmailSubjectByLink")
        if subject is not None and not 1 <= len(subject) <= 140:
            raise ConfirmationLinkError("Invalid verification message template")
    elif option == "CONFIRM_WITH_CODE":
        message = template.get("EmailMessage")
        if (
            not isinstance(message, str)
            or not 6 <= len(message) <= 20_000
            or message.count("{####}") != 1
            or "EmailMessageByLink" in template
            or "EmailSubjectByLink" in template
        ):
            raise ConfirmationLinkError("Invalid verification message template")
        subject = template.get("EmailSubject")
        if subject is not None and not 1 <= len(subject) <= 140:
            raise ConfirmationLinkError("Invalid verification message template")
    else:
        raise ConfirmationLinkError("Invalid verification message template")
    sms = template.get("SmsMessage")
    if sms is not None and (not 6 <= len(sms) <= 140 or sms.count("{####}") != 1):
        raise ConfirmationLinkError("Invalid verification message template")
    return dict(template)


def _owned_https_endpoint(value: Any, allowed_hostnames: Any):
    if not isinstance(value, str) or len(value) > 2048:
        raise ConfirmationLinkError("Invalid confirmation-link endpoint")
    if (
        not isinstance(allowed_hostnames, (set, frozenset))
        or not 1 <= len(allowed_hostnames) <= 128
    ):
        raise ConfirmationLinkError("Invalid confirmation-link endpoint")
    if any(not isinstance(host, str) or host != host.lower() for host in allowed_hostnames):
        raise ConfirmationLinkError("Invalid confirmation-link endpoint")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfirmationLinkError("Invalid confirmation-link endpoint") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hostnames
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ConfirmationLinkError("Invalid confirmation-link endpoint")
    return parsed


def _scope(account_id, region, pool_id, client_id, username) -> tuple[str, ...]:
    if (
        not isinstance(account_id, str)
        or _ACCOUNT_ID.fullmatch(account_id) is None
        or not isinstance(region, str)
        or _REGION.fullmatch(region) is None
        or not isinstance(pool_id, str)
        or _POOL_ID.fullmatch(pool_id) is None
        or not pool_id.startswith(f"{region}_")
        or not isinstance(client_id, str)
        or _CLIENT_ID.fullmatch(client_id) is None
        or not isinstance(username, str)
        or not 1 <= len(username) <= 128
    ):
        raise ConfirmationLinkError("Invalid confirmation-link scope")
    return account_id, region, pool_id, client_id, username


def _utc_now(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ConfirmationLinkError("Invalid confirmation-link clock")
    return value.astimezone(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
