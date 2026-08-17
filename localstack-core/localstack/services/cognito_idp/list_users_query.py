from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

_FILTER = re.compile(
    r'^\s*(?P<quote>"?)(?P<attribute>[A-Za-z_][A-Za-z0-9_:]*)(?P=quote)\s*'
    r'(?P<operator>\^=|=)\s*"(?P<value>(?:[^"\\]|\\["\\])*)"\s*$'
)
_SEARCHABLE = frozenset(
    {
        "username",
        "email",
        "phone_number",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "cognito:user_status",
        "status",
        "sub",
    }
)
_CASE_SENSITIVE = frozenset({"username", "status"})
_TOKEN_TTL = timedelta(hours=1)


class ListUsersQueryError(ValueError):
    """The ListUsers query or pagination token is invalid."""


@dataclasses.dataclass(frozen=True)
class UserFilter:
    attribute: str
    operator: str
    value: str

    def apply(self, users: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        result = [user for user in users if self.matches(user)]
        return sorted(result, key=self.sort_key)

    def matches(self, user: Mapping[str, Any]) -> bool:
        actual = _attribute_value(user, self.attribute)
        if actual is None:
            return False
        expected = self.value
        if self.attribute not in _CASE_SENSITIVE:
            actual, expected = actual.casefold(), expected.casefold()
        return actual == expected if self.operator == "=" else actual.startswith(expected)

    def sort_key(self, user: Mapping[str, Any]) -> tuple[str, ...]:
        value = _attribute_value(user, self.attribute) or ""
        if self.attribute not in _CASE_SENSITIVE:
            value = value.casefold()
        username = _username(user)
        return value, username.casefold(), username

    @property
    def canonical(self) -> str:
        return json.dumps([self.attribute, self.operator, self.value], separators=(",", ":"))


def compile_user_filter(raw: object) -> UserFilter | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str) or len(raw) > 256:
        raise ListUsersQueryError("Invalid ListUsers filter")
    match = _FILTER.fullmatch(raw)
    if match is None:
        raise ListUsersQueryError("Invalid ListUsers filter")
    attribute = match.group("attribute")
    if attribute not in _SEARCHABLE:
        raise ListUsersQueryError("Attribute is not searchable")
    value = re.sub(r'\\(["\\])', r"\1", match.group("value"))
    return UserFilter(attribute=attribute, operator=match.group("operator"), value=value)


class ListUsersQueryPager:
    def __init__(
        self,
        *,
        secret: bytes,
        now: Callable[[], datetime] | None = None,
    ):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("pagination signing secret must contain at least 32 bytes")
        self._secret = secret
        self._now = now or (lambda: datetime.now(UTC))

    def page(
        self,
        users: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
        *,
        scope: str,
        filter_text: object,
        limit: object,
        pagination_token: object = None,
    ) -> tuple[list[Mapping[str, Any]], str | None]:
        if not isinstance(scope, str) or not scope or len(scope.encode()) > 256:
            raise ListUsersQueryError("Invalid pagination scope")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 60:
            raise ListUsersQueryError("Limit must be between 0 and 60")
        if limit == 0:
            return [], None
        compiled = compile_user_filter(filter_text)
        query = compiled.canonical if compiled else ""
        query_hash = hashlib.sha256(f"{scope}\0{query}".encode()).hexdigest()
        ordered = (
            compiled.apply(users) if compiled else sorted(users, key=lambda user: _username(user))
        )
        after: tuple[str, ...] | None = None
        if pagination_token is not None:
            payload = self._decode_token(pagination_token)
            if not hmac.compare_digest(payload.get("query", ""), query_hash):
                raise ListUsersQueryError("Pagination token doesn't match query")
            cursor = payload.get("after")
            if (
                not isinstance(cursor, list)
                or not 2 <= len(cursor) <= 3
                or not all(isinstance(item, str) for item in cursor)
            ):
                raise ListUsersQueryError("Invalid pagination token")
            after = tuple(cursor)
        key = compiled.sort_key if compiled else lambda user: (_username(user), "")
        if after is not None:
            ordered = [user for user in ordered if key(user) > after]
        result = list(ordered[:limit])
        if len(ordered) <= limit or not result:
            return result, None
        cursor = key(result[-1])
        expires = int((self._utc_now() + _TOKEN_TTL).timestamp())
        return result, self._encode_token(
            {"v": 1, "query": query_hash, "after": cursor, "exp": expires}
        )

    def _encode_token(self, payload: Mapping[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        signature = hmac.new(self._secret, raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode().rstrip("=")

    def _decode_token(self, token: object) -> dict[str, Any]:
        if not isinstance(token, str) or not 1 <= len(token) <= 4096:
            raise ListUsersQueryError("Invalid pagination token")
        try:
            decoded = base64.b64decode(
                token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
            )
            raw, signature = decoded[:-32], decoded[-32:]
            if len(raw) == 0 or not hmac.compare_digest(
                signature, hmac.new(self._secret, raw, hashlib.sha256).digest()
            ):
                raise ListUsersQueryError("Invalid pagination token")
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ListUsersQueryError("Invalid pagination token") from error
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise ListUsersQueryError("Invalid pagination token")
        expires = payload.get("exp")
        if not isinstance(expires, int) or expires <= int(self._utc_now().timestamp()):
            raise ListUsersQueryError("Pagination token expired")
        return payload

    def _utc_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        return value.astimezone(UTC)


def new_pagination_secret() -> bytes:
    return secrets.token_bytes(32)


def _attribute_value(user: Mapping[str, Any], attribute: str) -> str | None:
    if attribute == "username":
        return _username(user)
    if attribute == "cognito:user_status":
        value = user.get("UserStatus")
    elif attribute == "status":
        enabled = user.get("Enabled")
        value = str(enabled).lower() if isinstance(enabled, bool) else None
    else:
        attributes = user.get("Attributes", {})
        if isinstance(attributes, Mapping):
            value = attributes.get(attribute)
        elif isinstance(attributes, Sequence) and not isinstance(attributes, (str, bytes)):
            value = next(
                (
                    item.get("Value")
                    for item in attributes
                    if isinstance(item, Mapping) and item.get("Name") == attribute
                ),
                None,
            )
        else:
            value = None
    return value if isinstance(value, str) else None


def _username(user: Mapping[str, Any]) -> str:
    value = user.get("Username")
    if not isinstance(value, str):
        raise ListUsersQueryError("User is missing a valid username")
    return value
