import base64
import binascii
import dataclasses
import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote_plus, urlsplit

from localstack.services.cognito_idp.tokens import sign_jwt

MAX_CLIENT_METADATA_BYTES = 128 * 1024
MAX_CLIENT_METADATA_ENTRIES = 32
_WELL_KNOWN_SCOPES = {"aws.cognito.signin.user.admin", "email", "openid", "phone", "profile"}
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_POOL_ID = re.compile(r"[\w-]+_[0-9A-Za-z]+")


class ClientCredentialsError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class ClientCredentialsConfig:
    client_id: str
    secret_hashes: tuple[str, ...]
    allowed_flows: tuple[str, ...]
    allowed_scopes: frozenset[str]
    access_token_ttl_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or not 1 <= len(self.client_id) <= 128:
            raise ClientCredentialsError("Invalid OAuth client")
        if not isinstance(self.secret_hashes, tuple) or len(self.secret_hashes) > 4:
            raise ClientCredentialsError("Invalid OAuth client secrets")
        if any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in self.secret_hashes
        ):
            raise ClientCredentialsError("Invalid OAuth client secrets")
        if not isinstance(self.allowed_flows, tuple) or len(self.allowed_flows) > 3:
            raise ClientCredentialsError("Invalid OAuth client flows")
        if (
            not isinstance(self.allowed_scopes, frozenset)
            or not 1 <= len(self.allowed_scopes) <= 50
        ):
            raise ClientCredentialsError("Invalid OAuth client scopes")
        if any(not _is_custom_scope(value) for value in self.allowed_scopes):
            raise ClientCredentialsError("Only custom resource-server scopes are valid")
        if (
            not isinstance(self.access_token_ttl_seconds, int)
            or isinstance(self.access_token_ttl_seconds, bool)
            or not 300 <= self.access_token_ttl_seconds <= 86_400
        ):
            raise ClientCredentialsError("Invalid access-token validity")


@dataclasses.dataclass(frozen=True)
class ClientCredentialsResult:
    token_response: dict[str, Any]
    scopes: tuple[str, ...]
    client_metadata: dict[str, str]


def issue_client_credentials_token(
    *,
    config: ClientCredentialsConfig,
    authorization: Any,
    form: Any,
    issuer: Any,
    signing_key_id: Any,
    signing_private_key: Any,
    now: datetime | None = None,
) -> ClientCredentialsResult:
    if not isinstance(config, ClientCredentialsConfig):
        raise ClientCredentialsError("Invalid OAuth client")
    if config.allowed_flows != ("client_credentials",):
        raise ClientCredentialsError("client_credentials must be enabled exclusively")
    if not config.secret_hashes:
        raise ClientCredentialsError("client_credentials requires a confidential client")
    form = _form(form)
    if form.get("grant_type") != "client_credentials":
        raise ClientCredentialsError("Unsupported grant_type")
    client_id, client_secret = _client_authentication(authorization, form)
    if client_id != config.client_id or not _secret_matches(client_secret, config.secret_hashes):
        raise ClientCredentialsError("Invalid client credentials")
    scopes = _scopes(form.get("scope"), config.allowed_scopes)
    metadata = _client_metadata(form.get("aws_client_metadata"))
    issuer = _issuer(issuer)
    current = _utc(now or datetime.now(UTC))
    issued_at = int(current.timestamp())
    claims = {
        "auth_time": issued_at,
        "client_id": config.client_id,
        "exp": issued_at + config.access_token_ttl_seconds,
        "iss": issuer,
        "jti": secrets.token_urlsafe(16),
        "scope": " ".join(scopes),
        "sub": config.client_id,
        "token_use": "access",
        "version": 2,
    }
    if not isinstance(signing_key_id, str) or not 1 <= len(signing_key_id) <= 256:
        raise ClientCredentialsError("Invalid signing key")
    if not isinstance(signing_private_key, bytes) or len(signing_private_key) > 64 * 1024:
        raise ClientCredentialsError("Invalid signing key")
    try:
        access_token = sign_jwt(
            signing_private_key,
            signing_key_id,
            claims,
            now=issued_at,
        )
    except (TypeError, ValueError) as error:
        raise ClientCredentialsError("Invalid signing key") from error
    return ClientCredentialsResult(
        token_response={
            "access_token": access_token,
            "expires_in": config.access_token_ttl_seconds,
            "token_type": "Bearer",
        },
        scopes=scopes,
        client_metadata=metadata,
    )


def build_machine_token_trigger_event(
    *,
    region: Any,
    pool_id: Any,
    client_id: Any,
    scopes: Any,
    client_metadata: Any,
) -> dict[str, Any]:
    if (
        not isinstance(region, str)
        or _REGION.fullmatch(region) is None
        or not isinstance(pool_id, str)
        or _POOL_ID.fullmatch(pool_id) is None
        or not isinstance(client_id, str)
        or not 1 <= len(client_id) <= 128
    ):
        raise ClientCredentialsError("Invalid machine-token trigger scope")
    if (
        not isinstance(scopes, tuple)
        or len(scopes) > 50
        or any(not _is_custom_scope(value) for value in scopes)
    ):
        raise ClientCredentialsError("Invalid machine-token scopes")
    metadata = _validated_metadata_map(client_metadata)
    return {
        "callerContext": {"awsSdkVersion": "local", "clientId": client_id},
        "region": region,
        "request": {
            "clientMetadata": metadata,
            "scopes": list(scopes),
        },
        "response": {"claimsAndScopeOverrideDetails": None},
        "triggerSource": "TokenGeneration_ClientCredentials",
        "userName": client_id,
        "userPoolId": pool_id,
        "version": "3",
    }


def _form(value: Any) -> dict[str, str]:
    allowed = {
        "aws_client_metadata",
        "client_id",
        "client_secret",
        "grant_type",
        "scope",
    }
    if (
        not isinstance(value, dict)
        or len(value) > len(allowed)
        or set(value) - allowed
        or any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items())
    ):
        raise ClientCredentialsError("Invalid token request")
    return dict(value)


def _client_authentication(authorization: Any, form: dict[str, str]) -> tuple[str, str]:
    has_post = "client_id" in form or "client_secret" in form
    has_basic = authorization not in (None, "")
    if has_post and has_basic:
        raise ClientCredentialsError("Use exactly one authentication method")
    if has_basic:
        if not isinstance(authorization, str) or not authorization.startswith("Basic "):
            raise ClientCredentialsError("Invalid client authentication")
        encoded = authorization.removeprefix("Basic ")
        if not 1 <= len(encoded) <= 4096 or any(character.isspace() for character in encoded):
            raise ClientCredentialsError("Invalid client authentication")
        try:
            raw = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise ClientCredentialsError("Invalid client authentication") from error
        if ":" not in raw:
            raise ClientCredentialsError("Invalid client authentication")
        client_id, secret = (unquote_plus(part) for part in raw.split(":", 1))
    else:
        if set(form).intersection({"client_id", "client_secret"}) != {
            "client_id",
            "client_secret",
        }:
            raise ClientCredentialsError("Use exactly one authentication method")
        client_id, secret = form["client_id"], form["client_secret"]
    if not 1 <= len(client_id) <= 128 or not 1 <= len(secret) <= 1024:
        raise ClientCredentialsError("Invalid client authentication")
    return client_id, secret


def _secret_matches(secret: str, candidates: tuple[str, ...]) -> bool:
    digest = hashlib.sha256(secret.encode()).hexdigest()
    matches = [hmac.compare_digest(digest, candidate) for candidate in candidates]
    return any(matches)


def _scopes(requested: str | None, allowed: frozenset[str]) -> tuple[str, ...]:
    if requested is None or requested == "":
        scopes = tuple(sorted(allowed))
    else:
        if len(requested) > 25_600 or any(
            character.isspace() and character != " " for character in requested
        ):
            raise ClientCredentialsError("Invalid OAuth scope")
        values = requested.split(" ")
        if not values or len(values) > 50 or "" in values or len(values) != len(set(values)):
            raise ClientCredentialsError("Invalid OAuth scope")
        scopes = tuple(values)
    if any(not _is_custom_scope(scope) for scope in scopes):
        raise ClientCredentialsError("Only custom resource-server scopes are supported")
    if any(scope not in allowed for scope in scopes):
        raise ClientCredentialsError("OAuth scope is not allowed for this client")
    return scopes


def _is_custom_scope(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 256
        and value not in _WELL_KNOWN_SCOPES
        and "/" in value
        and not value.startswith("/")
        and not value.endswith("/")
        and not any(character.isspace() or ord(character) < 0x21 for character in value)
    )


def _client_metadata(value: str | None) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if not isinstance(value, str) or len(value.encode()) > MAX_CLIENT_METADATA_BYTES:
        raise ClientCredentialsError("Invalid aws_client_metadata")

    def pairs(values):
        result = {}
        for key, item in values:
            if key in result:
                raise ClientCredentialsError("Invalid aws_client_metadata: duplicate key")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ClientCredentialsError("Invalid aws_client_metadata") from error
    return _validated_metadata_map(parsed)


def _validated_metadata_map(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or len(value) > MAX_CLIENT_METADATA_ENTRIES
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or len(key.encode()) > 131_072
            or len(item.encode()) > 131_072
            for key, item in value.items()
        )
    ):
        raise ClientCredentialsError("Invalid aws_client_metadata")
    return dict(value)


def _issuer(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ClientCredentialsError("Invalid token issuer")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ClientCredentialsError("Invalid token issuer")
    return value.rstrip("/")


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ClientCredentialsError("Invalid token clock")
    return value.astimezone(UTC)
