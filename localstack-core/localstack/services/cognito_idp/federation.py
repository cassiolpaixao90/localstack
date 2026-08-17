from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import ssl
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from localstack import config
from localstack.services.cognito_idp.models import CognitoIdentityProvider
from localstack.services.cognito_idp.tokens import public_key_from_jwk

_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_TOKEN_BYTES = 16 * 1024
_MAX_JWKS_KEYS = 10
_TIMEOUT_SECONDS = 3
_CACHE_TTL = timedelta(minutes=5)
_METADATA_HOSTS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "instance-data",
    "instance-data.ec2.internal",
    "metadata.aws.internal",
    "metadata.google.internal",
}


class OidcFederationError(ValueError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=_TIMEOUT_SECONDS, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def secure_json_request(
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    bearer_token: str | None = None,
    allowlist: list[str] | None = None,
) -> dict[str, Any]:
    parsed, address = _validated_target(
        url, allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST if allowlist is None else allowlist
    )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    body = None
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Host": parsed.netloc,
        "User-Agent": "LocalStack-Cognito-OIDC/1",
    }
    if form is not None:
        encoded_form = urlencode(form).encode()
        if len(encoded_form) > 64 * 1024:
            raise OidcFederationError("OIDC request body exceeds limit")
        if method == "GET":
            separator = "&" if "?" in target else "?"
            target = f"{target}{separator}{encoded_form.decode()}"
        else:
            body = encoded_form
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer_token is not None:
        if not isinstance(bearer_token, str) or not 1 <= len(bearer_token) <= _MAX_TOKEN_BYTES:
            raise OidcFederationError("Invalid OIDC bearer token")
        headers["Authorization"] = f"Bearer {bearer_token}"
    connection: http.client.HTTPConnection
    if parsed.scheme == "https":
        connection = _PinnedHTTPSConnection(parsed.hostname, port, address)
    else:
        connection = http.client.HTTPConnection(address, port, timeout=_TIMEOUT_SECONDS)
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            raise OidcFederationError("OIDC redirects are disabled")
        if response.status < 200 or response.status >= 300:
            raise OidcFederationError("OIDC endpoint returned an error")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                if int(content_length) > _MAX_RESPONSE_BYTES:
                    raise OidcFederationError("OIDC response exceeds size limit")
            except ValueError as error:
                raise OidcFederationError("Invalid OIDC Content-Length") from error
        payload = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise OidcFederationError("OIDC response exceeds size limit")
        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].lower()
        if content_type not in {"application/json", "application/jwk-set+json"}:
            raise OidcFederationError("OIDC endpoint did not return JSON")
        return _strict_json_object(payload)
    except (OSError, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError) as error:
        raise OidcFederationError("OIDC endpoint request failed") from error
    finally:
        connection.close()


def oidc_configuration(provider: CognitoIdentityProvider) -> dict[str, str]:
    now = datetime.now(UTC)
    if (
        provider.discovery_document is not None
        and provider.discovery_expires_at is not None
        and provider.discovery_expires_at > now
    ):
        return dict(provider.discovery_document)
    details = provider.provider_details
    endpoint_mapping = {
        "authorization_endpoint": "authorize_url",
        "jwks_uri": "jwks_uri",
        "token_endpoint": "token_url",
        "userinfo_endpoint": "attributes_url",
    }
    if all(field in details for field in endpoint_mapping.values()):
        document = {
            "issuer": details["oidc_issuer"],
            **{output: details[source] for output, source in endpoint_mapping.items()},
        }
    else:
        document = secure_json_request(f"{details['oidc_issuer']}/.well-known/openid-configuration")
    if document.get("issuer") != details["oidc_issuer"]:
        raise OidcFederationError("OIDC discovery issuer mismatch")
    result = {"issuer": details["oidc_issuer"]}
    for field in endpoint_mapping:
        value = document.get(field)
        if not isinstance(value, str):
            raise OidcFederationError(f"OIDC discovery is missing {field}")
        _validated_target(value, allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
        result[field] = value
    provider.discovery_document = dict(result)
    provider.discovery_expires_at = now + _CACHE_TTL
    return result


def social_configuration(provider: CognitoIdentityProvider) -> dict[str, str]:
    if provider.provider_type not in {
        "Google",
        "Facebook",
        "LoginWithAmazon",
        "SignInWithApple",
    }:
        raise OidcFederationError("Unsupported social identity provider")
    result = {
        key: value
        for key, value in provider.provider_details.items()
        if key
        in {
            "attributes_url",
            "authorize_url",
            "jwks_uri",
            "oidc_issuer",
            "token_request_method",
            "token_url",
        }
    }
    overrides = _social_endpoint_overrides()
    if base := overrides.get(provider.provider_type):
        result.update(
            {
                "attributes_url": f"{base}/userinfo",
                "authorize_url": f"{base}/authorize",
                "token_url": f"{base}/token",
            }
        )
        if provider.provider_type in {"Google", "SignInWithApple"}:
            result.update({"jwks_uri": f"{base}/jwks", "oidc_issuer": base})
    required = {"authorize_url", "token_url"}
    if provider.provider_type != "SignInWithApple":
        required.add("attributes_url")
    if provider.provider_type in {"Google", "SignInWithApple"}:
        required.update({"jwks_uri", "oidc_issuer"})
    if not required <= result.keys():
        raise OidcFederationError("Incomplete social endpoint configuration")
    for field in required - {"oidc_issuer"}:
        _validated_target(result[field], allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
    if "oidc_issuer" in result:
        _validated_target(result["oidc_issuer"], allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
        result["issuer"] = result["oidc_issuer"]
    result["authorization_endpoint"] = result["authorize_url"]
    return result


def apple_client_secret(provider: CognitoIdentityProvider, private_key_pem: str) -> str:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except (TypeError, ValueError) as error:
        raise OidcFederationError("Invalid Apple private key") from error
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise OidcFederationError("Apple private key must use P-256")
    now = int(time.time())
    header = _jwt_json_segment({"alg": "ES256", "kid": provider.provider_details["key_id"]})
    payload = _jwt_json_segment(
        {
            "aud": "https://appleid.apple.com",
            "exp": now + 300,
            "iat": now,
            "iss": provider.provider_details["team_id"],
            "jti": str(uuid.uuid4()),
            "sub": provider.provider_details["client_id"],
        }
    )
    der = private_key.sign(f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256()))
    first, second = decode_dss_signature(der)
    signature = (
        base64.urlsafe_b64encode(first.to_bytes(32, "big") + second.to_bytes(32, "big"))
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.{signature}"


def social_claims(
    provider: CognitoIdentityProvider,
    configuration: dict[str, str],
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    nonce_hash: str,
    secret: str,
) -> dict[str, Any]:
    client_secret = (
        apple_client_secret(provider, secret)
        if provider.provider_type == "SignInWithApple"
        else secret
    )
    form = {
        "client_id": provider.provider_details["client_id"],
        "client_secret": client_secret,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    token_response = secure_json_request(
        configuration["token_url"],
        method=provider.provider_details.get("token_request_method", "POST"),
        form=form,
    )
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not 1 <= len(access_token) <= _MAX_TOKEN_BYTES:
        raise OidcFederationError("Social token response is incomplete")
    if provider.provider_type in {"Google", "SignInWithApple"}:
        id_token = token_response.get("id_token")
        if not isinstance(id_token, str):
            raise OidcFederationError("Social ID token is missing")
        claims = verify_id_token(
            id_token,
            provider=provider,
            configuration=configuration,
            nonce_hash=nonce_hash,
            access_token=access_token,
        )
        if provider.provider_type == "SignInWithApple":
            return claims
    else:
        claims = {}
    attributes_url = configuration.get("attributes_url")
    if attributes_url is None:
        return claims
    mapped_fields = sorted(
        {
            source
            for destination, source in provider.attribute_mapping.items()
            if destination != "username"
        }
    )
    if provider.provider_details.get("attributes_url_add_attributes") == "true":
        separator = "&" if "?" in attributes_url else "?"
        attributes_url = f"{attributes_url}{separator}fields={','.join(mapped_fields)}"
    user_info = secure_json_request(attributes_url, bearer_token=access_token)
    subject_field = {
        "Facebook": "id",
        "LoginWithAmazon": "user_id",
    }.get(provider.provider_type, "sub")
    subject = user_info.get(subject_field)
    if not isinstance(subject, str) or not subject:
        raise OidcFederationError("Social subject is missing")
    if claims.get("sub") not in {None, subject}:
        raise OidcFederationError("Social userInfo subject mismatch")
    return {**user_info, **claims, "sub": subject}


def apple_form_claims(value: str | None) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, str) or not 1 <= len(value) <= 8192:
        raise OidcFederationError("Invalid Apple user response")
    document = _strict_json_object(value.encode())
    if set(document) - {"email", "name"}:
        raise OidcFederationError("Invalid Apple user response")
    result = {}
    email = document.get("email")
    if email is not None:
        if not isinstance(email, str) or not 1 <= len(email) <= 2048:
            raise OidcFederationError("Invalid Apple user email")
        result["email"] = email
    name = document.get("name")
    if name is not None:
        if not isinstance(name, dict) or set(name) - {"firstName", "lastName"}:
            raise OidcFederationError("Invalid Apple user name")
        given = name.get("firstName")
        family = name.get("lastName")
        if any(
            item is not None and (not isinstance(item, str) or not 1 <= len(item) <= 1024)
            for item in (given, family)
        ):
            raise OidcFederationError("Invalid Apple user name")
        if given is not None:
            result["given_name"] = given
        if family is not None:
            result["family_name"] = family
        if given is not None or family is not None:
            result["name"] = " ".join(item for item in (given, family) if item)
    return result


def _social_endpoint_overrides() -> dict[str, str]:
    result = {}
    for item in config.COGNITO_IDP_SOCIAL_ENDPOINTS:
        if "=" not in item:
            raise OidcFederationError("Invalid social endpoint override")
        provider_type, base = item.split("=", 1)
        if (
            provider_type
            not in {
                "Google",
                "Facebook",
                "LoginWithAmazon",
                "SignInWithApple",
            }
            or provider_type in result
        ):
            raise OidcFederationError("Invalid social endpoint override")
        parsed, _ = _validated_target(
            base.rstrip("/"), allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST
        )
        if parsed.path not in {"", "/"} or parsed.query:
            raise OidcFederationError("Social endpoint override must be an origin")
        result[provider_type] = base.rstrip("/")
    return result


def _jwt_json_segment(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def oidc_jwks(provider: CognitoIdentityProvider, configuration: dict[str, str]) -> dict[str, Any]:
    now = datetime.now(UTC)
    if (
        provider.jwks_document is not None
        and provider.jwks_expires_at is not None
        and provider.jwks_expires_at > now
    ):
        return dict(provider.jwks_document)
    document = secure_json_request(configuration["jwks_uri"])
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= _MAX_JWKS_KEYS:
        raise OidcFederationError("Invalid OIDC JWKS")
    seen = set()
    for key in keys:
        if (
            not isinstance(key, dict)
            or key.get("kty") != "RSA"
            or key.get("alg") not in {None, "RS256"}
            or key.get("use") not in {None, "sig"}
            or not isinstance(key.get("kid"), str)
            or not 1 <= len(key["kid"]) <= 128
            or key["kid"] in seen
        ):
            raise OidcFederationError("Invalid OIDC JWK")
        try:
            public_key_from_jwk(key)
        except (TypeError, ValueError) as error:
            raise OidcFederationError("Invalid OIDC JWK") from error
        seen.add(key["kid"])
    provider.jwks_document = {"keys": [dict(key) for key in keys]}
    provider.jwks_expires_at = now + _CACHE_TTL
    return dict(provider.jwks_document)


def verify_id_token(
    token: str,
    *,
    provider: CognitoIdentityProvider,
    configuration: dict[str, str],
    nonce_hash: str,
    access_token: str,
) -> dict[str, Any]:
    if not isinstance(token, str) or not 1 <= len(token) <= _MAX_TOKEN_BYTES:
        raise OidcFederationError("Invalid OIDC ID token")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise OidcFederationError("Invalid OIDC ID token")
    header = _strict_jwt_segment(parts[0])
    claims = _strict_jwt_segment(parts[1])
    signature = _strict_base64url(parts[2])
    if (
        not isinstance(header, dict)
        or header.get("alg") != "RS256"
        or not isinstance(header.get("kid"), str)
        or header.get("typ") not in {None, "JWT"}
    ):
        raise OidcFederationError("Unsupported OIDC token header")
    key = next(
        (
            item
            for item in oidc_jwks(provider, configuration)["keys"]
            if item["kid"] == header["kid"]
        ),
        None,
    )
    if key is None:
        provider.jwks_expires_at = None
        key = next(
            (
                item
                for item in oidc_jwks(provider, configuration)["keys"]
                if item["kid"] == header["kid"]
            ),
            None,
        )
    if key is None:
        raise OidcFederationError("Unknown OIDC signing key")
    try:
        public_key_from_jwk(key).verify(
            signature,
            f"{parts[0]}.{parts[1]}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, TypeError, ValueError) as error:
        raise OidcFederationError("Invalid OIDC token signature") from error
    now = int(time.time())
    audience = claims.get("aud")
    client_id = provider.provider_details["client_id"]
    if isinstance(audience, str):
        audience_valid = hmac.compare_digest(audience, client_id)
    elif (
        isinstance(audience, list)
        and 1 <= len(audience) <= 10
        and len(audience) == len(set(audience))
        and all(isinstance(item, str) and item for item in audience)
    ):
        audience_valid = (
            client_id in audience
            and len(audience) == 1
            or (
                client_id in audience
                and isinstance(claims.get("azp"), str)
                and hmac.compare_digest(claims["azp"], client_id)
            )
        )
    else:
        audience_valid = False
    nonce = claims.get("nonce")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    not_before = claims.get("nbf")
    if (
        claims.get("iss") != configuration["issuer"]
        or not audience_valid
        or not isinstance(claims.get("sub"), str)
        or not 1 <= len(claims["sub"]) <= 255
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not now < expires_at <= now + 24 * 60 * 60
        or not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not now - 24 * 60 * 60 <= issued_at <= now + 60
        or expires_at <= issued_at
        or (
            not_before is not None
            and (
                not isinstance(not_before, int)
                or isinstance(not_before, bool)
                or not_before > now + 60
                or not_before < issued_at - 60
            )
        )
        or not isinstance(nonce, str)
        or not hmac.compare_digest(hashlib.sha256(nonce.encode()).hexdigest(), nonce_hash)
    ):
        raise OidcFederationError("Invalid OIDC token claims")
    at_hash = claims.get("at_hash")
    if at_hash is not None:
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()[:16])
            .rstrip(b"=")
            .decode()
        )
        if not isinstance(at_hash, str) or not hmac.compare_digest(at_hash, expected):
            raise OidcFederationError("Invalid OIDC at_hash")
    return claims


def _validated_target(url: str, *, allowlist: list[str]):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise OidcFederationError("Invalid OIDC URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise OidcFederationError("Invalid OIDC URL") from error
    hostname = parsed.hostname.lower() if parsed.hostname is not None else None
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or hostname in _METADATA_HOSTS
    ):
        raise OidcFederationError("Unsafe OIDC URL")
    normalized_allowlist = {item.lower() for item in allowlist if item and "*" not in item}
    authority = f"{hostname}:{port}"
    host_allowed = hostname in normalized_allowlist or authority in normalized_allowlist
    if parsed.scheme == "http" and not host_allowed:
        raise OidcFederationError("OIDC HTTP requires an exact egress allowlist entry")
    if port not in {80, 443} and authority not in normalized_allowlist:
        raise OidcFederationError("OIDC non-standard port requires exact allowlisting")
    first = _resolve_addresses(hostname, port)
    second = _resolve_addresses(hostname, port)
    if not first or first != second:
        raise OidcFederationError("OIDC DNS resolution changed during validation")
    for address in first:
        ip = ipaddress.ip_address(address)
        address_allowed = address.lower() in normalized_allowlist or (
            f"{address.lower()}:{port}" in normalized_allowlist
        )
        if _unsafe_ip(ip) and not (host_allowed or address_allowed):
            raise OidcFederationError("OIDC endpoint resolves to a private address")
        if str(ip) in _METADATA_HOSTS:
            raise OidcFederationError("Metadata endpoints are always blocked")
    return parsed, sorted(first)[0]


def _resolve_addresses(hostname: str, port: int) -> set[str]:
    try:
        return {item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise OidcFederationError("OIDC DNS resolution failed") from error


def _unsafe_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _strict_json_object(payload: bytes) -> dict[str, Any]:
    def reject_constant(_):
        raise OidcFederationError("Non-finite JSON numbers are forbidden")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OidcFederationError("Duplicate JSON object member")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OidcFederationError("Invalid OIDC JSON") from error
    if not isinstance(document, dict):
        raise OidcFederationError("OIDC JSON response must be an object")
    _validate_json_bounds(document, depth=0)
    return document


def _validate_json_bounds(value: Any, *, depth: int) -> None:
    if depth > 16:
        raise OidcFederationError("OIDC JSON nesting exceeds limit")
    if isinstance(value, dict):
        if len(value) > 2048:
            raise OidcFederationError("OIDC JSON object exceeds member limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 1024:
                raise OidcFederationError("OIDC JSON key exceeds limit")
            _validate_json_bounds(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 2048:
            raise OidcFederationError("OIDC JSON array exceeds item limit")
        for item in value:
            _validate_json_bounds(item, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > _MAX_RESPONSE_BYTES:
            raise OidcFederationError("OIDC JSON string exceeds limit")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise OidcFederationError("Unsupported OIDC JSON value")


def _strict_base64url(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in value
        )
    ):
        raise OidcFederationError("Invalid base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as error:
        raise OidcFederationError("Invalid base64url") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
    if not hmac.compare_digest(canonical, value):
        raise OidcFederationError("Non-canonical base64url")
    return decoded


def _strict_jwt_segment(value: str) -> dict[str, Any]:
    return _strict_json_object(_strict_base64url(value))
