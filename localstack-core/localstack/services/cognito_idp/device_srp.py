import base64
import dataclasses
import hashlib
import hmac
import re
import secrets
from collections.abc import MutableMapping
from datetime import UTC, datetime, timedelta
from typing import Any

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
_SESSION_TTL = timedelta(minutes=3)
_MAX_SESSIONS = 10_000
_MAX_DEVICE_GROUP_KEY_BYTES = 131_072
_MAX_USERNAME_BYTES = 128
_MAX_CLIENT_ID_BYTES = 128
_MAX_POOL_ID_BYTES = 128
_MAX_DEVICE_KEY_BYTES = 55
_MAX_SALT_BYTES = 128
_MAX_VERIFIER_BYTES = (_SRP_N.bit_length() + 7) // 8 + 1
_PASSWORD_CLAIM_MAX_SKEW = timedelta(minutes=5)
_DEVICE_KEY_PATTERN = re.compile(r"[\w-]+_[0-9a-f-]+")
_HEX_PATTERN = re.compile(r"[0-9a-fA-F]+")
_TIMESTAMP_PATTERN = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"([1-9]|[12][0-9]|3[01]) ([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) UTC ([0-9]{4})$"
)
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = {
    month: number
    for number, month in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        1,
    )
}


class DeviceSrpError(ValueError):
    """An invalid or unauthorized remembered-device SRP operation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class DeviceSrpSession:
    token_hash: str
    pool_id: str
    client_id: str
    username: str
    device_key: str
    shared_key: str
    secret_block_hash: str
    created_at: datetime
    expires_at: datetime
    auth_context: dict[str, str] = dataclasses.field(default_factory=dict)
    client_metadata: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class DeviceSrpStart:
    session_token: str
    session: DeviceSrpSession
    challenge_parameters: dict[str, str]


def normalize_device_verifier(salt: Any, verifier: Any) -> tuple[str, str]:
    """Validate and canonicalize the verifier material submitted to ConfirmDevice."""
    salt_bytes = _strict_base64(salt, "Salt", minimum=1, maximum=_MAX_SALT_BYTES)
    verifier_bytes = _strict_base64(
        verifier, "PasswordVerifier", minimum=1, maximum=_MAX_VERIFIER_BYTES
    )
    verifier_value = int.from_bytes(verifier_bytes, "big")
    if not 0 < verifier_value < _SRP_N:
        raise DeviceSrpError("InvalidParameterException", "Invalid PasswordVerifier")
    return base64.b64encode(salt_bytes).decode(), base64.b64encode(verifier_bytes).decode()


def start_device_srp(
    *,
    pool_id: Any,
    client_id: Any,
    username: Any,
    device_key: Any,
    device_group_key: Any,
    salt: Any,
    verifier: Any,
    public_a: Any,
    now: datetime | None = None,
    private_b: int | None = None,
    secret_block: bytes | None = None,
    session_token: str | None = None,
    auth_context: dict[str, str] | None = None,
    client_metadata: dict[str, str] | None = None,
) -> DeviceSrpStart:
    """Create the DEVICE_PASSWORD_VERIFIER challenge for a confirmed device."""
    now = _aware_utc(now)
    pool_id = _bounded_text(pool_id, "pool ID", _MAX_POOL_ID_BYTES)
    client_id = _bounded_text(client_id, "client ID", _MAX_CLIENT_ID_BYTES)
    username = _bounded_text(username, "username", _MAX_USERNAME_BYTES)
    device_key = _device_key(device_key)
    device_group_key = _bounded_text(
        device_group_key, "device group key", _MAX_DEVICE_GROUP_KEY_BYTES
    )
    salt, verifier = normalize_device_verifier(salt, verifier)
    public_a_value = _public_value(public_a)
    verifier_value = int.from_bytes(base64.b64decode(verifier, validate=True), "big")

    if private_b is None:
        private_b = secrets.randbelow(_SRP_N - 2) + 1
    if not isinstance(private_b, int) or isinstance(private_b, bool) or not 0 < private_b < _SRP_N:
        raise DeviceSrpError("InvalidParameterException", "Invalid server SRP private value")
    public_b = (_srp_multiplier() * verifier_value + pow(_SRP_G, private_b, _SRP_N)) % _SRP_N
    if public_b == 0:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication parameters")
    scrambling = int(_hex_hash(f"{_pad_hex(public_a_value)}{_pad_hex(public_b)}"), 16)
    if scrambling == 0:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication parameters")
    shared_secret = pow(
        (public_a_value * pow(verifier_value, scrambling, _SRP_N)) % _SRP_N,
        private_b,
        _SRP_N,
    )
    if shared_secret == 0:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication parameters")

    if secret_block is None:
        secret_block = secrets.token_bytes(32)
    if not isinstance(secret_block, bytes) or len(secret_block) != 32:
        raise DeviceSrpError("InvalidParameterException", "Invalid secret block")
    if session_token is None:
        session_token = secrets.token_urlsafe(48)
    if not isinstance(session_token, str) or not 32 <= len(session_token) <= 1024:
        raise DeviceSrpError("InvalidParameterException", "Invalid authentication session")

    session = DeviceSrpSession(
        token_hash=_token_hash(session_token),
        pool_id=pool_id,
        client_id=client_id,
        username=username,
        device_key=device_key,
        shared_key=base64.b64encode(_hkdf(shared_secret, scrambling)).decode(),
        secret_block_hash=hashlib.sha256(secret_block).hexdigest(),
        created_at=now,
        expires_at=now + _SESSION_TTL,
        auth_context=dict(auth_context or {}),
        client_metadata=dict(client_metadata or {}),
    )
    return DeviceSrpStart(
        session_token=session_token,
        session=session,
        challenge_parameters={
            "DEVICE_KEY": device_key,
            "SALT": base64.b64decode(salt, validate=True).hex(),
            "SECRET_BLOCK": base64.b64encode(secret_block).decode(),
            "SRP_B": _pad_hex(public_b),
            "USERNAME": username,
        },
    )


def reserve_device_srp_session(
    sessions: MutableMapping[str, DeviceSrpSession],
    started: DeviceSrpStart,
    *,
    now: datetime | None = None,
    maximum: int = _MAX_SESSIONS,
) -> None:
    """Prune stale state and add a hash-only one-use session under the caller's lock."""
    now = _aware_utc(now)
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise DeviceSrpError("InvalidParameterException", "Invalid session quota")
    for key, session in list(sessions.items()):
        if session.expires_at <= now:
            sessions.pop(key, None)
    while len(sessions) >= maximum:
        oldest = min(
            sessions.values(), key=lambda item: (item.created_at, item.expires_at, item.token_hash)
        )
        sessions.pop(oldest.token_hash, None)
    sessions[started.session.token_hash] = started.session


def consume_device_srp_session(
    sessions: MutableMapping[str, DeviceSrpSession],
    raw_session: Any,
    *,
    pool_id: Any,
    client_id: Any,
    username: Any,
    device_key: Any,
    now: datetime | None = None,
) -> DeviceSrpSession:
    """Consume a session after binding checks; a mismatched caller can't burn another session."""
    now = _aware_utc(now)
    if not isinstance(raw_session, str) or not 1 <= len(raw_session) <= 1024:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication session")
    session = sessions.get(_token_hash(raw_session))
    if session is None:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication session")
    if session.expires_at <= now:
        sessions.pop(session.token_hash, None)
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication session")
    bindings = (
        (session.pool_id, pool_id),
        (session.client_id, client_id),
        (session.username, username),
        (session.device_key, device_key),
    )
    if any(
        not isinstance(supplied, str)
        or not hmac.compare_digest(expected.encode(), supplied.encode())
        for expected, supplied in bindings
    ):
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication session")
    sessions.pop(session.token_hash, None)
    return session


def verify_device_password(
    session: DeviceSrpSession,
    *,
    device_group_key: Any,
    secret_block: Any,
    timestamp: Any,
    signature: Any,
    now: datetime | None = None,
) -> None:
    """Verify the final Amplify DEVICE_PASSWORD_VERIFIER response."""
    now = _aware_utc(now)
    device_group_key = _bounded_text(
        device_group_key, "device group key", _MAX_DEVICE_GROUP_KEY_BYTES
    )
    secret_block_bytes = _strict_base64(
        secret_block, "PASSWORD_CLAIM_SECRET_BLOCK", minimum=32, maximum=32
    )
    if not hmac.compare_digest(
        hashlib.sha256(secret_block_bytes).hexdigest(), session.secret_block_hash
    ):
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    timestamp_value = _claim_timestamp(timestamp)
    if abs(now - timestamp_value) > _PASSWORD_CLAIM_MAX_SKEW:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    signature_bytes = _strict_base64(signature, "PASSWORD_CLAIM_SIGNATURE", minimum=32, maximum=32)
    try:
        shared_key = base64.b64decode(session.shared_key, validate=True)
    except (ValueError, TypeError):
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    expected = hmac.new(
        shared_key,
        device_group_key.encode()
        + session.device_key.encode()
        + secret_block_bytes
        + timestamp.encode(),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected, signature_bytes):
        raise DeviceSrpError("NotAuthorizedException", "Incorrect device key or password")


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pad_hex(value: int) -> str:
    encoded = format(value, "x")
    if len(encoded) % 2:
        encoded = f"0{encoded}"
    if encoded[0] in "89abcdefABCDEF":
        encoded = f"00{encoded}"
    return encoded


def _hex_hash(value: str) -> str:
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


def _srp_multiplier() -> int:
    return int(_hex_hash(f"{_pad_hex(_SRP_N)}{_pad_hex(_SRP_G)}"), 16)


def _hkdf(shared_secret: int, scrambling: int) -> bytes:
    pseudo_random_key = hmac.new(
        bytes.fromhex(_pad_hex(scrambling)),
        bytes.fromhex(_pad_hex(shared_secret)),
        hashlib.sha256,
    ).digest()
    return hmac.new(pseudo_random_key, b"Caldera Derived Key\x01", hashlib.sha256).digest()[:16]


def _public_value(value: Any) -> int:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or _HEX_PATTERN.fullmatch(value) is None
    ):
        raise DeviceSrpError("InvalidParameterException", "Invalid SRP_A")
    result = int(value, 16)
    if not 0 < result < _SRP_N or result % _SRP_N == 0:
        raise DeviceSrpError("InvalidParameterException", "Invalid SRP_A")
    return result


def _device_key(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode()) <= _MAX_DEVICE_KEY_BYTES
        or _DEVICE_KEY_PATTERN.fullmatch(value) is None
    ):
        raise DeviceSrpError("InvalidParameterException", "Invalid DeviceKey")
    return value


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= maximum:
        raise DeviceSrpError("InvalidParameterException", f"Invalid {field}")
    return value


def _strict_base64(value: Any, field: str, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum * 2 + 8:
        raise DeviceSrpError("InvalidParameterException", f"Invalid {field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise DeviceSrpError("InvalidParameterException", f"Invalid {field}")
    if not minimum <= len(decoded) <= maximum:
        raise DeviceSrpError("InvalidParameterException", f"Invalid {field}")
    return decoded


def _aware_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DeviceSrpError("InvalidParameterException", "Invalid timestamp")
    return value.astimezone(UTC)


def _claim_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    match = _TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    weekday, month, day, hour, minute, second, year = match.groups()
    try:
        result = datetime(
            int(year),
            _MONTHS[month],
            int(day),
            int(hour),
            int(minute),
            int(second),
            tzinfo=UTC,
        )
    except ValueError:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    if _WEEKDAYS[result.weekday()] != weekday:
        raise DeviceSrpError("NotAuthorizedException", "Invalid authentication response")
    return result
