import dataclasses
import hashlib
import json
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_CUSTOM_AUTH_SESSIONS = 10_000
MAX_CUSTOM_AUTH_GENERATIONS = 20_000
MAX_CUSTOM_AUTH_HISTORY = 20
CUSTOM_AUTH_SESSION_TTL = timedelta(minutes=3)
_MAX_MAP_ENTRIES = 32
_MAX_MAP_BYTES = 16 * 1024
_MAX_CHALLENGE_METADATA_BYTES = 2_048
_MAX_ANSWER_BYTES = 128 * 1024


class CustomAuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclasses.dataclass
class CustomChallengeResult:
    challenge_name: str
    challenge_result: bool
    challenge_metadata: str | None = None


@dataclasses.dataclass
class CustomAuthSession:
    region: str
    pool_id: str
    client_id: str
    username: str
    user_attributes: dict[str, str]
    user_not_found: bool
    created_at: datetime
    expires_at: datetime
    encrypted_private_parameters: bytes
    challenge_metadata: str | None
    history: list[CustomChallengeResult]
    generation_cursor: int
    pool_generation: int
    client_generation: int
    user_generation: int


@dataclasses.dataclass
class CustomAuthState:
    sessions: dict[str, CustomAuthSession] = dataclasses.field(default_factory=dict)
    cleanup_sequence: int = 0
    generation_floor: int = 0
    generations: dict[str, int] = dataclasses.field(default_factory=dict)
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
class CustomAuthOutcome:
    issue_tokens: bool
    username: str
    challenge_parameters: dict[str, str] | None = None
    session: str | None = None


TriggerInvoker = Callable[[str, dict[str, Any]], dict[str, Any]]
SecretResolver = Callable[[str], bytes]


class CustomAuthManager:
    def __init__(
        self,
        state: CustomAuthState,
        secret_resolver: SecretResolver,
        *,
        now: Callable[[], datetime] | None = None,
    ):
        self.state = state
        self._secret_resolver = secret_resolver
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = state._lock

    def start(
        self,
        *,
        region: str,
        pool_id: str,
        client_id: str,
        username: str,
        user_attributes: dict[str, str],
        user_not_found: bool,
        invoke: TriggerInvoker,
        initial_history: list[CustomChallengeResult] | None = None,
        client_metadata: Any = None,
    ) -> CustomAuthOutcome:
        attributes = _bounded_map(user_attributes, "userAttributes")
        metadata = _bounded_map(client_metadata, "ClientMetadata")
        common = _common_event(region, pool_id, client_id, username)
        history = _validated_history(initial_history or [])
        with self._lock:
            generations = self._generation_tuple(pool_id, client_id, username)
        define = self._define(invoke, common, attributes, user_not_found, history, metadata)
        if define["failAuthentication"] or define["issueTokens"]:
            if user_not_found or define["failAuthentication"]:
                raise CustomAuthError("NotAuthorizedException", "Incorrect username or password")
            self._assert_expected_generations(pool_id, client_id, username, generations)
            return CustomAuthOutcome(issue_tokens=True, username=username)
        return self._create_and_store(
            invoke=invoke,
            common=common,
            attributes=attributes,
            user_not_found=user_not_found,
            history=history,
            client_metadata=metadata,
            expected_generations=generations,
        )

    def respond(
        self,
        *,
        region: str,
        session_token: Any,
        challenge_answer: Any,
        client_metadata: Any,
        invoke: TriggerInvoker,
        expected_pool_id: str | None = None,
        expected_client_id: str | None = None,
        expected_username: str | None = None,
    ) -> CustomAuthOutcome:
        token = _bounded_string(session_token, "Session", minimum=20, maximum=2048)
        answer = _bounded_string(challenge_answer, "ANSWER", minimum=0, maximum=_MAX_ANSWER_BYTES)
        metadata = _bounded_map(client_metadata, "ClientMetadata")
        token_hash = _token_hash(token)
        now = self._now()
        with self._lock:
            self._prune(now)
            session = self.state.sessions.pop(token_hash, None)
        if session is None or session.expires_at <= now:
            raise CustomAuthError("NotAuthorizedException", "Invalid authentication session")
        if (
            session.region != region
            or session.pool_id != (expected_pool_id or session.pool_id)
            or session.client_id != (expected_client_id or session.client_id)
            or session.username != (expected_username or session.username)
        ):
            raise CustomAuthError("NotAuthorizedException", "Invalid authentication session")
        common = _common_event(region, session.pool_id, session.client_id, session.username)
        private_parameters = self._decrypt_private(session)
        verify_event = {
            **common,
            "request": {
                "challengeAnswer": answer,
                "clientMetadata": metadata,
                "privateChallengeParameters": private_parameters,
                "userAttributes": dict(session.user_attributes),
                "userNotFound": session.user_not_found,
            },
            "response": {},
            "triggerSource": "VerifyAuthChallengeResponse_Authentication",
        }
        verified = _trigger_response(
            invoke("VerifyAuthChallengeResponse", verify_event),
            required={"answerCorrect"},
            optional=set(),
        )
        if not isinstance(verified["answerCorrect"], bool):
            raise CustomAuthError("InvalidLambdaResponseException", "Invalid verify response")
        history = [*session.history]
        history.append(
            CustomChallengeResult(
                challenge_name="CUSTOM_CHALLENGE",
                challenge_result=verified["answerCorrect"],
                challenge_metadata=session.challenge_metadata,
            )
        )
        if len(history) > MAX_CUSTOM_AUTH_HISTORY:
            raise CustomAuthError("NotAuthorizedException", "Custom authentication limit exceeded")
        define = self._define(
            invoke,
            common,
            session.user_attributes,
            session.user_not_found,
            history,
            metadata,
        )
        if define["failAuthentication"] or define["issueTokens"]:
            if session.user_not_found or define["failAuthentication"]:
                raise CustomAuthError("NotAuthorizedException", "Incorrect username or password")
            self._assert_session_current(session)
            return CustomAuthOutcome(issue_tokens=True, username=session.username)
        if len(history) >= MAX_CUSTOM_AUTH_HISTORY:
            raise CustomAuthError("NotAuthorizedException", "Custom authentication limit exceeded")
        self._assert_session_current(session)
        return self._create_and_store(
            invoke=invoke,
            common=common,
            attributes=session.user_attributes,
            user_not_found=session.user_not_found,
            history=history,
            client_metadata=metadata,
            expected_session=session,
            expected_generations=(
                session.generation_cursor,
                session.pool_generation,
                session.client_generation,
                session.user_generation,
            ),
        )

    def cleanup_pool(self, pool_id: str) -> None:
        with self._lock:
            self._record_cleanup(_scope_key("pool", pool_id))
            self.state.sessions = {
                key: value for key, value in self.state.sessions.items() if value.pool_id != pool_id
            }

    def cleanup_client(self, pool_id: str, client_id: str) -> None:
        with self._lock:
            self._record_cleanup(_scope_key("client", pool_id, client_id))
            self.state.sessions = {
                token: value
                for token, value in self.state.sessions.items()
                if (value.pool_id, value.client_id) != (pool_id, client_id)
            }

    def cleanup_user(self, pool_id: str, username: str) -> None:
        with self._lock:
            self._record_cleanup(_scope_key("user", pool_id, username))
            self.state.sessions = {
                token: value
                for token, value in self.state.sessions.items()
                if (value.pool_id, value.username) != (pool_id, username)
            }

    def _record_cleanup(self, key: str) -> None:
        self.state.cleanup_sequence += 1
        sequence = self.state.cleanup_sequence
        self.state.generations.pop(key, None)
        self.state.generations[key] = sequence
        while len(self.state.generations) > MAX_CUSTOM_AUTH_GENERATIONS:
            oldest = next(iter(self.state.generations))
            self.state.generation_floor = max(
                self.state.generation_floor, self.state.generations.pop(oldest)
            )

    def _define(
        self,
        invoke: TriggerInvoker,
        common: dict[str, Any],
        attributes: dict[str, str],
        user_not_found: bool,
        history: list[CustomChallengeResult],
        client_metadata: dict[str, str],
    ) -> dict[str, Any]:
        event = {
            **common,
            "request": {
                "clientMetadata": dict(client_metadata),
                "session": _history_event(history),
                "userAttributes": dict(attributes),
                "userNotFound": user_not_found,
            },
            "response": {},
            "triggerSource": "DefineAuthChallenge_Authentication",
        }
        response = _trigger_response(
            invoke("DefineAuthChallenge", event),
            required={"failAuthentication", "issueTokens"},
            optional={"challengeName"},
        )
        issue, fail = response["issueTokens"], response["failAuthentication"]
        if not isinstance(issue, bool) or not isinstance(fail, bool) or (issue and fail):
            raise CustomAuthError("InvalidLambdaResponseException", "Invalid define response")
        challenge = response.get("challengeName")
        if issue or fail:
            if challenge not in (None, ""):
                raise CustomAuthError("InvalidLambdaResponseException", "Invalid define response")
        elif challenge != "CUSTOM_CHALLENGE":
            raise CustomAuthError(
                "InvalidLambdaResponseException", "Only CUSTOM_CHALLENGE is supported"
            )
        return response

    def _create_and_store(
        self,
        *,
        invoke: TriggerInvoker,
        common: dict[str, Any],
        attributes: dict[str, str],
        user_not_found: bool,
        history: list[CustomChallengeResult],
        client_metadata: dict[str, str],
        expected_session: CustomAuthSession | None = None,
        expected_generations: tuple[int, int, int, int] | None = None,
    ) -> CustomAuthOutcome:
        event = {
            **common,
            "request": {
                "challengeName": "CUSTOM_CHALLENGE",
                "clientMetadata": dict(client_metadata),
                "session": _history_event(history),
                "userAttributes": dict(attributes),
                "userNotFound": user_not_found,
            },
            "response": {},
            "triggerSource": "CreateAuthChallenge_Authentication",
        }
        response = _trigger_response(
            invoke("CreateAuthChallenge", event),
            required={
                "challengeMetadata",
                "privateChallengeParameters",
                "publicChallengeParameters",
            },
            optional=set(),
        )
        public = _bounded_map(
            response["publicChallengeParameters"],
            "publicChallengeParameters",
            error_code="InvalidLambdaResponseException",
            allow_none=False,
        )
        private = _bounded_map(
            response["privateChallengeParameters"],
            "privateChallengeParameters",
            error_code="InvalidLambdaResponseException",
            allow_none=False,
        )
        challenge_metadata = response["challengeMetadata"]
        try:
            valid_challenge_metadata = (
                isinstance(challenge_metadata, str)
                and len(challenge_metadata.encode("utf-8")) <= _MAX_CHALLENGE_METADATA_BYTES
            )
        except UnicodeEncodeError:
            valid_challenge_metadata = False
        if not valid_challenge_metadata:
            raise CustomAuthError("InvalidLambdaResponseException", "Invalid challengeMetadata")
        pool_id, client_id, username = (
            common["userPoolId"],
            common["callerContext"]["clientId"],
            common["userName"],
        )
        encrypted_private_parameters = self._encrypt_private(pool_id, client_id, username, private)
        now = self._now()
        with self._lock:
            self._prune(now)
            current_generations = self._generation_tuple(pool_id, client_id, username)
            if expected_generations is not None and not self._generations_are_current(
                expected_generations, current_generations
            ):
                raise CustomAuthError("NotAuthorizedException", "Authentication state changed")
            if expected_session is not None and expected_session.expires_at <= now:
                raise CustomAuthError("NotAuthorizedException", "Authentication session expired")
            if len(self.state.sessions) >= MAX_CUSTOM_AUTH_SESSIONS:
                raise CustomAuthError("TooManyRequestsException", "Custom auth quota exceeded")
            token = secrets.token_urlsafe(48)
            token_hash = _token_hash(token)
            while token_hash in self.state.sessions:
                token = secrets.token_urlsafe(48)
                token_hash = _token_hash(token)
            created_at = expected_session.created_at if expected_session else now
            expires_at = (
                expected_session.expires_at if expected_session else now + CUSTOM_AUTH_SESSION_TTL
            )
            session = CustomAuthSession(
                region=common["region"],
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                user_attributes=dict(attributes),
                user_not_found=user_not_found,
                created_at=created_at,
                expires_at=expires_at,
                encrypted_private_parameters=encrypted_private_parameters,
                challenge_metadata=challenge_metadata or None,
                history=[*history],
                generation_cursor=current_generations[0],
                pool_generation=current_generations[1],
                client_generation=current_generations[2],
                user_generation=current_generations[3],
            )
            self.state.sessions[token_hash] = session
        return CustomAuthOutcome(
            issue_tokens=False,
            username=username,
            challenge_parameters=public,
            session=token,
        )

    def _assert_session_current(self, session: CustomAuthSession) -> None:
        with self._lock:
            if session.expires_at <= self._now():
                raise CustomAuthError("NotAuthorizedException", "Authentication session expired")
            if not self._generations_are_current(
                (
                    session.generation_cursor,
                    session.pool_generation,
                    session.client_generation,
                    session.user_generation,
                ),
                self._generation_tuple(session.pool_id, session.client_id, session.username),
            ):
                raise CustomAuthError("NotAuthorizedException", "Authentication state changed")

    def _assert_expected_generations(
        self,
        pool_id: str,
        client_id: str,
        username: str,
        expected: tuple[int, int, int, int],
    ) -> None:
        with self._lock:
            if not self._generations_are_current(
                expected, self._generation_tuple(pool_id, client_id, username)
            ):
                raise CustomAuthError("NotAuthorizedException", "Authentication state changed")

    def _generation_tuple(
        self, pool_id: str, client_id: str, username: str
    ) -> tuple[int, int, int, int]:
        return (
            self.state.cleanup_sequence,
            self.state.generations.get(_scope_key("pool", pool_id), 0),
            self.state.generations.get(_scope_key("client", pool_id, client_id), 0),
            self.state.generations.get(_scope_key("user", pool_id, username), 0),
        )

    def _generations_are_current(
        self,
        expected: tuple[int, int, int, int],
        current: tuple[int, int, int, int],
    ) -> bool:
        return expected[0] >= self.state.generation_floor and expected[1:] == current[1:]

    def _encrypt_private(
        self, pool_id: str, client_id: str, username: str, value: dict[str, str]
    ) -> bytes:
        key = _encryption_key(self._secret_resolver(pool_id))
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return nonce + AESGCM(key).encrypt(
            nonce, plaintext, _private_aad(pool_id, client_id, username)
        )

    def _decrypt_private(self, session: CustomAuthSession) -> dict[str, str]:
        value = session.encrypted_private_parameters
        if not isinstance(value, bytes) or len(value) < 29:
            raise CustomAuthError("NotAuthorizedException", "Invalid authentication session")
        try:
            plaintext = AESGCM(_encryption_key(self._secret_resolver(session.pool_id))).decrypt(
                value[:12],
                value[12:],
                _private_aad(session.pool_id, session.client_id, session.username),
            )
            decoded = json.loads(plaintext)
        except Exception as error:
            raise CustomAuthError(
                "NotAuthorizedException", "Invalid authentication session"
            ) from error
        try:
            return _bounded_map(decoded, "privateChallengeParameters", allow_none=False)
        except CustomAuthError as error:
            raise CustomAuthError(
                "NotAuthorizedException", "Invalid authentication session"
            ) from error

    def _prune(self, now: datetime) -> None:
        self.state.sessions = {
            key: value for key, value in self.state.sessions.items() if value.expires_at > now
        }


def _trigger_response(returned: Any, *, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(returned, dict) or not isinstance(returned.get("response"), dict):
        raise CustomAuthError("InvalidLambdaResponseException", "Invalid Lambda response")
    response = returned["response"]
    if set(response) - required - optional or not required <= set(response):
        raise CustomAuthError("InvalidLambdaResponseException", "Invalid Lambda response")
    return response


def _bounded_map(
    value: Any,
    field: str,
    *,
    error_code: str = "InvalidParameterException",
    allow_none: bool = True,
) -> dict[str, str]:
    if value is None:
        if allow_none:
            return {}
        raise CustomAuthError(error_code, f"Invalid {field}")
    if not isinstance(value, dict) or len(value) > _MAX_MAP_ENTRIES:
        raise CustomAuthError(error_code, f"Invalid {field}")
    result: dict[str, str] = {}
    total = 0
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not 1 <= len(key) <= 128
            or len(item) > 2048
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in key)
        ):
            raise CustomAuthError(error_code, f"Invalid {field}")
        try:
            total += len(key.encode()) + len(item.encode())
        except UnicodeEncodeError as error:
            raise CustomAuthError(error_code, f"Invalid {field}") from error
        if total > _MAX_MAP_BYTES:
            raise CustomAuthError(error_code, f"Invalid {field}")
        result[key] = item
    return result


def _bounded_string(value: Any, field: str, *, minimum: int, maximum: int) -> str:
    try:
        valid = isinstance(value, str) and minimum <= len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise CustomAuthError("InvalidParameterException", f"Invalid {field}")
    return value


def _history_event(history: list[CustomChallengeResult]) -> list[dict[str, Any]]:
    return [
        {
            "challengeName": item.challenge_name,
            "challengeResult": item.challenge_result,
            **(
                {"challengeMetadata": item.challenge_metadata}
                if item.challenge_metadata is not None
                else {}
            ),
        }
        for item in history
    ]


def _validated_history(history: list[CustomChallengeResult]) -> list[CustomChallengeResult]:
    if not isinstance(history, list) or len(history) > MAX_CUSTOM_AUTH_HISTORY:
        raise CustomAuthError("InvalidParameterException", "Invalid custom auth history")
    result = []
    for item in history:
        if (
            not isinstance(item, CustomChallengeResult)
            or not isinstance(item.challenge_name, str)
            or not 1 <= len(item.challenge_name) <= 128
            or not isinstance(item.challenge_result, bool)
        ):
            raise CustomAuthError("InvalidParameterException", "Invalid custom auth history")
        metadata = item.challenge_metadata
        if metadata is not None:
            try:
                valid_metadata = (
                    isinstance(metadata, str)
                    and len(metadata.encode("utf-8")) <= _MAX_CHALLENGE_METADATA_BYTES
                )
            except UnicodeEncodeError:
                valid_metadata = False
            if not valid_metadata:
                raise CustomAuthError("InvalidParameterException", "Invalid custom auth history")
        result.append(dataclasses.replace(item))
    return result


def _common_event(region: str, pool_id: str, client_id: str, username: str) -> dict[str, Any]:
    return {
        "callerContext": {"awsSdkVersion": "localstack", "clientId": client_id},
        "region": region,
        "userName": username,
        "userPoolId": pool_id,
        "version": "1",
    }


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _encryption_key(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise CustomAuthError("InvalidParameterException", "Invalid custom auth state key")
    return hashlib.sha256(b"localstack-cognito-custom-auth-v1\x00" + secret).digest()


def _private_aad(pool_id: str, client_id: str, username: str) -> bytes:
    return f"{pool_id}\x00{client_id}\x00{username}".encode()


def _scope_key(kind: str, *values: str) -> str:
    digest = hashlib.sha256()
    digest.update(kind.encode())
    for value in values:
        encoded = value.encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()
