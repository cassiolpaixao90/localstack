import threading
import uuid
from datetime import UTC, datetime, timedelta

import dill
import pytest

from localstack.services.cognito_idp import custom_auth as custom_auth_module
from localstack.services.cognito_idp.custom_auth import (
    CustomAuthError,
    CustomAuthManager,
    CustomAuthState,
)


@pytest.fixture
def topology(region_name):
    return {
        "client_id": uuid.uuid4().hex,
        "pool_id": f"{region_name}_{uuid.uuid4().hex[:12]}",
        "region": region_name,
        "username": "alice",
    }


@pytest.fixture
def state_secret():
    return b"custom-auth-test-secret-material" * 2


class ChallengeFlow:
    def __init__(self):
        self.calls = []

    def __call__(self, trigger, event):
        self.calls.append((trigger, event))
        if trigger == "DefineAuthChallenge":
            history = event["request"]["session"]
            if history and history[-1]["challengeResult"]:
                return {"response": {"failAuthentication": False, "issueTokens": True}}
            return {
                "response": {
                    "challengeName": "CUSTOM_CHALLENGE",
                    "failAuthentication": False,
                    "issueTokens": False,
                }
            }
        if trigger == "CreateAuthChallenge":
            return {
                "response": {
                    "challengeMetadata": "captcha-v1",
                    "privateChallengeParameters": {"answer": "secret-answer"},
                    "publicChallengeParameters": {"captchaUrl": "/captcha/one"},
                }
            }
        if trigger == "VerifyAuthChallengeResponse":
            request = event["request"]
            return {
                "response": {
                    "answerCorrect": request["challengeAnswer"]
                    == request["privateChallengeParameters"]["answer"]
                }
            }
        raise AssertionError(trigger)


def _start(manager, topology, flow, *, missing=False):
    return manager.start(
        **topology,
        user_attributes={} if missing else {"email": "alice@example.test", "sub": "user-sub"},
        user_not_found=missing,
        invoke=flow,
    )


def test_start_stores_hash_only_encrypted_private_state(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)

    challenge = _start(manager, topology, flow)

    assert challenge.issue_tokens is False
    assert challenge.challenge_parameters == {"captchaUrl": "/captcha/one"}
    assert challenge.session is not None and len(challenge.session) >= 20
    assert challenge.session not in repr(state)
    assert b"secret-answer" not in dill.dumps(state)
    assert [name for name, _ in flow.calls] == [
        "DefineAuthChallenge",
        "CreateAuthChallenge",
    ]
    for _, event in flow.calls:
        assert event["request"]["clientMetadata"] == {}
        assert event["request"]["userNotFound"] is False


def test_tampered_private_state_is_rejected_before_verify(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)
    stored = next(iter(state.sessions.values()))
    stored.encrypted_private_parameters = stored.encrypted_private_parameters[:-1] + bytes(
        [stored.encrypted_private_parameters[-1] ^ 1]
    )

    with pytest.raises(CustomAuthError) as error:
        manager.respond(
            region=topology["region"],
            session_token=challenge.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )

    assert error.value.code == "NotAuthorizedException"
    assert [name for name, _ in flow.calls].count("VerifyAuthChallengeResponse") == 0
    assert state.sessions == {}


def test_correct_response_rotates_one_use_session_and_passes_response_metadata(
    topology, state_secret
):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)

    result = manager.respond(
        region=topology["region"],
        session_token=challenge.session,
        challenge_answer="secret-answer",
        client_metadata={"tenant": "enterprise"},
        invoke=flow,
    )

    assert result.issue_tokens is True
    verify = next(event for name, event in flow.calls if name == "VerifyAuthChallengeResponse")
    assert verify["request"]["clientMetadata"] == {"tenant": "enterprise"}
    assert verify["request"]["privateChallengeParameters"] == {"answer": "secret-answer"}
    define = [event for name, event in flow.calls if name == "DefineAuthChallenge"][-1]
    assert define["request"]["session"] == [
        {
            "challengeMetadata": "captcha-v1",
            "challengeName": "CUSTOM_CHALLENGE",
            "challengeResult": True,
        }
    ]
    with pytest.raises(CustomAuthError) as replay:
        manager.respond(
            region=topology["region"],
            session_token=challenge.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )
    assert replay.value.code == "NotAuthorizedException"


def test_wrong_answer_history_is_bounded_and_never_contains_raw_answer(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)

    next_challenge = manager.respond(
        region=topology["region"],
        session_token=challenge.session,
        challenge_answer="very-sensitive-wrong-answer",
        client_metadata={"surface": "mobile"},
        invoke=flow,
    )

    assert next_challenge.issue_tokens is False
    assert next_challenge.session != challenge.session
    assert "very-sensitive-wrong-answer" not in repr(state)
    stored = next(iter(state.sessions.values()))
    assert stored.history[0].challenge_result is False
    assert len(stored.history) == 1


def test_prevent_user_existence_synthetic_flow_can_never_issue_tokens(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow, missing=True)
    assert all(event["request"]["userNotFound"] for _, event in flow.calls)

    with pytest.raises(CustomAuthError) as denied:
        manager.respond(
            region=topology["region"],
            session_token=challenge.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )
    assert denied.value.code == "NotAuthorizedException"
    assert state.sessions == {}


@pytest.mark.parametrize(
    "returned",
    [
        {},
        {"response": {"issueTokens": False}},
        {
            "response": {
                "challengeName": "CUSTOM_CHALLENGE",
                "failAuthentication": False,
                "issueTokens": False,
                "unexpected": True,
            }
        },
        {
            "response": {
                "challengeName": "SMS_MFA",
                "failAuthentication": False,
                "issueTokens": False,
            }
        },
    ],
)
def test_define_lambda_response_is_strict(topology, state_secret, returned):
    manager = CustomAuthManager(CustomAuthState(), lambda _: state_secret)
    with pytest.raises(CustomAuthError) as error:
        _start(manager, topology, lambda *_: returned)
    assert error.value.code == "InvalidLambdaResponseException"


def test_expiry_quota_and_pickle_restart_are_enforced(topology, state_secret, monkeypatch):
    clock = [datetime(2026, 1, 1, tzinfo=UTC)]
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret, now=lambda: clock[0])
    challenge = _start(manager, topology, flow)
    restored = dill.loads(dill.dumps(state))
    restarted = CustomAuthManager(restored, lambda _: state_secret, now=lambda: clock[0])
    assert restarted.respond(
        region=topology["region"],
        session_token=challenge.session,
        challenge_answer="secret-answer",
        client_metadata={},
        invoke=flow,
    ).issue_tokens

    state.sessions.clear()
    monkeypatch.setattr(custom_auth_module, "MAX_CUSTOM_AUTH_SESSIONS", 1)
    first = _start(manager, topology, flow)
    with pytest.raises(CustomAuthError) as quota:
        _start(manager, {**topology, "username": "bob"}, flow)
    assert quota.value.code == "TooManyRequestsException"
    clock[0] += timedelta(minutes=4)
    with pytest.raises(CustomAuthError) as expired:
        manager.respond(
            region=topology["region"],
            session_token=first.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )
    assert expired.value.code == "NotAuthorizedException"


def test_challenge_rotation_does_not_extend_original_session_ttl(topology, state_secret):
    clock = [datetime(2026, 1, 1, tzinfo=UTC)]
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret, now=lambda: clock[0])
    challenge = _start(manager, topology, flow)
    original_expiry = next(iter(state.sessions.values())).expires_at

    clock[0] += timedelta(minutes=2, seconds=50)
    rotated = manager.respond(
        region=topology["region"],
        session_token=challenge.session,
        challenge_answer="wrong",
        client_metadata={},
        invoke=flow,
    )

    assert next(iter(state.sessions.values())).expires_at == original_expiry
    clock[0] += timedelta(seconds=11)
    with pytest.raises(CustomAuthError) as expired:
        manager.respond(
            region=topology["region"],
            session_token=rotated.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )
    assert expired.value.code == "NotAuthorizedException"


def test_session_is_region_bound_and_consumed_on_mismatch(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)
    wrong_region = "eu-west-1" if topology["region"] != "eu-west-1" else "us-west-2"

    with pytest.raises(CustomAuthError) as error:
        manager.respond(
            region=wrong_region,
            session_token=challenge.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )

    assert error.value.code == "NotAuthorizedException"
    assert state.sessions == {}


def test_cleanup_generation_journal_is_bounded_and_overflow_fails_closed(
    topology, state_secret, monkeypatch
):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)
    monkeypatch.setattr(custom_auth_module, "MAX_CUSTOM_AUTH_GENERATIONS", 2)

    manager.cleanup_user(topology["pool_id"], "unrelated-one")
    manager.cleanup_user(topology["pool_id"], "unrelated-two")
    manager.cleanup_user(topology["pool_id"], "unrelated-three")

    assert len(state.generations) == 2
    assert "unrelated" not in repr(state.generations)
    with pytest.raises(CustomAuthError) as stale:
        manager.respond(
            region=topology["region"],
            session_token=challenge.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )
    assert stale.value.code == "NotAuthorizedException"


def test_client_and_pool_cleanup_are_isolated(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    first = _start(manager, topology, flow)
    second_topology = {
        **topology,
        "client_id": uuid.uuid4().hex,
        "username": "bob",
    }
    second = _start(manager, second_topology, flow)

    manager.cleanup_client(topology["pool_id"], topology["client_id"])
    assert len(state.sessions) == 1
    with pytest.raises(CustomAuthError):
        manager.respond(
            region=topology["region"],
            session_token=first.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )

    manager.cleanup_pool(topology["pool_id"])
    assert state.sessions == {}
    with pytest.raises(CustomAuthError):
        manager.respond(
            region=topology["region"],
            session_token=second.session,
            challenge_answer="secret-answer",
            client_metadata={},
            invoke=flow,
        )


def test_concurrent_replay_invokes_verify_once(topology, state_secret):
    state = CustomAuthState()
    flow = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    second_manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, flow)
    barrier = threading.Barrier(2)
    results = []

    def respond(worker):
        barrier.wait()
        try:
            results.append(
                worker.respond(
                    region=topology["region"],
                    session_token=challenge.session,
                    challenge_answer="secret-answer",
                    client_metadata={},
                    invoke=flow,
                )
            )
        except CustomAuthError as error:
            results.append(error)

    threads = [
        threading.Thread(target=respond, args=(worker,)) for worker in (manager, second_manager)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert all(not thread.is_alive() for thread in threads)
    assert sum(getattr(result, "issue_tokens", False) for result in results) == 1
    assert [name for name, _ in flow.calls].count("VerifyAuthChallengeResponse") == 1


def test_cleanup_during_trigger_prevents_session_resurrection(topology, state_secret):
    state = CustomAuthState()
    base = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    challenge = _start(manager, topology, base)
    creating = threading.Event()
    release = threading.Event()

    def blocking(trigger, event):
        if trigger == "CreateAuthChallenge" and event["request"]["session"]:
            creating.set()
            assert release.wait(timeout=5)
        return base(trigger, event)

    outcome = []

    def respond():
        try:
            outcome.append(
                manager.respond(
                    region=topology["region"],
                    session_token=challenge.session,
                    challenge_answer="wrong",
                    client_metadata={},
                    invoke=blocking,
                )
            )
        except CustomAuthError as error:
            outcome.append(error)

    thread = threading.Thread(target=respond)
    thread.start()
    assert creating.wait(timeout=5)
    manager.cleanup_user(topology["pool_id"], topology["username"])
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert isinstance(outcome[0], CustomAuthError)
    assert outcome[0].code == "NotAuthorizedException"
    assert state.sessions == {}


def test_cleanup_during_initial_create_prevents_session_resurrection(topology, state_secret):
    state = CustomAuthState()
    base = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)
    creating = threading.Event()
    release = threading.Event()

    def blocking(trigger, event):
        if trigger == "CreateAuthChallenge":
            creating.set()
            assert release.wait(timeout=5)
        return base(trigger, event)

    outcome = []

    def start():
        try:
            outcome.append(_start(manager, topology, blocking))
        except CustomAuthError as error:
            outcome.append(error)

    thread = threading.Thread(target=start)
    thread.start()
    assert creating.wait(timeout=5)
    manager.cleanup_user(topology["pool_id"], topology["username"])
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert isinstance(outcome[0], CustomAuthError)
    assert outcome[0].code == "NotAuthorizedException"
    assert state.sessions == {}


@pytest.mark.parametrize(
    "trigger,response",
    [
        (
            "CreateAuthChallenge",
            {
                "challengeMetadata": "captcha-v1",
                "privateChallengeParameters": {"answer": object()},
                "publicChallengeParameters": {},
            },
        ),
        (
            "CreateAuthChallenge",
            {
                "challengeMetadata": "captcha-v1",
                "privateChallengeParameters": {},
                "publicChallengeParameters": None,
            },
        ),
        ("VerifyAuthChallengeResponse", {"answerCorrect": "yes"}),
    ],
)
def test_create_and_verify_lambda_responses_are_strict(topology, state_secret, trigger, response):
    state = CustomAuthState()
    base = ChallengeFlow()
    manager = CustomAuthManager(state, lambda _: state_secret)

    def malformed(name, event):
        if name == trigger:
            return {"response": response}
        return base(name, event)

    if trigger == "CreateAuthChallenge":

        def call():
            return _start(manager, topology, malformed)

    else:
        challenge = _start(manager, topology, base)

        def call():
            return manager.respond(
                region=topology["region"],
                session_token=challenge.session,
                challenge_answer="secret-answer",
                client_metadata={},
                invoke=malformed,
            )

    with pytest.raises(CustomAuthError) as error:
        call()
    assert error.value.code == "InvalidLambdaResponseException"
    assert state.sessions == {}
