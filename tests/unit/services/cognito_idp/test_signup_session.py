import pickle
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from localstack.services.cognito_idp.signup_session import (
    SignupSessionError,
    SignupSessionManager,
    SignupSessionState,
)


@pytest.fixture
def topology():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = f"aa-{uuid.uuid4().hex[:4]}-1"
    return {
        "account_id": account_id,
        "region": region_name,
        "pool_id": f"{region_name}_pool123",
        "client_id": "client123",
        "username": "alice@example.test",
        "user_sub": "01234567-89ab-cdef-0123-456789abcdef",
    }


def test_signup_confirm_initiate_user_auth_session_chain_is_one_use(topology):
    now = datetime(2026, 8, 10, tzinfo=UTC)
    manager = SignupSessionManager(SignupSessionState(), now=lambda: now)
    signup = manager.issue_signup(**topology)
    continuation = manager.confirm_signup(
        signup_session=signup,
        primary_factor="EMAIL_OTP",
        **topology,
    )
    assert signup not in repr(manager.state.sessions)
    proof = manager.consume_for_initiate_auth(
        session=continuation,
        auth_flow="USER_AUTH",
        **topology,
    )
    assert proof.primary_factor == "EMAIL_OTP"
    assert proof.first_sign_in is True
    with pytest.raises(SignupSessionError, match="Invalid or expired"):
        manager.consume_for_initiate_auth(
            session=continuation,
            auth_flow="USER_AUTH",
            **topology,
        )


def test_session_rejects_wrong_flow_binding_and_expiry(topology):
    clock = [datetime(2026, 8, 10, tzinfo=UTC)]
    manager = SignupSessionManager(
        SignupSessionState(), now=lambda: clock[0], ttl=timedelta(minutes=3)
    )
    signup = manager.issue_signup(**topology)
    with pytest.raises(SignupSessionError, match="binding"):
        manager.confirm_signup(
            signup_session=signup,
            primary_factor="EMAIL_OTP",
            **{**topology, "client_id": "different-client"},
        )

    signup = manager.issue_signup(**topology)
    continuation = manager.confirm_signup(
        signup_session=signup,
        primary_factor="SMS_OTP",
        **topology,
    )
    with pytest.raises(SignupSessionError, match="USER_AUTH"):
        manager.consume_for_initiate_auth(
            session=continuation,
            auth_flow="USER_PASSWORD_AUTH",
            **topology,
        )

    signup = manager.issue_signup(**topology)
    continuation = manager.confirm_signup(
        signup_session=signup,
        primary_factor="EMAIL_OTP",
        **topology,
    )
    clock[0] += timedelta(minutes=4)
    with pytest.raises(SignupSessionError, match="Invalid or expired"):
        manager.consume_for_initiate_auth(
            session=continuation,
            auth_flow="USER_AUTH",
            **topology,
        )


def test_confirm_can_issue_continuation_without_signup_session_and_survives_pickle(topology):
    state = SignupSessionState()
    manager = SignupSessionManager(state)
    continuation = manager.confirm_signup(
        signup_session=None,
        primary_factor="EMAIL_OTP",
        **topology,
    )
    restored = SignupSessionManager(pickle.loads(pickle.dumps(state)))
    proof = restored.consume_for_initiate_auth(
        session=continuation,
        auth_flow="USER_AUTH",
        **topology,
    )
    assert proof.username == topology["username"]


def test_concurrent_consume_and_cleanup_are_atomic(topology):
    manager = SignupSessionManager(SignupSessionState())
    continuation = manager.confirm_signup(
        signup_session=None,
        primary_factor="EMAIL_OTP",
        **topology,
    )
    outcomes = []

    def consume():
        try:
            manager.consume_for_initiate_auth(
                session=continuation,
                auth_flow="USER_AUTH",
                **topology,
            )
            outcomes.append("ok")
        except SignupSessionError:
            outcomes.append("rejected")

    workers = [threading.Thread(target=consume) for _ in range(10)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)
    assert outcomes.count("ok") == 1
    assert outcomes.count("rejected") == 9

    session = manager.confirm_signup(
        signup_session=None,
        primary_factor="EMAIL_OTP",
        **topology,
    )
    manager.cleanup_user(topology["pool_id"], topology["username"])
    with pytest.raises(SignupSessionError, match="Invalid or expired"):
        manager.consume_for_initiate_auth(
            session=session,
            auth_flow="USER_AUTH",
            **topology,
        )
