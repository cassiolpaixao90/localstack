import dataclasses
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from localstack.services.cognito_idp.mfa_passwordless import (
    ChallengeState,
    EmailMfaConfiguration,
    MfaPasswordlessEngine,
    MfaPasswordlessError,
    MfaPasswordlessState,
    PoolAuthPolicy,
    SmsMfaConfiguration,
    UserAuthState,
    available_recovery_attributes,
    available_user_auth_challenges,
    set_user_mfa_preferences,
    validate_pool_auth_policy,
)

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
SIGNING_KEY = b"mfa-passwordless-test-signing-key"


class StubSender:
    def __init__(self):
        self.requests = []

    def deliver_otp(self, request, reservation_id, *, commit, rollback):
        self.requests.append(request)
        if commit(reservation_id) is not True:
            rollback(reservation_id)
            raise RuntimeError("notification commit failed")
        return f"message-{len(self.requests)}"


class FailingSender:
    def deliver_otp(self, _request, reservation_id, *, commit, rollback):
        rollback(reservation_id)
        raise RuntimeError("delivery failed")


@pytest.fixture
def policy():
    return PoolAuthPolicy(
        mfa_configuration="OPTIONAL",
        allowed_first_auth_factors=frozenset({"PASSWORD", "EMAIL_OTP", "SMS_OTP"}),
        auto_verified_attributes=frozenset({"email", "phone_number"}),
        recovery_attributes=(),
        email_mfa=EmailMfaConfiguration(
            message="Your email authentication code is {####}.",
            subject="Authentication code",
        ),
        sms_mfa=SmsMfaConfiguration(
            message="Your SMS authentication code is {####}.",
            sms_configuration={"SnsCallerArn": "arn:aws:iam::123456789012:role/cognito-sms"},
        ),
    )


@pytest.fixture
def user():
    return UserAuthState(
        username="alice",
        password_enabled=True,
        attributes={"email": "alice@example.com", "phone_number": "+15551234567"},
        verified_attributes=frozenset({"email", "phone_number"}),
    )


@pytest.fixture
def engine():
    return MfaPasswordlessEngine(signing_key=SIGNING_KEY)


def test_pool_mfa_configurations_validate_templates_auto_verification_and_recovery(policy):
    validate_pool_auth_policy(policy)
    for invalid in (
        PoolAuthPolicy(
            allowed_first_auth_factors=frozenset({"EMAIL_OTP"}),
            auto_verified_attributes=frozenset(),
        ),
        PoolAuthPolicy(
            mfa_configuration="ON",
            email_mfa=EmailMfaConfiguration(message="missing placeholder", subject="Code"),
            auto_verified_attributes=frozenset({"email"}),
            recovery_attributes=("email",),
        ),
        PoolAuthPolicy(
            mfa_configuration="ON",
            sms_mfa=SmsMfaConfiguration(message="Code {####}", sms_configuration={}),
            auto_verified_attributes=frozenset({"phone_number"}),
            recovery_attributes=("phone_number",),
        ),
    ):
        with pytest.raises(MfaPasswordlessError):
            validate_pool_auth_policy(invalid)


def test_passwordless_and_email_mfa_enforce_feature_tier_and_developer_email():
    for policy, code in (
        (
            PoolAuthPolicy(
                feature_tier="LITE",
                allowed_first_auth_factors=frozenset({"PASSWORD", "EMAIL_OTP"}),
                auto_verified_attributes=frozenset({"email"}),
            ),
            "FeatureUnavailableInTierException",
        ),
        (
            PoolAuthPolicy(
                feature_tier="LITE",
                email_mfa=EmailMfaConfiguration(),
            ),
            "FeatureUnavailableInTierException",
        ),
        (
            PoolAuthPolicy(
                email_sending_account="COGNITO_DEFAULT",
                email_mfa=EmailMfaConfiguration(),
            ),
            "InvalidParameterException",
        ),
    ):
        with pytest.raises(MfaPasswordlessError) as raised:
            validate_pool_auth_policy(policy)
        assert raised.value.code == code


def test_user_mfa_preferences_require_configured_factor_valid_destination_and_one_preferred(
    policy, user
):
    configured = set_user_mfa_preferences(
        policy,
        user,
        sms={"Enabled": True, "PreferredMfa": True},
        email={"Enabled": True, "PreferredMfa": False},
    )
    assert configured.sms_mfa_enabled is True
    assert configured.sms_mfa_preferred is True
    assert configured.email_mfa_enabled is True
    assert configured.email_mfa_preferred is False

    unverified = UserAuthState(
        username="bob",
        password_enabled=True,
        attributes={"email": "bob@example.com"},
    )
    configured_unverified = set_user_mfa_preferences(
        policy,
        unverified,
        email={"Enabled": True, "PreferredMfa": True},
    )
    assert configured_unverified.email_mfa_enabled is True
    with pytest.raises(MfaPasswordlessError, match="valid"):
        set_user_mfa_preferences(
            policy,
            dataclasses.replace(unverified, attributes={}),
            email={"Enabled": True, "PreferredMfa": True},
        )
    with pytest.raises(MfaPasswordlessError, match="preferred"):
        set_user_mfa_preferences(
            policy,
            user,
            sms={"Enabled": True, "PreferredMfa": True},
            email={"Enabled": True, "PreferredMfa": True},
        )
    with pytest.raises(MfaPasswordlessError, match="must be enabled"):
        set_user_mfa_preferences(
            policy,
            user,
            email={"PreferredMfa": True},
        )
    with pytest.raises(MfaPasswordlessError, match="Only one"):
        set_user_mfa_preferences(
            policy,
            dataclasses.replace(
                user,
                software_token_mfa_enabled=True,
                software_token_mfa_preferred=True,
            ),
            sms={"Enabled": True, "PreferredMfa": True},
        )


def test_mfa_destinations_do_not_require_auto_verification_configuration(user):
    mfa_only = PoolAuthPolicy(
        mfa_configuration="OPTIONAL",
        allowed_first_auth_factors=frozenset({"PASSWORD"}),
        auto_verified_attributes=frozenset(),
        recovery_attributes=(),
        email_mfa=EmailMfaConfiguration(),
    )
    configured = set_user_mfa_preferences(
        mfa_only,
        dataclasses.replace(user, verified_attributes=frozenset()),
        email={"Enabled": True, "PreferredMfa": True},
    )
    assert configured.email_mfa_enabled is True
    engine = MfaPasswordlessEngine(signing_key=SIGNING_KEY)
    started = engine.start_mfa(
        policy=mfa_only,
        user=configured,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        client_metadata={},
        sender=StubSender(),
        now=NOW,
        code_factory=lambda: "123456",
    )
    assert engine.complete_otp(
        challenge_name="EMAIL_OTP",
        session=started["Session"],
        username="alice",
        response_code="EMAIL_OTP_CODE",
        response_value="123456",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=1),
    ).verified_attribute == "email"

    sms_uses_existing_delivery = PoolAuthPolicy(
        mfa_configuration="OPTIONAL",
        sms_delivery_configured=True,
        recovery_attributes=(),
        sms_mfa=SmsMfaConfiguration(message="Code {####}"),
    )
    validate_pool_auth_policy(sms_uses_existing_delivery)


def test_recovery_excludes_the_same_verified_destination_used_for_mfa(user):
    policy = PoolAuthPolicy(
        mfa_configuration="OPTIONAL",
        auto_verified_attributes=frozenset({"email", "phone_number"}),
        recovery_attributes=("email", "phone_number"),
        sms_mfa=SmsMfaConfiguration(
            message="Code {####}",
            sms_configuration={"SnsCallerArn": "arn:aws:iam::123456789012:role/sms"},
        ),
    )
    with_sms = set_user_mfa_preferences(
        policy,
        user,
        sms={"Enabled": True, "PreferredMfa": True},
    )
    assert available_recovery_attributes(policy, with_sms) == ["email"]


def test_user_auth_without_preference_returns_select_challenge_and_available_choices(
    engine, policy, user
):
    started = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge=None,
        prevent_user_existence_errors=True,
        client_metadata={"tenant": "one"},
        sender=StubSender(),
        now=NOW,
    )
    assert started["ChallengeName"] == "SELECT_CHALLENGE"
    assert started["AvailableChallenges"] == [
        "PASSWORD",
        "PASSWORD_SRP",
        "EMAIL_OTP",
        "SMS_OTP",
    ]
    assert started["ChallengeParameters"] == {"USERNAME": "alice"}
    assert started["Session"] not in engine.persisted_tokens()


@pytest.mark.parametrize(
    ("challenge", "medium", "attribute", "response_key"),
    (
        ("EMAIL_OTP", "EMAIL", "email", "EMAIL_OTP_CODE"),
        ("SMS_OTP", "SMS", "phone_number", "SMS_OTP_CODE"),
    ),
)
def test_passwordless_otp_is_hash_only_single_use_and_propagates_metadata(
    engine, policy, user, challenge, medium, attribute, response_key
):
    sender = StubSender()
    started = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge=challenge,
        prevent_user_existence_errors=True,
        client_metadata={"tenant": "one"},
        sender=sender,
        now=NOW,
        code_factory=lambda: "123456",
    )
    assert started["ChallengeName"] == challenge
    assert started["ChallengeParameters"]["CODE_DELIVERY_DELIVERY_MEDIUM"] == medium
    assert started["ChallengeParameters"]["CODE_DELIVERY_DESTINATION"] != user.attributes[
        attribute
    ]
    assert sender.requests[0].secret == "123456"
    assert "123456" not in pickle.dumps(engine).decode("latin1")

    completed = engine.complete_otp(
        challenge_name=challenge,
        session=started["Session"],
        username="alice",
        response_code=response_key,
        response_value="123456",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=1),
    )
    assert completed.username == "alice"
    assert completed.client_metadata == {"tenant": "one"}
    assert completed.verified_attribute == attribute
    assert completed.confirm_user is True
    with pytest.raises(MfaPasswordlessError, match="Invalid authentication session"):
        engine.complete_otp(
            challenge_name=challenge,
            session=started["Session"],
            username="alice",
            response_code=response_key,
            response_value="123456",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(seconds=2),
        )


def test_select_challenge_can_transition_to_password_and_password_srp(engine, policy, user):
    for answer in ("PASSWORD", "PASSWORD_SRP"):
        selected = engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge=None,
            prevent_user_existence_errors=True,
            client_metadata={"request": answer},
            sender=StubSender(),
            now=NOW,
        )
        challenge = engine.respond_select_challenge(
            policy=policy,
            user=user,
            session=selected["Session"],
            answer=answer,
            username="alice",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            sender=StubSender(),
            now=NOW + timedelta(seconds=1),
        )
        assert challenge["ChallengeName"] == answer
        consumed = engine.consume_primary_challenge(
            challenge_name=answer,
            session=challenge["Session"],
            username="alice",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(seconds=2),
        )
        assert consumed.client_metadata == {"request": answer}


def test_sms_mfa_uses_distinct_challenge_contract_and_verified_phone(engine, policy, user):
    sender = StubSender()
    preferred = set_user_mfa_preferences(
        policy,
        user,
        sms={"Enabled": True, "PreferredMfa": True},
    )
    started = engine.start_mfa(
        policy=policy,
        user=preferred,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        client_metadata={"source": "password"},
        sender=sender,
        now=NOW,
        code_factory=lambda: "654321",
    )
    assert started["ChallengeName"] == "SMS_MFA"
    completed = engine.complete_otp(
        challenge_name="SMS_MFA",
        session=started["Session"],
        username="alice",
        response_code="SMS_MFA_CODE",
        response_value="654321",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=1),
    )
    assert completed.verified_attribute == "phone_number"
    assert completed.confirm_user is False
    assert completed.client_metadata == {"source": "password"}


def test_multiple_mfa_without_preference_returns_select_mfa_type(engine, policy, user):
    both = set_user_mfa_preferences(
        policy,
        user,
        sms={"Enabled": True, "PreferredMfa": False},
        email={"Enabled": True, "PreferredMfa": False},
    )
    selected = engine.start_mfa(
        policy=policy,
        user=both,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        client_metadata={"source": "srp"},
        sender=StubSender(),
        now=NOW,
    )
    assert selected["ChallengeName"] == "SELECT_MFA_TYPE"
    assert selected["ChallengeParameters"]["MFAS_CAN_CHOOSE"] == '["SMS_MFA","EMAIL_OTP"]'
    sender = StubSender()
    otp = engine.respond_select_mfa(
        policy=policy,
        user=both,
        session=selected["Session"],
        answer="EMAIL_OTP",
        username="alice",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        sender=sender,
        now=NOW + timedelta(seconds=1),
        code_factory=lambda: "123456",
    )
    assert otp["ChallengeName"] == "EMAIL_OTP"
    assert sender.requests[0].purpose == "EMAIL_MFA"
    assert engine.complete_otp(
        challenge_name="EMAIL_OTP",
        session=otp["Session"],
        username="alice",
        response_code="EMAIL_OTP_CODE",
        response_value="123456",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=2),
    ).client_metadata == {"source": "srp"}


def test_pue_unknown_user_is_indistinguishable_does_not_send_and_never_authenticates(
    engine, policy, user
):
    sender = StubSender()
    started = engine.start_user_auth(
        policy=policy,
        user=None,
        username="missing",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="EMAIL_OTP",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=sender,
        now=NOW,
        code_factory=lambda: "123456",
    )
    assert started["ChallengeName"] == "EMAIL_OTP"
    assert started["ChallengeParameters"]["CODE_DELIVERY_DELIVERY_MEDIUM"] == "EMAIL"
    assert sender.requests == []
    real = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="EMAIL_OTP",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=sender,
        now=NOW,
    )
    assert (
        started["ChallengeParameters"]["CODE_DELIVERY_DESTINATION"]
        == real["ChallengeParameters"]["CODE_DELIVERY_DESTINATION"]
    )
    with pytest.raises(MfaPasswordlessError) as mismatch:
        engine.complete_otp(
            challenge_name="EMAIL_OTP",
            session=started["Session"],
            username="missing",
            response_code="EMAIL_OTP_CODE",
            response_value="000000",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(milliseconds=500),
        )
    assert mismatch.value.code == "CodeMismatchException"
    with pytest.raises(MfaPasswordlessError) as raised:
        engine.complete_otp(
            challenge_name="EMAIL_OTP",
            session=started["Session"],
            username="missing",
            response_code="EMAIL_OTP_CODE",
            response_value="123456",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(seconds=1),
        )
    assert raised.value.code == "NotAuthorizedException"


def test_pue_select_challenge_stays_synthetic_across_transition(engine, policy):
    sender = StubSender()
    selected = engine.start_user_auth(
        policy=policy,
        user=None,
        username="missing",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge=None,
        prevent_user_existence_errors=True,
        client_metadata={"pue": "yes"},
        sender=sender,
        now=NOW,
    )
    assert selected["AvailableChallenges"] == [
        "PASSWORD",
        "PASSWORD_SRP",
        "EMAIL_OTP",
        "SMS_OTP",
    ]
    otp = engine.respond_select_challenge(
        policy=policy,
        user=None,
        session=selected["Session"],
        answer="SMS_OTP",
        username="missing",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        sender=sender,
        now=NOW + timedelta(seconds=1),
        code_factory=lambda: "123456",
    )
    assert otp["ChallengeName"] == "SMS_OTP"
    assert sender.requests == []
    with pytest.raises(MfaPasswordlessError) as raised:
        engine.complete_otp(
            challenge_name="SMS_OTP",
            session=otp["Session"],
            username="missing",
            response_code="SMS_OTP_CODE",
            response_value="123456",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(seconds=2),
        )
    assert raised.value.code == "NotAuthorizedException"


def test_pue_disabled_unknown_user_fails_before_creating_state(engine, policy):
    with pytest.raises(MfaPasswordlessError) as raised:
        engine.start_user_auth(
            policy=policy,
            user=None,
            username="missing",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=False,
            client_metadata={},
            sender=StubSender(),
            now=NOW,
        )
    assert raised.value.code == "UserNotFoundException"
    assert engine.session_count == 0


def test_wrong_code_is_bounded_and_expiry_cleanup_is_deterministic(engine, policy, user):
    started = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="SMS_OTP",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=StubSender(),
        now=NOW,
        code_factory=lambda: "123456",
    )
    for attempt in range(5):
        with pytest.raises(MfaPasswordlessError) as raised:
            engine.complete_otp(
                challenge_name="SMS_OTP",
                session=started["Session"],
                username="alice",
                response_code="SMS_OTP_CODE",
                response_value="000000",
                pool_id="us-east-1_EXAMPLE",
                client_id="client",
                now=NOW + timedelta(seconds=attempt + 1),
            )
        assert raised.value.code == "CodeMismatchException"
    assert engine.session_count == 0

    expiring = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="EMAIL_OTP",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=StubSender(),
        now=NOW,
    )
    with pytest.raises(MfaPasswordlessError, match="Invalid authentication session"):
        engine.complete_otp(
            challenge_name="EMAIL_OTP",
            session=expiring["Session"],
            username="alice",
            response_code="EMAIL_OTP_CODE",
            response_value="000000",
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            now=NOW + timedelta(minutes=6),
        )
    assert engine.session_count == 0


def test_concurrent_completion_has_exactly_one_success(engine, policy, user):
    started = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="EMAIL_OTP",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=StubSender(),
        now=NOW,
        code_factory=lambda: "123456",
    )

    def complete_once(_):
        try:
            engine.complete_otp(
                challenge_name="EMAIL_OTP",
                session=started["Session"],
                username="alice",
                response_code="EMAIL_OTP_CODE",
                response_value="123456",
                pool_id="us-east-1_EXAMPLE",
                client_id="client",
                now=NOW + timedelta(seconds=1),
            )
            return "success"
        except MfaPasswordlessError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(complete_once, range(8)))
    assert outcomes.count("success") == 1
    assert outcomes.count("NotAuthorizedException") == 7


def test_engine_is_pickle_persistent_without_plain_sessions(engine, policy, user):
    started = engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="PASSWORD",
        prevent_user_existence_errors=True,
        client_metadata={"persisted": "yes"},
        sender=StubSender(),
        now=NOW,
    )
    restored = pickle.loads(pickle.dumps(engine))
    assert started["Session"] not in restored.persisted_tokens()
    assert restored.consume_primary_challenge(
        challenge_name="PASSWORD",
        session=started["Session"],
        username="alice",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=1),
    ).client_metadata == {"persisted": "yes"}


def test_persisted_state_is_shared_by_ephemeral_engines(policy, user):
    state = MfaPasswordlessState()
    first = MfaPasswordlessEngine(signing_key=SIGNING_KEY, state=state)
    started = first.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="EMAIL_OTP",
        prevent_user_existence_errors=True,
        client_metadata={"manager": "first"},
        sender=StubSender(),
        now=NOW,
        code_factory=lambda: "123456",
    )
    restored_state = pickle.loads(pickle.dumps(state))
    second = MfaPasswordlessEngine(signing_key=SIGNING_KEY, state=restored_state)
    assert second.complete_otp(
        challenge_name="EMAIL_OTP",
        session=started["Session"],
        username="alice",
        response_code="EMAIL_OTP_CODE",
        response_value="123456",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=1),
    ).client_metadata == {"manager": "first"}


def test_cleanup_is_bound_to_pool_and_optional_username(engine, policy, user):
    for current in (
        user,
        dataclasses.replace(user, username="bob"),
    ):
        engine.start_user_auth(
            policy=policy,
            user=current,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="PASSWORD",
            prevent_user_existence_errors=True,
            client_metadata={},
            sender=StubSender(),
            now=NOW,
        )
    engine.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_OTHER",
        client_id="client",
        preferred_challenge="PASSWORD",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=StubSender(),
        now=NOW,
    )
    assert engine.cleanup(pool_id="us-east-1_EXAMPLE", username="alice") == 1
    assert engine.session_count == 2
    assert engine.cleanup(pool_id="us-east-1_EXAMPLE") == 1
    assert engine.session_count == 1


def test_bounds_reject_oversized_metadata_invalid_codes_and_capacity(engine, policy, user):
    with pytest.raises(MfaPasswordlessError):
        engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={"x": "y" * 2049},
            sender=StubSender(),
            now=NOW,
        )
    with pytest.raises(MfaPasswordlessError):
        engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={},
            sender=StubSender(),
            now=NOW,
            code_factory=lambda: "12345x",
        )

    bounded = MfaPasswordlessEngine(signing_key=SIGNING_KEY, maximum_sessions=1)
    bounded.start_user_auth(
        policy=policy,
        user=user,
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        preferred_challenge="PASSWORD",
        prevent_user_existence_errors=True,
        client_metadata={},
        sender=StubSender(),
        now=NOW,
    )
    with pytest.raises(MfaPasswordlessError) as capacity:
        bounded.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={},
            sender=StubSender(),
            now=NOW,
        )
    assert capacity.value.code == "LimitExceededException"


def test_delivery_failure_aborts_pending_challenge(engine, policy, user):
    with pytest.raises(RuntimeError, match="delivery failed"):
        engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={},
            sender=FailingSender(),
            now=NOW,
        )
    assert engine.session_count == 0


def test_delivery_adapter_cannot_return_without_committing_reservation(engine, policy, user):
    class NonCommittingSender:
        def deliver_otp(self, _request, _reservation_id, *, commit, rollback):
            return "uncommitted-message"

    with pytest.raises(MfaPasswordlessError) as error:
        engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={},
            sender=NonCommittingSender(),
            now=NOW,
        )
    assert error.value.code == "NotAuthorizedException"
    assert engine.session_count == 0


def test_concurrent_delivery_replacement_cannot_activate_stale_reservation(policy, user):
    engine = MfaPasswordlessEngine(signing_key=SIGNING_KEY)
    entered = threading.Event()
    release = threading.Event()

    class BlockingSender:
        def deliver_otp(self, _request, reservation_id, *, commit, rollback):
            entered.set()
            assert release.wait(timeout=5)
            if commit(reservation_id) is not True:
                rollback(reservation_id)
                raise RuntimeError("notification commit failed")
            return "stale-message"

    def start_stale():
        try:
            engine.start_user_auth(
                policy=policy,
                user=user,
                pool_id="us-east-1_EXAMPLE",
                client_id="client",
                preferred_challenge="EMAIL_OTP",
                prevent_user_existence_errors=True,
                client_metadata={"generation": "old"},
                sender=BlockingSender(),
                now=NOW,
                code_factory=lambda: "111111",
            )
            return "unexpected-success"
        except MfaPasswordlessError as error:
            return error.code
        except RuntimeError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        stale = executor.submit(start_stale)
        assert entered.wait(timeout=5)
        current = engine.start_user_auth(
            policy=policy,
            user=user,
            pool_id="us-east-1_EXAMPLE",
            client_id="client",
            preferred_challenge="EMAIL_OTP",
            prevent_user_existence_errors=True,
            client_metadata={"generation": "new"},
            sender=StubSender(),
            now=NOW + timedelta(seconds=1),
            code_factory=lambda: "222222",
        )
        release.set()
        assert stale.result(timeout=5) == "notification commit failed"
    assert engine.session_count == 1
    assert engine.complete_otp(
        challenge_name="EMAIL_OTP",
        session=current["Session"],
        username="alice",
        response_code="EMAIL_OTP_CODE",
        response_value="222222",
        pool_id="us-east-1_EXAMPLE",
        client_id="client",
        now=NOW + timedelta(seconds=2),
    ).client_metadata == {"generation": "new"}


def test_available_challenges_accept_unverified_otp_destination_and_success_verifies_it(
    policy, user
):
    assert available_user_auth_challenges(policy, user) == [
        "PASSWORD",
        "PASSWORD_SRP",
        "EMAIL_OTP",
        "SMS_OTP",
    ]
    unverified = UserAuthState(
        username="alice",
        password_enabled=True,
        attributes=user.attributes,
        verified_attributes=frozenset(),
    )
    assert available_user_auth_challenges(policy, unverified) == [
        "PASSWORD",
        "PASSWORD_SRP",
        "EMAIL_OTP",
        "SMS_OTP",
    ]
    assert ChallengeState.ACTIVE.value == "ACTIVE"


def test_passwordless_otp_is_unavailable_with_required_or_user_activated_mfa(user):
    required = PoolAuthPolicy(
        mfa_configuration="ON",
        allowed_first_auth_factors=frozenset({"PASSWORD", "EMAIL_OTP"}),
        auto_verified_attributes=frozenset({"email"}),
        email_mfa=EmailMfaConfiguration(),
        recovery_attributes=(),
    )
    with pytest.raises(MfaPasswordlessError, match="incompatible"):
        validate_pool_auth_policy(required)

    optional = dataclasses.replace(required, mfa_configuration="OPTIONAL")
    active_mfa = dataclasses.replace(user, email_mfa_enabled=True, email_mfa_preferred=True)
    assert available_user_auth_challenges(optional, active_mfa) == [
        "PASSWORD",
        "PASSWORD_SRP",
    ]
    active_totp = dataclasses.replace(user, software_token_mfa_enabled=True)
    assert available_user_auth_challenges(optional, active_totp) == [
        "PASSWORD",
        "PASSWORD_SRP",
    ]
