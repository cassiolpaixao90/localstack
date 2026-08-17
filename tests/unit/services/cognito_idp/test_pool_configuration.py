import copy
import hashlib
import pickle
from dataclasses import dataclass

import pytest

from localstack.services.cognito_idp.pool_configuration import (
    PoolConfigurationError,
    PoolIdentity,
    assert_password_not_reused,
    assert_pool_delete_allowed,
    commit_verified_attribute,
    invoke_pre_sign_up,
    parse_pool_configuration,
    plan_attribute_updates,
    revalidate_customer_managed_key,
    rotate_password_history,
)


@pytest.fixture
def identity():
    return PoolIdentity(partition="aws", region="us-east-1", account_id="123456789012")


def test_pool_configuration_parses_supported_contract_and_is_pickle_persistent(identity):
    request = {
        "DeletionProtection": "ACTIVE",
        "IssuerConfiguration": {"Type": "ORIGINAL"},
        "KeyConfiguration": {"KeyType": "AWS_OWNED_KEY"},
        "LambdaConfig": {
            "PreSignUp": ("arn:aws:lambda:us-east-1:123456789012:function:validate-registration")
        },
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 12,
                "PasswordHistorySize": 5,
                "TemporaryPasswordValidityDays": 0,
            }
        },
        "SmsAuthenticationMessage": "Your authentication code is {####}",
        "UserAttributeUpdateSettings": {
            "AttributesRequireVerificationBeforeUpdate": ["email", "phone_number"]
        },
        "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
    }
    original = copy.deepcopy(request)

    configuration = parse_pool_configuration(request, identity=identity)
    restored = pickle.loads(pickle.dumps(configuration))

    assert request == original
    assert restored == configuration
    assert restored.deletion_protection == "ACTIVE"
    assert restored.temporary_password_validity_days == 7
    assert restored.password_history_size == 5
    assert restored.to_response() == {
        "DeletionProtection": "ACTIVE",
        "IssuerConfiguration": {"Type": "ORIGINAL"},
        "KeyConfiguration": {"KeyType": "AWS_OWNED_KEY"},
        "LambdaConfig": request["LambdaConfig"],
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": 12,
                "PasswordHistorySize": 5,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "RequireUppercase": True,
                "TemporaryPasswordValidityDays": 7,
            }
        },
        "SmsAuthenticationMessage": "Your authentication code is {####}",
        "UserAttributeUpdateSettings": {
            "AttributesRequireVerificationBeforeUpdate": ["email", "phone_number"]
        },
        "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
    }


@pytest.mark.parametrize("value", [None, "DELETING", True, 1])
def test_deletion_protection_is_strict_and_blocks_delete(identity, value):
    request = {} if value is None else {"DeletionProtection": value}
    if value is None:
        configuration = parse_pool_configuration(request, identity=identity)
        assert configuration.deletion_protection == "INACTIVE"
        assert_pool_delete_allowed(configuration)
        return

    with pytest.raises(PoolConfigurationError) as error:
        parse_pool_configuration(request, identity=identity)
    assert error.value.code == "InvalidParameterException"

    active = parse_pool_configuration({"DeletionProtection": "ACTIVE"}, identity=identity)
    with pytest.raises(PoolConfigurationError) as protected:
        assert_pool_delete_allowed(active)
    assert protected.value.code == "InvalidParameterException"


def test_attribute_updates_remain_pending_until_the_new_destination_is_verified(identity):
    configuration = parse_pool_configuration(
        {"UserAttributeUpdateSettings": {"AttributesRequireVerificationBeforeUpdate": ["email"]}},
        identity=identity,
    )
    current = {"email": "old@example.test", "email_verified": "true", "name": "Old"}
    updates = {"email": "new@example.test", "name": "New"}
    original_current = dict(current)
    original_updates = dict(updates)

    plan = plan_attribute_updates(current, updates, configuration)

    assert current == original_current
    assert updates == original_updates
    assert plan.attributes == {
        "email": "old@example.test",
        "email_verified": "true",
        "name": "New",
    }
    assert plan.pending == {"email": "new@example.test"}

    committed = commit_verified_attribute(plan, "email")
    assert committed.attributes["email"] == "new@example.test"
    assert committed.attributes["email_verified"] == "true"
    assert committed.pending == {}


def test_attribute_update_settings_reject_duplicates_unknowns_and_oversized_values(identity):
    for values in (
        ["email", "email"],
        ["preferred_username"],
        ["email", "phone_number", "email"],
    ):
        with pytest.raises(PoolConfigurationError):
            parse_pool_configuration(
                {
                    "UserAttributeUpdateSettings": {
                        "AttributesRequireVerificationBeforeUpdate": values
                    }
                },
                identity=identity,
            )

    configuration = parse_pool_configuration({}, identity=identity)
    with pytest.raises(PoolConfigurationError):
        plan_attribute_updates({}, {"name": "x" * 2049}, configuration)


def test_advanced_security_is_explicitly_fail_closed_without_a_local_engine(identity):
    for mode in ("AUDIT", "ENFORCED"):
        with pytest.raises(PoolConfigurationError) as error:
            parse_pool_configuration(
                {"UserPoolAddOns": {"AdvancedSecurityMode": mode}}, identity=identity
            )
        assert error.value.code == "InvalidParameterException"
        assert "local advanced-security engine" in str(error.value)

    with pytest.raises(PoolConfigurationError):
        parse_pool_configuration(
            {
                "UserPoolAddOns": {
                    "AdvancedSecurityAdditionalFlows": {"CustomAuthMode": "AUDIT"},
                    "AdvancedSecurityMode": "OFF",
                }
            },
            identity=identity,
        )


def test_sms_authentication_message_requires_one_code_placeholder(identity):
    valid = "Use {####} to sign in"
    configuration = parse_pool_configuration({"SmsAuthenticationMessage": valid}, identity=identity)
    assert configuration.sms_authentication_message == valid

    multiple = parse_pool_configuration(
        {"SmsAuthenticationMessage": "Use {####}, backup {####}"}, identity=identity
    )
    assert multiple.sms_authentication_message == "Use {####}, backup {####}"

    for value in ("No code here", "x" * 141, 123):
        with pytest.raises(PoolConfigurationError):
            parse_pool_configuration({"SmsAuthenticationMessage": value}, identity=identity)


def test_issuer_configuration_runs_original_and_fails_closed_for_updated(identity):
    original = parse_pool_configuration(
        {"IssuerConfiguration": {"Type": "ORIGINAL"}}, identity=identity
    )
    assert original.issuer_type == "ORIGINAL"

    with pytest.raises(PoolConfigurationError) as error:
        parse_pool_configuration({"IssuerConfiguration": {"Type": "UPDATED"}}, identity=identity)
    assert error.value.code == "InvalidParameterException"


def test_customer_managed_key_is_scoped_and_validated_before_commit(identity):
    arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    calls = []

    configuration = parse_pool_configuration(
        {
            "KeyConfiguration": {
                "KeyType": "CUSTOMER_MANAGED_KEY",
                "KmsKeyArn": arn,
            }
        },
        identity=identity,
        kms_key_validator=lambda value: calls.append(value) or "key-id:v1:enabled",
    )

    assert calls == [arn]
    assert configuration.kms_key_arn == arn
    restored = pickle.loads(pickle.dumps(configuration))
    revalidate_customer_managed_key(restored, lambda _: "key-id:v1:enabled")
    with pytest.raises(PoolConfigurationError):
        revalidate_customer_managed_key(configuration, lambda _: "key-id:v2:disabled")
    for invalid in (
        "arn:aws:kms:us-west-2:123456789012:key/other-region",
        "arn:aws:kms:us-east-1:999999999999:key/other-account",
        "arn:aws:iam::123456789012:role/not-a-key",
    ):
        with pytest.raises(PoolConfigurationError):
            parse_pool_configuration(
                {
                    "KeyConfiguration": {
                        "KeyType": "CUSTOMER_MANAGED_KEY",
                        "KmsKeyArn": invalid,
                    }
                },
                identity=identity,
                kms_key_validator=lambda _: "key-id:v1:enabled",
            )

    with pytest.raises(PoolConfigurationError) as missing_adapter:
        parse_pool_configuration(
            {
                "KeyConfiguration": {
                    "KeyType": "CUSTOMER_MANAGED_KEY",
                    "KmsKeyArn": arn,
                }
            },
            identity=identity,
        )
    assert missing_adapter.value.code == "InvalidParameterException"


def test_pre_sign_up_receives_validation_data_and_cannot_mutate_inputs(identity):
    configuration = parse_pool_configuration(
        {"LambdaConfig": {"PreSignUp": "arn:aws:lambda:us-east-1:123456789012:function:validate"}},
        identity=identity,
    )
    attributes = {"email": "alice@example.test"}
    validation_data = {"tenant": "enterprise"}
    client_metadata = {"surface": "amplify-web"}
    seen = []

    def executor(arn, event):
        seen.append((arn, copy.deepcopy(event)))
        event["request"]["validationData"]["tenant"] = "tampered"
        return {
            "response": {
                "autoConfirmUser": True,
                "autoVerifyEmail": True,
                "autoVerifyPhone": False,
            }
        }

    result = invoke_pre_sign_up(
        configuration,
        executor,
        identity=identity,
        pool_id="us-east-1_pool",
        client_id="client-id",
        username="alice",
        trigger_source="PreSignUp_SignUp",
        user_attributes=attributes,
        validation_data=validation_data,
        client_metadata=client_metadata,
    )

    assert validation_data == {"tenant": "enterprise"}
    assert result.auto_confirm_user is True
    assert result.auto_verify_email is True
    assert seen[0][0].endswith(":function:validate")
    assert seen[0][1]["request"] == {
        "clientMetadata": client_metadata,
        "userAttributes": attributes,
        "validationData": validation_data,
    }


def test_pre_sign_up_fails_closed_on_invalid_response_or_cross_scope_lambda(identity):
    with pytest.raises(PoolConfigurationError):
        parse_pool_configuration(
            {
                "LambdaConfig": {
                    "PreSignUp": "arn:aws:lambda:us-west-2:123456789012:function:validate"
                }
            },
            identity=identity,
        )

    configuration = parse_pool_configuration(
        {"LambdaConfig": {"PreSignUp": "arn:aws:lambda:us-east-1:123456789012:function:validate"}},
        identity=identity,
    )
    with pytest.raises(PoolConfigurationError):
        invoke_pre_sign_up(
            configuration,
            lambda *_: {"response": {"autoConfirmUser": "yes"}},
            identity=identity,
            pool_id="us-east-1_pool",
            client_id="client-id",
            username="alice",
            trigger_source="PreSignUp_SignUp",
            user_attributes={},
            validation_data={},
            client_metadata={},
        )

    with pytest.raises(PoolConfigurationError) as invocation:
        invoke_pre_sign_up(
            configuration,
            lambda *_: (_ for _ in ()).throw(RuntimeError("must not escape")),
            identity=identity,
            pool_id="us-east-1_pool",
            client_id="client-id",
            username="alice",
            trigger_source="PreSignUp_SignUp",
            user_attributes={},
            validation_data={},
            client_metadata={},
        )
    assert invocation.value.code == "UnexpectedLambdaException"


@dataclass(frozen=True)
class FakePasswordHash:
    digest: str

    @classmethod
    def from_password(cls, value):
        return cls(hashlib.sha256(value.encode()).hexdigest())

    def verify(self, candidate):
        return hashlib.sha256(candidate.encode()).hexdigest() == self.digest


def test_password_history_enforces_bound_and_rotation_without_plaintext(identity):
    configuration = parse_pool_configuration(
        {"Policies": {"PasswordPolicy": {"PasswordHistorySize": 2}}}, identity=identity
    )
    current = FakePasswordHash.from_password("current")
    previous = [
        FakePasswordHash.from_password("previous-1"),
        FakePasswordHash.from_password("previous-2"),
    ]

    for reused in ("current", "previous-1", "previous-2"):
        with pytest.raises(PoolConfigurationError) as error:
            assert_password_not_reused(reused, current, previous, configuration)
        assert error.value.code == "PasswordHistoryPolicyViolationException"

    assert_password_not_reused("fresh", current, previous, configuration)
    rotated = rotate_password_history(current, previous, configuration)
    assert rotated == [current, previous[0]]
    assert "current" not in repr(pickle.dumps(rotated))


def test_password_policy_bounds_and_temporary_zero_reset(identity):
    reset = parse_pool_configuration(
        {
            "Policies": {
                "PasswordPolicy": {
                    "PasswordHistorySize": 0,
                    "TemporaryPasswordValidityDays": 0,
                }
            }
        },
        identity=identity,
    )
    assert reset.password_history_size == 0
    assert reset.temporary_password_validity_days == 7

    for policy in (
        {"PasswordHistorySize": 25},
        {"PasswordHistorySize": -1},
        {"TemporaryPasswordValidityDays": 366},
        {"MinimumLength": 5},
    ):
        with pytest.raises(PoolConfigurationError):
            parse_pool_configuration({"Policies": {"PasswordPolicy": policy}}, identity=identity)
