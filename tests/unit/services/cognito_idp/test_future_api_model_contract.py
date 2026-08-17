import pickle
import uuid
from pathlib import Path

import botocore
import pytest
from botocore.session import Session

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp import user_pool_replicas as replica_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.plugins import Service

ROOT = Path(__file__).parents[4]
EXPECTED_VERSION = "1.43.67"
NEW_OPERATIONS = {
    "AdminGetUserAuthFactors": "admin_get_user_auth_factors",
    "CreateUserPoolReplica": "create_user_pool_replica",
    "DeleteUserPoolReplica": "delete_user_pool_replica",
    "GetProvisionedLimit": "get_provisioned_limit",
    "ListUserPoolReplicas": "list_user_pool_replicas",
    "UpdateProvisionedLimit": "update_provisioned_limit",
    "UpdateUserPoolReplica": "update_user_pool_replica",
}


def test_botocore_pins_are_atomically_updated_to_1_43_67():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert '"boto3==1.43.67"' in pyproject
    assert '"botocore==1.43.67"' in pyproject
    assert '"awscli==1.46.0"' in pyproject
    for name in (
        "requirements-base-runtime.txt",
        "requirements-dev.txt",
        "requirements-runtime.txt",
        "requirements-test.txt",
        "requirements-typehint.txt",
    ):
        contents = (ROOT / name).read_text()
        assert "boto3==1.43.67" in contents
        assert "botocore==1.43.67" in contents
        assert "s3transfer==0.19.2" in contents


def test_botocore_1_43_67_exposes_exact_129_operation_contract():
    if botocore.__version__ != EXPECTED_VERSION:
        pytest.xfail(
            f"runtime dependency refresh pending: {botocore.__version__} != {EXPECTED_VERSION}"
        )
    model = Session().get_service_model("cognito-idp")
    assert len(model.operation_names) == 129
    assert set(NEW_OPERATIONS) <= set(model.operation_names)
    assert list(model.operation_model("AdminGetUserAuthFactors").input_shape.members) == [
        "UserPoolId",
        "Username",
    ]
    assert list(model.operation_model("GetProvisionedLimit").input_shape.members) == [
        "LimitDefinition"
    ]
    assert list(model.operation_model("UpdateUserPoolReplica").input_shape.members) == [
        "UserPoolId",
        "RegionName",
        "Status",
    ]


def test_botocore_1_43_67_exposes_sms_email_mfa_and_choice_auth_contracts():
    if botocore.__version__ != EXPECTED_VERSION:
        pytest.xfail(
            f"runtime dependency refresh pending: {botocore.__version__} != {EXPECTED_VERSION}"
        )
    model = Session().get_service_model("cognito-idp")
    challenges = set(model.shape_for("ChallengeNameType").enum)
    assert {
        "EMAIL_OTP",
        "PASSWORD",
        "PASSWORD_SRP",
        "SELECT_CHALLENGE",
        "SMS_MFA",
        "SMS_OTP",
    } <= challenges
    assert "EMAIL_MFA" not in challenges
    set_pool_mfa = model.operation_model("SetUserPoolMfaConfig")
    assert {"EmailMfaConfiguration", "SmsMfaConfiguration"} <= set(set_pool_mfa.input_shape.members)
    assert {"EmailMfaConfiguration", "SmsMfaConfiguration"} <= set(
        set_pool_mfa.output_shape.members
    )
    email_mfa = model.shape_for("EmailMfaConfigType")
    assert list(email_mfa.members) == ["Message", "Subject"]
    assert email_mfa.members["Message"].metadata["min"] == 6
    assert email_mfa.members["Message"].metadata["max"] == 20_000
    sms_mfa = model.shape_for("SmsMfaConfigType")
    assert list(sms_mfa.members) == [
        "SmsAuthenticationMessage",
        "SmsConfiguration",
    ]
    assert sms_mfa.members["SmsAuthenticationMessage"].metadata["min"] == 6
    assert sms_mfa.members["SmsAuthenticationMessage"].metadata["max"] == 140
    allowed_shape = model.shape_for("AllowedFirstAuthFactorsListType")
    assert allowed_shape.metadata == {"max": 5, "min": 1}
    allowed_factors = set(allowed_shape.member.enum)
    assert {"EMAIL_OTP", "PASSWORD", "SMS_OTP", "WEB_AUTHN"} <= allowed_factors
    assert model.shape_for("SessionType").metadata["min"] == 20
    assert model.shape_for("SessionType").metadata["max"] == 2_048
    assert model.shape_for("AuthSessionValidityType").metadata == {"max": 15, "min": 3}


@pytest.mark.parametrize(("operation", "method"), NEW_OPERATIONS.items())
def test_red_provider_must_dispatch_all_new_modeled_operations(operation, method):
    assert hasattr(CognitoIdpProvider, method), f"RED: {operation} lacks provider dispatch"


@pytest.fixture
def context(region_name):
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = region_name
    yield value
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    if store.POOL_LOCATIONS.get(pool_id) == (
                        value.account_id,
                        store._region_name,
                    ):
                        store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


@pytest.fixture
def future_api_topology(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "future-api-pool"})["UserPool"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "Username": "alice",
            "UserPoolId": pool["Id"],
        },
    )
    yield pool
    try:
        provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    except CommonServiceException as error:
        if error.code != "ResourceNotFoundException":
            raise
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert pool["Id"] not in store.user_pool_replicas
        assert pool["Id"] not in store.POOL_LOCATIONS


def test_provider_dispatches_exact_current_botocore_contract(provider):
    expected = set(Session().get_service_model("cognito-idp").operation_names)
    dispatched = set(Service.for_provider(provider).skeleton.dispatch_table)

    assert len(expected) == 129
    assert dispatched == expected


def test_admin_get_user_auth_factors_uses_current_user_state(
    provider, context, future_api_topology
):
    response = provider.admin_get_user_auth_factors(
        context,
        {"Username": "alice", "UserPoolId": future_api_topology["Id"]},
    )

    assert response == {"ConfiguredUserAuthFactors": ["PASSWORD"], "Username": "alice"}


def test_replica_handlers_share_primary_state_across_regions_and_cleanup(
    provider, context, future_api_topology, monkeypatch
):
    monkeypatch.setattr(replica_module, "_TRANSITION_DELAY", replica_module.timedelta(0))
    secondary_region = next(
        region
        for region in Session().get_available_regions("cognito-idp")
        if region != context.region
    )
    pool_id = future_api_topology["Id"]
    with pytest.raises(CommonServiceException) as same_region:
        provider.create_user_pool_replica(
            context,
            {"RegionName": context.region, "UserPoolId": pool_id},
        )
    assert same_region.value.code == "InvalidParameterException"
    assert pool_id not in provider.get_store(context).user_pool_replicas

    created = provider.create_user_pool_replica(
        context,
        {
            "RegionName": secondary_region,
            "UserPoolId": pool_id,
            "UserPoolTags": {"Owner": "future-api-contract"},
        },
    )["UserPoolReplica"]
    assert created["Status"] == "CREATING"

    listed = provider.list_user_pool_replicas(context, {"UserPoolId": pool_id})
    assert [item["Role"] for item in listed["UserPoolReplicas"]] == ["PRIMARY", "SECONDARY"]
    assert listed["UserPoolReplicas"][1]["Status"] == "INACTIVE"

    secondary_context = RequestContext(None)
    secondary_context.account_id = context.account_id
    secondary_context.region = secondary_region
    active = provider.update_user_pool_replica(
        secondary_context,
        {"RegionName": secondary_region, "Status": "ACTIVE", "UserPoolId": pool_id},
    )["UserPoolReplica"]
    assert active["Status"] == "ACTIVE"
    provider.update_user_pool_replica(
        context,
        {"RegionName": secondary_region, "Status": "INACTIVE", "UserPoolId": pool_id},
    )
    deleted = provider.delete_user_pool_replica(
        context, {"RegionName": secondary_region, "UserPoolId": pool_id}
    )["UserPoolReplica"]
    assert deleted["Status"] == "DELETING"
    assert provider.list_user_pool_replicas(context, {"UserPoolId": pool_id})[
        "UserPoolReplicas"
    ] == [listed["UserPoolReplicas"][0]]

    restored = pickle.loads(pickle.dumps(provider.get_store(context).user_pool_replicas))
    assert restored[pool_id].secondary is None


def test_provisioned_limit_handlers_are_scoped_atomic_and_persistent(
    provider, context, monkeypatch
):
    definition = {
        "Attributes": {"Category": "UserAuthentication"},
        "LimitClass": "API_CATEGORY",
    }
    monkeypatch.setitem(
        provider_module._PROVISIONED_LIMIT_ACCOUNT_MAXIMA, "UserAuthentication", 500
    )
    assert (
        provider.get_provisioned_limit(context, {"LimitDefinition": definition})["Limit"][
            "ProvisionedLimitValue"
        ]
        == 120
    )
    updated = provider.update_provisioned_limit(
        context,
        {"LimitDefinition": definition, "RequestedLimitValue": 300},
    )
    assert updated["Limit"]["ProvisionedLimitValue"] == 300
    restored = pickle.loads(pickle.dumps(provider.get_store(context).provisioned_limits))
    assert restored.values[(context.account_id, context.region, "UserAuthentication")] == 300

    with pytest.raises(CommonServiceException) as excessive:
        provider.update_provisioned_limit(
            context,
            {"LimitDefinition": definition, "RequestedLimitValue": 501},
        )
    assert excessive.value.code == "ServiceQuotaExceededException"
    assert provider.get_provisioned_limit(context, {"LimitDefinition": definition}) == updated
