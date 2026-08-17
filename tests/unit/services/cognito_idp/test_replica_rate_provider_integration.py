import uuid

import pytest
from botocore.session import Session

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.http import Request
from localstack.services.cognito_idp import notification_delivery
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp import provisioned_rate_enforcement as rate_module
from localstack.services.cognito_idp.endpoints import CognitoIdpJwksEndpoint
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment
from localstack.services.cognito_idp.user_pool_replicas import (
    UserPoolReplica,
    UserPoolReplicaTopology,
)
from localstack.utils.aws.arns import get_partition


@pytest.fixture
def regional_contexts(region_name):
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    secondary_region = next(
        candidate
        for candidate in Session().get_available_regions("cognito-idp")
        if candidate != region_name and get_partition(candidate) == get_partition(region_name)
    )

    def context(region):
        value = RequestContext(None)
        value.account_id = account_id
        value.region = region
        value.partition = get_partition(region)
        return value

    yield context(region_name), context(secondary_region)
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(account_id, None)


@pytest.fixture
def replicated_stack(regional_contexts):
    primary, secondary = regional_contexts
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(primary, {"PoolName": "replicated-users"})["UserPool"]
    client = provider.create_user_pool_client(
        primary,
        {
            "ClientName": "regional-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        primary,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        primary,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[primary.account_id][primary.region]
        store.user_pool_replicas[pool["Id"]] = UserPoolReplicaTopology(
            account_id=primary.account_id,
            partition=primary.partition,
            pool_id=pool["Id"],
            primary_region=primary.region,
            secondary=UserPoolReplica(region_name=secondary.region, status="ACTIVE"),
        )
    return provider, primary, secondary, pool, client


def test_active_secondary_reads_authenticates_and_issues_regional_tokens(replicated_stack):
    provider, _, secondary, pool, client = replicated_stack

    described = provider.describe_user_pool(secondary, {"UserPoolId": pool["Id"]})
    authenticated = provider.initiate_auth(
        secondary,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )

    assert described["UserPool"]["Id"] == pool["Id"]
    claims = decode_jwt_segment(authenticated["AuthenticationResult"]["IdToken"].split(".")[1])
    assert claims["iss"].startswith(f"https://cognito-idp.{secondary.region}.")
    assert claims["iss"].endswith(f"/{pool['Id']}")


def test_oversized_untrusted_access_token_is_rejected_before_jwt_decode(
    replicated_stack, monkeypatch
):
    provider, _, secondary, _, _ = replicated_stack
    decoded = []

    def decode(value):
        decoded.append(value)
        return {}

    monkeypatch.setattr(provider_module, "decode_jwt_segment", decode)
    token = f"a.{'b' * (16 * 1024 + 1)}.c"

    assert provider._request_pool_id(secondary, {"AccessToken": token}) is None
    assert decoded == []


def test_secondary_attribute_verification_code_is_a_write_and_fails_before_delivery(
    replicated_stack, monkeypatch
):
    provider, primary, secondary, pool, client = replicated_stack
    provider.admin_update_user_attributes(
        primary,
        {
            "UserAttributes": [{"Name": "email", "Value": "alice@example.test"}],
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    authenticated = provider.initiate_auth(
        secondary,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )
    deliveries = []

    def deliver(*args, **kwargs):
        deliveries.append((args, kwargs))
        return {"MessageId": "must-not-deliver"}

    monkeypatch.setattr(notification_delivery, "_save_cognito_default_email", deliver)
    with pytest.raises(CommonServiceException) as denied:
        provider.get_user_attribute_verification_code(
            secondary,
            {
                "AccessToken": authenticated["AuthenticationResult"]["AccessToken"],
                "AttributeName": "email",
            },
        )

    assert denied.value.code == "OperationNotEnabledException"
    assert deliveries == []


def test_secondary_describe_returns_the_regional_replica_arn(replicated_stack):
    provider, primary, secondary, pool, _ = replicated_stack

    described = provider.describe_user_pool(secondary, {"UserPoolId": pool["Id"]})

    assert described["UserPool"]["Arn"].split(":")[3] == secondary.region
    assert described["UserPool"]["Arn"].split(":")[3] != primary.region


def test_secondary_accepts_only_regional_configuration_writes(replicated_stack):
    provider, primary, secondary, pool, _ = replicated_stack

    assert (
        provider.update_user_pool(
            secondary,
            {
                "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"},
                "UserPoolId": pool["Id"],
            },
        )
        == {}
    )
    secondary_pool = provider.describe_user_pool(secondary, {"UserPoolId": pool["Id"]})["UserPool"]
    primary_pool = provider.describe_user_pool(primary, {"UserPoolId": pool["Id"]})["UserPool"]
    assert secondary_pool["EmailConfiguration"] == {"EmailSendingAccount": "COGNITO_DEFAULT"}
    assert "EmailConfiguration" not in primary_pool


def test_secondary_write_and_inactive_replica_fail_before_mutation(replicated_stack):
    provider, primary, secondary, pool, _ = replicated_stack

    with pytest.raises(CommonServiceException) as denied:
        provider.admin_create_user(
            secondary,
            {
                "MessageAction": "SUPPRESS",
                "TemporaryPassword": "TemporaryPass9!",
                "UserPoolId": pool["Id"],
                "Username": "mallory",
            },
        )
    assert denied.value.code == "OperationNotEnabledException"
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[primary.account_id][primary.region]
        assert "mallory" not in store.user_pools[pool["Id"]].users
        store.user_pool_replicas[pool["Id"]].secondary.status = "INACTIVE"

    with pytest.raises(CommonServiceException) as inactive:
        provider.describe_user_pool(secondary, {"UserPoolId": pool["Id"]})
    assert inactive.value.code == "OperationNotEnabledException"


def test_secondary_jwks_uses_primary_keys_and_fails_closed_when_inactive(replicated_stack):
    provider, primary, secondary, pool, _ = replicated_stack
    endpoint = CognitoIdpJwksEndpoint()
    suffix = "amazonaws.com.cn" if primary.partition == "aws-cn" else "amazonaws.com"
    request = Request(
        "GET",
        f"/{pool['Id']}/.well-known/jwks.json",
        headers={"Host": f"cognito-idp.{secondary.region}.{suffix}"},
    )

    response = endpoint.get_jwks(request, pool["Id"])
    assert response.status_code == 200
    assert response.json == provider.get_jwks(primary, pool["Id"])

    with cognito_idp_stores.lock:
        store = cognito_idp_stores[primary.account_id][primary.region]
        store.user_pool_replicas[pool["Id"]].secondary.status = "INACTIVE"
    assert endpoint.get_jwks(request, pool["Id"]).status_code == 404


def test_single_handler_boundary_enforces_resizable_persisted_rate_limit(
    replicated_stack, monkeypatch
):
    provider, primary, _, pool, _ = replicated_stack
    monkeypatch.setitem(rate_module.DEFAULT_API_CATEGORY_LIMITS, "UserRead", 1)

    assert (
        provider.admin_get_user(primary, {"UserPoolId": pool["Id"], "Username": "alice"})[
            "Username"
        ]
        == "alice"
    )
    with pytest.raises(CommonServiceException) as throttled:
        provider.admin_get_user(primary, {"UserPoolId": pool["Id"], "Username": "alice"})

    assert throttled.value.code == "TooManyRequestsException"
    assert throttled.value.retry_after_seconds == pytest.approx(1.0, abs=0.01)
    with cognito_idp_stores.lock:
        state = cognito_idp_stores[primary.account_id][primary.region].provisioned_rate_limits
        assert (primary.account_id, primary.region, "UserRead") in state.buckets
