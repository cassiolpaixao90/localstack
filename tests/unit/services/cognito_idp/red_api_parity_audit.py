"""Focused Cognito IDP parity REDs.

This module deliberately does not match pytest's default ``test_*.py`` pattern.
Run one block explicitly while implementing it, for example::

    python -m pytest -q tests/unit/services/cognito_idp/red_api_parity_audit.py \
      -k recovery

Keeping the audit REDs out of default collection prevents an unfinished parity
vertical from destabilizing the shared Cognito integration gate.
"""

import inspect
import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
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


def _pool_client(provider, context, **pool_configuration):
    pool = provider.create_user_pool(
        context,
        {"PoolName": f"parity-{uuid.uuid4().hex[:8]}", **pool_configuration},
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "parity-client",
            "ExplicitAuthFlows": [
                "ALLOW_REFRESH_TOKEN_AUTH",
                "ALLOW_USER_PASSWORD_AUTH",
            ],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    return pool, client


def _confirmed_user(provider, context, pool_id, *, attributes):
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TemporaryPass9!",
            "UserAttributes": attributes,
            "UserPoolId": pool_id,
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool_id,
            "Username": "alice",
        },
    )


def test_red_recovery_must_not_deliver_to_an_unverified_email(provider, context, monkeypatch):
    pool, client = _pool_client(
        provider,
        context,
        AccountRecoverySetting={"RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]},
    )
    _confirmed_user(
        provider,
        context,
        pool["Id"],
        attributes=[
            {"Name": "email", "Value": "unverified@example.test"},
            {"Name": "email_verified", "Value": "false"},
        ],
    )
    deliveries = []
    monkeypatch.setattr(
        provider,
        "_deliver_reserved_user_code",
        lambda *args, **kwargs: deliveries.append((args, kwargs)),
    )

    with pytest.raises(CommonServiceException) as unavailable:
        provider.forgot_password(
            context,
            {"ClientId": client["ClientId"], "Username": "alice"},
        )

    assert unavailable.value.code == "InvalidParameterException"
    assert deliveries == []


def test_red_admin_reset_must_not_deliver_to_an_unverified_email(provider, context, monkeypatch):
    pool, _ = _pool_client(
        provider,
        context,
        AccountRecoverySetting={"RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]},
    )
    _confirmed_user(
        provider,
        context,
        pool["Id"],
        attributes=[
            {"Name": "email", "Value": "unverified@example.test"},
            {"Name": "email_verified", "Value": "false"},
        ],
    )
    deliveries = []
    monkeypatch.setattr(
        provider,
        "_deliver_reserved_user_code",
        lambda *args, **kwargs: deliveries.append((args, kwargs)),
    )

    with pytest.raises(CommonServiceException) as unavailable:
        provider.admin_reset_user_password(
            context,
            {"UserPoolId": pool["Id"], "Username": "alice"},
        )

    assert unavailable.value.code == "InvalidParameterException"
    assert deliveries == []


@pytest.mark.parametrize(
    "setting",
    [
        {
            "RecoveryMechanisms": [
                {"Name": "verified_phone_number", "Priority": 1},
                {"Name": "verified_email", "Priority": 2},
            ]
        },
        {"RecoveryMechanisms": [{"Name": "admin_only", "Priority": 1}]},
    ],
)
def test_red_all_official_account_recovery_modes_round_trip(provider, context, setting):
    pool = provider.create_user_pool(
        context,
        {"AccountRecoverySetting": setting, "PoolName": "recovery-parity"},
    )["UserPool"]

    assert pool["AccountRecoverySetting"] == setting


def test_red_confirmation_link_template_round_trips(provider, context):
    value = {
        "DefaultEmailOption": "CONFIRM_WITH_LINK",
        "EmailMessageByLink": "Confirm with {##this link##}",
        "EmailSubjectByLink": "Confirm account",
    }
    pool = provider.create_user_pool(
        context,
        {"VerificationMessageTemplate": value, "PoolName": "nested-link-template"},
    )["UserPool"]

    assert pool["VerificationMessageTemplate"] == value


@pytest.mark.parametrize(
    "domain_configuration",
    [
        {
            "CustomDomainConfig": {
                "CertificateArn": (
                    "arn:aws:acm:us-east-1:000000000000:certificate/"
                    "00000000-0000-0000-0000-000000000000"
                )
            }
        },
        {
            "Routing": {
                "Failover": {
                    "PrimaryRoute53HealthCheckId": "health-check-id",
                    "SecondaryRegion": "us-west-2",
                }
            }
        },
    ],
)
def test_red_domain_modeled_fields_reach_resource_validation(
    provider, context, domain_configuration
):
    pool = provider.create_user_pool(context, {"PoolName": "domain-parity"})["UserPool"]

    try:
        provider.create_user_pool_domain(
            context,
            {
                "Domain": "domain-parity",
                "UserPoolId": pool["Id"],
                **domain_configuration,
            },
        )
    except CommonServiceException as error:
        assert "Unsupported request fields" not in error.message


def test_red_import_job_forwards_the_official_password_hashing_algorithm(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(context, {"PoolName": "import-parity"})["UserPool"]
    calls = []

    class Jobs:
        def create_job(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"JobId": "job-id", "Status": "Created"}

    monkeypatch.setattr(provider_module, "get_user_import_jobs", lambda *_: Jobs())
    provider.create_user_import_job(
        context,
        {
            "CloudWatchLogsRoleArn": (f"arn:aws:iam::{context.account_id}:role/import-role"),
            "JobName": "argon2id-import",
            "PasswordHashingAlgorithm": "ARGON2ID",
            "UserPoolId": pool["Id"],
        },
    )

    assert calls
    assert "ARGON2ID" in (*calls[0][0], *calls[0][1].values())


def test_red_list_users_applies_the_modeled_filter(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "filter-parity"})["UserPool"]
    for username in ("alice", "bob"):
        provider.admin_create_user(
            context,
            {
                "MessageAction": "SUPPRESS",
                "TemporaryPassword": "TemporaryPass9!",
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )

    result = provider.list_users(
        context,
        {"Filter": 'username ^= "ali"', "UserPoolId": pool["Id"]},
    )

    assert [user["Username"] for user in result["Users"]] == ["alice"]


def test_red_admin_attribute_update_accepts_client_metadata(provider, context):
    pool, _ = _pool_client(provider, context)
    _confirmed_user(provider, context, pool["Id"], attributes=[])

    provider.admin_update_user_attributes(
        context,
        {
            "ClientMetadata": {"tenant": "enterprise"},
            "UserAttributes": [{"Name": "name", "Value": "Alice"}],
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )

    user = provider.admin_get_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice"},
    )
    assert {item["Name"]: item["Value"] for item in user["UserAttributes"]}["name"] == "Alice"


def test_red_verify_software_token_consumes_friendly_device_name():
    source = inspect.getsource(CognitoIdpProvider.verify_software_token)

    assert source.count('"FriendlyDeviceName"') > 1


def test_red_client_credentials_is_a_functional_oauth_flow(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "m2m-parity"})["UserPool"]
    resource = provider.create_resource_server(
        context,
        {
            "Identifier": "https://api.example.test",
            "Name": "api",
            "Scopes": [{"ScopeDescription": "read", "ScopeName": "read"}],
            "UserPoolId": pool["Id"],
        },
    )["ResourceServer"]

    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["client_credentials"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": [f"{resource['Identifier']}/read"],
            "ClientName": "machine-client",
            "GenerateSecret": True,
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]

    assert client["AllowedOAuthFlows"] == ["client_credentials"]


def test_red_list_user_pools_reports_real_lambda_and_replica_configuration(provider, context):
    lambda_config = {
        "PostConfirmation": (
            f"arn:aws:lambda:{context.region}:{context.account_id}:function:post-confirm"
        )
    }
    pool = provider.create_user_pool(
        context,
        {"LambdaConfig": lambda_config, "PoolName": "summary-parity"},
    )["UserPool"]
    provider.create_user_pool_replica(
        context,
        {"RegionName": "us-west-2", "UserPoolId": pool["Id"]},
    )

    listed = provider.list_user_pools(context, {"MaxResults": 60})["UserPools"]
    summary = next(item for item in listed if item["Id"] == pool["Id"])

    assert summary["LambdaConfig"] == lambda_config
    assert summary["ReplicaRegions"] == ["us-west-2"]
