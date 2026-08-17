import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def test_add_custom_attributes_round_trips_all_types_and_preserves_existing_users(
    provider, context
):
    pool = provider.create_user_pool(context, {"PoolName": "custom-attributes"})["UserPool"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "Temporary9!",
            "UserPoolId": pool["Id"],
            "Username": "existing",
        },
    )
    attributes = [
        {
            "AttributeDataType": "String",
            "Mutable": True,
            "Name": "department",
            "Required": False,
            "StringAttributeConstraints": {"MaxLength": "12", "MinLength": "2"},
        },
        {
            "AttributeDataType": "Number",
            "Mutable": True,
            "Name": "score",
            "NumberAttributeConstraints": {"MaxValue": "10.5", "MinValue": "-2"},
        },
        {"AttributeDataType": "Boolean", "Mutable": True, "Name": "enabled"},
        {"AttributeDataType": "DateTime", "Mutable": True, "Name": "joinedAt"},
        {
            "AttributeDataType": "String",
            "DeveloperOnlyAttribute": True,
            "Mutable": True,
            "Name": "internal",
        },
    ]

    assert (
        provider.add_custom_attributes(
            context, {"CustomAttributes": attributes, "UserPoolId": pool["Id"]}
        )
        == {}
    )

    described = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert described["SchemaAttributes"] == [
        {**attributes[0], "Name": "custom:department"},
        {**attributes[1], "Name": "custom:score"},
        {**attributes[2], "Name": "custom:enabled"},
        {**attributes[3], "Name": "custom:joinedAt"},
        {**attributes[4], "Name": "dev:internal"},
    ]
    existing = provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "existing"})
    assert all(
        item["Name"]
        not in {
            "custom:department",
            "custom:score",
            "custom:enabled",
            "custom:joinedAt",
            "dev:internal",
        }
        for item in existing["UserAttributes"]
    )


def test_add_custom_attributes_is_atomic_for_duplicates_quota_and_invalid_required(
    provider, context, monkeypatch
):
    pool = provider.create_user_pool(context, {"PoolName": "custom-atomic"})["UserPool"]
    provider.add_custom_attributes(
        context,
        {
            "CustomAttributes": [{"AttributeDataType": "String", "Name": "existing"}],
            "UserPoolId": pool["Id"],
        },
    )
    before = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"][
        "SchemaAttributes"
    ]

    for custom_attributes in (
        [
            {"AttributeDataType": "String", "Name": "new"},
            {"AttributeDataType": "String", "Name": "existing"},
        ],
        [{"AttributeDataType": "String", "Name": "required", "Required": True}],
        [{"AttributeDataType": "String", "Name": "email"}],
        [
            {"AttributeDataType": "String", "Name": "wouldBeValid"},
            {
                "AttributeDataType": "Number",
                "Name": "badConstraints",
                "StringAttributeConstraints": {"MinLength": "1"},
            },
        ],
        [{"AttributeDataType": "String", "Name": f"attribute{index}"} for index in range(26)],
    ):
        with pytest.raises(CommonServiceException) as invalid:
            provider.add_custom_attributes(
                context,
                {"CustomAttributes": custom_attributes, "UserPoolId": pool["Id"]},
            )
        assert invalid.value.code == "InvalidParameterException"
        assert (
            provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"][
                "SchemaAttributes"
            ]
            == before
        )

    monkeypatch.setattr(provider_module, "_MAX_CUSTOM_ATTRIBUTES_PER_POOL", 2)
    with pytest.raises(CommonServiceException) as quota:
        provider.add_custom_attributes(
            context,
            {
                "CustomAttributes": [
                    {"AttributeDataType": "String", "Name": "second"},
                    {"AttributeDataType": "String", "Name": "third"},
                ],
                "UserPoolId": pool["Id"],
            },
        )
    assert quota.value.code == "LimitExceededException"
    assert (
        provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"][
            "SchemaAttributes"
        ]
        == before
    )


def test_custom_attribute_constraints_mutability_and_developer_authorization(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "PoolName": "custom-values",
            "Schema": [
                {
                    "AttributeDataType": "String",
                    "Mutable": False,
                    "Name": "immutable",
                    "StringAttributeConstraints": {"MaxLength": "4", "MinLength": "2"},
                },
                {
                    "AttributeDataType": "Number",
                    "Mutable": True,
                    "Name": "score",
                    "NumberAttributeConstraints": {"MaxValue": "10", "MinValue": "1"},
                },
                {"AttributeDataType": "Boolean", "Mutable": True, "Name": "enabled"},
                {"AttributeDataType": "DateTime", "Mutable": True, "Name": "joinedAt"},
                {
                    "AttributeDataType": "String",
                    "DeveloperOnlyAttribute": True,
                    "Mutable": True,
                    "Name": "internal",
                },
            ],
        },
    )["UserPool"]
    provider.admin_create_user(
        context,
        {
            "TemporaryPassword": "Temporary9!",
            "UserAttributes": [
                {"Name": "custom:immutable", "Value": "okay"},
                {"Name": "custom:score", "Value": "2.5"},
                {"Name": "custom:enabled", "Value": "true"},
                {"Name": "custom:joinedAt", "Value": "2025-01-02T03:04:05Z"},
                {"Name": "dev:internal", "Value": "admin-only"},
            ],
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )

    invalid_values = {
        "custom:score": "11",
        "custom:enabled": "yes",
        "custom:joinedAt": "not-a-date",
    }
    for name, value in invalid_values.items():
        with pytest.raises(CommonServiceException) as invalid:
            provider.admin_update_user_attributes(
                context,
                {
                    "UserAttributes": [{"Name": name, "Value": value}],
                    "UserPoolId": pool["Id"],
                    "Username": "alice",
                },
            )
        assert invalid.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as immutable:
        provider.admin_update_user_attributes(
            context,
            {
                "UserAttributes": [{"Name": "custom:immutable", "Value": "new"}],
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )
    assert immutable.value.code == "InvalidParameterException"

    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "custom-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "WriteAttributes": ["dev:internal"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_set_user_password(
        context,
        {
            "Password": "Permanent9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    access_token = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "Permanent9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]["AccessToken"]
    with pytest.raises(CommonServiceException) as developer_only:
        provider.update_user_attributes(
            context,
            {
                "AccessToken": access_token,
                "UserAttributes": [{"Name": "dev:internal", "Value": "client-write"}],
            },
        )
    assert developer_only.value.code == "NotAuthorizedException"
