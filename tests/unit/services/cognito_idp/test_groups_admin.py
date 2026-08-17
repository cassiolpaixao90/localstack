import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _stack(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "admin-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "admin-client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    for username in ("alice", "bob", "carol"):
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "TemporaryPass9!",
                "UserAttributes": [{"Name": "email", "Value": f"{username}@example.com"}],
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )
        provider.admin_set_user_password(
            context,
            {
                "Password": "PermanentPass9!",
                "Permanent": True,
                "UserPoolId": pool["Id"],
                "Username": username,
            },
        )
    return pool, client


def test_group_crud_and_hmac_bound_pagination(provider, context):
    pool, _ = _stack(provider, context)
    for name, precedence in (("admin", 1), ("member", 20), ("trainer", 10)):
        created = provider.create_group(
            context,
            {
                "Description": f"{name} users",
                "GroupName": name,
                "Precedence": precedence,
                "RoleArn": f"arn:aws:iam::{context.account_id}:role/{name}",
                "UserPoolId": pool["Id"],
            },
        )["Group"]
        assert created["GroupName"] == name

    first = provider.list_groups(context, {"Limit": 1, "UserPoolId": pool["Id"]})
    assert [group["GroupName"] for group in first["Groups"]] == ["admin"]
    second = provider.list_groups(
        context,
        {"Limit": 2, "NextToken": first["NextToken"], "UserPoolId": pool["Id"]},
    )
    assert [group["GroupName"] for group in second["Groups"]] == ["member", "trainer"]

    replacement = "A" if first["NextToken"][-1] != "A" else "B"
    tampered = f"{first['NextToken'][:-1]}{replacement}"
    with pytest.raises(CommonServiceException) as invalid:
        provider.list_groups(context, {"Limit": 1, "NextToken": tampered, "UserPoolId": pool["Id"]})
    assert invalid.value.code == "InvalidParameterException"
    with pytest.raises(CommonServiceException) as cross_operation:
        provider.list_users_in_group(
            context,
            {
                "GroupName": "admin",
                "Limit": 1,
                "NextToken": first["NextToken"],
                "UserPoolId": pool["Id"],
            },
        )
    assert cross_operation.value.code == "InvalidParameterException"
    other_pool = provider.create_user_pool(context, {"PoolName": "other-users"})["UserPool"]
    with pytest.raises(CommonServiceException) as cross_pool:
        provider.list_groups(
            context,
            {"Limit": 1, "NextToken": first["NextToken"], "UserPoolId": other_pool["Id"]},
        )
    assert cross_pool.value.code == "InvalidParameterException"

    updated = provider.update_group(
        context,
        {"Description": "administrators", "GroupName": "admin", "UserPoolId": pool["Id"]},
    )["Group"]
    assert updated["Description"] == "administrators"
    assert updated["Precedence"] == 1
    assert (
        provider.get_group(context, {"GroupName": "admin", "UserPoolId": pool["Id"]})["Group"]
        == updated
    )


def test_memberships_drive_signed_group_role_claims_and_cleanup(provider, context):
    pool, client = _stack(provider, context)
    roles = {
        "admin": f"arn:aws:iam::{context.account_id}:role/admin",
        "trainer": f"arn:aws:iam::{context.account_id}:role/trainer",
        "member": f"arn:aws:iam::{context.account_id}:role/member",
    }
    for name, precedence in (("admin", 1), ("trainer", 1), ("member", 20)):
        provider.create_group(
            context,
            {
                "GroupName": name,
                "Precedence": precedence,
                "RoleArn": roles[name],
                "UserPoolId": pool["Id"],
            },
        )
        provider.admin_add_user_to_group(
            context,
            {"GroupName": name, "Username": "alice", "UserPoolId": pool["Id"]},
        )

    groups = provider.admin_list_groups_for_user(
        context, {"Limit": 2, "Username": "alice", "UserPoolId": pool["Id"]}
    )
    assert len(groups["Groups"]) == 2
    assert groups["NextToken"]
    assert [
        user["Username"]
        for user in provider.list_users_in_group(
            context, {"GroupName": "admin", "UserPoolId": pool["Id"]}
        )["Users"]
    ] == ["alice"]

    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    for token_name in ("AccessToken", "IdToken"):
        claims = decode_jwt_segment(auth[token_name].split(".")[1])
        assert claims["cognito:groups"] == ["admin", "trainer", "member"]
        assert claims["cognito:roles"] == [roles["admin"], roles["trainer"], roles["member"]]
        assert "cognito:preferred_role" not in claims

    provider.admin_remove_user_from_group(
        context,
        {"GroupName": "trainer", "Username": "alice", "UserPoolId": pool["Id"]},
    )
    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )["AuthenticationResult"]
    claims = decode_jwt_segment(auth["IdToken"].split(".")[1])
    assert claims["cognito:preferred_role"] == roles["admin"]

    provider.delete_group(context, {"GroupName": "admin", "UserPoolId": pool["Id"]})
    assert provider.admin_list_groups_for_user(
        context, {"Username": "alice", "UserPoolId": pool["Id"]}
    )["Groups"] == [
        provider.get_group(context, {"GroupName": "member", "UserPoolId": pool["Id"]})["Group"]
    ]


def test_administrative_user_lifecycle_and_pagination(provider, context):
    pool, client = _stack(provider, context)
    first = provider.list_users(context, {"Limit": 2, "UserPoolId": pool["Id"]})
    assert [user["Username"] for user in first["Users"]] == ["alice", "bob"]
    assert (
        provider.list_users(
            context,
            {"Limit": 2, "PaginationToken": first["PaginationToken"], "UserPoolId": pool["Id"]},
        )["Users"][0]["Username"]
        == "carol"
    )

    provider.admin_update_user_attributes(
        context,
        {
            "UserAttributes": [
                {"Name": "email", "Value": "updated@example.com"},
                {"Name": "custom:tier", "Value": "enterprise"},
            ],
            "Username": "alice",
            "UserPoolId": pool["Id"],
        },
    )
    user = provider.admin_get_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    assert {item["Name"]: item["Value"] for item in user["UserAttributes"]}["email"] == (
        "updated@example.com"
    )
    provider.admin_delete_user_attributes(
        context,
        {"UserAttributeNames": ["custom:tier"], "Username": "alice", "UserPoolId": pool["Id"]},
    )
    provider.admin_disable_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    assert not provider.admin_get_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})[
        "Enabled"
    ]
    provider.admin_enable_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    provider.create_group(context, {"GroupName": "member", "UserPoolId": pool["Id"]})
    provider.admin_add_user_to_group(
        context,
        {"GroupName": "member", "Username": "alice", "UserPoolId": pool["Id"]},
    )
    provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "PermanentPass9!", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )
    with cognito_idp_stores.lock:
        store = provider.get_store(context)
        assert store.refresh_sessions
    provider.admin_reset_user_password(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    assert (
        provider.admin_get_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})[
            "UserStatus"
        ]
        == "RESET_REQUIRED"
    )
    with cognito_idp_stores.lock:
        assert not store.refresh_sessions
    with pytest.raises(CommonServiceException) as cannot_confirm_reset:
        provider.admin_confirm_sign_up(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    assert cannot_confirm_reset.value.code == "NotAuthorizedException"
    provider.admin_delete_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    with cognito_idp_stores.lock:
        assert not store.refresh_sessions
        assert "alice" not in store.user_pools[pool["Id"]].groups["member"].members
    with pytest.raises(CommonServiceException) as deleted:
        provider.admin_get_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})
    assert deleted.value.code == "UserNotFoundException"


def test_group_and_membership_quotas_fail_without_partial_mutation(provider, context, monkeypatch):
    pool, _ = _stack(provider, context)
    monkeypatch.setattr(provider_module, "_MAX_GROUPS_PER_POOL", 2)
    for name in ("first", "second"):
        provider.create_group(context, {"GroupName": name, "UserPoolId": pool["Id"]})
    with pytest.raises(CommonServiceException) as group_quota:
        provider.create_group(context, {"GroupName": "third", "UserPoolId": pool["Id"]})
    assert group_quota.value.code == "LimitExceededException"

    monkeypatch.setattr(provider_module, "_MAX_GROUP_MEMBERSHIPS_PER_USER", 1)
    provider.admin_add_user_to_group(
        context,
        {"GroupName": "first", "Username": "alice", "UserPoolId": pool["Id"]},
    )
    with pytest.raises(CommonServiceException) as membership_quota:
        provider.admin_add_user_to_group(
            context,
            {"GroupName": "second", "Username": "alice", "UserPoolId": pool["Id"]},
        )
    assert membership_quota.value.code == "LimitExceededException"
    assert (
        provider.list_users_in_group(context, {"GroupName": "second", "UserPoolId": pool["Id"]})[
            "Users"
        ]
        == []
    )
