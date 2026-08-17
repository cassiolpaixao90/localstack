import configparser
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.capabilities.catalog import scan_cloudformation_resources
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluser import (
    CognitoUserPoolUserProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpooluser_plugin import (
    CognitoUserPoolUserProviderPlugin,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolusertogroupattachment import (
    CognitoUserPoolUserToGroupAttachmentProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolusertogroupattachment_plugin import (
    CognitoUserPoolUserToGroupAttachmentProviderPlugin,
)

PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _request(*, client, desired_state, previous_state=None, logical_resource_id="User"):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id=logical_resource_id,
        stack_name="enterprise",
        region_name="us-east-1",
    )


class _NativeCognitoClient:
    def __init__(self, provider: CognitoIdpProvider, context: RequestContext):
        self.provider = provider
        self.context = context

    def __getattr__(self, name: str):
        handler = getattr(self.provider, name)

        def invoke(**request):
            try:
                return handler(self.context, request)
            except CommonServiceException as error:
                raise ClientError(
                    {"Error": {"Code": error.code, "Message": error.message}},
                    name,
                ) from error

        return invoke


@pytest.fixture
def native_cognito():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    context.partition = "aws"
    provider = CognitoIdpProvider()
    client = _NativeCognitoClient(provider, context)
    pool = provider.create_user_pool(context, {"PoolName": "cfn-users"})["UserPool"]
    yield provider, client, context, pool
    try:
        provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    finally:
        with cognito_idp_stores.lock:
            cognito_idp_stores.pop(context.account_id, None)


def test_user_and_attachment_schema_plugin_and_ref_contracts_are_closed():
    user_schema = CognitoUserPoolUserProvider.SCHEMA
    attachment_schema = CognitoUserPoolUserToGroupAttachmentProvider.SCHEMA
    user_plugin = CognitoUserPoolUserProviderPlugin()
    attachment_plugin = CognitoUserPoolUserToGroupAttachmentProviderPlugin()

    user_plugin.load()
    attachment_plugin.load()

    assert user_schema["additionalProperties"] is False
    assert user_schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/Username",
    ]
    assert set(user_schema["createOnlyProperties"]) == {
        f"/properties/{name}" for name in user_schema["properties"]
    }
    assert set(user_schema["writeOnlyProperties"]) == {
        "/properties/ClientMetadata",
        "/properties/DesiredDeliveryMediums",
        "/properties/ForceAliasCreation",
        "/properties/MessageAction",
        "/properties/ValidationData",
    }
    assert attachment_schema["additionalProperties"] is False
    assert attachment_schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/Username",
        "/properties/GroupName",
    ]
    assert attachment_schema["readOnlyProperties"] == ["/properties/Id"]
    assert set(attachment_schema["createOnlyProperties"]) == {
        "/properties/GroupName",
        "/properties/UserPoolId",
        "/properties/Username",
    }
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolUser"] == (
        "/properties/Username"
    )
    assert (
        PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::UserPoolUserToGroupAttachment"]
        == "/properties/Id"
    )
    assert user_plugin.factory is CognitoUserPoolUserProvider
    assert attachment_plugin.factory is CognitoUserPoolUserToGroupAttachmentProvider

    manifest = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    manifest.read(PROJECT_ROOT / "plux.ini")
    plugins = manifest["localstack.cloudformation.resource_providers"]
    assert plugins["aws::cognito::userpooluser"].endswith(":CognitoUserPoolUserProviderPlugin")
    assert plugins["aws::cognito::userpoolusertogroupattachment"].endswith(
        ":CognitoUserPoolUserToGroupAttachmentProviderPlugin"
    )

    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            {"Username": "admin", "UserPoolId": "us-east-1_pool"},
            CognitoUserPoolUserProvider.TYPE,
            CognitoUserPoolUserProvider.SCHEMA,
        )
        == "admin"
    )


def test_capability_scanner_discovers_both_native_user_resource_types():
    by_service, records = scan_cloudformation_resources(PROJECT_ROOT)
    expected = {
        "AWS::Cognito::UserPoolUser",
        "AWS::Cognito::UserPoolUserToGroupAttachment",
    }

    assert expected <= set(by_service["cognito-idp"])
    assert expected <= {
        record["type"] for record in records if record["source_service"] == "cognito-idp"
    }


def test_user_native_roundtrip_list_replacement_and_idempotent_delete(native_cognito):
    _, client, _, pool = native_cognito
    provider = CognitoUserPoolUserProvider()
    desired = {
        "UserAttributes": [
            {"Name": "email", "Value": "admin@example.test"},
            {"Name": "name", "Value": "Admin"},
        ],
        "Username": "admin@example.test",
        "UserPoolId": pool["Id"],
    }

    created = provider.create(_request(client=client, desired_state=desired))
    assert created.status == OperationStatus.SUCCESS
    assert created.resource_model == {
        "UserAttributes": desired["UserAttributes"],
        "Username": desired["Username"],
        "UserPoolId": pool["Id"],
    }
    retried = provider.create(_request(client=client, desired_state=desired))
    assert retried.status == OperationStatus.FAILED
    assert retried.error_code == "AlreadyExists"

    read = provider.read(_request(client=client, desired_state=created.resource_model))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model == created.resource_model

    listed = provider.list(_request(client=client, desired_state={"UserPoolId": pool["Id"]}))
    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [created.resource_model]

    unchanged = provider.update(
        _request(
            client=client,
            desired_state=created.resource_model,
            previous_state=created.resource_model,
        )
    )
    assert unchanged.status == OperationStatus.SUCCESS
    assert unchanged.resource_model == created.resource_model

    replacement = provider.update(
        _request(
            client=client,
            desired_state=created.resource_model | {"Username": "replacement"},
            previous_state=created.resource_model,
        )
    )
    assert replacement.status == OperationStatus.FAILED
    assert "replacement" in replacement.message.lower()

    deleted = provider.delete(
        _request(client=client, desired_state={}, previous_state=created.resource_model)
    )
    repeated = provider.delete(
        _request(client=client, desired_state={}, previous_state=created.resource_model)
    )
    assert deleted.status == OperationStatus.SUCCESS
    assert repeated.status == OperationStatus.SUCCESS

    generated = provider.create(
        _request(
            client=client,
            desired_state={"UserPoolId": pool["Id"]},
            logical_resource_id="GeneratedUser",
        )
    )
    generated_retry = provider.create(
        _request(
            client=client,
            desired_state={"UserPoolId": pool["Id"]},
            logical_resource_id="GeneratedUser",
        )
    )
    assert generated.status == OperationStatus.SUCCESS
    assert generated_retry.status == OperationStatus.FAILED
    assert generated_retry.error_code == "AlreadyExists"
    provider.delete(_request(client=client, desired_state=generated.resource_model))


def test_attachment_native_roundtrip_pagination_ref_and_cleanup(native_cognito):
    native_provider, client, context, pool = native_cognito
    user_provider = CognitoUserPoolUserProvider()
    attachment_provider = CognitoUserPoolUserToGroupAttachmentProvider()
    user_state = user_provider.create(
        _request(
            client=client,
            desired_state={"Username": "member", "UserPoolId": pool["Id"]},
        )
    ).resource_model
    native_provider.create_group(context, {"GroupName": "operators", "UserPoolId": pool["Id"]})
    desired = {
        "GroupName": "operators",
        "Username": "member",
        "UserPoolId": pool["Id"],
    }

    created = attachment_provider.create(
        _request(client=client, desired_state=desired, logical_resource_id="Membership")
    )
    retried = attachment_provider.create(
        _request(client=client, desired_state=desired, logical_resource_id="Membership")
    )
    assert created.status == OperationStatus.SUCCESS
    assert retried.resource_model == created.resource_model
    assert created.resource_model["Id"].startswith("UserToGroupAttachment-")
    assert {key: created.resource_model[key] for key in desired} == desired

    read = attachment_provider.read(_request(client=client, desired_state=created.resource_model))
    assert read.status == OperationStatus.SUCCESS
    assert read.resource_model == created.resource_model

    listed = attachment_provider.list(
        _request(client=client, desired_state={"UserPoolId": pool["Id"]})
    )
    assert listed.status == OperationStatus.SUCCESS
    assert listed.resource_models == [created.resource_model]

    unchanged = attachment_provider.update(
        _request(
            client=client,
            desired_state=created.resource_model,
            previous_state=created.resource_model,
        )
    )
    assert unchanged.status == OperationStatus.SUCCESS
    assert unchanged.resource_model == created.resource_model

    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            created.resource_model,
            attachment_provider.TYPE,
            attachment_provider.SCHEMA,
        )
        == created.resource_model["Id"]
    )

    replacement = attachment_provider.update(
        _request(
            client=client,
            desired_state=created.resource_model | {"GroupName": "different"},
            previous_state=created.resource_model,
        )
    )
    assert replacement.status == OperationStatus.FAILED
    assert "replacement" in replacement.message.lower()

    deleted = attachment_provider.delete(
        _request(client=client, desired_state={}, previous_state=created.resource_model)
    )
    repeated = attachment_provider.delete(
        _request(client=client, desired_state={}, previous_state=created.resource_model)
    )
    assert deleted.status == OperationStatus.SUCCESS
    assert repeated.status == OperationStatus.SUCCESS

    missing = attachment_provider.read(
        _request(client=client, desired_state=created.resource_model)
    )
    assert missing.status == OperationStatus.FAILED
    assert missing.error_code == "NotFound"

    user_provider.delete(_request(client=client, desired_state=user_state))


def test_attachment_rollback_without_created_physical_id_is_a_noop():
    client = MagicMock()
    provider = CognitoUserPoolUserToGroupAttachmentProvider()
    partial = {"GroupName": "trainer", "UserPoolId": "us-east-1_pool"}

    rolled_back = provider.delete(_request(client=client, desired_state=partial))
    assert rolled_back.status == OperationStatus.SUCCESS
    assert rolled_back.resource_model == partial
    client.admin_remove_user_from_group.assert_not_called()

    invalid_owned_state = provider.delete(
        _request(client=client, desired_state={**partial, "Id": "owned-physical-id"})
    )
    assert invalid_owned_state.status == OperationStatus.FAILED
    client.admin_remove_user_from_group.assert_not_called()


def test_user_create_only_delivery_and_trigger_features_fail_closed(native_cognito):
    _, client, _, pool = native_cognito
    provider = CognitoUserPoolUserProvider()

    unsupported_models = (
        {"ClientMetadata": {"tenant": "one"}},
        {"DesiredDeliveryMediums": ["EMAIL"]},
        {"ForceAliasCreation": True},
        {"MessageAction": "RESEND"},
        {"ValidationData": [{"Name": "tenant", "Value": "one"}]},
    )
    for extra in unsupported_models:
        result = provider.create(
            _request(
                client=client,
                desired_state={
                    "Username": f"user-{len(extra)}-{next(iter(extra))}",
                    "UserPoolId": pool["Id"],
                    **extra,
                },
            )
        )
        assert result.status == OperationStatus.FAILED
        assert result.error_code == "InvalidRequest"


def test_user_forwards_suppress_without_adopting_matching_existing_user():
    client = MagicMock()
    client.admin_create_user.return_value = {"User": {"Attributes": [], "Username": "admin"}}
    desired = {
        "MessageAction": "SUPPRESS",
        "Username": "admin",
        "UserPoolId": "us-east-1_pool",
    }
    provider = CognitoUserPoolUserProvider()

    created = provider.create(_request(client=client, desired_state=desired))

    assert created.status == OperationStatus.SUCCESS
    client.admin_create_user.assert_called_once()
    assert client.admin_create_user.call_args.kwargs["MessageAction"] == "SUPPRESS"

    client.admin_create_user.side_effect = ClientError(
        {"Error": {"Code": "UsernameExistsException", "Message": "exists"}},
        "AdminCreateUser",
    )
    duplicate = provider.create(_request(client=client, desired_state=desired))
    assert duplicate.status == OperationStatus.FAILED
    assert duplicate.error_code == "AlreadyExists"
    client.admin_get_user.assert_not_called()
    client.admin_delete_user.assert_not_called()


def test_user_and_attachment_lists_follow_pages_and_reject_token_cycles():
    client = MagicMock()
    client.list_users.side_effect = [
        {
            "Users": [{"Attributes": [], "Username": "z-user"}],
            "PaginationToken": "next-user",
        },
        {"Users": [{"Attributes": [], "Username": "a-user"}]},
    ]
    user_provider = CognitoUserPoolUserProvider()

    users = user_provider.list(
        _request(client=client, desired_state={"UserPoolId": "us-east-1_pool"})
    )

    assert users.status == OperationStatus.SUCCESS
    assert [model["Username"] for model in users.resource_models] == ["a-user", "z-user"]

    client.admin_list_groups_for_user.side_effect = [
        {"Groups": [{"GroupName": "z-group"}], "NextToken": "next-group"},
        {"Groups": [{"GroupName": "a-group"}]},
    ]
    attachment_provider = CognitoUserPoolUserToGroupAttachmentProvider()
    attachments = attachment_provider.list(
        _request(
            client=client,
            desired_state={"UserPoolId": "us-east-1_pool", "Username": "member"},
        )
    )

    assert attachments.status == OperationStatus.SUCCESS
    assert [model["GroupName"] for model in attachments.resource_models] == [
        "a-group",
        "z-group",
    ]

    client.list_users.side_effect = [
        {"Users": [], "PaginationToken": "loop"},
        {"Users": [], "PaginationToken": "loop"},
    ]
    cycle = user_provider.list(
        _request(client=client, desired_state={"UserPoolId": "us-east-1_pool"})
    )
    assert cycle.status == OperationStatus.FAILED
    assert "continuation token" in cycle.message
