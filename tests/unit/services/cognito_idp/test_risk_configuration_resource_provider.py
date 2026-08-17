import copy
import uuid
from unittest.mock import MagicMock

from localstack.aws.api import RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_userpoolriskconfigurationattachment import (
    CognitoUserPoolRiskConfigurationAttachmentProvider,
)
from tests.unit.services.cognito_idp.test_resource_providers import _NativeCognitoClient, _request


def _desired():
    return {
        "ClientId": "ALL",
        "CompromisedCredentialsRiskConfiguration": {
            "Actions": {"EventAction": "BLOCK"},
            "EventFilter": ["SIGN_IN"],
        },
        "RiskExceptionConfiguration": {
            "BlockedIPRangeList": ["198.51.100.0/24"],
            "SkippedIPRangeList": ["192.0.2.10/32"],
        },
        "UserPoolId": "us-east-1_pool",
    }


def test_risk_attachment_create_read_delete_maps_all_without_mutation():
    client = MagicMock()
    desired = _desired()
    original = copy.deepcopy(desired)
    api_configuration = {
        **{key: value for key, value in desired.items() if key != "ClientId"},
        "LastModifiedDate": 1,
    }
    client.set_risk_configuration.return_value = {"RiskConfiguration": api_configuration}
    client.describe_risk_configuration.return_value = {"RiskConfiguration": api_configuration}
    provider = CognitoUserPoolRiskConfigurationAttachmentProvider()

    created = provider.create(_request(client=client, desired_state=desired))
    read = provider.read(_request(client=client, desired_state=desired))
    deleted = provider.delete(_request(client=client, desired_state=desired))

    assert created.status == read.status == deleted.status == OperationStatus.SUCCESS
    assert desired == original
    assert created.resource_model == desired
    client.set_risk_configuration.assert_any_call(
        ClientId="ALL",
        CompromisedCredentialsRiskConfiguration=desired["CompromisedCredentialsRiskConfiguration"],
        RiskExceptionConfiguration=desired["RiskExceptionConfiguration"],
        UserPoolId=desired["UserPoolId"],
    )
    client.set_risk_configuration.assert_called_with(
        ClientId="ALL", UserPoolId=desired["UserPoolId"]
    )
    client.describe_risk_configuration.assert_called_once_with(
        ClientId="ALL", UserPoolId=desired["UserPoolId"]
    )


def test_risk_attachment_schema_only_promises_executable_subset():
    schema = CognitoUserPoolRiskConfigurationAttachmentProvider.SCHEMA

    assert set(schema["properties"]) == {
        "ClientId",
        "CompromisedCredentialsRiskConfiguration",
        "RiskExceptionConfiguration",
        "UserPoolId",
    }
    assert "AccountTakeoverRiskConfiguration" not in schema["properties"]
    assert schema["createOnlyProperties"] == [
        "/properties/UserPoolId",
        "/properties/ClientId",
    ]
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES[
        "AWS::Cognito::UserPoolRiskConfigurationAttachment"
    ] == ("UserPoolRiskConfigurationAttachment-</properties/UserPoolId>-</properties/ClientId>")
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            {"ClientId": "ALL", "UserPoolId": "us-east-1_pool"},
            CognitoUserPoolRiskConfigurationAttachmentProvider.TYPE,
            schema,
        )
        == "UserPoolRiskConfigurationAttachment-us-east-1_pool-ALL"
    )


def test_risk_attachment_round_trips_against_native_provider():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native = CognitoIdpProvider()
    client = _NativeCognitoClient(native, context)
    pool = native.create_user_pool(context, {"PoolName": "risk-cfn-users"})["UserPool"]
    desired = {**_desired(), "UserPoolId": pool["Id"]}
    provider = CognitoUserPoolRiskConfigurationAttachmentProvider()
    try:
        created = provider.create(_request(client=client, desired_state=desired))
        read = provider.read(_request(client=client, desired_state=created.resource_model))
        deleted = provider.delete(
            _request(
                client=client, desired_state=read.resource_model, previous_state=read.resource_model
            )
        )

        assert created.status == read.status == deleted.status == OperationStatus.SUCCESS
        assert read.resource_model == desired
        reset = native.describe_risk_configuration(context, {"UserPoolId": pool["Id"]})[
            "RiskConfiguration"
        ]
        assert "CompromisedCredentialsRiskConfiguration" not in reset
        assert "RiskExceptionConfiguration" not in reset
    finally:
        try:
            native.delete_user_pool(context, {"UserPoolId": pool["Id"]})
        finally:
            with cognito_idp_stores.lock:
                cognito_idp_stores.pop(context.account_id, None)
