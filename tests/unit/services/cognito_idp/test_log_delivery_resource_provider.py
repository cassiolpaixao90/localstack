import configparser
import copy
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from localstack.aws.api import RequestContext
from localstack.capabilities.catalog import scan_cloudformation_resources
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp import log_delivery
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_logdeliveryconfiguration import (
    CognitoLogDeliveryConfigurationProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_logdeliveryconfiguration_plugin import (
    CognitoLogDeliveryConfigurationProviderPlugin,
)
from tests.unit.services.cognito_idp.test_log_delivery import FakeFirehose, FakeLogs, FakeS3
from tests.unit.services.cognito_idp.test_resource_providers import _NativeCognitoClient, _request

PROJECT_ROOT = Path(__file__).resolve().parents[4]


def _desired():
    return {
        "UserPoolId": "us-east-1_pool",
        "LogConfigurations": [
            {
                "EventSource": "userAuthEvents",
                "LogLevel": "INFO",
                "S3Configuration": {"BucketArn": "arn:aws:s3:::auth-events"},
            }
        ],
    }


def test_log_delivery_cfn_crud_maps_without_mutating_desired():
    client = MagicMock()
    desired = _desired()
    original = copy.deepcopy(desired)
    response = {"LogDeliveryConfiguration": copy.deepcopy(desired)}
    client.set_log_delivery_configuration.return_value = response
    client.get_log_delivery_configuration.return_value = response
    provider = CognitoLogDeliveryConfigurationProvider()

    created = provider.create(_request(client=client, desired_state=desired))
    read = provider.read(_request(client=client, desired_state=desired))
    updated = provider.update(
        _request(client=client, desired_state=desired, previous_state=desired)
    )
    deleted = provider.delete(
        _request(client=client, desired_state=desired, previous_state=desired)
    )

    assert (
        created.status == read.status == updated.status == deleted.status == OperationStatus.SUCCESS
    )
    assert desired == original
    assert created.resource_model == read.resource_model == updated.resource_model == desired
    client.get_log_delivery_configuration.assert_called_once_with(UserPoolId=desired["UserPoolId"])
    client.set_log_delivery_configuration.assert_called_with(
        UserPoolId=desired["UserPoolId"], LogConfigurations=[]
    )


def test_log_delivery_cfn_schema_ref_and_replacement_contract():
    schema = CognitoLogDeliveryConfigurationProvider.SCHEMA
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")

    assert schema["primaryIdentifier"] == ["/properties/UserPoolId"]
    assert schema["createOnlyProperties"] == ["/properties/UserPoolId"]
    assert schema["required"] == ["UserPoolId"]
    assert schema["properties"]["LogConfigurations"]["maxItems"] == 2
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            {"UserPoolId": "us-east-1_pool"},
            CognitoLogDeliveryConfigurationProvider.TYPE,
            schema,
        )
        == "us-east-1_pool"
    )
    plugin = CognitoLogDeliveryConfigurationProviderPlugin()
    plugin.load()
    assert plugin.factory is CognitoLogDeliveryConfigurationProvider

    manifest = configparser.ConfigParser(delimiters=("=",), interpolation=None)
    manifest.read(PROJECT_ROOT / "plux.ini")
    assert manifest["localstack.cloudformation.resource_providers"][
        "aws::cognito::logdeliveryconfiguration"
    ].endswith(":CognitoLogDeliveryConfigurationProviderPlugin")


def test_capability_scanner_discovers_native_log_delivery_resource_type():
    by_service, records = scan_cloudformation_resources(PROJECT_ROOT)

    assert "AWS::Cognito::LogDeliveryConfiguration" in by_service["cognito-idp"]
    assert "AWS::Cognito::LogDeliveryConfiguration" in {
        record["type"] for record in records if record["source_service"] == "cognito-idp"
    }


def test_log_delivery_cfn_roundtrip_against_native_provider(monkeypatch):
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    destinations = SimpleNamespace(
        logs=FakeLogs(),
        s3=FakeS3(account_id=context.account_id),
        firehose=FakeFirehose(context.account_id, context.region),
    )
    monkeypatch.setattr(log_delivery, "_client_factory", lambda _context: destinations)
    native = CognitoIdpProvider()
    client = _NativeCognitoClient(native, context)
    pool = native.create_user_pool(context, {"PoolName": "log-delivery-cfn"})["UserPool"]
    desired = {**_desired(), "UserPoolId": pool["Id"]}
    provider = CognitoLogDeliveryConfigurationProvider()
    try:
        created = provider.create(_request(client=client, desired_state=desired))
        read = provider.read(_request(client=client, desired_state=created.resource_model))
        deleted = provider.delete(
            _request(
                client=client,
                desired_state=read.resource_model,
                previous_state=read.resource_model,
            )
        )

        assert created.status == read.status == deleted.status == OperationStatus.SUCCESS
        assert read.resource_model == desired
        assert native.get_log_delivery_configuration(context, {"UserPoolId": pool["Id"]}) == {
            "LogDeliveryConfiguration": {
                "UserPoolId": pool["Id"],
                "LogConfigurations": [],
            }
        }
    finally:
        try:
            native.delete_user_pool(context, {"UserPoolId": pool["Id"]})
        finally:
            with cognito_idp_stores.lock:
                cognito_idp_stores.pop(context.account_id, None)
