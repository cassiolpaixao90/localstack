import copy
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.resource_providers.aws_cognito_managedloginbranding import (
    CognitoManagedLoginBrandingProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_managedloginbranding_plugin import (
    CognitoManagedLoginBrandingProviderPlugin,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_terms import (
    CognitoTermsProvider,
)
from localstack.services.cognito_idp.resource_providers.aws_cognito_terms_plugin import (
    CognitoTermsProviderPlugin,
)


def _request(*, client, desired_state, previous_state=None):
    return SimpleNamespace(
        aws_client_factory=SimpleNamespace(cognito_idp=client),
        custom_context={},
        desired_state=desired_state,
        previous_state=previous_state,
        logical_resource_id="ManagedLoginResource",
        stack_name="enterprise",
        region_name="us-east-1",
    )


def _not_found(operation):
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
        operation,
    )


class _NativeClient:
    def __init__(self, provider, context):
        self.provider = provider
        self.context = context

    def __getattr__(self, name):
        handler = getattr(self.provider, name)

        def invoke(**request):
            try:
                return handler(self.context, request)
            except CommonServiceException as error:
                raise ClientError(
                    {"Error": {"Code": error.code, "Message": error.message}}, name
                ) from error

        return invoke


def test_managed_login_resource_schemas_plugins_and_ref_contracts():
    branding_schema = CognitoManagedLoginBrandingProvider.SCHEMA
    terms_schema = CognitoTermsProvider.SCHEMA
    branding_plugin = CognitoManagedLoginBrandingProviderPlugin()
    terms_plugin = CognitoTermsProviderPlugin()
    branding_plugin.load()
    terms_plugin.load()

    assert branding_schema["additionalProperties"] is False
    assert branding_schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/ManagedLoginBrandingId",
    ]
    assert set(branding_schema["createOnlyProperties"]) == {
        "/properties/ClientId",
        "/properties/UserPoolId",
    }
    assert terms_schema["additionalProperties"] is False
    assert terms_schema["properties"]["Links"]["maxProperties"] == 13
    assert terms_schema["primaryIdentifier"] == [
        "/properties/UserPoolId",
        "/properties/TermsId",
    ]
    assert branding_plugin.factory is CognitoManagedLoginBrandingProvider
    assert terms_plugin.factory is CognitoTermsProvider
    assert (
        PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::ManagedLoginBranding"]
        == "/properties/ManagedLoginBrandingId"
    )
    assert PHYSICAL_RESOURCE_ID_SPECIAL_CASES["AWS::Cognito::Terms"] == ("/properties/TermsId")
    executor = ResourceProviderExecutor(stack_name="stack", stack_id="stack-id")
    branding_model = {
        "ManagedLoginBrandingId": "branding-id",
        "UserPoolId": "us-east-1_pool",
    }
    terms_model = {"TermsId": "terms-id", "UserPoolId": "us-east-1_pool"}
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            branding_model,
            CognitoManagedLoginBrandingProvider.TYPE,
            branding_schema,
        )
        == "branding-id"
    )
    assert (
        executor.extract_physical_resource_id_from_model_with_schema(
            terms_model,
            CognitoTermsProvider.TYPE,
            terms_schema,
        )
        == "terms-id"
    )


def test_managed_login_and_terms_cloudformation_round_trip_native():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    native = CognitoIdpProvider()
    client = _NativeClient(native, context)
    pool = native.create_user_pool(context, {"PoolName": "cfn-managed-login"})["UserPool"]
    app_client = native.create_user_pool_client(
        context,
        {"ClientName": "cfn-client", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    branding_desired = {
        "ClientId": app_client["ClientId"],
        "Settings": {"componentClasses": {"pageBackground": {"lightMode": {"color": "123456ff"}}}},
        "UserPoolId": pool["Id"],
    }
    terms_desired = {
        "ClientId": app_client["ClientId"],
        "Enforcement": "NONE",
        "Links": {"cognito:default": "https://example.test/terms"},
        "TermsName": "terms-of-use",
        "TermsSource": "LINK",
        "UserPoolId": pool["Id"],
    }
    original_branding = copy.deepcopy(branding_desired)
    original_terms = copy.deepcopy(terms_desired)
    branding_provider = CognitoManagedLoginBrandingProvider()
    terms_provider = CognitoTermsProvider()

    try:
        branding = branding_provider.create(_request(client=client, desired_state=branding_desired))
        terms = terms_provider.create(_request(client=client, desired_state=terms_desired))
        assert branding.status == terms.status == OperationStatus.SUCCESS
        assert branding_desired == original_branding
        assert terms_desired == original_terms
        assert branding.resource_model["ManagedLoginBrandingId"]
        assert terms.resource_model["TermsId"]

        updated_branding_state = {
            **branding.resource_model,
            "Settings": {
                "componentClasses": {"pageBackground": {"lightMode": {"color": "abcdefFF"}}}
            },
        }
        updated_branding = branding_provider.update(
            _request(
                client=client,
                desired_state=updated_branding_state,
                previous_state=branding.resource_model,
            )
        )
        updated_terms_state = {
            **terms.resource_model,
            "Links": {"cognito:default": "https://example.test/new-terms"},
        }
        updated_terms = terms_provider.update(
            _request(
                client=client,
                desired_state=updated_terms_state,
                previous_state=terms.resource_model,
            )
        )
        assert updated_branding.resource_model["Settings"] == updated_branding_state["Settings"]
        assert updated_terms.resource_model["Links"] == updated_terms_state["Links"]
        assert (
            branding_provider.read(
                _request(client=client, desired_state=updated_branding.resource_model)
            ).status
            == OperationStatus.SUCCESS
        )
        assert (
            terms_provider.read(
                _request(client=client, desired_state=updated_terms.resource_model)
            ).status
            == OperationStatus.SUCCESS
        )
        assert (
            len(
                branding_provider.list(
                    _request(client=client, desired_state={"UserPoolId": pool["Id"]})
                ).resource_models
            )
            == 1
        )
        assert (
            len(
                terms_provider.list(
                    _request(client=client, desired_state={"UserPoolId": pool["Id"]})
                ).resource_models
            )
            == 1
        )
        reset_branding = branding_provider.update(
            _request(
                client=client,
                desired_state={
                    "ClientId": app_client["ClientId"],
                    "ManagedLoginBrandingId": updated_branding.resource_model[
                        "ManagedLoginBrandingId"
                    ],
                    "UseCognitoProvidedValues": True,
                    "UserPoolId": pool["Id"],
                },
                previous_state=updated_branding.resource_model,
            )
        )
        assert reset_branding.resource_model["UseCognitoProvidedValues"] is True
        assert "Settings" not in reset_branding.resource_model
        assert "Assets" not in reset_branding.resource_model
        assert (
            branding_provider.delete(
                _request(client=client, desired_state=reset_branding.resource_model)
            ).status
            == OperationStatus.SUCCESS
        )
        assert (
            terms_provider.delete(
                _request(client=client, desired_state=updated_terms.resource_model)
            ).status
            == OperationStatus.SUCCESS
        )
    finally:
        with cognito_idp_stores.lock:
            store = native.get_store(context)
            for pool_id in list(store.user_pools):
                store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


def test_cfn_create_reconciles_only_matching_apply_then_raise_and_rejects_existing():
    branding_desired = {
        "ClientId": "client",
        "Settings": {"componentClasses": {"pageBackground": {"lightMode": {"color": "123456ff"}}}},
        "UserPoolId": "us-east-1_pool",
    }
    branding_description = {
        **branding_desired,
        "ManagedLoginBrandingId": str(uuid.uuid4()),
        "UseCognitoProvidedValues": False,
    }
    branding_client = SimpleNamespace()
    branding_client.describe_managed_login_branding_by_client = MagicMock(
        side_effect=[_not_found("Describe"), {"ManagedLoginBranding": branding_description}]
    )
    branding_client.create_managed_login_branding = MagicMock(
        side_effect=ReadTimeoutError(endpoint_url="https://cognito.test")
    )
    result = CognitoManagedLoginBrandingProvider().create(
        _request(client=branding_client, desired_state=branding_desired)
    )
    assert result.status == OperationStatus.SUCCESS

    external_client = SimpleNamespace(
        describe_managed_login_branding_by_client=MagicMock(
            return_value={"ManagedLoginBranding": branding_description}
        ),
        create_managed_login_branding=MagicMock(),
    )
    existing = CognitoManagedLoginBrandingProvider().create(
        _request(client=external_client, desired_state=branding_desired)
    )
    assert existing.status == OperationStatus.FAILED
    assert existing.error_code == "AlreadyExists"
    external_client.create_managed_login_branding.assert_not_called()

    terms_desired = {
        "ClientId": "client",
        "Enforcement": "NONE",
        "Links": {"cognito:default": "https://example.test/terms"},
        "TermsName": "terms-of-use",
        "TermsSource": "LINK",
        "UserPoolId": "us-east-1_pool",
    }
    terms_description = {**terms_desired, "TermsId": str(uuid.uuid4())}
    terms_client = SimpleNamespace(
        create_terms=MagicMock(side_effect=ReadTimeoutError(endpoint_url="https://cognito.test")),
        describe_terms=MagicMock(return_value={"Terms": terms_description}),
        list_terms=MagicMock(
            side_effect=[
                {"Terms": []},
                {
                    "Terms": [
                        {
                            "TermsId": terms_description["TermsId"],
                            "TermsName": "terms-of-use",
                        }
                    ]
                },
            ]
        ),
    )
    terms_result = CognitoTermsProvider().create(
        _request(client=terms_client, desired_state=terms_desired)
    )
    assert terms_result.status == OperationStatus.SUCCESS

    invalid_client = SimpleNamespace(
        describe_managed_login_branding_by_client=MagicMock(side_effect=_not_found("Describe")),
        create_managed_login_branding=MagicMock(side_effect=ValueError("invalid request")),
    )
    with pytest.raises(ValueError, match="invalid request"):
        CognitoManagedLoginBrandingProvider().create(
            _request(client=invalid_client, desired_state=branding_desired)
        )
