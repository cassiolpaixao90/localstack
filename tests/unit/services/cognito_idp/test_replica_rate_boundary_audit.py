import inspect

import pytest

from localstack.aws.api import CommonServiceException
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.spec import load_service
from localstack.services.cognito_idp.endpoints import CognitoIdpOAuthEndpoint


def test_retry_after_survives_aws_json_exception_serialization():
    service = load_service("cognito-idp")
    error = CommonServiceException(
        "TooManyRequestsException",
        "Provisioned API rate exceeded",
        status_code=400,
        sender_fault=True,
    )
    error.retry_after_seconds = 0.25

    response = create_serializer(service).serialize_error_to_response(
        error,
        service.operation_model("AdminGetUser"),
        {},
        "request-id",
    )

    assert response.headers["Retry-After"] == "1"


@pytest.mark.parametrize("handler_name", ["idp_response", "saml_idp_response"])
def test_federation_callbacks_have_a_provisioned_rate_boundary(handler_name):
    handler = getattr(CognitoIdpOAuthEndpoint, handler_name)
    assert "_consume_provisioned_rate" in inspect.getsource(handler)
