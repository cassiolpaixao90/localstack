import logging

from localstack.aws.accounts import (
    get_account_id_from_access_key_id,
)
from localstack.aws.api import CommonServiceException
from localstack.aws.protocol.serializer import create_serializer
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localstack.http import Response
from localstack.services.sts.credentials import (
    NATIVE_SESSION_ACCESS_KEY_PREFIX,
    SessionAuthResult,
    authenticate_session,
)
from localstack.utils.aws.request_context import (
    extract_access_key_id_from_auth_header,
    mock_aws_request_headers,
)

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class MissingAuthHeaderInjector(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # FIXME: this is needed for allowing access to resources via plain URLs where access is typically restricted (
        #  e.g., GET requests on S3 URLs or apigateway routes). this should probably be part of a general IAM middleware
        #  (that allows access to restricted resources by default)
        if not context.service:
            return

        api = context.service.service_name
        headers = context.request.headers

        if not headers.get("Authorization"):
            headers["Authorization"] = mock_aws_request_headers(
                api, aws_access_key_id="injectedaccesskey", region_name=AWS_REGION_US_EAST_1
            )["Authorization"]


class AccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Obtain the access key ID
        access_key_id = (
            extract_access_key_id_from_auth_header(context.request.headers)
            or DEFAULT_AWS_ACCOUNT_ID
        )

        # Obtain the account ID from access key ID
        context.account_id = get_account_id_from_access_key_id(access_key_id)

        # Make Moto use the same Account ID as LocalStack
        context.request.headers.add("x-moto-account-id", context.account_id)


class NativeSessionAuthEnforcer(Handler):
    """
    Fails closed on requests carrying natively issued STS session credentials
    (reserved access-key prefix) that are revoked, expired, unknown, or whose
    session token does not match. All other access keys keep the default
    permissive behavior.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        if access_key_id is None:
            credential = context.request.args.get("X-Amz-Credential", "")
            access_key_id = credential.split("/", 1)[0] if credential else None
        if not access_key_id or not access_key_id.startswith(NATIVE_SESSION_ACCESS_KEY_PREFIX):
            return

        session_token = context.request.headers.get("X-Amz-Security-Token") or (
            context.request.args.get("X-Amz-Security-Token")
        )

        result = authenticate_session(
            access_key_id,
            session_token,
            account_id=context.account_id,
            region=context.region,
        )
        if result is SessionAuthResult.OK:
            return
        if result is SessionAuthResult.EXPIRED:
            self._reject(
                chain,
                context,
                response,
                "ExpiredToken",
                "The security token included in the request is expired",
            )
            return
        self._reject(
            chain,
            context,
            response,
            "InvalidClientTokenId",
            "The security token included in the request is invalid",
        )

    @staticmethod
    def _reject(
        chain: HandlerChain, context: RequestContext, response: Response, code: str, message: str
    ) -> None:
        # the operation is not parsed yet at this point of the chain, so the service
        # exception serializer cannot be used; serialize with any operation of the
        # service model instead (error shape depends on the protocol, not the operation)
        error = CommonServiceException(code, message, 400, sender_fault=True)
        serializer = create_serializer(context.service)
        operation = context.service.operation_model(context.service.operation_names[0])
        error_response = serializer.serialize_error_to_response(
            error, operation, context.request.headers, context.request_id
        )
        response.update_from(error_response)
        chain.stop()
