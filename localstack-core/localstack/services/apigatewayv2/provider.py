import base64
import copy
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from botocore.utils import InvalidArnException
from moto.acm import models as acm_models

from localstack import config
from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.services.apigateway.cognito_jwt import partition_dns_suffix
from localstack.services.apigateway.helpers import get_regional_domain_name
from localstack.services.apigatewayv2.jwt_authorizer import (
    HttpApiJwtAuthorizerConfiguration,
    HttpApiJwtConfigurationError,
)
from localstack.services.apigatewayv2.models import (
    ApiGatewayV2Api,
    ApiGatewayV2ApiMapping,
    ApiGatewayV2Authorizer,
    ApiGatewayV2Deployment,
    ApiGatewayV2DeploymentSnapshot,
    ApiGatewayV2DomainName,
    ApiGatewayV2Integration,
    ApiGatewayV2Route,
    ApiGatewayV2Stage,
    ApiGatewayV2Store,
    apigatewayv2_stores,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import StateVisitor
from localstack.utils.aws.arns import get_partition, parse_arn
from localstack.utils.strings import short_uid

_MAX_APIS_PER_REGION = 600
_MAX_AUTHORIZERS_PER_API = 10
_MAX_INTEGRATIONS_PER_API = 300
_MAX_ROUTES_PER_API = 300
_MAX_STAGES_PER_API = 10
_MAX_DOMAIN_NAMES_PER_REGION = 120
_MAX_API_MAPPINGS_PER_DOMAIN = 200
_MAX_AUDIENCES_PER_AUTHORIZER = 50
_DEFAULT_PAGE_SIZE = 25
_MAX_PAGE_SIZE = 500
_MAX_PAGE_TOKEN_BYTES = 2048
_MAX_ID_ATTEMPTS = 64
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HTTP_ROUTE_SELECTION_EXPRESSION = "$request.method $request.path"
_HTTP_API_KEY_SELECTION_EXPRESSION = "$request.header.x-api-key"
_AUTHORIZATION_IDENTITY_SOURCE = "$request.header.Authorization"

_CREATE_API_FIELDS = {
    "ApiKeySelectionExpression",
    "CorsConfiguration",
    "CredentialsArn",
    "Description",
    "DisableSchemaValidation",
    "DisableExecuteApiEndpoint",
    "IpAddressType",
    "Name",
    "ProtocolType",
    "RouteKey",
    "RouteSelectionExpression",
    "Tags",
    "Target",
    "Version",
}
_UPDATE_API_FIELDS = {
    "ApiId",
    "ApiKeySelectionExpression",
    "CorsConfiguration",
    "CredentialsArn",
    "Description",
    "DisableSchemaValidation",
    "DisableExecuteApiEndpoint",
    "IpAddressType",
    "Name",
    "RouteKey",
    "RouteSelectionExpression",
    "Target",
    "Version",
}
_CREATE_AUTHORIZER_FIELDS = {
    "ApiId",
    "AuthorizerCredentialsArn",
    "AuthorizerPayloadFormatVersion",
    "AuthorizerResultTtlInSeconds",
    "AuthorizerType",
    "AuthorizerUri",
    "EnableSimpleResponses",
    "IdentitySource",
    "IdentityValidationExpression",
    "JwtConfiguration",
    "Name",
}
_UPDATE_AUTHORIZER_FIELDS = _CREATE_AUTHORIZER_FIELDS | {"AuthorizerId"}
_REQUEST_AUTHORIZER_ONLY_FIELDS = {
    "AuthorizerCredentialsArn",
    "AuthorizerPayloadFormatVersion",
    "AuthorizerResultTtlInSeconds",
    "AuthorizerUri",
    "EnableSimpleResponses",
    "IdentityValidationExpression",
}
_CREATE_INTEGRATION_FIELDS = {
    "ApiId",
    "ConnectionType",
    "Description",
    "IntegrationMethod",
    "IntegrationType",
    "IntegrationUri",
    "PayloadFormatVersion",
    "TimeoutInMillis",
}
_UPDATE_INTEGRATION_FIELDS = _CREATE_INTEGRATION_FIELDS | {"IntegrationId"}
_CREATE_ROUTE_FIELDS = {
    "ApiId",
    "ApiKeyRequired",
    "AuthorizationScopes",
    "AuthorizationType",
    "AuthorizerId",
    "OperationName",
    "RouteKey",
    "Target",
}
_UPDATE_ROUTE_FIELDS = _CREATE_ROUTE_FIELDS | {"RouteId"}
_CREATE_STAGE_FIELDS = {
    "AccessLogSettings",
    "ApiId",
    "AutoDeploy",
    "DefaultRouteSettings",
    "DeploymentId",
    "Description",
    "StageName",
    "StageVariables",
    "Tags",
}
_UPDATE_STAGE_FIELDS = _CREATE_STAGE_FIELDS - {"Tags"}
_ROUTE_KEY_RE = re.compile(
    r"^(?P<method>ANY|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT) "
    r"(?P<path>/[A-Za-z0-9._~!$&'()*+,;=:@%/{}+-]*)$"
)
_TARGET_RE = re.compile(r"^integrations/(?P<id>[a-z0-9]{8,16})$")
_STAGE_NAME_RE = re.compile(r"^(?:\$default|[A-Za-z0-9_-]{1,128})$")
_DOMAIN_NAME_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_API_MAPPING_KEY_RE = re.compile(r"^[A-Za-z0-9$_.+!*'()/-]{0,300}$")

_CREATE_DOMAIN_NAME_FIELDS = {
    "DomainName",
    "DomainNameConfigurations",
    "MutualTlsAuthentication",
    "RoutingMode",
    "Tags",
}
_UPDATE_DOMAIN_NAME_FIELDS = _CREATE_DOMAIN_NAME_FIELDS - {"Tags"}
_CREATE_API_MAPPING_FIELDS = {"ApiId", "ApiMappingKey", "DomainName", "Stage"}
_UPDATE_API_MAPPING_FIELDS = _CREATE_API_MAPPING_FIELDS | {"ApiMappingId"}


class ApiGatewayV2Provider(ServiceLifecycleHook):
    service = "apigatewayv2"
    version = "2018-11-29"

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        certificate_resolver: Callable[[RequestContext, str], dict[str, Any] | None] | None = None,
    ):
        self._clock = clock or _utcnow
        self._certificate_resolver = certificate_resolver or _local_acm_certificate

    def on_after_init(self) -> None:
        from localstack.services.apigateway.next_gen.execute_api.router import (
            get_api_gateway_router,
        )

        router = get_api_gateway_router()
        router.register_routes()
        router.sync_custom_domains()

    def accept_state_visitor(self, visitor: StateVisitor) -> None:
        visitor.visit(apigatewayv2_stores)

    @handler("CreateApi", expand=False)
    def create_api(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        properties = _create_api_properties(context, request, self._clock())
        with apigatewayv2_stores.lock:
            store = _store(context)
            if len(store.apis) >= _MAX_APIS_PER_REGION:
                _error(
                    "LimitExceededException",
                    "The Regional API quota has been reached",
                    429,
                )
            api_id = _new_id(store.apis)
            arn = f"arn:{_partition(context)}:apigateway:{context.region}::/apis/{api_id}"
            properties["ApiId"] = api_id
            properties["ApiEndpoint"] = config.external_service_url(
                subdomains=f"{api_id}.execute-api"
            )
            api = ApiGatewayV2Api(
                api_id=api_id,
                arn=arn,
                created_at=properties["CreatedDate"],
                properties=properties,
            )
            store.apis[api_id] = api
            return api.to_response()

    @handler("GetApi", expand=False)
    def get_api(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId"})
        with apigatewayv2_stores.lock:
            return _api(_store(context), request.get("ApiId")).to_response()

    @handler("GetApis", expand=False)
    def get_apis(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"MaxResults", "NextToken"})
        limit = _page_size(request.get("MaxResults"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            after = _decode_page_token(store, request.get("NextToken"), "apis")
            items = sorted(store.apis.values(), key=lambda item: item.api_id)
            page, next_after = _page_after(items, limit, after, lambda item: item.api_id)
            response: dict[str, Any] = {"Items": [item.to_response() for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_page_token(store, "apis", next_after)
            return response

    @handler("UpdateApi", expand=False)
    def update_api(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_API_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            prospective = _updated_api_properties(context, api.properties, request)
            api.properties = prospective
            return api.to_response()

    @handler("DeleteApi", expand=False)
    def delete_api(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId"})
        with apigatewayv2_stores.lock:
            store = _store(context)
            api = _api(store, request.get("ApiId"))
            if any(
                mapping.properties.get("ApiId") == api.api_id
                for domain in store.domain_names.values()
                for mapping in domain.api_mappings.values()
            ):
                _error("ConflictException", "The API is referenced by an API mapping", 409)
            api.authorizers.clear()
            api.integrations.clear()
            api.routes.clear()
            api.deployments.clear()
            api.stages.clear()
            del store.apis[api.api_id]

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _CREATE_AUTHORIZER_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            properties = _authorizer_properties(context, request)
            if any(
                item.properties["Name"] == properties["Name"] for item in api.authorizers.values()
            ):
                _error("ConflictException", "An authorizer with this name already exists", 409)
            if len(api.authorizers) >= _MAX_AUTHORIZERS_PER_API:
                _error(
                    "LimitExceededException",
                    "The authorizer quota for this API has been reached",
                    429,
                )
            authorizer_id = _new_id(api.authorizers)
            properties["AuthorizerId"] = authorizer_id
            arn = f"{api.arn}/authorizers/{authorizer_id}"
            authorizer = ApiGatewayV2Authorizer(
                authorizer_id=authorizer_id,
                arn=arn,
                properties=properties,
            )
            api.authorizers[authorizer_id] = authorizer
            _refresh_auto_deploy_stages(api, self._clock())
            return authorizer.to_response()

    @handler("GetAuthorizer", expand=False)
    def get_authorizer(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "AuthorizerId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            return _authorizer(api, request.get("AuthorizerId")).to_response()

    @handler("GetAuthorizers", expand=False)
    def get_authorizers(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "MaxResults", "NextToken"})
        limit = _page_size(request.get("MaxResults"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            api = _api(store, request.get("ApiId"))
            scope = f"authorizers:{api.api_id}"
            after = _decode_page_token(store, request.get("NextToken"), scope)
            items = sorted(api.authorizers.values(), key=lambda item: item.authorizer_id)
            page, next_after = _page_after(items, limit, after, lambda item: item.authorizer_id)
            response: dict[str, Any] = {"Items": [item.to_response() for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_page_token(store, scope, next_after)
            return response

    @handler("UpdateAuthorizer", expand=False)
    def update_authorizer(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_AUTHORIZER_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            authorizer = _authorizer(api, request.get("AuthorizerId"))
            merged = {
                **authorizer.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key not in {"ApiId", "AuthorizerId"}
                },
                "ApiId": api.api_id,
            }
            properties = _authorizer_properties(context, merged)
            if any(
                item.authorizer_id != authorizer.authorizer_id
                and item.properties["Name"] == properties["Name"]
                for item in api.authorizers.values()
            ):
                _error("ConflictException", "An authorizer with this name already exists", 409)
            properties["AuthorizerId"] = authorizer.authorizer_id
            authorizer.properties = properties
            _refresh_auto_deploy_stages(api, self._clock())
            return authorizer.to_response()

    @handler("DeleteAuthorizer", expand=False)
    def delete_authorizer(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId", "AuthorizerId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            authorizer = _authorizer(api, request.get("AuthorizerId"))
            if any(
                route.properties.get("AuthorizerId") == authorizer.authorizer_id
                for route in api.routes.values()
            ):
                _error("ConflictException", "The authorizer is referenced by a route", 409)
            del api.authorizers[authorizer.authorizer_id]
            _refresh_auto_deploy_stages(api, self._clock())

    @handler("CreateIntegration", expand=False)
    def create_integration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _CREATE_INTEGRATION_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            if len(api.integrations) >= _MAX_INTEGRATIONS_PER_API:
                _error("LimitExceededException", "The integration quota has been reached", 429)
            properties = _integration_properties(context, request)
            integration_id = _new_id(api.integrations)
            properties["IntegrationId"] = integration_id
            integration = ApiGatewayV2Integration(integration_id, properties)
            api.integrations[integration_id] = integration
            _refresh_auto_deploy_stages(api, self._clock())
            return integration.to_response()

    @handler("GetIntegration", expand=False)
    def get_integration(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "IntegrationId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            return _integration(api, request.get("IntegrationId")).to_response()

    @handler("GetIntegrations", expand=False)
    def get_integrations(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        return self._list_api_resources(context, request, "integrations")

    @handler("UpdateIntegration", expand=False)
    def update_integration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_INTEGRATION_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            integration = _integration(api, request.get("IntegrationId"))
            merged = {
                **integration.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key not in {"ApiId", "IntegrationId"}
                },
            }
            properties = _integration_properties(context, merged)
            properties["IntegrationId"] = integration.integration_id
            integration.properties = properties
            _refresh_auto_deploy_stages(api, self._clock())
            return integration.to_response()

    @handler("DeleteIntegration", expand=False)
    def delete_integration(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId", "IntegrationId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            integration = _integration(api, request.get("IntegrationId"))
            target = f"integrations/{integration.integration_id}"
            if any(route.properties.get("Target") == target for route in api.routes.values()):
                _error("ConflictException", "The integration is referenced by a route", 409)
            del api.integrations[integration.integration_id]
            _refresh_auto_deploy_stages(api, self._clock())

    @handler("CreateRoute", expand=False)
    def create_route(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, _CREATE_ROUTE_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            if len(api.routes) >= _MAX_ROUTES_PER_API:
                _error("LimitExceededException", "The route quota has been reached", 429)
            properties = _route_properties(api, request)
            if any(
                route.properties["RouteKey"] == properties["RouteKey"]
                for route in api.routes.values()
            ):
                _error("ConflictException", "A route with this key already exists", 409)
            route_id = _new_id(api.routes)
            properties["RouteId"] = route_id
            route = ApiGatewayV2Route(route_id, properties)
            api.routes[route_id] = route
            _refresh_auto_deploy_stages(api, self._clock())
            return route.to_response()

    @handler("GetRoute", expand=False)
    def get_route(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "RouteId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            return _route(api, request.get("RouteId")).to_response()

    @handler("GetRoutes", expand=False)
    def get_routes(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        return self._list_api_resources(context, request, "routes")

    @handler("UpdateRoute", expand=False)
    def update_route(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_ROUTE_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            route = _route(api, request.get("RouteId"))
            merged = {
                **route.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key not in {"ApiId", "RouteId"}
                },
            }
            properties = _route_properties(api, merged)
            if any(
                item.route_id != route.route_id
                and item.properties["RouteKey"] == properties["RouteKey"]
                for item in api.routes.values()
            ):
                _error("ConflictException", "A route with this key already exists", 409)
            properties["RouteId"] = route.route_id
            route.properties = properties
            _refresh_auto_deploy_stages(api, self._clock())
            return route.to_response()

    @handler("DeleteRoute", expand=False)
    def delete_route(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId", "RouteId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            route = _route(api, request.get("RouteId"))
            del api.routes[route.route_id]
            _refresh_auto_deploy_stages(api, self._clock())

    @handler("CreateDeployment", expand=False)
    def create_deployment(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "Description", "StageName"})
        if request.get("StageName") is not None:
            _error("BadRequestException", "CreateDeployment StageName is not supported", 400)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            if not api.routes:
                _error("BadRequestException", "The API has no routes to deploy", 400)
            deployment = _new_deployment(
                api,
                self._clock(),
                auto_deployed=False,
                description=request.get("Description"),
            )
            return deployment.to_response()

    @handler("GetDeployment", expand=False)
    def get_deployment(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "DeploymentId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            return _deployment(api, request.get("DeploymentId")).to_response()

    @handler("GetDeployments", expand=False)
    def get_deployments(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        return self._list_api_resources(context, request, "deployments")

    @handler("DeleteDeployment", expand=False)
    def delete_deployment(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId", "DeploymentId"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            deployment = _deployment(api, request.get("DeploymentId"))
            if any(
                stage.properties.get("DeploymentId") == deployment.deployment_id
                for stage in api.stages.values()
            ):
                _error("ConflictException", "The deployment is referenced by a stage", 409)
            del api.deployments[deployment.deployment_id]

    @handler("CreateStage", expand=False)
    def create_stage(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, _CREATE_STAGE_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            if len(api.stages) >= _MAX_STAGES_PER_API:
                _error("LimitExceededException", "The stage quota has been reached", 429)
            properties = _stage_properties(api, request, self._clock())
            stage_name = properties["StageName"]
            if stage_name in api.stages:
                _error("ConflictException", "A stage with this name already exists", 409)
            stage = ApiGatewayV2Stage(stage_name, properties)
            api.stages[stage_name] = stage
            return stage.to_response()

    @handler("GetStage", expand=False)
    def get_stage(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "StageName"})
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            return _stage(api, request.get("StageName")).to_response()

    @handler("GetStages", expand=False)
    def get_stages(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        return self._list_api_resources(context, request, "stages")

    @handler("UpdateStage", expand=False)
    def update_stage(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_STAGE_FIELDS)
        with apigatewayv2_stores.lock:
            api = _api(_store(context), request.get("ApiId"))
            stage = _stage(api, request.get("StageName"))
            merged = {
                **stage.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key not in {"ApiId", "StageName"}
                },
                "StageName": stage.stage_name,
            }
            properties = _stage_properties(api, merged, stage.properties["CreatedDate"])
            properties["LastUpdatedDate"] = self._clock()
            stage.properties = properties
            return stage.to_response()

    @handler("DeleteStage", expand=False)
    def delete_stage(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiId", "StageName"})
        with apigatewayv2_stores.lock:
            store = _store(context)
            api = _api(store, request.get("ApiId"))
            stage = _stage(api, request.get("StageName"))
            if any(
                mapping.properties.get("ApiId") == api.api_id
                and mapping.properties.get("Stage") == stage.stage_name
                for domain in store.domain_names.values()
                for mapping in domain.api_mappings.values()
            ):
                _error("ConflictException", "The stage is referenced by an API mapping", 409)
            del api.stages[stage.stage_name]

    @handler("CreateDomainName", expand=False)
    def create_domain_name(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _CREATE_DOMAIN_NAME_FIELDS)
        domain_name = _domain_name(request.get("DomainName"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            if domain_name in store.domain_names:
                _error("ConflictException", "The domain name already exists", 409)
            if len(store.domain_names) >= _MAX_DOMAIN_NAMES_PER_REGION:
                _error("LimitExceededException", "The domain name quota has been reached", 429)
            properties = _domain_name_properties(
                context, request, domain_name, self._certificate_resolver
            )
            arn = (
                f"arn:{_partition(context)}:apigateway:{context.region}::/domainnames/{domain_name}"
            )
            properties["DomainNameArn"] = arn
            domain = ApiGatewayV2DomainName(domain_name, arn, properties)
            store.domain_names[domain_name] = domain
            try:
                _execute_api_router().register_custom_domain(domain_name)
            except Exception:
                del store.domain_names[domain_name]
                raise
            return domain.to_response()

    @handler("GetDomainName", expand=False)
    def get_domain_name(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"DomainName"})
        with apigatewayv2_stores.lock:
            return _domain(_store(context), request.get("DomainName")).to_response()

    @handler("GetDomainNames", expand=False)
    def get_domain_names(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"MaxResults", "NextToken"})
        limit = _page_size(request.get("MaxResults"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            after = _decode_page_token(store, request.get("NextToken"), "domain-names")
            items = sorted(store.domain_names.values(), key=lambda item: item.domain_name)
            page, next_after = _page_after(items, limit, after, lambda item: item.domain_name)
            response: dict[str, Any] = {"Items": [item.to_response() for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_page_token(store, "domain-names", next_after)
            return response

    @handler("UpdateDomainName", expand=False)
    def update_domain_name(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_DOMAIN_NAME_FIELDS)
        with apigatewayv2_stores.lock:
            domain = _domain(_store(context), request.get("DomainName"))
            merged = {
                **domain.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key != "DomainName"
                },
                "DomainName": domain.domain_name,
                "Tags": domain.properties.get("Tags", {}),
            }
            if "DomainNameConfigurations" not in request:
                configuration = domain.properties["DomainNameConfigurations"][0]
                merged["DomainNameConfigurations"] = [
                    {
                        key: copy.deepcopy(configuration[key])
                        for key in (
                            "CertificateArn",
                            "EndpointType",
                            "IpAddressType",
                            "SecurityPolicy",
                            "OwnershipVerificationCertificateArn",
                        )
                        if key in configuration
                    }
                ]
            properties = _domain_name_properties(
                context, merged, domain.domain_name, self._certificate_resolver
            )
            properties["DomainNameArn"] = domain.arn
            domain.properties = properties
            return domain.to_response()

    @handler("DeleteDomainName", expand=False)
    def delete_domain_name(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"DomainName"})
        with apigatewayv2_stores.lock:
            store = _store(context)
            domain = _domain(store, request.get("DomainName"))
            del store.domain_names[domain.domain_name]
            try:
                _execute_api_router().sync_custom_domains()
            except Exception:
                store.domain_names[domain.domain_name] = domain
                try:
                    _execute_api_router().sync_custom_domains()
                except Exception as rollback_error:
                    rollback_error_text = str(rollback_error)[:512]
                    if rollback_error_text:
                        raise RuntimeError(
                            "Custom-domain route cleanup failed and rollback was incomplete: "
                            f"{rollback_error_text}"
                        ) from rollback_error
                    raise RuntimeError(
                        "Custom-domain route cleanup failed and rollback was incomplete"
                    ) from rollback_error
                raise

    @handler("CreateApiMapping", expand=False)
    def create_api_mapping(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _CREATE_API_MAPPING_FIELDS)
        with apigatewayv2_stores.lock:
            store = _store(context)
            domain = _domain(store, request.get("DomainName"))
            if len(domain.api_mappings) >= _MAX_API_MAPPINGS_PER_DOMAIN:
                _error("LimitExceededException", "The API mapping quota has been reached", 429)
            properties = _api_mapping_properties(store, request)
            if any(
                item.properties.get("ApiMappingKey") == properties["ApiMappingKey"]
                for item in domain.api_mappings.values()
            ):
                _error("ConflictException", "The API mapping key already exists", 409)
            mapping_id = _new_id(domain.api_mappings)
            properties["ApiMappingId"] = mapping_id
            mapping = ApiGatewayV2ApiMapping(mapping_id, properties)
            domain.api_mappings[mapping_id] = mapping
            return mapping.to_response()

    @handler("GetApiMapping", expand=False)
    def get_api_mapping(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ApiMappingId", "DomainName"})
        with apigatewayv2_stores.lock:
            domain = _domain(_store(context), request.get("DomainName"))
            return _api_mapping(domain, request.get("ApiMappingId")).to_response()

    @handler("GetApiMappings", expand=False)
    def get_api_mappings(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"DomainName", "MaxResults", "NextToken"})
        limit = _page_size(request.get("MaxResults"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            domain = _domain(store, request.get("DomainName"))
            scope = f"api-mappings:{domain.domain_name}"
            after = _decode_page_token(store, request.get("NextToken"), scope)
            items = sorted(domain.api_mappings.values(), key=lambda item: item.api_mapping_id)
            page, next_after = _page_after(items, limit, after, lambda item: item.api_mapping_id)
            response: dict[str, Any] = {"Items": [item.to_response() for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_page_token(store, scope, next_after)
            return response

    @handler("UpdateApiMapping", expand=False)
    def update_api_mapping(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        _reject_unknown(request, _UPDATE_API_MAPPING_FIELDS)
        with apigatewayv2_stores.lock:
            store = _store(context)
            domain = _domain(store, request.get("DomainName"))
            mapping = _api_mapping(domain, request.get("ApiMappingId"))
            merged = {
                **mapping.properties,
                **{
                    key: copy.deepcopy(value)
                    for key, value in request.items()
                    if key not in {"ApiMappingId", "DomainName"}
                },
            }
            properties = _api_mapping_properties(store, merged)
            if any(
                item.api_mapping_id != mapping.api_mapping_id
                and item.properties.get("ApiMappingKey") == properties["ApiMappingKey"]
                for item in domain.api_mappings.values()
            ):
                _error("ConflictException", "The API mapping key already exists", 409)
            properties["ApiMappingId"] = mapping.api_mapping_id
            mapping.properties = properties
            return mapping.to_response()

    @handler("DeleteApiMapping", expand=False)
    def delete_api_mapping(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ApiMappingId", "DomainName"})
        with apigatewayv2_stores.lock:
            domain = _domain(_store(context), request.get("DomainName"))
            mapping = _api_mapping(domain, request.get("ApiMappingId"))
            del domain.api_mappings[mapping.api_mapping_id]

    @handler("GetTags", expand=False)
    def get_tags(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        _reject_unknown(request, {"ResourceArn"})
        with apigatewayv2_stores.lock:
            properties = _taggable_properties(_store(context), request.get("ResourceArn"))
            return {"Tags": copy.deepcopy(properties.get("Tags", {}))}

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ResourceArn", "Tags"})
        tags = _tags(request.get("Tags"))
        if not tags:
            _error("BadRequestException", "Tags must not be empty", 400)
        with apigatewayv2_stores.lock:
            properties = _taggable_properties(_store(context), request.get("ResourceArn"))
            properties["Tags"] = _tags({**properties.get("Tags", {}), **tags})

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: ServiceRequest) -> None:
        _reject_unknown(request, {"ResourceArn", "TagKeys"})
        tag_keys = _string_list(request.get("TagKeys"), "TagKeys", maximum=50, item_maximum=128)
        if not tag_keys:
            _error("BadRequestException", "TagKeys must not be empty", 400)
        with apigatewayv2_stores.lock:
            properties = _taggable_properties(_store(context), request.get("ResourceArn"))
            properties["Tags"] = {
                key: value
                for key, value in properties.get("Tags", {}).items()
                if key not in tag_keys
            }

    def _list_api_resources(
        self, context: RequestContext, request: ServiceRequest, collection: str
    ) -> ServiceResponse:
        _reject_unknown(request, {"ApiId", "MaxResults", "NextToken"})
        limit = _page_size(request.get("MaxResults"))
        with apigatewayv2_stores.lock:
            store = _store(context)
            api = _api(store, request.get("ApiId"))
            resources = getattr(api, collection)
            scope = f"{collection}:{api.api_id}"
            after = _decode_page_token(store, request.get("NextToken"), scope)
            items = sorted(resources.items())
            page, next_after = _page_after(items, limit, after, lambda item: item[0])
            response: dict[str, Any] = {"Items": [item[1].to_response() for item in page]}
            if next_after is not None:
                response["NextToken"] = _encode_page_token(store, scope, next_after)
            return response


def _store(context: RequestContext) -> ApiGatewayV2Store:
    return apigatewayv2_stores[context.account_id][context.region]


def _api(store: ApiGatewayV2Store, value: Any) -> ApiGatewayV2Api:
    api = store.apis.get(value) if isinstance(value, str) else None
    if api is None:
        _error("NotFoundException", "The specified API was not found", 404)
    return api


def _authorizer(api: ApiGatewayV2Api, value: Any) -> ApiGatewayV2Authorizer:
    authorizer = api.authorizers.get(value) if isinstance(value, str) else None
    if authorizer is None:
        _error("NotFoundException", "The specified authorizer was not found", 404)
    return authorizer


def _integration(api: ApiGatewayV2Api, value: Any) -> ApiGatewayV2Integration:
    integration = api.integrations.get(value) if isinstance(value, str) else None
    if integration is None:
        _error("NotFoundException", "The specified integration was not found", 404)
    return integration


def _route(api: ApiGatewayV2Api, value: Any) -> ApiGatewayV2Route:
    route = api.routes.get(value) if isinstance(value, str) else None
    if route is None:
        _error("NotFoundException", "The specified route was not found", 404)
    return route


def _deployment(api: ApiGatewayV2Api, value: Any) -> ApiGatewayV2Deployment:
    deployment = api.deployments.get(value) if isinstance(value, str) else None
    if deployment is None:
        _error("NotFoundException", "The specified deployment was not found", 404)
    return deployment


def _stage(api: ApiGatewayV2Api, value: Any) -> ApiGatewayV2Stage:
    stage = api.stages.get(value) if isinstance(value, str) else None
    if stage is None:
        _error("NotFoundException", "The specified stage was not found", 404)
    return stage


def _domain(store: ApiGatewayV2Store, value: Any) -> ApiGatewayV2DomainName:
    domain_name = value.lower() if isinstance(value, str) else None
    domain = store.domain_names.get(domain_name) if domain_name is not None else None
    if domain is None:
        _error("NotFoundException", "The specified domain name was not found", 404)
    return domain


def _api_mapping(domain: ApiGatewayV2DomainName, value: Any) -> ApiGatewayV2ApiMapping:
    mapping = domain.api_mappings.get(value) if isinstance(value, str) else None
    if mapping is None:
        _error("NotFoundException", "The specified API mapping was not found", 404)
    return mapping


def _taggable_properties(store: ApiGatewayV2Store, resource_arn: Any) -> dict[str, Any]:
    if not isinstance(resource_arn, str):
        _error("BadRequestException", "ResourceArn is required", 400)
    for api in store.apis.values():
        if resource_arn == api.arn:
            return api.properties
        stage_prefix = f"{api.arn}/stages/"
        if resource_arn.startswith(stage_prefix):
            stage_name = resource_arn.removeprefix(stage_prefix)
            if "/" not in stage_name and stage_name in api.stages:
                return api.stages[stage_name].properties
    for domain in store.domain_names.values():
        if resource_arn == domain.arn:
            return domain.properties
    _error("NotFoundException", "The specified resource was not found", 404)


def _domain_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.lower()
        or _DOMAIN_NAME_RE.fullmatch(value) is None
    ):
        _error("BadRequestException", "Invalid DomainName", 400)
    return value


def _domain_name_properties(
    context: RequestContext,
    request: ServiceRequest,
    domain_name: str,
    certificate_resolver: Callable[[RequestContext, str], dict[str, Any] | None],
) -> dict[str, Any]:
    if request.get("MutualTlsAuthentication") is not None:
        _error("BadRequestException", "Mutual TLS is not supported in this domain subset", 400)
    if request.get("RoutingMode", "API_MAPPING_ONLY") != "API_MAPPING_ONLY":
        _error("BadRequestException", "Only API_MAPPING_ONLY routing is supported", 400)
    configurations = request.get("DomainNameConfigurations")
    if not isinstance(configurations, list) or len(configurations) != 1:
        _error("BadRequestException", "Exactly one regional domain configuration is required", 400)
    configuration = configurations[0]
    allowed = {
        "CertificateArn",
        "EndpointType",
        "IpAddressType",
        "SecurityPolicy",
        "OwnershipVerificationCertificateArn",
    }
    if not isinstance(configuration, dict) or not set(configuration) <= allowed:
        _error("BadRequestException", "Invalid DomainNameConfiguration", 400)
    if configuration.get("OwnershipVerificationCertificateArn") is not None:
        _error("BadRequestException", "Ownership verification certificates are not supported", 400)
    if configuration.get("EndpointType", "REGIONAL") != "REGIONAL":
        _error("BadRequestException", "Only REGIONAL custom domains are supported", 400)
    if configuration.get("SecurityPolicy", "TLS_1_2") != "TLS_1_2":
        _error("BadRequestException", "Only TLS_1_2 custom domains are supported", 400)
    ip_address_type = configuration.get("IpAddressType", "ipv4")
    if ip_address_type not in {"ipv4", "dualstack"}:
        _error("BadRequestException", "Invalid IpAddressType", 400)
    certificate_arn = _required_string(configuration.get("CertificateArn"), "CertificateArn", 2048)
    try:
        parsed = parse_arn(certificate_arn)
    except (InvalidArnException, ValueError):
        _error("BadRequestException", "Invalid CertificateArn", 400)
    if (
        parsed.get("partition") != _partition(context)
        or parsed.get("service") != "acm"
        or parsed.get("region") != context.region
        or parsed.get("account") != context.account_id
        or re.fullmatch(r"certificate/[A-Za-z0-9-]{1,128}", parsed.get("resource", "")) is None
    ):
        _error(
            "BadRequestException",
            "CertificateArn must reference ACM in the API account and region",
            400,
        )
    certificate = certificate_resolver(context, certificate_arn)
    if not isinstance(certificate, dict) or certificate.get("Status") != "ISSUED":
        _error("BadRequestException", "The ACM certificate does not exist or is not issued", 400)
    certificate_names = {
        item.lower()
        for item in [
            certificate.get("DomainName"),
            *(certificate.get("SubjectAlternativeNames") or []),
        ]
        if isinstance(item, str)
    }
    if not any(_certificate_name_covers(item, domain_name) for item in certificate_names):
        _error("BadRequestException", "The ACM certificate does not cover the domain name", 400)
    regional_name = get_regional_domain_name(domain_name, context.region)
    hosted_zone_id = (
        "Z"
        + hashlib.sha256(f"{_partition(context)}:{context.region}:apigatewayv2".encode())
        .hexdigest()[:13]
        .upper()
    )
    return {
        "ApiMappingSelectionExpression": "$request.basepath",
        "DomainName": domain_name,
        "DomainNameConfigurations": [
            {
                "ApiGatewayDomainName": regional_name,
                "CertificateArn": certificate_arn,
                "DomainNameStatus": "AVAILABLE",
                "EndpointType": "REGIONAL",
                "HostedZoneId": hosted_zone_id,
                "IpAddressType": ip_address_type,
                "SecurityPolicy": "TLS_1_2",
            }
        ],
        "RoutingMode": "API_MAPPING_ONLY",
        "Tags": _tags(request.get("Tags")),
    }


def _certificate_name_covers(certificate_name: str, domain_name: str) -> bool:
    if certificate_name == domain_name:
        return True
    if domain_name.startswith("*.") or not certificate_name.startswith("*."):
        return False
    suffix = certificate_name[1:]
    return domain_name.endswith(suffix) and domain_name.count(".") == certificate_name.count(".")


def _local_acm_certificate(context: RequestContext, certificate_arn: str) -> dict[str, Any] | None:
    account_backends = acm_models.acm_backends.get(context.account_id)
    backend = account_backends.get(context.region) if account_backends is not None else None
    certificate = backend._certificates.get(certificate_arn) if backend is not None else None
    if certificate is None:
        return None
    response = certificate.describe()
    detail = response.get("Certificate") if isinstance(response, dict) else None
    return copy.deepcopy(detail) if isinstance(detail, dict) else None


def _api_mapping_properties(store: ApiGatewayV2Store, request: ServiceRequest) -> dict[str, Any]:
    api = _api(store, request.get("ApiId"))
    stage = _stage(api, request.get("Stage"))
    key = request.get("ApiMappingKey", "")
    if (
        not isinstance(key, str)
        or _API_MAPPING_KEY_RE.fullmatch(key) is None
        or key.startswith("/")
        or key.endswith("/")
        or "//" in key
    ):
        _error("BadRequestException", "Invalid ApiMappingKey", 400)
    return {"ApiId": api.api_id, "ApiMappingKey": key, "Stage": stage.stage_name}


def _integration_properties(context: RequestContext, request: ServiceRequest) -> dict[str, Any]:
    integration_type = request.get("IntegrationType")
    if integration_type not in {"AWS_PROXY", "HTTP_PROXY"}:
        _error(
            "BadRequestException",
            "Only AWS_PROXY Lambda and HTTP_PROXY integrations are currently supported",
            400,
        )
    connection_type = request.get("ConnectionType", "INTERNET")
    if connection_type != "INTERNET":
        _error("BadRequestException", "Only INTERNET integrations are currently supported", 400)
    method = request.get("IntegrationMethod", "POST" if integration_type == "AWS_PROXY" else "ANY")
    if method not in {"ANY", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}:
        _error("BadRequestException", "Invalid IntegrationMethod", 400)
    uri = _required_string(request.get("IntegrationUri"), "IntegrationUri", 2048)
    if integration_type == "HTTP_PROXY":
        parsed = urlsplit(uri)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            _error("BadRequestException", "Invalid IntegrationUri", 400)
        payload_format = request.get("PayloadFormatVersion", "1.0")
        if payload_format != "1.0":
            _error("BadRequestException", "HTTP_PROXY requires payload format version 1.0", 400)
    else:
        if method != "POST":
            _error("BadRequestException", "Lambda AWS_PROXY requires IntegrationMethod POST", 400)
        payload_format = request.get("PayloadFormatVersion", "2.0")
        if payload_format != "2.0":
            _error(
                "BadRequestException", "Lambda AWS_PROXY requires payload format version 2.0", 400
            )
        function_prefix = (
            f"arn:{_partition(context)}:lambda:{context.region}:{context.account_id}:function:"
        )
        invocation_prefix = (
            f"arn:{_partition(context)}:apigateway:{context.region}:lambda:path/2015-03-31/"
            f"functions/{function_prefix}"
        )
        if uri.startswith(function_prefix):
            function_part = uri.removeprefix(function_prefix)
        elif uri.startswith(invocation_prefix) and uri.endswith("/invocations"):
            function_part = uri.removeprefix(invocation_prefix).removesuffix("/invocations")
        else:
            function_part = ""
        if (
            re.fullmatch(r"[A-Za-z0-9-_]{1,64}(?::(?:\$LATEST|[A-Za-z0-9-_]+))?", function_part)
            is None
        ):
            _error(
                "BadRequestException",
                "IntegrationUri must reference a local Lambda in the API account and region",
                400,
            )
    timeout = request.get("TimeoutInMillis", 30000)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 50 <= timeout <= 30000:
        _error("BadRequestException", "TimeoutInMillis must be between 50 and 30000", 400)
    properties: dict[str, Any] = {
        "ApiGatewayManaged": False,
        "ConnectionType": "INTERNET",
        "IntegrationMethod": method,
        "IntegrationType": integration_type,
        "IntegrationUri": uri,
        "PayloadFormatVersion": payload_format,
        "TimeoutInMillis": timeout,
    }
    if description := _optional_string(request.get("Description"), "Description", 1024):
        properties["Description"] = description
    return properties


def _route_properties(api: ApiGatewayV2Api, request: ServiceRequest) -> dict[str, Any]:
    route_key = _required_string(request.get("RouteKey"), "RouteKey", 512)
    if route_key != "$default" and _ROUTE_KEY_RE.fullmatch(route_key) is None:
        _error("BadRequestException", "Invalid RouteKey", 400)
    if route_key != "$default":
        _validate_route_path(_ROUTE_KEY_RE.fullmatch(route_key).group("path"))
    target = _required_string(request.get("Target"), "Target", 128)
    target_match = _TARGET_RE.fullmatch(target)
    if target_match is None or target_match.group("id") not in api.integrations:
        _error("BadRequestException", "The route target integration does not exist", 400)
    authorization_type = request.get("AuthorizationType", "NONE")
    if authorization_type not in {"NONE", "JWT"}:
        _error("BadRequestException", "Only NONE and JWT authorization are supported", 400)
    authorizer_id = request.get("AuthorizerId")
    scopes = request.get("AuthorizationScopes", [])
    if not isinstance(scopes, list):
        _error("BadRequestException", "Invalid AuthorizationScopes", 400)
    scopes = _string_list(scopes, "AuthorizationScopes", maximum=100, item_maximum=256)
    if authorization_type == "JWT":
        if not isinstance(authorizer_id, str) or authorizer_id not in api.authorizers:
            _error("BadRequestException", "A JWT route requires an existing authorizer", 400)
    elif authorizer_id is not None or scopes:
        _error("BadRequestException", "Authorization fields require JWT authorization", 400)
    api_key_required = request.get("ApiKeyRequired", False)
    if api_key_required is not False:
        _error("BadRequestException", "API keys are not supported for HTTP APIs", 400)
    properties: dict[str, Any] = {
        "ApiGatewayManaged": False,
        "ApiKeyRequired": False,
        "AuthorizationScopes": scopes,
        "AuthorizationType": authorization_type,
        "RouteKey": route_key,
        "Target": target,
    }
    if authorization_type == "JWT":
        properties["AuthorizerId"] = authorizer_id
    if operation_name := _optional_string(request.get("OperationName"), "OperationName", 64):
        properties["OperationName"] = operation_name
    return properties


def _validate_route_path(path: str) -> None:
    variables: set[str] = set()
    segments = path.split("/")[1:]
    for index, segment in enumerate(segments):
        if "{" not in segment and "}" not in segment:
            continue
        match = re.fullmatch(r"\{(?P<name>[A-Za-z][A-Za-z0-9_]*)(?P<greedy>\+)?\}", segment)
        if match is None or match.group("name") in variables:
            _error("BadRequestException", "Invalid route path parameter", 400)
        if match.group("greedy") and index != len(segments) - 1:
            _error("BadRequestException", "A greedy path parameter must be last", 400)
        variables.add(match.group("name"))


def _stage_properties(
    api: ApiGatewayV2Api, request: ServiceRequest, created_at: datetime
) -> dict[str, Any]:
    stage_name = request.get("StageName")
    if not isinstance(stage_name, str) or _STAGE_NAME_RE.fullmatch(stage_name) is None:
        _error("BadRequestException", "Invalid StageName", 400)
    auto_deploy = request.get("AutoDeploy", False)
    if not isinstance(auto_deploy, bool):
        _error("BadRequestException", "AutoDeploy must be a boolean", 400)
    deployment_id = request.get("DeploymentId")
    if auto_deploy and deployment_id is None:
        deployment_id = _new_deployment(api, created_at, auto_deployed=True).deployment_id
    if not isinstance(deployment_id, str) or deployment_id not in api.deployments:
        _error("BadRequestException", "The stage requires an existing deployment", 400)
    stage_variables = request.get("StageVariables", {})
    if not isinstance(stage_variables, dict) or len(stage_variables) > 100:
        _error("BadRequestException", "Invalid StageVariables", 400)
    for key, value in stage_variables.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 64
            or not isinstance(value, str)
            or len(value) > 512
        ):
            _error("BadRequestException", "Invalid StageVariables", 400)
    properties: dict[str, Any] = {
        "ApiGatewayManaged": False,
        "AutoDeploy": auto_deploy,
        "CreatedDate": created_at,
        "DeploymentId": deployment_id,
        "LastUpdatedDate": created_at,
        "StageName": stage_name,
        "StageVariables": copy.deepcopy(stage_variables),
        "Tags": _tags(request.get("Tags")),
    }
    if access_logs := _access_log_settings(request.get("AccessLogSettings")):
        properties["AccessLogSettings"] = access_logs
    if route_settings := _default_route_settings(request.get("DefaultRouteSettings")):
        properties["DefaultRouteSettings"] = route_settings
    if description := _optional_string(request.get("Description"), "Description", 1024):
        properties["Description"] = description
    return properties


def _access_log_settings(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"DestinationArn", "Format"}:
        _error("BadRequestException", "Invalid AccessLogSettings", 400)
    destination = _required_string(value.get("DestinationArn"), "DestinationArn", 2048)
    log_format = _required_string(value.get("Format"), "Format", 1024)
    if not destination.startswith("arn:"):
        _error("BadRequestException", "Invalid access log destination", 400)
    return {"DestinationArn": destination, "Format": log_format}


def _default_route_settings(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    allowed = {
        "DataTraceEnabled",
        "DetailedMetricsEnabled",
        "LoggingLevel",
        "ThrottlingBurstLimit",
        "ThrottlingRateLimit",
    }
    if not isinstance(value, dict) or not set(value) <= allowed:
        _error("BadRequestException", "Invalid DefaultRouteSettings", 400)
    result = copy.deepcopy(value)
    for field in ("DataTraceEnabled", "DetailedMetricsEnabled"):
        if field in result and not isinstance(result[field], bool):
            _error("BadRequestException", f"{field} must be a boolean", 400)
    if "LoggingLevel" in result and result["LoggingLevel"] not in {"ERROR", "INFO", "OFF"}:
        _error("BadRequestException", "Invalid LoggingLevel", 400)
    burst = result.get("ThrottlingBurstLimit")
    if burst is not None and (
        not isinstance(burst, int) or isinstance(burst, bool) or not 1 <= burst <= 5000
    ):
        _error("BadRequestException", "Invalid ThrottlingBurstLimit", 400)
    rate = result.get("ThrottlingRateLimit")
    if rate is not None and (
        not isinstance(rate, (int, float)) or isinstance(rate, bool) or not 0 < rate <= 10000
    ):
        _error("BadRequestException", "Invalid ThrottlingRateLimit", 400)
    return result


def _new_deployment(
    api: ApiGatewayV2Api,
    created_at: datetime,
    *,
    auto_deployed: bool,
    description: Any = None,
) -> ApiGatewayV2Deployment:
    deployment_id = _new_id(api.deployments)
    properties: dict[str, Any] = {
        "AutoDeployed": auto_deployed,
        "CreatedDate": created_at,
        "DeploymentId": deployment_id,
        "DeploymentStatus": "DEPLOYED",
    }
    if description := _optional_string(description, "Description", 1024):
        properties["Description"] = description
    deployment = ApiGatewayV2Deployment(
        deployment_id,
        properties,
        ApiGatewayV2DeploymentSnapshot(
            authorizers=copy.deepcopy(api.authorizers),
            integrations=copy.deepcopy(api.integrations),
            routes=copy.deepcopy(api.routes),
        ),
    )
    api.deployments[deployment_id] = deployment
    return deployment


def _refresh_auto_deploy_stages(api: ApiGatewayV2Api, updated_at: datetime) -> None:
    for stage in api.stages.values():
        if not stage.properties.get("AutoDeploy"):
            continue
        deployment = _new_deployment(api, updated_at, auto_deployed=True)
        stage.properties["DeploymentId"] = deployment.deployment_id
        stage.properties["LastUpdatedDate"] = updated_at


def _create_api_properties(
    context: RequestContext, request: ServiceRequest, created_at: datetime
) -> dict[str, Any]:
    _reject_unknown(request, _CREATE_API_FIELDS)
    if any(request.get(field) is not None for field in ("CredentialsArn", "RouteKey", "Target")):
        _error(
            "BadRequestException",
            "Quick create is not currently supported",
            400,
        )
    if request.get("ProtocolType") != "HTTP":
        _error("BadRequestException", "Only HTTP APIs are currently supported", 400)
    if request.get("DisableSchemaValidation") not in (None, False):
        _error(
            "BadRequestException",
            "DisableSchemaValidation is supported only for WebSocket APIs",
            400,
        )
    name = _required_string(request.get("Name"), "Name", 128)
    api_key_expression = request.get(
        "ApiKeySelectionExpression", _HTTP_API_KEY_SELECTION_EXPRESSION
    )
    if api_key_expression != _HTTP_API_KEY_SELECTION_EXPRESSION:
        _error("BadRequestException", "Invalid ApiKeySelectionExpression", 400)
    route_expression = request.get("RouteSelectionExpression", _HTTP_ROUTE_SELECTION_EXPRESSION)
    if route_expression != _HTTP_ROUTE_SELECTION_EXPRESSION:
        _error("BadRequestException", "Invalid RouteSelectionExpression for an HTTP API", 400)
    ip_address_type = request.get("IpAddressType", "ipv4")
    if ip_address_type not in {"ipv4", "dualstack"}:
        _error("BadRequestException", "Invalid IpAddressType", 400)
    disabled = request.get("DisableExecuteApiEndpoint", False)
    if not isinstance(disabled, bool):
        _error("BadRequestException", "DisableExecuteApiEndpoint must be a boolean", 400)
    if not isinstance(created_at, datetime) or created_at.tzinfo is None:
        _error("BadRequestException", "CreatedDate must be timezone-aware", 400)
    properties: dict[str, Any] = {
        "ApiGatewayManaged": False,
        "ApiKeySelectionExpression": api_key_expression,
        "CreatedDate": created_at,
        "DisableExecuteApiEndpoint": disabled,
        "IpAddressType": ip_address_type,
        "Name": name,
        "ProtocolType": "HTTP",
        "RouteSelectionExpression": route_expression,
        "Tags": _tags(request.get("Tags")),
    }
    optional = {
        "CorsConfiguration": _cors(request.get("CorsConfiguration")),
        "Description": _optional_string(request.get("Description"), "Description", 1024),
        "Version": _optional_string(request.get("Version"), "Version", 64),
    }
    properties.update({key: value for key, value in optional.items() if value is not None})
    return properties


def _updated_api_properties(
    context: RequestContext, existing: dict[str, Any], request: ServiceRequest
) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "Name": existing["Name"],
        "ProtocolType": "HTTP",
        "ApiKeySelectionExpression": existing["ApiKeySelectionExpression"],
        "RouteSelectionExpression": existing["RouteSelectionExpression"],
        "DisableExecuteApiEndpoint": existing["DisableExecuteApiEndpoint"],
        "IpAddressType": existing["IpAddressType"],
        "Tags": existing["Tags"],
    }
    for field in (
        "ApiKeySelectionExpression",
        "CorsConfiguration",
        "CredentialsArn",
        "Description",
        "DisableSchemaValidation",
        "DisableExecuteApiEndpoint",
        "IpAddressType",
        "Name",
        "RouteKey",
        "RouteSelectionExpression",
        "Target",
        "Version",
    ):
        if field in request:
            merged[field] = copy.deepcopy(request[field])
        elif field in existing:
            merged[field] = copy.deepcopy(existing[field])
    properties = _create_api_properties(context, merged, existing["CreatedDate"])
    properties["ApiId"] = existing["ApiId"]
    properties["ApiEndpoint"] = existing["ApiEndpoint"]
    return properties


def _authorizer_properties(context: RequestContext, request: ServiceRequest) -> dict[str, Any]:
    if any(request.get(field) is not None for field in _REQUEST_AUTHORIZER_ONLY_FIELDS):
        _error("BadRequestException", "REQUEST authorizer fields are not supported for JWT", 400)
    if request.get("AuthorizerType") != "JWT":
        _error("BadRequestException", "Only JWT authorizers are currently supported", 400)
    name = _required_string(request.get("Name"), "Name", 128)
    identity_source = request.get("IdentitySource")
    jwt_configuration = request.get("JwtConfiguration")
    if not isinstance(jwt_configuration, dict) or set(jwt_configuration) != {"Audience", "Issuer"}:
        _error("BadRequestException", "JwtConfiguration requires Audience and Issuer", 400)
    audience = jwt_configuration.get("Audience")
    if (
        not isinstance(audience, list)
        or not 1 <= len(audience) <= _MAX_AUDIENCES_PER_AUTHORIZER
        or not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in audience)
        or len(set(audience)) != len(audience)
    ):
        _error("BadRequestException", "Invalid JWT audience configuration", 400)
    issuer = jwt_configuration.get("Issuer")
    try:
        configuration = HttpApiJwtAuthorizerConfiguration(
            identity_source=tuple(identity_source) if isinstance(identity_source, list) else (),
            issuer=issuer,
            audience=tuple(audience),
        )
    except HttpApiJwtConfigurationError as error:
        _error("BadRequestException", str(error), 400)
    partition = _partition(context)
    expected_prefix = f"https://cognito-idp.{context.region}.{partition_dns_suffix(partition)}/"
    if not configuration.issuer.startswith(expected_prefix):
        _error("BadRequestException", "The Cognito issuer is outside the API region", 400)
    return {
        "AuthorizerType": "JWT",
        "IdentitySource": list(configuration.identity_source),
        "JwtConfiguration": {
            "Audience": list(configuration.audience),
            "Issuer": configuration.issuer,
        },
        "Name": name,
    }


def _cors(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    allowed = {
        "AllowCredentials",
        "AllowHeaders",
        "AllowMethods",
        "AllowOrigins",
        "ExposeHeaders",
        "MaxAge",
    }
    if not isinstance(value, dict) or not set(value) <= allowed:
        _error("BadRequestException", "Invalid CorsConfiguration", 400)
    result: dict[str, Any] = {}
    if "AllowCredentials" in value:
        if not isinstance(value["AllowCredentials"], bool):
            _error("BadRequestException", "AllowCredentials must be a boolean", 400)
        result["AllowCredentials"] = value["AllowCredentials"]
    for field in ("AllowHeaders", "AllowMethods", "AllowOrigins", "ExposeHeaders"):
        if field in value:
            result[field] = _string_list(value[field], field, maximum=100, item_maximum=256)
    if result.get("AllowCredentials") and "*" in result.get("AllowOrigins", []):
        _error(
            "BadRequestException", "AllowCredentials cannot be combined with a wildcard origin", 400
        )
    if "MaxAge" in value:
        max_age = value["MaxAge"]
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not 0 <= max_age <= 86400:
            _error("BadRequestException", "MaxAge must be between 0 and 86400", 400)
        result["MaxAge"] = max_age
    return result


def _tags(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 50:
        _error("BadRequestException", "Invalid tags", 400)
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or key.lower().startswith("aws:")
            or not isinstance(item, str)
            or len(item) > 256
        ):
            _error("BadRequestException", "Invalid tags", 400)
        result[key] = item
    return result


def _string_list(value: Any, name: str, *, maximum: int, item_maximum: int) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or not all(isinstance(item, str) and 1 <= len(item) <= item_maximum for item in value)
        or len(set(value)) != len(value)
    ):
        _error("BadRequestException", f"Invalid {name}", 400)
    return list(value)


def _required_string(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _error("BadRequestException", f"{name} is required", 400)
    return value


def _optional_string(value: Any, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        _error("BadRequestException", f"Invalid {name}", 400)
    return value


def _page_size(value: Any) -> int:
    if value is None:
        return _DEFAULT_PAGE_SIZE
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        _error("BadRequestException", "Invalid MaxResults", 400)
    result = int(value)
    if not 1 <= result <= _MAX_PAGE_SIZE:
        _error("BadRequestException", "MaxResults must be between 1 and 500", 400)
    return result


def _page_secret(store: ApiGatewayV2Store, *, create: bool) -> bytes:
    if not store.pagination_secret:
        if not create:
            _error("BadRequestException", "Invalid NextToken", 400)
        store.pagination_secret = secrets.token_bytes(32)
    return store.pagination_secret


def _encode_page_token(store: ApiGatewayV2Store, scope: str, after: str) -> str:
    payload = json.dumps(
        {"after": after, "scope": scope, "version": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.digest(_page_secret(store, create=True), encoded.encode(), hashlib.sha256)
    ).rstrip(b"=")
    token = f"{encoded}.{signature.decode()}"
    if len(token) > _MAX_PAGE_TOKEN_BYTES:
        _error("BadRequestException", "Invalid NextToken", 400)
    return token


def _decode_page_token(store: ApiGatewayV2Store, value: Any, scope: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PAGE_TOKEN_BYTES:
        _error("BadRequestException", "Invalid NextToken", 400)
    parts = value.split(".")
    if len(parts) != 2 or any(_BASE64URL_RE.fullmatch(part) is None for part in parts):
        _error("BadRequestException", "Invalid NextToken", 400)
    encoded, signature = parts
    expected = base64.urlsafe_b64encode(
        hmac.digest(_page_secret(store, create=False), encoded.encode(), hashlib.sha256)
    ).rstrip(b"=")
    if not hmac.compare_digest(signature.encode(), expected):
        _error("BadRequestException", "Invalid NextToken", 400)
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
            raise ValueError
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        _error("BadRequestException", "Invalid NextToken", 400)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"after", "scope", "version"}
        or payload.get("scope") != scope
        or payload.get("version") != 1
    ):
        _error("BadRequestException", "Invalid NextToken", 400)
    after = payload.get("after")
    if (
        not isinstance(after, str)
        or not 1 <= len(after) <= 300
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in after)
    ):
        _error("BadRequestException", "Invalid NextToken", 400)
    return after


def _page_after(items: list, limit: int, after: str | None, key):
    start = 0
    if after is not None:
        while start < len(items) and key(items[start]) <= after:
            start += 1
    page = items[start : start + limit]
    has_more = start + len(page) < len(items)
    next_after = key(page[-1]) if page and has_more else None
    return page, next_after


def _new_id(existing: dict[str, Any]) -> str:
    for _ in range(_MAX_ID_ATTEMPTS):
        value = short_uid()
        if value not in existing:
            return value
    _error("LimitExceededException", "Unable to allocate a unique identifier", 429)


def _reject_unknown(request: ServiceRequest, allowed: set[str]) -> None:
    if not isinstance(request, dict) or not set(request) <= allowed:
        _error("BadRequestException", "The request contains unsupported fields", 400)


def _partition(context: RequestContext) -> str:
    return context.partition or get_partition(context.region)


def _execute_api_router():
    from localstack.services.apigateway.next_gen.execute_api.router import (
        get_api_gateway_router,
    )

    return get_api_gateway_router()


def _error(code: str, message: str, status_code: int) -> None:
    raise CommonServiceException(
        code=code,
        message=message,
        status_code=status_code,
        sender_fault=True,
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)
