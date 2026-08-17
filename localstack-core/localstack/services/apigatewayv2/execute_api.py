import base64
import copy
import fnmatch
import json
import logging
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import BoundedSemaphore, RLock
from typing import Any, TypedDict, Unpack

import requests
from botocore.exceptions import ClientError
from rolo import Request

from localstack.http import Response
from localstack.services.apigatewayv2.jwt_authorizer import (
    HttpApiJwtAuthorization,
    HttpApiJwtAuthorizerConfiguration,
    HttpApiJwtConfigurationError,
    HttpApiJwtUnauthorized,
    authorize_native_cognito_jwt,
)
from localstack.services.apigatewayv2.models import (
    ApiGatewayV2Api,
    ApiGatewayV2DeploymentSnapshot,
    apigatewayv2_stores,
)
from localstack.utils.aws.arns import get_partition

LOG = logging.getLogger(__name__)

_HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_LAMBDA_EXECUTOR = ThreadPoolExecutor(max_workers=32, thread_name_prefix="apigwv2-lambda")
_LAMBDA_ADMISSION = BoundedSemaphore(64)
_MAX_LAMBDA_RESPONSE_BYTES = 6 * 1024 * 1024


class HttpApiRouteParameters(TypedDict, total=False):
    api_id: str
    custom_domain: str
    path: str
    stage: str | None


@dataclass(frozen=True)
class _Invocation:
    account_id: str
    region: str
    api: ApiGatewayV2Api
    stage_name: str
    path: str
    snapshot: ApiGatewayV2DeploymentSnapshot


class HttpApiGatewayEndpoint:
    """Invoke the deployed, native HTTP API subset.

    The subset deliberately supports static and path-parameter routes, explicit
    and automatic deployments, stages, native Cognito JWT authorizers, Lambda
    payload 2.0, and INTERNET HTTP proxy integrations. Unsupported route and
    integration features remain control-plane validation errors rather than
    silently behaving like a different AWS feature.
    """

    def __init__(
        self,
        *,
        lambda_invoker: Callable[[str, bytes, str], bytes] | None = None,
    ) -> None:
        self._lambda_invoker = lambda_invoker or _invoke_local_lambda
        self._throttle_lock = RLock()
        self._throttle_buckets: dict[tuple[str, str], tuple[float, float]] = {}

    def is_http_api(self, api_id: str) -> bool:
        with apigatewayv2_stores.lock:
            return any(api_id in store.apis for _, _, store in apigatewayv2_stores.iter_stores())

    def __call__(self, request: Request, **kwargs: Unpack[HttpApiRouteParameters]) -> Response:
        if custom_domain := kwargs.get("custom_domain"):
            if request.scheme.lower() != "https":
                return _json_response(403, {"message": "Forbidden"})
            invocation = self._resolve_custom_invocation(custom_domain, kwargs.get("path", ""))
        else:
            invocation = self._resolve_invocation(
                kwargs.get("api_id", "").lower(), kwargs.get("stage"), kwargs.get("path", "")
            )
        if invocation is None:
            return _json_response(404, {"message": "Not Found"})

        def respond(response: Response) -> Response:
            return _with_cors(response, request, invocation.api.properties)

        if invocation.api.properties.get("DisableExecuteApiEndpoint"):
            return respond(_json_response(403, {"message": "Forbidden"}))
        cors_response = _preflight_response(request, invocation.api.properties)
        if cors_response is not None:
            return cors_response

        matched_route = _matching_route(invocation.snapshot, request.method, invocation.path)
        if matched_route is None:
            return respond(_json_response(404, {"message": "Not Found"}))
        if self._is_throttled(invocation):
            response = _json_response(429, {"message": "Too Many Requests"})
            response.headers["x-amzn-ErrorType"] = "TooManyRequestsException"
            return respond(response)
        route, path_parameters = matched_route
        route_properties = route.properties
        authorization: HttpApiJwtAuthorization | None = None
        if route_properties.get("AuthorizationType") == "JWT":
            authorizer = invocation.snapshot.authorizers.get(route_properties.get("AuthorizerId"))
            if authorizer is None:
                return respond(_json_response(500, {"message": "Internal Server Error"}))
            try:
                configuration = authorizer.properties["JwtConfiguration"]
                authorization = authorize_native_cognito_jwt(
                    authorization_headers=tuple(request.headers.getlist("Authorization")),
                    configuration=HttpApiJwtAuthorizerConfiguration(
                        identity_source=tuple(authorizer.properties["IdentitySource"]),
                        issuer=configuration["Issuer"],
                        audience=tuple(configuration["Audience"]),
                    ),
                    authorization_scopes=tuple(route_properties.get("AuthorizationScopes", ())),
                    api_account_id=invocation.account_id,
                    api_region=invocation.region,
                )
            except HttpApiJwtUnauthorized:
                return respond(_json_response(401, {"message": "Unauthorized"}))
            except (HttpApiJwtConfigurationError, KeyError, TypeError, ValueError):
                LOG.exception("Invalid deployed HTTP API JWT authorizer configuration")
                return respond(_json_response(500, {"message": "Internal Server Error"}))

        target_value = route_properties.get("Target")
        if not isinstance(target_value, str) or not target_value.startswith("integrations/"):
            return respond(_json_response(500, {"message": "Internal Server Error"}))
        target = target_value.removeprefix("integrations/")
        integration = invocation.snapshot.integrations.get(target)
        if integration is None:
            return respond(_json_response(500, {"message": "Internal Server Error"}))
        if integration.properties.get("IntegrationType") == "AWS_PROXY":
            result = _invoke_lambda_proxy(
                request,
                invocation,
                route_properties,
                integration.properties,
                authorization,
                path_parameters,
                self._lambda_invoker,
            )
        elif integration.properties.get("IntegrationType") == "HTTP_PROXY":
            result = _invoke_http_proxy(request, integration.properties)
        else:
            result = _json_response(500, {"message": "Internal Server Error"})
        return respond(result)

    def _is_throttled(self, invocation: _Invocation) -> bool:
        settings = invocation.api.stages[invocation.stage_name].properties.get(
            "DefaultRouteSettings", {}
        )
        rate = settings.get("ThrottlingRateLimit")
        burst = settings.get("ThrottlingBurstLimit")
        if not isinstance(rate, (int, float)) or not isinstance(burst, int):
            return False
        now = time.monotonic()
        key = (invocation.api.api_id, invocation.stage_name)
        with self._throttle_lock:
            tokens, updated_at = self._throttle_buckets.get(key, (float(burst), now))
            tokens = min(float(burst), tokens + (now - updated_at) * rate)
            if tokens < 1:
                self._throttle_buckets[key] = (tokens, now)
                return True
            self._throttle_buckets[key] = (tokens - 1, now)
            return False

    @staticmethod
    def _resolve_invocation(
        api_id: str, route_stage: str | None, route_path: str
    ) -> _Invocation | None:
        with apigatewayv2_stores.lock:
            matches = [
                (account_id, region, api)
                for account_id, region, store in apigatewayv2_stores.iter_stores()
                if (api := store.apis.get(api_id)) is not None
            ]
            if len(matches) != 1:
                return None
            account_id, region, api = matches[0]
            if route_stage in api.stages:
                stage_name = route_stage
                path = _path(route_path)
            elif "$default" in api.stages:
                stage_name = "$default"
                segments = [part for part in (route_stage, route_path) if part]
                path = _path("/".join(segments))
            else:
                return None
            stage = api.stages[stage_name]
            deployment = api.deployments.get(stage.properties.get("DeploymentId"))
            if deployment is None:
                return None
            return _Invocation(
                account_id=account_id,
                region=region,
                api=copy.deepcopy(api),
                stage_name=stage_name,
                path=path,
                snapshot=copy.deepcopy(deployment.snapshot),
            )

    @staticmethod
    def _resolve_custom_invocation(custom_domain: str, route_path: str) -> _Invocation | None:
        requested_domain = custom_domain.split(":", 1)[0].lower()
        path = _path(route_path)
        with apigatewayv2_stores.lock:
            matches = []
            for account_id, region, store in apigatewayv2_stores.iter_stores():
                for domain in store.domain_names.values():
                    if not _custom_domain_matches(domain.domain_name, requested_domain):
                        continue
                    candidates = []
                    for mapping in domain.api_mappings.values():
                        key = mapping.properties.get("ApiMappingKey", "")
                        prefix = f"/{key}" if key else ""
                        if key and path != prefix and not path.startswith(f"{prefix}/"):
                            continue
                        candidates.append((len(key.split("/")) if key else 0, len(key), mapping))
                    if not candidates:
                        continue
                    _, _, mapping = max(candidates, key=lambda item: (item[0], item[1]))
                    api = store.apis.get(mapping.properties.get("ApiId"))
                    if api is None:
                        continue
                    stage_name = mapping.properties.get("Stage")
                    stage = api.stages.get(stage_name)
                    if stage is None:
                        continue
                    deployment = api.deployments.get(stage.properties.get("DeploymentId"))
                    if deployment is None:
                        continue
                    key = mapping.properties.get("ApiMappingKey", "")
                    prefix = f"/{key}" if key else ""
                    mapped_path = _path(path[len(prefix) :]) if prefix else path
                    matches.append(
                        _Invocation(
                            account_id=account_id,
                            region=region,
                            api=copy.deepcopy(api),
                            stage_name=stage_name,
                            path=mapped_path,
                            snapshot=copy.deepcopy(deployment.snapshot),
                        )
                    )
            return matches[0] if len(matches) == 1 else None


def _matching_route(
    snapshot: ApiGatewayV2DeploymentSnapshot, method: str, path: str
) -> tuple[Any, dict[str, str]] | None:
    candidates = []
    default = None
    for route in snapshot.routes.values():
        route_key = route.properties["RouteKey"]
        if route_key == "$default":
            default = route
            continue
        route_method, template = route_key.split(" ", 1)
        if route_method not in {"ANY", method.upper()}:
            continue
        parameters = _match_route_path(template, path)
        if parameters is None:
            continue
        static_segments = sum("{" not in segment for segment in template.split("/")[1:])
        greedy = "{proxy+}" in template or "+}" in template
        rank = (route_method == method.upper(), static_segments, not greedy, len(template))
        candidates.append((rank, route, parameters))
    if candidates:
        _, route, parameters = max(candidates, key=lambda item: item[0])
        return route, parameters
    return (default, {}) if default is not None else None


def _custom_domain_matches(configured: str, requested: str) -> bool:
    if configured == requested:
        return True
    if not configured.startswith("*."):
        return False
    return requested.endswith(configured[1:]) and requested.count(".") == configured.count(".")


def _match_route_path(template: str, path: str) -> dict[str, str] | None:
    template_segments = template.strip("/").split("/") if template != "/" else []
    path_segments = path.strip("/").split("/") if path != "/" else []
    parameters: dict[str, str] = {}
    index = 0
    for template_segment in template_segments:
        if template_segment.startswith("{") and template_segment.endswith("+}"):
            if index >= len(path_segments):
                return None
            parameters[template_segment[1:-2]] = "/".join(path_segments[index:])
            index = len(path_segments)
            break
        if index >= len(path_segments):
            return None
        if template_segment.startswith("{") and template_segment.endswith("}"):
            parameters[template_segment[1:-1]] = path_segments[index]
        elif template_segment != path_segments[index]:
            return None
        index += 1
    return parameters if index == len(path_segments) else None


def _invoke_http_proxy(request: Request, integration: dict[str, Any]) -> Response:
    method = integration.get("IntegrationMethod")
    uri = integration.get("IntegrationUri")
    timeout = integration.get("TimeoutInMillis")
    if (
        method not in {"ANY", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
        or not isinstance(uri, str)
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
    ):
        return _json_response(500, {"message": "Internal Server Error"})
    if method == "ANY":
        method = request.method
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _HOP_BY_HOP_HEADERS
    }
    query = {
        key: values[0] if len(values) == 1 else values
        for key in request.args
        if (values := request.args.getlist(key))
    }
    parameters: dict[str, Any] = {
        "method": method,
        "url": uri,
        "params": query,
        "headers": headers,
        "timeout": timeout / 1000,
        "allow_redirects": False,
    }
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        parameters["data"] = request.get_data()
    try:
        upstream = requests.request(**parameters)
    except requests.RequestException:
        LOG.exception("HTTP API integration request failed")
        return _json_response(502, {"message": "Internal Server Error"})
    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in _HOP_BY_HOP_HEADERS
    }
    return Response(upstream.content, status=upstream.status_code, headers=response_headers)


def _invoke_lambda_proxy(
    request: Request,
    invocation: _Invocation,
    route: dict[str, Any],
    integration: dict[str, Any],
    authorization: HttpApiJwtAuthorization | None,
    path_parameters: dict[str, str],
    invoker: Callable[[str, bytes, str], bytes],
) -> Response:
    uri = integration.get("IntegrationUri")
    timeout = integration.get("TimeoutInMillis")
    if not isinstance(uri, str) or not isinstance(timeout, int) or isinstance(timeout, bool):
        return _json_response(500, {"message": "Internal Server Error"})
    function_arn = (
        uri.split("/functions/", 1)[1].removesuffix("/invocations")
        if "/functions/" in uri and uri.endswith("/invocations")
        else uri
    )
    event = _lambda_event(request, invocation, route, authorization, path_parameters)
    route_key = route.get("RouteKey")
    source_path = (
        route_key.split(" ", 1)[1]
        if isinstance(route_key, str) and " " in route_key
        else invocation.path
    )
    source_arn = (
        f"arn:{get_partition(invocation.region)}:execute-api:{invocation.region}:"
        f"{invocation.account_id}:{invocation.api.api_id}/{invocation.stage_name}/"
        f"{request.method}{source_path}"
    )
    if not _LAMBDA_ADMISSION.acquire(blocking=False):
        return _json_response(503, {"message": "Service Unavailable"})
    future = None
    try:
        future = _LAMBDA_EXECUTOR.submit(
            invoker,
            function_arn,
            json.dumps(event, separators=(",", ":")).encode(),
            source_arn,
        )
        future.add_done_callback(lambda _: _LAMBDA_ADMISSION.release())
        payload = future.result(timeout=timeout / 1000)
    except FutureTimeoutError:
        future.cancel()
        return _json_response(504, {"message": "Endpoint request timed out"})
    except ClientError as error:
        if future is None:
            _LAMBDA_ADMISSION.release()
        LOG.warning("HTTP API Lambda invocation was rejected: %s", error)
        status = (
            500 if error.response.get("Error", {}).get("Code") == "AccessDeniedException" else 502
        )
        return _json_response(status, {"message": "Internal Server Error"})
    except Exception:
        if future is None:
            _LAMBDA_ADMISSION.release()
        LOG.exception("HTTP API Lambda integration failed")
        return _json_response(502, {"message": "Internal Server Error"})
    return _lambda_response(payload)


def _lambda_event(
    request: Request,
    invocation: _Invocation,
    route: dict[str, Any],
    authorization: HttpApiJwtAuthorization | None,
    path_parameters: dict[str, str],
) -> dict[str, Any]:
    raw_body = request.get_data()
    try:
        body = raw_body.decode() if raw_body else None
        is_base64_encoded = False
    except UnicodeDecodeError:
        body = base64.b64encode(raw_body).decode()
        is_base64_encoded = True
    headers = {key.lower(): value for key, value in request.headers.items()}
    query = {
        key: ",".join(request.args.getlist(key))
        for key in request.args
        if request.args.getlist(key)
    }
    now = datetime.now(UTC)
    request_context: dict[str, Any] = {
        "accountId": invocation.account_id,
        "apiId": invocation.api.api_id,
        "domainName": request.host,
        "domainPrefix": request.host.split(":", 1)[0].split(".", 1)[0],
        "http": {
            "method": request.method,
            "path": invocation.path,
            "protocol": request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            "sourceIp": request.remote_addr or "",
            "userAgent": request.user_agent.string,
        },
        "requestId": str(uuid.uuid4()),
        "routeKey": route["RouteKey"],
        "stage": invocation.stage_name,
        "time": now.strftime("%d/%b/%Y:%H:%M:%S %z"),
        "timeEpoch": int(now.timestamp() * 1000),
    }
    if authorization is not None:
        request_context["authorizer"] = {
            "jwt": {
                "claims": _event_claims(authorization.claims),
                "scopes": list(authorization.scopes),
            }
        }
    event: dict[str, Any] = {
        "version": "2.0",
        "routeKey": route["RouteKey"],
        "rawPath": invocation.path,
        "rawQueryString": request.query_string.decode("latin-1"),
        "headers": headers,
        "queryStringParameters": query or None,
        "pathParameters": copy.deepcopy(path_parameters) or None,
        "requestContext": request_context,
        "body": body,
        "isBase64Encoded": is_base64_encoded,
        "stageVariables": copy.deepcopy(
            invocation.api.stages[invocation.stage_name].properties.get("StageVariables", {})
        ),
    }
    if cookies := request.headers.getlist("Cookie"):
        event["cookies"] = cookies
    return event


def _lambda_response(payload: bytes) -> Response:
    if not isinstance(payload, bytes) or len(payload) > _MAX_LAMBDA_RESPONSE_BYTES:
        return _json_response(502, {"message": "Internal Server Error"})
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _json_response(502, {"message": "Internal Server Error"})
    if not isinstance(value, dict) or not set(value) <= {
        "body",
        "cookies",
        "headers",
        "isBase64Encoded",
        "statusCode",
    }:
        return _json_response(502, {"message": "Internal Server Error"})
    status = value.get("statusCode", 200)
    headers = value.get("headers", {})
    body = value.get("body", "")
    encoded = value.get("isBase64Encoded", False)
    cookies = value.get("cookies", [])
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or not 100 <= status <= 599
        or not isinstance(headers, dict)
        or not all(_valid_header(key, item) for key, item in headers.items())
        or not isinstance(body, str)
        or not isinstance(encoded, bool)
        or not isinstance(cookies, list)
        or not all(_valid_header("set-cookie", item) for item in cookies)
    ):
        return _json_response(502, {"message": "Internal Server Error"})
    if encoded:
        try:
            content = base64.b64decode(body, validate=True)
            if base64.b64encode(content).decode() != body:
                raise ValueError
        except (ValueError, TypeError):
            return _json_response(502, {"message": "Internal Server Error"})
    else:
        content = body.encode()
    response = Response(content, status=status)
    for key, item in headers.items():
        if key.lower() not in _HOP_BY_HOP_HEADERS:
            response.headers[key] = item
    for cookie in cookies:
        response.headers.add("Set-Cookie", cookie)
    return response


def _event_claims(claims: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in claims.items():
        if isinstance(value, str):
            result[key] = value
        elif isinstance(value, bool):
            result[key] = "true" if value else "false"
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            result[key] = str(value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            result[key] = f"[{' '.join(value)}]"
        else:
            result[key] = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return result


def _valid_header(key: Any, value: Any) -> bool:
    return (
        isinstance(key, str)
        and bool(key)
        and "\r" not in key
        and "\n" not in key
        and isinstance(value, str)
        and "\r" not in value
        and "\n" not in value
    )


def _invoke_local_lambda(function_arn: str, event: bytes, source_arn: str) -> bytes:
    from localstack.services.apigateway.next_gen.execute_api.integrations.aws import (
        RestApiAwsProxyIntegration,
    )

    statements = _function_policy_statements(function_arn)
    if not _lambda_policy_allows(statements, function_arn, source_arn):
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Invalid permissions on Lambda function",
                }
            },
            "Invoke",
        )
    return RestApiAwsProxyIntegration.call_lambda(
        function_arn=function_arn,
        event=event,
        source_arn=source_arn,
    )


def _function_policy_statements(function_arn: str) -> tuple[dict[str, Any], ...]:
    from localstack.services.lambda_.invocation.models import lambda_stores
    from localstack.utils.aws.arns import parse_arn

    try:
        parsed = parse_arn(function_arn)
    except ValueError:
        return ()
    if parsed.get("service") != "lambda" or not parsed.get("resource", "").startswith("function:"):
        return ()
    resource_parts = parsed["resource"].split(":", 2)
    if len(resource_parts) < 2 or not resource_parts[1]:
        return ()
    function_name = resource_parts[1]
    qualifier = resource_parts[2] if len(resource_parts) == 3 else "$LATEST"
    store = lambda_stores[parsed["account"]][parsed["region"]]
    function = store.functions.get(function_name)
    if function is None or (policy := function.permissions.get(qualifier)) is None:
        return ()
    return tuple(copy.deepcopy(policy.policy.Statement))


def _lambda_policy_allows(
    statements: tuple[dict[str, Any], ...], function_arn: str, source_arn: str
) -> bool:
    matching_effects = {
        statement.get("Effect")
        for statement in statements
        if _lambda_statement_matches(statement, function_arn, source_arn)
    }
    return "Allow" in matching_effects and "Deny" not in matching_effects


def _lambda_statement_matches(
    statement: dict[str, Any], function_arn: str, source_arn: str
) -> bool:
    if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
        return False
    principal = statement.get("Principal")
    if principal != "*":
        services = principal.get("Service") if isinstance(principal, dict) else None
        services = [services] if isinstance(services, str) else services
        if not isinstance(services, list) or "apigateway.amazonaws.com" not in services:
            return False
    actions = statement.get("Action")
    actions = [actions] if isinstance(actions, str) else actions
    if not isinstance(actions, list) or not any(
        isinstance(action, str) and action.lower() in {"lambda:invokefunction", "lambda:*", "*"}
        for action in actions
    ):
        return False
    resources = statement.get("Resource")
    resources = [resources] if isinstance(resources, str) else resources
    if not isinstance(resources, list) or not any(
        isinstance(resource, str) and fnmatch.fnmatchcase(function_arn, resource)
        for resource in resources
    ):
        return False
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict) or not set(condition) <= {
        "ArnEquals",
        "ArnLike",
        "StringEquals",
    }:
        return False
    for operator, clauses in condition.items():
        if not isinstance(clauses, dict):
            return False
        for key, expected in clauses.items():
            values = [expected] if isinstance(expected, str) else expected
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                return False
            if key.lower() == "aws:sourcearn" and operator in {"ArnEquals", "ArnLike"}:
                matches = (
                    source_arn in values
                    if operator == "ArnEquals"
                    else any(fnmatch.fnmatchcase(source_arn, item) for item in values)
                )
                if not matches:
                    return False
            elif key.lower() == "aws:sourceaccount" and operator == "StringEquals":
                source_account = source_arn.split(":", 5)[4]
                if source_account not in values:
                    return False
            else:
                return False
    return True


def _preflight_response(request: Request, api_properties: dict[str, Any]) -> Response | None:
    cors = api_properties.get("CorsConfiguration")
    if not cors or request.method != "OPTIONS":
        return None
    origin = request.headers.get("Origin")
    requested_method = request.headers.get("Access-Control-Request-Method")
    if not origin or not requested_method:
        return None
    response = Response(status=204)
    if not _set_cors_headers(response, cors, origin, requested_method):
        return _json_response(403, {"message": "Forbidden"})
    requested_headers = {
        item.strip().lower()
        for item in request.headers.get("Access-Control-Request-Headers", "").split(",")
        if item.strip()
    }
    allowed_headers = {item.lower() for item in cors.get("AllowHeaders", [])}
    if (
        requested_headers
        and "*" not in allowed_headers
        and not requested_headers <= allowed_headers
    ):
        return _json_response(403, {"message": "Forbidden"})
    return response


def _apply_cors(response: Response, request: Request, api_properties: dict[str, Any]) -> None:
    cors = api_properties.get("CorsConfiguration")
    origin = request.headers.get("Origin")
    if cors and origin:
        _set_cors_headers(response, cors, origin, request.method)


def _with_cors(response: Response, request: Request, api_properties: dict[str, Any]) -> Response:
    _apply_cors(response, request, api_properties)
    return response


def _set_cors_headers(response: Response, cors: dict[str, Any], origin: str, method: str) -> bool:
    origins = cors.get("AllowOrigins", [])
    methods = cors.get("AllowMethods", [])
    if origin not in origins and "*" not in origins:
        return False
    if method not in methods and "*" not in methods:
        return False
    response.headers["Access-Control-Allow-Origin"] = "*" if "*" in origins else origin
    if methods:
        response.headers["Access-Control-Allow-Methods"] = ",".join(methods)
    if headers := cors.get("AllowHeaders"):
        response.headers["Access-Control-Allow-Headers"] = ",".join(headers)
    if exposed := cors.get("ExposeHeaders"):
        response.headers["Access-Control-Expose-Headers"] = ",".join(exposed)
    if "MaxAge" in cors:
        response.headers["Access-Control-Max-Age"] = str(cors["MaxAge"])
    if cors.get("AllowCredentials"):
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return True


def _path(value: str) -> str:
    return f"/{value.lstrip('/')}" if value else "/"


def _json_response(status: int, value: dict[str, Any]) -> Response:
    response = Response(status=status)
    response.set_json(value)
    return response
