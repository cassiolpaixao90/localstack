"""Native Cognito user-pool log delivery configuration and local exporters."""

import copy
import dataclasses
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.aws.connect import connect_to
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)

_DESTINATION_FIELDS = (
    "CloudWatchLogsConfiguration",
    "FirehoseConfiguration",
    "S3Configuration",
)
_MAX_CONFIGURATIONS = 2
_MAX_DELIVERY_BYTES = 256 * 1024
_DELIVERY_LOCK = threading.RLock()


def _error(code: str, message: str) -> None:
    raise CommonServiceException(code, message, status_code=400, sender_fault=True)


def _client_factory(context: RequestContext):
    return connect_to(aws_access_key_id=context.account_id, region_name=context.region)


def _pool_id(request: ServiceRequest) -> str:
    value = request.get("UserPoolId")
    if not isinstance(value, str) or not 1 <= len(value) <= 55 or "_" not in value:
        _error("InvalidParameterException", "Invalid UserPoolId")
    return value


def _require_pool(context: RequestContext, pool_id: str) -> None:
    with cognito_idp_stores.lock:
        if pool_id not in cognito_idp_stores[context.account_id][context.region].user_pools:
            _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")


def _arn(value: Any, *, service: str, account_id: str, region: str) -> dict[str, str]:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048:
        _error("InvalidParameterException", f"Invalid {service} destination ARN")
    try:
        parsed = parse_arn(value)
    except (KeyError, TypeError, ValueError):
        _error("InvalidParameterException", f"Invalid {service} destination ARN")
    if parsed["service"] != service:
        _error("InvalidParameterException", f"Destination must be an {service} ARN")
    if service != "s3" and (parsed["account"] != account_id or parsed["region"] != region):
        _error(
            "InvalidParameterException", "Destination must be in the user-pool account and region"
        )
    return parsed


def _configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value) <= {
        "EventSource",
        "LogLevel",
        *_DESTINATION_FIELDS,
    }:
        _error("InvalidParameterException", "Invalid log configuration shape")
    event_source = value.get("EventSource")
    log_level = value.get("LogLevel")
    destinations = [field for field in _DESTINATION_FIELDS if field in value]
    if len(destinations) != 1:
        _error("InvalidParameterException", "Each log configuration requires one destination")
    destination = destinations[0]
    if event_source == "userNotification":
        if log_level != "ERROR" or destination != "CloudWatchLogsConfiguration":
            _error(
                "InvalidParameterException",
                "userNotification requires ERROR delivery to CloudWatch Logs",
            )
    elif event_source == "userAuthEvents":
        if log_level != "INFO":
            _error("InvalidParameterException", "userAuthEvents requires INFO delivery")
    else:
        _error("InvalidParameterException", "Invalid EventSource")
    nested = value[destination]
    expected_key = {
        "CloudWatchLogsConfiguration": "LogGroupArn",
        "FirehoseConfiguration": "StreamArn",
        "S3Configuration": "BucketArn",
    }[destination]
    if not isinstance(nested, dict) or set(nested) != {expected_key}:
        _error("InvalidParameterException", f"Invalid {destination}")
    return copy.deepcopy(value)


def _log_group_name(resource: str) -> str:
    prefix = "log-group:"
    if not resource.startswith(prefix):
        _error("InvalidParameterException", "Invalid CloudWatch Logs group ARN")
    name = resource[len(prefix) :]
    if name.endswith(":*"):
        name = name[:-2]
    if not 1 <= len(name) <= 512:
        _error("InvalidParameterException", "Invalid CloudWatch Logs group ARN")
    return name


def _validate_cloudwatch(context: RequestContext, arn: Any) -> None:
    parsed = _arn(arn, service="logs", account_id=context.account_id, region=context.region)
    name = _log_group_name(parsed["resource"])
    try:
        groups = (
            _client_factory(context)
            .logs.describe_log_groups(logGroupNamePrefix=name, limit=2)
            .get("logGroups", [])
        )
    except (BotoCoreError, ClientError):
        _error("InvalidParameterException", "CloudWatch Logs group is unavailable")
    group = next((item for item in groups if item.get("logGroupName") == name), None)
    if group is None:
        _error("InvalidParameterException", "CloudWatch Logs group does not exist")
    if group.get("kmsKeyId"):
        _error("InvalidParameterException", "KMS-encrypted log groups are not supported by Cognito")


def _validate_s3(context: RequestContext, arn: Any) -> None:
    parsed = _arn(arn, service="s3", account_id=context.account_id, region=context.region)
    resource = parsed["resource"]
    if not resource or "/" in resource or ":" in resource:
        _error("InvalidParameterException", "S3 destination must be a bucket ARN")
    client = _client_factory(context).s3
    try:
        client.head_bucket(Bucket=resource, ExpectedBucketOwner=context.account_id)
        location = (
            client.get_bucket_location(Bucket=resource, ExpectedBucketOwner=context.account_id).get(
                "LocationConstraint"
            )
            or "us-east-1"
        )
    except (BotoCoreError, ClientError):
        _error("InvalidParameterException", "S3 destination bucket is unavailable")
    if location != context.region:
        _error("InvalidParameterException", "S3 destination must be in the user-pool region")


def _validate_firehose(context: RequestContext, arn: Any) -> None:
    parsed = _arn(arn, service="firehose", account_id=context.account_id, region=context.region)
    prefix = "deliverystream/"
    if not parsed["resource"].startswith(prefix):
        _error("InvalidParameterException", "Invalid Firehose stream ARN")
    name = parsed["resource"][len(prefix) :]
    try:
        description = _client_factory(context).firehose.describe_delivery_stream(
            DeliveryStreamName=name, Limit=1
        )["DeliveryStreamDescription"]
    except (BotoCoreError, ClientError):
        _error("InvalidParameterException", "Firehose destination stream is unavailable")
    if description.get("DeliveryStreamARN") != arn:
        _error("InvalidParameterException", "Firehose destination stream ARN mismatch")


def _validate_destination(context: RequestContext, configuration: dict[str, Any]) -> None:
    if nested := configuration.get("CloudWatchLogsConfiguration"):
        _validate_cloudwatch(context, nested["LogGroupArn"])
    elif nested := configuration.get("S3Configuration"):
        _validate_s3(context, nested["BucketArn"])
    else:
        _validate_firehose(context, configuration["FirehoseConfiguration"]["StreamArn"])


class CognitoIdpLogDeliveryProvider:
    """Mixin for the two native Cognito log-delivery control-plane handlers."""

    @handler("GetLogDeliveryConfiguration", expand=False)
    def get_log_delivery_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        if set(request) != {"UserPoolId"}:
            _error("InvalidParameterException", "Unsupported request fields")
        pool_id = _pool_id(request)
        with cognito_idp_stores.lock:
            store = cognito_idp_stores[context.account_id][context.region]
            if pool_id not in store.user_pools:
                _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
            configurations = copy.deepcopy(store.log_delivery_configurations.get(pool_id, []))
        return {
            "LogDeliveryConfiguration": {
                "UserPoolId": pool_id,
                "LogConfigurations": configurations,
            }
        }

    @handler("SetLogDeliveryConfiguration", expand=False)
    def set_log_delivery_configuration(
        self, context: RequestContext, request: ServiceRequest
    ) -> ServiceResponse:
        if set(request) != {"UserPoolId", "LogConfigurations"}:
            _error("InvalidParameterException", "Unsupported request fields")
        pool_id = _pool_id(request)
        _require_pool(context, pool_id)
        raw = request.get("LogConfigurations")
        if not isinstance(raw, list) or len(raw) > _MAX_CONFIGURATIONS:
            _error("InvalidParameterException", "LogConfigurations must contain at most 2 items")
        configurations = [_configuration(value) for value in raw]
        sources = [value["EventSource"] for value in configurations]
        if len(sources) != len(set(sources)):
            _error("InvalidParameterException", "EventSource must be unique")
        for configuration in configurations:
            _validate_destination(context, configuration)
        with cognito_idp_stores.lock:
            store = cognito_idp_stores[context.account_id][context.region]
            if pool_id not in store.user_pools:
                _error("ResourceNotFoundException", f"User pool {pool_id} does not exist")
            if configurations:
                store.log_delivery_configurations[pool_id] = copy.deepcopy(configurations)
            else:
                store.log_delivery_configurations.pop(pool_id, None)
        return {
            "LogDeliveryConfiguration": {
                "UserPoolId": pool_id,
                "LogConfigurations": copy.deepcopy(configurations),
            }
        }


def cleanup_log_delivery(pool_id: str, *, account_id: str, region: str) -> None:
    with cognito_idp_stores.lock:
        cognito_idp_stores[account_id][region].log_delivery_configurations.pop(pool_id, None)


def _event_payload(event_source: str, pool_id: str, event: Any) -> bytes:
    if dataclasses.is_dataclass(event):
        value = dataclasses.asdict(event)
    elif isinstance(event, dict):
        value = copy.deepcopy(event)
    else:
        value = {"message": str(event)[:4096]}
    envelope = {
        "eventSource": event_source,
        "userPoolId": pool_id,
        "event": value,
    }
    body = json.dumps(envelope, default=str, separators=(",", ":"), sort_keys=True).encode()
    if len(body) > _MAX_DELIVERY_BYTES:
        raise ValueError("Cognito log delivery event exceeded size bound")
    return body


def _deliver(context: RequestContext, pool_id: str, event_source: str, event: Any) -> None:
    with cognito_idp_stores.lock:
        configurations = copy.deepcopy(
            cognito_idp_stores[context.account_id][context.region].log_delivery_configurations.get(
                pool_id, []
            )
        )
    configuration = next(
        (value for value in configurations if value["EventSource"] == event_source), None
    )
    if configuration is None:
        return
    object_key = f"AWSLogs/{context.account_id}/Cognito/{pool_id}/{uuid.uuid4()}.json"
    error: Exception | None = None
    for _attempt in range(2):
        try:
            _deliver_once(context, pool_id, event_source, event, configuration, object_key)
            return
        except Exception as current_error:
            error = current_error
    LOG.warning(
        "Cognito %s log delivery failed for pool %s after bounded retry: %s",
        event_source,
        pool_id,
        type(error).__name__,
    )


def _deliver_once(
    context: RequestContext,
    pool_id: str,
    event_source: str,
    event: Any,
    configuration: dict[str, Any],
    object_key: str,
) -> None:
    body = _event_payload(event_source, pool_id, event)
    factory = _client_factory(context)
    if nested := configuration.get("CloudWatchLogsConfiguration"):
        parsed = parse_arn(nested["LogGroupArn"])
        group = _log_group_name(parsed["resource"])
        stream = f"cognito/{pool_id}/{event_source}"
        with _DELIVERY_LOCK:
            try:
                factory.logs.create_log_stream(logGroupName=group, logStreamName=stream)
            except Exception as error:
                if "ResourceAlreadyExists" not in type(error).__name__:
                    raise
            factory.logs.put_log_events(
                logGroupName=group,
                logStreamName=stream,
                logEvents=[
                    {
                        "timestamp": int(datetime.now(UTC).timestamp() * 1000),
                        "message": body.decode(),
                    }
                ],
            )
    elif nested := configuration.get("S3Configuration"):
        bucket = parse_arn(nested["BucketArn"])["resource"]
        factory.s3.put_object(
            Bucket=bucket,
            Key=object_key,
            Body=body,
            ContentType="application/json",
            ExpectedBucketOwner=context.account_id,
        )
    else:
        arn = configuration["FirehoseConfiguration"]["StreamArn"]
        name = parse_arn(arn)["resource"].removeprefix("deliverystream/")
        factory.firehose.put_record(DeliveryStreamName=name, Record={"Data": body + b"\n"})


def emit_auth_event(context: RequestContext, event: Any) -> None:
    pool_id = event.pool_id if dataclasses.is_dataclass(event) else event.get("pool_id")
    if isinstance(pool_id, str):
        _deliver(context, pool_id, "userAuthEvents", event)


def emit_notification_error(context: RequestContext, pool_id: str, event: Any) -> None:
    _deliver(context, pool_id, "userNotification", event)
