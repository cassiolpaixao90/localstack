import json
import pickle
import uuid
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import log_delivery
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.log_delivery import (
    CognitoIdpLogDeliveryProvider,
    cleanup_log_delivery,
    emit_auth_event,
    emit_notification_error,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.plugins import Service


class LogDeliveryProvider(CognitoIdpLogDeliveryProvider):
    service = "cognito-idp"


class FakeLogs:
    def __init__(self):
        self.groups = {}
        self.events = []
        self.streams = set()

    def describe_log_groups(self, *, logGroupNamePrefix, limit):
        return {
            "logGroups": [
                {"logGroupName": name, **configuration}
                for name, configuration in self.groups.items()
                if name.startswith(logGroupNamePrefix)
            ][:limit]
        }

    def create_log_stream(self, *, logGroupName, logStreamName):
        self.streams.add((logGroupName, logStreamName))

    def put_log_events(self, **request):
        self.events.append(request)


class FakeS3:
    def __init__(self, region="us-east-1", account_id=None):
        self.region = region
        self.account_id = account_id
        self.buckets = {"auth-events"}
        self.objects = []

    def head_bucket(self, *, Bucket, ExpectedBucketOwner):
        if Bucket not in self.buckets or (
            self.account_id is not None and ExpectedBucketOwner != self.account_id
        ):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "bucket owner mismatch"}},
                "HeadBucket",
            )

    def get_bucket_location(self, *, Bucket, ExpectedBucketOwner):
        return {"LocationConstraint": self.region}

    def put_object(self, **request):
        self.objects.append(request)


class FakeFirehose:
    def __init__(self, account_id, region):
        self.account_id = account_id
        self.region = region
        self.records = []

    def describe_delivery_stream(self, *, DeliveryStreamName, Limit):
        return {
            "DeliveryStreamDescription": {
                "DeliveryStreamARN": (
                    f"arn:aws:firehose:{self.region}:{self.account_id}:"
                    f"deliverystream/{DeliveryStreamName}"
                )
            }
        }

    def put_record(self, **request):
        self.records.append(request)


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        region_bundle = cognito_idp_stores.get(value.account_id)
        if region_bundle is not None:
            for store in region_bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def pool(context):
    return CognitoIdpProvider().create_user_pool(context, {"PoolName": "log-delivery"})["UserPool"]


@pytest.fixture
def clients(context, monkeypatch):
    value = SimpleNamespace(
        logs=FakeLogs(),
        s3=FakeS3(account_id=context.account_id),
        firehose=FakeFirehose(context.account_id, context.region),
    )
    value.logs.groups["/aws/vendedlogs/cognito"] = {}
    monkeypatch.setattr(log_delivery, "_client_factory", lambda _context: value)
    return value


def cloudwatch(context):
    return {
        "EventSource": "userNotification",
        "LogLevel": "ERROR",
        "CloudWatchLogsConfiguration": {
            "LogGroupArn": (
                f"arn:aws:logs:{context.region}:{context.account_id}:"
                "log-group:/aws/vendedlogs/cognito"
            )
        },
    }


def s3():
    return {
        "EventSource": "userAuthEvents",
        "LogLevel": "INFO",
        "S3Configuration": {"BucketArn": "arn:aws:s3:::auth-events"},
    }


def test_handlers_register_only_two_log_delivery_operations():
    service = Service.for_provider(LogDeliveryProvider())

    assert set(service.skeleton.dispatch_table) == {
        "GetLogDeliveryConfiguration",
        "SetLogDeliveryConfiguration",
    }
    assert {
        "GetLogDeliveryConfiguration",
        "SetLogDeliveryConfiguration",
    } <= set(Service.for_provider(CognitoIdpProvider()).skeleton.dispatch_table)


def test_set_get_reset_roundtrip_is_immutable(context, pool, clients):
    provider = LogDeliveryProvider()
    request = {
        "UserPoolId": pool["Id"],
        "LogConfigurations": [cloudwatch(context), s3()],
    }

    created = provider.set_log_delivery_configuration(context, request)
    request["LogConfigurations"][0]["LogLevel"] = "INFO"
    returned = provider.get_log_delivery_configuration(context, {"UserPoolId": pool["Id"]})

    assert created == returned
    assert returned["LogDeliveryConfiguration"]["LogConfigurations"][0]["LogLevel"] == "ERROR"
    assert provider.set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": []}
    ) == {"LogDeliveryConfiguration": {"UserPoolId": pool["Id"], "LogConfigurations": []}}
    assert provider.get_log_delivery_configuration(context, {"UserPoolId": pool["Id"]}) == {
        "LogDeliveryConfiguration": {"UserPoolId": pool["Id"], "LogConfigurations": []}
    }


@pytest.mark.parametrize(
    "configurations",
    [
        [s3(), s3()],
        [cloudwatch(SimpleNamespace(region="us-east-1", account_id="000000000000"))] * 3,
        [
            {
                "EventSource": "userNotification",
                "LogLevel": "ERROR",
                "S3Configuration": {"BucketArn": "arn:aws:s3:::auth-events"},
            }
        ],
        [
            {
                "EventSource": "userAuthEvents",
                "LogLevel": "ERROR",
                "S3Configuration": {"BucketArn": "arn:aws:s3:::auth-events"},
            }
        ],
        [
            {
                "EventSource": "userAuthEvents",
                "LogLevel": "INFO",
                "S3Configuration": {"BucketArn": "arn:aws:s3:::auth-events"},
                "FirehoseConfiguration": {
                    "StreamArn": "arn:aws:firehose:us-east-1:000000000000:deliverystream/a"
                },
            }
        ],
    ],
)
def test_configuration_shape_fails_closed(context, pool, clients, configurations):
    with pytest.raises(CommonServiceException) as error:
        LogDeliveryProvider().set_log_delivery_configuration(
            context, {"UserPoolId": pool["Id"], "LogConfigurations": configurations}
        )

    assert error.value.code == "InvalidParameterException"


def test_destination_account_region_resource_and_kms_are_validated(context, pool, clients):
    provider = LogDeliveryProvider()
    configuration = cloudwatch(context)
    configuration["CloudWatchLogsConfiguration"]["LogGroupArn"] = (
        f"arn:aws:logs:{context.region}:999999999999:log-group:/aws/vendedlogs/cognito"
    )
    with pytest.raises(CommonServiceException):
        provider.set_log_delivery_configuration(
            context, {"UserPoolId": pool["Id"], "LogConfigurations": [configuration]}
        )

    clients.logs.groups["/aws/vendedlogs/cognito"] = {"kmsKeyId": "arn:aws:kms:..."}
    with pytest.raises(CommonServiceException, match="KMS-encrypted"):
        provider.set_log_delivery_configuration(
            context,
            {"UserPoolId": pool["Id"], "LogConfigurations": [cloudwatch(context)]},
        )
    clients.logs.groups["/aws/vendedlogs/cognito"] = {}
    clients.s3.region = "eu-west-1"
    with pytest.raises(CommonServiceException, match="user-pool region"):
        provider.set_log_delivery_configuration(
            context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
        )
    clients.s3.region = context.region
    clients.s3.account_id = "999999999999"
    with pytest.raises(CommonServiceException, match="unavailable"):
        provider.set_log_delivery_configuration(
            context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
        )


def test_configuration_is_account_region_isolated_and_cleanup_is_scoped(context, pool, clients):
    provider = LogDeliveryProvider()
    provider.set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
    )
    other = RequestContext(None)
    other.account_id = context.account_id
    other.region = "eu-west-1"
    with pytest.raises(CommonServiceException) as error:
        provider.get_log_delivery_configuration(other, {"UserPoolId": pool["Id"]})
    assert error.value.code == "ResourceNotFoundException"

    cleanup_log_delivery(pool["Id"], account_id=context.account_id, region=context.region)
    assert (
        provider.get_log_delivery_configuration(context, {"UserPoolId": pool["Id"]})[
            "LogDeliveryConfiguration"
        ]["LogConfigurations"]
        == []
    )


def test_set_rechecks_pool_after_destination_validation_without_orphaning_state(
    context, pool, clients, monkeypatch
):
    provider = LogDeliveryProvider()

    def delete_during_validation(_context, _configuration):
        with cognito_idp_stores.lock:
            store = cognito_idp_stores[context.account_id][context.region]
            store.user_pools.pop(pool["Id"])
            store.POOL_LOCATIONS.pop(pool["Id"], None)

    monkeypatch.setattr(log_delivery, "_validate_destination", delete_during_validation)

    with pytest.raises(CommonServiceException) as error:
        provider.set_log_delivery_configuration(
            context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
        )

    assert error.value.code == "ResourceNotFoundException"
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert pool["Id"] not in store.log_delivery_configurations


def test_configuration_survives_store_serialization_and_delete_pool_cleans_it(
    context, pool, clients
):
    native = CognitoIdpProvider()
    LogDeliveryProvider().set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
    )

    restored = pickle.loads(pickle.dumps(native.get_store(context)))
    assert restored.log_delivery_configurations[pool["Id"]] == [s3()]

    native.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    assert pool["Id"] not in native.get_store(context).log_delivery_configurations


def test_auth_event_recorder_invokes_configured_exporter(context, pool, clients):
    native = CognitoIdpProvider()
    client = native.create_user_pool_client(
        context, {"UserPoolId": pool["Id"], "ClientName": "auth-events"}
    )["UserPoolClient"]
    LogDeliveryProvider().set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
    )
    store = native.get_store(context)

    provider_module._record_auth_event(
        context,
        store,
        store.user_pools[pool["Id"]],
        store.user_pools[pool["Id"]].clients[client["ClientId"]],
        "member",
        True,
        {},
        "Low",
        "NoRisk",
        False,
    )

    assert len(clients.s3.objects) == 1
    payload = json.loads(clients.s3.objects[0]["Body"])
    assert payload["event"]["username"] == "member"


def test_emitters_deliver_bounded_json_to_cloudwatch_and_s3(context, pool, clients):
    provider = LogDeliveryProvider()
    provider.set_log_delivery_configuration(
        context,
        {"UserPoolId": pool["Id"], "LogConfigurations": [cloudwatch(context), s3()]},
    )

    emit_notification_error(context, pool["Id"], {"error": "delivery failed"})
    emit_auth_event(
        context,
        {"pool_id": pool["Id"], "username": "member", "event_response": "Pass"},
    )

    assert len(clients.logs.events) == 1
    log_message = json.loads(clients.logs.events[0]["logEvents"][0]["message"])
    assert log_message["eventSource"] == "userNotification"
    assert len(clients.s3.objects) == 1
    s3_message = json.loads(clients.s3.objects[0]["Body"])
    assert s3_message["eventSource"] == "userAuthEvents"
    assert s3_message["event"]["username"] == "member"


def test_delivery_failure_and_oversized_event_never_cascade(context, pool, clients, caplog):
    LogDeliveryProvider().set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
    )
    clients.s3.put_object = lambda **_request: (_ for _ in ()).throw(RuntimeError("secret"))

    emit_auth_event(context, {"pool_id": pool["Id"], "value": "x"})
    emit_auth_event(context, {"pool_id": pool["Id"], "value": "x" * (300 * 1024)})

    assert "RuntimeError" in caplog.text
    assert "secret" not in caplog.text
    assert "exceeded size bound" not in caplog.text


def test_delivery_retries_once_with_the_same_idempotent_s3_key(context, pool, clients):
    LogDeliveryProvider().set_log_delivery_configuration(
        context, {"UserPoolId": pool["Id"], "LogConfigurations": [s3()]}
    )
    original = clients.s3.put_object
    requests = []

    def transient(**request):
        requests.append(request)
        if len(requests) == 1:
            raise RuntimeError("transient")
        original(**request)

    clients.s3.put_object = transient
    emit_auth_event(context, {"pool_id": pool["Id"], "value": "bounded"})

    assert len(requests) == 2
    assert requests[0]["Key"] == requests[1]["Key"]
    assert len(clients.s3.objects) == 1
