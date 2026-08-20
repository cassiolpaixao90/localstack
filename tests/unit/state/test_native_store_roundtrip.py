from localstack.aws.api.cloudformation import StackStatus
from localstack.aws.api.lambda_ import Architecture, PackageType, Runtime, State, TracingMode
from localstack.aws.api.sqs import Message
from localstack.services.cloudformation.stores import CloudFormationStore
from localstack.services.cloudformation.v2.entities import Stack as StackV2
from localstack.services.dynamodb.models import DynamoDBStore
from localstack.services.lambda_.invocation.lambda_models import (
    Function,
    FunctionVersion,
    LambdaEphemeralStorage,
    S3Code,
    VersionFunctionConfiguration,
    VersionIdentifier,
    VersionState,
)
from localstack.services.lambda_.invocation.models import LambdaStore
from localstack.services.sns.models import SnsStore
from localstack.services.sqs.models import FifoQueue, SqsStore, StandardQueue
from localstack.services.stores import AccountRegionBundle
from localstack.state.service_persistence import load_service_snapshots, save_service_snapshots

ACCOUNT_ID = "000000000000"
REGION_NAME = "us-east-1"


def test_sqs_snapshot_roundtrip_preserves_standard_and_fifo_queues(tmp_path):
    source = AccountRegionBundle("sqs", SqsStore)
    store = source[ACCOUNT_ID][REGION_NAME]
    standard = StandardQueue("standard-queue", REGION_NAME, ACCOUNT_ID)
    standard.put(Message(Body="hello-standard", MessageId="message-1"))
    fifo = FifoQueue("fifo-queue.fifo", REGION_NAME, ACCOUNT_ID)
    fifo.put(
        Message(Body="hello-fifo", MessageId="message-2"),
        message_group_id="group-1",
        message_deduplication_id="dedup-1",
    )
    store.queues[standard.name] = standard
    store.queues[fifo.name] = fifo
    target = AccountRegionBundle("sqs", SqsStore)

    save_service_snapshots(tmp_path, {"sqs": source})
    load_service_snapshots(tmp_path, {"sqs": target})

    restored_store = target[ACCOUNT_ID][REGION_NAME]
    assert restored_store._universal is target._universal
    assert target[ACCOUNT_ID].lock is target.lock
    restored_standard = restored_store.queues["standard-queue"]
    assert restored_standard.approximate_number_of_messages == 1
    assert restored_standard.visible.queue[0].message["Body"] == "hello-standard"
    assert restored_standard.visible.is_shutdown is False
    restored_fifo = restored_store.queues["fifo-queue.fifo"]
    assert restored_fifo.approximate_number_of_messages == 1
    assert restored_fifo.message_groups["group-1"].messages[0].message["Body"] == "hello-fifo"
    assert restored_fifo.message_group_queue.is_shutdown is False


def test_sns_snapshot_roundtrip_preserves_topic_and_subscription(tmp_path):
    source = AccountRegionBundle("sns", SnsStore)
    store = source[ACCOUNT_ID][REGION_NAME]
    topic_arn = f"arn:aws:sns:{REGION_NAME}:{ACCOUNT_ID}:topic-1"
    subscription_arn = f"{topic_arn}:subscription-1"
    store.topics[topic_arn] = {
        "arn": topic_arn,
        "name": "topic-1",
        "attributes": {"DisplayName": "topic one"},
        "data_protection_policy": None,
        "subscriptions": [subscription_arn],
    }
    store.subscriptions[subscription_arn] = {
        "TopicArn": topic_arn,
        "Endpoint": "http://localhost:1111/endpoint",
        "Protocol": "http",
        "SubscriptionArn": subscription_arn,
        "PendingConfirmation": "false",
        "Owner": ACCOUNT_ID,
    }
    target = AccountRegionBundle("sns", SnsStore)

    save_service_snapshots(tmp_path, {"sns": source})
    load_service_snapshots(tmp_path, {"sns": target})

    restored_store = target[ACCOUNT_ID][REGION_NAME]
    assert restored_store._universal is target._universal
    assert target[ACCOUNT_ID].lock is target.lock
    assert restored_store.topics[topic_arn] == store.topics[topic_arn]
    assert restored_store.subscriptions[subscription_arn] == store.subscriptions[subscription_arn]


def test_cloudformation_snapshot_roundtrip_preserves_v2_stack(tmp_path):
    source = AccountRegionBundle("cloudformation", CloudFormationStore)
    store = source[ACCOUNT_ID][REGION_NAME]
    stack = StackV2(
        account_id=ACCOUNT_ID,
        region_name=REGION_NAME,
        request_payload={"StackName": "stack-1", "TemplateBody": '{"Resources": {}}'},
    )
    stack.set_stack_status(StackStatus.CREATE_COMPLETE)
    store.stacks_v2[stack.stack_id] = stack
    target = AccountRegionBundle("cloudformation", CloudFormationStore)

    save_service_snapshots(tmp_path, {"cloudformation": source})
    load_service_snapshots(tmp_path, {"cloudformation": target})

    restored_store = target[ACCOUNT_ID][REGION_NAME]
    assert restored_store._universal is target._universal
    assert target[ACCOUNT_ID].lock is target.lock
    restored = restored_store.stacks_v2[stack.stack_id]
    assert restored.stack_name == "stack-1"
    assert restored.status == StackStatus.CREATE_COMPLETE
    assert restored.stack_id == stack.stack_id


def test_lambda_snapshot_roundtrip_preserves_function_with_s3_code(tmp_path):
    source = AccountRegionBundle("lambda", LambdaStore)
    store = source[ACCOUNT_ID][REGION_NAME]
    code = S3Code(
        id="code-1",
        account_id=ACCOUNT_ID,
        s3_bucket=f"awslambda-{REGION_NAME}-tasks",
        s3_key="snapshots/function-1.zip",
        s3_object_version=None,
        code_sha256="a" * 64,
        code_size=42,
    )
    version_id = VersionIdentifier(
        function_name="function-1", qualifier="$LATEST", region=REGION_NAME, account=ACCOUNT_ID
    )
    config = VersionFunctionConfiguration(
        description="roundtrip function",
        role=f"arn:aws:iam::{ACCOUNT_ID}:role/role-1",
        timeout=3,
        runtime=Runtime.python3_12,
        memory_size=128,
        handler="index.handler",
        package_type=PackageType.Zip,
        environment={"KEY": "value"},
        architectures=[Architecture.x86_64],
        internal_revision="revision-1",
        ephemeral_storage=LambdaEphemeralStorage(size=512),
        snap_start=None,
        tracing_config_mode=TracingMode.PassThrough,
        code=code,
        last_modified="2026-01-01T00:00:00.000000+0000",
        state=VersionState(state=State.Active),
    )
    function = Function(function_name="function-1")
    function.versions["$LATEST"] = FunctionVersion(id=version_id, config=config)
    store.functions["function-1"] = function
    target = AccountRegionBundle("lambda", LambdaStore)

    save_service_snapshots(tmp_path, {"lambda": source})
    load_service_snapshots(tmp_path, {"lambda": target})

    restored_store = target[ACCOUNT_ID][REGION_NAME]
    assert restored_store._universal is target._universal
    assert target[ACCOUNT_ID].lock is target.lock
    restored_function = restored_store.functions["function-1"]
    assert restored_function.function_name == "function-1"
    restored_version = restored_function.versions["$LATEST"]
    assert restored_version.id.qualified_arn() == version_id.qualified_arn()
    assert restored_version.config.state.state == State.Active
    assert restored_version.config.environment == {"KEY": "value"}
    restored_code = restored_version.config.code
    assert isinstance(restored_code, S3Code)
    assert restored_code.s3_bucket == f"awslambda-{REGION_NAME}-tasks"
    assert restored_code.s3_key == "snapshots/function-1.zip"
    assert restored_code.code_sha256 == "a" * 64
    assert restored_code.code_size == 42


def test_dynamodb_snapshot_roundtrip_preserves_table_definitions(tmp_path):
    source = AccountRegionBundle("dynamodb", DynamoDBStore)
    store = source[ACCOUNT_ID][REGION_NAME]
    table_name = "table-1"
    store.table_definitions[table_name] = {
        "TableName": table_name,
        "TableId": "table-id-1",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }
    store.TABLE_REGION[table_name] = REGION_NAME
    store.TABLE_TAGS[f"arn:aws:dynamodb:{REGION_NAME}:{ACCOUNT_ID}:table/{table_name}"] = {
        "owner": "roundtrip"
    }
    target = AccountRegionBundle("dynamodb", DynamoDBStore)

    save_service_snapshots(tmp_path, {"dynamodb": source})
    load_service_snapshots(tmp_path, {"dynamodb": target})

    restored_store = target[ACCOUNT_ID][REGION_NAME]
    assert restored_store._universal is target._universal
    assert target[ACCOUNT_ID].lock is target.lock
    restored = restored_store.table_definitions[table_name]
    assert restored["TableId"] == "table-id-1"
    assert restored["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]
    assert restored_store.TABLE_REGION[table_name] == REGION_NAME
    assert restored_store.TABLE_TAGS[
        f"arn:aws:dynamodb:{REGION_NAME}:{ACCOUNT_ID}:table/{table_name}"
    ] == {"owner": "roundtrip"}
