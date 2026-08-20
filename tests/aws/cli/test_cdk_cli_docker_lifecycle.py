import json
import logging
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import boto3
import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.cli.cdk import (
    build_cdk_environment,
    launch_cdk,
    probe_cdk_cli_version,
    probe_localstack_health,
)
from localstack.testing.pytest import markers
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import (
    PINNED_CDK_VERSION,
    PINNED_NODE_VERSION,
    TOOLCHAIN_ROOT,
    CdkRuntime,
    _require,
)

LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_platform.py"
OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
CONTAINER_PATTERN = re.compile(r"^ls-cdk-docker-gate-[a-z0-9-]{1,80}$")
ENDPOINT_PATTERN = re.compile(
    r"^http://(?:localhost|127\.0\.0\.1|localhost\.localstack\.cloud):\d{2,5}$"
)
ID_PATTERN = re.compile(r"^[A-Za-z0-9_$-]{1,256}$")
LIST_DEADLINE_SECONDS = 10
RPC_CONFIG = Config(connect_timeout=2, read_timeout=10, retries={"total_max_attempts": 1})
EXPECTED_OUTPUT_KEYS = {
    "ApiEndpoint",
    "ApiId",
    "DeploymentAccount",
    "DeploymentId",
    "DeploymentRegion",
    "FunctionName",
    "QueueName",
    "QueueUrl",
    "StageName",
    "TableName",
    "TopicArn",
    "UserPoolClientId",
    "UserPoolId",
}
EXPECTED_STACK_RESOURCES = {
    "Deployment": "AWS::ApiGatewayV2::Deployment",
    "Handler886CB40B": "AWS::Lambda::Function",
    "HandlerServiceRoleDefaultPolicyCBD0CC91": "AWS::IAM::Policy",
    "HandlerServiceRoleFCDC14AE": "AWS::IAM::Role",
    "HttpApiF5A9A8A7": "AWS::ApiGatewayV2::Api",
    "HttpApiGETworkidF3D0EEA9": "AWS::ApiGatewayV2::Route",
    "HttpApiGETworkidLambdaIntegration2BE4F9C6": "AWS::ApiGatewayV2::Integration",
    "HttpApiGETworkidLambdaIntegrationPermissionF058F5C2": "AWS::Lambda::Permission",
    "Stage": "AWS::ApiGatewayV2::Stage",
    "UserPool6BA7E5F2": "AWS::Cognito::UserPool",
    "UserPoolUserPoolClient40176907": "AWS::Cognito::UserPoolClient",
    "WorkEvents7C5008F6": "AWS::SNS::Topic",
    "WorkQueue94013F35": "AWS::SQS::Queue",
    "WorkQueueEnterprisePlatformWorkEvents74BA77600534E08D": "AWS::SNS::Subscription",
    "WorkQueuePolicy1B56CCA8": "AWS::SQS::QueuePolicy",
    "WorkTableAAA68FEB": "AWS::DynamoDB::Table",
}


def _gate_configuration() -> tuple[str, str]:
    endpoint = os.environ.get("CDK_DOCKER_GATE_ENDPOINT", "")
    container = os.environ.get("CDK_DOCKER_GATE_CONTAINER", "")
    if not ENDPOINT_PATTERN.fullmatch(endpoint) or not CONTAINER_PATTERN.fullmatch(container):
        pytest.skip("explicit CDK docker gate endpoint and owned container are required")
    return endpoint, container


def _docker(*arguments: str) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0 or len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
        raise RuntimeError(result.stderr.decode(errors="replace")[:4096])
    return result.stdout.decode().strip()


def _wait_healthy(endpoint: str, timeout_seconds: float = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            response = requests.get(f"{endpoint}/_localstack/health", timeout=2)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise TimeoutError("CDK docker gate container did not become healthy")


def _clients(endpoint: str, region_name: str) -> dict:
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=region_name,
    )
    return {
        name: session.client(name, endpoint_url=endpoint, config=RPC_CONFIG)
        for name in (
            "apigatewayv2",
            "cloudformation",
            "cognito-idp",
            "dynamodb",
            "lambda",
            "sns",
            "sqs",
        )
    }


def _deadline() -> float:
    return time.monotonic() + LIST_DEADLINE_SECONDS


def _ensure_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("bounded resource inventory exceeded its deadline")


def _queue_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxResults": 1000}
        if token:
            parameters["NextToken"] = token
        response = client.list_queues(**parameters)
        result.update(response.get("QueueUrls", []))
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid SQS continuation token")
        seen.add(token)
    raise RuntimeError("SQS inventory exceeded the page bound")


def _topic_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {}
        if token:
            parameters["NextToken"] = token
        response = client.list_topics(**parameters)
        result.update(item["TopicArn"] for item in response.get("Topics", []))
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid SNS continuation token")
        seen.add(token)
    raise RuntimeError("SNS inventory exceeded the page bound")


def _table_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"Limit": 100}
        if token:
            parameters["ExclusiveStartTableName"] = token
        response = client.list_tables(**parameters)
        result.update(response.get("TableNames", []))
        token = response.get("LastEvaluatedTableName")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid DynamoDB continuation token")
        seen.add(token)
    raise RuntimeError("DynamoDB inventory exceeded the page bound")


def _function_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    marker = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxItems": 50}
        if marker:
            parameters["Marker"] = marker
        response = client.list_functions(**parameters)
        result.update(item["FunctionName"] for item in response.get("Functions", []))
        marker = response.get("NextMarker")
        if marker is None:
            return result
        if not isinstance(marker, str) or not marker or marker in seen:
            raise RuntimeError("invalid Lambda continuation marker")
        seen.add(marker)
    raise RuntimeError("Lambda inventory exceeded the page bound")


def _api_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxResults": "500"}
        if token:
            parameters["NextToken"] = token
        response = client.get_apis(**parameters)
        result.update(item["ApiId"] for item in response.get("Items", []))
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid API Gateway v2 continuation token")
        seen.add(token)
    raise RuntimeError("API Gateway v2 inventory exceeded the page bound")


def _pool_inventory(client, *, deadline: float) -> set[str]:
    result = set()
    token = None
    seen = set()
    for _ in range(16):
        _ensure_deadline(deadline)
        parameters = {"MaxResults": 60}
        if token:
            parameters["NextToken"] = token
        response = client.list_user_pools(**parameters)
        result.update(item["Id"] for item in response.get("UserPools", []))
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid Cognito continuation token")
        seen.add(token)
    raise RuntimeError("Cognito inventory exceeded the page bound")


def _inventories(clients: dict, *, deadline: float) -> dict[str, set[str]]:
    return {
        "apis": _api_inventory(clients["apigatewayv2"], deadline=deadline),
        "functions": _function_inventory(clients["lambda"], deadline=deadline),
        "pools": _pool_inventory(clients["cognito-idp"], deadline=deadline),
        "queues": _queue_inventory(clients["sqs"], deadline=deadline),
        "tables": _table_inventory(clients["dynamodb"], deadline=deadline),
        "topics": _topic_inventory(clients["sns"], deadline=deadline),
    }


def _stack_absent(cloudformation, stack_name: str) -> bool:
    try:
        cloudformation.describe_stacks(StackName=stack_name)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return False


def _stack_status(cloudformation, stack_name: str) -> str:
    return cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file() or not APP_PATH.is_file():
        raise ValueError("the pinned Python interpreter and platform fixture must be file-backed")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _load_outputs(path: Path, stack_name: str, account_id: str, region_name: str) -> dict:
    value = json.loads(read_regular_bounded(path, 64 * 1024))
    if not isinstance(value, dict) or set(value) != {stack_name}:
        raise ValueError("CDK output must contain exactly the owned stack")
    outputs = value[stack_name]
    if not isinstance(outputs, dict) or set(outputs) != EXPECTED_OUTPUT_KEYS:
        raise ValueError("CDK platform output contract is not closed")
    if outputs["DeploymentAccount"] != account_id or outputs["DeploymentRegion"] != region_name:
        raise ValueError("CDK output scope does not match the deployment")
    if any(not isinstance(item, str) or not item or len(item) > 2048 for item in outputs.values()):
        raise ValueError("CDK output contains an invalid value")
    return outputs


def _validated_stack(cloudformation, stack_name: str, owner_nonce: str, status: str) -> dict:
    stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    owner_values = [
        item.get("Value") for item in stack.get("Tags", []) if item.get("Key") == OWNER_TAG_KEY
    ]
    if stack.get("StackStatus") != status or owner_values != [owner_nonce]:
        raise RuntimeError("CloudFormation stack ownership or status validation failed")
    return stack


def _validated_resource_ids(cloudformation, stack_id: str) -> dict[str, str]:
    resources = cloudformation.describe_stack_resources(StackName=stack_id)["StackResources"]
    if len(resources) != len(EXPECTED_STACK_RESOURCES):
        raise RuntimeError("CloudFormation stack resource set is incomplete")
    result = {}
    for item in resources:
        logical_id = item.get("LogicalResourceId")
        physical_id = item.get("PhysicalResourceId")
        if (
            logical_id not in EXPECTED_STACK_RESOURCES
            or item.get("ResourceType") != EXPECTED_STACK_RESOURCES[logical_id]
            or not item.get("ResourceStatus", "").endswith("_COMPLETE")
            or not isinstance(physical_id, str)
            or not physical_id
            or logical_id in result
        ):
            raise RuntimeError("CloudFormation resource identity contract is invalid")
        result[logical_id] = physical_id
    if set(result) != set(EXPECTED_STACK_RESOURCES):
        raise RuntimeError("CloudFormation stack resource set is not exact")
    return result


def _queue_attributes(sqs, queue_url: str) -> dict[str, str]:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]


@dataclass(frozen=True)
class DockerGate:
    account_id: str
    clients: dict
    container: str
    endpoint: str
    owner_nonce: str
    prefix: str
    region_name: str
    runtime: CdkRuntime
    stack_name: str


@pytest.fixture
def docker_gate(tmp_path, account_id, region_name):
    endpoint, container = _gate_configuration()
    if os.name != "posix":
        pytest.skip("the CDK process-group supervisor requires POSIX")
    node = shutil.which("node")
    _require(node is not None, "the pinned Node executable is not installed", required=False)
    node = str(Path(node).resolve())
    node_version = launch_cdk(
        ["--version"],
        executable=node,
        environment={"PATH": str(Path(node).parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    expected_node_version = os.environ.get("CDK_EXPECTED_NODE_VERSION", PINNED_NODE_VERSION)
    _require(
        node_version.returncode == 0
        and not node_version.timed_out
        and node_version.stdout.decode().strip() == f"v{expected_node_version}",
        f"Node {expected_node_version} is required",
        required=False,
    )
    cdk_executable = (TOOLCHAIN_ROOT / "node_modules/aws-cdk/bin/cdk").resolve()
    _require(
        cdk_executable.is_file(),
        "run npm ci in tests/aws/cli before this gate",
        required=False,
    )
    home = tmp_path / "home"
    temporary = tmp_path / "tmp"
    workspace = tmp_path / "workspace"
    for directory in (home, temporary, workspace):
        directory.mkdir()
    environment = build_cdk_environment(
        {
            "HOME": str(home),
            "PATH": str(Path(node).parent),
            "TMPDIR": str(temporary),
        },
        endpoint_url=endpoint,
        region=region_name,
        account_id=account_id,
    )
    probe_localstack_health(endpoint, timeout_seconds=5)
    _require(
        probe_cdk_cli_version(str(cdk_executable), environment=environment, cwd=workspace)
        == PINNED_CDK_VERSION,
        f"CDK CLI {PINNED_CDK_VERSION} is required",
        required=False,
    )
    owner_nonce = secrets.token_hex(12)
    assert OWNER_PATTERN.fullmatch(owner_nonce)
    deployment = f"d{owner_nonce[:23]}"
    prefix = f"localstack-platform-{deployment}"
    yield DockerGate(
        account_id=account_id,
        clients=_clients(endpoint, region_name),
        container=container,
        endpoint=endpoint,
        owner_nonce=owner_nonce,
        prefix=prefix,
        region_name=region_name,
        runtime=CdkRuntime(
            executable=str(cdk_executable),
            environment=environment,
            workspace=workspace,
        ),
        stack_name=prefix,
    )


def _deploy(gate: DockerGate, visibility_timeout: str, output_path: Path | None = None):
    arguments = [
        "deploy",
        "EnterprisePlatform",
        "--app",
        _python_app_command(),
        "--context",
        f"deployment={gate.prefix.removeprefix('localstack-platform-')}",
        "--context",
        f"owner={gate.owner_nonce}",
        "--context",
        f"visibilityTimeout={visibility_timeout}",
        "--require-approval",
        "never",
        "--no-lookups",
        "--strict",
        "--no-version-reporting",
        "--no-path-metadata",
        "--no-asset-metadata",
        "--no-notices",
        "--no-color",
        "--ci",
        "--execute",
    ]
    if output_path is not None:
        arguments.extend(["--outputs-file", str(output_path)])
    result = launch_cdk(
        arguments,
        executable=gate.runtime.executable,
        environment=gate.runtime.environment,
        cwd=gate.runtime.workspace,
        timeout_seconds=600,
        max_output_bytes=256 * 1024,
    )
    assert not result.timed_out
    assert not result.stdout_truncated
    assert not result.stderr_truncated
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result


@markers.aws.only_localstack
def test_cdk_docker_full_lifecycle_with_restart(docker_gate: DockerGate, tmp_path):
    gate = docker_gate
    cloudformation = gate.clients["cloudformation"]
    baseline = _inventories(gate.clients, deadline=_deadline())
    if any(baseline.values()):
        raise RuntimeError("the CDK docker gate requires an isolated empty service volume")
    if not _stack_absent(cloudformation, gate.stack_name):
        raise RuntimeError("owned stack name collided before deployment")
    output_path = tmp_path / "platform-outputs.json"
    cleanup_errors = []
    try:
        # Phase 1: initial deploy with the real pinned CDK CLI against the container
        _deploy(gate, "30", output_path)
        outputs = _load_outputs(output_path, gate.stack_name, gate.account_id, gate.region_name)
        stack = _validated_stack(
            cloudformation, gate.stack_name, gate.owner_nonce, "CREATE_COMPLETE"
        )
        resource_ids = _validated_resource_ids(cloudformation, stack["StackId"])
        assert resource_ids["HttpApiF5A9A8A7"] == outputs["ApiId"]
        assert resource_ids["Handler886CB40B"] == outputs["FunctionName"]
        assert resource_ids["UserPool6BA7E5F2"] == outputs["UserPoolId"]
        assert resource_ids["UserPoolUserPoolClient40176907"] == outputs["UserPoolClientId"]
        assert ID_PATTERN.fullmatch(resource_ids["HttpApiGETworkidF3D0EEA9"])

        # Smoke: Lambda wiring, HTTP API route, SNS -> SQS subscription, queue attribute
        lambda_result = gate.clients["lambda"].invoke(FunctionName=outputs["FunctionName"])
        assert lambda_result["StatusCode"] == 200
        body = json.loads(json.loads(lambda_result["Payload"].read())["body"])
        assert body["queue"] == outputs["QueueName"]
        assert body["table"] == outputs["TableName"]
        assert body["topic"] == outputs["TopicArn"]
        assert _queue_attributes(gate.clients["sqs"], outputs["QueueUrl"]) == {
            "VisibilityTimeout": "30"
        }
        gate.clients["sns"].publish(TopicArn=outputs["TopicArn"], Message="probe-message")
        received = gate.clients["sqs"].receive_message(
            QueueUrl=outputs["QueueUrl"], WaitTimeSeconds=10
        )
        envelope = json.loads(received["Messages"][0]["Body"])
        assert envelope["Message"] == "probe-message"
        gate.clients["sqs"].delete_message(
            QueueUrl=outputs["QueueUrl"],
            ReceiptHandle=received["Messages"][0]["ReceiptHandle"],
        )
        http_response = requests.get(
            f"{gate.endpoint}/_aws/execute-api/{outputs['ApiId']}/$default/work/probe-1",
            timeout=30,
        )
        assert http_response.status_code == 200
        assert http_response.json()["queue"] == outputs["QueueName"]

        # Phase 2: no-op deploy leaves the stack untouched
        _deploy(gate, "30")
        assert _stack_status(cloudformation, gate.stack_name) == "CREATE_COMPLETE"

        # Phase 3: in-place update of the queue visibility timeout
        _deploy(gate, "60")
        assert _stack_status(cloudformation, gate.stack_name) == "UPDATE_COMPLETE"
        assert _queue_attributes(gate.clients["sqs"], outputs["QueueUrl"]) == {
            "VisibilityTimeout": "60"
        }

        # Phase 4: destroy through the real CDK CLI and prove zero residue. This must
        # precede the restart phase: CFN stack state does not survive a container
        # restart yet, so `cdk destroy` cannot track the stack afterwards.
        result = launch_cdk(
            [
                "destroy",
                "EnterprisePlatform",
                "--app",
                _python_app_command(),
                "--context",
                f"deployment={gate.prefix.removeprefix('localstack-platform-')}",
                "--context",
                f"owner={gate.owner_nonce}",
                "--context",
                "visibilityTimeout=60",
                "--force",
                "--no-version-reporting",
                "--no-notices",
                "--no-color",
                "--ci",
            ],
            executable=gate.runtime.executable,
            environment=gate.runtime.environment,
            cwd=gate.runtime.workspace,
            timeout_seconds=600,
            max_output_bytes=256 * 1024,
        )
        assert not result.timed_out
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert _stack_absent(cloudformation, gate.stack_name)
        residue_after_destroy = _inventories(gate.clients, deadline=_deadline())
        assert residue_after_destroy == baseline, f"destroy left residue: {residue_after_destroy}"

        # Phase 5: container restart keeps the fork-proven persistence surface
        # (Cognito user pools). SQS/SNS/Lambda/DynamoDB/CFN stack persistence across
        # restarts is tracked as backlog in docs/cdk-localstack-enterprise.md.
        probe_pool = gate.clients["cognito-idp"].create_user_pool(
            PoolName=f"{gate.prefix}-restart-probe",
            UserPoolTags={OWNER_TAG_KEY: gate.owner_nonce},
        )["UserPool"]
        container_id = _docker("inspect", "--format", "{{.Id}}", gate.container)
        _docker("stop", "--time", "15", gate.container)
        _docker("start", gate.container)
        _wait_healthy(gate.endpoint)
        assert _docker("inspect", "--format", "{{.Id}}", gate.container) == container_id
        assert probe_pool["Id"] in _pool_inventory(
            gate.clients["cognito-idp"], deadline=_deadline()
        )
        gate.clients["cognito-idp"].delete_user_pool(UserPoolId=probe_pool["Id"])
    finally:
        if not _stack_absent(cloudformation, gate.stack_name):
            try:
                cloudformation.delete_stack(
                    StackName=gate.stack_name, DeletionMode="FORCE_DELETE_STACK"
                )
                cloudformation.get_waiter("stack_delete_complete").wait(
                    StackName=gate.stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90}
                )
            except Exception as error:
                cleanup_errors.append(error)
        try:
            residue = _inventories(gate.clients, deadline=_deadline())
            leaked = {
                name: sorted(values - baseline[name])
                for name, values in residue.items()
                if values != baseline[name]
            }
            if leaked:
                cleanup_errors.append(RuntimeError(f"docker gate resource residue: {leaked}"))
            if not _stack_absent(cloudformation, gate.stack_name):
                cleanup_errors.append(RuntimeError("owned CloudFormation stack remains"))
        except Exception as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            summary = "; ".join(f"{type(error).__name__}: {error}" for error in cleanup_errors)
            raise RuntimeError(f"CDK docker gate cleanup failed: {summary}") from cleanup_errors[0]
