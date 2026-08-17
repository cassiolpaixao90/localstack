import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError
from OpenSSL import crypto

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from tests.aws.cli.execution_evidence import read_regular_bounded
from tests.aws.cli.test_cdk_cli_bootstrap_upgrade import CdkRuntime

pytest_plugins = ("tests.aws.cli.test_cdk_cli_bootstrap_upgrade",)

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = (
    PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_http_api_custom_domain.py"
)
OWNER_TAG_KEY = "localstack:diagnostic-owner"
OWNER_PATTERN = re.compile(r"^[a-f0-9]{24}$")
CONTAINER_PATTERN = re.compile(r"^ls-domain-gate-[a-z0-9-]{1,80}$")
RPC_CONFIG = Config(
    connect_timeout=2,
    read_timeout=2,
    retries={"mode": "standard", "total_max_attempts": 1},
)
EXPECTED_RESOURCES = {
    "ApiMapping": "AWS::ApiGatewayV2::ApiMapping",
    "CustomDomain": "AWS::ApiGatewayV2::DomainName",
    "Deployment": "AWS::ApiGatewayV2::Deployment",
    "HealthIntegration": "AWS::ApiGatewayV2::Integration",
    "HealthRoute": "AWS::ApiGatewayV2::Route",
    "HttpApi": "AWS::ApiGatewayV2::Api",
    "Stage": "AWS::ApiGatewayV2::Stage",
}
EXPECTED_OUTPUTS = {
    "ApiId",
    "ApiMappingId",
    "DeploymentAccount",
    "DeploymentId",
    "DeploymentRegion",
    "DomainName",
    "RegionalDomainName",
    "StageName",
}


@dataclass(frozen=True)
class CustomDomainDeployment:
    api_id: str
    domain_name: str
    endpoint: str
    mapping_id: str
    stack_id: str


def _certificate_material(domain_name: str) -> tuple[bytes, bytes]:
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    certificate = crypto.X509()
    certificate.set_version(2)
    certificate.set_serial_number(secrets.randbits(63))
    certificate.get_subject().CN = domain_name
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(key)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(24 * 60 * 60)
    certificate.add_extensions(
        [crypto.X509Extension(b"subjectAltName", False, f"DNS:{domain_name}".encode())]
    )
    certificate.sign(key, "sha256")
    return (
        crypto.dump_certificate(crypto.FILETYPE_PEM, certificate),
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key),
    )


def _python_app_command() -> str:
    configured = os.environ.get("CDK_PYTHON_SYNTH_PYTHON")
    python = Path(configured) if configured else Path(sys.executable)
    if not python.is_absolute() or not python.is_file() or not APP_PATH.is_file():
        raise ValueError("the pinned Python interpreter and custom-domain fixture must exist")
    return shlex.join((str(python), "-I", "-B", str(APP_PATH)))


def _list_domains(client) -> dict[str, dict]:
    result = {}
    token = None
    seen = set()
    for _ in range(16):
        request = {"MaxResults": "500"}
        if token:
            request["NextToken"] = token
        response = client.get_domain_names(**request)
        for item in response.get("Items", []):
            result[item["DomainName"]] = item
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid custom-domain continuation token")
        seen.add(token)
    raise RuntimeError("custom-domain inventory exceeded its page bound")


def _list_apis(client) -> dict[str, dict]:
    result = {}
    token = None
    seen = set()
    for _ in range(16):
        request = {"MaxResults": "500"}
        if token:
            request["NextToken"] = token
        response = client.get_apis(**request)
        for item in response.get("Items", []):
            result[item["ApiId"]] = item
        token = response.get("NextToken")
        if token is None:
            return result
        if not isinstance(token, str) or not token or token in seen:
            raise RuntimeError("invalid API continuation token")
        seen.add(token)
    raise RuntimeError("API inventory exceeded its page bound")


def _stack_absent(client, stack_name: str) -> bool:
    try:
        client.describe_stacks(StackName=stack_name)
    except ClientError as error:
        return error.response.get("Error", {}).get("Code") == "ValidationError"
    return False


def _cleanup_owned_native_resources(
    client,
    *,
    baseline_apis: dict[str, dict],
    baseline_domains: dict[str, dict],
    domain_name: str,
    owner: str,
) -> None:
    domains = _list_domains(client)
    if domain_name in domains and domain_name not in baseline_domains:
        domain = client.get_domain_name(DomainName=domain_name)
        if domain.get("Tags", {}).get(OWNER_TAG_KEY) != owner:
            raise RuntimeError("refusing to delete a custom domain without its owner tag")
        mappings = client.get_api_mappings(DomainName=domain_name, MaxResults="500")
        if mappings.get("NextToken") is not None:
            raise RuntimeError("owned mapping fallback exceeded one bounded page")
        for mapping in mappings.get("Items", []):
            client.delete_api_mapping(DomainName=domain_name, ApiMappingId=mapping["ApiMappingId"])
        client.delete_domain_name(DomainName=domain_name)
    for api_id, api in _list_apis(client).items():
        if api_id in baseline_apis:
            continue
        if api.get("Tags", {}).get(OWNER_TAG_KEY) != owner:
            raise RuntimeError("refusing to delete an HTTP API without its owner tag")
        client.delete_api(ApiId=api_id)


def _restart_owned_container(container: str, endpoint: str) -> None:
    if not CONTAINER_PATTERN.fullmatch(container):
        raise RuntimeError("custom-domain gate container identity is invalid")

    def docker(*arguments: str) -> str:
        result = subprocess.run(
            ["docker", *arguments], capture_output=True, check=False, timeout=30
        )
        if result.returncode != 0 or len(result.stdout) > 64 * 1024:
            raise RuntimeError(result.stderr.decode(errors="replace")[:4096])
        return result.stdout.decode().strip()

    before = docker("inspect", "--format", "{{.Id}}", container)
    docker("stop", "--timeout", "15", container)
    docker("start", container)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{endpoint}/_localstack/health", timeout=2).status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(0.2)
    else:
        raise TimeoutError("custom-domain container did not become healthy after restart")
    if docker("inspect", "--format", "{{.Id}}", container) != before:
        raise RuntimeError("custom-domain restart replaced the owned container")


@pytest.fixture
def imported_custom_domain_certificate(aws_client_factory, account_id, region_name):
    owner = secrets.token_hex(12)
    domain_name = f"d{owner}.localhost.localstack.cloud"
    acm = aws_client_factory(config=RPC_CONFIG).acm
    certificate, private_key = _certificate_material(domain_name)
    response = acm.import_certificate(Certificate=certificate, PrivateKey=private_key)
    certificate_arn = response["CertificateArn"]
    expected_prefix = (
        f"arn:{get_partition(region_name)}:acm:{region_name}:{account_id}:certificate/"
    )
    if not certificate_arn.startswith(expected_prefix):
        raise RuntimeError("imported certificate escaped the test account or region")
    described = acm.describe_certificate(CertificateArn=certificate_arn)["Certificate"]
    if described.get("Status") != "ISSUED" or described.get("DomainName") != domain_name:
        raise RuntimeError("imported certificate is not issued for the owned domain")
    try:
        yield domain_name, certificate_arn
    finally:
        try:
            acm.delete_certificate(CertificateArn=certificate_arn)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise


@pytest.fixture
def deployed_http_api_custom_domain(
    pinned_cdk_cli_runtime: CdkRuntime,
    imported_custom_domain_certificate,
    aws_client_factory,
    account_id,
    region_name,
    tmp_path,
):
    domain_name, certificate_arn = imported_custom_domain_certificate
    owner = domain_name.removeprefix("d").removesuffix(".localhost.localstack.cloud")
    if not OWNER_PATTERN.fullmatch(owner):
        raise RuntimeError("custom-domain ownership nonce is invalid")
    deployment = f"d{owner[:23]}"
    stack_name = f"localstack-http-domain-{deployment}"
    clients = aws_client_factory(config=RPC_CONFIG)
    cloudformation = clients.cloudformation
    apigatewayv2 = clients.apigatewayv2
    baseline_apis = _list_apis(apigatewayv2)
    baseline_domains = _list_domains(apigatewayv2)
    if not _stack_absent(cloudformation, stack_name) or domain_name in baseline_domains:
        raise RuntimeError("owned deployment identity collided before creation")
    output_path = tmp_path / "custom-domain-output.json"
    environment = dict(pinned_cdk_cli_runtime.environment)
    environment.update(
        {
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": region_name,
            "CUSTOM_DOMAIN_CERTIFICATE_ARN": certificate_arn,
            "CUSTOM_DOMAIN_NAME": domain_name,
        }
    )
    stack_id = None
    try:
        result = launch_cdk(
            [
                "deploy",
                "EnterpriseHttpApiCustomDomain",
                "--app",
                _python_app_command(),
                "--context",
                f"deployment={deployment}",
                "--context",
                f"owner={owner}",
                "--outputs-file",
                str(output_path),
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
            ],
            executable=pinned_cdk_cli_runtime.executable,
            environment=environment,
            cwd=pinned_cdk_cli_runtime.workspace,
            timeout_seconds=150,
            max_output_bytes=256 * 1024,
        )
        assert not result.timed_out
        assert not result.stdout_truncated
        assert not result.stderr_truncated
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        document = json.loads(read_regular_bounded(output_path, 64 * 1024))
        outputs = document.get(stack_name)
        if not isinstance(outputs, dict) or set(outputs) != EXPECTED_OUTPUTS:
            raise RuntimeError("custom-domain CDK output contract is not closed")
        if (
            outputs["DeploymentAccount"] != account_id
            or outputs["DeploymentRegion"] != region_name
            or outputs["DomainName"] != domain_name
        ):
            raise RuntimeError("custom-domain CDK output topology is invalid")
        stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
        stack_id = stack["StackId"]
        owner_tags = [tag["Value"] for tag in stack.get("Tags", []) if tag["Key"] == OWNER_TAG_KEY]
        if stack.get("StackStatus") != "CREATE_COMPLETE" or owner_tags != [owner]:
            raise RuntimeError("custom-domain stack status or ownership is invalid")
        resources = cloudformation.describe_stack_resources(StackName=stack_id)["StackResources"]
        actual = {
            item["LogicalResourceId"]: item["ResourceType"]
            for item in resources
            if item.get("ResourceStatus") == "CREATE_COMPLETE"
        }
        if actual != EXPECTED_RESOURCES or len(resources) != len(EXPECTED_RESOURCES):
            raise RuntimeError("custom-domain stack resource set is not exact")
        ids = {item["LogicalResourceId"]: item["PhysicalResourceId"] for item in resources}
        if (
            ids["HttpApi"] != outputs["ApiId"]
            or ids["CustomDomain"] != domain_name
            or ids["ApiMapping"] != outputs["ApiMappingId"]
            or ids["Stage"] != outputs["StageName"]
        ):
            raise RuntimeError("custom-domain resource physical IDs are inconsistent")
        endpoint = apigatewayv2.meta.endpoint_url.rstrip("/")
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("API client endpoint is invalid")
        custom_endpoint = f"https://{domain_name}:{parsed.port or 443}"
        yield CustomDomainDeployment(
            api_id=outputs["ApiId"],
            domain_name=domain_name,
            endpoint=custom_endpoint,
            mapping_id=outputs["ApiMappingId"],
            stack_id=stack_id,
        )
    finally:
        if stack_id is not None and not _stack_absent(cloudformation, stack_name):
            cloudformation.delete_stack(StackName=stack_id)
            cloudformation.get_waiter("stack_delete_complete").wait(
                StackName=stack_id, WaiterConfig={"Delay": 1, "MaxAttempts": 90}
            )
        if (
            _list_apis(apigatewayv2) != baseline_apis
            or _list_domains(apigatewayv2) != baseline_domains
        ):
            _cleanup_owned_native_resources(
                apigatewayv2,
                baseline_apis=baseline_apis,
                baseline_domains=baseline_domains,
                domain_name=domain_name,
                owner=owner,
            )
        if _list_apis(apigatewayv2) != baseline_apis:
            raise RuntimeError("HTTP API inventory leaked after custom-domain cleanup")
        if _list_domains(apigatewayv2) != baseline_domains:
            raise RuntimeError("custom-domain inventory leaked after cleanup")
        if not _stack_absent(cloudformation, stack_name):
            raise RuntimeError("custom-domain CloudFormation stack remains after cleanup")


@markers.aws.only_localstack
def test_cdk_http_api_custom_domain_maps_and_invokes(
    deployed_http_api_custom_domain: CustomDomainDeployment,
    aws_client_factory,
):
    deployment = deployed_http_api_custom_domain
    apigatewayv2 = aws_client_factory(config=RPC_CONFIG).apigatewayv2
    domain = apigatewayv2.get_domain_name(DomainName=deployment.domain_name)
    assert domain["DomainNameConfigurations"][0]["DomainNameStatus"] == "AVAILABLE"
    mappings = apigatewayv2.get_api_mappings(DomainName=deployment.domain_name)["Items"]
    assert mappings == [
        {
            "ApiId": deployment.api_id,
            "ApiMappingId": deployment.mapping_id,
            "ApiMappingKey": "v1",
            "Stage": "prod",
        }
    ]
    response = requests.get(
        f"{deployment.endpoint}/v1/health",
        timeout=10,
    )
    assert response.status_code == 200
    assert response.json()["services"]["apigatewayv2"] in {"available", "running"}

    plain_http = requests.get(
        f"http://{deployment.domain_name}:{urlsplit(deployment.endpoint).port}/v1/health",
        timeout=10,
    )
    assert plain_http.status_code == 403
    assert plain_http.json() == {"message": "Forbidden"}

    if container := os.environ.get("CUSTOM_DOMAIN_GATE_CONTAINER"):
        _restart_owned_container(container, apigatewayv2.meta.endpoint_url.rstrip("/"))
        restored = apigatewayv2.get_domain_name(DomainName=deployment.domain_name)
        assert restored["DomainName"] == deployment.domain_name
        restored_mappings = apigatewayv2.get_api_mappings(DomainName=deployment.domain_name)[
            "Items"
        ]
        assert restored_mappings == mappings
        after_restart = requests.get(f"{deployment.endpoint}/v1/health", timeout=10)
        assert after_restart.status_code == 200
