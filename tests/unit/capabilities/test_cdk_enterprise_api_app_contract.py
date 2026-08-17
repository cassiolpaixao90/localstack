import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests.aws.cli.test_cdk_cli_apigateway_deploy import _load_outputs

from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_api.py"


def _deployment_outputs() -> dict:
    return {
        "ApiId": "api-id",
        "ApiRootResourceId": "root-id",
        "ApiStageName": "local",
        "DeploymentAccount": TEST_AWS_ACCOUNT_ID,
        "DeploymentRegion": TEST_AWS_REGION_NAME,
    }


def test_enterprise_api_output_parser_accepts_only_the_expected_deployment(tmp_path):
    path = tmp_path / "outputs.json"
    expected = _deployment_outputs()
    path.write_text(json.dumps({"expected-stack": expected}))

    assert (
        _load_outputs(
            path,
            stack_name="expected-stack",
            account_id=TEST_AWS_ACCOUNT_ID,
            region_name=TEST_AWS_REGION_NAME,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("payload", "stack_name", "account_id", "message"),
    [
        (
            {"wrong-stack": _deployment_outputs()},
            "expected-stack",
            TEST_AWS_ACCOUNT_ID,
            "exactly the deployed stack",
        ),
        (
            {"expected-stack": _deployment_outputs() | {"Unexpected": "value"}},
            "expected-stack",
            TEST_AWS_ACCOUNT_ID,
            "closed API contract",
        ),
        (
            {"expected-stack": _deployment_outputs()},
            "expected-stack",
            "111111111111",
            "account does not match",
        ),
    ],
)
def test_enterprise_api_output_parser_fails_closed(
    tmp_path,
    payload: dict,
    stack_name: str,
    account_id: str,
    message: str,
):
    path = tmp_path / "outputs.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match=message):
        _load_outputs(
            path,
            stack_name=stack_name,
            account_id=account_id,
            region_name=TEST_AWS_REGION_NAME,
        )


def test_enterprise_api_app_synthesizes_the_closed_apigateway_contract(tmp_path):
    output = tmp_path / "cdk.out"
    environment = {
        **os.environ,
        "CDK_CONTEXT_JSON": json.dumps(
            {
                "project": "localstack-enterprise",
                "stage": "dev",
                "deployment": "contract",
                "owner": "platform",
            },
            sort_keys=True,
        ),
        "CDK_DEFAULT_ACCOUNT": TEST_AWS_ACCOUNT_ID,
        "CDK_DEFAULT_REGION": TEST_AWS_REGION_NAME,
        "CDK_OUTDIR": str(output),
    }
    subprocess.run(
        [sys.executable, "-I", "-B", str(APP_PATH)],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=30,
    )

    template = json.loads((output / "EnterpriseApi.template.json").read_bytes())
    tags = [
        {"Key": "component", "Value": "api"},
        {"Key": "env", "Value": "dev"},
        {"Key": "managed-by", "Value": "cdk"},
        {"Key": "owner", "Value": "platform"},
        {"Key": "project", "Value": "localstack-enterprise"},
    ]
    assert template == {
        "Description": "LocalStack enterprise API Gateway CDK verification stack",
        "Resources": {
            "Api": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Description": "LocalStack enterprise API Gateway verification API",
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                    "Name": "localstack-enterprise-dev-contract-api",
                    "Tags": tags,
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "HealthMethod": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "AuthorizationType": "NONE",
                    "HttpMethod": "GET",
                    "Integration": {
                        "IntegrationResponses": [
                            {
                                "ResponseTemplates": {
                                    "application/json": ('{"service":"localstack","status":"ok"}')
                                },
                                "StatusCode": "200",
                            }
                        ],
                        "PassthroughBehavior": "NEVER",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "Type": "MOCK",
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                    "ResourceId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
                    "RestApiId": {"Ref": "Api"},
                },
            },
            "ApiDeploymentb77f9abb9936": {
                "Type": "AWS::ApiGateway::Deployment",
                "Properties": {
                    "Description": "LocalStack enterprise API Gateway deployment",
                    "RestApiId": {"Ref": "Api"},
                },
                "DependsOn": ["HealthMethod"],
            },
            "ApiStage": {
                "Type": "AWS::ApiGateway::Stage",
                "Properties": {
                    "DeploymentId": {"Ref": "ApiDeploymentb77f9abb9936"},
                    "Description": "LocalStack enterprise API Gateway local stage",
                    "RestApiId": {"Ref": "Api"},
                    "StageName": "local",
                    "Tags": tags,
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "Api"}},
            "ApiRootResourceId": {"Value": {"Fn::GetAtt": ["Api", "RootResourceId"]}},
            "ApiStageName": {"Value": "local"},
            "DeploymentAccount": {"Value": TEST_AWS_ACCOUNT_ID},
            "DeploymentRegion": {"Value": TEST_AWS_REGION_NAME},
        },
    }
