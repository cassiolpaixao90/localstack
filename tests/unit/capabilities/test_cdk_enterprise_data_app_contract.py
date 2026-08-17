import ast
import json
import os
import subprocess
import sys
from pathlib import Path

from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

PROJECT_ROOT = Path(__file__).parents[3]
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_data.py"


def test_enterprise_data_app_keeps_the_closed_deployment_contract():
    payload = APP_PATH.read_text()
    module = ast.parse(payload, filename=str(APP_PATH))

    imports = {
        alias.name
        for statement in module.body
        if isinstance(statement, ast.ImportFrom) and statement.module == "aws_cdk"
        for alias in statement.names
    }
    assert {
        "App",
        "CfnOutput",
        "Environment",
        "LegacyStackSynthesizer",
        "RemovalPolicy",
        "Stack",
        "Tags",
        "aws_dynamodb",
        "aws_s3",
    } <= imports

    constants = {
        node.value
        for node in ast.walk(module)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert {
        "project",
        "env",
        "component",
        "managed-by",
        "owner",
        "TableName",
        "BucketName",
    } <= constants
    assert "CDK_DEFAULT_ACCOUNT" in constants
    assert "CDK_DEFAULT_REGION" in constants
    assert TEST_AWS_ACCOUNT_ID not in constants
    assert TEST_AWS_REGION_NAME not in constants

    attributes = {node.attr for node in ast.walk(module) if isinstance(node, ast.Attribute)}
    assert {"account", "region"} <= attributes

    calls = {
        node.func.attr
        for node in ast.walk(module)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert {"CfnTable", "CfnBucket", "apply_removal_policy", "synth"} <= calls


def test_enterprise_data_app_synthesizes_the_closed_resource_contract(tmp_path):
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

    template = json.loads((output / "EnterpriseData.template.json").read_bytes())
    tags = [
        {"Key": "component", "Value": "data"},
        {"Key": "env", "Value": "dev"},
        {"Key": "managed-by", "Value": "cdk"},
        {"Key": "owner", "Value": "platform"},
        {"Key": "project", "Value": "localstack-enterprise"},
    ]
    assert template == {
        "Description": "LocalStack enterprise data-plane CDK verification stack",
        "Resources": {
            "Records": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": "localstack-enterprise-dev-contract-records",
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
                    "SSESpecification": {"SSEEnabled": True},
                    "Tags": tags,
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
            "Artifacts": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "localstack-enterprise-dev-contract-artifacts",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [
                            {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    },
                    "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "Tags": tags,
                },
                "UpdateReplacePolicy": "Delete",
                "DeletionPolicy": "Delete",
            },
        },
        "Outputs": {
            "TableName": {"Value": {"Ref": "Records"}},
            "BucketName": {"Value": {"Ref": "Artifacts"}},
            "DeploymentAccount": {"Value": TEST_AWS_ACCOUNT_ID},
            "DeploymentRegion": {"Value": TEST_AWS_REGION_NAME},
        },
    }
