import os
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.aws.api.cloudformation import Parameter
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


def _delete_versioned_bucket(aws_client, bucket_name: str) -> None:
    for page in aws_client.s3.get_paginator("list_object_versions").paginate(Bucket=bucket_name):
        objects = [
            {"Key": item["Key"], "VersionId": item["VersionId"]}
            for collection in ("Versions", "DeleteMarkers")
            for item in page.get(collection, [])
        ]
        for offset in range(0, len(objects), 1000):
            aws_client.s3.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": objects[offset : offset + 1000], "Quiet": True},
            )

    for page in aws_client.s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket_name):
        for upload in page.get("Uploads", []):
            aws_client.s3.abort_multipart_upload(
                Bucket=bucket_name,
                Key=upload["Key"],
                UploadId=upload["UploadId"],
            )

    aws_client.s3.delete_bucket(Bucket=bucket_name)
    try:
        aws_client.s3.head_bucket(Bucket=bucket_name)
    except ClientError as error:
        if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
            return
        raise
    raise AssertionError(f"retained bootstrap bucket still exists: {bucket_name}")


@pytest.fixture
def cdk_bootstrap_resources(aws_client):
    attachments, cleanup_target = [], {}

    def _register(stack_name: str, bucket_name: str) -> None:
        cleanup_target.update(stack_name=stack_name, bucket_name=bucket_name)

    def _attach(role_name: str, policy_arn: str):
        response = aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn,
        )
        attachments.append((role_name, policy_arn))
        return response

    yield SimpleNamespace(register=_register, attach=_attach)

    try:
        for role_name, policy_arn in reversed(attachments):
            aws_client.iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn,
            )
    finally:
        stack_name = cleanup_target.get("stack_name")
        bucket_name = cleanup_target.get("bucket_name")
        try:
            if stack_name:
                try:
                    aws_client.cloudformation.delete_stack(StackName=stack_name)
                    aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                        StackName=stack_name,
                        WaiterConfig={"Delay": 1, "MaxAttempts": 60},
                    )
                except ClientError as error:
                    if error.response.get("Error", {}).get("Code") != "ValidationError":
                        raise
        finally:
            if bucket_name:
                try:
                    aws_client.s3.head_bucket(Bucket=bucket_name)
                except ClientError as error:
                    if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                        raise
                else:
                    _delete_versioned_bucket(aws_client, bucket_name)


class TestCdkInit:
    @pytest.mark.parametrize(
        "bootstrap_version,parameters",
        [
            ("10", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            ("11", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            ("12", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            (
                "28",
                {
                    "CloudFormationExecutionPolicies": "",
                    "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
                    "PublicAccessBlockConfiguration": "true",
                    "TrustedAccounts": "",
                    "TrustedAccountsForLookup": "",
                },
            ),
        ],
        ids=["10", "11", "12", "28"],
    )
    @markers.aws.validated
    def test_cdk_bootstrap(self, deploy_cfn_template, aws_client, bootstrap_version, parameters):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                f"../../../templates/cdk_bootstrap_v{bootstrap_version}.yaml",
            ),
            parameters=parameters,
        )
        init_stack_result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cdk_init_template.yaml"
            )
        )
        assert init_stack_result.outputs["BootstrapVersionOutput"] == bootstrap_version
        stack_res = aws_client.cloudformation.describe_stack_resources(
            StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
        )
        assert len(stack_res["StackResources"]) == 1
        assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template,parameters_fn",
        [
            pytest.param(
                "cdk_bootstrap.yml",
                lambda qualifier: [
                    {
                        "ParameterKey": "BootstrapVariant",
                        "ParameterValue": "AWS CDK: Default Resources",
                    },
                    {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
                    {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
                    {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
                    {
                        "ParameterKey": "FileAssetsBucketKmsKeyId",
                        "ParameterValue": "AWS_MANAGED_KEY",
                    },
                    {
                        "ParameterKey": "PublicAccessBlockConfiguration",
                        "ParameterValue": "true",
                    },
                    {"ParameterKey": "Qualifier", "ParameterValue": qualifier},
                    {
                        "ParameterKey": "UseExamplePermissionsBoundary",
                        "ParameterValue": "false",
                    },
                ],
                id="v20",
            ),
            pytest.param(
                "cdk_bootstrap_v28.yaml",
                lambda qualifier: [
                    {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
                    {
                        "ParameterKey": "FileAssetsBucketKmsKeyId",
                        "ParameterValue": "AWS_MANAGED_KEY",
                    },
                    {
                        "ParameterKey": "PublicAccessBlockConfiguration",
                        "ParameterValue": "true",
                    },
                    {"ParameterKey": "Qualifier", "ParameterValue": qualifier},
                    {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
                    {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
                ],
                id="v28",
            ),
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Wrong format, they are our internal parameter format
            "$..Parameters",
            # from the list of changes
            "$..Changes..Details",
            "$..Changes..LogicalResourceId",
            "$..Changes..ResourceType",
            "$..Changes..Scope",
            # provider
            "$..IncludeNestedStacks",
            # mismatch between amazonaws.com and localhost.localstack.cloud
            "$..Outputs..OutputValue",
            "$..Outputs..Description",
        ]
    )
    @skip_if_legacy_engine()
    def test_cdk_bootstrap_redeploy(
        self,
        aws_client,
        cleanup_stacks,
        cleanup_changesets,
        cleanups,
        snapshot,
        template,
        parameters_fn: Callable[[str], list[Parameter]],
    ):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(SortingTransformer("Parameters", lambda p: p["ParameterKey"]))
        snapshot.add_transformer(SortingTransformer("Outputs", lambda p: p["OutputKey"]))

        stack_name = f"CDKToolkit-{short_uid()}"
        change_set_name = f"cdk-deploy-change-set-{short_uid()}"
        qualifier = short_uid()
        snapshot.add_transformer(snapshot.transform.regex(qualifier, "<qualifier>"))

        def clean_resources():
            cleanup_stacks([stack_name])
            cleanup_changesets([change_set_name])

        cleanups.append(clean_resources)

        template_path = os.path.realpath(
            os.path.join(os.path.dirname(__file__), f"../../../templates/{template}")
        )
        template_body = load_file(template_path)
        if template_body is None:
            raise RuntimeError(f"Template {template_path} not loaded")

        aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_body,
            ChangeSetType="CREATE",
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            Description="CDK Changeset for execution 731ed7da-8b2d-49c6-bca3-4698b6875954",
            Parameters=parameters_fn(qualifier),
        )
        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            StackName=stack_name, ChangeSetName=change_set_name
        )
        describe_change_set = aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )
        snapshot.match("describe-change-set", describe_change_set)

        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )

        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)
        stacks = aws_client.cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
        snapshot.match("describe-stacks", stacks)

        # When CDK bootstrap command is executed again it just confirms that the template is the same
        aws_client.cloudformation.get_template(StackName=stack_name, TemplateStage="Original")

        # TODO: create scenario where the template is different to catch cdk behavior

    @markers.aws.only_localstack
    @skip_if_legacy_engine()
    def test_cdk_bootstrap_upgrade_v28_to_v32_preserves_roles(
        self,
        deploy_cfn_template,
        cdk_bootstrap_resources,
        aws_client,
        account_id,
        region_name,
    ):
        qualifier = short_uid()[:10]
        stack_name = f"CDKToolkit-{short_uid()}"
        bucket_name = f"cdk-{qualifier}-assets-{account_id}-{region_name}"
        cdk_bootstrap_resources.register(stack_name, bucket_name)
        parameters = {
            "CloudFormationExecutionPolicies": "",
            "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
            "PublicAccessBlockConfiguration": "true",
            "Qualifier": qualifier,
            "TrustedAccounts": "",
            "TrustedAccountsForLookup": "",
        }
        template_directory = os.path.realpath(
            os.path.join(os.path.dirname(__file__), "../../../templates")
        )

        created = deploy_cfn_template(
            stack_name=stack_name,
            template_path=os.path.join(template_directory, "cdk_bootstrap_v28.yaml"),
            parameters=parameters,
            max_wait=60,
            delay_between_polls=1,
        )
        assert created.outputs["BootstrapVersion"] == "28"
        assert created.outputs["BucketName"] == bucket_name
        stack_resources = aws_client.cloudformation.describe_stack_resources(
            StackName=created.stack_id
        )["StackResources"]
        role_names = {
            resource["LogicalResourceId"]: resource["PhysicalResourceId"]
            for resource in stack_resources
            if resource["ResourceType"] == "AWS::IAM::Role"
        }
        expected_roles = {
            "CloudFormationExecutionRole",
            "DeploymentActionRole",
            "FilePublishingRole",
            "ImagePublishingRole",
            "LookupRole",
        }
        assert set(role_names) == expected_roles

        role_identity_before = {
            logical_id: {
                key: value
                for key, value in aws_client.iam.get_role(RoleName=role_name)["Role"].items()
                if key in {"Arn", "RoleId"}
            }
            for logical_id, role_name in role_names.items()
        }
        partition = role_identity_before["DeploymentActionRole"]["Arn"].split(":", 2)[1]
        external_policy_arn = f"arn:{partition}:iam::aws:policy/SecurityAudit"
        for role_name in role_names.values():
            baseline_policies = aws_client.iam.list_attached_role_policies(RoleName=role_name)[
                "AttachedPolicies"
            ]
            assert external_policy_arn not in {policy["PolicyArn"] for policy in baseline_policies}
            cdk_bootstrap_resources.attach(role_name, external_policy_arn)

        updated = deploy_cfn_template(
            is_update=True,
            stack_name=created.stack_id,
            template_path=os.path.join(template_directory, "cdk_bootstrap_v32.yaml"),
            parameters=parameters,
            max_wait=60,
            delay_between_polls=1,
        )

        roles_after = {
            logical_id: aws_client.iam.get_role(RoleName=role_name)["Role"]
            for logical_id, role_name in role_names.items()
        }
        role_identity_after = {
            logical_id: {key: role[key] for key in ("Arn", "RoleId")}
            for logical_id, role in roles_after.items()
        }
        attached_policies = {
            logical_id: {
                policy["PolicyArn"]
                for policy in aws_client.iam.list_attached_role_policies(RoleName=role_name)[
                    "AttachedPolicies"
                ]
            }
            for logical_id, role_name in role_names.items()
        }

        assert updated.stack_id == created.stack_id
        assert updated.outputs["BootstrapVersion"] == "32"
        assert role_identity_after == role_identity_before
        assert all(external_policy_arn in policies for policies in attached_policies.values())
        assert (
            f"arn:{partition}:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
            in attached_policies["DeploymentActionRole"]
        )
        for logical_id in (
            "DeploymentActionRole",
            "FilePublishingRole",
            "ImagePublishingRole",
            "LookupRole",
        ):
            statements = roles_after[logical_id]["AssumeRolePolicyDocument"]["Statement"]
            assert any(
                statement.get("Condition", {}).get("Null", {}).get("sts:ExternalId") == "true"
                for statement in statements
            )

        deployment_policy = aws_client.iam.get_role_policy(
            RoleName=role_names["DeploymentActionRole"],
            PolicyName="default",
        )["PolicyDocument"]
        deployment_statement_ids = {
            statement.get("Sid") for statement in deployment_policy["Statement"]
        }
        assert "DeployPermissions" in deployment_statement_ids
        assert "CloudFormationPermissions" not in deployment_statement_ids
        assert (
            aws_client.ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")["Parameter"][
                "Value"
            ]
            == "32"
        )


class TestCdkSampleApp:
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Attributes.Policy.Statement..Condition",
            "$..Attributes.Policy.Statement..Resource",
            "$..StackResourceSummaries..PhysicalResourceId",
        ]
    )
    @markers.aws.validated
    def test_cdk_sample(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(
            SortingTransformer("StackResourceSummaries", lambda x: x["LogicalResourceId"]),
            priority=-1,
        )

        deploy = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cfn_cdk_sample_app.yaml"
            ),
            max_wait=120,
        )

        queue_url = deploy.outputs["QueueUrl"]

        queue_attr_policy = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"]
        )
        snapshot.match("queue_attr_policy", queue_attr_policy)
        stack_resources = aws_client.cloudformation.list_stack_resources(StackName=deploy.stack_id)
        snapshot.match("stack_resources", stack_resources)

        # physical resource id of the queue policy AWS::SQS::QueuePolicy
        queue_policy_resource = aws_client.cloudformation.describe_stack_resource(
            StackName=deploy.stack_id, LogicalResourceId="CdksampleQueuePolicyFA91005A"
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                queue_policy_resource["StackResourceDetail"]["PhysicalResourceId"],
                "<queue-policy-physid>",
            )
        )
        # TODO: make sure phys id of the resource conforms to this format: stack-d98dcad5-CdksampleQueuePolicyFA91005A-1WYVV4PMCWOYI
