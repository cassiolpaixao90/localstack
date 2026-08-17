import json
from pathlib import Path

import jsonschema
import pytest

from localstack.capabilities import cdk as cdk_catalog
from localstack.capabilities.cdk import build_cdk_service_map

PROJECT_ROOT = Path(__file__).parents[3]
MAP_PATH = PROJECT_ROOT / "capabilities/cdk/services.json"
SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/services.schema.json"


@pytest.fixture(scope="module")
def generated_service_map():
    return build_cdk_service_map(PROJECT_ROOT)


def test_cdk_service_map_matches_the_pinned_construct_library_and_local_catalog(
    generated_service_map,
):
    expected = generated_service_map
    committed = json.loads(
        cdk_catalog._read_regular_bounded(
            MAP_PATH, cdk_catalog.MAX_SERVICE_MAP_BYTES, "CDK service map"
        )
    )
    schema = json.loads(
        cdk_catalog._read_regular_bounded(
            SCHEMA_PATH, cdk_catalog.MAX_SERVICE_MAP_SCHEMA_BYTES, "CDK service map schema"
        )
    )

    jsonschema.validators.validator_for(schema).check_schema(schema)
    jsonschema.validate(committed, schema)
    assert committed == expected
    assert committed["map_sha256"] == cdk_catalog._sha256(
        cdk_catalog._canonical_bytes({**committed, "map_sha256": ""})
    )
    assert committed["claim"] == "static-inventory-only"
    assert committed["summary"] == {
        "cdk_service_modules": 300,
        "modules_with_construct_classes": 282,
        "modules_with_l1_resources": 272,
        "cdk_l1_resource_types": 1557,
        "current_cfn_catalog_resource_types": 1555,
        "cdk_current_cfn_overlap": 1544,
        "cdk_only_resource_types": 13,
        "current_cfn_only_resource_types": 11,
        "localstack_resource_provider_types": 129,
        "localstack_aws_resource_provider_types": 129,
        "localstack_cdk_l1_intersection": 126,
        "static_l1_coverage_basis_points": 809,
        "modules_static_complete": 8,
        "modules_static_partial": 21,
        "modules_static_none": 243,
        "modules_without_l1_resources": 28,
        "modules_with_api_catalog_candidates": 254,
        "modules_l1_without_api_catalog_candidate": 18,
        "modules_l1_with_unmapped_cfn_namespaces": 18,
        "resource_provider_schema_declared_handlers": 425,
        "resource_provider_handlers_method_body_present_unverified": 250,
        "resource_provider_handlers_notimplemented_only": 97,
        "resource_provider_handlers_contains_notimplemented": 1,
        "resource_provider_handlers_method_missing": 77,
        "resource_provider_records_all_method_bodies_present_unverified": 27,
        "resource_provider_records_incomplete_static_handler_surface": 62,
        "resource_provider_records_no_schema_handler_declarations": 37,
    }

    services = committed["services"]
    assert [service["module"] for service in services] == sorted(
        service["module"] for service in services
    )
    assert len({service["module"] for service in services}) == len(services)
    assert {
        service["module"]
        for service in services
        if service["static_resource_provider_status"] == "complete"
    } == {
        "aws_cognito",
        "aws_dynamodb",
        "aws_elasticsearch",
        "aws_kinesisfirehose",
        "aws_scheduler",
        "aws_secretsmanager",
        "aws_sns",
        "aws_sqs",
    }
    assert all(service["support_claim"] == "not-established" for service in services)
    assert all(
        service["planning_status"]
        in {
            "all-resource-provider-records-present",
            "partial-resource-provider-records",
            "no-resource-provider-records",
            "no-l1-resource-types",
        }
        for service in services
    )
    for service in services:
        assert service["bindings"]["go"].startswith("github.com/aws/aws-cdk-go/awscdk/v2/")
        assert [resource["type"] for resource in service["resources"]] == service[
            "l1_resource_types"
        ]
        assert [
            resource["type"]
            for resource in service["resources"]
            if resource["localstack_resource_provider"] is not None
        ] == service["localstack_resource_provider_types"]
        for resource in service["resources"]:
            provider = resource["localstack_resource_provider"]
            if provider is not None:
                assert (PROJECT_ROOT / provider["implementation_source"]).is_file()
                assert not provider["implementation_source"].endswith("_base.py")
                assert (PROJECT_ROOT / provider["catalog_source"]).is_file()
                assert (PROJECT_ROOT / provider["registration_source"]).is_file()
                handler_contract = provider["handler_contract"]
                assert (PROJECT_ROOT / handler_contract["schema_source"]).is_file()
                assert set(handler_contract["schema_declared_handlers"]) == set(
                    handler_contract["handler_statuses"]
                )
                assert provider["catalog_sha256"] == cdk_catalog._sha256(
                    (PROJECT_ROOT / provider["catalog_source"]).read_bytes()
                )
                assert provider["implementation_sha256"] == cdk_catalog._sha256(
                    (PROJECT_ROOT / provider["implementation_source"]).read_bytes()
                )
                assert provider["registration_sha256"] == cdk_catalog._sha256(
                    (PROJECT_ROOT / provider["registration_source"]).read_bytes()
                )

    sns = next(service for service in services if service["module"] == "aws_sns")
    sns_handler_contracts = {
        resource["type"]: resource["localstack_resource_provider"]["handler_contract"]
        for resource in sns["resources"]
    }
    assert sns_handler_contracts["AWS::SNS::TopicPolicy"]["static_status"] == (
        "all-method-bodies-present-unverified"
    )
    assert sns_handler_contracts["AWS::SNS::TopicInlinePolicy"]["static_status"] == (
        "all-method-bodies-present-unverified"
    )

    dynamodb = next(service for service in services if service["module"] == "aws_dynamodb")
    table = next(
        resource for resource in dynamodb["resources"] if resource["type"] == "AWS::DynamoDB::Table"
    )
    assert table["localstack_resource_provider"]["handler_contract"]["handler_statuses"] == {
        "create": "method-body-present-unverified",
        "delete": "method-body-present-unverified",
        "list": "method-body-present-unverified",
        "read": "method-body-present-unverified",
        "update": "method-body-present-unverified",
    }

    ses = next(service for service in services if service["module"] == "aws_ses")
    email_identity = next(
        resource for resource in ses["resources"] if resource["type"] == "AWS::SES::EmailIdentity"
    )
    assert (
        email_identity["localstack_resource_provider"]["handler_contract"]["handler_statuses"][
            "create"
        ]
        == "contains-notimplemented"
    )

    sqs = next(service for service in services if service["module"] == "aws_sqs")
    queue = next(resource for resource in sqs["resources"] if resource["type"] == "AWS::SQS::Queue")
    assert queue["localstack_resource_provider"]["handler_contract"]["schema_source"].endswith(
        "generated/aws_sqs_queue.schema.json"
    )


def test_cdk_service_map_exposes_catalog_drift_without_hiding_it(generated_service_map):
    service_map = generated_service_map

    assert service_map["drift"]["cdk_only_resource_types"] == [
        "AWS::IoTFleetHub::Application",
        "AWS::LookoutMetrics::Alert",
        "AWS::LookoutMetrics::AnomalyDetector",
        "AWS::NimbleStudio::LaunchProfile",
        "AWS::NimbleStudio::StreamingImage",
        "AWS::NimbleStudio::StudioComponent",
        "AWS::Serverless::Api",
        "AWS::Serverless::Application",
        "AWS::Serverless::Function",
        "AWS::Serverless::HttpApi",
        "AWS::Serverless::LayerVersion",
        "AWS::Serverless::SimpleTable",
        "AWS::Serverless::StateMachine",
    ]
    assert service_map["drift"]["current_cfn_only_resource_types"] == [
        "AMZN::SDC::Deployment",
        "AWS::BedrockAgentCore::BrowserProfile",
        "AWS::BedrockAgentCore::Evaluator",
        "AWS::BedrockAgentCore::OnlineEvaluationConfig",
        "AWS::BedrockMantle::Project",
        "AWS::Billing::BillingView",
        "AWS::GammaDilithium::JobDefinition",
        "AWS::IoTManagedIntegrations::CredentialLocker",
        "AWS::IoTManagedIntegrations::ManagedThing",
        "AWS::IoTManagedIntegrations::ProvisioningProfile",
        "AWS::Lambda::ResourcePolicy",
    ]

    alexa = next(service for service in service_map["services"] if service["module"] == "alexa_ask")
    assert alexa["bindings"]["go"] == "github.com/aws/aws-cdk-go/awscdk/v2/alexaask"
    assert alexa["resources"][0]["present_in_current_cfn_catalog"] is True

    kinesis_analytics = next(
        service
        for service in service_map["services"]
        if service["module"] == "aws_kinesisanalytics"
    )
    assert {entry["service"] for entry in kinesis_analytics["api_catalog"]} == {
        "kinesisanalytics",
        "kinesisanalyticsv2",
    }
    assert kinesis_analytics["api_mapping_status"] == "mapped"
    assert kinesis_analytics["unmapped_cloudformation_namespaces"] == []

    cognito = next(
        service for service in service_map["services"] if service["module"] == "aws_cognito"
    )
    assert {entry["service"] for entry in cognito["api_catalog"]} == {
        "cognito-identity",
        "cognito-idp",
        "cognito-sync",
    }
    assert cognito["unmapped_cloudformation_namespaces"] == []
    assert cognito["static_resource_provider_status"] == "complete"
    assert cognito["localstack_resource_provider_types"] == [
        "AWS::Cognito::IdentityPool",
        "AWS::Cognito::IdentityPoolPrincipalTag",
        "AWS::Cognito::IdentityPoolRoleAttachment",
        "AWS::Cognito::LogDeliveryConfiguration",
        "AWS::Cognito::ManagedLoginBranding",
        "AWS::Cognito::Terms",
        "AWS::Cognito::UserPool",
        "AWS::Cognito::UserPoolClient",
        "AWS::Cognito::UserPoolDomain",
        "AWS::Cognito::UserPoolGroup",
        "AWS::Cognito::UserPoolIdentityProvider",
        "AWS::Cognito::UserPoolResourceServer",
        "AWS::Cognito::UserPoolRiskConfigurationAttachment",
        "AWS::Cognito::UserPoolUICustomizationAttachment",
        "AWS::Cognito::UserPoolUser",
        "AWS::Cognito::UserPoolUserToGroupAttachment",
    ]

    timestream = next(
        service for service in service_map["services"] if service["module"] == "aws_timestream"
    )
    assert {entry["service"] for entry in timestream["api_catalog"]} == {
        "timestream-influxdb",
        "timestream-query",
        "timestream-write",
    }
    assert timestream["unmapped_cloudformation_namespaces"] == []

    assert {
        service["module"]
        for service in service_map["services"]
        if service["unmapped_cloudformation_namespaces"]
    } == {
        "alexa_ask",
        "aws_apptest",
        "aws_codestar",
        "aws_evidently",
        "aws_iotanalytics",
        "aws_iotevents",
        "aws_iotfleethub",
        "aws_lookoutmetrics",
        "aws_lookoutvision",
        "aws_nimblestudio",
        "aws_opsworks",
        "aws_opsworkscm",
        "aws_panorama",
        "aws_qldb",
        "aws_robomaker",
        "aws_s3express",
        "aws_sam",
        "aws_simspaceweaver",
    }

    resolved_generated_sources = {
        resource["type"]: resource["localstack_resource_provider"]
        for service in service_map["services"]
        for resource in service["resources"]
        if resource["localstack_resource_provider"] is not None
        and resource["localstack_resource_provider"]["catalog_source"].endswith("_base.py")
    }
    assert set(resolved_generated_sources) == {
        "AWS::Lambda::Function",
        "AWS::SQS::Queue",
        "AWS::SQS::QueueInlinePolicy",
        "AWS::SQS::QueuePolicy",
    }
    assert all(
        provider["catalog_source"].endswith("_base.py")
        and provider["registration_source"].endswith("_plugin.py")
        and not provider["implementation_source"].endswith("_base.py")
        for provider in resolved_generated_sources.values()
    )
    assert all(
        resource["localstack_resource_provider"]["registration_source"].endswith("_plugin.py")
        for service in service_map["services"]
        for resource in service["resources"]
        if resource["localstack_resource_provider"] is not None
    )

    sam = next(service for service in service_map["services"] if service["module"] == "aws_sam")
    assert sam["planning_status"] == "no-resource-provider-records"


def test_cdk_service_map_reader_rejects_unbounded_or_indirect_inputs(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (cdk_catalog.MAX_SERVICE_MAP_BYTES + 1))
    with pytest.raises(ValueError, match="outside the accepted size"):
        cdk_catalog._read_regular_bounded(
            oversized, cdk_catalog.MAX_SERVICE_MAP_BYTES, "CDK service map"
        )

    regular = tmp_path / "regular.json"
    regular.write_bytes(b"{}")
    link = tmp_path / "linked.json"
    link.symlink_to(regular)
    with pytest.raises((OSError, ValueError)):
        cdk_catalog._read_regular_bounded(
            link, cdk_catalog.MAX_SERVICE_MAP_BYTES, "CDK service map"
        )


@pytest.mark.parametrize(
    "plugin_class",
    [
        (
            "class WidgetProviderPlugin:\n"
            '    name = "AWS::Example::Widget"\n'
            "    def load(self):\n"
            "        from localstack.services.example.resource_providers."
            "aws_example_widget import WidgetProvider\n"
            "        self.factory = WidgetProvider\n"
        ),
        (
            "class WidgetProviderPlugin(CloudFormationResourceProviderPlugin):\n"
            '    name = "AWS::Example::Widget"\n'
            "    def load(self):\n"
            "        from localstack.services.example.resource_providers."
            "aws_example_widget import WidgetProvider\n"
            "        if False:\n"
            "            self.factory = WidgetProvider\n"
        ),
    ],
    ids=["missing-plugin-base", "factory-in-dead-branch"],
)
def test_cdk_service_map_rejects_unregistered_provider_shapes(tmp_path, plugin_class):
    provider_dir = tmp_path / "localstack-core/localstack/services/example/resource_providers"
    provider_dir.mkdir(parents=True)
    provider = provider_dir / "aws_example_widget.py"
    provider.write_text('class WidgetProvider:\n    TYPE = "AWS::Example::Widget"\n')
    plugin = provider_dir / "aws_example_widget_plugin.py"
    plugin.write_text(
        "from localstack.services.cloudformation.resource_provider import (\n"
        "    CloudFormationResourceProviderPlugin,\n"
        ")\n\n"
        f"{plugin_class}"
    )

    with pytest.raises(ValueError, match="registration plugin|provider factory"):
        cdk_catalog._resolve_provider_record(
            tmp_path,
            "AWS::Example::Widget",
            {
                "source": provider.relative_to(tmp_path).as_posix(),
                "source_service": "example",
            },
        )


def test_cdk_service_map_distinguishes_nontrivial_handlers_from_stubs(tmp_path):
    provider_dir = tmp_path / "localstack-core/localstack/services/example/resource_providers"
    provider_dir.mkdir(parents=True)
    provider = provider_dir / "aws_example_widget.py"
    provider.write_text(
        "class WidgetProvider:\n"
        '    TYPE = "AWS::Example::Widget"\n'
        "    def create(self, request):\n"
        "        return request\n"
        "    def update(self, request):\n"
        '        """Not implemented yet."""\n'
        "        raise NotImplementedError\n"
        "    def delete(self, request):\n"
        "        if request:\n"
        "            return request\n"
        "        raise NotImplementedError\n"
    )
    (provider_dir / "aws_example_widget.schema.json").write_text(
        json.dumps(
            {
                "typeName": "AWS::Example::Widget",
                "handlers": {"create": {}, "read": {}, "update": {}, "delete": {}},
            }
        )
    )
    (provider_dir / "aws_example_widget_plugin.py").write_text(
        "from localstack.services.cloudformation.resource_provider import (\n"
        "    CloudFormationResourceProviderPlugin,\n"
        ")\n\n"
        "class WidgetProviderPlugin(CloudFormationResourceProviderPlugin):\n"
        '    name = "AWS::Example::Widget"\n'
        "    def load(self):\n"
        "        from localstack.services.example.resource_providers."
        "aws_example_widget import WidgetProvider\n"
        "        self.factory = WidgetProvider\n"
    )

    record = cdk_catalog._resolve_provider_record(
        tmp_path,
        "AWS::Example::Widget",
        {
            "source": provider.relative_to(tmp_path).as_posix(),
            "source_service": "example",
        },
    )

    assert record["handler_contract"] == {
        "schema_source": (
            "localstack-core/localstack/services/example/resource_providers/"
            "aws_example_widget.schema.json"
        ),
        "schema_sha256": cdk_catalog._sha256(
            (provider_dir / "aws_example_widget.schema.json").read_bytes()
        ),
        "schema_declared_handlers": ["create", "delete", "read", "update"],
        "handler_statuses": {
            "create": "method-body-present-unverified",
            "delete": "contains-notimplemented",
            "read": "method-missing",
            "update": "notimplemented-only",
        },
        "static_status": "incomplete-static-handler-surface",
    }
