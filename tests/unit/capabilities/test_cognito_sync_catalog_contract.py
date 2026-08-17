from pathlib import Path

from localstack.capabilities.catalog import (
    build_catalog,
    load_botocore_models,
    scan_cloudformation_resources,
    scan_generated_apis,
    scan_providers,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]

OPERATIONS = {
    "BulkPublish",
    "DeleteDataset",
    "DescribeDataset",
    "DescribeIdentityPoolUsage",
    "DescribeIdentityUsage",
    "GetBulkPublishDetails",
    "GetCognitoEvents",
    "GetIdentityPoolConfiguration",
    "ListDatasets",
    "ListIdentityPoolUsage",
    "ListRecords",
    "RegisterDevice",
    "SetCognitoEvents",
    "SetIdentityPoolConfiguration",
    "SubscribeToDataset",
    "UnsubscribeFromDataset",
    "UpdateRecords",
}


def test_cognito_sync_native_catalog_contract():
    generated = scan_generated_apis(PROJECT_ROOT)
    providers = scan_providers(PROJECT_ROOT, generated)
    provider = providers["cognito-sync"][0]

    assert provider.name == "default"
    assert provider.fallback is None
    assert set(provider.handlers) == OPERATIONS
    assert not any(handler.unconditional_notimplemented for handler in provider.handlers.values())

    version, models = load_botocore_models()
    resources, resource_records = scan_cloudformation_resources(PROJECT_ROOT)
    _, catalog = build_catalog(
        version,
        models,
        generated,
        providers,
        resources,
        resource_records,
    )
    service = catalog["services"]["cognito-sync"]
    assert len(service["operation_statuses"]["partial"]) == 17
    assert not service["operation_statuses"]["missing"]
