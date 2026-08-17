from pathlib import Path

from localstack.capabilities.catalog import (
    build_catalog,
    load_botocore_models,
    scan_cloudformation_resources,
    scan_generated_apis,
    scan_providers,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_cognito_identity_native_catalog_contract():
    generated = scan_generated_apis(PROJECT_ROOT)
    providers = scan_providers(PROJECT_ROOT, generated)
    provider = providers["cognito-identity"][0]

    assert provider.name == "default"
    assert provider.fallback is None
    assert set(provider.handlers) == {
        "CreateIdentityPool",
        "DeleteIdentities",
        "DeleteIdentityPool",
        "DescribeIdentity",
        "DescribeIdentityPool",
        "GetCredentialsForIdentity",
        "GetId",
        "GetIdentityPoolRoles",
        "GetOpenIdToken",
        "GetOpenIdTokenForDeveloperIdentity",
        "GetPrincipalTagAttributeMap",
        "ListIdentities",
        "ListIdentityPools",
        "ListTagsForResource",
        "LookupDeveloperIdentity",
        "MergeDeveloperIdentities",
        "SetPrincipalTagAttributeMap",
        "SetIdentityPoolRoles",
        "TagResource",
        "UnlinkDeveloperIdentity",
        "UnlinkIdentity",
        "UntagResource",
        "UpdateIdentityPool",
    }
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
    service = catalog["services"]["cognito-identity"]
    assert len(service["operation_statuses"]["partial"]) == 23
    assert not service["operation_statuses"]["missing"]
    assert "GetCredentialsForIdentity" in service["operation_statuses"]["partial"]
