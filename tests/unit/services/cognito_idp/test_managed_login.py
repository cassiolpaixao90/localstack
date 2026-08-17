import pickle
import struct
import uuid
import zlib

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from tests.unit.services.cognito_idp.test_image_validation import (
    BASELINE_JPEG,
    PROGRESSIVE_JPEG,
)


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _stack(provider, context, name="managed-login"):
    pool = provider.create_user_pool(context, {"PoolName": name})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {"ClientName": f"{name}-client", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    return pool, client


def _settings(color="102030ff"):
    return {
        "categories": {
            "form": {"location": {"horizontal": "CENTER", "vertical": "CENTER"}},
            "global": {"colorSchemeMode": "LIGHT", "spacingDensity": "REGULAR"},
        },
        "componentClasses": {
            "buttons": {"borderRadius": 9},
            "form": {
                "borderRadius": 13,
                "lightMode": {"backgroundColor": "ffffffff", "borderColor": "ccddeeFF"},
            },
            "pageBackground": {"lightMode": {"color": color}},
            "primaryButton": {
                "lightMode": {
                    "defaults": {
                        "backgroundColor": "1122aaff",
                        "textColor": "ffffffff",
                    }
                }
            },
        },
    }


def _png():
    def chunk(name, content):
        return (
            struct.pack(">I", len(content))
            + name
            + content
            + struct.pack(">I", zlib.crc32(name + content) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )


@pytest.mark.parametrize("content", [BASELINE_JPEG, PROGRESSIVE_JPEG])
def test_managed_login_accepts_fully_decodable_jpeg(provider, context, content):
    pool, client = _stack(provider, context, "managed-login-jpeg")
    result = provider.create_managed_login_branding(
        context,
        {
            "Assets": [
                {
                    "Bytes": content,
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "JPEG",
                }
            ],
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert result["Assets"][0]["Bytes"] == content


def test_managed_login_rejects_undecodable_jpeg_and_contract_unsupported_webp(provider, context):
    pool, client = _stack(provider, context, "managed-login-invalid-image")
    scan = BASELINE_JPEG.index(b"\xff\xda")
    invalid_jpeg = BASELINE_JPEG[: scan + 20] + b"\xff\xd9"
    for content, extension in (
        (invalid_jpeg, "JPEG"),
        (b"RIFF\x16\0\0\0WEBPVP8X\x0a\0\0\0" + b"\0" * 10, "WEBP"),
    ):
        with pytest.raises(CommonServiceException):
            provider.create_managed_login_branding(
                context,
                {
                    "Assets": [
                        {
                            "Bytes": content,
                            "Category": "FORM_LOGO",
                            "ColorMode": "LIGHT",
                            "Extension": extension,
                        }
                    ],
                    "ClientId": client["ClientId"],
                    "UserPoolId": pool["Id"],
                },
            )


def test_managed_login_branding_crud_partial_merge_assets_and_isolation(provider, context):
    pool, client = _stack(provider, context)
    created = provider.create_managed_login_branding(
        context,
        {
            "ClientId": client["ClientId"],
            "UseCognitoProvidedValues": True,
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert created["UserPoolId"] == pool["Id"]
    assert created["UseCognitoProvidedValues"] is True
    assert "Settings" not in created and "Assets" not in created
    with pytest.raises(CommonServiceException) as duplicate:
        provider.create_managed_login_branding(
            context,
            {
                "ClientId": client["ClientId"],
                "UseCognitoProvidedValues": True,
                "UserPoolId": pool["Id"],
            },
        )
    assert duplicate.value.code == "ManagedLoginBrandingExistsException"

    merged = provider.describe_managed_login_branding_by_client(
        context,
        {
            "ClientId": client["ClientId"],
            "ReturnMergedResources": True,
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert merged["Settings"]["categories"]["global"]["colorSchemeMode"] == "LIGHT"

    updated = provider.update_managed_login_branding(
        context,
        {
            "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
            "Settings": _settings(),
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert updated["UseCognitoProvidedValues"] is False
    assert updated["Settings"] == _settings()
    first_modified = updated["LastModifiedDate"]

    png = _png()
    with_asset = provider.update_managed_login_branding(
        context,
        {
            "Assets": [
                {
                    "Bytes": png,
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "PNG",
                }
            ],
            "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert with_asset["Settings"] == _settings()
    assert with_asset["Assets"][0]["Bytes"] == png
    assert with_asset["Assets"][0]["ResourceId"]
    assert with_asset["LastModifiedDate"] >= first_modified
    resource_id = with_asset["Assets"][0]["ResourceId"]
    reused = provider.update_managed_login_branding(
        context,
        {
            "Assets": [
                {
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "PNG",
                    "ResourceId": resource_id,
                }
            ],
            "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    assert reused["Assets"][0]["Bytes"] == png
    with pytest.raises(CommonServiceException):
        provider.update_managed_login_branding(
            context,
            {
                "Assets": [
                    {
                        "Category": "FORM_LOGO",
                        "ColorMode": "LIGHT",
                        "Extension": "JPEG",
                        "ResourceId": resource_id,
                    }
                ],
                "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
                "UserPoolId": pool["Id"],
            },
        )

    serialized = pickle.dumps(provider.get_store(context).user_pools[pool["Id"]])
    assert png in serialized
    restored = pickle.loads(serialized)
    assert restored.managed_login_branding[client["ClientId"]].settings == _settings()

    other_pool, _ = _stack(provider, context, "other-managed-login")
    with pytest.raises(CommonServiceException):
        provider.describe_managed_login_branding(
            context,
            {
                "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
                "UserPoolId": other_pool["Id"],
            },
        )

    assert (
        provider.delete_managed_login_branding(
            context,
            {
                "ManagedLoginBrandingId": created["ManagedLoginBrandingId"],
                "UserPoolId": pool["Id"],
            },
        )
        == {}
    )
    with pytest.raises(CommonServiceException):
        provider.describe_managed_login_branding_by_client(
            context,
            {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]},
        )


def test_managed_login_branding_validation_is_atomic(provider, context):
    pool, client = _stack(provider, context)
    created = provider.create_managed_login_branding(
        context,
        {
            "ClientId": client["ClientId"],
            "Settings": _settings(),
            "UserPoolId": pool["Id"],
        },
    )["ManagedLoginBranding"]
    branding_id = created["ManagedLoginBrandingId"]
    invalid_requests = [
        {"UseCognitoProvidedValues": True, "Settings": _settings()},
        {"Settings": {"script": {"html": "<script>alert(1)</script>"}}},
        {
            "Assets": [
                {
                    "Bytes": b"not-a-png",
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "PNG",
                }
            ]
        },
        {
            "Assets": [
                {
                    "Bytes": b"\x89PNG\r\n\x1a\n" + b"x" * 1_000_000,
                    "Category": "FORM_LOGO",
                    "ColorMode": "LIGHT",
                    "Extension": "PNG",
                }
            ]
        },
    ]
    for invalid in invalid_requests:
        with pytest.raises(CommonServiceException):
            provider.update_managed_login_branding(
                context,
                {
                    **invalid,
                    "ManagedLoginBrandingId": branding_id,
                    "UserPoolId": pool["Id"],
                },
            )
        current = provider.describe_managed_login_branding(
            context,
            {"ManagedLoginBrandingId": branding_id, "UserPoolId": pool["Id"]},
        )["ManagedLoginBranding"]
        assert current["Settings"] == _settings()
        assert "Assets" not in current


def test_terms_crud_languages_paging_and_client_cleanup(provider, context):
    pool, client = _stack(provider, context)
    empty_links = provider.create_terms(
        context,
        {
            "ClientId": client["ClientId"],
            "Enforcement": "NONE",
            "TermsName": "privacy-policy",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )["Terms"]
    assert empty_links["Links"] == {}
    provider.delete_terms(context, {"TermsId": empty_links["TermsId"], "UserPoolId": pool["Id"]})
    terms = provider.create_terms(
        context,
        {
            "ClientId": client["ClientId"],
            "Enforcement": "NONE",
            "Links": {
                "cognito:default": "https://example.test/terms",
                "cognito:portuguese-brazil": "https://example.test/pt/termos",
            },
            "TermsName": "terms-of-use",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )["Terms"]
    privacy = provider.create_terms(
        context,
        {
            "ClientId": client["ClientId"],
            "Enforcement": "NONE",
            "Links": {"cognito:default": "https://example.test/privacy?a=1&b=2"},
            "TermsName": "privacy-policy",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )["Terms"]
    with pytest.raises(CommonServiceException) as duplicate:
        provider.create_terms(
            context,
            {
                "ClientId": client["ClientId"],
                "Enforcement": "NONE",
                "Links": {"cognito:default": "https://example.test/other"},
                "TermsName": "terms-of-use",
                "TermsSource": "LINK",
                "UserPoolId": pool["Id"],
            },
        )
    assert duplicate.value.code == "TermsExistsException"

    page = provider.list_terms(context, {"MaxResults": 1, "UserPoolId": pool["Id"]})
    assert len(page["Terms"]) == 1 and page["NextToken"]
    assert set(page["Terms"][0]) == {
        "CreationDate",
        "Enforcement",
        "LastModifiedDate",
        "TermsId",
        "TermsName",
    }
    second = provider.list_terms(
        context,
        {
            "MaxResults": 1,
            "NextToken": page["NextToken"],
            "UserPoolId": pool["Id"],
        },
    )
    assert len(second["Terms"]) == 1
    assert {page["Terms"][0]["TermsId"], second["Terms"][0]["TermsId"]} == {
        terms["TermsId"],
        privacy["TermsId"],
    }
    with pytest.raises(CommonServiceException):
        provider.list_terms(
            context,
            {
                "MaxResults": 1,
                "NextToken": page["NextToken"] + "x",
                "UserPoolId": pool["Id"],
            },
        )

    updated = provider.update_terms(
        context,
        {
            "Links": {"cognito:default": "https://example.test/new-terms"},
            "TermsId": terms["TermsId"],
            "UserPoolId": pool["Id"],
        },
    )["Terms"]
    assert updated["TermsName"] == "terms-of-use"
    assert updated["Links"] == {"cognito:default": "https://example.test/new-terms"}
    assert (
        provider.describe_terms(context, {"TermsId": terms["TermsId"], "UserPoolId": pool["Id"]})[
            "Terms"
        ]
        == updated
    )

    for links in (
        {"cognito:dutch": "javascript:alert(1)"},
        {"cognito:unknown": "https://example.test/unknown"},
        {f"cognito:{index}": "https://example.test" for index in range(14)},
    ):
        with pytest.raises(CommonServiceException):
            provider.update_terms(
                context,
                {"Links": links, "TermsId": terms["TermsId"], "UserPoolId": pool["Id"]},
            )
        assert (
            provider.describe_terms(
                context, {"TermsId": terms["TermsId"], "UserPoolId": pool["Id"]}
            )["Terms"]
            == updated
        )

    provider.delete_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )
    assert provider.list_terms(context, {"UserPoolId": pool["Id"]})["Terms"] == []
    assert provider.get_store(context).user_pools[pool["Id"]].managed_login_branding == {}
