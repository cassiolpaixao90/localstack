import hashlib
import pickle
import struct
import zlib
from datetime import UTC, datetime, timedelta

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.http import Request, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.cognito_idp.classic_ui import (
    ClassicUIError,
    apply_classic_ui_update,
    classic_markup,
    customization_response,
    inherited_customization,
    safe_image_path,
    validate_classic_css,
    validate_classic_image,
    validate_classic_ui_update,
)
from localstack.services.cognito_idp.endpoints import CognitoIdpOAuthEndpoint
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from tests.unit.services.cognito_idp.test_image_validation import (
    BASELINE_JPEG,
    PROGRESSIVE_JPEG,
)


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = "123456789012"
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


def _png(width=2, height=2):
    def chunk(name, content):
        return (
            struct.pack(">I", len(content))
            + name
            + content
            + struct.pack(">I", zlib.crc32(name + content) & 0xFFFFFFFF)
        )

    rows = b"".join(b"\0" + b"\0" * (width * 4) for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def _noisy_grayscale_png(width=350, height=178):
    payload = bytearray()
    counter = 0
    while len(payload) < width * height:
        payload.extend(hashlib.sha256(str(counter).encode()).digest())
        counter += 1
    rows = b"".join(
        b"\0" + bytes(payload[row * width : (row + 1) * width]) for row in range(height)
    )

    def chunk(name, content):
        return (
            struct.pack(">I", len(content))
            + name
            + content
            + struct.pack(">I", zlib.crc32(name + content) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


CSS = """
.background-customizable { background-color: #fefefe; }
.logo-customizable { max-width: 60%; max-height: 30%; }
.label-customizable { color: navy; font-weight: 600; }
.inputField-customizable { width: 100%; height: 34px; border: 1px solid #ccc; }
.inputField-customizable:focus { border-color: #66afe9; outline: 0; }
.submitButton-customizable { width: 100%; height: 40px; background-color: #337ab7; color: white; text-align: center; }
.submitButton-customizable:hover { background-color: #286090; color: white; }
"""


def test_css_image_update_inheritance_response_markup_and_persistence():
    css, image = validate_classic_ui_update(
        css=CSS,
        image=_png(),
        css_supplied=True,
        image_supplied=True,
    )
    now = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    image_url = safe_image_path("us-east-1_pool", "ALL", "20260810120000000000", "png")
    default = apply_classic_ui_update(
        None,
        client_id="ALL",
        css=css,
        image=image,
        css_supplied=True,
        image_supplied=True,
        image_url=image_url,
        now=now,
    )
    assert default.created_at == default.updated_at == now
    assert default.css_version == "20260810120000000000"
    normalized_css = validate_classic_css(CSS)
    assert customization_response("us-east-1_pool", default) == {
        "ClientId": "ALL",
        "CreationDate": now,
        "CSS": normalized_css,
        "CSSVersion": "20260810120000000000",
        "ImageUrl": image_url,
        "LastModifiedDate": now,
        "UserPoolId": "us-east-1_pool",
    }
    inherited = inherited_customization({"ALL": default}, "client123")
    assert inherited == default and inherited is not default
    style, logo = classic_markup(inherited)
    assert style.startswith('<style id="classic-ui-customization">')
    assert ".submitButton-customizable:hover" in style
    assert logo == (
        '<img class="logo-customizable" alt="" '
        'src="/cognito-idp/classic-ui/us-east-1_pool/ALL/20260810120000000000/logo.png">'
    )
    assert pickle.loads(pickle.dumps(default)) == default

    override = apply_classic_ui_update(
        None,
        client_id="client123",
        css=".label-customizable { color: red; }",
        image=None,
        css_supplied=True,
        image_supplied=False,
        image_url=None,
        now=now + timedelta(seconds=1),
    )
    assert inherited_customization({"ALL": default, "client123": override}, "client123") == override
    css_reset = apply_classic_ui_update(
        override,
        client_id="client123",
        css="",
        image=None,
        css_supplied=True,
        image_supplied=True,
        image_url=None,
        now=now + timedelta(seconds=2),
    )
    assert css_reset.css == "" and css_reset.image is None
    assert css_reset.created_at == override.created_at


@pytest.mark.parametrize(
    "css",
    [
        ".unknown-customizable { color: red; }",
        ".label-customizable, body { color: red; }",
        ".label-customizable { position: fixed; }",
        ".label-customizable { color: url(https://evil.example/x); }",
        ".label-customizable { color: expression(alert(1)); }",
        ".label-customizable { color: red; } @import 'https://evil.example/x';",
        "@media screen { .label-customizable { color: red; } }",
        "@supports(display:grid){.label-customizable{color:red}}",
        "@page { margin: 0; }",
        ".label\\2d customizable { color: red; }",
        ".label-customizable { color: red; } </style><script>alert(1)</script>",
        "/* </style><script>alert(1)</script> */ .label-customizable { color: red; }",
        ".inputField-customizable { border: 101px solid red; }",
    ],
)
def test_css_parser_rejects_selector_property_and_injection_bypasses(css):
    with pytest.raises(ClassicUIError):
        validate_classic_css(css)


def test_css_image_and_wire_bounds_fail_closed():
    with pytest.raises(ClassicUIError):
        validate_classic_css(".label-customizable{color:red}" + " " * 131_073)
    with pytest.raises(ClassicUIError):
        validate_classic_image(b"\xff\xd8" + b"x" * 20 + b"\xff\xd9")
    with pytest.raises(ClassicUIError):
        validate_classic_image(_png(351, 1))

    def chunk(name, content):
        return (
            struct.pack(">I", len(content))
            + name
            + content
            + struct.pack(">I", zlib.crc32(name + content) & 0xFFFFFFFF)
        )

    invalid_pixels = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", b"not-zlib")
        + chunk(b"IEND", b"")
    )
    with pytest.raises(ClassicUIError):
        validate_classic_image(invalid_pixels)
    with pytest.raises(ClassicUIError):
        validate_classic_ui_update(
            css=".label-customizable{color:red}",
            image=b"x" * (100 * 1024 + 1),
            css_supplied=True,
            image_supplied=True,
        )
    noisy = _noisy_grayscale_png()
    assert len(noisy) < 100 * 1024
    oversized_wire_css = ".label-customizable{color:red}" * 1_900
    with pytest.raises(ClassicUIError, match="135 KB"):
        validate_classic_ui_update(
            css=oversized_wire_css,
            image=noisy,
            css_supplied=True,
            image_supplied=True,
        )


@pytest.mark.parametrize("content", [BASELINE_JPEG, PROGRESSIVE_JPEG])
def test_classic_ui_accepts_fully_decodable_jpeg(content):
    assert validate_classic_image(content) == (content, "jpeg")


def test_classic_ui_rejects_jpeg_with_undecodable_entropy():
    scan = BASELINE_JPEG.index(b"\xff\xda")
    with pytest.raises(ClassicUIError, match="JPEG"):
        validate_classic_image(BASELINE_JPEG[: scan + 20] + b"\xff\xd9")


def test_classic_ui_serves_jpeg_with_exact_type_cache_etag_and_path_isolation(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "classic-ui-jpeg-http"})["UserPool"]
    provider.create_user_pool_domain(
        context,
        {
            "Domain": "classic-ui-jpeg-http",
            "ManagedLoginVersion": 1,
            "UserPoolId": pool["Id"],
        },
    )
    item = provider.set_ui_customization(
        context,
        {"ImageFile": BASELINE_JPEG, "UserPoolId": pool["Id"]},
    )["UICustomization"]
    assert item["ImageUrl"].endswith("/logo.jpeg")

    router = Router(dispatcher=handler_dispatcher())
    router.add(CognitoIdpOAuthEndpoint())
    host = "classic-ui-jpeg-http.localhost.localstack.cloud"
    first = router.dispatch(Request("GET", item["ImageUrl"], scheme="https", server=(host, None)))
    assert first.status_code == 200
    assert first.data == BASELINE_JPEG
    assert first.content_type == "image/jpeg"
    assert first.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert first.headers["Content-Security-Policy"] == "default-src 'none'"
    assert first.headers["X-Content-Type-Options"] == "nosniff"
    assert first.headers["ETag"]

    cached = router.dispatch(
        Request(
            "GET",
            item["ImageUrl"],
            headers={"If-None-Match": first.headers["ETag"]},
            scheme="https",
            server=(host, None),
        )
    )
    assert cached.status_code == 304
    assert cached.data == b""
    assert cached.headers["ETag"] == first.headers["ETag"]

    wrong_extension = router.dispatch(
        Request(
            "GET",
            item["ImageUrl"].removesuffix(".jpeg") + ".png",
            scheme="https",
            server=(host, None),
        )
    )
    assert wrong_extension.status_code == 404


def test_safe_local_image_url_rejects_path_and_markup_injection():
    for values in (
        ("bad/pool", "ALL", "20260810120000000000", "png"),
        ("us-east-1_pool", "../../x", "20260810120000000000", "png"),
        ("us-east-1_pool", "ALL", "not-a-version", "png"),
        ("us-east-1_pool", "ALL", "20260810120000000000", "gif"),
    ):
        with pytest.raises(ClassicUIError):
            safe_image_path(*values)

    now = datetime.now(UTC)
    item = apply_classic_ui_update(
        None,
        client_id="ALL",
        css="",
        image=(_png(), "png"),
        css_supplied=True,
        image_supplied=True,
        image_url='javascript:alert(1)"',
        now=now,
    )
    with pytest.raises(ClassicUIError):
        classic_markup(item)


def test_native_ui_customization_default_override_reset_domain_and_client_cleanup(
    provider, context
):
    pool = provider.create_user_pool(context, {"PoolName": "classic-ui"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {"ClientName": "classic-client", "UserPoolId": pool["Id"]},
    )["UserPoolClient"]
    with pytest.raises(CommonServiceException) as no_domain:
        provider.set_ui_customization(context, {"CSS": CSS, "UserPoolId": pool["Id"]})
    assert no_domain.value.code == "InvalidParameterException"

    provider.create_user_pool_domain(
        context,
        {"Domain": "classic-ui-test", "ManagedLoginVersion": 1, "UserPoolId": pool["Id"]},
    )
    assert provider.get_ui_customization(context, {"UserPoolId": pool["Id"]}) == {
        "UICustomization": {}
    }
    default = provider.set_ui_customization(
        context,
        {"CSS": CSS, "ImageFile": _png(), "UserPoolId": pool["Id"]},
    )["UICustomization"]
    assert default["ClientId"] == "ALL"
    assert default["ImageUrl"].endswith("/ALL/" + default["CSSVersion"] + "/logo.png")
    inherited = provider.get_ui_customization(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )["UICustomization"]
    assert inherited == default

    override = provider.set_ui_customization(
        context,
        {
            "CSS": ".label-customizable { color: red; }",
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )["UICustomization"]
    assert override["ClientId"] == client["ClientId"]
    assert "ImageUrl" not in override
    assert override["CreationDate"] == override["LastModifiedDate"]
    reset = provider.set_ui_customization(
        context,
        {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]},
    )["UICustomization"]
    assert reset["CSS"] == "" and "ImageUrl" not in reset
    assert reset["CreationDate"] == override["CreationDate"]
    assert reset["CSSVersion"] > override["CSSVersion"]

    provider.delete_user_pool_domain(
        context, {"Domain": "classic-ui-test", "UserPoolId": pool["Id"]}
    )
    with pytest.raises(CommonServiceException):
        provider.get_ui_customization(
            context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
        )
    provider.create_user_pool_domain(
        context,
        {"Domain": "classic-ui-test", "ManagedLoginVersion": 1, "UserPoolId": pool["Id"]},
    )
    assert (
        provider.get_ui_customization(
            context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
        )["UICustomization"]["CSSVersion"]
        == reset["CSSVersion"]
    )
    provider.delete_user_pool_client(
        context, {"ClientId": client["ClientId"], "UserPoolId": pool["Id"]}
    )
    stored = provider.get_store(context).user_pools[pool["Id"]]
    assert client["ClientId"] not in stored.ui_customizations
    assert "ALL" in stored.ui_customizations
