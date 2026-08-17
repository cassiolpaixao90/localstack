from urllib.parse import urlsplit

import pytest

from tests.aws.services.cognito_idp import test_amplify_v6_expo_web as expo_web


def test_browser_url_allowlist_rejects_prefix_confusion():
    app = "http://127.0.0.1:4100"
    api = "http://abc.execute-api.localhost.localstack.cloud:4575/prod"
    cognito = "https://cognito-idp.us-east-1.amazonaws.com"

    assert expo_web._allowed_browser_url(f"{app}/home", app, api, cognito)
    assert expo_web._allowed_browser_url(f"{api}/v1/profile", app, api, cognito)
    assert expo_web._allowed_browser_url(f"{cognito}/", app, api, cognito)
    assert not expo_web._allowed_browser_url("http://127.0.0.1:4100.evil.test/", app, api, cognito)
    assert not expo_web._allowed_browser_url(
        "http://abc.execute-api.localhost.localstack.cloud:4575/product", app, api, cognito
    )
    assert not expo_web._allowed_browser_url(f"{cognito}/malicious", app, api, cognito)


def test_local_endpoint_is_loopback_with_explicit_port(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:4575")
    assert expo_web._local_endpoint() == "http://127.0.0.1:4575"

    for endpoint in (
        "http://127.0.0.1",
        "http://127.0.0.1:4575/path",
        "https://cognito-idp.us-east-1.amazonaws.com",
    ):
        monkeypatch.setenv("AWS_ENDPOINT_URL", endpoint)
        with pytest.raises(AssertionError):
            expo_web._local_endpoint()


def test_cognito_browser_headers_are_closed_to_observed_amplify_contract():
    assert expo_web.COGNITO_BROWSER_HEADERS == {
        "amz-sdk-invocation-id",
        "amz-sdk-request",
        "cache-control",
        "content-type",
        "x-amz-target",
        "x-amz-user-agent",
    }
    assert "authorization" not in expo_web.COGNITO_BROWSER_HEADERS


def test_origin_comparison_includes_scheme_host_and_port():
    expected = urlsplit("http://127.0.0.1:4100")
    assert expo_web._same_origin(urlsplit("http://127.0.0.1:4100/home"), expected)
    assert not expo_web._same_origin(urlsplit("https://127.0.0.1:4100/home"), expected)
    assert not expo_web._same_origin(urlsplit("http://127.0.0.1:4101/home"), expected)
