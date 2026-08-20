import base64
import hashlib
from urllib.parse import urlsplit

import pytest
import requests

from localstack import config
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

_CALLBACK_URL = "https://client.example.test/callback"
_BRANDED_PAGE_COLOR = "#102030ff"
_CLASSIC_BANNER_COLOR = "#a1b2c3"
_PKCE_VERIFIER = "rendering-check-verifier-0123456789-0123456789"


def _pkce_challenge() -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(_PKCE_VERIFIER.encode()).digest())
        .rstrip(b"=")
        .decode()
    )


def _hosted_ui_url(domain: str) -> str:
    endpoint = urlsplit(config.internal_service_url())
    return f"{endpoint.scheme}://{domain}.localhost.localstack.cloud:{endpoint.port}"


def _start_transaction(session: requests.Session, base_url: str, client_id: str) -> None:
    authorize = session.get(
        f"{base_url}/oauth2/authorize",
        params={
            "client_id": client_id,
            "code_challenge": _pkce_challenge(),
            "code_challenge_method": "S256",
            "redirect_uri": _CALLBACK_URL,
            "response_type": "code",
            "scope": "openid",
            "state": "rendering-check",
        },
        allow_redirects=False,
        timeout=5,
    )
    assert authorize.status_code == 302
    assert urlsplit(authorize.headers["Location"]).path == "/login"


@pytest.fixture
def hosted_ui_client(aws_client):
    pool_id = None
    domains = []
    try:
        pool = aws_client.cognito_idp.create_user_pool(PoolName=f"pool-{short_uid()}")["UserPool"]
        pool_id = pool["Id"]
        client = aws_client.cognito_idp.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=f"client-{short_uid()}",
            AllowedOAuthFlows=["code"],
            AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthScopes=["openid"],
            CallbackURLs=[_CALLBACK_URL],
            SupportedIdentityProviders=["COGNITO"],
        )["UserPoolClient"]

        def create_domain(managed_login_version=None):
            domain = f"ui-{short_uid()}"
            request = {"Domain": domain, "UserPoolId": pool_id}
            if managed_login_version is not None:
                request["ManagedLoginVersion"] = managed_login_version
            aws_client.cognito_idp.create_user_pool_domain(**request)
            domains.append(domain)
            return domain

        yield pool_id, client["ClientId"], create_domain
    finally:
        for domain in domains:
            aws_client.cognito_idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        if pool_id is not None:
            aws_client.cognito_idp.delete_user_pool(UserPoolId=pool_id)


class TestHostedUiRendering:
    @markers.aws.only_localstack
    def test_managed_login_branding_and_terms_change_rendered_pages(
        self, aws_client, hosted_ui_client
    ):
        pool_id, client_id, create_domain = hosted_ui_client
        domain = create_domain(managed_login_version=2)
        base_url = _hosted_ui_url(domain)

        session = requests.Session()
        _start_transaction(session, base_url, client_id)
        default_login = session.get(f"{base_url}/login", timeout=5)
        assert default_login.status_code == 200
        assert _BRANDED_PAGE_COLOR not in default_login.text

        aws_client.cognito_idp.create_managed_login_branding(
            UserPoolId=pool_id,
            ClientId=client_id,
            Settings={
                "categories": {
                    "form": {"location": {"horizontal": "CENTER", "vertical": "CENTER"}},
                    "global": {"colorSchemeMode": "LIGHT", "spacingDensity": "REGULAR"},
                },
                "componentClasses": {
                    "pageBackground": {"lightMode": {"color": _BRANDED_PAGE_COLOR.lstrip("#")}},
                },
            },
        )
        for terms_name, link in (
            ("privacy-policy", "https://example.test/privacy"),
            ("terms-of-use", "https://example.test/terms"),
        ):
            aws_client.cognito_idp.create_terms(
                ClientId=client_id,
                Enforcement="NONE",
                Links={"cognito:default": link},
                TermsName=terms_name,
                TermsSource="LINK",
                UserPoolId=pool_id,
            )

        session = requests.Session()
        _start_transaction(session, base_url, client_id)
        branded_login = session.get(f"{base_url}/login", timeout=5)
        assert branded_login.status_code == 200
        assert _BRANDED_PAGE_COLOR in branded_login.text

        signup = session.get(f"{base_url}/signup", timeout=5)
        assert signup.status_code == 200
        assert "https://example.test/privacy" in signup.text
        assert "https://example.test/terms" in signup.text

    @markers.aws.only_localstack
    def test_classic_ui_customization_changes_rendered_page(self, aws_client, hosted_ui_client):
        pool_id, client_id, create_domain = hosted_ui_client
        domain = create_domain()
        base_url = _hosted_ui_url(domain)

        session = requests.Session()
        _start_transaction(session, base_url, client_id)
        default_login = session.get(f"{base_url}/login", timeout=5)
        assert default_login.status_code == 200
        assert _CLASSIC_BANNER_COLOR not in default_login.text

        aws_client.cognito_idp.set_ui_customization(
            UserPoolId=pool_id,
            ClientId=client_id,
            CSS=f".banner-customizable {{ background-color: {_CLASSIC_BANNER_COLOR}; }}",
        )

        session = requests.Session()
        _start_transaction(session, base_url, client_id)
        customized_login = session.get(f"{base_url}/login", timeout=5)
        assert customized_login.status_code == 200
        assert _CLASSIC_BANNER_COLOR in customized_login.text
