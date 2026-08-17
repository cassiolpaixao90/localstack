import base64
import hashlib
import os
import pickle
import uuid
import zlib
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit
from xml.dom import minidom

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.x509.oid import NameOID

from localstack import config
from localstack.aws.api import RequestContext
from localstack.http import Request, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.cognito_idp.endpoints import (
    CognitoIdpJwksEndpoint,
    CognitoIdpOAuthEndpoint,
)
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import (
    CognitoIdpProvider,
    _identity_provider_client_secret,
)
from localstack.services.cognito_idp.saml import (
    ENVELOPED_SIGNATURE,
    EXCLUSIVE_C14N,
    RSA_SHA256,
    SAML2_BEARER,
    SAML2_PROTOCOL,
    SAML2_REDIRECT,
    SAML2_SUCCESS,
    SAML_ASSERTION,
    SAML_METADATA,
    SAML_PROTOCOL,
    SHA256,
    XMLDSIG,
    SamlFederationError,
    _exclusive_c14n,
    saml_metadata,
    validate_saml_response,
)
from localstack.services.cognito_idp.tokens import decode_jwt_segment

CALLBACK = "https://app.example.test/callback"
DOMAIN = "saml-browser-test"
HOST = f"{DOMAIN}.localhost.localstack.cloud"
VERIFIER = "v" * 43


def _request(method, path, *, query=None, form=None, cookie=None, host=HOST):
    headers = {}
    body = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(form)
    if cookie:
        headers["Cookie"] = cookie
    return Request(
        method,
        path,
        headers=headers,
        body=body,
        query_string=urlencode(query or {}),
        remote_addr="127.0.0.1",
        scheme="https",
        server=(host, None),
    )


def _cookies(response):
    jar = SimpleCookie()
    for header in response.headers.getlist("Set-Cookie"):
        jar.load(header)
    return "; ".join(f"{key}={value.value}" for key, value in jar.items())


def _challenge():
    return (
        base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
    )


@pytest.fixture
def signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local SAML IdP")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    encoded_certificate = base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)
    ).decode()
    return private_key, encoded_certificate


def _metadata(encoded_certificate, sso_url):
    return f'''<md:EntityDescriptor xmlns:md="{SAML_METADATA}" entityID="https://idp.example.test/entity">
<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="{SAML2_PROTOCOL}">
<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{XMLDSIG}"><ds:X509Data><ds:X509Certificate>{encoded_certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleSignOnService Binding="{SAML2_REDIRECT}" Location="{sso_url}"/>
</md:IDPSSODescriptor></md:EntityDescriptor>'''


def _instant(value):
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signed_response(
    private_key,
    *,
    pool_id,
    acs_url,
    request_id,
    assertion_id="_assertion-one",
    email="saml@example.test",
    sign_assertion=False,
):
    now = datetime.now(UTC)
    response_id = f"_response-{uuid.uuid4().hex}"
    target_id = assertion_id if sign_assertion else response_id
    signature_xml = f'''<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXCLUSIVE_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#{target_id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_SIGNATURE}"/><ds:Transform Algorithm="{EXCLUSIVE_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>'''
    xml = f'''<samlp:Response xmlns:samlp="{SAML_PROTOCOL}" xmlns:saml="{SAML_ASSERTION}" xmlns:ds="{XMLDSIG}" ID="{response_id}" Version="2.0" IssueInstant="{_instant(now)}" Destination="{acs_url}" InResponseTo="{request_id}">
<saml:Issuer>https://idp.example.test/entity</saml:Issuer>
{"" if sign_assertion else signature_xml}
<samlp:Status><samlp:StatusCode Value="{SAML2_SUCCESS}"/></samlp:Status>
<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{_instant(now)}">
<saml:Issuer>https://idp.example.test/entity</saml:Issuer>
{signature_xml if sign_assertion else ""}
<saml:Subject><saml:NameID>saml-subject</saml:NameID><saml:SubjectConfirmation Method="{SAML2_BEARER}"><saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{acs_url}" NotOnOrAfter="{_instant(now + timedelta(minutes=5))}"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{_instant(now - timedelta(minutes=1))}" NotOnOrAfter="{_instant(now + timedelta(minutes=5))}"><saml:AudienceRestriction><saml:Audience>urn:amazon:cognito:sp:{pool_id}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AuthnStatement AuthnInstant="{_instant(now)}"/>
<saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion></samlp:Response>'''
    document = minidom.parseString(xml.encode())
    signature = document.getElementsByTagNameNS(XMLDSIG, "Signature")[0]
    signed_element = (
        document.getElementsByTagNameNS(SAML_ASSERTION, "Assertion")[0]
        if sign_assertion
        else document.documentElement
    )
    clone = signed_element.cloneNode(deep=True)
    clone_signature = clone.getElementsByTagNameNS(XMLDSIG, "Signature")[0]
    clone_signature.parentNode.removeChild(clone_signature)
    digest = base64.b64encode(hashlib.sha256(_exclusive_c14n(clone)).digest()).decode()
    document.getElementsByTagNameNS(XMLDSIG, "DigestValue")[0].appendChild(
        document.createTextNode(digest)
    )
    signed_info = signature.getElementsByTagNameNS(XMLDSIG, "SignedInfo")[0]
    signature_value = private_key.sign(
        _exclusive_c14n(signed_info), padding.PKCS1v15(), hashes.SHA256()
    )
    document.getElementsByTagNameNS(XMLDSIG, "SignatureValue")[0].appendChild(
        document.createTextNode(base64.b64encode(signature_value).decode())
    )
    return base64.b64encode(document.toxml(encoding="utf-8")).decode()


def _encrypt_assertion(encoded_response, certificate_pem):
    document = minidom.parseString(base64.b64decode(encoded_response))
    assertion = document.getElementsByTagNameNS(SAML_ASSERTION, "Assertion")[0]
    # XML Encryption carries the encrypted element as an independent octet
    # stream, so namespace declarations inherited from Response must be made
    # explicit before encryption.
    assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", SAML_ASSERTION)
    assertion.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", XMLDSIG)
    plaintext = assertion.toxml(encoding="utf-8")
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    encrypted_key = certificate.public_key().encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    encrypted = minidom.parseString(
        f'''<saml:EncryptedAssertion xmlns:saml="{SAML_ASSERTION}" xmlns:ds="{XMLDSIG}" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>{base64.b64encode(encrypted_key).decode()}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{base64.b64encode(iv + ciphertext).decode()}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>'''
    ).documentElement
    assertion.parentNode.replaceChild(encrypted, assertion)
    return base64.b64encode(document.toxml(encoding="utf-8")).decode()


def test_saml_metadata_rejects_entities_and_untrusted_shape(
    signing_material, httpserver, monkeypatch
):
    _, certificate = signing_material
    upstream = httpserver.url_for("").rstrip("/")
    monkeypatch.setattr(config, "COGNITO_IDP_EGRESS_ALLOWLIST", [urlsplit(upstream).netloc])
    parsed = saml_metadata({"MetadataFile": _metadata(certificate, f"{upstream}/sso")})
    assert parsed["sso_redirect"] == f"{upstream}/sso"
    httpserver.expect_request("/metadata", method="GET").respond_with_data(
        _metadata(certificate, f"{upstream}/sso"),
        content_type="application/samlmetadata+xml",
    )
    assert saml_metadata({"MetadataURL": f"{upstream}/metadata"})["entity_id"] == (
        "https://idp.example.test/entity"
    )
    with pytest.raises(SamlFederationError):
        saml_metadata({"MetadataFile": '<!DOCTYPE x [<!ENTITY x "boom">]><x>&x;</x>'})
    with pytest.raises(SamlFederationError):
        saml_metadata({"MetadataFile": "<md:EntityDescriptor/>"})


def test_saml_hosted_ui_signed_response_code_pipeline_and_replay(
    signing_material, httpserver, monkeypatch
):
    private_key, certificate = signing_material
    upstream = httpserver.url_for("").rstrip("/")
    monkeypatch.setattr(config, "COGNITO_IDP_EGRESS_ALLOWLIST", [urlsplit(upstream).netloc])
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "saml-browser"})["UserPool"]
    provider.create_identity_provider(
        context,
        {
            "AttributeMapping": {"email": "mail"},
            "ProviderDetails": {
                "MetadataFile": _metadata(certificate, f"{upstream}/sso"),
                "RequestSigningAlgorithm": "rsa-sha256",
            },
            "ProviderName": "CorporateSAML",
            "ProviderType": "SAML",
            "UserPoolId": pool["Id"],
        },
    )
    client = provider.create_user_pool_client(
        context,
        {
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email"],
            "CallbackURLs": [CALLBACK],
            "ClientName": "saml-public",
            "SupportedIdentityProviders": ["CorporateSAML"],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.create_user_pool_domain(context, {"Domain": DOMAIN, "UserPoolId": pool["Id"]})
    router = Router(dispatcher=handler_dispatcher())
    router.add(CognitoIdpJwksEndpoint())
    router.add(CognitoIdpOAuthEndpoint())

    def begin():
        response = router.dispatch(
            _request(
                "GET",
                "/oauth2/authorize",
                query={
                    "client_id": client["ClientId"],
                    "code_challenge": _challenge(),
                    "code_challenge_method": "S256",
                    "redirect_uri": CALLBACK,
                    "response_type": "code",
                    "scope": "openid email",
                    "state": "app-state",
                },
            )
        )
        assert response.headers["Location"] == "/login"
        cookie = _cookies(response)
        login = router.dispatch(_request("GET", "/login", cookie=cookie))
        assert b"Continue with CorporateSAML" in login.data
        selected = router.dispatch(
            _request(
                "GET",
                "/login",
                cookie=cookie,
                query={"identity_provider": "CorporateSAML"},
            )
        )
        query = parse_qs(urlsplit(selected.headers["Location"]).query)
        signed_query = urlencode(
            [
                ("SAMLRequest", query["SAMLRequest"][0]),
                ("RelayState", query["RelayState"][0]),
                ("SigAlg", query["SigAlg"][0]),
            ]
        )
        signing_certificate = x509.load_pem_x509_certificate(
            provider.get_signing_certificate(context, {"UserPoolId": pool["Id"]})[
                "Certificate"
            ].encode()
        )
        signing_certificate.public_key().verify(
            base64.b64decode(query["Signature"][0]),
            signed_query.encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        request_xml = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15)
        request_document = minidom.parseString(request_xml)
        return (
            response,
            query["RelayState"][0],
            request_document.documentElement.getAttribute("ID"),
            request_document.documentElement.getAttribute("AssertionConsumerServiceURL"),
        )

    authorize, relay_state, request_id, acs_url = begin()
    saml_response = _signed_response(
        private_key,
        pool_id=pool["Id"],
        acs_url=acs_url,
        request_id=request_id,
    )
    with cognito_idp_stores.lock:
        stored_provider = (
            cognito_idp_stores[context.account_id][context.region]
            .user_pools[pool["Id"]]
            .identity_providers["CorporateSAML"]
        )
    validate_saml_response(
        saml_response,
        stored_provider,
        pool_id=pool["Id"],
        acs_url=acs_url,
        request_id_hash=hashlib.sha256(request_id.encode()).hexdigest(),
        now=datetime.now(UTC),
    )
    tampered = base64.b64encode(
        base64.b64decode(saml_response).replace(b"saml@example.test", b"evil@example.test")
    ).decode()
    with pytest.raises(SamlFederationError):
        validate_saml_response(
            tampered,
            stored_provider,
            pool_id=pool["Id"],
            acs_url=acs_url,
            request_id_hash=hashlib.sha256(request_id.encode()).hexdigest(),
            now=datetime.now(UTC),
        )
    callback = router.dispatch(
        _request(
            "POST",
            "/saml2/idpresponse",
            cookie=_cookies(authorize),
            form={"RelayState": relay_state, "SAMLResponse": saml_response},
        )
    )
    assert callback.status_code == 302
    callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
    assert callback_query["state"] == ["app-state"]
    token = router.dispatch(
        _request(
            "POST",
            "/oauth2/token",
            form={
                "client_id": client["ClientId"],
                "code": callback_query["code"][0],
                "code_verifier": VERIFIER,
                "grant_type": "authorization_code",
                "redirect_uri": CALLBACK,
            },
        )
    )
    claims = decode_jwt_segment(token.json["id_token"].split(".")[1])
    assert claims["email"] == "saml@example.test"
    assert claims["identities"][0]["providerType"] == "SAML"

    second, second_relay, second_request_id, second_acs = begin()
    replayed_assertion = _signed_response(
        private_key,
        pool_id=pool["Id"],
        acs_url=second_acs,
        request_id=second_request_id,
    )
    replay = router.dispatch(
        _request(
            "POST",
            "/saml2/idpresponse",
            cookie=_cookies(second),
            form={"RelayState": second_relay, "SAMLResponse": replayed_assertion},
        )
    )
    assert parse_qs(urlsplit(replay.headers["Location"]).query)["error"] == [
        "temporarily_unavailable"
    ]
    with cognito_idp_stores.lock:
        store = cognito_idp_stores[context.account_id][context.region]
        assert len(store.saml_replays) == 1

    with cognito_idp_stores.lock:
        for domain in list(store.user_pool_domains.values()):
            store.DOMAIN_LOCATIONS.pop(domain.local_hostname, None)
        store.POOL_LOCATIONS.pop(pool["Id"], None)
        cognito_idp_stores.pop(context.account_id, None)


def test_saml_encrypted_assertion_requires_provider_key_and_never_stores_it_plaintext(
    signing_material, httpserver, monkeypatch
):
    private_key, certificate = signing_material
    upstream = httpserver.url_for("").rstrip("/")
    monkeypatch.setattr(config, "COGNITO_IDP_EGRESS_ALLOWLIST", [urlsplit(upstream).netloc])
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "saml-encrypted"})["UserPool"]
    described = provider.create_identity_provider(
        context,
        {
            "AttributeMapping": {"email": "mail"},
            "ProviderDetails": {
                "EncryptedResponses": "true",
                "MetadataFile": _metadata(certificate, f"{upstream}/sso"),
                "RequestSigningAlgorithm": "rsa-sha256",
            },
            "ProviderName": "EncryptedSAML",
            "ProviderType": "SAML",
            "UserPoolId": pool["Id"],
        },
    )["IdentityProvider"]
    stored_pool = provider.get_store(context).user_pools[pool["Id"]]
    stored_provider = stored_pool.identity_providers["EncryptedSAML"]
    encryption_key = _identity_provider_client_secret(stored_pool, stored_provider)
    assert "PRIVATE KEY" in encryption_key
    assert encryption_key.encode() not in pickle.dumps(stored_provider)
    request_id = "_encrypted-request"
    acs_url = f"https://{HOST}/saml2/idpresponse"
    signed = _signed_response(
        private_key,
        pool_id=pool["Id"],
        acs_url=acs_url,
        request_id=request_id,
        assertion_id="_encrypted-assertion",
        sign_assertion=True,
    )
    encrypted = _encrypt_assertion(
        signed, described["ProviderDetails"]["ActiveEncryptionCertificate"]
    )
    claims, _, _ = validate_saml_response(
        encrypted,
        stored_provider,
        pool_id=pool["Id"],
        acs_url=acs_url,
        request_id_hash=hashlib.sha256(request_id.encode()).hexdigest(),
        now=datetime.now(UTC),
        encryption_private_key=encryption_key,
    )
    assert claims["mail"] == "saml@example.test"
    with pytest.raises(SamlFederationError):
        validate_saml_response(
            signed,
            stored_provider,
            pool_id=pool["Id"],
            acs_url=acs_url,
            request_id_hash=hashlib.sha256(request_id.encode()).hexdigest(),
            now=datetime.now(UTC),
            encryption_private_key=encryption_key,
        )
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(context.account_id, None)
