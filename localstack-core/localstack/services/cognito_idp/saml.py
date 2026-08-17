from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import re
import ssl
import zlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode
from xml.dom import Node, minidom

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.x509.oid import NameOID

from localstack import config
from localstack.services.cognito_idp.federation import (
    OidcFederationError,
    _PinnedHTTPSConnection,
    _validated_target,
)
from localstack.services.cognito_idp.models import CognitoIdentityProvider, UserPool

SAML_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"
XMLNS = "http://www.w3.org/2000/xmlns/"
SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML2_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
SAML2_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
SAML2_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SAML2_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
XMLENC = "http://www.w3.org/2001/04/xmlenc#"
RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

_MAX_METADATA_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024
_MAX_CERTIFICATES = 5
_MAX_ATTRIBUTES = 64
_MAX_ATTRIBUTE_VALUES = 10
_MAX_ATTRIBUTE_VALUE = 2048
_CLOCK_SKEW = timedelta(seconds=60)
_MAX_ASSERTION_LIFETIME = timedelta(hours=12)
_METADATA_TTL = timedelta(hours=6)
_ISO_INSTANT = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<fraction>\.\d{1,6})?Z$"
)


class SamlFederationError(OidcFederationError):
    pass


class SamlSignatureKeyError(SamlFederationError):
    pass


def saml_signing_certificate(pool: UserPool) -> str:
    if pool.saml_signing_certificate is not None:
        return pool.saml_signing_certificate
    private_key = serialization.load_pem_private_key(
        pool.access_signing_private_key_pem, password=None
    )
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Cognito User Pool {pool.pool_id}")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    pool.saml_signing_certificate = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return pool.saml_signing_certificate


def generate_saml_encryption_material(provider_name: str) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Cognito SAML {provider_name}")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return private_pem, certificate_pem


def saml_metadata(details: dict[str, str]) -> dict[str, Any]:
    if metadata_file := details.get("MetadataFile"):
        payload = metadata_file.encode()
    elif metadata_url := details.get("MetadataURL"):
        payload = _secure_xml_request(metadata_url)
    else:
        raise SamlFederationError("SAML metadata source is missing")
    return _parse_metadata(payload)


def refresh_saml_metadata(provider: CognitoIdentityProvider) -> dict[str, Any]:
    now = datetime.now(UTC)
    if (
        provider.discovery_document is not None
        and provider.discovery_expires_at is not None
        and provider.discovery_expires_at > now
    ):
        return dict(provider.discovery_document)
    document = saml_metadata(provider.provider_details)
    provider.discovery_document = document
    provider.discovery_expires_at = now + _METADATA_TTL
    return dict(document)


def saml_authorization_location(
    provider: CognitoIdentityProvider,
    pool: UserPool,
    *,
    acs_url: str,
    request_id: str,
    relay_state: str,
    now: datetime,
) -> str:
    metadata = refresh_saml_metadata(provider)
    issue_instant = _format_instant(now)
    issuer = f"urn:amazon:cognito:sp:{pool.pool_id}"
    request = (
        f'<samlp:AuthnRequest xmlns:samlp="{SAML_PROTOCOL}" '
        f'xmlns:saml="{SAML_ASSERTION}" ID="{_xml_attribute(request_id)}" '
        f'Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{_xml_attribute(metadata["sso_redirect"])}" '
        f'AssertionConsumerServiceURL="{_xml_attribute(acs_url)}" '
        f'ProtocolBinding="{SAML2_POST}">'
        f"<saml:Issuer>{_xml_text(issuer)}</saml:Issuer>"
        "</samlp:AuthnRequest>"
    ).encode()
    compressor = zlib.compressobj(level=9, wbits=-15)
    encoded_request = base64.b64encode(compressor.compress(request) + compressor.flush()).decode()
    parameters = [("SAMLRequest", encoded_request), ("RelayState", relay_state)]
    if provider.provider_details.get("RequestSigningAlgorithm") == "rsa-sha256":
        parameters.append(("SigAlg", RSA_SHA256))
        signed_query = urlencode(parameters)
        private_key = serialization.load_pem_private_key(
            pool.access_signing_private_key_pem, password=None
        )
        signature = private_key.sign(signed_query.encode(), padding.PKCS1v15(), hashes.SHA256())
        parameters.append(("Signature", base64.b64encode(signature).decode()))
    separator = "&" if "?" in metadata["sso_redirect"] else "?"
    return f"{metadata['sso_redirect']}{separator}{urlencode(parameters)}"


def validate_saml_response(
    encoded_response: str,
    provider: CognitoIdentityProvider,
    *,
    pool_id: str,
    acs_url: str,
    request_id_hash: str,
    now: datetime,
    encryption_private_key: str = "",
) -> tuple[dict[str, str], str, datetime]:
    if not isinstance(encoded_response, str) or not 1 <= len(encoded_response) <= 100_000:
        raise SamlFederationError("Invalid SAMLResponse")
    try:
        payload = base64.b64decode(encoded_response, validate=True)
    except (TypeError, ValueError) as error:
        raise SamlFederationError("Invalid SAMLResponse encoding") from error
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise SamlFederationError("SAMLResponse exceeds limit")
    document = _safe_xml_document(payload)
    response = document.documentElement
    if response.namespaceURI != SAML_PROTOCOL or response.localName != "Response":
        raise SamlFederationError("SAML root must be Response")
    encrypted_assertions = _direct_elements(response, SAML_ASSERTION, "EncryptedAssertion")
    encryption_required = provider.provider_details.get("EncryptedResponses") == "true"
    if encrypted_assertions:
        if not encryption_required or len(encrypted_assertions) != 1 or not encryption_private_key:
            raise SamlFederationError("Unexpected encrypted SAML assertion")
        assertion = _decrypt_assertion(encrypted_assertions[0], encryption_private_key)
        response.replaceChild(assertion, encrypted_assertions[0])
    elif encryption_required:
        raise SamlFederationError("Encrypted SAML assertion is required")
    assertions = _descendants(response, SAML_ASSERTION, "Assertion")
    if len(assertions) != 1:
        raise SamlFederationError("SAMLResponse must contain one Assertion")
    assertion = assertions[0]
    try:
        _verify_xml_signature(document, response, assertion, refresh_saml_metadata(provider))
    except SamlSignatureKeyError:
        if "MetadataURL" not in provider.provider_details:
            raise
        provider.discovery_expires_at = None
        _verify_xml_signature(document, response, assertion, refresh_saml_metadata(provider))
    if assertion.getAttribute("Version") != "2.0" or not _instant_within(
        assertion.getAttribute("IssueInstant"), now, _MAX_ASSERTION_LIFETIME
    ):
        raise SamlFederationError("Invalid SAML Assertion version or timestamp")
    request_id = response.getAttribute("InResponseTo")
    if not request_id or not hmac.compare_digest(
        hashlib.sha256(request_id.encode()).hexdigest(), request_id_hash
    ):
        raise SamlFederationError("SAML InResponseTo mismatch")
    if (
        response.getAttribute("Version") != "2.0"
        or response.getAttribute("Destination") != acs_url
        or not _instant_within(response.getAttribute("IssueInstant"), now, _CLOCK_SKEW)
    ):
        raise SamlFederationError("Invalid SAML Response binding")
    status_codes = _descendants(response, SAML_PROTOCOL, "StatusCode")
    if len(status_codes) != 1 or status_codes[0].getAttribute("Value") != SAML2_SUCCESS:
        raise SamlFederationError("SAML status is not success")
    metadata = refresh_saml_metadata(provider)
    issuers = _direct_elements(assertion, SAML_ASSERTION, "Issuer")
    if len(issuers) != 1 or _text(issuers[0]) != metadata["entity_id"]:
        raise SamlFederationError("SAML issuer mismatch")
    conditions = _direct_elements(assertion, SAML_ASSERTION, "Conditions")
    if len(conditions) != 1:
        raise SamlFederationError("SAML Conditions are required")
    not_before = _parse_instant(conditions[0].getAttribute("NotBefore"))
    not_after = _parse_instant(conditions[0].getAttribute("NotOnOrAfter"))
    if (
        not_before > now + _CLOCK_SKEW
        or not_after <= now - _CLOCK_SKEW
        or not_after - not_before > _MAX_ASSERTION_LIFETIME
    ):
        raise SamlFederationError("SAML assertion is outside its validity window")
    audiences = _descendants(conditions[0], SAML_ASSERTION, "Audience")
    expected_audience = f"urn:amazon:cognito:sp:{pool_id}"
    if len(audiences) != 1 or _text(audiences[0]) != expected_audience:
        raise SamlFederationError("SAML audience mismatch")
    confirmations = _descendants(assertion, SAML_ASSERTION, "SubjectConfirmation")
    valid_confirmation = False
    for confirmation in confirmations:
        if confirmation.getAttribute("Method") != SAML2_BEARER:
            continue
        data = _direct_elements(confirmation, SAML_ASSERTION, "SubjectConfirmationData")
        if len(data) != 1:
            continue
        confirmation_after = _parse_instant(data[0].getAttribute("NotOnOrAfter"))
        confirmation_request = data[0].getAttribute("InResponseTo")
        valid_confirmation = (
            data[0].getAttribute("Recipient") == acs_url
            and confirmation_after > now - _CLOCK_SKEW
            and confirmation_after <= now + _MAX_ASSERTION_LIFETIME
            and confirmation_request == request_id
        )
        if valid_confirmation:
            break
    if not valid_confirmation:
        raise SamlFederationError("Invalid SAML bearer confirmation")
    name_ids = _descendants(assertion, SAML_ASSERTION, "NameID")
    if len(name_ids) != 1 or not 1 <= len(_text(name_ids[0])) <= 2048:
        raise SamlFederationError("SAML NameID is required")
    authn = _direct_elements(assertion, SAML_ASSERTION, "AuthnStatement")
    if len(authn) != 1 or not _instant_within(
        authn[0].getAttribute("AuthnInstant"), now, _MAX_ASSERTION_LIFETIME
    ):
        raise SamlFederationError("Invalid SAML AuthnStatement")
    claims = {"NameID": _text(name_ids[0]), "sub": _text(name_ids[0])}
    attributes = _descendants(assertion, SAML_ASSERTION, "Attribute")
    if len(attributes) > _MAX_ATTRIBUTES:
        raise SamlFederationError("SAML attribute count exceeds limit")
    for attribute in attributes:
        name = attribute.getAttribute("Name")
        values = _direct_elements(attribute, SAML_ASSERTION, "AttributeValue")
        if (
            not 1 <= len(name) <= 2048
            or not 1 <= len(values) <= _MAX_ATTRIBUTE_VALUES
            or name in claims
        ):
            raise SamlFederationError("Invalid SAML Attribute")
        parsed_values = [_text(value) for value in values]
        if any(not 1 <= len(value) <= _MAX_ATTRIBUTE_VALUE for value in parsed_values):
            raise SamlFederationError("Invalid SAML AttributeValue")
        claims[name] = (
            parsed_values[0] if len(parsed_values) == 1 else "[" + ",".join(parsed_values) + "]"
        )
    assertion_id = assertion.getAttribute("ID")
    if not assertion_id:
        raise SamlFederationError("SAML Assertion ID is required")
    replay_hash = hashlib.sha256(
        f"{pool_id}\0{provider.provider_name}\0{assertion_id}".encode()
    ).hexdigest()
    return claims, replay_hash, not_after


def _parse_metadata(payload: bytes) -> dict[str, Any]:
    if len(payload) > _MAX_METADATA_BYTES:
        raise SamlFederationError("SAML metadata exceeds limit")
    document = _safe_xml_document(payload)
    root = document.documentElement
    if root.namespaceURI != SAML_METADATA or root.localName != "EntityDescriptor":
        raise SamlFederationError("Invalid SAML EntityDescriptor")
    entity_id = root.getAttribute("entityID")
    descriptors = _direct_elements(root, SAML_METADATA, "IDPSSODescriptor")
    if (
        not 1 <= len(entity_id) <= 2048
        or len(descriptors) != 1
        or SAML2_PROTOCOL not in descriptors[0].getAttribute("protocolSupportEnumeration").split()
    ):
        raise SamlFederationError("Invalid SAML IdP descriptor")
    certificates = []
    for descriptor in _direct_elements(descriptors[0], SAML_METADATA, "KeyDescriptor"):
        if descriptor.getAttribute("use") not in {"", "signing"}:
            continue
        for node in _descendants(descriptor, XMLDSIG, "X509Certificate"):
            certificate_text = "".join(_text(node).split())
            try:
                der = base64.b64decode(certificate_text, validate=True)
                certificate = x509.load_der_x509_certificate(der)
            except (TypeError, ValueError) as error:
                raise SamlFederationError("Invalid SAML signing certificate") from error
            public_key = certificate.public_key()
            now = datetime.now(UTC)
            if (
                not isinstance(public_key, rsa.RSAPublicKey)
                or public_key.key_size < 2048
                or certificate.not_valid_before_utc > now
                or certificate.not_valid_after_utc <= now
            ):
                raise SamlFederationError("Unsafe SAML signing certificate")
            certificates.append(certificate_text)
    certificates = list(dict.fromkeys(certificates))
    if not 1 <= len(certificates) <= _MAX_CERTIFICATES:
        raise SamlFederationError("SAML signing certificate count is invalid")
    redirect_locations = [
        element.getAttribute("Location")
        for element in _direct_elements(descriptors[0], SAML_METADATA, "SingleSignOnService")
        if element.getAttribute("Binding") == SAML2_REDIRECT
    ]
    if len(redirect_locations) != 1:
        raise SamlFederationError("SAML Redirect SSO endpoint is required")
    _validated_target(redirect_locations[0], allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
    result = {
        "entity_id": entity_id,
        "signing_certificates": certificates,
        "sso_redirect": redirect_locations[0],
        "want_authn_requests_signed": descriptors[0].getAttribute("WantAuthnRequestsSigned").lower()
        == "true",
    }
    logout = [
        element.getAttribute("Location")
        for element in _direct_elements(descriptors[0], SAML_METADATA, "SingleLogoutService")
        if element.getAttribute("Binding") in {SAML2_REDIRECT, SAML2_POST}
    ]
    if logout:
        if len(set(logout)) != 1:
            raise SamlFederationError("Ambiguous SAML logout endpoint")
        _validated_target(logout[0], allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
        result["slo"] = logout[0]
    return result


def _decrypt_assertion(encrypted_assertion, private_key_pem: str):
    encrypted_data_nodes = _direct_elements(encrypted_assertion, XMLENC, "EncryptedData")
    if len(encrypted_data_nodes) != 1:
        raise SamlFederationError("Invalid EncryptedAssertion")
    encrypted_data = encrypted_data_nodes[0]
    data_methods = _direct_elements(encrypted_data, XMLENC, "EncryptionMethod")
    data_values = _descendants(encrypted_data, XMLENC, "CipherValue")
    encrypted_keys = _descendants(encrypted_data, XMLENC, "EncryptedKey")
    if (
        len(data_methods) != 1
        or data_methods[0].getAttribute("Algorithm") != AES256_CBC
        or len(data_values) != 2
        or len(encrypted_keys) != 1
    ):
        raise SamlFederationError("Unsupported SAML assertion encryption")
    encrypted_key = encrypted_keys[0]
    key_methods = _direct_elements(encrypted_key, XMLENC, "EncryptionMethod")
    key_values = _descendants(encrypted_key, XMLENC, "CipherValue")
    if (
        len(key_methods) != 1
        or key_methods[0].getAttribute("Algorithm") != RSA_OAEP
        or len(key_values) != 1
    ):
        raise SamlFederationError("Unsupported SAML key encryption")
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        symmetric_key = private_key.decrypt(
            _strict_base64_text(_text(key_values[0])),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        encrypted_payload = _strict_base64_text(_text(data_values[-1]))
        if len(symmetric_key) != 32 or len(encrypted_payload) < 32:
            raise ValueError
        iv, ciphertext = encrypted_payload[:16], encrypted_payload[16:]
        decryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except (TypeError, ValueError) as error:
        raise SamlFederationError("SAML assertion decryption failed") from error
    assertion_document = _safe_xml_document(plaintext)
    assertion = assertion_document.documentElement
    if assertion.namespaceURI != SAML_ASSERTION or assertion.localName != "Assertion":
        raise SamlFederationError("Decrypted SAML content is not an Assertion")
    return assertion.cloneNode(deep=True)


def _verify_xml_signature(document, response, assertion, metadata) -> None:
    signatures = _descendants(document, XMLDSIG, "Signature")
    if len(signatures) != 1:
        raise SamlFederationError("Exactly one XML signature is required")
    signature = signatures[0]
    signed_info_nodes = _direct_elements(signature, XMLDSIG, "SignedInfo")
    signature_values = _direct_elements(signature, XMLDSIG, "SignatureValue")
    if len(signed_info_nodes) != 1 or len(signature_values) != 1:
        raise SamlFederationError("Invalid XML signature structure")
    signed_info = signed_info_nodes[0]
    canonicalization = _direct_elements(signed_info, XMLDSIG, "CanonicalizationMethod")
    methods = _direct_elements(signed_info, XMLDSIG, "SignatureMethod")
    references = _direct_elements(signed_info, XMLDSIG, "Reference")
    if (
        len(canonicalization) != 1
        or canonicalization[0].getAttribute("Algorithm") != EXCLUSIVE_C14N
        or canonicalization[0].childNodes
        or len(methods) != 1
        or methods[0].getAttribute("Algorithm") != RSA_SHA256
        or methods[0].childNodes
        or len(references) != 1
    ):
        raise SamlFederationError("Unsupported XML signature algorithms")
    reference_uri = references[0].getAttribute("URI")
    if not reference_uri.startswith("#") or len(reference_uri) > 257:
        raise SamlFederationError("Invalid XML signature reference")
    identifiers = {}
    for element in document.getElementsByTagName("*"):
        if element.hasAttribute("ID"):
            identifier = element.getAttribute("ID")
            if not identifier or identifier in identifiers:
                raise SamlFederationError("Duplicate XML ID")
            identifiers[identifier] = element
    signed_element = identifiers.get(reference_uri[1:])
    if signed_element not in {response, assertion}:
        raise SamlFederationError("Signature must cover Response or Assertion")
    transforms_nodes = _direct_elements(references[0], XMLDSIG, "Transforms")
    digest_methods = _direct_elements(references[0], XMLDSIG, "DigestMethod")
    digest_values = _direct_elements(references[0], XMLDSIG, "DigestValue")
    if len(transforms_nodes) != 1 or len(digest_methods) != 1 or len(digest_values) != 1:
        raise SamlFederationError("Invalid XML digest structure")
    transforms = [
        node.getAttribute("Algorithm")
        for node in _direct_elements(transforms_nodes[0], XMLDSIG, "Transform")
    ]
    if transforms != [ENVELOPED_SIGNATURE, EXCLUSIVE_C14N] or (
        digest_methods[0].getAttribute("Algorithm") != SHA256
    ):
        raise SamlFederationError("Unsupported XML digest transforms")
    clone = signed_element.cloneNode(deep=True)
    clone_signatures = _descendants(clone, XMLDSIG, "Signature")
    if len(clone_signatures) != 1:
        raise SamlFederationError("Signature wrapping detected")
    clone_signatures[0].parentNode.removeChild(clone_signatures[0])
    digest = base64.b64encode(hashlib.sha256(_exclusive_c14n(clone)).digest()).decode()
    if not hmac.compare_digest("".join(_text(digest_values[0]).split()), digest):
        raise SamlFederationError("SAML XML digest mismatch")
    signature_value = _strict_base64_text(_text(signature_values[0]))
    signed_bytes = _exclusive_c14n(signed_info)
    verified = False
    for encoded_certificate in metadata["signing_certificates"]:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(encoded_certificate, validate=True)
        )
        try:
            certificate.public_key().verify(
                signature_value, signed_bytes, padding.PKCS1v15(), hashes.SHA256()
            )
            verified = True
            break
        except InvalidSignature:
            continue
    if not verified:
        raise SamlSignatureKeyError("Invalid SAML XML signature")


def _exclusive_c14n(node: Node, rendered: dict[str, str] | None = None) -> bytes:
    rendered = (
        {"": "", "xml": "http://www.w3.org/XML/1998/namespace"}
        if rendered is None
        else dict(rendered)
    )

    def emit(current: Node, namespace_context: dict[str, str]) -> str:
        if current.nodeType == Node.ELEMENT_NODE:
            prefix = current.prefix or ""
            visible = {prefix: current.namespaceURI or ""}
            attributes = []
            for index in range(current.attributes.length):
                attribute = current.attributes.item(index)
                if attribute.namespaceURI == XMLNS or attribute.name == "xmlns":
                    continue
                attributes.append(attribute)
                if attribute.prefix:
                    visible[attribute.prefix] = attribute.namespaceURI or ""
            declarations = []
            next_context = dict(namespace_context)
            for visible_prefix, uri in visible.items():
                if next_context.get(visible_prefix) != uri:
                    declarations.append((visible_prefix, uri))
                    next_context[visible_prefix] = uri
            declarations.sort(key=lambda item: item[0])
            attributes.sort(key=lambda item: (item.namespaceURI or "", item.localName or item.name))
            start = [f"<{current.tagName}"]
            for visible_prefix, uri in declarations:
                name = "xmlns" if not visible_prefix else f"xmlns:{visible_prefix}"
                start.append(f' {name}="{_xml_attribute(uri)}"')
            for attribute in attributes:
                start.append(f' {attribute.name}="{_xml_attribute(attribute.value)}"')
            start.append(">")
            for child in current.childNodes:
                start.append(emit(child, next_context))
            start.append(f"</{current.tagName}>")
            return "".join(start)
        if current.nodeType in {Node.TEXT_NODE, Node.CDATA_SECTION_NODE}:
            return _xml_text(current.data).replace("\r", "&#xD;")
        if current.nodeType in {Node.COMMENT_NODE}:
            return ""
        if current.nodeType in {Node.PROCESSING_INSTRUCTION_NODE, Node.ENTITY_REFERENCE_NODE}:
            raise SamlFederationError("Unsupported XML node in signed content")
        return ""

    return emit(node, rendered).encode()


def _safe_xml_document(payload: bytes):
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper or b"<?XML-STYLESHEET" in upper:
        raise SamlFederationError("Unsafe XML declaration")
    try:
        document = minidom.parseString(payload)
    except Exception as error:
        raise SamlFederationError("Invalid SAML XML") from error
    if len(document.childNodes) != 1 or document.documentElement is None:
        raise SamlFederationError("Invalid SAML XML document")
    return document


def _secure_xml_request(url: str) -> bytes:
    parsed, address = _validated_target(url, allowlist=config.COGNITO_IDP_EGRESS_ALLOWLIST)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    connection: http.client.HTTPConnection
    if parsed.scheme == "https":
        connection = _PinnedHTTPSConnection(parsed.hostname, port, address)
    else:
        connection = http.client.HTTPConnection(address, port, timeout=3)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Accept": "application/samlmetadata+xml, application/xml, text/xml",
                "Accept-Encoding": "identity",
                "Host": parsed.netloc,
                "User-Agent": "LocalStack-Cognito-SAML/1",
            },
        )
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            raise SamlFederationError("SAML metadata redirects are disabled")
        if not 200 <= response.status < 300:
            raise SamlFederationError("SAML metadata endpoint returned an error")
        content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].lower()
        if content_type not in {
            "application/samlmetadata+xml",
            "application/xml",
            "text/xml",
        }:
            raise SamlFederationError("SAML metadata endpoint did not return XML")
        payload = response.read(_MAX_METADATA_BYTES + 1)
        if len(payload) > _MAX_METADATA_BYTES:
            raise SamlFederationError("SAML metadata exceeds limit")
        return payload
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise SamlFederationError("SAML metadata request failed") from error
    finally:
        connection.close()


def _direct_elements(node, namespace: str, local_name: str) -> list:
    return [
        child
        for child in node.childNodes
        if child.nodeType == Node.ELEMENT_NODE
        and child.namespaceURI == namespace
        and child.localName == local_name
    ]


def _descendants(node, namespace: str, local_name: str) -> list:
    return list(node.getElementsByTagNameNS(namespace, local_name))


def _text(node) -> str:
    if any(
        child.nodeType not in {Node.TEXT_NODE, Node.CDATA_SECTION_NODE} for child in node.childNodes
    ):
        raise SamlFederationError("Nested XML content is not supported")
    return "".join(child.data for child in node.childNodes).strip()


def _strict_base64_text(value: str) -> bytes:
    compact = "".join(value.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (TypeError, ValueError) as error:
        raise SamlFederationError("Invalid XML signature encoding") from error


def _parse_instant(value: str) -> datetime:
    match = _ISO_INSTANT.fullmatch(value or "")
    if match is None:
        raise SamlFederationError("Invalid SAML timestamp")
    return datetime.fromisoformat(f"{match.group('date')}{match.group('fraction') or ''}+00:00")


def _instant_within(value: str, now: datetime, window: timedelta) -> bool:
    try:
        instant = _parse_instant(value)
    except SamlFederationError:
        return False
    return now - window <= instant <= now + _CLOCK_SKEW


def _format_instant(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _xml_attribute(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def _xml_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
