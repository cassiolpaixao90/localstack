import socket
import ssl
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from localstack.services.cognito_idp.custom_domain_routing import (
    CustomDomainRoutingError,
    select_domain_region,
    validate_custom_domain_binding,
)


@pytest.fixture
def topology():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = f"aa-{uuid.uuid4().hex[:4]}-1"
    return {
        "account_id": account_id,
        "partition": "aws",
        "primary_region": region_name,
        "secondary_region": f"{region_name[:-1]}2",
        "owner_token": "0123456789abcdef01234567",
    }


@pytest.fixture
def certificate(topology):
    now = datetime(2026, 8, 10, tzinfo=UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "auth.example.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("auth.example.test")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return {
        "CertificateArn": (
            f"arn:{topology['partition']}:acm:us-east-1:{topology['account_id']}:"
            "certificate/01234567-89ab-cdef-0123-456789abcdef"
        ),
        "Status": "ISSUED",
        "Certificate": cert.public_bytes(serialization.Encoding.PEM),
        "PrivateKey": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "Tags": {"localstack:owner": topology["owner_token"]},
    }


def test_acm_tls_and_local_health_state_select_failover(topology, certificate):
    health = {
        "Id": "01234567-89ab-cdef-0123-456789abcdef",
        "AccountId": topology["account_id"],
        "OwnerToken": topology["owner_token"],
        "Type": "HTTPS",
        "FQDN": "auth.example.test",
        "Port": 443,
        "ResourcePath": "/health",
        "Status": "HEALTHY",
    }
    binding = validate_custom_domain_binding(
        domain="auth.example.test",
        certificate_arn=certificate["CertificateArn"],
        security_policy="TLS_V1_2_2021",
        health_check_id=health["Id"],
        acm_lookup=lambda _: certificate,
        health_check_lookup=lambda _: health,
        now=datetime(2026, 8, 10, tzinfo=UTC),
        **topology,
    )
    assert binding.certificate_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert (
        select_domain_region(binding, health_status="HEALTHY", secondary_status="ACTIVE")
        == (topology["primary_region"])
    )
    assert (
        select_domain_region(binding, health_status="UNHEALTHY", secondary_status="ACTIVE")
        == topology["secondary_region"]
    )
    with pytest.raises(CustomDomainRoutingError, match="unavailable"):
        select_domain_region(binding, health_status="UNHEALTHY", secondary_status="CREATING")
    with pytest.raises(CustomDomainRoutingError, match="indeterminate"):
        select_domain_region(binding, health_status="UNKNOWN", secondary_status="ACTIVE")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"Status": "PENDING_VALIDATION"}, "ISSUED"),
        ({"Tags": {"localstack:owner": "fedcba9876543210fedcba98"}}, "ownership"),
        ({"CertificateArn": "wrong-region"}, "us-east-1"),
    ],
)
def test_certificate_status_owner_and_region_are_fail_closed(
    topology, certificate, change, message
):
    candidate = {**certificate, **change}
    if candidate["CertificateArn"] == "wrong-region":
        candidate["CertificateArn"] = (
            f"arn:{topology['partition']}:acm:{topology['primary_region']}:"
            f"{topology['account_id']}:certificate/x"
        )
    with pytest.raises(CustomDomainRoutingError, match=message):
        validate_custom_domain_binding(
            domain="auth.example.test",
            certificate_arn=candidate["CertificateArn"],
            security_policy="TLS_V1_2_2021",
            health_check_id=None,
            acm_lookup=lambda _: candidate,
            health_check_lookup=lambda _: None,
            now=datetime(2026, 8, 10, tzinfo=UTC),
            **topology,
        )


def test_legacy_tls_policy_is_rejected(topology, certificate):
    with pytest.raises(CustomDomainRoutingError, match="TLS_V1_2_2021"):
        validate_custom_domain_binding(
            domain="auth.example.test",
            certificate_arn=certificate["CertificateArn"],
            security_policy="TLS_V1",
            health_check_id=None,
            acm_lookup=lambda _: certificate,
            health_check_lookup=lambda _: None,
            now=datetime(2026, 8, 10, tzinfo=UTC),
            **topology,
        )


def test_certificate_hostname_key_and_health_check_are_verified(topology, certificate):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key = {
        **certificate,
        "PrivateKey": other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }
    with pytest.raises(CustomDomainRoutingError, match="private key"):
        validate_custom_domain_binding(
            domain="auth.example.test",
            certificate_arn=certificate["CertificateArn"],
            security_policy="TLS_V1_2_2021",
            health_check_id=None,
            acm_lookup=lambda _: wrong_key,
            health_check_lookup=lambda _: None,
            now=datetime(2026, 8, 10, tzinfo=UTC),
            **topology,
        )


def test_binding_material_serves_local_tls_with_hostname_verification(
    topology, certificate, tmp_path
):
    binding = validate_custom_domain_binding(
        domain="auth.example.test",
        certificate_arn=certificate["CertificateArn"],
        security_policy="TLS_V1_2_2021",
        health_check_id=None,
        acm_lookup=lambda _: certificate,
        health_check_lookup=lambda _: None,
        now=datetime(2026, 8, 10, tzinfo=UTC),
        **topology,
    )
    certificate_path = tmp_path / "certificate.pem"
    key_path = tmp_path / "private-key.pem"
    certificate_path.write_bytes(binding.certificate_pem)
    key_path.write_bytes(binding.private_key_pem)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certificate_path, key_path)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    errors = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection, server_context.wrap_socket(connection, server_side=True) as tls:
                tls.recv(1)
                tls.sendall(b"y")
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=serve)
    worker.start()
    client_context = ssl.create_default_context(cadata=binding.certificate_pem.decode())
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(listener.getsockname(), timeout=2) as connection:
        with client_context.wrap_socket(connection, server_hostname="auth.example.test") as tls:
            tls.sendall(b"x")
            assert tls.recv(1) == b"y"
    worker.join(timeout=2)
    listener.close()
    assert not worker.is_alive()
    assert errors == []

    bad_health = {
        "Id": "health-id",
        "AccountId": topology["account_id"],
        "OwnerToken": topology["owner_token"],
        "Type": "HTTP",
        "FQDN": "169.254.169.254",
        "Port": 80,
        "ResourcePath": "/latest/meta-data",
        "Status": "HEALTHY",
    }
    with pytest.raises(CustomDomainRoutingError, match="health check"):
        validate_custom_domain_binding(
            domain="auth.example.test",
            certificate_arn=certificate["CertificateArn"],
            security_policy="TLS_V1_2_2021",
            health_check_id=bad_health["Id"],
            acm_lookup=lambda _: certificate,
            health_check_lookup=lambda _: bad_health,
            now=datetime(2026, 8, 10, tzinfo=UTC),
            **topology,
        )
