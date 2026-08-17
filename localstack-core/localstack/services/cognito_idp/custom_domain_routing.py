import dataclasses
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_ACCOUNT_ID = re.compile(r"[0-9]{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_OWNER = re.compile(r"[0-9a-f]{24,128}")
_CERTIFICATE_ID = re.compile(r"[0-9A-Za-z-]{1,128}")
_HEALTH_ID = re.compile(r"[0-9A-Za-z-]{1,64}")


class CustomDomainRoutingError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class CustomDomainBinding:
    domain: str
    certificate_arn: str
    certificate_pem: bytes
    private_key_pem: bytes
    security_policy: str
    account_id: str
    partition: str
    primary_region: str
    secondary_region: str | None
    health_check_id: str | None
    owner_token: str


def validate_custom_domain_binding(
    *,
    domain: Any,
    certificate_arn: Any,
    security_policy: Any,
    health_check_id: Any,
    acm_lookup,
    health_check_lookup,
    account_id: Any,
    partition: Any,
    primary_region: Any,
    secondary_region: Any = None,
    owner_token: Any,
    now: datetime | None = None,
) -> CustomDomainBinding:
    domain = _domain(domain)
    _topology(account_id, partition, primary_region, secondary_region, owner_token)
    if security_policy not in {"TLS_V1_2_2021", "TLS_V1_3_2025"}:
        raise CustomDomainRoutingError("Custom domains require TLS_V1_2_2021 or TLS_V1_3_2025")
    arn = _certificate_arn(certificate_arn, partition, account_id)
    if not callable(acm_lookup) or not callable(health_check_lookup):
        raise CustomDomainRoutingError("Local resource lookup is required")
    certificate_record = acm_lookup(arn)
    if not isinstance(certificate_record, dict):
        raise CustomDomainRoutingError("ACM certificate does not exist locally")
    if certificate_record.get("CertificateArn") != arn:
        raise CustomDomainRoutingError("ACM certificate topology is inconsistent")
    if certificate_record.get("Status") != "ISSUED":
        raise CustomDomainRoutingError("ACM certificate must be ISSUED")
    tags = certificate_record.get("Tags")
    if not isinstance(tags, dict) or tags.get("localstack:owner") != owner_token:
        raise CustomDomainRoutingError("ACM certificate ownership mismatch")
    certificate_pem = certificate_record.get("Certificate")
    private_key_pem = certificate_record.get("PrivateKey")
    if not isinstance(certificate_pem, bytes) or len(certificate_pem) > 1024 * 1024:
        raise CustomDomainRoutingError("Invalid ACM certificate material")
    if not isinstance(private_key_pem, bytes) or len(private_key_pem) > 1024 * 1024:
        raise CustomDomainRoutingError("Invalid ACM private key material")
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as error:
        raise CustomDomainRoutingError("Invalid ACM certificate material") from error
    if private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise CustomDomainRoutingError("ACM certificate private key mismatch")
    current = _utc(now or datetime.now(UTC))
    if current < certificate.not_valid_before_utc or current >= certificate.not_valid_after_utc:
        raise CustomDomainRoutingError("ACM certificate is not currently valid")
    try:
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound as error:
        raise CustomDomainRoutingError(
            "ACM certificate has no DNS subject alternative name"
        ) from error
    if not any(_dns_name_matches(pattern, domain) for pattern in names):
        raise CustomDomainRoutingError("ACM certificate does not match the custom domain")

    if health_check_id is not None:
        if secondary_region is None:
            raise CustomDomainRoutingError("Failover requires a secondary Region")
        if not isinstance(health_check_id, str) or _HEALTH_ID.fullmatch(health_check_id) is None:
            raise CustomDomainRoutingError("Invalid Route53 health check")
        health = health_check_lookup(health_check_id)
        if (
            not isinstance(health, dict)
            or health.get("Id") != health_check_id
            or health.get("AccountId") != account_id
            or health.get("OwnerToken") != owner_token
            or health.get("Type") != "HTTPS"
            or health.get("FQDN") != domain
            or health.get("Port") != 443
            or health.get("ResourcePath") != "/health"
            or health.get("Status") not in {"HEALTHY", "UNHEALTHY"}
        ):
            raise CustomDomainRoutingError("Invalid Route53 health check")
    return CustomDomainBinding(
        domain=domain,
        certificate_arn=arn,
        certificate_pem=certificate_pem,
        private_key_pem=private_key_pem,
        security_policy=security_policy,
        account_id=account_id,
        partition=partition,
        primary_region=primary_region,
        secondary_region=secondary_region,
        health_check_id=health_check_id,
        owner_token=owner_token,
    )


def select_domain_region(
    binding: CustomDomainBinding,
    *,
    health_status: Any,
    secondary_status: Any,
) -> str:
    if not isinstance(binding, CustomDomainBinding):
        raise CustomDomainRoutingError("Invalid custom-domain binding")
    if binding.health_check_id is None:
        return binding.primary_region
    if health_status == "HEALTHY":
        return binding.primary_region
    if health_status != "UNHEALTHY":
        raise CustomDomainRoutingError("Primary health is indeterminate")
    if secondary_status != "ACTIVE":
        raise CustomDomainRoutingError("Secondary Region is unavailable")
    if binding.secondary_region is None:
        raise CustomDomainRoutingError("Secondary Region is unavailable")
    return binding.secondary_region


def _certificate_arn(value: Any, partition: str, account_id: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise CustomDomainRoutingError("Invalid ACM certificate ARN")
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[:3] != ["arn", partition, "acm"]:
        raise CustomDomainRoutingError("Invalid ACM certificate ARN")
    if parts[3] != "us-east-1":
        raise CustomDomainRoutingError("ACM certificate must be in us-east-1")
    if parts[4] != account_id or not parts[5].startswith("certificate/"):
        raise CustomDomainRoutingError("ACM certificate account mismatch")
    certificate_id = parts[5].removeprefix("certificate/")
    if _CERTIFICATE_ID.fullmatch(certificate_id) is None:
        raise CustomDomainRoutingError("Invalid ACM certificate ARN")
    return value


def _domain(value: Any) -> str:
    if not isinstance(value, str) or value != value.lower() or not 4 <= len(value) <= 63:
        raise CustomDomainRoutingError("Invalid custom domain")
    if value.endswith(".") or ":" in value or "/" in value or "@" in value:
        raise CustomDomainRoutingError("Invalid custom domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise CustomDomainRoutingError("Invalid custom domain")
    labels = value.split(".")
    if len(labels) < 2 or any(
        not 1 <= len(label) <= 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise CustomDomainRoutingError("Invalid custom domain")
    return value


def _topology(account_id, partition, primary_region, secondary_region, owner_token) -> None:
    if (
        not isinstance(account_id, str)
        or _ACCOUNT_ID.fullmatch(account_id) is None
        or partition not in {"aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b"}
        or not isinstance(primary_region, str)
        or _REGION.fullmatch(primary_region) is None
        or (
            secondary_region is not None
            and (
                not isinstance(secondary_region, str)
                or _REGION.fullmatch(secondary_region) is None
                or primary_region == secondary_region
            )
        )
        or not isinstance(owner_token, str)
        or _OWNER.fullmatch(owner_token) is None
    ):
        raise CustomDomainRoutingError("Invalid custom-domain topology")


def _dns_name_matches(pattern: str, domain: str) -> bool:
    pattern = pattern.lower()
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain.endswith(f".{suffix}") and domain.count(".") == suffix.count(".") + 1
    return False


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CustomDomainRoutingError("Invalid custom-domain clock")
    return value.astimezone(UTC)
