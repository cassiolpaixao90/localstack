import ipaddress
import os
import re
from collections.abc import Collection, Iterable, Mapping
from urllib.parse import urlsplit

from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID

_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REGION_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$")
_PRESERVED_ENVIRONMENT = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
    }
)
_LOCAL_HOSTS = frozenset(
    {
        "gateway.docker.internal",
        "host.docker.internal",
        "localhost",
        "localhost.localstack.cloud",
    }
)
_AWS_PUBLIC_DOMAINS = (
    "amazonaws.com",
    "amazonaws.com.cn",
    "amazonaws.eu",
    "api.amazonwebservices.com.cn",
    "api.amazonwebservices.eu",
    "api.aws",
    "api.aws.hci.ic.gov",
    "api.aws.ic.gov",
    "api.aws.scloud",
    "api.cloud-aws.adc-e.uk",
    "c2s.ic.gov",
    "cloud.adc-e.uk",
    "csp.hci.ic.gov",
    "sc2s.sgov.gov",
)


class CdkLauncherError(ValueError):
    """Raised when CDK could escape the configured local environment."""


def validate_local_endpoint(
    endpoint_url: str, *, allowed_remote_hosts: Collection[str] = ()
) -> str:
    """Validate an endpoint without performing DNS or network access."""
    if (
        not isinstance(endpoint_url, str)
        or endpoint_url != endpoint_url.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in endpoint_url)
    ):
        raise CdkLauncherError("invalid LocalStack endpoint URL")
    try:
        parsed = urlsplit(endpoint_url)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise CdkLauncherError("invalid LocalStack endpoint URL") from error

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CdkLauncherError("LocalStack endpoint must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise CdkLauncherError("LocalStack endpoint must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise CdkLauncherError("LocalStack endpoint must not contain a path, query, or fragment")
    if port is None or not 1 <= port <= 65535:
        raise CdkLauncherError("LocalStack endpoint must contain a valid port")

    host = _canonical_host(parsed.hostname)
    if any(host == domain or host.endswith(f".{domain}") for domain in _AWS_PUBLIC_DOMAINS):
        raise CdkLauncherError("public AWS endpoints are not allowed")

    allowed_hosts = {_canonical_host(allowed) for allowed in allowed_remote_hosts}
    if (
        host in _LOCAL_HOSTS
        or host.endswith(".localhost.localstack.cloud")
        or host in allowed_hosts
        or _is_loopback(host)
    ):
        return endpoint_url

    raise CdkLauncherError(f"remote LocalStack host requires explicit permission: {host}")


def build_cdk_environment(
    parent_environment: Mapping[str, str],
    *,
    endpoint_url: str,
    s3_endpoint_url: str | None = None,
    region: str = AWS_REGION_US_EAST_1,
    account_id: str = DEFAULT_AWS_ACCOUNT_ID,
    pass_environment: Iterable[str] = (),
    allowed_remote_hosts: Collection[str] = (),
) -> dict[str, str]:
    """Build a minimal child environment that cannot inherit AWS credentials."""
    endpoint_url = validate_local_endpoint(endpoint_url, allowed_remote_hosts=allowed_remote_hosts)
    s3_endpoint_url = validate_local_endpoint(
        s3_endpoint_url or endpoint_url, allowed_remote_hosts=allowed_remote_hosts
    )
    if not _REGION_NAME.fullmatch(region):
        raise CdkLauncherError("invalid AWS region")
    if not re.fullmatch(r"[0-9]{12}", account_id):
        raise CdkLauncherError("AWS account ID must contain exactly 12 digits")

    environment = {
        name: value
        for name, value in parent_environment.items()
        if name in _PRESERVED_ENVIRONMENT or name.startswith("LC_")
    }
    for name in pass_environment:
        if not _ENVIRONMENT_NAME.fullmatch(name) or name.upper().startswith("AWS_"):
            raise CdkLauncherError(f"unsafe environment variable requested: {name}")
        if name in parent_environment:
            environment[name] = parent_environment[name]

    environment.update(
        {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": endpoint_url,
            "AWS_ENDPOINT_URL_S3": s3_endpoint_url,
            "AWS_REGION": region,
            "AWS_S3_FORCE_PATH_STYLE": "true",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "CDK_DEFAULT_ACCOUNT": account_id,
            "CDK_DEFAULT_REGION": region,
        }
    )
    return environment


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _canonical_host(host: str) -> str:
    if "%" in host:
        raise CdkLauncherError("percent-encoded endpoint hostnames are not allowed")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass

    try:
        canonical = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, AttributeError) as error:
        raise CdkLauncherError("invalid endpoint hostname") from error
    if canonical.endswith("."):
        canonical = canonical[:-1]
    if not canonical or canonical.endswith("."):
        raise CdkLauncherError("invalid endpoint hostname")
    return canonical
