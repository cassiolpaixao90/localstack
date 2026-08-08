import os
from urllib.parse import urlsplit

import pytest

from localstack.cli.cdk import CdkLauncherError, build_cdk_environment, validate_local_endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:4566",
        "http://[::1]:4566",
        "http://localhost:4566",
        "http://localhost.localstack.cloud:4566",
        "http://s3.localhost.localstack.cloud:4566",
    ],
)
def test_validate_local_endpoint_accepts_local_hosts(endpoint):
    assert validate_local_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://cloudformation.us-east-1.amazonaws.com",
        "https://sts.us-east-1.api.aws",
        "file:///tmp/localstack.sock",
        "http://user:password@localhost:4566",
        "http://localhost:4566/path",
        "http://localhost:4566?target=aws",
        "http://localstack:4566",
        " http://localhost:4566",
    ],
)
def test_validate_local_endpoint_rejects_unsafe_or_remote_hosts(endpoint):
    with pytest.raises(CdkLauncherError):
        validate_local_endpoint(endpoint)


def test_validate_local_endpoint_allows_explicit_container_host():
    endpoint = "http://localstack:4566"

    assert validate_local_endpoint(endpoint, allowed_remote_hosts={"localstack"}) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.us-east-1.api.aws.:443",
        "https://sts。us-east-1。api。aws:443",
        "https://sts%2eus-east-1%2eapi%2eaws:443",
        "https://sts%2Eus-east-1%2Eamazonaws%2Ecom:443",
        "https://cloudformation%2ecn-north-1%2eamazonaws%2ecom%2ecn:443",
        "https://cloudformation.cn-north-1.amazonaws.com.cn:443",
        "https://cloudformation.cn-north-1.api.amazonwebservices.com.cn:443",
        "https://cloudformation.eusc-de-east-1.amazonaws.eu:443",
        "https://cloudformation.eusc-de-east-1.api.amazonwebservices.eu:443",
        "https://cloudformation.us-iso-east-1.c2s.ic.gov:443",
        "https://cloudformation.us-iso-east-1.api.aws.ic.gov:443",
        "https://cloudformation.us-isob-east-1.sc2s.sgov.gov:443",
        "https://cloudformation.us-isob-east-1.api.aws.scloud:443",
        "https://cloudformation.eu-isoe-west-1.cloud.adc-e.uk:443",
        "https://cloudformation.eu-isoe-west-1.api.cloud-aws.adc-e.uk:443",
        "https://cloudformation.us-isof-south-1.csp.hci.ic.gov:443",
        "https://cloudformation.us-isof-south-1.api.aws.hci.ic.gov:443",
    ],
)
def test_validate_local_endpoint_rejects_canonical_aws_hosts_before_allowlist(endpoint):
    with pytest.raises(CdkLauncherError):
        validate_local_endpoint(endpoint, allowed_remote_hosts={urlsplit(endpoint).hostname})


def test_validate_local_endpoint_rejects_embedded_control_characters():
    with pytest.raises(CdkLauncherError):
        validate_local_endpoint("http://local\nhost:4566", allowed_remote_hosts={"localhost"})


def test_build_cdk_environment_strips_parent_aws_credentials_and_profiles():
    parent = {
        "PATH": "/usr/bin",
        "HOME": "/home/developer",
        "LANG": "en_US.UTF-8",
        "AWS_ACCESS_KEY_ID": "production-key",
        "AWS_SECRET_ACCESS_KEY": "production-secret",
        "AWS_SESSION_TOKEN": "production-token",
        "AWS_PROFILE": "production",
        "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/production",
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/tmp/token",
        "HTTP_PROXY": "http://proxy.example:8080",
    }

    environment = build_cdk_environment(
        parent,
        endpoint_url="http://localhost.localstack.cloud:4566",
        region="eu-west-1",
        account_id="000000000123",
    )

    assert environment == {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_DEFAULT_REGION": "eu-west-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ENDPOINT_URL": "http://localhost.localstack.cloud:4566",
        "AWS_ENDPOINT_URL_S3": "http://localhost.localstack.cloud:4566",
        "AWS_REGION": "eu-west-1",
        "AWS_S3_FORCE_PATH_STYLE": "true",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "CDK_DEFAULT_ACCOUNT": "000000000123",
        "CDK_DEFAULT_REGION": "eu-west-1",
        "HOME": "/home/developer",
        "LANG": "en_US.UTF-8",
        "PATH": "/usr/bin",
    }


def test_build_cdk_environment_uses_explicit_s3_endpoint_and_pass_environment():
    parent = {"PATH": "/bin", "JAVA_HOME": "/jdk", "CUSTOM_BUILD_FLAG": "enabled"}

    environment = build_cdk_environment(
        parent,
        endpoint_url="http://localhost:4566",
        s3_endpoint_url="http://s3.localhost.localstack.cloud:4566",
        pass_environment=("JAVA_HOME", "CUSTOM_BUILD_FLAG"),
    )

    assert environment["AWS_ENDPOINT_URL_S3"] == "http://s3.localhost.localstack.cloud:4566"
    assert environment["JAVA_HOME"] == "/jdk"
    assert environment["CUSTOM_BUILD_FLAG"] == "enabled"


@pytest.mark.parametrize(
    "name",
    ["AWS_PROFILE", "AWS_SECRET_ACCESS_KEY", "AWS_WEB_IDENTITY_TOKEN_FILE", "invalid-name"],
)
def test_build_cdk_environment_rejects_unsafe_pass_environment(name):
    with pytest.raises(CdkLauncherError):
        build_cdk_environment(
            {name: "unsafe"},
            endpoint_url="http://localhost:4566",
            pass_environment=(name,),
        )


@pytest.mark.parametrize(
    ("region", "account_id"),
    [
        ("", "000000000000"),
        ("bad-region", "000000000000"),
        ("us east 1", "000000000000"),
        ("us-east-1", "123"),
    ],
)
def test_build_cdk_environment_rejects_invalid_aws_identity(region, account_id):
    with pytest.raises(CdkLauncherError):
        build_cdk_environment(
            {},
            endpoint_url="http://localhost:4566",
            region=region,
            account_id=account_id,
        )
