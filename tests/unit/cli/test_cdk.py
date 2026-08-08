import json
import os
import sys
import threading
import time
from urllib.parse import urlsplit

import pytest

from localstack.cli.cdk import (
    MAX_CDK_OUTPUT_BYTES,
    CdkLauncherError,
    build_cdk_environment,
    launch_cdk,
    validate_local_endpoint,
)


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


def test_launch_cdk_passes_arguments_literally_and_preserves_exit_code(tmp_path):
    marker = tmp_path / "shell-was-used"
    arguments = ["with spaces", ";", f"$(touch {marker})", "*.py"]
    script = "import json,sys; print(json.dumps(sys.argv[1:])); print('err', file=sys.stderr); sys.exit(7)"

    result = launch_cdk(
        ["-c", script, *arguments],
        executable=sys.executable,
        environment={},
    )

    assert result.returncode == 7
    assert json.loads(result.stdout) == arguments
    assert result.stderr == b"err\n"
    assert not marker.exists()
    assert result.stdout_truncated is False
    assert result.stderr_truncated is False


def test_launch_cdk_bounds_and_drains_stdout_and_stderr():
    output_bytes = 2 * 1024 * 1024
    script = f"import os; os.write(1, b'o' * {output_bytes}); os.write(2, b'e' * {output_bytes})"

    result = launch_cdk(
        ["-c", script],
        executable=sys.executable,
        environment={},
        max_output_bytes=1024,
    )

    assert result.returncode == 0
    assert result.stdout == b"o" * 1024
    assert result.stderr == b"e" * 1024
    assert result.stdout_bytes == output_bytes
    assert result.stderr_bytes == output_bytes
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group assertion")
def test_launch_cdk_timeout_kills_process_group():
    script = """
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
print(child.pid, flush=True)
time.sleep(60)
"""
    started = time.monotonic()

    result = launch_cdk(
        ["-c", script],
        executable=sys.executable,
        environment={},
        timeout_seconds=0.2,
    )

    assert result.returncode == 124
    assert result.timed_out is True
    assert time.monotonic() - started < 3
    child_pid = int(result.stdout)
    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"child process {child_pid} survived launcher timeout")


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group assertion")
def test_launch_cdk_closes_pipes_from_descendant_after_leader_exits():
    script = """
import subprocess
import sys

subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
"""
    started = time.monotonic()

    result = launch_cdk(
        ["-c", script],
        executable=sys.executable,
        environment={},
        timeout_seconds=0.2,
    )

    assert result.returncode == 0
    assert time.monotonic() - started < 3


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group assertion")
def test_launch_cdk_timeout_kills_descendant_that_ignores_sigterm():
    child_script = (
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    )
    script = f"""
import subprocess
import sys
import time

subprocess.Popen([sys.executable, "-c", {child_script!r}])
time.sleep(60)
"""
    started = time.monotonic()

    result = launch_cdk(
        ["-c", script],
        executable=sys.executable,
        environment={},
        timeout_seconds=0.2,
    )

    assert result.returncode == 124
    assert result.timed_out is True
    assert time.monotonic() - started < 3


def test_launch_cdk_returns_126_when_executable_is_missing():
    result = launch_cdk([], executable="missing-cdk-executable", environment={})

    assert result.returncode == 126
    assert b"missing-cdk-executable" in result.stderr


@pytest.mark.parametrize(
    ("timeout_seconds", "max_output_bytes"),
    [
        (0, 1024),
        (-1, 1024),
        (float("inf"), 1024),
        (float("nan"), 1024),
        (threading.TIMEOUT_MAX * 2, 1024),
        (1e100, 1024),
        (10**1000, 1024),
        (True, 1024),
        (1, -1),
        (1, 1.5),
        (1, True),
        (1, MAX_CDK_OUTPUT_BYTES + 1),
        (1, 10**1000),
    ],
)
def test_launch_cdk_rejects_invalid_resource_limits(timeout_seconds, max_output_bytes):
    with pytest.raises(CdkLauncherError):
        launch_cdk(
            [],
            executable=sys.executable,
            environment={},
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
