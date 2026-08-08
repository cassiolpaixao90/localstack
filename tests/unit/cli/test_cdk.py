import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from click.testing import CliRunner

import localstack.cli.cdk as cdk_module
from localstack.cli.cdk import (
    MAX_CDK_CAPTURE_BYTES,
    CdkLauncherError,
    build_cdk_environment,
    cli,
    launch_cdk,
    probe_cdk_cli_version,
    probe_localstack_health,
    validate_local_endpoint,
)


@pytest.fixture
def http_server():
    servers = []

    def start(
        *,
        status=200,
        body=b'{"services": {}, "version": "test"}',
        headers=None,
        chunk_delay=0,
    ):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    if chunk_delay:
                        for byte in body:
                            self.wfile.write(bytes((byte,)))
                            self.wfile.flush()
                            time.sleep(chunk_delay)
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        servers.append((server, thread))
        endpoint = f"http://127.0.0.1:{server.server_port}"
        return endpoint, requests

    yield start

    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join()


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


def test_launch_cdk_streams_output_before_child_exits(tmp_path):
    output_path = tmp_path / "stdout"
    result = []
    with output_path.open("wb", buffering=0) as stdout:
        thread = threading.Thread(
            target=lambda: result.append(
                launch_cdk(
                    ["-c", "import time; print('ready', flush=True); time.sleep(.5)"],
                    executable=sys.executable,
                    environment={},
                    stdout=stdout,
                )
            )
        )

        thread.start()
        deadline = time.monotonic() + 0.3
        while b"ready" not in output_path.read_bytes() and time.monotonic() < deadline:
            time.sleep(0.01)

        assert b"ready" in output_path.read_bytes()
        assert thread.is_alive()
        thread.join(2)
    assert result[0].returncode == 0


def test_launch_cdk_bounds_runtime_when_direct_output_is_backpressured():
    read_fd, write_fd = os.pipe()
    started = time.monotonic()
    try:
        result = launch_cdk(
            ["-c", "import os; os.write(1, b'x' * (1024 * 1024))"],
            executable=sys.executable,
            environment={},
            stdout=write_fd,
            timeout_seconds=0.1,
        )
    finally:
        os.close(write_fd)
        os.close(read_fd)

    assert result.returncode == 124
    assert result.timed_out is True
    assert time.monotonic() - started < 2


def test_launch_cdk_can_read_explicit_input_stream(tmp_path):
    input_path = tmp_path / "stdin"
    input_path.write_bytes(b"approved\n")
    with input_path.open("rb") as stdin:
        result = launch_cdk(
            ["-c", "print(input())"],
            executable=sys.executable,
            environment={},
            stdin=stdin,
        )

    assert result.stdout == b"approved\n"


@pytest.mark.skipif(os.name != "posix", reason="PTY assertion requires POSIX")
def test_launch_cdk_preserves_tty_descriptors():
    import pty

    master_fd, slave_fd = pty.openpty()
    try:
        result = launch_cdk(
            [
                "-c",
                "import json,sys; print(json.dumps([s.isatty() for s in "
                "(sys.stdin,sys.stdout,sys.stderr)]), flush=True)",
            ],
            executable=sys.executable,
            environment={},
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
        )
        output = os.read(master_fd, 4096)
        os.close(slave_fd)
        slave_fd = -1
    finally:
        if slave_fd >= 0:
            os.close(slave_fd)
        os.close(master_fd)

    assert result.returncode == 0
    assert b"[true, true, true]" in output


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
        (1, MAX_CDK_CAPTURE_BYTES + 1),
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


def test_probe_localstack_health_validates_bounded_response(http_server):
    endpoint, requests = http_server(
        body=b'{"services":{"s3":"available"},"version":"4.14.0","edition":"community"}'
    )

    health = probe_localstack_health(endpoint, timeout_seconds=1)

    assert health == {
        "edition": "community",
        "services": {"s3": "available"},
        "version": "4.14.0",
    }
    assert requests == ["/_localstack/health"]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (503, b'{"services": {}, "version": "test"}'),
        (200, b"not-json"),
        (200, b'{"version":"test"}'),
        (200, b'{"services":{},"version":""}'),
        (200, b"x" * (64 * 1024 + 1)),
    ],
)
def test_probe_localstack_health_rejects_invalid_response(http_server, status, body):
    endpoint, _ = http_server(status=status, body=body)

    with pytest.raises(CdkLauncherError):
        probe_localstack_health(endpoint, timeout_seconds=1)


def test_probe_localstack_health_does_not_follow_redirects(http_server):
    redirected_endpoint, redirected_requests = http_server()
    endpoint, _ = http_server(
        status=302,
        body=b"",
        headers={"Location": f"{redirected_endpoint}/_localstack/health"},
    )

    with pytest.raises(CdkLauncherError):
        probe_localstack_health(endpoint, timeout_seconds=1)

    assert redirected_requests == []


def test_probe_localstack_health_enforces_total_deadline(http_server):
    endpoint, _ = http_server(chunk_delay=0.05)
    started = time.monotonic()

    with pytest.raises(CdkLauncherError):
        probe_localstack_health(endpoint, timeout_seconds=0.1)

    assert time.monotonic() - started < 0.5


def test_probe_localstack_health_does_not_retain_http_response(http_server):
    endpoint, _ = http_server(status=503)

    with pytest.raises(CdkLauncherError) as error:
        probe_localstack_health(endpoint, timeout_seconds=1)

    assert error.value.__cause__ is None


def test_probe_localstack_health_reaps_helper_when_interrupted(monkeypatch):
    class InterruptedProcess:
        returncode = None
        killed = False

        def communicate(self, timeout=None):
            if not self.killed:
                raise KeyboardInterrupt
            self.returncode = -9
            return b"", None

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True

    process = InterruptedProcess()
    monkeypatch.setattr(cdk_module.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(KeyboardInterrupt):
        probe_localstack_health("http://127.0.0.1:4566", timeout_seconds=1)

    assert process.killed is True
    assert process.returncode == -9


def test_probe_localstack_health_uses_isolated_helper_environment(http_server, monkeypatch):
    endpoint, _ = http_server()
    parent_popen = subprocess.Popen
    invocation = {}

    def recording_popen(arguments, **kwargs):
        invocation.update(arguments=arguments, **kwargs)
        return parent_popen(arguments, **kwargs)

    monkeypatch.setattr(cdk_module.subprocess, "Popen", recording_popen)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "parent-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")

    probe_localstack_health(endpoint, timeout_seconds=1)

    arguments = invocation["arguments"]
    assert arguments[1:3] == ["-I", "-S"]
    assert os.path.isabs(arguments[3])
    assert invocation["cwd"] == os.path.dirname(arguments[3])
    assert not any(
        name.startswith("AWS_") or name.endswith("_PROXY") or name in {"PYTHONPATH", "PYTHONHOME"}
        for name in invocation["env"]
    )


@pytest.mark.parametrize(
    ("output", "version"),
    [
        ("2.177.0", "2.177.0"),
        ("2.241.1 (build abc123)", "2.241.1"),
        ("2.1000.0", "2.1000.0"),
    ],
)
def test_probe_cdk_cli_version_accepts_supported_versions(tmp_path, output, version):
    executable = tmp_path / "cdk"
    executable.write_text(f"#!{sys.executable}\nprint({output!r})\n")
    executable.chmod(0o700)

    assert probe_cdk_cli_version(str(executable), environment={}) == version


@pytest.mark.parametrize("version", ["1.204.0", "2.176.999"])
def test_probe_cdk_cli_version_rejects_unsupported_versions(tmp_path, version):
    executable = tmp_path / "cdk"
    executable.write_text(f"#!{sys.executable}\nprint({version!r})\n")
    executable.chmod(0o700)

    with pytest.raises(CdkLauncherError):
        probe_cdk_cli_version(str(executable), environment={})


@pytest.mark.parametrize(
    "output",
    [
        "Node.js 22.0.0\\nAWS CDK 2.1.0",
        "2.177.0-beta.0",
        "warning 9.9.9\\n2.177.0",
    ],
)
def test_probe_cdk_cli_version_rejects_ambiguous_or_prerelease_output(tmp_path, output):
    executable = tmp_path / "cdk"
    executable.write_text(f"#!{sys.executable}\nprint({output!r})\n")
    executable.chmod(0o700)

    with pytest.raises(CdkLauncherError):
        probe_cdk_cli_version(str(executable), environment={})


def test_cdk_cli_runs_fake_executable_with_safe_environment(http_server):
    endpoint, _ = http_server()
    script = """
import json
import os
import sys

print(json.dumps({"arguments": sys.argv[1:], "environment": {
    "AWS_ACCESS_KEY_ID": os.environ["AWS_ACCESS_KEY_ID"],
    "AWS_ENDPOINT_URL": os.environ["AWS_ENDPOINT_URL"],
    "AWS_PROFILE": os.environ.get("AWS_PROFILE"),
    "CDK_DEFAULT_ACCOUNT": os.environ["CDK_DEFAULT_ACCOUNT"],
}}))
"""
    result = CliRunner().invoke(
        cli,
        [
            "--endpoint-url",
            endpoint,
            "--exec",
            sys.executable,
            "--unsafe-skip-version-check",
            "--",
            "-c",
            script,
            "with spaces",
            ";",
        ],
        env={"AWS_PROFILE": "production"},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == {
        "arguments": ["with spaces", ";"],
        "environment": {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_ENDPOINT_URL": endpoint,
            "AWS_PROFILE": None,
            "CDK_DEFAULT_ACCOUNT": "000000000000",
        },
    }


def test_cdk_cli_preflight_failure_prevents_child_execution(http_server, tmp_path):
    endpoint, _ = http_server(status=503)
    marker = tmp_path / "child-started"
    result = CliRunner().invoke(
        cli,
        [
            "--endpoint-url",
            endpoint,
            "--exec",
            sys.executable,
            "--",
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ],
    )

    assert result.exit_code == 125
    assert "preflight" in result.output.lower()
    assert not marker.exists()


def test_cdk_cli_version_failure_prevents_child_execution(http_server, tmp_path):
    endpoint, _ = http_server()
    marker = tmp_path / "child-started"
    executable = tmp_path / "cdk"
    executable.write_text(
        f"""#!{sys.executable}
import pathlib
import sys

if sys.argv[1:] == ["--version"]:
    print("2.176.0")
else:
    pathlib.Path({str(marker)!r}).touch()
"""
    )
    executable.chmod(0o700)

    result = CliRunner().invoke(
        cli,
        ["--endpoint-url", endpoint, "--exec", str(executable), "--", "deploy"],
    )

    assert result.exit_code == 125
    assert "2.177.0" in result.output
    assert not marker.exists()


def test_cdk_cli_propagates_exit_code_and_reports_truncation(http_server):
    endpoint, _ = http_server()
    result = CliRunner().invoke(
        cli,
        [
            "--endpoint-url",
            endpoint,
            "--exec",
            sys.executable,
            "--max-capture-bytes",
            "8",
            "--unsafe-skip-version-check",
            "--",
            "-c",
            "import sys; print('0123456789'); print('abcdefghij', file=sys.stderr); sys.exit(7)",
        ],
    )

    assert result.exit_code == 7
    assert "01234567" in result.output
    assert "abcdefgh" in result.output
    assert "truncated" in result.output.lower()


def test_cdk_cli_stops_parsing_launcher_options_after_cdk_command(tmp_path):
    executable = tmp_path / "cdk"
    executable.write_text(
        f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n"
    )
    executable.chmod(0o700)

    result = CliRunner().invoke(
        cli,
        [
            "--no-preflight",
            "--unsafe-skip-version-check",
            "--exec",
            str(executable),
            "deploy",
            "--timeout-seconds",
            "5",
            "--no-preflight",
            "--exec",
            "other",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == [
        "deploy",
        "--timeout-seconds",
        "5",
        "--no-preflight",
        "--exec",
        "other",
    ]


def test_cdk_cli_uses_documented_environment_precedence(tmp_path):
    executable = tmp_path / "cdk"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], "
        "'endpoint': os.environ['AWS_ENDPOINT_URL'], "
        "'s3': os.environ['AWS_ENDPOINT_URL_S3'], "
        "'region': os.environ['AWS_REGION']}))\n"
    )
    executable.chmod(0o700)

    result = CliRunner().invoke(
        cli,
        ["--no-preflight", "--unsafe-skip-version-check", "synth"],
        env={
            "LSTK_CDK_CMD": str(executable),
            "AWS_ENDPOINT_URL": "http://127.0.0.1:4566",
            "AWS_ENDPOINT_URL_S3": "http://127.0.0.1:4572",
            "AWS_REGION": "eu-west-1",
        },
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "argv": ["synth"],
        "endpoint": "http://127.0.0.1:4566",
        "s3": "http://127.0.0.1:4572",
        "region": "eu-west-1",
    }


def test_cdk_cli_explicit_options_override_environment(tmp_path):
    executable = tmp_path / "cdk"
    ignored_executable = tmp_path / "ignored-cdk"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os\n"
        "print(json.dumps({'endpoint': os.environ['AWS_ENDPOINT_URL'], "
        "'s3': os.environ['AWS_ENDPOINT_URL_S3'], "
        "'region': os.environ['AWS_REGION']}))\n"
    )
    executable.chmod(0o700)

    result = CliRunner().invoke(
        cli,
        [
            "--no-preflight",
            "--unsafe-skip-version-check",
            "--exec",
            str(executable),
            "--endpoint-url",
            "http://127.0.0.1:4566",
            "--s3-endpoint-url",
            "http://127.0.0.1:4572",
            "--region",
            "ap-southeast-2",
            "synth",
        ],
        env={
            "LSTK_CDK_CMD": str(ignored_executable),
            "AWS_ENDPOINT_URL": "http://127.0.0.1:5566",
            "AWS_ENDPOINT_URL_S3": "http://127.0.0.1:5572",
            "AWS_REGION": "eu-west-1",
        },
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "endpoint": "http://127.0.0.1:4566",
        "s3": "http://127.0.0.1:4572",
        "region": "ap-southeast-2",
    }


def test_cdk_cli_rejects_forced_interactive_mode_without_terminal(tmp_path):
    executable = tmp_path / "cdk"
    executable.write_text(f"#!{sys.executable}\n")
    executable.chmod(0o700)

    result = CliRunner().invoke(
        cli,
        [
            "--no-preflight",
            "--unsafe-skip-version-check",
            "--interactive",
            "--exec",
            str(executable),
            "synth",
        ],
    )

    assert result.exit_code == 125
    assert "requires a terminal" in result.output
