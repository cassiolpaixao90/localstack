import ipaddress
import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from typing import BinaryIO
from urllib.parse import urlsplit

import click

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
_TERMINATION_GRACE_SECONDS = 0.5
MAX_CDK_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_CDK_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_PREFLIGHT_TIMEOUT_SECONDS = 10
_MAX_HEALTH_RESPONSE_BYTES = 64 * 1024
_DEFAULT_ENDPOINT_URL = "http://localhost.localstack.cloud:4566"
_MINIMUM_CDK_CLI_VERSION = (2, 177, 0)
_MINIMUM_CDK_CLI_VERSION_TEXT = ".".join(str(part) for part in _MINIMUM_CDK_CLI_VERSION)
_HEALTH_PROBE_LOCK = threading.Lock()
_HEALTH_HELPER_ENVIRONMENT = frozenset({"LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR"})


class CdkLauncherError(ValueError):
    """Raised when CDK could escape the configured local environment."""


class CdkExecutableError(CdkLauncherError):
    def __init__(self, result: "CdkLaunchResult"):
        super().__init__("CDK executable could not be started")
        self.result = result


@dataclass(frozen=True)
class CdkLaunchResult:
    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool


class _BoundedCapture:
    def __init__(self, limit: int):
        self.limit = limit
        self.content = bytearray()
        self.total_bytes = 0

    def append(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        remaining = self.limit - len(self.content)
        if remaining > 0:
            self.content.extend(chunk[:remaining])

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self.content)


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


def probe_localstack_health(
    endpoint_url: str,
    *,
    timeout_seconds: float = 2,
    allowed_remote_hosts: Collection[str] = (),
) -> dict:
    """Verify a bounded health response without proxies or redirects."""
    endpoint_url = validate_local_endpoint(endpoint_url, allowed_remote_hosts=allowed_remote_hosts)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > MAX_PREFLIGHT_TIMEOUT_SECONDS
        or not math.isfinite(timeout_seconds)
    ):
        raise CdkLauncherError(
            "preflight timeout must be greater than 0 "
            f"and at most {MAX_PREFLIGHT_TIMEOUT_SECONDS} seconds"
        )

    deadline = time.monotonic() + timeout_seconds
    remaining = max(0, deadline - time.monotonic())
    if not _HEALTH_PROBE_LOCK.acquire(timeout=remaining):
        raise CdkLauncherError("preflight failed: total deadline exceeded")
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            helper_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "_cdk_health_probe.py")
            )
            helper_environment = {
                name: value
                for name, value in os.environ.items()
                if name in _HEALTH_HELPER_ENVIRONMENT
            }
            helper_environment["PYTHONIOENCODING"] = "utf-8"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    helper_path,
                    endpoint_url,
                ],
                cwd=os.path.dirname(helper_path),
                env=helper_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise CdkLauncherError(f"preflight failed: {error}") from None

        remaining = max(0, deadline - time.monotonic())
        try:
            output, _ = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise CdkLauncherError("preflight failed: total deadline exceeded")
        if time.monotonic() > deadline:
            raise CdkLauncherError("preflight failed: total deadline exceeded")
    finally:
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        _HEALTH_PROBE_LOCK.release()

    if process.returncode or not output:
        raise CdkLauncherError("preflight failed: health helper exited unexpectedly")
    kind, body = output[:1], output[1:]
    if kind == b"E":
        raise CdkLauncherError(f"preflight failed: {body.decode(errors='replace')}") from None
    if kind != b"O":
        raise CdkLauncherError("preflight failed: invalid health helper response")

    if len(body) > _MAX_HEALTH_RESPONSE_BYTES:
        raise CdkLauncherError("preflight failed: health response exceeds 65536 bytes")
    try:
        health = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CdkLauncherError("preflight failed: health response is not valid JSON") from error
    if (
        not isinstance(health, dict)
        or not isinstance(health.get("services"), dict)
        or not isinstance(health.get("version"), str)
        or not health["version"]
    ):
        raise CdkLauncherError("preflight failed: endpoint did not identify as LocalStack")
    return health


def launch_cdk(
    arguments: Sequence[str],
    *,
    executable: str = "cdk",
    environment: Mapping[str, str],
    cwd: str | PathLike[str] | None = None,
    timeout_seconds: float = 30 * 60,
    max_output_bytes: int = 1024 * 1024,
    stdin: BinaryIO | int | None = subprocess.DEVNULL,
    stdout: BinaryIO | int | None = subprocess.PIPE,
    stderr: BinaryIO | int | None = subprocess.PIPE,
) -> CdkLaunchResult:
    """Execute trusted CDK with bounded capture and POSIX process-group runtime."""
    if os.name != "posix":
        raise CdkLauncherError("safe CDK process supervision is not available on this platform")
    if not executable or not isinstance(executable, str):
        raise CdkLauncherError("CDK executable must be a non-empty string")
    if isinstance(arguments, (str, bytes)) or not all(
        isinstance(argument, str) for argument in arguments
    ):
        raise CdkLauncherError("CDK arguments must be a sequence of strings")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > MAX_CDK_TIMEOUT_SECONDS
        or not math.isfinite(timeout_seconds)
    ):
        raise CdkLauncherError(
            f"CDK timeout must be greater than 0 and at most {MAX_CDK_TIMEOUT_SECONDS} seconds"
        )
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes < 0
        or max_output_bytes > MAX_CDK_CAPTURE_BYTES
    ):
        raise CdkLauncherError(
            f"CDK capture limit must be an integer from 0 to {MAX_CDK_CAPTURE_BYTES} bytes"
        )

    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)
    popen_options = {
        "cwd": cwd,
        "env": dict(environment),
        "stdin": stdin,
        "stdout": stdout,
        "stderr": stderr,
        "start_new_session": True,
        "bufsize": 0,
    }

    try:
        process = subprocess.Popen([executable, *arguments], **popen_options)
    except (FileNotFoundError, PermissionError) as error:
        stderr_capture.append(f"unable to execute {executable}: {error}\n".encode())
        return _launch_result(126, False, stdout_capture, stderr_capture)
    except OSError as error:
        raise CdkLauncherError(f"unable to start CDK: {error}") from error

    stop_readers = threading.Event()
    readers = []
    if stdout == subprocess.PIPE:
        readers.append(_start_reader(process.stdout, stdout_capture, stop_readers, "cdk-stdout"))
    if stderr == subprocess.PIPE:
        readers.append(_start_reader(process.stderr, stderr_capture, stop_readers, "cdk-stderr"))
    timed_out = threading.Event()
    stop_watchdog = threading.Event()
    watchdog = threading.Thread(
        target=_watch_timeout,
        args=(process.pid, timeout_seconds, stop_watchdog, timed_out),
        name="cdk-timeout",
        daemon=True,
    )
    watchdog.start()
    returncode: int
    try:
        returncode = process.wait()
    except KeyboardInterrupt:
        _terminate_process_group(process.pid)
        returncode = 130
    finally:
        stop_watchdog.set()
        watchdog.join()
        _terminate_process_group(process.pid)
        _finish_readers(process, readers, stop_readers)

    if timed_out.is_set():
        returncode = 124
    return _launch_result(returncode, timed_out.is_set(), stdout_capture, stderr_capture)


def probe_cdk_cli_version(
    executable: str,
    *,
    environment: Mapping[str, str],
    cwd: str | PathLike[str] | None = None,
) -> str:
    """Require a CDK CLI version that honors the standard endpoint environment."""
    result = launch_cdk(
        ["--version"],
        executable=executable,
        environment=environment,
        cwd=cwd,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    if result.returncode == 126:
        raise CdkExecutableError(result)
    if result.returncode:
        raise CdkLauncherError(f"CDK version check failed with exit code {result.returncode}")

    output = result.stdout.decode("utf-8", errors="replace").strip()
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?: \(build [^)]+\))?", output)
    if not match:
        raise CdkLauncherError("CDK version check returned an unrecognized version")
    version = tuple(int(part) for part in match.groups())
    if version < _MINIMUM_CDK_CLI_VERSION:
        raise CdkLauncherError(
            f"CDK CLI {_MINIMUM_CDK_CLI_VERSION_TEXT} or newer is required; "
            f"found {'.'.join(match.groups())}"
        )
    return ".".join(match.groups())


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


def _start_reader(
    stream: BinaryIO | None,
    capture: _BoundedCapture,
    stop: threading.Event,
    name: str,
) -> threading.Thread:
    def drain() -> None:
        if stream is None:
            return
        selector = selectors.DefaultSelector()
        try:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
            while not stop.is_set():
                for _ in selector.select(timeout=0.05):
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        return
                    capture.append(chunk)
        except (OSError, ValueError):
            pass
        finally:
            selector.close()

    thread = threading.Thread(target=drain, name=name, daemon=True)
    thread.start()
    return thread


def _finish_readers(
    process: subprocess.Popen[bytes],
    readers: Collection[threading.Thread],
    stop: threading.Event,
) -> None:
    deadline = time.monotonic() + 1
    for reader in readers:
        reader.join(max(0, deadline - time.monotonic()))
    stop.set()
    for reader in readers:
        reader.join(0.2)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    if any(reader.is_alive() for reader in readers):
        raise CdkLauncherError("failed to stop CDK output readers")


def _terminate_process_group(process_group_id: int) -> None:
    if not _process_group_exists(process_group_id):
        return
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except (PermissionError, ProcessLookupError):
        return
    deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while _process_group_exists(process_group_id) and time.monotonic() < deadline:
        time.sleep(0.01)
    if _process_group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            pass


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return False


def _watch_timeout(
    process_group_id: int,
    timeout_seconds: float,
    stop: threading.Event,
    timed_out: threading.Event,
) -> None:
    if stop.wait(timeout_seconds):
        return
    timed_out.set()
    _terminate_process_group(process_group_id)


def _launch_result(
    returncode: int,
    timed_out: bool,
    stdout: _BoundedCapture,
    stderr: _BoundedCapture,
) -> CdkLaunchResult:
    return CdkLaunchResult(
        returncode=returncode,
        timed_out=timed_out,
        stdout=bytes(stdout.content),
        stderr=bytes(stderr.content),
        stdout_bytes=stdout.total_bytes,
        stderr_bytes=stderr.total_bytes,
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


@click.command(
    context_settings={
        "allow_extra_args": True,
        "allow_interspersed_args": False,
        "help_option_names": ["-h", "--help"],
        "ignore_unknown_options": True,
    }
)
@click.option("--exec", "executable", envvar="LSTK_CDK_CMD", default="cdk", show_default=True)
@click.option(
    "--endpoint-url",
    envvar=["AWS_ENDPOINT_URL", "LOCALSTACK_ENDPOINT_URL"],
    default=_DEFAULT_ENDPOINT_URL,
    show_default=True,
)
@click.option("--s3-endpoint-url", envvar="AWS_ENDPOINT_URL_S3")
@click.option(
    "--region",
    envvar=["AWS_REGION", "AWS_DEFAULT_REGION"],
    default=AWS_REGION_US_EAST_1,
    show_default=True,
)
@click.option("--account-id", default=DEFAULT_AWS_ACCOUNT_ID, show_default=True)
@click.option("--cwd", type=click.Path(file_okay=False, path_type=str))
@click.option("--timeout-seconds", type=float, default=30 * 60, show_default=True)
@click.option(
    "--max-capture-bytes",
    "max_output_bytes",
    type=int,
    default=1024 * 1024,
    show_default=True,
)
@click.option("--preflight-timeout-seconds", type=float, default=2, show_default=True)
@click.option("--allow-remote-host", multiple=True)
@click.option("--pass-env", "pass_environment", multiple=True)
@click.option("--preflight/--no-preflight", default=True, show_default=True)
@click.option("--unsafe-skip-version-check", is_flag=True, default=False)
@click.option("--interactive/--non-interactive", default=None)
@click.argument("cdk_arguments", nargs=-1, type=click.UNPROCESSED)
def cli(
    executable: str,
    endpoint_url: str,
    s3_endpoint_url: str | None,
    region: str,
    account_id: str,
    cwd: str | None,
    timeout_seconds: float,
    max_output_bytes: int,
    preflight_timeout_seconds: float,
    allow_remote_host: tuple[str, ...],
    pass_environment: tuple[str, ...],
    preflight: bool,
    unsafe_skip_version_check: bool,
    interactive: bool | None,
    cdk_arguments: tuple[str, ...],
) -> None:
    """Run the standard AWS CDK CLI against LocalStack.

    Launcher options precede the CDK command; everything after it is passed literally.
    """
    try:
        if preflight:
            probe_localstack_health(
                endpoint_url,
                timeout_seconds=preflight_timeout_seconds,
                allowed_remote_hosts=allow_remote_host,
            )
        environment = build_cdk_environment(
            os.environ,
            endpoint_url=endpoint_url,
            s3_endpoint_url=s3_endpoint_url,
            region=region,
            account_id=account_id,
            pass_environment=pass_environment,
            allowed_remote_hosts=allow_remote_host,
        )
        if not unsafe_skip_version_check:
            probe_cdk_cli_version(executable, environment=environment, cwd=cwd)
        stdin_stream = click.get_binary_stream("stdin")
        stdout_stream = click.get_binary_stream("stdout")
        stderr_stream = click.get_binary_stream("stderr")
        if interactive is None:
            interactive = stdin_stream.isatty()
        if interactive and not stdin_stream.isatty():
            raise CdkLauncherError("interactive mode requires a terminal on stdin")
        result = launch_cdk(
            cdk_arguments,
            executable=executable,
            environment=environment,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            stdin=None if interactive else subprocess.DEVNULL,
            stdout=_direct_stream_or_pipe(stdout_stream),
            stderr=_direct_stream_or_pipe(stderr_stream),
        )
    except CdkExecutableError as error:
        _emit_launch_result(error.result)
        raise click.exceptions.Exit(126) from error
    except CdkLauncherError as error:
        click.echo(f"CDK launcher failed: {error}", err=True)
        raise click.exceptions.Exit(125) from error

    _emit_launch_result(result)
    if result.returncode:
        raise click.exceptions.Exit(result.returncode)


def _direct_stream_or_pipe(stream: BinaryIO) -> BinaryIO | int:
    try:
        stream.fileno()
    except (AttributeError, OSError):
        return subprocess.PIPE
    return stream


def _emit_launch_result(result: CdkLaunchResult) -> None:
    stdout = click.get_binary_stream("stdout")
    stderr = click.get_binary_stream("stderr")
    stdout.write(result.stdout)
    stderr.write(result.stderr)
    stdout.flush()
    stderr.flush()
    if result.stdout_truncated:
        click.echo(
            f"CDK stdout truncated after {len(result.stdout)} of {result.stdout_bytes} bytes",
            err=True,
        )
    if result.stderr_truncated:
        click.echo(
            f"CDK stderr truncated after {len(result.stderr)} of {result.stderr_bytes} bytes",
            err=True,
        )


if __name__ == "__main__":
    cli()
