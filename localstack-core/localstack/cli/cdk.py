import ipaddress
import math
import os
import re
import selectors
import signal
import subprocess
import threading
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from typing import BinaryIO
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
_TERMINATION_GRACE_SECONDS = 0.5
MAX_CDK_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_CDK_OUTPUT_BYTES = 64 * 1024 * 1024


class CdkLauncherError(ValueError):
    """Raised when CDK could escape the configured local environment."""


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


def launch_cdk(
    arguments: Sequence[str],
    *,
    executable: str = "cdk",
    environment: Mapping[str, str],
    cwd: str | PathLike[str] | None = None,
    timeout_seconds: float = 30 * 60,
    max_output_bytes: int = 1024 * 1024,
) -> CdkLaunchResult:
    """Execute trusted CDK in a POSIX process group with bounded output and runtime."""
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
        or max_output_bytes > MAX_CDK_OUTPUT_BYTES
    ):
        raise CdkLauncherError(
            f"CDK output limit must be an integer from 0 to {MAX_CDK_OUTPUT_BYTES} bytes"
        )

    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)
    popen_options = {
        "cwd": cwd,
        "env": dict(environment),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
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
    readers = [
        _start_reader(process.stdout, stdout_capture, stop_readers, "cdk-stdout"),
        _start_reader(process.stderr, stderr_capture, stop_readers, "cdk-stderr"),
    ]
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
