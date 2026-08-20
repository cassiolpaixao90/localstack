"""Amplify Swift 2.60.1 protocol gate on the native macOS runtime.

This is not iOS Simulator or Amplify UI evidence. Package resolution/build is
allowed to populate SwiftPM's external cache; the executable itself runs with
network access restricted to the test-owned loopback endpoints.

Host requirement: the harness binary carries a test-owned
keychain-access-groups entitlement. macOS 26 (amfid error -424) kills ad-hoc
signed binaries with restricted entitlements at launch, and the Amplify
keychain store cannot run without the entitlement, so this gate skips unless
the host accepts the ad-hoc restricted signature (older macOS) or a properly
provisioned signing identity is wired into the build.
"""

import concurrent.futures
import errno
import hashlib
import json
import os
import platform
import select
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    AmplifyV6Stack,
    _local_api_endpoint,
)
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    amplify_v6_stack as _amplify_v6_stack,
)

from localstack.testing.pytest import markers

THIS_FOLDER = Path(__file__).parent
SWIFT_SOURCE = THIS_FOLDER / "native" / "swift" / "Sources" / "AmplifyNativeGate" / "main.swift"
AMPLIFY_SWIFT_VERSION = "2.60.1"
AMPLIFY_SWIFT_REVISION = "82700377212a3e4afebfe1fdbcafb98a5fae8b17"
AMPLIFY_SWIFT_ARCHIVE_URL = (
    "https://github.com/aws-amplify/amplify-swift/archive/refs/tags/2.60.1.tar.gz"
)
AMPLIFY_SWIFT_ARCHIVE_SHA256 = "63a707b4817d6eb4a8162a6e00161d1c60bf836712d51e588a43b808781724ee"
MAX_BUILD_OUTPUT = 1024 * 1024
MAX_RUNTIME_OUTPUT = 128 * 1024
MAX_RELAY_CONNECTIONS = 256
MAX_RELAY_BYTES = 64 * 1024 * 1024

amplify_v6_stack = _amplify_v6_stack


class _TcpRelay:
    def __init__(self, destination_port: int):
        self.destination_port = destination_port
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listener.bind(("127.0.0.1", 443))
        except OSError as error:
            self.listener.close()
            if error.errno == errno.EADDRINUSE:
                raise AssertionError(
                    "native gate refuses to replace the process on TCP/443"
                ) from error
            raise
        self.listener.listen(32)
        self.listener.settimeout(0.25)
        self.stop = threading.Event()
        self.errors = []
        self.connections = 0
        self.transferred = 0
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("native loopback relay did not terminate")
        if self.errors:
            raise AssertionError(f"native loopback relay failed: {self.errors[0]}")

    def _serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self.stop.is_set():
                    self.errors.append(error)
                return
            self.connections += 1
            if self.connections > MAX_RELAY_CONNECTIONS:
                client.close()
                self.errors.append(AssertionError("native relay connection bound exceeded"))
                return
            threading.Thread(target=self._pipe, args=(client,), daemon=True).start()

    def _pipe(self, client: socket.socket):
        try:
            upstream = socket.create_connection(("127.0.0.1", self.destination_port), timeout=5)
            with client, upstream:
                client.setblocking(False)
                upstream.setblocking(False)
                sockets = [client, upstream]
                while not self.stop.is_set():
                    readable, _, exceptional = select.select(sockets, [], sockets, 0.25)
                    if exceptional:
                        return
                    for source in readable:
                        try:
                            data = source.recv(64 * 1024)
                        except BlockingIOError:
                            continue
                        if not data:
                            return
                        self.transferred += len(data)
                        if self.transferred > MAX_RELAY_BYTES:
                            self.errors.append(AssertionError("native relay byte bound exceeded"))
                            self.stop.set()
                            return
                        destination = upstream if source is client else client
                        destination.sendall(data)
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(error)


_DOCKER_RELAY_SOURCE = r"""import json
import signal
import socket
import sys
import threading

destination = (sys.argv[1], int(sys.argv[2]))
stop = threading.Event()
lock = threading.Lock()
connections = 0
transferred = 0
threads = []
listener = socket.create_server(("0.0.0.0", 8443))
listener.settimeout(0.25)

def terminate(*_args):
    stop.set()

def pipe(source, target):
    global transferred
    try:
        while not stop.is_set():
            data = source.recv(65536)
            if not data:
                return
            with lock:
                transferred += len(data)
                if transferred > 64 * 1024 * 1024:
                    stop.set()
                    return
            target.sendall(data)
    except OSError:
        return

def handle(client):
    try:
        upstream = socket.create_connection(destination, 5)
    except OSError:
        client.close()
        return
    for source, target in ((client, upstream), (upstream, client)):
        thread = threading.Thread(target=pipe, args=(source, target), daemon=True)
        threads.append(thread)
        thread.start()

signal.signal(signal.SIGTERM, terminate)
signal.signal(signal.SIGINT, terminate)
while not stop.is_set():
    try:
        client, _ = listener.accept()
    except TimeoutError:
        continue
    connections += 1
    if connections > 256:
        client.close()
        stop.set()
        break
    handle(client)
listener.close()
for thread in threads:
    thread.join(timeout=1)
print(json.dumps({"connections": connections, "transferred": transferred}), flush=True)
"""


class _DockerTcpRelay:
    """Privilege-safe raw TLS relay for macOS hosts that reject low-port binds."""

    def __init__(self, destination_port: int):
        self.destination_port = destination_port
        self.connections = 0
        self.transferred = 0
        self.name = f"ls-amplify-native-relay-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.docker = shutil.which("docker")
        if not self.docker:
            raise AssertionError("native TLS relay fallback requires Docker")

    def _source_image(self) -> str:
        listed = _bounded_run(
            [
                self.docker,
                "ps",
                "--filter",
                f"publish={self.destination_port}",
                "--format",
                "{{.ID}}",
            ],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=4096,
        )
        container_ids = [value for value in listed.stdout.decode().splitlines() if value]
        if listed.returncode or len(container_ids) != 1:
            raise AssertionError("native TLS relay requires exactly one container on the edge port")
        inspected = _bounded_run(
            [self.docker, "inspect", container_ids[0]],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=64 * 1024,
        )
        if inspected.returncode:
            raise AssertionError("unable to inspect the local edge container")
        details = json.loads(inspected.stdout)[0]
        bindings = details["HostConfig"]["PortBindings"].get("4566/tcp", [])
        if not any(
            binding.get("HostIp") in {"127.0.0.1", "localhost"}
            and binding.get("HostPort") == str(self.destination_port)
            for binding in bindings
        ):
            raise AssertionError("edge container is not bound to the expected loopback port")
        return details["Image"]

    def __enter__(self):
        image = self._source_image()
        started = _bounded_run(
            [
                self.docker,
                "run",
                "--detach",
                "--name",
                self.name,
                "--add-host",
                "host.docker.internal:host-gateway",
                "--publish",
                "127.0.0.1:443:8443",
                "--entrypoint",
                "python",
                image,
                "-c",
                _DOCKER_RELAY_SOURCE,
                "host.docker.internal",
                str(self.destination_port),
            ],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=30,
            limit=64 * 1024,
        )
        if started.returncode:
            raise AssertionError(
                f"unable to start native TLS relay: {started.stderr.decode(errors='replace')}"
            )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                probe = socket.create_connection(("127.0.0.1", 443), timeout=0.25)
                probe.close()
                return self
            except OSError:
                time.sleep(0.1)
        self._cleanup()
        raise AssertionError("native TLS relay did not become ready")

    def _cleanup(self):
        stopped = _bounded_run(
            [self.docker, "stop", "--time", "5", self.name],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=64 * 1024,
        )
        logs = _bounded_run(
            [self.docker, "logs", self.name],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=64 * 1024,
        )
        _bounded_run(
            [self.docker, "rm", self.name],
            cwd=Path.cwd(),
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=4096,
        )
        if stopped.returncode or logs.returncode:
            raise AssertionError("native TLS relay cleanup failed")
        summary = json.loads(logs.stdout.decode().splitlines()[-1])
        self.connections = summary["connections"]
        self.transferred = summary["transferred"]

    def __exit__(self, *_args):
        self._cleanup()


def _tls_relay(destination_port: int):
    try:
        return _TcpRelay(destination_port)
    except PermissionError:
        if platform.system() != "Darwin":
            raise
        return _DockerTcpRelay(destination_port)


def _bounded_run(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: int, limit: int, stdin=None
):
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise AssertionError(f"native gate command exceeded {timeout}s deadline") from error
    if len(stdout) > limit or len(stderr) > limit:
        raise AssertionError("native gate command exceeded its output bound")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _swift_cache() -> Path:
    return Path.home() / "Library" / "Caches" / "localstack" / "amplify-native-swift-2.60.1"


def _swift_executable() -> Path:
    swift = shutil.which("swift")
    sandbox = shutil.which("sandbox-exec")
    if platform.system() != "Darwin" or not swift or not sandbox:
        pytest.skip("Amplify Swift native gate requires macOS Swift and sandbox-exec")
    return Path(swift).resolve()


def _download_swift_archive() -> Path:
    cache = _swift_cache()
    archive = cache / "amplify-swift-2.60.1.tar.gz"
    cache.mkdir(parents=True, exist_ok=True)
    if (
        archive.is_file()
        and hashlib.sha256(archive.read_bytes()).hexdigest() != AMPLIFY_SWIFT_ARCHIVE_SHA256
    ):
        raise AssertionError("cached Amplify Swift archive hash mismatch")
    if not archive.is_file():
        temporary = archive.with_suffix(".download")
        curl = shutil.which("curl")
        if not curl:
            raise AssertionError("Amplify Swift archive download requires curl")
        result = _bounded_run(
            [
                curl,
                "--fail",
                "--location",
                "--max-time",
                "180",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--output",
                str(temporary),
                "--write-out",
                "%{url_effective}",
                AMPLIFY_SWIFT_ARCHIVE_URL,
            ],
            cwd=cache,
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=190,
            limit=4096,
        )
        final_url = result.stdout.decode().split("?", 1)[0]
        if result.returncode or not (
            final_url.startswith("https://github.com/aws-amplify/amplify-swift/")
            or final_url.startswith("https://codeload.github.com/aws-amplify/amplify-swift/")
        ):
            raise AssertionError("Amplify Swift archive download left its official origins")
        if temporary.stat().st_size > 64 * 1024 * 1024:
            raise AssertionError("Amplify Swift archive exceeded size bound")
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != AMPLIFY_SWIFT_ARCHIVE_SHA256:
            temporary.unlink(missing_ok=True)
            raise AssertionError("downloaded Amplify Swift archive hash mismatch")
        temporary.replace(archive)
    return archive


def _extract_swift_source(archive: Path, destination: Path) -> Path:
    destination.mkdir()
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if len(members) > 100_000:
            raise AssertionError("Amplify Swift archive member bound exceeded")
        for member in members:
            target = (destination / member.name).resolve()
            if destination.resolve() not in target.parents:
                raise AssertionError("Amplify Swift archive attempted path traversal")
        bundle.extractall(destination, filter="data")
    source = destination / "amplify-swift-2.60.1"
    if not (source / "Package.resolved").is_file():
        raise AssertionError("Amplify Swift archive omitted its official dependency lock")
    return source


def _ensure_swift_mirrors(source: Path) -> dict[str, Path]:
    lock = json.loads((source / "Package.resolved").read_text())
    mirrors = _swift_cache() / "mirrors"
    mirrors.mkdir(exist_ok=True)
    git = shutil.which("git")
    if not git:
        raise AssertionError("Amplify Swift source verification requires git")

    def prepare(pin: dict) -> tuple[str, Path]:
        identity = pin["identity"]
        location = pin["location"]
        state = pin["state"]
        destination = mirrors / f"{identity}.git"
        if destination.exists():
            verified = _bounded_run(
                [git, "--git-dir", str(destination), "rev-parse", "HEAD^{commit}"],
                cwd=mirrors,
                env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
                timeout=10,
                limit=4096,
            )
            if verified.returncode or verified.stdout.decode().strip() != state["revision"]:
                raise AssertionError(f"cached Swift mirror revision mismatch: {identity}")
            integrity = _bounded_run(
                [git, "--git-dir", str(destination), "fsck", "--strict", "--no-dangling"],
                cwd=mirrors,
                env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
                timeout=30,
                limit=64 * 1024,
            )
            if integrity.returncode:
                raise AssertionError(f"cached Swift mirror failed strict fsck: {identity}")
            return location, destination
        clone = _bounded_run(
            [
                git,
                "clone",
                "--bare",
                "--depth",
                "1",
                "--branch",
                state["version"],
                location,
                str(destination),
            ],
            cwd=mirrors,
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=180,
            limit=64 * 1024,
        )
        if clone.returncode:
            alternate = _bounded_run(
                [
                    git,
                    "clone",
                    "--bare",
                    "--depth",
                    "1",
                    "--branch",
                    f"v{state['version']}",
                    location,
                    str(destination),
                ],
                cwd=mirrors,
                env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
                timeout=180,
                limit=64 * 1024,
            )
            if alternate.returncode:
                raise AssertionError(f"unable to fetch pinned Swift dependency: {identity}")
        verified = _bounded_run(
            [git, "--git-dir", str(destination), "rev-parse", "HEAD^{commit}"],
            cwd=mirrors,
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=10,
            limit=4096,
        )
        if verified.stdout.decode().strip() != state["revision"]:
            raise AssertionError(f"downloaded Swift mirror revision mismatch: {identity}")
        integrity = _bounded_run(
            [git, "--git-dir", str(destination), "fsck", "--strict", "--no-dangling"],
            cwd=mirrors,
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=30,
            limit=64 * 1024,
        )
        if integrity.returncode:
            raise AssertionError(f"downloaded Swift mirror failed strict fsck: {identity}")
        return location, destination

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        return dict(executor.map(prepare, lock["pins"]))


def _build_swift_harness(work: Path, *, externally_sandboxed: bool = False) -> Path:
    swift = _swift_executable()
    source = _extract_swift_source(_download_swift_archive(), work / "amplify-source")
    mirrors = _ensure_swift_mirrors(source)
    package = work / "package"
    harness = package / "Sources" / "AmplifyNativeGate"
    harness.mkdir(parents=True)
    shutil.copy2(SWIFT_SOURCE, harness / "main.swift")
    (package / "Package.swift").write_text(
        f'''// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "AmplifyNativeGate",
    platforms: [.macOS(.v12)],
    dependencies: [.package(name: "amplify-swift", path: "{source}")],
    targets: [.executableTarget(
        name: "AmplifyNativeGate",
        dependencies: [
            .product(name: "Amplify", package: "amplify-swift"),
            .product(name: "AWSAPIPlugin", package: "amplify-swift"),
            .product(name: "AWSCognitoAuthPlugin", package: "amplify-swift"),
            .product(name: "AWSPluginsCore", package: "amplify-swift")
        ]
    )]
)
'''
    )
    shutil.copy2(source / "Package.resolved", package / "Package.resolved")

    scratch = Path.home() / "Library" / "Caches" / "localstack" / "amplify-native-swift-2.60.1"
    scratch.mkdir(parents=True, exist_ok=True)
    environment = {
        key: os.environ[key]
        for key in ("DEVELOPER_DIR", "HOME", "PATH", "SDKROOT", "TMPDIR")
        if key in os.environ
    }
    for original, mirror in mirrors.items():
        configured = _bounded_run(
            [
                str(swift),
                "package",
                "--package-path",
                str(package),
                "config",
                "set-mirror",
                "--original-url",
                original,
                "--mirror-url",
                mirror.as_uri(),
            ],
            cwd=package,
            env=environment,
            timeout=20,
            limit=4096,
        )
        if configured.returncode:
            raise AssertionError("unable to configure a pinned local Swift dependency mirror")
    build_command = [
        str(swift),
        "build",
        "--package-path",
        str(package),
        "--scratch-path",
        str(scratch),
        "--configuration",
        "release",
    ]
    if externally_sandboxed:
        build_command.append("--disable-sandbox")
    build_command.append("--disable-automatic-resolution")
    result = _bounded_run(
        build_command,
        cwd=package,
        env=environment,
        timeout=1200,
        limit=MAX_BUILD_OUTPUT,
    )
    if result.returncode:
        raise AssertionError(
            f"Amplify Swift build failed: {result.stderr.decode(errors='replace')}"
        )
    binary = scratch / "release" / "AmplifyNativeGate"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise AssertionError("Amplify Swift build did not produce the native executable")
    identifier = f"com.localstack.amplify-native-gate.{uuid.uuid4().hex}"
    entitlements = work / "AmplifyNativeGate.entitlements"
    entitlements.write_text(
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>{identifier}</string>
    <key>keychain-access-groups</key>
    <array><string>{identifier}</string></array>
</dict>
</plist>
"""
    )
    signed = _bounded_run(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--identifier",
            identifier,
            "--entitlements",
            str(entitlements),
            "--timestamp=none",
            str(binary),
        ],
        cwd=work,
        env=environment,
        timeout=30,
        limit=64 * 1024,
    )
    if signed.returncode:
        raise AssertionError(f"Amplify Swift ad-hoc signing failed: {signed.stderr.decode()}")
    # macOS 26 kills ad-hoc signed binaries carrying restricted entitlements at
    # launch (amfid error -424), and the Amplify keychain store cannot operate
    # without keychain-access-groups. Probe a launch and skip explicitly when
    # the host rejects the signature instead of failing opaquely at runtime.
    probe = _bounded_run(
        [str(binary)],
        cwd=work,
        env=environment,
        timeout=30,
        limit=64 * 1024,
        stdin=subprocess.DEVNULL,
    )
    if probe.returncode == -9:
        pytest.skip(
            "Amplify Swift native gate requires a signing identity whose keychain "
            "entitlements survive amfid; this host kills ad-hoc restricted signatures"
        )
    verified = _bounded_run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(binary)],
        cwd=work,
        env=environment,
        timeout=30,
        limit=64 * 1024,
    )
    if verified.returncode:
        raise AssertionError(
            f"Amplify Swift signature verification failed: {verified.stderr.decode()}"
        )
    dumped = _bounded_run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)],
        cwd=work,
        env=environment,
        timeout=30,
        limit=64 * 1024,
    )
    dumped_entitlements = dumped.stdout + dumped.stderr
    if dumped.returncode or dumped_entitlements.count(identifier.encode()) != 2:
        raise AssertionError("Amplify Swift test-owned keychain entitlements changed")
    if b"network" in dumped_entitlements.lower() or b"sandbox" in dumped_entitlements.lower():
        raise AssertionError(
            "Amplify Swift binary gained an unexpected network/sandbox entitlement"
        )
    return binary


def _configuration(stack: AmplifyV6Stack, region_name: str, cognito_host: str) -> dict:
    return {
        "auth": {
            "plugins": {
                "awsCognitoAuthPlugin": {
                    "CognitoUserPool": {
                        "Default": {
                            "AppClientId": stack.user_pool_client_id,
                            "Endpoint": cognito_host,
                            "PoolId": stack.user_pool_id,
                            "Region": region_name,
                        }
                    },
                    "Auth": {"Default": {"authenticationFlowType": "USER_SRP_AUTH"}},
                }
            }
        },
        "api": {
            "plugins": {
                "awsAPIPlugin": {
                    "billgym": {
                        "authorizationType": "NONE",
                        "endpoint": stack.api_endpoint,
                        "endpointType": "REST",
                        "region": region_name,
                    }
                }
            }
        },
    }


@markers.aws.only_localstack
def test_amplify_swift_native_protocol(
    amplify_v6_stack: AmplifyV6Stack,
    region_name: str,
):
    endpoint = urlsplit(os.environ.get("AWS_ENDPOINT_URL", "http://127.0.0.1:4566"))
    if endpoint.hostname not in {"127.0.0.1", "localhost"} or endpoint.port is None:
        raise AssertionError("native Swift gate requires an explicit loopback edge port")
    before = hashlib.sha256(SWIFT_SOURCE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="amplify-swift-native-") as directory:
        work = Path(directory)
        binary = _build_swift_harness(work)
        stack = AmplifyV6Stack(
            **{
                **amplify_v6_stack.__dict__,
                "api_endpoint": _local_api_endpoint(amplify_v6_stack.api_endpoint),
            }
        )
        cognito_host = "cognito-native.localhost.localstack.cloud"
        configuration_file = work / "amplifyconfiguration.json"
        configuration_file.write_text(json.dumps(_configuration(stack, region_name, cognito_host)))
        request = {
            "apiEndpoint": stack.api_endpoint,
            "configurationFile": str(configuration_file),
            "newPassword": stack.new_password,
            "tenantId": stack.tenant_id,
            "temporaryPassword": stack.temporary_password,
            "userPoolClientId": stack.user_pool_client_id,
            "username": stack.username,
        }
        api_port = urlsplit(stack.api_endpoint).port
        if api_port is None:
            raise AssertionError("native Swift API endpoint lost its explicit port")
        profile = (
            "(version 1)(allow default)(deny network*)"
            '(allow network-outbound (literal "/private/var/run/mDNSResponder"))'
            f'(allow network-outbound (remote ip "localhost:443" "localhost:{api_port}"))'
        )
        environment = {
            "HOME": str(work / "home"),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(work / "tmp"),
        }
        Path(environment["HOME"]).mkdir()
        Path(environment["TMPDIR"]).mkdir()
        with _tls_relay(endpoint.port) as relay:
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-p", profile, str(binary)],
                input=json.dumps(request).encode(),
                capture_output=True,
                timeout=120,
                env=environment,
                check=False,
            )
        if len(result.stdout) > MAX_RUNTIME_OUTPUT or len(result.stderr) > MAX_RUNTIME_OUTPUT:
            raise AssertionError("Amplify Swift runtime exceeded its output bound")
        if result.returncode:
            raise AssertionError(
                f"Amplify Swift native gate failed: {result.stderr.decode(errors='replace')}"
            )
        evidence = json.loads(result.stdout)
        assert evidence == {
            "apiStatus": "ok",
            "globalSignOut": True,
            "groups": ["trainer"],
            "keychainItemsAfterSignOut": 0,
            "newPassword": True,
            "refresh": True,
            "sdk": "Amplify Swift 2.60.1",
            "tenantId": stack.tenant_id,
            "totp": True,
        }
        assert relay.connections > 0
        assert relay.transferred > 0
    assert hashlib.sha256(SWIFT_SOURCE.read_bytes()).hexdigest() == before
