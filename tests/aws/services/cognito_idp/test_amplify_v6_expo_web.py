"""Real Billgym Expo Web Authenticator gate using headless Chrome and CDP."""

import base64
import hashlib
import hmac
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

import pytest
import requests
import websocket
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    AmplifyV6Stack,
)
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    amplify_v6_stack as _amplify_v6_stack,
)

from localstack.cli.cdk import launch_cdk
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition

DEFAULT_BILLGYM = Path("/Users/cassiopaixao/GolandProjects/billgym")
MAX_BUILD_OUTPUT = 1024 * 1024
MAX_BROWSER_EVENTS = 4096
MAX_CHROME_LOG = 128 * 1024
MAX_NODE_MODULE_ENTRIES = 200_000
NODE_ARCHIVE_SHA256 = "61130f394c1630d211dd50aecc4353d379480f36d3ac913cd85dbba1aed585c6"
NODE_VERSION = "v22.23.2"
CHROME_ARCHIVE_SHA256 = "4b3caaabb967070f1541ff5b0fd2c95b2ba839be33a58842a8a877ec5f3fbd9b"
CHROME_VERSION = "151.0.7922.77"
COGNITO_BROWSER_HEADERS = {
    "amz-sdk-invocation-id",
    "amz-sdk-request",
    "cache-control",
    "content-type",
    "x-amz-target",
    "x-amz-user-agent",
}

# Make the fixture available to this module without shadowing the test argument.
amplify_v6_stack = _amplify_v6_stack


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


class _BoundedPipe:
    def __init__(self, limit: int):
        self.read_fd, self.write_fd = os.pipe()
        self.limit = limit
        self.output = bytearray()
        self.truncated = False
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _drain(self):
        with os.fdopen(self.read_fd, "rb") as stream:
            while chunk := stream.read(8192):
                remaining = self.limit - len(self.output)
                if remaining > 0:
                    self.output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True

    def parent_close(self):
        os.close(self.write_fd)

    def finish(self) -> str:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise TimeoutError("Chrome log drain did not stop")
        suffix = "\n<chrome log truncated>" if self.truncated else ""
        return self.output.decode(errors="replace") + suffix


class _Cdp:
    def __init__(
        self,
        websocket_url: str,
        localstack_endpoint: str,
        app_origin: str,
        cognito_origin: str,
    ):
        self.ws = websocket.create_connection(websocket_url, timeout=0.5, suppress_origin=True)
        self.next_id = 0
        self.localstack_endpoint = localstack_endpoint
        self.app_origin = app_origin
        self.cognito_origin = cognito_origin
        self.http = requests.Session()
        self.http.trust_env = False
        self.network = []
        self.console = []
        self.targets = []
        self.api_paths = []
        self.failures = []
        self.responses = []

    def close(self):
        self.ws.close()
        self.http.close()

    def _send(self, method: str, params: dict | None = None) -> int:
        self.next_id += 1
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params or {}}))
        return self.next_id

    def command(self, method: str, params: dict | None = None, timeout: float = 10):
        command_id = self._send(method, params)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = json.loads(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                continue
            if "method" in message:
                self._event(message)
            elif message.get("id") == command_id:
                if "error" in message:
                    raise AssertionError(f"CDP {method} failed: {message['error']}")
                return message.get("result", {})
        raise TimeoutError(f"CDP command timed out: {method}")

    def _event(self, message: dict):
        method, params = message["method"], message.get("params", {})
        if method == "Fetch.requestPaused":
            self._proxy_cognito(params)
        elif method == "Network.requestWillBeSent":
            self._append(self.network, params["request"]["url"], "network")
        elif method in {"Runtime.consoleAPICalled", "Runtime.exceptionThrown"}:
            self._append(self.console, {"method": method, "params": params}, "console")
        elif method == "Network.responseReceived":
            url = params["response"]["url"]
            self._append(
                self.responses,
                (url, params["response"]["status"]),
                "network response",
            )
            if "/v1/" in url:
                self._append(
                    self.api_paths,
                    (url, params["response"]["status"]),
                    "API response",
                )
        elif method == "Network.loadingFailed":
            self._append(
                self.failures,
                {
                    "blockedReason": params.get("blockedReason"),
                    "errorText": params.get("errorText"),
                    "type": params.get("type"),
                },
                "network failure",
            )

    @staticmethod
    def _append(items: list, item, label: str):
        if len(items) >= MAX_BROWSER_EVENTS:
            raise AssertionError(f"browser exceeded bounded {label} evidence")
        items.append(item)

    def _proxy_cognito(self, params: dict):
        request_id = params["requestId"]
        request = params["request"]
        url = request["url"]
        if not re.fullmatch(rf"{re.escape(self.cognito_origin)}/", url):
            raise AssertionError(f"unexpected intercepted origin: {url}")
        headers = request.get("headers", {})
        lower_headers = {key.lower(): value for key, value in headers.items()}
        if lower_headers.get("origin") != self.app_origin:
            raise AssertionError("Cognito adapter rejected a non-gate browser origin")
        if request["method"] not in {"OPTIONS", "POST"}:
            raise AssertionError(f"unexpected Cognito browser method: {request['method']}")
        if (
            request["method"] == "OPTIONS"
            and lower_headers.get("access-control-request-method") != "POST"
        ):
            raise AssertionError("Cognito adapter rejected a non-POST preflight")
        requested_headers = {
            item.strip().lower()
            for item in lower_headers.get("access-control-request-headers", "").split(",")
            if item.strip()
        }
        if not requested_headers <= COGNITO_BROWSER_HEADERS:
            raise AssertionError(
                f"unexpected Cognito preflight headers: {sorted(requested_headers)}"
            )
        if request["method"] == "OPTIONS":
            status, body, response_headers = 204, b"", []
        else:
            forwarded = {
                key: value
                for key, value in headers.items()
                if key.lower() in COGNITO_BROWSER_HEADERS
            }
            forwarded["Host"] = urlsplit(self.cognito_origin).netloc
            response = self.http.request(
                request["method"],
                self.localstack_endpoint,
                allow_redirects=False,
                data=request.get("postData", "").encode(),
                headers=forwarded,
                timeout=5,
            )
            if 300 <= response.status_code < 400:
                raise AssertionError("Cognito adapter rejected a LocalStack redirect")
            status, body = response.status_code, response.content
            response_headers = [
                {
                    "name": "content-type",
                    "value": response.headers.get("content-type", "application/json"),
                }
            ]
            target = lower_headers.get("x-amz-target")
            if target:
                self._append(self.targets, target, "Cognito target")
        response_headers.extend(
            [
                {"name": "access-control-allow-origin", "value": self.app_origin},
                {"name": "access-control-allow-methods", "value": "POST,OPTIONS"},
                {
                    "name": "access-control-allow-headers",
                    "value": ",".join(sorted(requested_headers)),
                },
                {"name": "vary", "value": "origin"},
            ]
        )
        self._send(
            "Fetch.fulfillRequest",
            {
                "requestId": request_id,
                "responseCode": status,
                "responseHeaders": response_headers,
                "body": base64.b64encode(body).decode(),
            },
        )

    def evaluate(self, expression: str):
        result = self.command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )["result"]
        if result.get("subtype") == "error":
            raise AssertionError(result.get("description", "browser evaluation failed"))
        return result.get("value")

    def wait(self, expression: str, timeout: float = 15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.evaluate(expression):
                return
            time.sleep(0.15)
        text = self.evaluate("document.body.innerText.slice(0,4000)")
        evidence = {
            "console": self.console[-10:],
            "failures": self.failures[-20:],
            "network": self.network[-20:],
            "responses": self.responses[-20:],
            "targets": self.targets[-20:],
        }
        raise TimeoutError(
            f"UI checkpoint timed out: {expression}\n{text}\n"
            f"bounded CDP evidence: {json.dumps(evidence, default=str)[-12000:]}"
        )

    def fill_visible(self, values: list[str]):
        expression = f"""
        (() => {{
          const inputs = [...document.querySelectorAll('input')].filter(e => e.offsetParent !== null);
          const values = {json.dumps(values)};
          if (inputs.length !== values.length) return {{inputs: inputs.length, values: values.length}};
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          inputs.forEach((input, index) => {{
            setter.call(input, values[index]);
            input.dispatchEvent(new Event('input', {{bubbles:true}}));
            input.dispatchEvent(new Event('change', {{bubbles:true}}));
          }});
          return true;
        }})()
        """
        result = self.evaluate(expression)
        if result is not True:
            raise AssertionError(f"visible input contract mismatch: {result}")

    def click(self, texts: list[str] = None, aria: str | None = None):
        expression = f"""
        (() => {{
          const visible = e => e.offsetParent !== null && !e.disabled;
          const nodes = [...document.querySelectorAll('button,[role=button]')].filter(visible);
          const texts = {json.dumps(texts or [])};
          const target = {f"nodes.find(e => e.getAttribute('aria-label') === {json.dumps(aria)})" if aria else "nodes.find(e => texts.some(t => (e.innerText || e.textContent || '').trim().includes(t)))"};
          if (!target) return nodes.map(e => (e.getAttribute('aria-label') || e.innerText || '').trim());
          target.click(); return true;
        }})()
        """
        result = self.evaluate(expression)
        if result is not True:
            raise AssertionError(f"button not found: {aria or texts}; visible={result}")


def _totp(secret: str, offset_steps: int = 0) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    step = int(time.time()) // 30 + offset_steps
    digest = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(int.from_bytes(digest[offset : offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def _billgym_checkout() -> Path:
    checkout = Path(os.environ.get("BILLGYM_CHECKOUT", DEFAULT_BILLGYM)).resolve()
    if not (checkout / "apps/mobile/package.json").is_file():
        pytest.skip("Billgym mobile checkout is unavailable")
    return checkout


def _node_modules_inventory(checkout: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    for root in (checkout / "node_modules", checkout / "apps/mobile/node_modules"):
        for directory, directories, files in os.walk(root, followlinks=False):
            for name in sorted([*directories, *files]):
                path = Path(directory, name)
                stat = path.lstat()
                relative = path.relative_to(checkout)
                digest.update(
                    f"{relative}\0{stat.st_mode}\0{stat.st_size}\0{stat.st_mtime_ns}\0".encode()
                )
                if path.is_symlink():
                    digest.update(os.readlink(path).encode())
                count += 1
                if count > MAX_NODE_MODULE_ENTRIES:
                    raise AssertionError("Billgym dependency inventory exceeded its bound")
    return digest.hexdigest()


def _copy_billgym(checkout: Path, workspace: Path):
    (workspace / "apps").mkdir(parents=True)
    shutil.copytree(
        checkout / "apps/mobile",
        workspace / "apps/mobile",
        ignore=shutil.ignore_patterns("node_modules", ".expo", ".env", "dist"),
    )
    shutil.copy2(checkout / "package.json", workspace / "package.json")
    shutil.copy2(checkout / "pnpm-workspace.yaml", workspace / "pnpm-workspace.yaml")
    (workspace / "node_modules").symlink_to(checkout / "node_modules", target_is_directory=True)
    (workspace / "apps/mobile/node_modules").symlink_to(
        checkout / "apps/mobile/node_modules", target_is_directory=True
    )


def _extract_node(workspace: Path) -> Path:
    archive = Path(
        os.environ.get(
            "EXPO_UI_NODE_ARCHIVE",
            str(Path.home() / ".cache/localstack/toolchains/node-v22.23.2-darwin-arm64.tar.gz"),
        )
    ).resolve()
    if not archive.is_file():
        raise AssertionError("hash-pinned Node 22.23.2 arm64 archive is unavailable")
    digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    if digest != NODE_ARCHIVE_SHA256:
        raise AssertionError("Node 22.23.2 arm64 archive hash mismatch")
    destination = workspace / "toolchain"
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(destination, filter="data")
    node = destination / "node-v22.23.2-darwin-arm64/bin/node"
    if not node.is_file():
        raise AssertionError("Node archive omitted the expected executable")
    return node


def _extract_chrome(workspace: Path) -> Path:
    archive = Path(
        os.environ.get(
            "EXPO_UI_CHROME_ARCHIVE",
            str(
                Path.home() / ".cache/localstack/toolchains/"
                "chrome-for-testing-151.0.7922.77-mac-arm64.zip"
            ),
        )
    ).resolve()
    if not archive.is_file():
        raise AssertionError("hash-pinned Chrome for Testing arm64 archive is unavailable")
    digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    if digest != CHROME_ARCHIVE_SHA256:
        raise AssertionError("Chrome for Testing arm64 archive hash mismatch")
    workspace.mkdir(parents=True, exist_ok=True)
    extracted = launch_cdk(
        ["-x", "-k", str(archive), str(workspace)],
        executable="/usr/bin/ditto",
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    if (
        extracted.returncode
        or extracted.timed_out
        or extracted.stdout_truncated
        or extracted.stderr_truncated
    ):
        raise AssertionError("Chrome for Testing extraction failed closed")
    chrome = (
        workspace / "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing"
    )
    if not chrome.is_file():
        raise AssertionError("Chrome archive omitted the expected executable")
    framework = (
        chrome.parents[1] / "Frameworks/Google Chrome for Testing Framework.framework/Versions"
    )
    current = framework / "Current"
    crashpad = framework / CHROME_VERSION / "Helpers/chrome_crashpad_handler"
    if (
        not os.access(chrome, os.X_OK)
        or not os.access(crashpad, os.X_OK)
        or not current.is_symlink()
        or os.readlink(current) != CHROME_VERSION
    ):
        raise AssertionError("Chrome bundle modes or framework symlinks are invalid")
    signature = launch_cdk(
        ["-dv", "--verbose=4", str(chrome.parents[2])],
        executable="/usr/bin/codesign",
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        max_output_bytes=16 * 1024,
    )
    signature_text = signature.stderr.decode(errors="replace")
    if signature.returncode or not {
        "Identifier=Google Chrome for Testing",
        "Format=app bundle with Mach-O thin (arm64)",
        "Signature=adhoc",
    } <= set(signature_text.splitlines()):
        raise AssertionError("Chrome for Testing signing metadata is invalid")
    return chrome


def _build_expo(
    stack: AmplifyV6Stack, checkout: Path, workspace: Path, region_name: str
) -> tuple[Path, str]:
    node = _extract_node(workspace)
    probe = launch_cdk(
        ["--print", "JSON.stringify({version:process.version,arch:process.arch})"],
        executable=str(node),
        environment={"PATH": str(node.parent)},
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    if probe.returncode:
        raise AssertionError("Expo UI Node probe failed")
    runtime = json.loads(probe.stdout)
    if runtime != {"version": NODE_VERSION, "arch": "arm64"}:
        raise AssertionError("Expo UI build requires exact Node 22.23.2 arm64")
    _copy_billgym(checkout, workspace)
    output = workspace / "dist"
    environment = {
        "CI": "1",
        "EXPO_NO_TELEMETRY": "1",
        "EXPO_PUBLIC_AWS_REGION": region_name,
        "EXPO_PUBLIC_API_URL": stack.api_endpoint,
        "EXPO_PUBLIC_COGNITO_CLIENT_ID": stack.user_pool_client_id,
        "EXPO_PUBLIC_COGNITO_USER_POOL_ID": stack.user_pool_id,
        "PATH": f"{node.parent}:/usr/bin:/bin",
        "TMPDIR": str(workspace / "tmp"),
    }
    Path(environment["TMPDIR"]).mkdir()
    expo = checkout / "apps/mobile/node_modules/expo/bin/cli"
    result = launch_cdk(
        [
            str(expo),
            "export",
            "--platform",
            "web",
            "--output-dir",
            str(output),
            "--dev",
            "--max-workers",
            "1",
        ],
        executable=str(node),
        environment=environment,
        cwd=workspace / "apps/mobile",
        timeout_seconds=120,
        max_output_bytes=MAX_BUILD_OUTPUT,
    )
    if result.returncode or result.stdout_truncated or result.stderr_truncated:
        raise AssertionError(
            f"Expo export failed: {result.stderr.decode(errors='replace')[-4000:]}"
        )
    if not (output / "index.html").is_file():
        raise AssertionError("Expo export omitted index.html")
    return output, f"{runtime['version']} {runtime['arch']}"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _chrome_websocket(port: int) -> str:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/json", timeout=0.5) as response:
                pages = json.load(response)
            page = next(item for item in pages if item["type"] == "page")
            return page["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.1)
    raise TimeoutError("headless Chrome did not expose CDP")


def _cognito_origin(region_name: str) -> str:
    suffixes = {
        "aws": "amazonaws.com",
        "aws-cn": "amazonaws.com.cn",
        "aws-us-gov": "amazonaws.com",
    }
    partition = get_partition(region_name)
    suffix = suffixes.get(partition)
    if suffix is None:
        raise AssertionError(f"unsupported Cognito partition in UI gate: {partition}")
    return f"https://cognito-idp.{region_name}.{suffix}"


def _local_endpoint() -> str:
    endpoint = os.environ.get("AWS_ENDPOINT_URL", "http://127.0.0.1:4566")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise AssertionError("Expo UI gate requires an explicit loopback LocalStack endpoint")
    if (
        parsed.port is None
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise AssertionError("invalid LocalStack endpoint for Expo UI gate")
    return endpoint.rstrip("/")


def _chrome_version(chrome: Path) -> str:
    info = chrome.parents[1] / "Info.plist"
    if not info.is_file():
        raise AssertionError("Chrome application metadata is unavailable")
    with info.open("rb") as stream:
        version = plistlib.load(stream).get("CFBundleShortVersionString")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
        raise AssertionError(f"unexpected Chrome runtime version: {version}")
    return version


def _same_origin(left, right) -> bool:
    try:
        return (left.scheme, left.hostname, left.port) == (
            right.scheme,
            right.hostname,
            right.port,
        )
    except ValueError:
        return False


def _allowed_browser_url(url: str, app_origin: str, api_endpoint: str, cognito_origin: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme in {"data", "blob"}:
        return True
    app = urlsplit(app_origin)
    if _same_origin(parsed, app):
        return True
    api = urlsplit(api_endpoint)
    if _same_origin(parsed, api) and (
        parsed.path == api.path or parsed.path.startswith(f"{api.path.rstrip('/')}/")
    ):
        return True
    cognito = urlsplit(cognito_origin)
    return (
        _same_origin(parsed, cognito)
        and parsed.path == "/"
        and not parsed.query
        and not parsed.fragment
    )


@markers.aws.only_localstack
def test_billgym_expo_web_authenticator_ui(aws_client, region_name, request, tmp_path):
    checkout = _billgym_checkout()
    before = subprocess.run(
        ["git", "-C", checkout, "status", "--porcelain=v1", "-z"],
        check=True,
        capture_output=True,
        timeout=5,
    ).stdout
    dependencies_before = _node_modules_inventory(checkout)
    stack = request.getfixturevalue("amplify_v6_stack")
    aws_client.cognito_idp.set_user_pool_mfa_config(
        UserPoolId=stack.user_pool_id,
        MfaConfiguration="ON",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    output, node_runtime = _build_expo(stack, checkout, tmp_path / "workspace", region_name)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), lambda *args, **kwargs: _QuietHandler(*args, directory=output, **kwargs)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    app_origin = f"http://127.0.0.1:{server.server_port}"
    chrome_port = _free_port()
    cognito_origin = _cognito_origin(region_name)
    endpoint = _local_endpoint()
    chrome_binary = _extract_chrome(tmp_path / "browser-runtime")
    chrome_version = _chrome_version(chrome_binary)
    chrome_log = _BoundedPipe(MAX_CHROME_LOG)
    chrome = subprocess.Popen(
        [
            str(chrome_binary),
            "--headless=new",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-first-run",
            "--no-default-browser-check",
            "--remote-allow-origins=*",
            f"--remote-debugging-port={chrome_port}",
            f"--user-data-dir={tmp_path / 'chrome-profile'}",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE *.localhost.localstack.cloud",
            app_origin,
        ],
        stdin=subprocess.DEVNULL,
        stdout=chrome_log.write_fd,
        stderr=chrome_log.write_fd,
        start_new_session=True,
    )
    chrome_log.parent_close()
    cdp = None
    primary_error = None
    try:
        cdp = _Cdp(_chrome_websocket(chrome_port), endpoint, app_origin, cognito_origin)
        for domain in ("Page", "Runtime", "Network"):
            cdp.command(f"{domain}.enable")
        cdp.command(
            "Fetch.enable",
            {"patterns": [{"urlPattern": f"{cognito_origin}/*", "requestStage": "Request"}]},
        )
        cdp.wait("document.querySelectorAll('input').length === 2", 20)
        cdp.fill_visible([stack.username, stack.temporary_password])
        cdp.click(["Entrar", "Sign In"])
        cdp.wait("document.querySelectorAll('input[type=password]').length >= 2")
        cdp.fill_visible([stack.new_password, stack.new_password])
        cdp.click(["Mudar senha", "Change Password"])
        cdp.wait("/\\b[A-Z2-7]{16,}\\b/.test(document.body.innerText)")
        secret = cdp.evaluate("document.body.innerText.match(/\\b[A-Z2-7]{16,}\\b/)[0]")
        cdp.fill_visible([_totp(secret, -1)])
        cdp.click(["confirme", "Confirm"])
        cdp.wait("document.body.innerText.includes('Novo plano de treino')", 20)
        cdp.click(aria="Abrir menu")
        cdp.wait("document.body.innerText.includes('Perfil')")
        cdp.click(["Perfil"])
        cdp.wait("document.body.innerText.includes('Sair')")
        cdp.click(["Sair"])
        cdp.wait("document.querySelectorAll('input').length === 2")
        cdp.fill_visible([stack.username, stack.new_password])
        cdp.click(["Entrar", "Sign In"])
        cdp.wait("document.querySelectorAll('input').length === 1")
        cdp.fill_visible([_totp(secret)])
        cdp.click(["confirme", "Confirm"])
        cdp.wait("document.body.innerText.includes('Novo plano de treino')", 20)
        cdp.click(aria="Abrir menu")
        cdp.wait("document.body.innerText.includes('Perfil')")
        cdp.click(["Perfil"])
        cdp.wait("document.body.innerText.includes('Sair')")
        cdp.click(["Sair"])
        cdp.wait("document.querySelectorAll('input').length === 2")

        assert node_runtime == "v22.23.2 arm64"
        assert chrome_version == CHROME_VERSION
        assert {
            "AWSCognitoIdentityProviderService.InitiateAuth",
            "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
            "AWSCognitoIdentityProviderService.AssociateSoftwareToken",
            "AWSCognitoIdentityProviderService.VerifySoftwareToken",
            "AWSCognitoIdentityProviderService.RevokeToken",
        } <= set(cdp.targets)
        assert any("/v1/profile" in url and status == 200 for url, status in cdp.api_paths)
        escaped = [
            url
            for url in cdp.network
            if not _allowed_browser_url(url, app_origin, stack.api_endpoint, cognito_origin)
        ]
        assert escaped == []
        assert not [entry for entry in cdp.console if entry["method"] == "Runtime.exceptionThrown"]
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if cdp is not None:
            cdp.close()
        chrome.terminate()
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            chrome.kill()
            chrome.wait(timeout=5)
        captured_chrome_log = chrome_log.finish()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        after = subprocess.run(
            ["git", "-C", checkout, "status", "--porcelain=v1", "-z"],
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout
        if after != before:
            pytest.fail("Expo Web gate mutated the Billgym checkout")
        if _node_modules_inventory(checkout) != dependencies_before:
            pytest.fail("Expo Web gate mutated Billgym's ignored dependency tree")
        if primary_error is not None and captured_chrome_log:
            primary_error.add_note(f"bounded Chrome log:\n{captured_chrome_log}")
