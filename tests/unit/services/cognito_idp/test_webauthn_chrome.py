import base64
import hashlib
import ipaddress
import json
import os
import shutil
import signal
import ssl
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import boto3
import pytest
import websocket
from botocore.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from localstack import config
from localstack.aws.api import RequestContext
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.utils.net import get_free_tcp_port
from tests.unit.services.cognito_idp.test_webauthn import USERNAME, _stack

RP_ID = "auth.example.test"


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(value.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _chrome_executable():
    return shutil.which("google-chrome") or (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    )


def _terminate_process_group(process, *, timeout=10):
    """Terminate Chrome and every helper process created in its isolated session."""
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=timeout)

    deadline = time.monotonic() + timeout
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        if time.monotonic() >= deadline:
            try:
                os.killpg(process_group, signal.SIGKILL)
            except ProcessLookupError:
                return
            raise TimeoutError("Chrome process group did not terminate")
        time.sleep(0.05)


def _page_handler(provider, context):
    operations = {
        "CompleteWebAuthnRegistration": provider.complete_web_authn_registration,
        "InitiateAuth": provider.initiate_auth,
        "ListWebAuthnCredentials": provider.list_web_authn_credentials,
        "RespondToAuthChallenge": provider.respond_to_auth_challenge,
        "StartWebAuthnRegistration": provider.start_web_authn_registration,
    }

    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<!doctype html><meta charset=utf-8><title>Local WebAuthn gate</title>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            operation = self.headers.get("X-Amz-Target", "").rsplit(".", 1)[-1]
            handler = operations.get(operation)
            if handler is None:
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            response = handler(context, request)
            body = json.dumps(
                response,
                separators=(",", ":"),
                default=lambda value: value.timestamp(),
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Page


class _Cdp:
    def __init__(self, url):
        self.socket = websocket.create_connection(url, origin="http://localhost", timeout=20)
        self.identifier = 0

    def command(self, method, params=None, session_id=None):
        self.identifier += 1
        message = {"id": self.identifier, "method": method}
        if params is not None:
            message["params"] = params
        if session_id is not None:
            message["sessionId"] = session_id
        self.socket.send(json.dumps(message, separators=(",", ":")))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            response = json.loads(self.socket.recv())
            if response.get("id") != self.identifier:
                continue
            if error := response.get("error"):
                raise RuntimeError(f"Chrome CDP error: {error}")
            return response.get("result", {})
        raise TimeoutError(f"Chrome CDP command timed out: {method}")

    def close(self):
        self.socket.close()


def _certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, RP_ID)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(RP_ID), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki = base64.b64encode(hashlib.sha256(public_key).digest()).decode()
    return cert_path, key_path, spki


def _credential_script(options, *, registration):
    operation = "create" if registration else "get"
    response_fields = (
        "attestationObject: encode(credential.response.attestationObject),"
        "transports: credential.response.getTransports()"
        if registration
        else "authenticatorData: encode(credential.response.authenticatorData),"
        "signature: encode(credential.response.signature),"
        "userHandle: encode(credential.response.userHandle)"
    )
    return rf"""
    (async () => {{
      const decode = value => {{
        const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4-value.length%4)%4);
        return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
      }};
      const encode = value => {{
        if (value === null) return null;
        const bytes = new Uint8Array(value);
        let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      }};
      const options = {json.dumps(options)};
      options.challenge = decode(options.challenge);
      if (options.user) options.user.id = decode(options.user.id);
      for (const descriptor of options.excludeCredentials || []) descriptor.id = decode(descriptor.id);
      for (const descriptor of options.allowCredentials || []) descriptor.id = decode(descriptor.id);
      const credential = await navigator.credentials.{operation}({{publicKey: options}});
      return JSON.stringify({{
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.getClientExtensionResults(),
        id: credential.id,
        rawId: encode(credential.rawId),
        response: {{clientDataJSON: encode(credential.response.clientDataJSON), {response_fields}}},
        type: credential.type
      }});
    }})()
    """


@pytest.mark.skipif(
    not _chrome_executable() or not Path(_chrome_executable()).exists(),
    reason="Google Chrome is required for the WebAuthn browser gate",
)
def test_chrome_virtual_authenticator_registration_and_user_auth(
    provider, context, monkeypatch, tmp_path
):
    pool, client, tokens = _stack(provider, context)
    cert_path, key_path, certificate_spki = _certificate(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _page_handler(provider, context))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    origin = f"https://{RP_ID}:{server.server_port}"
    monkeypatch.setattr(config, "external_service_url", lambda: origin)
    sdk = boto3.client(
        "cognito-idp",
        region_name=context.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        endpoint_url=f"https://127.0.0.1:{server.server_port}",
        verify=str(cert_path),
        config=Config(retries={"max_attempts": 0}),
    )

    debugging_port = get_free_tcp_port()
    process = subprocess.Popen(
        [
            _chrome_executable(),
            "--headless=new",
            "--disable-gpu",
            f"--ignore-certificate-errors-spki-list={certificate_spki}",
            "--no-first-run",
            "--no-default-browser-check",
            f"--remote-debugging-port={debugging_port}",
            "--remote-allow-origins=*",
            f"--host-resolver-rules=MAP {RP_ID} 127.0.0.1",
            f"--user-data-dir={tmp_path / 'chrome-profile'}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    cdp = None
    try:
        for _ in range(200):
            try:
                with urlopen(f"http://127.0.0.1:{debugging_port}/json/version") as response:
                    devtools = json.load(response)
                break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError("Chrome exited before opening its debugging port")
                time.sleep(0.05)
        else:
            raise TimeoutError("Chrome did not open its debugging port")
        cdp = _Cdp(devtools["webSocketDebuggerUrl"])
        target_id = cdp.command("Target.createTarget", {"url": origin})["targetId"]
        session_id = cdp.command("Target.attachToTarget", {"flatten": True, "targetId": target_id})[
            "sessionId"
        ]
        cdp.command("WebAuthn.enable", session_id=session_id)
        cdp.command(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "automaticPresenceSimulation": True,
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "protocol": "ctap2",
                    "transport": "internal",
                }
            },
            session_id,
        )
        for _ in range(100):
            ready = cdp.command(
                "Runtime.evaluate",
                {"expression": "document.readyState", "returnByValue": True},
                session_id,
            )["result"].get("value")
            if ready == "complete":
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("Local WebAuthn page did not load")

        creation = sdk.start_web_authn_registration(AccessToken=tokens["AccessToken"])[
            "CredentialCreationOptions"
        ]
        registered = cdp.command(
            "Runtime.evaluate",
            {
                "awaitPromise": True,
                "expression": _credential_script(creation, registration=True),
                "returnByValue": True,
            },
            session_id,
        )["result"]["value"]
        sdk.complete_web_authn_registration(
            AccessToken=tokens["AccessToken"], Credential=json.loads(registered)
        )

        started = sdk.initiate_auth(
            AuthFlow="USER_AUTH",
            AuthParameters={
                "PREFERRED_CHALLENGE": "WEB_AUTHN",
                "USERNAME": USERNAME,
            },
            ClientId=client["ClientId"],
        )
        request_options = json.loads(started["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
        assertion = cdp.command(
            "Runtime.evaluate",
            {
                "awaitPromise": True,
                "expression": _credential_script(request_options, registration=False),
                "returnByValue": True,
            },
            session_id,
        )["result"]["value"]
        authenticated = sdk.respond_to_auth_challenge(
            ChallengeName="WEB_AUTHN",
            ChallengeResponses={"CREDENTIAL": assertion, "USERNAME": USERNAME},
            ClientId=client["ClientId"],
            Session=started["Session"],
        )
        assert authenticated["AuthenticationResult"]["AccessToken"]
        assert (
            sdk.list_web_authn_credentials(AccessToken=tokens["AccessToken"])["Credentials"][0][
                "RelyingPartyId"
            ]
            == RP_ID
        )
    finally:
        try:
            if cdp is not None:
                cdp.close()
        finally:
            try:
                _terminate_process_group(process)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
