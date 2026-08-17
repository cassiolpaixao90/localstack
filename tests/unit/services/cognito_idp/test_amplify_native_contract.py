from pathlib import Path

NATIVE = Path(__file__).parents[3] / "aws" / "services" / "cognito_idp" / "native"
SWIFT_TEST = (
    Path(__file__).parents[3] / "aws" / "services" / "cognito_idp" / "test_amplify_native_swift.py"
)


def test_swift_manifest_and_lock_pin_amplify_2_60_1():
    assert not (NATIVE / "swift" / "Package.swift").exists()
    source = SWIFT_TEST.read_text()
    assert 'AMPLIFY_SWIFT_VERSION = "2.60.1"' in source
    assert 'AMPLIFY_SWIFT_REVISION = "82700377212a3e4afebfe1fdbcafb98a5fae8b17"' in source
    assert "63a707b4817d6eb4a8162a6e00161d1c60bf836712d51e588a43b808781724ee" in source
    assert '"--disable-automatic-resolution"' in source
    assert 'state["revision"]' in source


def test_swift_runtime_is_loopback_only_and_does_not_disable_tls():
    source = SWIFT_TEST.read_text()
    assert "(deny network*)" in source
    assert 'remote ip "localhost:443"' in source
    assert "disableCertificate" not in source
    assert "URLSessionDelegate" not in source
    assert '127.0.0.1", 443' in source
    assert "EADDRINUSE" in source


def test_swift_gate_claim_is_native_macos_protocol_only():
    source = SWIFT_TEST.read_text()
    assert "not iOS Simulator or Amplify UI evidence" in source
    harness = (NATIVE / "swift" / "Sources" / "AmplifyNativeGate" / "main.swift").read_text()
    for operation in (
        "confirmSignInWithNewPassword",
        "setUpTOTP",
        "forceRefresh",
        "globalSignOut",
        "Amplify.API.get",
    ):
        assert operation in harness
