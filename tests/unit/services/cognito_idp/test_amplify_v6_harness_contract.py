from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.aws.services.cognito_idp import test_amplify_v6_runtime as runtime


def test_harness_preserves_real_amplify_protocol_and_denies_egress():
    source = runtime.HARNESS.read_text()

    assert "userPoolEndpoint" not in source
    assert "createRequire(join(mobileRoot, 'package.json'))" in source
    assert "EXPECTED_AMPLIFY_VERSION = '6.20.0'" in source
    assert "EXPECTED_NODE_VERSION = 'v22.23.2'" in source
    assert "Network egress denied" in source
    assert "USER_SRP_AUTH" in source
    assert "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED" in source
    assert "CONFIRM_SIGN_IN_WITH_TOTP_CODE" in source
    assert "fetchAuthSession({ forceRefresh: true })" in source
    assert "signOut({ global: true })" in source
    assert "api.get" in source


def test_node_gate_rejects_runner_with_wrong_content_digest(monkeypatch):
    monkeypatch.setattr(runtime.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        runtime,
        "launch_cdk",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"sha256:wrong\n"),
    )

    with pytest.raises(RuntimeError, match="content-addressed Node 22.23.2"):
        runtime._pinned_node_runner()


def test_test_owned_adapter_is_the_only_origin_rewrite():
    source = Path(runtime.HARNESS).read_text()

    assert "COGNITO_HOST.exec(original.hostname)" in source
    assert "headers.set('host', original.host)" in source
    assert "destination = new URL" in source
    assert "original.origin === api.origin" in source


def test_protocol_gate_does_not_claim_ui_or_native_runtime():
    source = Path(runtime.__file__).read_text()

    assert "not UI or native-device runtime qualification" in source
    assert "Expo browser, iOS, or Android" in source
    assert runtime.PINNED_NODE_IMAGE.startswith("node@sha256:")
