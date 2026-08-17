import pickle
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from localstack.services.cognito_idp.confirmation_links import (
    ConfirmationLinkError,
    ConfirmationLinkManager,
    ConfirmationLinkState,
    validate_verification_message_template,
)


@pytest.fixture
def topology():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = f"aa-{uuid.uuid4().hex[:4]}-1"
    return {
        "account_id": account_id,
        "region": region_name,
        "pool_id": f"{region_name}_pool123",
        "client_id": "client123",
        "username": "alice@example.test",
    }


def test_link_template_is_strict_and_rendered_without_html_injection(topology):
    now = datetime(2026, 8, 10, tzinfo=UTC)
    manager = ConfirmationLinkManager(ConfirmationLinkState(), now=lambda: now)
    issued = manager.issue(
        **topology,
        base_url="https://auth.localhost.localstack.cloud",
        allowed_hostnames={"auth.localhost.localstack.cloud"},
        template={
            "DefaultEmailOption": "CONFIRM_WITH_LINK",
            "EmailSubjectByLink": "Confirm your account",
            "EmailMessageByLink": "Open {##<Confirm & continue>##}",
        },
    )

    assert issued.token not in repr(manager.state.entries)
    assert "&lt;Confirm &amp; continue&gt;" in issued.rendered_message
    assert "confirmation_code=" in issued.rendered_message
    assert issued.url.startswith("https://auth.localhost.localstack.cloud/confirmUser?")
    consumed = manager.consume(token=issued.token, **topology)
    assert consumed.username == topology["username"]
    with pytest.raises(ConfirmationLinkError, match="Invalid or expired"):
        manager.consume(token=issued.token, **topology)


@pytest.mark.parametrize(
    "template",
    [
        {"DefaultEmailOption": "CONFIRM_WITH_LINK", "EmailMessageByLink": "missing"},
        {
            "DefaultEmailOption": "CONFIRM_WITH_LINK",
            "EmailMessageByLink": "{##one##} {##two##}",
        },
        {"DefaultEmailOption": "CONFIRM_WITH_CODE", "EmailMessage": "missing code"},
        {
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
            "EmailMessage": "Code {####}",
            "EmailMessageByLink": "{##link##}",
        },
    ],
)
def test_invalid_or_ambiguous_templates_fail_closed(template):
    with pytest.raises(ConfirmationLinkError, match="template"):
        validate_verification_message_template(template)


def test_link_endpoint_is_owned_https_only_and_ssrf_safe(topology):
    manager = ConfirmationLinkManager(ConfirmationLinkState())
    template = {
        "DefaultEmailOption": "CONFIRM_WITH_LINK",
        "EmailMessageByLink": "{##Confirm##}",
    }
    for url in (
        "http://auth.localhost.localstack.cloud",
        "https://127.0.0.1",
        "https://user@auth.localhost.localstack.cloud",
        "https://auth.localhost.localstack.cloud.evil.test",
        "https://auth.localhost.localstack.cloud/path",
    ):
        with pytest.raises(ConfirmationLinkError, match="endpoint"):
            manager.issue(
                **topology,
                base_url=url,
                allowed_hostnames={"auth.localhost.localstack.cloud"},
                template=template,
            )


def test_link_expiry_pickle_cleanup_and_concurrent_replay(topology):
    clock = [datetime(2026, 8, 10, tzinfo=UTC)]
    state = ConfirmationLinkState()
    manager = ConfirmationLinkManager(state, now=lambda: clock[0], ttl=timedelta(minutes=15))
    kwargs = {
        **topology,
        "base_url": "https://auth.localhost.localstack.cloud",
        "allowed_hostnames": {"auth.localhost.localstack.cloud"},
        "template": {
            "DefaultEmailOption": "CONFIRM_WITH_LINK",
            "EmailMessageByLink": "{##Confirm##}",
        },
    }
    expired = manager.issue(**kwargs)
    clock[0] += timedelta(minutes=16)
    with pytest.raises(ConfirmationLinkError, match="Invalid or expired"):
        manager.consume(token=expired.token, **topology)

    current = manager.issue(**kwargs)
    restored = pickle.loads(pickle.dumps(state))
    restored_manager = ConfirmationLinkManager(restored, now=lambda: clock[0])
    outcomes = []

    def consume():
        try:
            restored_manager.consume(token=current.token, **topology)
            outcomes.append("ok")
        except ConfirmationLinkError:
            outcomes.append("rejected")

    workers = [threading.Thread(target=consume) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)
    assert outcomes.count("ok") == 1
    assert outcomes.count("rejected") == 7

    another = restored_manager.issue(**kwargs)
    restored_manager.cleanup_pool(topology["pool_id"])
    with pytest.raises(ConfirmationLinkError, match="Invalid or expired"):
        restored_manager.consume(token=another.token, **topology)
