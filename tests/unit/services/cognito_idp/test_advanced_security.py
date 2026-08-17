from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.advanced_security import (
    AdvancedSecurityDecision,
    AdvancedSecurityError,
    LocalRiskResult,
    apply_advanced_security_mode,
)
from localstack.services.cognito_idp.models import RiskConfiguration


def _existing_local_engine(*, password=None, ip_address=None, configuration=None):
    configuration = configuration or {}
    pool = SimpleNamespace(
        risk_configurations={
            "ALL": RiskConfiguration(
                client_id=None,
                account_takeover=None,
                compromised_credentials=configuration.get("compromised"),
                risk_exceptions=configuration.get("exceptions"),
                updated_at=datetime.now(UTC),
            )
        }
    )
    client = SimpleNamespace(client_id="local-client")
    return lambda: provider_module._evaluate_local_auth_risk(pool, client, password, ip_address)


def test_off_bypasses_the_local_risk_engine_and_does_not_record():
    called = False

    def unexpected_evaluation():
        nonlocal called
        called = True
        raise AssertionError("OFF must not evaluate risk")

    decision = apply_advanced_security_mode("OFF", unexpected_evaluation)

    assert decision == AdvancedSecurityDecision(
        mode="OFF",
        risk_level="Low",
        risk_decision="NoRisk",
        would_block=False,
        blocked=False,
        compromised_credentials_detected=False,
        record_event=False,
    )
    assert not called


@pytest.mark.parametrize(("mode", "blocked"), [("AUDIT", False), ("ENFORCED", True)])
def test_audit_records_and_enforced_blocks_configured_cidr(mode, blocked):
    engine = _existing_local_engine(
        ip_address="198.51.100.20",
        configuration={
            "exceptions": {
                "BlockedIPRangeList": ["198.51.100.0/24"],
                "SkippedIPRangeList": [],
            }
        },
    )

    decision = apply_advanced_security_mode(mode, engine)

    assert decision.record_event
    assert decision.would_block
    assert decision.blocked is blocked
    assert not decision.evaluation_failed
    assert decision.event_risk() == {
        "CompromisedCredentialsDetected": False,
        "RiskDecision": "Block",
        "RiskLevel": "High",
    }


@pytest.mark.parametrize(("mode", "blocked"), [("AUDIT", False), ("ENFORCED", True)])
def test_audit_observes_and_enforced_blocks_local_compromised_password(mode, blocked):
    engine = _existing_local_engine(
        password="Password123!",
        ip_address="203.0.113.10",
        configuration={
            "compromised": {
                "Actions": {"EventAction": "BLOCK"},
                "EventFilter": ["SIGN_IN"],
            }
        },
    )

    decision = apply_advanced_security_mode(mode, engine)

    assert decision.record_event
    assert decision.would_block
    assert decision.blocked is blocked
    assert decision.compromised_credentials_detected
    assert decision.event_risk()["RiskDecision"] == "Block"


def test_skipped_cidr_is_deterministic_and_overrides_local_block_signals():
    engine = _existing_local_engine(
        password="Password123!",
        ip_address="192.0.2.10",
        configuration={
            "compromised": {
                "Actions": {"EventAction": "BLOCK"},
                "EventFilter": ["SIGN_IN"],
            },
            "exceptions": {
                "BlockedIPRangeList": ["192.0.2.0/24"],
                "SkippedIPRangeList": ["192.0.2.10/32"],
            },
        },
    )

    first = apply_advanced_security_mode("ENFORCED", engine)
    second = apply_advanced_security_mode("ENFORCED", engine)

    assert first == second
    assert first.record_event
    assert not first.would_block
    assert not first.blocked
    assert first.event_risk() == {
        "CompromisedCredentialsDetected": False,
        "RiskDecision": "NoRisk",
        "RiskLevel": "Low",
    }


@pytest.mark.parametrize(("mode", "blocked"), [("AUDIT", False), ("ENFORCED", True)])
def test_local_engine_failure_is_audited_and_only_enforced_mode_fails_closed(mode, blocked):
    def failed_engine():
        raise RuntimeError("internal evaluator detail")

    decision = apply_advanced_security_mode(mode, failed_engine)

    assert decision.record_event
    assert decision.evaluation_failed
    assert decision.would_block
    assert decision.blocked is blocked
    assert decision.event_risk() == {
        "CompromisedCredentialsDetected": False,
        "RiskDecision": "Block",
        "RiskLevel": "High",
    }


@pytest.mark.parametrize(
    "result",
    [
        None,
        ("Medium", "Block", True, False),
        ("High", "AccountTakeover", True, False),
        ("Low", "Block", True, False),
        ("High", "NoRisk", False, False),
        ("High", "Block", False, False),
        ("High", "Block", False, True),
        ("High", "Block", 1, False),
    ],
)
def test_unknown_or_proprietary_results_are_not_overclaimed_and_fail_closed(result):
    decision = apply_advanced_security_mode("ENFORCED", lambda: result)

    assert decision.evaluation_failed
    assert decision.blocked
    assert not decision.compromised_credentials_detected


def test_accepts_the_explicit_local_result_type():
    local = LocalRiskResult(
        risk_level="High",
        risk_decision="Block",
        would_block=True,
        compromised_credentials_detected=False,
    )

    decision = apply_advanced_security_mode("AUDIT", lambda: local)

    assert decision.would_block
    assert not decision.blocked


@pytest.mark.parametrize("mode", [None, "", "audit", "FULL_FUNCTION", object()])
def test_rejects_invalid_modes(mode):
    with pytest.raises(AdvancedSecurityError, match="Invalid AdvancedSecurityMode"):
        apply_advanced_security_mode(mode, lambda: ("Low", "NoRisk", False, False))


def test_rejects_non_callable_engine_even_when_mode_is_off():
    with pytest.raises(AdvancedSecurityError, match="Invalid local risk evaluator"):
        apply_advanced_security_mode("OFF", None)
