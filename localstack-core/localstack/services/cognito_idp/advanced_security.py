"""Deterministic policy layer for locally executable Cognito threat protection.

The local risk evaluator owns the supported signals (configured IP ranges and
compromised-password hashes). This module only applies the user-pool advanced
security mode to that result. It intentionally does not synthesize proprietary
account-takeover scores or Amazon threat-intelligence findings.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any


class AdvancedSecurityError(ValueError):
    """The configured mode or local risk result is invalid."""


@dataclasses.dataclass(frozen=True)
class LocalRiskResult:
    risk_level: str
    risk_decision: str
    would_block: bool
    compromised_credentials_detected: bool


@dataclasses.dataclass(frozen=True)
class AdvancedSecurityDecision:
    mode: str
    risk_level: str
    risk_decision: str
    would_block: bool
    blocked: bool
    compromised_credentials_detected: bool
    record_event: bool
    evaluation_failed: bool = False

    def event_risk(self) -> dict[str, str | bool]:
        return {
            "CompromisedCredentialsDetected": self.compromised_credentials_detected,
            "RiskDecision": self.risk_decision,
            "RiskLevel": self.risk_level,
        }


LocalRiskEvaluator = Callable[[], tuple[str, str, bool, bool] | LocalRiskResult]


def apply_advanced_security_mode(
    mode: Any,
    evaluate_local_risk: LocalRiskEvaluator,
) -> AdvancedSecurityDecision:
    """Apply OFF/AUDIT/ENFORCED without leaking local evaluator failures.

    OFF bypasses the engine. AUDIT records the local result but never enforces
    it. ENFORCED applies a supported local block and fails closed if the local
    evaluator cannot produce a valid deterministic result.
    """
    if mode not in {"OFF", "AUDIT", "ENFORCED"}:
        raise AdvancedSecurityError("Invalid AdvancedSecurityMode")
    if not callable(evaluate_local_risk):
        raise AdvancedSecurityError("Invalid local risk evaluator")
    if mode == "OFF":
        return AdvancedSecurityDecision(
            mode=mode,
            risk_level="Low",
            risk_decision="NoRisk",
            would_block=False,
            blocked=False,
            compromised_credentials_detected=False,
            record_event=False,
        )
    try:
        local = _local_risk_result(evaluate_local_risk())
    except Exception:
        return AdvancedSecurityDecision(
            mode=mode,
            risk_level="High",
            risk_decision="Block",
            would_block=True,
            blocked=mode == "ENFORCED",
            compromised_credentials_detected=False,
            record_event=True,
            evaluation_failed=True,
        )
    return AdvancedSecurityDecision(
        mode=mode,
        risk_level=local.risk_level,
        risk_decision=local.risk_decision,
        would_block=local.would_block,
        blocked=mode == "ENFORCED" and local.would_block,
        compromised_credentials_detected=local.compromised_credentials_detected,
        record_event=True,
    )


def _local_risk_result(value: Any) -> LocalRiskResult:
    if isinstance(value, LocalRiskResult):
        result = value
    elif isinstance(value, tuple) and len(value) == 4:
        result = LocalRiskResult(*value)
    else:
        raise AdvancedSecurityError("Invalid local risk result")
    if not isinstance(result.would_block, bool) or not isinstance(
        result.compromised_credentials_detected, bool
    ):
        raise AdvancedSecurityError("Invalid local risk result")
    supported_state = (
        result.risk_level,
        result.risk_decision,
        result.would_block,
    ) in {
        ("Low", "NoRisk", False),
        ("High", "Block", True),
    }
    if not supported_state or result.compromised_credentials_detected and not result.would_block:
        raise AdvancedSecurityError("Invalid local risk result")
    return result
