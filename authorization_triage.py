"""Triage metadata for potential authorization findings.

B3.6 provides deterministic prioritization for authorization candidates.

Triage does not confirm a vulnerability. It only describes how strongly
an existing authorization candidate should be prioritized for manual review.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from authorization_compare import AuthorizationComparison


class TriageLevel(StrEnum):
    """Coarse priority levels for manual authorization review."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class AuthorizationTriage:
    """Structured triage metadata for an authorization comparison."""

    level: TriageLevel
    score: int
    reasons: tuple[str, ...]
    candidate: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of the triage result."""
        return {
            "level": self.level.value,
            "score": self.score,
            "reasons": list(self.reasons),
            "candidate": self.candidate,
        }


def _successful(status: int | None) -> bool:
    """Return whether an HTTP status represents a successful response."""
    return status is not None and status < 400


def _status_differential_is_suspicious(
    comparison: AuthorizationComparison,
) -> bool:
    """Return whether the status relationship deserves additional priority."""
    victim = comparison.victim_status
    attacker = comparison.attacker_status

    if victim is None or attacker is None:
        return False

    return (
        victim < 400 <= attacker
        or attacker < 400 <= victim
    )


def build_authorization_triage(
    comparison: AuthorizationComparison,
) -> AuthorizationTriage:
    """Build deterministic triage metadata for an authorization comparison.

    Only existing authorization candidates receive a non-zero score.
    Individual response-difference signals are scored once to avoid
    double-counting overlapping structural metadata.
    """
    if not comparison.candidate:
        return AuthorizationTriage(
            level=TriageLevel.LOW,
            score=0,
            reasons=(),
            candidate=False,
        )

    score = 0
    reasons: list[str] = []

    if (
        _successful(comparison.victim_status)
        and _successful(comparison.attacker_status)
    ):
        score += 30
        reasons.append("both_sessions_successful")

    differences = set(comparison.response_differences)

    if comparison.response_structure_changed:
        score += 25
        reasons.append("response_structure_changed")

    if "content_type" in differences:
        score += 15
        reasons.append("response_content_type_changed")

    if "shape" in differences:
        score += 15
        reasons.append("response_shape_changed")

    if _status_differential_is_suspicious(comparison):
        score += 15
        reasons.append("suspicious_status_differential")

    score = min(score, 100)

    if score >= 60:
        level = TriageLevel.HIGH
    elif score >= 30:
        level = TriageLevel.MEDIUM
    else:
        level = TriageLevel.LOW

    return AuthorizationTriage(
        level=level,
        score=score,
        reasons=tuple(reasons),
        candidate=True,
    )
