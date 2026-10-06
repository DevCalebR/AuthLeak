"""Verification artifacts for potential authorization findings.

B3.7.1 defines the data contract used to package an authorization candidate
for safe, manual verification.

Artifact generation is intentionally network-free and stores only sanitized
authorization metadata and response-differential information.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from authorization_compare import AuthorizationComparison
from authorization_triage import AuthorizationTriage


@dataclass(frozen=True)
class VerificationArtifact:
    """Structured evidence package for manual authorization verification."""

    method: str
    url: str

    victim_status: int | None
    attacker_status: int | None
    victim_authenticated: bool
    attacker_authenticated: bool

    candidate: bool
    candidate_reason: str

    response_structure_changed: bool
    response_differences: tuple[str, ...]

    triage_level: str
    triage_score: int
    triage_reasons: tuple[str, ...]

    manual_verification_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the artifact."""
        return {
            "method": self.method,
            "url": self.url,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "victim_authenticated": self.victim_authenticated,
            "attacker_authenticated": self.attacker_authenticated,
            "candidate": self.candidate,
            "candidate_reason": self.candidate_reason,
            "response_structure_changed": self.response_structure_changed,
            "response_differences": list(self.response_differences),
            "triage_level": self.triage_level,
            "triage_score": self.triage_score,
            "triage_reasons": list(self.triage_reasons),
            "manual_verification_required": self.manual_verification_required,
        }


def build_verification_artifact(
    comparison: AuthorizationComparison,
    triage: AuthorizationTriage,
) -> VerificationArtifact:
    """Build a verification artifact from existing comparison and triage data.

    This function performs no network activity and does not alter the
    underlying authorization candidate decision.
    """
    return VerificationArtifact(
        method=comparison.method,
        url=comparison.url,
        victim_status=comparison.victim_status,
        attacker_status=comparison.attacker_status,
        victim_authenticated=comparison.victim_authenticated,
        attacker_authenticated=comparison.attacker_authenticated,
        candidate=comparison.candidate,
        candidate_reason=comparison.reason,
        response_structure_changed=comparison.response_structure_changed,
        response_differences=comparison.response_differences,
        triage_level=triage.level.value,
        triage_score=triage.score,
        triage_reasons=triage.reasons,
    )
