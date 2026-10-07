"""Canonical authorization evidence for AuthLeak.

B3.9.1 normalizes existing authorization comparison and triage results into
one immutable evidence contract.

This module performs no network activity, does not inspect response bodies,
and does not alter authorization candidate decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from authorization_compare import AuthorizationComparison
from authorization_triage import AuthorizationTriage


class AccessRelationship(StrEnum):
    """Normalized relationship between victim and attacker access outcomes."""

    SAME_SUCCESS = "same_success"
    ATTACKER_EXCEEDS_VICTIM = "attacker_exceeds_victim"
    VICTIM_ONLY = "victim_only"
    BOTH_DENIED = "both_denied"
    INCOMPLETE = "incomplete"


class EvidenceStrength(StrEnum):
    """Conservative strength of the currently observed authorization evidence."""

    NONE = "none"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


@dataclass(frozen=True)
class AuthorizationEvidence:
    """Canonical, metadata-only evidence for an authorization observation."""

    method: str
    url: str

    victim_status: int | None
    attacker_status: int | None
    victim_authenticated: bool
    attacker_authenticated: bool

    candidate: bool
    candidate_reason: str

    access_relationship: AccessRelationship

    response_structure_changed: bool
    response_differences: tuple[str, ...]

    triage_level: str
    triage_score: int
    triage_reasons: tuple[str, ...]

    evidence_strength: EvidenceStrength
    evidence_reasons: tuple[str, ...]

    manual_verification_required: bool = True

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "method": self.method,
            "url": self.url,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "victim_authenticated": self.victim_authenticated,
            "attacker_authenticated": self.attacker_authenticated,
            "candidate": self.candidate,
            "candidate_reason": self.candidate_reason,
            "access_relationship": self.access_relationship.value,
            "response_structure_changed": self.response_structure_changed,
            "response_differences": list(self.response_differences),
            "triage_level": self.triage_level,
            "triage_score": self.triage_score,
            "triage_reasons": list(self.triage_reasons),
            "evidence_strength": self.evidence_strength.value,
            "evidence_reasons": list(self.evidence_reasons),
            "manual_verification_required": self.manual_verification_required,
        }


def _successful(status: int | None) -> bool:
    """Return whether an HTTP status represents a successful response."""
    return status is not None and status < 400


def _access_relationship(
    comparison: AuthorizationComparison,
) -> AccessRelationship:
    """Normalize the victim/attacker access relationship."""
    victim = comparison.victim_status
    attacker = comparison.attacker_status

    if victim is None or attacker is None:
        return AccessRelationship.INCOMPLETE

    victim_success = _successful(victim)
    attacker_success = _successful(attacker)

    if victim_success and attacker_success:
        return AccessRelationship.SAME_SUCCESS

    if attacker_success and not victim_success:
        return AccessRelationship.ATTACKER_EXCEEDS_VICTIM

    if victim_success and not attacker_success:
        return AccessRelationship.VICTIM_ONLY

    return AccessRelationship.BOTH_DENIED


def _evidence_strength(
    comparison: AuthorizationComparison,
    triage: AuthorizationTriage,
    relationship: AccessRelationship,
) -> tuple[EvidenceStrength, tuple[str, ...]]:
    """Derive conservative evidence strength from existing metadata."""
    if not comparison.candidate:
        return EvidenceStrength.NONE, ()

    reasons: list[str] = []

    if relationship == AccessRelationship.ATTACKER_EXCEEDS_VICTIM:
        reasons.append("attacker_successful_where_victim_was_denied")

    elif relationship == AccessRelationship.SAME_SUCCESS:
        reasons.append("both_authenticated_sessions_received_successful_access")

    if comparison.response_structure_changed:
        reasons.append("response_structure_changed")

    if comparison.response_differences:
        reasons.append("response_differences_present")

    if triage.score >= 60:
        return EvidenceStrength.STRONG, tuple(reasons)

    if triage.score >= 30:
        return EvidenceStrength.MODERATE, tuple(reasons)

    return EvidenceStrength.WEAK, tuple(reasons)


def build_authorization_evidence(
    comparison: AuthorizationComparison,
    triage: AuthorizationTriage,
) -> AuthorizationEvidence:
    """Build canonical authorization evidence from existing contracts.

    This function performs no network activity and does not change the
    underlying authorization candidate decision.
    """
    relationship = _access_relationship(comparison)
    strength, evidence_reasons = _evidence_strength(
        comparison,
        triage,
        relationship,
    )

    return AuthorizationEvidence(
        method=comparison.method,
        url=comparison.url,
        victim_status=comparison.victim_status,
        attacker_status=comparison.attacker_status,
        victim_authenticated=comparison.victim_authenticated,
        attacker_authenticated=comparison.attacker_authenticated,
        candidate=comparison.candidate,
        candidate_reason=comparison.reason,
        access_relationship=relationship,
        response_structure_changed=comparison.response_structure_changed,
        response_differences=comparison.response_differences,
        triage_level=triage.level.value,
        triage_score=triage.score,
        triage_reasons=triage.reasons,
        evidence_strength=strength,
        evidence_reasons=evidence_reasons,
    )
