
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Sequence
from urllib.parse import urlsplit

from authorization_evidence import (
    AccessRelationship,
    AuthorizationEvidence,
)
from cross_account_relationships import (
    RelationshipConfidence,
    RelationshipType,
    ResourceRelationship,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class CorrelationType(StrEnum):
    """Conservative interpretation of linked evidence."""

    CORROBORATING_SIGNAL = "corroborating_signal"
    DISTINCT_RESOURCE_CONTEXT = "distinct_resource_context"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class EvidenceLink:
    """Explicitly link two evidence records to a relationship assessment."""

    left_index: int
    right_index: int
    relationship: ResourceRelationship


@dataclass(frozen=True)
class CorrelatedEvidence:
    """A metadata-only correlation result; contains no URLs or secrets."""

    left_index: int
    right_index: int
    method: str
    correlation: CorrelationType
    resource_relationship: RelationshipType
    relationship_confidence: RelationshipConfidence
    authorization_differential_present: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize safe correlation metadata without URLs or credentials."""
        return {
            "left_index": self.left_index,
            "right_index": self.right_index,
            "method": self.method,
            "correlation": self.correlation.value,
            "resource_relationship": self.resource_relationship.value,
            "relationship_confidence": self.relationship_confidence.value,
            "authorization_differential_present": (
                self.authorization_differential_present
            ),
            "reasons": list(self.reasons),
        }


def _safe_url_identity(url: str) -> tuple[str, str, int, str] | None:
    """Return normalized origin and path, excluding query strings and fragments."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return None

    if scheme not in {"http", "https"} or not hostname:
        return None

    if parsed.username is not None or parsed.password is not None:
        return None

    effective_port = port if port is not None else (
        443 if scheme == "https" else 80
    )

    return (
        scheme,
        hostname.lower(),
        effective_port,
        parsed.path or "/",
    )


def _authorization_differential(
    left: AuthorizationEvidence,
    right: AuthorizationEvidence,
) -> bool:
    """Report an existing attacker-exceeds-victim access signal."""
    return (
        left.access_relationship == AccessRelationship.ATTACKER_EXCEEDS_VICTIM
        or right.access_relationship == AccessRelationship.ATTACKER_EXCEEDS_VICTIM
    )


def correlate_authorization_evidence(
    evidence: Sequence[AuthorizationEvidence],
    links: Sequence[EvidenceLink],
) -> list[CorrelatedEvidence]:
    """
    Correlate existing authorization evidence with resource relationships.

    Performs no network requests and does not inspect response bodies.
    Correlation is a review signal, never vulnerability confirmation.

    The caller must keep evidence and links within the same authorized
    program, scan, and session context.
    """
    results: list[CorrelatedEvidence] = []

    for link in links:
        left_index = link.left_index
        right_index = link.right_index
        relationship = link.relationship

        if (
            left_index < 0
            or right_index < 0
            or left_index >= len(evidence)
            or right_index >= len(evidence)
            or left_index == right_index
        ):
            results.append(
                CorrelatedEvidence(
                    left_index=left_index,
                    right_index=right_index,
                    method="",
                    correlation=CorrelationType.INDETERMINATE,
                    resource_relationship=relationship.relationship,
                    relationship_confidence=relationship.confidence,
                    authorization_differential_present=False,
                    reasons=("invalid_or_repeated_evidence_indices",),
                )
            )
            continue

        left = evidence[left_index]
        right = evidence[right_index]

        left_method = str(left.method).upper()
        right_method = str(right.method).upper()
        method = left_method if left_method == right_method else ""

        reasons: list[str] = []
        eligible = True
        differential = _authorization_differential(left, right)

        if not method or method not in SAFE_METHODS:
            eligible = False
            reasons.append("method_not_eligible_for_correlation")

        if not left.candidate or not right.candidate:
            eligible = False
            reasons.append("both_records_must_be_existing_candidates")

        if not (
            left.victim_authenticated
            and left.attacker_authenticated
            and right.victim_authenticated
            and right.attacker_authenticated
        ):
            eligible = False
            reasons.append("authenticated_evidence_required")

        left_identity = _safe_url_identity(left.url)
        right_identity = _safe_url_identity(right.url)
        relationship_left_identity = _safe_url_identity(relationship.left_url)
        relationship_right_identity = _safe_url_identity(relationship.right_url)

        if (
            left_identity is None
            or right_identity is None
            or relationship_left_identity is None
            or relationship_right_identity is None
        ):
            eligible = False
            reasons.append("invalid_or_unsafe_url_identity")
        elif (
            left_identity != relationship_left_identity
            or right_identity != relationship_right_identity
        ):
            eligible = False
            reasons.append("relationship_provenance_mismatch")

        if not eligible:
            correlation = CorrelationType.INDETERMINATE
            differential = False
            reasons.append("correlation_is_not_vulnerability_confirmation")
        elif relationship.relationship == RelationshipType.POSSIBLE_SAME_RESOURCE:
            correlation = CorrelationType.CORROBORATING_SIGNAL
            reasons.append(
                "resource_relationship_may_corroborate_existing_signal"
            )
            reasons.append("resource_identity_does_not_prove_ownership")
            reasons.append("correlation_is_not_vulnerability_confirmation")
        elif (
            relationship.relationship
            == RelationshipType.POSSIBLE_DIFFERENT_RESOURCES
        ):
            correlation = CorrelationType.DISTINCT_RESOURCE_CONTEXT
            reasons.append(
                "different_resource_context_requires_manual_review"
            )
            reasons.append("resource_identity_does_not_prove_ownership")
            reasons.append("correlation_is_not_vulnerability_confirmation")
        else:
            correlation = CorrelationType.INDETERMINATE
            reasons.append("resource_relationship_is_indeterminate")
            reasons.append("correlation_is_not_vulnerability_confirmation")

        results.append(
            CorrelatedEvidence(
                left_index=left_index,
                right_index=right_index,
                method=method,
                correlation=correlation,
                resource_relationship=relationship.relationship,
                relationship_confidence=relationship.confidence,
                authorization_differential_present=differential,
                reasons=tuple(reasons),
            )
        )

    return results

