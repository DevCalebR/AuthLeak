"""Conservative candidate disposition and duplicate suppression for AuthLeak.

B3.9.4 separates candidates suitable for review from duplicate, incomplete,
ineligible, and non-candidate observations.

This module performs no network requests, does not inspect response bodies,
and never confirms or disproves a vulnerability. Every input receives a
disposition record so that observations are not silently discarded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

from authorization_compare import AuthorizationComparison


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class CandidateDisposition(StrEnum):
    """How an authorization comparison should be handled by the review queue."""

    RETAIN_FOR_REVIEW = "retain_for_review"
    DUPLICATE = "duplicate"
    NOT_A_CANDIDATE = "not_a_candidate"
    INCOMPLETE = "incomplete"
    INELIGIBLE = "ineligible"


@dataclass(frozen=True)
class SuppressionDecision:
    """Disposition metadata for one comparison; original evidence is preserved."""

    input_index: int
    disposition: CandidateDisposition
    reason: str
    duplicate_of_index: int | None = None

    @property
    def should_show_in_review_queue(self) -> bool:
        """Whether this record should appear as a distinct review-queue item."""
        return self.disposition == CandidateDisposition.RETAIN_FOR_REVIEW

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable decision record."""
        result = asdict(self)
        result["disposition"] = self.disposition.value
        result["should_show_in_review_queue"] = (
            self.should_show_in_review_queue
        )
        return result


def _duplicate_key(
    comparison: AuthorizationComparison,
) -> tuple[str, str] | None:
    """Build a conservative duplicate key from method and URL.

    Fragments are ignored because they are not sent in HTTP requests.
    Query strings are retained because they may distinguish resources.
    The original comparison and URL are never modified.
    """
    method = str(comparison.method or "").strip().upper()
    raw_url = str(comparison.url or "").strip()

    if method not in SAFE_METHODS or not raw_url:
        return None

    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"} or not parsed.hostname:
        return None

    # Do not classify URLs containing embedded credentials.
    if parsed.username is not None or parsed.password is not None:
        return None

    # Reject malformed ports rather than treating uncertain URLs as duplicates.
    try:
        port = parsed.port
    except ValueError:
        return None

    hostname = parsed.hostname.lower()

    # Preserve valid IPv6 authority syntax.
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    # Normalize away the scheme's default port.
    default_port = 443 if scheme == "https" else 80
    netloc = hostname
    if port is not None and port != default_port:
        netloc = f"{hostname}:{port}"

    normalized_url = urlunsplit(
        (
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    return method, normalized_url


def classify_authorization_comparisons(
    comparisons: list[AuthorizationComparison],
) -> list[SuppressionDecision]:
    """Classify comparisons without changing their candidate decisions.

    Rules are intentionally conservative:
    - Unsafe methods or unusable URLs are ineligible.
    - Unauthenticated comparisons are ineligible.
    - Missing status outcomes are incomplete, not automatically false positives.
    - Existing non-candidates remain non-candidates.
    - Exact method/URL duplicates point to the first retained candidate.
    - Other candidates remain available for manual review.

    A low triage score is never, by itself, a suppression reason.
    """
    decisions: list[SuppressionDecision] = []
    first_candidate_by_key: dict[tuple[str, str], int] = {}

    for index, comparison in enumerate(comparisons):
        method = str(comparison.method or "").strip().upper()
        key = _duplicate_key(comparison)

        if method not in SAFE_METHODS or key is None:
            decisions.append(
                SuppressionDecision(
                    input_index=index,
                    disposition=CandidateDisposition.INELIGIBLE,
                    reason="unsafe_method_or_invalid_url",
                )
            )
            continue

        if not (
            comparison.victim_authenticated
            and comparison.attacker_authenticated
        ):
            decisions.append(
                SuppressionDecision(
                    input_index=index,
                    disposition=CandidateDisposition.INELIGIBLE,
                    reason="both_sessions_must_be_authenticated",
                )
            )
            continue

        if (
            comparison.victim_status is None
            or comparison.attacker_status is None
        ):
            decisions.append(
                SuppressionDecision(
                    input_index=index,
                    disposition=CandidateDisposition.INCOMPLETE,
                    reason="missing_access_outcome",
                )
            )
            continue

        if not comparison.candidate:
            decisions.append(
                SuppressionDecision(
                    input_index=index,
                    disposition=CandidateDisposition.NOT_A_CANDIDATE,
                    reason="comparison_not_marked_as_candidate",
                )
            )
            continue

        previous_index = first_candidate_by_key.get(key)

        if previous_index is not None:
            decisions.append(
                SuppressionDecision(
                    input_index=index,
                    disposition=CandidateDisposition.DUPLICATE,
                    reason="duplicate_method_and_url",
                    duplicate_of_index=previous_index,
                )
            )
            continue

        first_candidate_by_key[key] = index
        decisions.append(
            SuppressionDecision(
                input_index=index,
                disposition=CandidateDisposition.RETAIN_FOR_REVIEW,
                reason="eligible_candidate_requires_manual_review",
            )
        )

    return decisions
