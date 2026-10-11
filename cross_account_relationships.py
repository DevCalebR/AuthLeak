"""Conservative cross-account resource relationship modeling.

This module compares already-observed URLs and metadata. It does not make
network requests, perform authorization tests, or confirm vulnerabilities.

A relationship is a heuristic:
- POSSIBLE_SAME_RESOURCE: the URLs have compatible resource paths and
  matching recognized identifiers.
- POSSIBLE_DIFFERENT_RESOURCES: the URLs have compatible resource paths
  and different recognized identifiers.
- INDETERMINATE: available evidence is insufficient or unsafe to compare.

All conclusions require manual verification before being treated as findings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from urllib.parse import urlparse, urlunparse

from resource_identity import (
    ResourceIdentity,
    ResourceIdentityConfidence,
    analyze_resource_identity,
)


class RelationshipType(str, Enum):
    """Possible relationship between two observed resources."""

    POSSIBLE_SAME_RESOURCE = "possible_same_resource"
    POSSIBLE_DIFFERENT_RESOURCES = "possible_different_resources"
    INDETERMINATE = "indeterminate"


class RelationshipConfidence(str, Enum):
    """Confidence in the URL-based relationship heuristic."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ResourceRelationship:
    """Metadata-only assessment of a pair of observed resource URLs."""

    method: str
    left_url: str
    right_url: str
    relationship: RelationshipType
    confidence: RelationshipConfidence
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""
        result = asdict(self)
        result["relationship"] = self.relationship.value
        result["confidence"] = self.confidence.value
        result["reasons"] = list(self.reasons)
        return result


def _safe_method(method: str) -> str | None:
    """Allow only methods suitable for conservative read-only analysis."""
    normalized = str(method or "").strip().upper()

    if normalized not in {"GET", "HEAD", "OPTIONS"}:
        return None

    return normalized


def _safe_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized origin without credentials or URL parameters.

    The origin includes scheme, hostname, and effective port. Explicit
    default ports are normalized so that https://host and https://host:443
    compare as the same origin.
    """
    try:
        parsed = urlparse(str(url or "").strip())
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None

    if scheme not in {"http", "https"} or not hostname:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname, port


def _safe_display_url(url: str) -> str:
    """Remove user information, query parameters, and fragments from a URL."""
    try:
        parsed = urlparse(str(url or "").strip())
        origin = _safe_origin(url)

        if origin is None:
            return ""

        scheme, hostname, effective_port = origin
        default_port = 443 if scheme == "https" else 80

        # Preserve non-default ports but omit default ports in display URLs.
        port_suffix = (
            f":{effective_port}" if effective_port != default_port else ""
        )

        # IPv6 hostnames require brackets when reconstructed.
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        safe_netloc = f"{hostname}{port_suffix}"

        return urlunparse(
            (
                scheme,
                safe_netloc,
                parsed.path or "/",
                "",
                "",
                "",
            )
        )
    except (TypeError, ValueError):
        return ""


def _normalized_path(
    url: str,
    identities: tuple[ResourceIdentity, ...],
) -> str:
    """Replace recognized identifier segments with a common placeholder."""
    try:
        parsed = urlparse(str(url or "").strip())
    except ValueError:
        return ""

    segments = [segment for segment in parsed.path.split("/") if segment]

    for identity in identities:
        index = identity.segment_index

        if 0 <= index < len(segments):
            segments[index] = "{id}"

    return "/" + "/".join(segments) if segments else "/"


def _is_low_confidence(identity: ResourceIdentity) -> bool:
    """Check an identity confidence value without relying on enum formatting."""
    confidence = identity.confidence

    if isinstance(confidence, ResourceIdentityConfidence):
        return confidence == ResourceIdentityConfidence.LOW

    return str(getattr(confidence, "value", confidence)).lower() == "low"


def _identity_type(identity: ResourceIdentity) -> str:
    """Return a normalized identifier-type label."""
    identifier_type = identity.identifier_type
    return str(getattr(identifier_type, "value", identifier_type)).lower()


def _indeterminate(
    *,
    method: str,
    left_url: str,
    right_url: str,
    reason: str,
) -> ResourceRelationship:
    """Build a low-confidence result when comparison is unsafe or inconclusive."""
    return ResourceRelationship(
        method=method,
        left_url=_safe_display_url(left_url),
        right_url=_safe_display_url(right_url),
        relationship=RelationshipType.INDETERMINATE,
        confidence=RelationshipConfidence.LOW,
        reasons=(reason,),
    )


def compare_resource_relationship(
    left_url: str,
    right_url: str,
    left_method: str = "GET",
    right_method: str = "GET",
    left_in_scope: bool = True,
    right_in_scope: bool = True,
    left_authenticated: bool = True,
    right_authenticated: bool = True,
) -> ResourceRelationship:
    """Compare two observed URLs for a possible resource relationship.

    This function does not prove that two requests belong to different
    accounts. Callers must establish account/session provenance separately.

    Only GET, HEAD, and OPTIONS observations are considered. Both observations
    must be in scope and authenticated, and both URLs must share the same
    normalized origin before their resource paths are compared.

    Args:
        left_url: First observed resource URL.
        right_url: Second observed resource URL.
        left_method: HTTP method associated with the first observation.
        right_method: HTTP method associated with the second observation.
        left_in_scope: Whether the first observation passed scope validation.
        right_in_scope: Whether the second observation passed scope validation.
        left_authenticated: Whether the first observation was authenticated.
        right_authenticated: Whether the second observation was authenticated.

    Returns:
        A conservative ResourceRelationship assessment. This is not a
        vulnerability confirmation.
    """
    safe_left_method = _safe_method(left_method)
    safe_right_method = _safe_method(right_method)

    if safe_left_method is None or safe_right_method is None:
        return _indeterminate(
            method="",
            left_url=left_url,
            right_url=right_url,
            reason="unsupported_or_unsafe_method",
        )

    if safe_left_method != safe_right_method:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="method_mismatch",
        )

    if not left_in_scope or not right_in_scope:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="observations_not_eligible_for_comparison",
        )

    if not left_authenticated or not right_authenticated:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="unauthenticated_observation",
        )

    left_origin = _safe_origin(left_url)
    right_origin = _safe_origin(right_url)

    if left_origin is None or left_origin != right_origin:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="host_missing_or_different",
        )

    left_identity_analysis = analyze_resource_identity(left_url)
    right_identity_analysis = analyze_resource_identity(right_url)

    left_identities = tuple(left_identity_analysis.identities)
    right_identities = tuple(right_identity_analysis.identities)

    left_path = _normalized_path(left_url, left_identities)
    right_path = _normalized_path(right_url, right_identities)

    if not left_path or not right_path or left_path != right_path:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="resource_path_shape_mismatch",
        )

    if not left_identities or not right_identities:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="no_recognized_resource_identifiers",
        )

    if len(left_identities) != len(right_identities):
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="identifier_count_mismatch",
        )

    left_types = tuple(_identity_type(identity) for identity in left_identities)
    right_types = tuple(
        _identity_type(identity) for identity in right_identities
    )

    if left_types != right_types:
        return _indeterminate(
            method=safe_left_method,
            left_url=left_url,
            right_url=right_url,
            reason="identifier_type_mismatch",
        )

    left_values = tuple(identity.identifier for identity in left_identities)
    right_values = tuple(identity.identifier for identity in right_identities)

    all_confident = not any(
        _is_low_confidence(identity)
        for identity in (*left_identities, *right_identities)
    )

    confidence = (
        RelationshipConfidence.MEDIUM
        if all_confident
        else RelationshipConfidence.LOW
    )

    if left_values == right_values:
        return ResourceRelationship(
            method=safe_left_method,
            left_url=_safe_display_url(left_url),
            right_url=_safe_display_url(right_url),
            relationship=RelationshipType.POSSIBLE_SAME_RESOURCE,
            confidence=confidence,
            reasons=("matching_path_identifiers",),
        )

    return ResourceRelationship(
        method=safe_left_method,
        left_url=_safe_display_url(left_url),
        right_url=_safe_display_url(right_url),
        relationship=RelationshipType.POSSIBLE_DIFFERENT_RESOURCES,
        confidence=confidence,
        reasons=("different_path_identifiers",),
    )
