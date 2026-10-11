"""Conservative resource identity analysis for AuthLeak.

B3.9.2 identifies possible resource identifiers in observed URL paths.

This module performs no network activity. It never retains query strings,
fragments, URL user information, request bodies, credentials, or response
bodies. Its output is an inference, not proof of resource ownership or
an authorization vulnerability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse, urlunsplit


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

_OPAQUE_ID_RE = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{8,}$"
)

_RESOURCE_CONTEXTS = {
    "id", "ids",
    "user", "users",
    "account", "accounts",
    "project", "projects",
    "document", "documents",
    "order", "orders",
    "organization", "organizations", "org", "orgs",
    "member", "members",
    "message", "messages",
    "item", "items",
    "comment", "comments",
    "task", "tasks",
    "ticket", "tickets",
    "file", "files",
    "invoice", "invoices",
    "team", "teams",
    "workspace", "workspaces",
    "repository", "repositories", "repo", "repos",
}


class ResourceIdentifierType(StrEnum):
    """Conservative classification of a possible resource identifier."""

    NUMERIC_ID = "numeric_id"
    UUID = "uuid"
    OPAQUE_ID = "opaque_id"


class ResourceIdentityConfidence(StrEnum):
    """Confidence that a path segment represents a resource identifier."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ResourceIdentity:
    """A possible resource identifier inferred from one URL path segment."""

    identifier: str
    segment_index: int
    identifier_type: ResourceIdentifierType
    resource_segment: str
    confidence: ResourceIdentityConfidence

    def to_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "segment_index": self.segment_index,
            "identifier_type": self.identifier_type.value,
            "resource_segment": self.resource_segment,
            "confidence": self.confidence.value,
        }


@dataclass(frozen=True)
class ResourceIdentityAnalysis:
    """Metadata-only resource identity analysis for one URL."""

    url: str
    path: str
    identities: tuple[ResourceIdentity, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "path": self.path,
            "identities": [
                identity.to_dict() for identity in self.identities
            ],
        }


def _safe_url_reference(value: str, parsed) -> str:
    """Return a URL reference without credentials, query, or fragment."""
    path = parsed.path or "/"

    # Relative URLs have no authority to sanitize.
    if not parsed.netloc:
        return urlunsplit(("", "", path, "", ""))

    # Never preserve user information from the authority component.
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        # Malformed authority: retain only the path.
        return urlunsplit(("", "", path, "", ""))

    if not hostname:
        return urlunsplit(("", "", path, "", ""))

    # IPv6 literals require brackets when reconstructed.
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host

    return urlunsplit((parsed.scheme, netloc, path, "", ""))


def _identifier_type(segment: str) -> ResourceIdentifierType | None:
    if segment.isdigit():
        return ResourceIdentifierType.NUMERIC_ID
    if _UUID_RE.fullmatch(segment):
        return ResourceIdentifierType.UUID
    if _OPAQUE_ID_RE.fullmatch(segment):
        return ResourceIdentifierType.OPAQUE_ID
    return None


def _confidence(
    identifier_type: ResourceIdentifierType,
    resource_segment: str,
) -> ResourceIdentityConfidence:
    """Estimate confidence; ambiguous segments remain low-confidence."""

    if resource_segment.lower() in _RESOURCE_CONTEXTS:
        if identifier_type in {
            ResourceIdentifierType.NUMERIC_ID,
            ResourceIdentifierType.UUID,
        }:
            return ResourceIdentityConfidence.HIGH
        return ResourceIdentityConfidence.MEDIUM

    if identifier_type == ResourceIdentifierType.UUID:
        return ResourceIdentityConfidence.MEDIUM

    return ResourceIdentityConfidence.LOW


def analyze_resource_identity(url: str) -> ResourceIdentityAnalysis:
    """Analyze possible identifiers in a URL path only.

    Query parameters and fragments are not analyzed or retained.
    """
    value = str(url or "").strip()

    try:
        parsed = urlparse(value)
    except ValueError:
        parsed = urlparse("")

    path = parsed.path or "/"
    safe_url = _safe_url_reference(value, parsed)

    segments = [
        segment.strip()
        for segment in path.strip("/").split("/")
        if segment.strip()
    ]

    identities: list[ResourceIdentity] = []

    for index, segment in enumerate(segments):
        identifier_type = _identifier_type(segment)
        if identifier_type is None:
            continue

        resource_segment = segments[index - 1] if index > 0 else ""

        identities.append(
            ResourceIdentity(
                identifier=segment,
                segment_index=index,
                identifier_type=identifier_type,
                resource_segment=resource_segment,
                confidence=_confidence(identifier_type, resource_segment),
            )
        )

    return ResourceIdentityAnalysis(
        url=safe_url,
        path=path,
        identities=tuple(identities),
    )
