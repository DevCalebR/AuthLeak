"""Bounded asset inventory primitives for AuthLeak reconnaissance.

The inventory is deliberately in-memory and capped so a noisy target cannot
grow discovery state without limit. It records metadata only; authentication
secrets and response bodies are never stored here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse


def _normalize_url(url: str) -> str:
    value = str(url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return value
    return value


@dataclass
class AssetInventory:
    """Deduplicated, bounded inventory for one or more authorized scan targets."""

    max_items: int = 5000
    discovered_urls: set[str] = field(default_factory=set)
    api_urls: set[str] = field(default_factory=set)
    script_urls: set[str] = field(default_factory=set)
    link_urls: set[str] = field(default_factory=set)
    form_urls: set[str] = field(default_factory=set)
    blocked_urls: set[str] = field(default_factory=set)
    resource_type_counts: Counter[str] = field(default_factory=Counter)
    method_counts: Counter[str] = field(default_factory=Counter)
    host_counts: Counter[str] = field(default_factory=Counter)
    status_counts: Counter[str] = field(default_factory=Counter)

    def __post_init__(self) -> None:
        if self.max_items < 1:
            raise ValueError("max_items must be at least 1")

    def _add(self, bucket: set[str], url: str) -> bool:
        normalized = _normalize_url(url)
        if not normalized or normalized in bucket:
            return False
        if len(bucket) >= self.max_items:
            return False
        bucket.add(normalized)
        return True

    def _record_common(
        self,
        url: str,
        *,
        method: str = "",
        resource_type: str = "",
    ) -> None:
        normalized = _normalize_url(url)
        if not normalized:
            return

        self._add(self.discovered_urls, normalized)

        parsed = urlparse(normalized)
        if parsed.hostname:
            self.host_counts[parsed.hostname.lower()] += 1

        if method:
            self.method_counts[str(method).upper()] += 1
        if resource_type:
            self.resource_type_counts[str(resource_type).lower()] += 1

    def record_request(
        self,
        url: str,
        method: str = "GET",
        resource_type: str = "",
        *,
        api_like: bool = False,
    ) -> None:
        """Record request metadata without retaining headers or response bodies."""
        self._record_common(url, method=method, resource_type=resource_type)
        if api_like:
            self._add(self.api_urls, url)

    def record_response(
        self,
        url: str,
        method: str = "",
        status_code: int | None = None,
        resource_type: str = "",
    ) -> None:
        """Record response metadata for requests already observed."""
        self._record_common(url, method=method, resource_type=resource_type)
        if status_code is not None:
            self.status_counts[str(int(status_code))] += 1

    def record_script(self, url: str, *, allowed: bool = True) -> None:
        """Record a client-side script reference and optionally mark it blocked."""
        if allowed:
            self._add(self.script_urls, url)
            self._add(self.discovered_urls, url)
        else:
            self.record_blocked(url)

    def record_link(self, url: str, *, allowed: bool = True) -> None:
        if allowed:
            self._add(self.link_urls, url)
            self._add(self.discovered_urls, url)
        else:
            self.record_blocked(url)

    def record_form(self, url: str, *, allowed: bool = True) -> None:
        if allowed:
            self._add(self.form_urls, url)
            self._add(self.discovered_urls, url)
        else:
            self.record_blocked(url)

    def record_blocked(self, url: str) -> None:
        """Record an out-of-scope URL that was discovered but never fetched."""
        self._add(self.blocked_urls, url)

    def to_dict(self) -> dict[str, object]:
        return {
            "limits": {"max_items_per_collection": self.max_items},
            "counts": {
                "discovered_urls": len(self.discovered_urls),
                "api_urls": len(self.api_urls),
                "script_urls": len(self.script_urls),
                "link_urls": len(self.link_urls),
                "form_urls": len(self.form_urls),
                "blocked_urls": len(self.blocked_urls),
            },
            "resource_type_counts": dict(sorted(self.resource_type_counts.items())),
            "method_counts": dict(sorted(self.method_counts.items())),
            "host_counts": dict(sorted(self.host_counts.items())),
            "status_counts": dict(sorted(self.status_counts.items())),
            "urls": sorted(self.discovered_urls),
            "api_urls": sorted(self.api_urls),
            "script_urls": sorted(self.script_urls),
            "link_urls": sorted(self.link_urls),
            "form_urls": sorted(self.form_urls),
            "blocked_urls": sorted(self.blocked_urls),
        }


def summarize_inventories(inventories: list[AssetInventory]) -> dict[str, object]:
    """Combine per-target inventories into one bounded aggregate summary."""
    combined = AssetInventory(
        max_items=max((item.max_items for item in inventories), default=5000)
    )
    for inventory in inventories:
        for url in inventory.discovered_urls:
            combined._add(combined.discovered_urls, url)
        for url in inventory.api_urls:
            combined._add(combined.api_urls, url)
        for url in inventory.script_urls:
            combined._add(combined.script_urls, url)
        for url in inventory.link_urls:
            combined._add(combined.link_urls, url)
        for url in inventory.form_urls:
            combined._add(combined.form_urls, url)
        for url in inventory.blocked_urls:
            combined._add(combined.blocked_urls, url)
        combined.resource_type_counts.update(inventory.resource_type_counts)
        combined.method_counts.update(inventory.method_counts)
        combined.host_counts.update(inventory.host_counts)
        combined.status_counts.update(inventory.status_counts)
    return combined.to_dict()
