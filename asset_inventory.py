"""Bounded asset inventory primitives for AuthLeak reconnaissance.

The inventory is deliberately in-memory and capped so a noisy target cannot
grow discovery state without limit. It records metadata only; authentication
secrets and response bodies are never stored here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlparse


def _normalize_url(url: str) -> str:
    value = str(url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return value
    return value


def _path_identifiers(path: str) -> list[str]:
    """Return conservative path identifiers without storing request bodies."""
    identifiers: list[str] = []

    for segment in path.strip("/").split("/"):
        value = segment.strip()
        if value and value.isdigit():
            identifiers.append(value)

    return identifiers


def _query_parameters(url: str) -> list[str]:
    """Return query parameter names only; never retain query values."""
    parsed = urlparse(url)
    return sorted(
        {
            str(name)
            for name, _ in parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
            if str(name)
        }
    )


@dataclass
class EndpointRecord:
    """Metadata-only representation of an observed HTTP endpoint."""

    url: str
    method: str
    host: str
    path: str
    resource_type: str = ""
    status: int | None = None
    query_parameters: list[str] = field(default_factory=list)
    path_identifiers: list[str] = field(default_factory=list)
    api_like: bool = False
    in_scope: bool = True
    auth_context: str = "unknown"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


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

    endpoints: dict[str, EndpointRecord] = field(default_factory=dict)

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

    def _endpoint_key(self, url: str, method: str) -> str:
        return f"{str(method or 'GET').upper()} {url}"

    def _record_endpoint(
        self,
        url: str,
        *,
        method: str = "GET",
        resource_type: str = "",
        status: int | None = None,
        api_like: bool = False,
        in_scope: bool = True,
    ) -> None:
        normalized = _normalize_url(url)
        if not normalized:
            return

        normalized_method = str(method or "GET").upper()
        key = self._endpoint_key(normalized, normalized_method)

        existing = self.endpoints.get(key)

        if existing is None:
            if len(self.endpoints) >= self.max_items:
                return

            parsed = urlparse(normalized)

            self.endpoints[key] = EndpointRecord(
                url=normalized,
                method=normalized_method,
                host=(parsed.netloc or "").lower(),
                path=parsed.path or "/",
                resource_type=str(resource_type or "").lower(),
                status=int(status) if status is not None else None,
                query_parameters=_query_parameters(normalized),
                path_identifiers=_path_identifiers(parsed.path or "/"),
                api_like=bool(api_like),
                in_scope=bool(in_scope),
            )
            return

        if resource_type and not existing.resource_type:
            existing.resource_type = str(resource_type).lower()

        if status is not None:
            existing.status = int(status)

        if api_like:
            existing.api_like = True

        if not in_scope:
            existing.in_scope = False

    def record_request(
        self,
        url: str,
        method: str = "GET",
        resource_type: str = "",
        *,
        api_like: bool = False,
        in_scope: bool = True,
    ) -> None:
        """Record request metadata without retaining headers or response bodies."""
        self._record_common(url, method=method, resource_type=resource_type)

        if api_like:
            self._add(self.api_urls, url)

        self._record_endpoint(
            url,
            method=method,
            resource_type=resource_type,
            api_like=api_like,
            in_scope=in_scope,
        )

    def record_response(
        self,
        url: str,
        method: str = "",
        status_code: int | None = None,
        resource_type: str = "",
        *,
        in_scope: bool = True,
    ) -> None:
        """Record response metadata for requests already observed."""
        self._record_common(url, method=method, resource_type=resource_type)

        if status_code is not None:
            self.status_counts[str(int(status_code))] += 1

        self._record_endpoint(
            url,
            method=method or "GET",
            resource_type=resource_type,
            status=status_code,
            in_scope=in_scope,
        )

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

    def summary(self) -> dict[str, object]:
        """Return compact counts suitable for scan progress updates."""
        return {
            "discovered_urls": len(self.discovered_urls),
            "api_urls": len(self.api_urls),
            "script_urls": len(self.script_urls),
            "link_urls": len(self.link_urls),
            "form_urls": len(self.form_urls),
            "blocked_urls": len(self.blocked_urls),
            "endpoints": len(self.endpoints),
            "resource_type_counts": dict(sorted(self.resource_type_counts.items())),
            "method_counts": dict(sorted(self.method_counts.items())),
            "host_counts": dict(sorted(self.host_counts.items())),
            "status_counts": dict(sorted(self.status_counts.items())),
        }

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
                "endpoints": len(self.endpoints),
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
            "endpoints": [
                self.endpoints[key].to_dict()
                for key in sorted(self.endpoints)
            ],
        }


def summarize_inventories(
    inventories: list[AssetInventory],
) -> dict[str, object]:
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

        for key, endpoint in inventory.endpoints.items():
            if key in combined.endpoints:
                existing = combined.endpoints[key]

                if endpoint.resource_type and not existing.resource_type:
                    existing.resource_type = endpoint.resource_type

                if endpoint.status is not None:
                    existing.status = endpoint.status

                if endpoint.api_like:
                    existing.api_like = True

                if not endpoint.in_scope:
                    existing.in_scope = False
            elif len(combined.endpoints) < combined.max_items:
                combined.endpoints[key] = EndpointRecord(
                    url=endpoint.url,
                    method=endpoint.method,
                    host=endpoint.host,
                    path=endpoint.path,
                    resource_type=endpoint.resource_type,
                    status=endpoint.status,
                    query_parameters=list(endpoint.query_parameters),
                    path_identifiers=list(endpoint.path_identifiers),
                    api_like=endpoint.api_like,
                    in_scope=endpoint.in_scope,
                    auth_context=endpoint.auth_context,
                )

        combined.resource_type_counts.update(inventory.resource_type_counts)
        combined.method_counts.update(inventory.method_counts)
        combined.host_counts.update(inventory.host_counts)
        combined.status_counts.update(inventory.status_counts)

    return combined.to_dict()
