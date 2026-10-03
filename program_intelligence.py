"""HackerOne program intelligence for AuthLeak.

Stage 1: inexpensive program/policy screening.
Stage 2: structured-scope enrichment for a small shortlist.
Stage 3: scope-quality analysis (asset hygiene, surface density, scan load,
         and scope exclusions).

This module only reads HackerOne program metadata and scope metadata. It does
not launch scans or make report submissions.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import Any
from urllib.parse import quote, urlparse

import httpx

H1_PROGRAMS_URL = "https://api.hackerone.com/v1/hackers/programs"
H1_PAGE_SIZE = 100
H1_USER_AGENT = "AuthLeak/1.4.2 (+authorized-security-testing)"

# These are deliberately conservative. A policy that is merely silent about
# automation stays "unknown" rather than becoming authorization.
AUTOMATION_ALLOWED_PATTERNS = (
    re.compile(r"\bautomated\s+(?:security\s+)?testing\s+is\s+(?:allowed|permitted)\b", re.I),
    re.compile(r"\bautomation\s+is\s+(?:allowed|permitted)\b", re.I),
    re.compile(r"\bautomated\s+scanning\s+is\s+(?:allowed|permitted)\b", re.I),
    re.compile(r"\bautomated\s+(?:tools|tooling)\s+(?:are|is)\s+(?:allowed|permitted)\b", re.I),
)
AUTOMATION_BLOCKED_PATTERNS = (
    re.compile(r"\b(?:automated|automation|automated\s+scanning|automated\s+tools)\b.{0,80}\b(?:prohibited|not allowed|forbidden|disallowed)\b", re.I | re.S),
    re.compile(r"\b(?:prohibited|not allowed|forbidden|disallowed)\b.{0,80}\b(?:automated|automation|automated\s+scanning|automated\s+tools)\b", re.I | re.S),
)
API_PATTERNS = (
    re.compile(r"\bapi\b", re.I),
    re.compile(r"graphql", re.I),
    re.compile(r"rest\s*api", re.I),
    re.compile(r"webhook", re.I),
    re.compile(r"/v\d+(?:[./_-]|$)", re.I),
)
AUTH_PATTERNS = (
    re.compile(r"authentication", re.I),
    re.compile(r"authorization", re.I),
    re.compile(r"access\s+control", re.I),
    re.compile(r"session", re.I),
    re.compile(r"oauth", re.I),
    re.compile(r"jwt", re.I),
    re.compile(r"\b(?:auth|login|signin|sign-in|identity|sso|accounts?)\b", re.I),
)
DISRUPTIVE_PATTERNS = (
    re.compile(r"denial[- ]of[- ]service", re.I),
    re.compile(r"disruptive", re.I),
    re.compile(r"brute[- ]force", re.I),
    re.compile(r"load\s+test", re.I),
    re.compile(r"stress\s+test", re.I),
)

PLACEHOLDER_PATTERNS = (
    re.compile(r"<[^>]+>"),
    re.compile(r"\{[^}]+\}"),
    re.compile(r"\b(?:your|my)-?(?:own|domain|subdomain|account)\b", re.I),
    re.compile(r"--your[^/\s]*--", re.I),
    re.compile(r"\b(?:replace|insert|enter|put)[-_ ]+(?:your|the)[-_ ]", re.I),
    re.compile(r"\b(?:placeholder|dummy)\b", re.I),
)
WILDCARD_PATTERN = re.compile(r"(^|[./])\*([./]|$)")


def _flatten_strings(value: Any, limit: int = 120_000) -> str:
    """Flatten nested JSON into searchable text without dumping secrets."""
    chunks: list[str] = []

    def visit(node: Any) -> None:
        if sum(len(x) for x in chunks) >= limit:
            return
        if isinstance(node, str):
            chunks.append(node[:12_000])
        elif isinstance(node, dict):
            for key, child in node.items():
                if str(key).lower() in {"hackerone_api_token", "token", "password", "secret"}:
                    continue
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return "\n".join(chunks)[:limit]


def _attrs(program: dict[str, Any]) -> dict[str, Any]:
    attrs = program.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def _name(program: dict[str, Any]) -> str:
    attrs = _attrs(program)
    return str(attrs.get("name") or attrs.get("title") or attrs.get("handle") or "Unknown")


def _handle(program: dict[str, Any]) -> str:
    return str(_attrs(program).get("handle") or "").strip()


def _bool_attr(attrs: dict[str, Any], *names: str) -> bool | None:
    for name in names:
        value = attrs.get(name)
        if isinstance(value, bool):
            return value
    return None


def _search_any(text: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def automation_status(program: dict[str, Any]) -> str:
    text = _flatten_strings(program)
    if _search_any(text, AUTOMATION_BLOCKED_PATTERNS):
        return "prohibited"
    if _search_any(text, AUTOMATION_ALLOWED_PATTERNS):
        return "allowed"
    return "unknown"


def metadata_analysis(program: dict[str, Any]) -> dict[str, Any]:
    attrs = _attrs(program)
    text = _flatten_strings(program)
    text_lower = text.lower()
    submission_state = str(attrs.get("submission_state") or attrs.get("state") or "unknown").lower()
    offers_bounties = _bool_attr(attrs, "offers_bounties", "bounty")
    triage_active = _bool_attr(attrs, "triage_active", "managed")
    open_scope = _bool_attr(attrs, "open_scope")
    safe_harbor = _bool_attr(attrs, "gold_standard_safe_harbor", "safe_harbor")
    automation = automation_status(program)

    score = 0
    signals: list[str] = []
    cautions: list[str] = []

    if submission_state in {"open", "accepting submissions", "accepted"}:
        score += 15
        signals.append("Submissions appear open")
    elif "closed" in submission_state:
        cautions.append("Program reports closed submissions")

    bounty_language = any(token in text_lower for token in ("bounty", "reward"))
    if offers_bounties is True:
        score += 10
        signals.append("Program reports bounty/reward eligibility")
    elif offers_bounties is None and bounty_language:
        score += 4
        signals.append("Bounty/reward language detected; structured scope will determine asset eligibility")
    elif offers_bounties is False:
        cautions.append("Program does not report bounty eligibility at the program level")

    if triage_active is True or "triage" in text_lower:
        score += 5
        signals.append("Triage language detected")

    if open_scope is True:
        score += 5
        signals.append("Open-scope policy indicated")

    if safe_harbor is True or "gold standard safe harbor" in text_lower:
        score += 3
        signals.append("Safe-harbor language indicated")

    api = _search_any(text, API_PATTERNS)
    auth = _search_any(text, AUTH_PATTERNS)
    web = any(x in text_lower for x in ("web application", "website", "web app", "web service"))
    client = any(x in text_lower for x in ("javascript", "frontend", "client-side", "browser"))
    if api:
        score += 8
        signals.append("API-oriented language detected")
    if auth:
        score += 8
        signals.append("Authentication/authorization language detected")
    if web:
        score += 5
    if client:
        score += 2

    if "rate limit" in text_lower or "requests per second" in text_lower:
        score += 2
        signals.append("Rate-limit guidance detected")
    if _search_any(text, DISRUPTIVE_PATTERNS):
        cautions.append("Policy contains restrictions related to disruptive testing")

    if automation == "prohibited":
        cautions.append("Automated testing appears prohibited")
    elif automation == "unknown":
        cautions.append("Automation permission is not explicitly determined")

    score = max(0, min(score, 70))
    if automation == "prohibited":
        gate = "blocked"
    elif automation == "allowed":
        gate = "ready"
    else:
        gate = "policy_review"

    return {
        "name": _name(program),
        "handle": _handle(program),
        "metadata_score": score,
        "automation_status": automation,
        "policy_gate": gate,
        "signals": signals[:8],
        "cautions": cautions[:6],
        "technical_profile": {
            "api": api,
            "auth": auth,
            "web": web,
            "client": client,
        },
    }


async def _maybe_log(log_cb, message: str) -> None:
    result = log_cb(message)
    if asyncio.iscoroutine(result):
        await result


async def fetch_programs(username: str, token: str, log_cb=lambda _message: None) -> list[dict[str, Any]]:
    """Fetch all programs available to the authenticated hacker."""
    programs: list[dict[str, Any]] = []
    page = 1
    async with httpx.AsyncClient(
        auth=(username, token),
        timeout=20.0,
        follow_redirects=False,
        headers={"Accept": "application/json", "User-Agent": H1_USER_AGENT},
    ) as client:
        while True:
            response = await client.get(H1_PROGRAMS_URL, params={"page[number]": page, "page[size]": H1_PAGE_SIZE})
            if response.status_code == 401:
                raise RuntimeError("HackerOne authentication failed (HTTP 401)")
            if response.status_code == 403:
                raise RuntimeError("HackerOne denied program access (HTTP 403)")
            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "unspecified")
                raise RuntimeError(f"HackerOne rate limit reached (HTTP 429, Retry-After: {retry_after})")
            response.raise_for_status()
            payload = response.json()
            items = payload.get("data", [])
            if not isinstance(items, list):
                raise RuntimeError("Unexpected HackerOne program response format")
            programs.extend(item for item in items if isinstance(item, dict))
            await _maybe_log(log_cb, f"[intelligence] Programs page {page}: {len(items)} records")
            if len(items) < H1_PAGE_SIZE:
                break
            page += 1
    return programs


async def fetch_structured_scopes(username: str, token: str, handle: str, log_cb=lambda _message: None) -> list[dict[str, Any]]:
    """Fetch a program's complete structured-scope metadata."""
    handle = handle.strip().strip("/")
    if not handle or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in handle):
        raise ValueError("Invalid HackerOne program handle")
    endpoint = f"{H1_PROGRAMS_URL}/{quote(handle, safe='')}/structured_scopes"
    scopes: list[dict[str, Any]] = []
    last_id = 0
    async with httpx.AsyncClient(
        auth=(username, token),
        timeout=20.0,
        follow_redirects=False,
        headers={"Accept": "application/json", "User-Agent": H1_USER_AGENT},
    ) as client:
        while True:
            response = await client.get(endpoint, params={"page[size]": H1_PAGE_SIZE, "filter[id__gt]": last_id})
            if response.status_code == 401:
                raise RuntimeError("HackerOne authentication failed (HTTP 401)")
            if response.status_code == 403:
                raise RuntimeError(f"HackerOne denied structured-scope access for '{handle}' (HTTP 403)")
            if response.status_code == 404:
                raise RuntimeError(f"HackerOne program '{handle}' was not found (HTTP 404)")
            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "unspecified")
                raise RuntimeError(f"HackerOne rate limit reached (HTTP 429, Retry-After: {retry_after})")
            response.raise_for_status()
            payload = response.json()
            items = payload.get("data", [])
            if not isinstance(items, list):
                raise RuntimeError("Unexpected HackerOne structured-scope response format")
            scopes.extend(item for item in items if isinstance(item, dict))
            await _maybe_log(log_cb, f"[intelligence] {handle}: fetched {len(items)} scopes (cumulative {len(scopes)})")
            if not items or len(items) < H1_PAGE_SIZE:
                break
            ids = []
            for item in items:
                try:
                    ids.append(int(item.get("id", 0)))
                except (TypeError, ValueError):
                    pass
            max_id = max(ids, default=last_id)
            if max_id <= last_id:
                raise RuntimeError("HackerOne scope pagination did not advance by ID")
            last_id = max_id
    return scopes


async def fetch_scope_exclusions(username: str, token: str, handle: str, log_cb=lambda _message: None) -> list[dict[str, Any]]:
    """Fetch program-level report categories excluded from rewards."""
    handle = handle.strip().strip("/")
    if not handle or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in handle):
        raise ValueError("Invalid HackerOne program handle")
    endpoint = f"{H1_PROGRAMS_URL}/{quote(handle, safe='')}/scope_exclusions"
    async with httpx.AsyncClient(
        auth=(username, token),
        timeout=20.0,
        follow_redirects=False,
        headers={"Accept": "application/json", "User-Agent": H1_USER_AGENT},
    ) as client:
        response = await client.get(endpoint)
        if response.status_code == 401:
            raise RuntimeError("HackerOne authentication failed (HTTP 401)")
        if response.status_code == 403:
            raise RuntimeError(f"HackerOne denied scope-exclusion access for '{handle}' (HTTP 403)")
        if response.status_code == 404:
            raise RuntimeError(f"HackerOne program '{handle}' was not found (HTTP 404)")
        if response.status_code == 429:
            retry_after = response.headers.get("retry-after", "unspecified")
            raise RuntimeError(f"HackerOne rate limit reached (HTTP 429, Retry-After: {retry_after})")
        response.raise_for_status()
        payload = response.json()
        items = payload.get("data", [])
        if not isinstance(items, list):
            raise RuntimeError("Unexpected HackerOne scope-exclusion response format")
        await _maybe_log(log_cb, f"[intelligence] {handle}: fetched {len(items)} scope exclusions")
        return [item for item in items if isinstance(item, dict)]


def _scope_attrs(scope: dict[str, Any]) -> dict[str, Any]:
    attrs = scope.get("attributes")
    return attrs if isinstance(attrs, dict) else {}


def normalize_scope_identifier(value: str) -> str:
    """Normalize common HackerOne display/markdown escaping without changing meaning."""
    value = value.strip().strip("`")
    markdown = re.match(r"^\[([^\]]+)\]\((https?://[^)]+)\)$", value)
    if markdown:
        value = markdown.group(2)
    value = value.replace(r"\.", ".").replace(r"\/", "/").replace(r"\_", "_")
    return value.strip()


def classify_scope_identifier(value: str) -> str:
    """Classify a scope asset as usable, placeholder, wildcard, or malformed."""
    normalized = normalize_scope_identifier(value)
    if not normalized:
        return "malformed"
    if WILDCARD_PATTERN.search(normalized):
        return "wildcard"
    if _search_any(normalized, PLACEHOLDER_PATTERNS):
        return "placeholder"

    candidate = normalized if "://" in normalized else f"https://{normalized}"
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return "malformed"
    if not host or "." not in host:
        return "malformed"
    return "usable"


def scope_load_classification(usable_url_count: int) -> str:
    if usable_url_count <= 5:
        return "light"
    if usable_url_count <= 25:
        return "moderate"
    if usable_url_count <= 100:
        return "heavy"
    return "very_heavy"


def _exclusion_label(item: dict[str, Any]) -> str:
    attrs = _scope_attrs(item)
    candidates = (
        attrs.get("name"),
        attrs.get("title"),
        attrs.get("category"),
        attrs.get("description"),
        attrs.get("instruction"),
        _flatten_strings(attrs, limit=400),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return " ".join(candidate.split())[:240]
    return "Unspecified scope exclusion"


def summarize_scope_exclusions(exclusions: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_exclusion_label(item) for item in exclusions]
    return {
        "count": len(exclusions),
        "examples": labels[:8],
    }


def summarize_scopes(scopes: list[dict[str, Any]], exclusions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    eligible_submission = []
    bounty_urls: list[str] = []
    asset_type_counts: Counter[str] = Counter()
    auth_assets: list[str] = []
    api_assets: list[str] = []
    web_assets: list[str] = []
    test_assets: list[str] = []
    max_severities: Counter[str] = Counter()

    scope_quality_counts: Counter[str] = Counter()
    usable_url_assets: list[str] = []
    placeholder_urls: list[str] = []
    wildcard_urls: list[str] = []
    malformed_urls: list[str] = []

    for scope in scopes:
        attrs = _scope_attrs(scope)
        asset_type = str(attrs.get("asset_type") or "unknown")
        asset_id_raw = str(attrs.get("asset_identifier") or "").strip()
        asset_id = normalize_scope_identifier(asset_id_raw)
        instruction = str(attrs.get("instruction") or "")
        haystack = f"{asset_id}\n{instruction}".lower()
        asset_type_counts[asset_type] += 1
        if attrs.get("max_severity"):
            max_severities[str(attrs["max_severity"]).lower()] += 1

        if attrs.get("eligible_for_submission") is True:
            eligible_submission.append({
                "asset_identifier": asset_id,
                "asset_type": asset_type,
                "instruction": instruction,
                "eligible_for_bounty": attrs.get("eligible_for_bounty") is True,
                "max_severity": attrs.get("max_severity"),
            })

        if asset_type == "URL" and attrs.get("eligible_for_submission") is True:
            classification = classify_scope_identifier(asset_id)
            scope_quality_counts[classification] += 1
            if classification == "usable":
                usable_url_assets.append(asset_id)
            elif classification == "placeholder":
                placeholder_urls.append(asset_id)
            elif classification == "wildcard":
                wildcard_urls.append(asset_id)
            else:
                malformed_urls.append(asset_id)

            if attrs.get("eligible_for_bounty") is True:
                bounty_urls.append(asset_id)
            if classification == "usable" and _search_any(haystack, API_PATTERNS):
                api_assets.append(asset_id)
            if classification == "usable" and _search_any(haystack, AUTH_PATTERNS):
                auth_assets.append(asset_id)
            if classification == "usable" and any(x in haystack for x in (
                "staging", "sandbox", "test environment", "test env", "development"
            )):
                test_assets.append(asset_id)
            if classification == "usable" and any(x in haystack for x in (
                "website", "web app", "web application", "portal", "dashboard"
            )):
                web_assets.append(asset_id)

    eligible_urls = [item for item in eligible_submission if item["asset_type"] == "URL"]
    eligible_url_count = len(eligible_urls)
    usable_url_count = len(set(x for x in usable_url_assets if x))
    bounty_url_count = len(set(x for x in bounty_urls if x and classify_scope_identifier(x) == "usable"))
    bounty_ratio = (bounty_url_count / usable_url_count) if usable_url_count else 0.0
    api_count = len(set(x for x in api_assets if x))
    auth_count = len(set(x for x in auth_assets if x))

    return {
        "total_scopes": len(scopes),
        "eligible_submission_assets": len(eligible_submission),
        "eligible_url_count": eligible_url_count,
        "usable_url_count": usable_url_count,
        "placeholder_url_count": len(set(placeholder_urls)),
        "wildcard_url_count": len(set(wildcard_urls)),
        "malformed_url_count": len(set(malformed_urls)),
        "bounty_url_count": bounty_url_count,
        "eligible_bounty_url_count": bounty_url_count,
        "bounty_eligible_url_ratio": round(bounty_ratio, 3),
        "api_like_url_count": api_count,
        "auth_like_url_count": auth_count,
        "api_density": round(api_count / usable_url_count, 3) if usable_url_count else 0.0,
        "auth_density": round(auth_count / usable_url_count, 3) if usable_url_count else 0.0,
        "api_auth_overlap_count": len(set(api_assets) & set(auth_assets)),
        "test_or_staging_url_count": len(set(x for x in test_assets if x)),
        "web_like_url_count": len(set(x for x in web_assets if x)),
        "non_url_submission_asset_count": max(0, len(eligible_submission) - eligible_url_count),
        "asset_type_counts": dict(asset_type_counts),
        "max_severity_counts": dict(max_severities),
        "scope_quality_counts": dict(scope_quality_counts),
        "scan_load": scope_load_classification(usable_url_count),
        "scope_examples": [item["asset_identifier"] for item in eligible_urls[:8] if item["asset_identifier"]],
        "usable_scope_examples": list(dict.fromkeys(usable_url_assets))[:8],
        "placeholder_examples": list(dict.fromkeys(placeholder_urls))[:8],
        "wildcard_examples": list(dict.fromkeys(wildcard_urls))[:8],
        "api_examples": sorted(set(x for x in api_assets if x))[:8],
        "auth_examples": sorted(set(x for x in auth_assets if x))[:8],
        "test_examples": sorted(set(x for x in test_assets if x))[:8],
        "scope_exclusions": summarize_scope_exclusions(exclusions or []),
    }


def _surface_bonus(count: int, density: float, cap: int) -> int:
    if count <= 0:
        return 0
    count_component = min(cap - 2, count)
    density_component = min(2, int(round(density * 4)))
    return max(2, count_component + density_component)


def final_compatibility_score(metadata: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    score = int(metadata.get("metadata_score", 0))
    reasons = list(metadata.get("signals", []))
    cautions = list(metadata.get("cautions", []))

    url_count = int(scope.get("eligible_url_count", 0))
    usable_count = int(scope.get("usable_url_count", url_count))
    placeholder_count = int(scope.get("placeholder_url_count", 0))
    wildcard_count = int(scope.get("wildcard_url_count", 0))
    malformed_count = int(scope.get("malformed_url_count", 0))
    api_count = int(scope.get("api_like_url_count", 0))
    auth_count = int(scope.get("auth_like_url_count", 0))
    api_auth_overlap = int(scope.get("api_auth_overlap_count", 0))
    test_count = int(scope.get("test_or_staging_url_count", 0))
    bounty_count = int(scope.get("eligible_bounty_url_count", 0))
    bounty_ratio = float(scope.get("bounty_eligible_url_ratio", 0.0) or 0.0)
    api_density = float(scope.get("api_density", 0.0) or 0.0)
    auth_density = float(scope.get("auth_density", 0.0) or 0.0)
    exclusions = int((scope.get("scope_exclusions") or {}).get("count", 0))

    if usable_count == 0:
        score -= 18
        cautions.append("No usable eligible URL assets found in structured scope")
    elif usable_count <= 10:
        score += 5
        reasons.append(f"{usable_count} usable eligible URL assets in structured scope")
    else:
        # Scope volume is informational after a modest threshold; do not reward
        # hundreds of generic URLs as though they were more specialized.
        score += 6
        reasons.append(f"{usable_count} usable eligible URL assets in structured scope")

    if placeholder_count:
        cautions.append(f"{placeholder_count} eligible URL assets look like placeholders/instructions")
    if wildcard_count:
        cautions.append(f"{wildcard_count} wildcard URL assets need interpretation before direct scanning")
    if malformed_count:
        cautions.append(f"{malformed_count} eligible URL assets could not be treated as concrete hosts")

    if api_count:
        api_bonus = _surface_bonus(api_count, api_density, cap=10)
        score += api_bonus
        reasons.append(f"{api_count} API-like eligible URL assets ({api_density:.0%} density)")
    if auth_count:
        auth_bonus = _surface_bonus(auth_count, auth_density, cap=10)
        score += auth_bonus
        reasons.append(f"{auth_count} auth/session-oriented eligible URL assets ({auth_density:.0%} density)")
    if api_auth_overlap:
        score += min(5, 2 + api_auth_overlap)
        reasons.append(f"{api_auth_overlap} eligible URL assets combine API and auth signals")
    if test_count:
        score += min(3, 1 + test_count // 5)
        reasons.append(f"{test_count} test/staging-like eligible URL assets")

    if bounty_count:
        if bounty_ratio >= 0.75:
            score += 6
            reasons.append(f"{bounty_count} bounty-eligible usable URLs ({bounty_ratio:.0%} of usable scope)")
        elif bounty_ratio >= 0.25:
            score += 4
            reasons.append(f"{bounty_count} bounty-eligible usable URLs ({bounty_ratio:.0%} of usable scope)")
        else:
            score += 2
            reasons.append(f"{bounty_count} bounty-eligible usable URLs ({bounty_ratio:.0%} of usable scope)")
    elif usable_count:
        score -= 8
        cautions.append("Structured scope contains usable URLs, but none are bounty-eligible")

    if usable_count >= 100:
        cautions.append("Very large usable scope; prioritize focused assets rather than scanning everything")
    if exclusions:
        reasons.append(f"{exclusions} program-level scope exclusion categories reported")

    if metadata.get("automation_status") == "unknown":
        cautions.append("Technical fit is separate from authorization; review automation policy before scanning")

    if usable_count and bounty_count == 0:
        cautions.append("Treat as disclosure/VDP scope until bounty eligibility is confirmed")

    score = max(0, min(score, 100))
    automation = metadata.get("automation_status")
    if automation == "prohibited":
        tier = "blocked"
    elif automation != "allowed" and bounty_count == 0:
        tier = "review" if score >= 50 else "low_fit"
    elif score >= 80:
        tier = "strong_fit"
    elif score >= 65:
        tier = "good_fit"
    elif score >= 50:
        tier = "review"
    else:
        tier = "low_fit"

    return {
        **metadata,
        "compatibility_score": score,
        "compatibility_tier": tier,
        "scope_profile": scope,
        "reasons": reasons[:12],
        "cautions": cautions[:10],
    }


async def enrich_shortlist(
    username: str,
    token: str,
    programs: list[dict[str, Any]],
    shortlist_size: int = 12,
    log_cb=lambda _message: None,
) -> list[dict[str, Any]]:
    """Fetch scopes and scope exclusions sequentially for a small shortlist."""
    analyses = []
    for program in programs:
        result = metadata_analysis(program)
        if result["policy_gate"] == "blocked":
            continue
        analyses.append((result["metadata_score"], program, result))
    analyses.sort(key=lambda item: (-item[0], item[2]["name"].lower()))

    limit = max(1, min(shortlist_size, 12))
    enriched: list[dict[str, Any]] = []
    for index, (_score, program, metadata) in enumerate(analyses[:limit], start=1):
        handle = metadata["handle"]
        if not handle:
            continue
        try:
            await _maybe_log(log_cb, f"[intelligence] Enriching {index}/{limit}: {metadata['name']} ({handle})")
            scopes = await fetch_structured_scopes(username, token, handle, log_cb)
            try:
                exclusions = await fetch_scope_exclusions(username, token, handle, log_cb)
            except Exception as exclusion_error:
                await _maybe_log(log_cb, f"[intelligence] {handle}: scope exclusions unavailable: {exclusion_error}")
                exclusions = []
            scope_summary = summarize_scopes(scopes, exclusions)
            enriched.append(final_compatibility_score(metadata, scope_summary))
        except Exception as error:
            enriched.append({
                **metadata,
                "compatibility_score": metadata["metadata_score"],
                "compatibility_tier": "scope_error",
                "scope_profile": {
                    "error": str(error),
                    "total_scopes": 0,
                    "scope_exclusions": {"count": 0, "examples": []},
                },
                "reasons": metadata["signals"][:12],
                "cautions": [*metadata["cautions"], f"Structured scope enrichment failed: {error}"][:10],
            })

    enriched.sort(key=lambda item: (-int(item.get("compatibility_score", 0)), item.get("name", "").lower()))
    return enriched


async def build_recommendations(
    username: str,
    token: str,
    shortlist_size: int = 12,
    log_cb=lambda _message: None,
) -> dict[str, Any]:
    programs = await fetch_programs(username, token, log_cb)
    enriched = await enrich_shortlist(username, token, programs, shortlist_size, log_cb)
    metadata = [metadata_analysis(program) for program in programs]
    return {
        "programs_analyzed": len(programs),
        "scope_enriched": len(enriched),
        "shortlist_size": min(max(shortlist_size, 1), 12),
        "recommendations": enriched,
        "metadata_summary": {
            "automation_prohibited": sum(x["automation_status"] == "prohibited" for x in metadata),
            "automation_allowed": sum(x["automation_status"] == "allowed" for x in metadata),
            "automation_unknown": sum(x["automation_status"] == "unknown" for x in metadata),
        },
    }
