"""Asynchronous crawler, vulnerability checks, and report utilities for AuthLeak."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx
from playwright.async_api import BrowserContext, Page, async_playwright

LogCallback = Callable[[str], Awaitable[None]]

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Generic Bearer Token": r"bearer\s*[a-zA-Z0-9_\-\.]{20,}",
}
API_PATH_MARKER = re.compile(r"/(?:api|v1|v2)(?:/|$)|/\d+/?$", re.IGNORECASE)


@dataclass
class Finding:
    title: str
    severity: str
    cvss: float
    description: str
    evidence: str
    source: str
    curl: str
    python: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validated_url(value: str, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL.")
    return value


def _is_api_endpoint(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(API_PATH_MARKER.search(parsed.path))


def _curl(url: str, headers: dict[str, str], payload: Any | None) -> str:
    parts = ["curl -i -X POST", shlex.quote(url)]
    for name, value in headers.items():
        parts.extend(["-H", shlex.quote(f"{name}: {value}")])
    if payload is not None:
        parts.extend(["-H", "'Content-Type: application/json'", "--data", shlex.quote(json.dumps(payload))])
    return " ".join(parts)


def _python_poc(url: str, headers: dict[str, str], payload: Any | None) -> str:
    return (
        "import requests\n\n"
        f"url = {url!r}\nheaders = {headers!r}\npayload = {payload!r}\n"
        "response = requests.post(url, headers=headers, json=payload, timeout=15)\n"
        "print(response.status_code)\nprint(response.text)\n"
    )


async def crawl_target(target_url: str, log: LogCallback) -> tuple[list[str], list[str]]:
    """Map scripts and API-shaped requests observed by a headless Chromium browser."""
    _validated_url(target_url, "Target URL")
    endpoints: set[str] = set()

    def inspect_request(request: Any) -> None:
        if _is_api_endpoint(request.url):
            endpoints.add(request.url)

    await log(f"[crawl] launching headless Chromium for {target_url}")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context: BrowserContext = await browser.new_context()
        page: Page = await context.new_page()
        page.on("request", inspect_request)
        try:
            await page.goto(target_url, wait_until="networkidle", timeout=30_000)
            scripts = await page.locator("script[src]").evaluate_all(
                "elements => elements.map(element => new URL(element.src, document.baseURI).href)"
            )
            await log(f"[crawl] observed {len(endpoints)} API-shaped request(s) and {len(scripts)} script asset(s)")
            return list(dict.fromkeys(scripts)), sorted(endpoints)
        finally:
            await context.close()
            await browser.close()


async def analyze_javascript(script_urls: list[str], client: httpx.AsyncClient, log: LogCallback) -> list[Finding]:
    """Download browser-discovered JavaScript assets and look for exposed secrets."""
    async def fetch(url: str) -> tuple[str, str]:
        try:
            response = await client.get(url)
            response.raise_for_status()
            await log(f"[asset] downloaded {url}")
            return url, response.text
        except httpx.HTTPError as error:
            await log(f"[warn] could not fetch {url}: {error}")
            return url, ""

    assets = await asyncio.gather(*(fetch(url) for url in script_urls))
    findings: list[Finding] = []
    for url, content in assets:
        for kind, pattern in SECRET_PATTERNS.items():
            for evidence in dict.fromkeys(re.findall(pattern, content, re.IGNORECASE)):
                findings.append(Finding(
                    title=f"Exposed {kind}", severity="high", cvss=7.5,
                    description="A credential-shaped value was found in a client-side JavaScript asset.",
                    evidence=evidence, source=url,
                    curl=f"curl -s {shlex.quote(url)} | grep -i {shlex.quote(evidence)}",
                    python=f"import requests\n\nasset = requests.get({url!r}, timeout=15).text\nprint({evidence!r} in asset)\n",
                    remediation=("Revoke and rotate this credential, keep privileged values in server-side environment variables or a secret manager, and block secrets in client bundles with CI scanning."),
                ))
                await log(f"[finding] {kind} found in {url}")
    return findings


async def token_swap_fuzz(endpoint: str, payload: Any, victim_token: str, attacker_token: str, victim_criteria: str, client: httpx.AsyncClient, log: LogCallback) -> Finding | None:
    """Apply Token B to a victim-shaped payload and confirm victim response content."""
    _validated_url(endpoint, "API endpoint")
    if not victim_token or not attacker_token or not victim_criteria:
        await log("[skip] TokenSwap requires Token A, Token B, and victim-response criteria.")
        return None
    headers = {"Authorization": attacker_token, "Content-Type": "application/json"}
    await log(f"[tokenswap] testing {endpoint} with Token B")
    try:
        response = await client.post(endpoint, headers=headers, json=payload)
    except httpx.HTTPError as error:
        await log(f"[warn] TokenSwap request failed for {endpoint}: {error}")
        return None
    if response.status_code == 200 and victim_criteria.lower() in response.text.lower():
        await log(f"[finding] TokenSwap response matched victim criteria at {endpoint}")
        return Finding(
            title="Potential IDOR / Token Swap", severity="critical", cvss=9.1,
            description="Token B retrieved victim-identifying content using victim-shaped request data.",
            evidence=f"HTTP 200; matched criteria: {victim_criteria}", source=endpoint,
            curl=_curl(endpoint, headers, payload), python=_python_poc(endpoint, headers, payload),
            remediation=("Authorize every requested object on the server using the authenticated principal rather than a client-supplied identifier. Return `403 Forbidden` for cross-user access and add authorization regression tests."),
        )
    await log(f"[tokenswap] no confirmation at {endpoint} (HTTP {response.status_code}).")
    return None


async def run_scan(config: dict[str, Any], log: LogCallback) -> list[dict[str, Any]]:
    """Crawl with Playwright, inspect JavaScript, then fuzz supplied and mapped endpoints."""
    target_url = _validated_url(str(config.get("target_url", "")), "Target URL")
    findings: list[Finding] = []
    scripts, discovered_endpoints = await crawl_target(target_url, log)
    configured_endpoint = str(config.get("api_endpoint", "")).strip()
    endpoints = list(dict.fromkeys(([configured_endpoint] if configured_endpoint else []) + discovered_endpoints))
    timeout = httpx.Timeout(15.0, connect=8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": "AuthLeak/0.2 local scanner"}) as client:
        findings.extend(await analyze_javascript(scripts, client, log))
        if endpoints:
            try:
                payload = json.loads(str(config.get("payload", "{}")))
            except json.JSONDecodeError as error:
                await log(f"[error] TokenSwap skipped: invalid JSON payload: {error}")
            else:
                token_checks = [
                    token_swap_fuzz(endpoint, payload, str(config.get("victim_token", "")), str(config.get("attacker_token", "")), str(config.get("victim_criteria", "")), client, log)
                    for endpoint in endpoints
                ]
                findings.extend(finding for finding in await asyncio.gather(*token_checks) if finding)
    await log(f"[complete] scan finished with {len(findings)} finding(s)")
    return [finding.to_dict() for finding in findings]


def render_markdown_report(findings: list[dict[str, Any]]) -> str:
    """Render findings into a triage-ready Markdown bug bounty report."""
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    table_rows = "\n".join(
        f"| {item['title']} | `{item['source']}` | {item['severity'].upper()} | {item['cvss']:.1f} |"
        for item in findings
    )
    sections = []
    for number, item in enumerate(findings, start=1):
        sections.append(
            f"## {number}. {item['title']}\n\n"
            f"**Severity:** {item['severity'].upper()}  \n**CVSS 3.1:** {item['cvss']:.1f}  \n"
            f"**Impacted endpoint / asset:** `{item['source']}`\n\n"
            f"### Vulnerability details\n{item['description']}\n\n"
            f"### Exact evidence\n```text\n{item['evidence']}\n```\n\n"
            f"### Step-by-step proof of concept\n1. Use only an authorized test environment.\n2. Run the following cURL command:\n```bash\n{item['curl']}\n```\n3. Or reproduce with Python requests:\n```python\n{item['python']}\n```\n\n"
            f"### Practical remediation advice\n```text\n{item['remediation']}\n```"
        )
    return (
        "# AuthLeak Bug Bounty Report\n\n"
        f"**Generated:** {generated_at}\n\n"
        "## Executive Summary\n"
        f"AuthLeak identified **{len(findings)}** confirmed finding(s) during this authorized assessment. Validate scope and impact before submission.\n\n"
        "## Vulnerability Summary Table\n\n"
        "| Type | Impacted Endpoint | Severity | CVSS 3.1 |\n|---|---|---|---:|\n"
        f"{table_rows}\n\n# Detailed Findings Breakdowns\n\n" + "\n\n".join(sections) + "\n"
    )
