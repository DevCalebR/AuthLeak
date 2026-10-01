"""Browser-driven scanning and local session-profile handling for AuthLeak."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlparse

import httpx
from playwright.async_api import BrowserContext, Page, Request, async_playwright

LogCallback = Callable[[str], Awaitable[None]]
SessionType = Literal["victim", "attacker"]
SESSIONS_DIR = Path(__file__).with_name("sessions")
API_PATH_MARKER = re.compile(r"/(?:api|v1|v2)(?:/|$)|/\d+/?$", re.IGNORECASE)
AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Generic Bearer Token": r"bearer\s*[a-zA-Z0-9_\-\.]{20,}",
}


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


def validate_url(value: str, field: str = "Target URL") -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL.")
    return value


def target_folder(target_url: str) -> Path:
    """Return the target-specific profile directory without allowing path traversal."""
    domain = urlparse(validate_url(target_url)).hostname or "unknown_target"
    safe_domain = re.sub(r"[^A-Za-z0-9]+", "_", domain).strip("_").lower()
    return SESSIONS_DIR / (safe_domain or "unknown_target")


def session_path(target_url: str, session_type: SessionType) -> Path:
    if session_type not in {"victim", "attacker"}:
        raise ValueError("session_type must be 'victim' or 'attacker'.")
    return target_folder(target_url) / f"session_{session_type}.json"


def session_status(target_url: str) -> dict[str, bool | str]:
    folder = target_folder(target_url)
    return {
        "target_folder": f"sessions/{folder.name}",
        "victim_stored": _load_session_headers(target_url, "victim") is not None,
        "attacker_stored": _load_session_headers(target_url, "attacker") is not None,
    }


def _auth_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if name.lower() in AUTH_HEADER_NAMES and value.strip()}


def _save_session(target_url: str, session_type: SessionType, headers: dict[str, str], request_url: str) -> Path:
    destination = session_path(target_url, session_type)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target_url": target_url,
        "captured_from": request_url,
        "captured_at": datetime.now(UTC).isoformat(),
        "headers": headers,
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination


async def harvest_session(target_url: str, session_type: SessionType, log: LogCallback) -> Path:
    """Open an operator-visible login browser and persist the first auth-bearing request."""
    validate_url(target_url, "Login URL")
    profile_path = session_path(target_url, session_type)
    captured: asyncio.Future[tuple[dict[str, str], str]] = asyncio.get_running_loop().create_future()

    def intercept(request: Request) -> None:
        if captured.done():
            return
        headers = _auth_headers(dict(request.headers))
        if headers:
            captured.set_result((headers, request.url))

    def inspect_response(response: Any) -> None:
        """Also inspect the response's originating request for auth-bearing headers."""
        intercept(response.request)

    await log(f"[harvest] opening headed Chromium for {session_type} login at {target_url}")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()
        page.on("request", intercept)
        page.on("response", inspect_response)
        try:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30_000)
            headers, request_url = await captured
            saved_path = _save_session(target_url, session_type, headers, request_url)
            await log(f"[harvest] {session_type} profile stored at {saved_path}")
            # The request callback resolves `captured` immediately; close on the next await.
            await page.close()
            await browser.close()
            return saved_path
        finally:
            if not page.is_closed():
                await page.close()
            if browser.is_connected():
                await browser.close()


def _load_session_headers(target_url: str, session_type: SessionType) -> dict[str, str] | None:
    path = session_path(target_url, session_type)
    if not path.is_file():
        return None
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
        headers = profile.get("headers", {})
        authenticated_headers = _auth_headers(headers) if isinstance(headers, dict) else {}
        return authenticated_headers or None
    except (OSError, json.JSONDecodeError):
        return None


def _is_api_endpoint(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(API_PATH_MARKER.search(parsed.path))


async def crawl_target(target_url: str, log: LogCallback) -> tuple[list[str], list[str]]:
    """Use a headless browser to map scripts and API-shaped outgoing requests."""
    endpoints: set[str] = set()

    def inspect_request(request: Request) -> None:
        if _is_api_endpoint(request.url):
            endpoints.add(request.url)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context: BrowserContext = await browser.new_context()
        page: Page = await context.new_page()
        page.on("request", inspect_request)
        try:
            await page.goto(target_url, wait_until="networkidle", timeout=30_000)
            scripts = await page.locator("script[src]").evaluate_all("items => items.map(item => item.src)")
            await log(f"[crawl] mapped {len(endpoints)} API endpoint(s) and {len(scripts)} script(s)")
            return list(dict.fromkeys(scripts)), sorted(endpoints)
        finally:
            await context.close()
            await browser.close()


async def analyze_javascript(script_urls: list[str], client: httpx.AsyncClient, log: LogCallback) -> list[Finding]:
    async def fetch(url: str) -> tuple[str, str]:
        try:
            response = await client.get(url)
            response.raise_for_status()
            return url, response.text
        except httpx.HTTPError as error:
            await log(f"[warn] unable to download {url}: {error}")
            return url, ""

    findings: list[Finding] = []
    for source, content in await asyncio.gather(*(fetch(url) for url in script_urls)):
        for kind, pattern in SECRET_PATTERNS.items():
            for evidence in dict.fromkeys(re.findall(pattern, content, re.IGNORECASE)):
                findings.append(Finding(
                    title=f"Exposed {kind}", severity="high", cvss=7.5,
                    description="A credential-shaped value was found in a browser-discovered JavaScript asset.",
                    evidence=evidence, source=source,
                    curl=f"curl -s {shlex.quote(source)} | grep -i {shlex.quote(evidence)}",
                    python=f"import requests\n\nasset = requests.get({source!r}, timeout=15).text\nprint({evidence!r} in asset)\n",
                    remediation="Rotate the credential, remove it from browser assets, and enforce secret scanning in the build pipeline.",
                ))
    return findings


async def token_swap_fuzz(endpoint: str, payload: Any, attacker_headers: dict[str, str], victim_criteria: str, client: httpx.AsyncClient, log: LogCallback) -> Finding | None:
    if not attacker_headers or not victim_criteria:
        return None
    try:
        response = await client.post(endpoint, headers=attacker_headers, json=payload)
    except httpx.HTTPError as error:
        await log(f"[warn] TokenSwap request failed for {endpoint}: {error}")
        return None
    if response.status_code == 200 and victim_criteria.lower() in response.text.lower():
        curl_headers = " ".join(
            f"-H {shlex.quote(f'{name}: {value}')}" for name, value in attacker_headers.items()
        )
        return Finding(
            title="Potential IDOR / Token Swap", severity="critical", cvss=9.1,
            description="The attacker session received victim-identifying content for a victim-shaped request.",
            evidence=f"HTTP 200; matched criteria: {victim_criteria}", source=endpoint,
            curl=(f"curl -i -X POST {shlex.quote(endpoint)} {curl_headers} "
                  f"-H 'Content-Type: application/json' --data {shlex.quote(json.dumps(payload))}"),
            python=f"import requests\n\nresponse = requests.post({endpoint!r}, headers={attacker_headers!r}, json={payload!r}, timeout=15)\nprint(response.status_code, response.text)\n",
            remediation="Authorize each object on the server against the authenticated principal and return 403 for cross-user access.",
        )
    return None


async def autonomous_crawl_and_scan(config: dict[str, Any], log: LogCallback) -> list[dict[str, Any]]:
    """Crawl a target and prefer pre-harvested local session profiles for TokenSwap."""
    target_url = validate_url(str(config.get("target_url", "")))
    victim_headers = _load_session_headers(target_url, "victim")
    attacker_headers = _load_session_headers(target_url, "attacker")
    if victim_headers and attacker_headers:
        await log("[sessions] using pre-harvested victim and attacker profiles for TokenSwap.")
    else:
        manual_attacker = str(config.get("attacker_token", "")).strip()
        attacker_headers = {"Authorization": manual_attacker} if manual_attacker else None
        victim_headers = {"Authorization": str(config.get("victim_token", "")).strip()} if config.get("victim_token") else None
        await log("[sessions] using manually supplied token values; no complete stored profile pair found.")

    scripts, mapped_endpoints = await crawl_target(target_url, log)
    configured_endpoint = str(config.get("api_endpoint", "")).strip()
    endpoints = list(dict.fromkeys(([configured_endpoint] if configured_endpoint else []) + mapped_endpoints))
    timeout = httpx.Timeout(15.0, connect=8.0)
    findings: list[Finding] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        findings.extend(await analyze_javascript(scripts, client, log))
        if endpoints and victim_headers and attacker_headers:
            try:
                payload = json.loads(str(config.get("payload", "{}")))
            except json.JSONDecodeError as error:
                await log(f"[error] invalid TokenSwap JSON payload: {error}")
            else:
                checks = [token_swap_fuzz(endpoint, payload, attacker_headers, str(config.get("victim_criteria", "")), client, log) for endpoint in endpoints]
                findings.extend(item for item in await asyncio.gather(*checks) if item)
    await log(f"[complete] scan finished with {len(findings)} finding(s)")
    return [finding.to_dict() for finding in findings]


run_scan = autonomous_crawl_and_scan
