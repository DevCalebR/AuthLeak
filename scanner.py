"""Asynchronous scanning primitives used by the AuthLeak local dashboard."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

LogCallback = Callable[[str], Awaitable[None]]

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


def _validated_url(value: str, field: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL.")
    return value


def _curl(url: str, headers: dict[str, str], payload: Any | None = None) -> str:
    parts = ["curl -i -X POST", shlex.quote(url)]
    for name, value in headers.items():
        parts.extend(["-H", shlex.quote(f"{name}: {value}")])
    if payload is not None:
        parts.extend(["-H", "'Content-Type: application/json'", "--data", shlex.quote(json.dumps(payload))])
    return " ".join(parts)


def _python_poc(url: str, headers: dict[str, str], payload: Any | None = None) -> str:
    return (
        "import requests\n\n"
        f"url = {url!r}\nheaders = {headers!r}\n"
        f"payload = {payload!r}\n"
        "response = requests.post(url, headers=headers, json=payload, timeout=15)\n"
        "print(response.status_code)\nprint(response.text)\n"
    )


def _secret_remediation(kind: str) -> str:
    return (
        f"### Secure fix for exposed {kind}\n"
        "1. Revoke and rotate the exposed credential immediately.\n"
        "2. Move secret values to server-side environment variables or a secret manager.\n"
        "3. Do not ship privileged credentials in JavaScript bundles; enforce CI secret scanning."
    )


async def extract_script_urls(target_url: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch a page and return unique absolute JavaScript asset URLs."""
    response = await client.get(target_url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    return list(dict.fromkeys(urljoin(str(response.url), node["src"]) for node in soup.select("script[src]") if node.get("src")))


async def analyze_javascript(script_urls: list[str], client: httpx.AsyncClient, log: LogCallback) -> list[Finding]:
    """Download script assets concurrently and scan them for credential-shaped strings."""
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
            for match in dict.fromkeys(re.findall(pattern, content, re.IGNORECASE)):
                evidence = match if isinstance(match, str) else "".join(match)
                findings.append(Finding(title=f"Exposed {kind}", severity="high", cvss=7.5, description="A credential-shaped value was found in a client-side JavaScript asset.", evidence=evidence, source=url, curl=f"curl -s {shlex.quote(url)} | grep -i {shlex.quote(evidence)}", python=("import requests\n\n" f"asset = requests.get({url!r}, timeout=15).text\n" f"print({evidence!r} in asset)\n"), remediation=_secret_remediation(kind)))
                await log(f"[finding] {kind} found in {url}")
    return findings


async def token_swap_fuzz(endpoint: str, payload: Any, victim_token: str, attacker_token: str, victim_criteria: str, client: httpx.AsyncClient, log: LogCallback) -> Finding | None:
    """Send the supplied victim-shaped payload under Token B and evaluate the response."""
    _validated_url(endpoint, "API endpoint")
    if not victim_token or not attacker_token or not victim_criteria:
        await log("[skip] TokenSwap requires both supplied tokens and victim-response criteria.")
        return None
    headers = {"Authorization": attacker_token, "Content-Type": "application/json"}
    await log(f"[tokenswap] testing {endpoint} with the attacker authorization header")
    try:
        response = await client.post(endpoint, headers=headers, json=payload)
    except httpx.HTTPError as error:
        await log(f"[warn] TokenSwap request failed: {error}")
        return None
    if response.status_code == 200 and victim_criteria.lower() in response.text.lower():
        await log("[finding] TokenSwap response contained the configured victim criteria.")
        return Finding(title="Potential IDOR / Token Swap", severity="critical", cvss=9.1, description="The API returned victim-identifying content when called using Token B with victim-shaped data.", evidence=f"HTTP 200; matched criteria: {victim_criteria}", source=endpoint, curl=_curl(endpoint, headers, payload), python=_python_poc(endpoint, headers, payload), remediation=("### Secure fix for broken object-level authorization\nAuthorize every requested object on the server using the authenticated principal, not a client-supplied ID.\nReturn `403 Forbidden` when the object belongs to another user and add authorization regression tests."))
    await log(f"[tokenswap] no confirmation (HTTP {response.status_code}; victim criteria not matched).")
    return None


async def run_scan(config: dict[str, Any], log: LogCallback) -> list[dict[str, Any]]:
    """Run enabled engines and return serializable findings."""
    target_url = _validated_url(str(config.get("target_url", "")), "Target URL")
    findings: list[Finding] = []
    timeout = httpx.Timeout(15.0, connect=8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": "AuthLeak/0.1 local scanner"}) as client:
        await log(f"[start] extracting JavaScript assets from {target_url}")
        try:
            scripts = await extract_script_urls(target_url, client)
            await log(f"[asset] discovered {len(scripts)} script URL(s)")
            findings.extend(await analyze_javascript(scripts, client, log))
        except httpx.HTTPError as error:
            await log(f"[error] asset extraction failed: {error}")
        endpoint = str(config.get("api_endpoint", "")).strip()
        if endpoint:
            try:
                payload = json.loads(str(config.get("payload", "{}")))
                finding = await token_swap_fuzz(endpoint, payload, str(config.get("victim_token", "")), str(config.get("attacker_token", "")), str(config.get("victim_criteria", "")), client, log)
                if finding:
                    findings.append(finding)
            except (ValueError, json.JSONDecodeError) as error:
                await log(f"[error] TokenSwap skipped: {error}")
    await log(f"[complete] scan finished with {len(findings)} finding(s)")
    return [finding.to_dict() for finding in findings]
