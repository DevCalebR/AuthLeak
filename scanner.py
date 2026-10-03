"""Browser-driven scanning, session harvesting, and sequential orchestration for AuthLeak.

The scanner is intentionally single-target-at-a-time at the batch layer.  Every
asset gets its own Playwright lifecycle and HTTP clients are context-managed so
browser and socket resources are released before the next asset is processed.

Session profiles are stored under a tenant directory, e.g.:
    sessions/nextcloud/session_victim.json
    sessions/example.com/session_attacker.json

Legacy root-level session files are read as a compatibility fallback, but all
new session writes go to tenant directories.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
import re
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.async_api import Request, Response, async_playwright

LogCallback = Callable[[str], Awaitable[None]]
ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]
SessionType = Literal["victim", "attacker"]

ROOT_DIR = Path(__file__).resolve().parent
SESSIONS_DIR = ROOT_DIR / "sessions"
REPORTS_DIR = ROOT_DIR / "reports"

AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# One second between assets is deliberately conservative for a local queue.
# It is a rate-safety measure, not a WAF-evasion mechanism.
INTER_ASSET_DELAY_SECONDS = float(os.getenv("AUTHLEAK_INTER_ASSET_DELAY", "1.0"))
PAGE_TIMEOUT_MS = int(os.getenv("AUTHLEAK_PAGE_TIMEOUT_MS", "20000"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("AUTHLEAK_HTTP_TIMEOUT", "10"))

findings_db: list[dict[str, Any]] = []
session_status: dict[str, str] = {}

_scan_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "authleak_scan_context",
    default={},
)


def validate_url(url: str, label: str = "URL") -> None:
    """Validate that a target is an absolute HTTP(S) URL with a hostname."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"Invalid {label}: value is required")

    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ValueError(f"Invalid {label}: must be an absolute http:// or https:// URL")


def _sanitize_tenant(value: str) -> str:
    """Convert a program slug or hostname into a safe filesystem directory name."""
    cleaned = value.strip().lower()
    cleaned = re.sub(r"[^a-z0-9._-]+", "_", cleaned)
    cleaned = cleaned.strip("._-")
    if not cleaned:
        raise ValueError("Unable to derive a safe session tenant name")
    return cleaned[:120]


def tenant_from_url(url: str) -> str:
    """Derive a filesystem tenant from a target URL's hostname."""
    validate_url(url)
    hostname = urlparse(url).hostname
    if not hostname:
        raise ValueError("Target URL does not contain a hostname")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return _sanitize_tenant(hostname)


def session_tenant_dir(tenant: str) -> Path:
    """Return and create the tenant session directory."""
    safe_tenant = _sanitize_tenant(tenant)
    directory = SESSIONS_DIR / safe_tenant
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SESSIONS_DIR, 0o700)
        os.chmod(directory, 0o700)
    except OSError:
        pass
    return directory


def _candidate_tenants(
    target_url: str | None = None,
    preferred_tenant: str | None = None,
) -> list[str]:
    """Build an ordered list of tenant names for dynamic session lookup."""
    candidates: list[str] = []
    if preferred_tenant:
        candidates.append(_sanitize_tenant(preferred_tenant))
    if target_url:
        try:
            candidates.append(tenant_from_url(target_url))
        except ValueError:
            pass

    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def _legacy_session_file(session_type: SessionType) -> Path:
    return SESSIONS_DIR / f"session_{session_type.lower()}.json"


def _session_file(
    session_type: SessionType,
    *,
    target_url: str | None = None,
    tenant: str | None = None,
) -> Path | None:
    """Resolve a session profile in tenant directories, then legacy root fallback."""
    for candidate in _candidate_tenants(target_url, tenant):
        path = session_tenant_dir(candidate) / f"session_{session_type.lower()}.json"
        if path.exists():
            return path

    legacy = _legacy_session_file(session_type)
    if legacy.exists():
        return legacy
    return None


def session_is_stored(
    session_type: SessionType,
    *,
    target_url: str | None = None,
    tenant: str | None = None,
) -> bool:
    return _session_file(session_type, target_url=target_url, tenant=tenant) is not None


def _read_session_profile(
    session_type: SessionType,
    *,
    target_url: str | None = None,
    tenant: str | None = None,
) -> dict[str, Any]:
    path = _session_file(session_type, target_url=target_url, tenant=tenant)
    if not path:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Filter an HTTP header mapping down to known credential-bearing headers."""
    return {k: v for k, v in headers.items() if k.lower() in AUTH_HEADER_NAMES}


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write a private JSON file with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def bind_scan_context(
    tenant: str | None,
    log_cb: LogCallback | None,
    progress_cb: ProgressCallback | None = None,
) -> contextvars.Token:
    """Bind tenant/log/progress callbacks for the exact sequential batch scope."""
    return _scan_context.set(
        {
            "tenant": _sanitize_tenant(tenant) if tenant else None,
            "log_cb": log_cb,
            "progress_cb": progress_cb,
        }
    )


def reset_scan_context(token: contextvars.Token) -> None:
    _scan_context.reset(token)


async def _emit(log_cb: LogCallback | None, message: str) -> None:
    if not log_cb:
        return
    try:
        await log_cb(message)
    except Exception:
        # Logging must never terminate a scan.
        pass


async def _progress(update: dict[str, Any]) -> None:
    callback = _scan_context.get().get("progress_cb")
    if not callback:
        return
    try:
        await callback(update)
    except Exception:
        pass


async def harvest_session(
    login_url: str,
    session_type: SessionType,
    log_cb: LogCallback,
    tenant: str | None = None,
) -> dict[str, Any]:
    """Open a headed browser, observe authentication, then save a tenant profile."""
    validate_url(login_url, "Login URL")
    resolved_tenant = _sanitize_tenant(tenant) if tenant else tenant_from_url(login_url)
    output_dir = session_tenant_dir(resolved_tenant)

    session_id = f"{resolved_tenant}_{session_type}_{int(asyncio.get_running_loop().time())}"
    session_status[session_id] = "harvesting"

    await _emit(
        log_cb,
        f"[+] Launching headed session harvester for {session_type.upper()} at {login_url}",
    )
    await _emit(log_cb, f"[session] Tenant vault: sessions/{resolved_tenant}/")

    auth_captured = asyncio.Event()
    captured_data: dict[str, Any] = {
        "headers": {},
        "cookies": [],
        "tenant": resolved_tenant,
        "target_url": login_url,
        "captured_at": "",
    }

    async def handle_request(request: Request) -> None:
        if auth_captured.is_set():
            return
        try:
            headers = await request.all_headers()
            interesting = _auth_headers(headers)
            # A pre-existing cookie can be present before authentication.  Do not
            # terminate the harvester solely on an outbound Cookie header.
            decisive = {
                k: v
                for k, v in interesting.items()
                if k.lower() != "cookie"
            }
            if decisive:
                captured_data["headers"].update(decisive)
                await _emit(log_cb, "[!] Intercepted outbound authentication header")
                auth_captured.set()
        except Exception:
            pass

    async def handle_response(response: Response) -> None:
        if auth_captured.is_set():
            return
        try:
            headers = await response.all_headers()
            if "set-cookie" not in headers:
                return

            await _emit(log_cb, "[!] Observed authentication-bearing Set-Cookie response")
            cookies = await response.frame.page.context.cookies([response.url])
            if not cookies:
                return

            captured_data["cookies"] = cookies
            cookie_string = "; ".join(
                f"{cookie['name']}={cookie['value']}" for cookie in cookies
            )
            captured_data["headers"]["cookie"] = cookie_string
            auth_captured.set()
        except Exception:
            pass

    browser = None
    context = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=False)
            context = await browser.new_context()
            page = await context.new_page()
            page.on("request", handle_request)
            page.on("response", handle_response)

            await page.goto(login_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            try:
                await asyncio.wait_for(auth_captured.wait(), timeout=300.0)
            except asyncio.TimeoutError:
                session_status[session_id] = "failed"
                await _emit(log_cb, "[-] Session harvest timed out after 5 minutes")
                return {}

            captured_data["captured_at"] = datetime.now(timezone.utc).isoformat()
            output_file = output_dir / f"session_{session_type.lower()}.json"
            _write_private_json(output_file, captured_data)
            session_status[session_id] = "completed"
            await _emit(
                log_cb,
                f"[+] Saved session profile to sessions/{resolved_tenant}/{output_file.name}",
            )
            return captured_data
    except Exception as error:
        session_status[session_id] = "failed"
        await _emit(log_cb, f"[error] Session harvester failed: {error}")
        return {}
    finally:
        # Explicitly close context/browser even though async_playwright also cleans
        # up on exit.  This makes lifecycle intent clear and prevents leaked pages.
        try:
            if context:
                await context.close()
        except Exception:
            pass
        try:
            if browser:
                await browser.close()
        except Exception:
            pass


def _make_finding(
    *,
    finding_type: str,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    source: str,
    curl: str,
    python_code: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "source": source,
        "curl": curl,
        "python": python_code,
        "poc_curl": curl,
        "remediation": remediation,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


def _record_finding(finding: dict[str, Any], scan_findings: list[dict[str, Any]]) -> None:
    key = (finding.get("title"), finding.get("source"), finding.get("evidence"))
    if not any(
        (item.get("title"), item.get("source"), item.get("evidence")) == key
        for item in findings_db
    ):
        findings_db.append(finding)
    if not any(
        (item.get("title"), item.get("source"), item.get("evidence")) == key
        for item in scan_findings
    ):
        scan_findings.append(finding)


def _headers_from_profile(profile: dict[str, Any]) -> dict[str, str]:
    headers = profile.get("headers", {})
    if not isinstance(headers, dict):
        return {}
    return _auth_headers({str(k): str(v) for k, v in headers.items()})


def _token_headers(victim_token: str | None, attacker_token: str | None) -> tuple[dict[str, str], dict[str, str]]:
    victim = {"Authorization": victim_token} if victim_token else {}
    attacker = {"Authorization": attacker_token} if attacker_token else {}
    return victim, attacker


def _safe_curl_headers(headers: dict[str, str]) -> str:
    """Render credential headers without leaking live session values into findings."""
    lines: list[str] = []
    for name in sorted(headers):
        lines.append(f"-H '{name}: <SESSION_REDACTED>'")
    return " ".join(lines)


def _merge_headers(base: dict[str, str], overlay: dict[str, str]) -> dict[str, str]:
    merged = dict(base)
    for key, value in overlay.items():
        # Preserve whichever casing was supplied by the overlay while removing
        # a duplicate case-insensitive key from the base mapping.
        for existing in list(merged):
            if existing.lower() == key.lower():
                merged.pop(existing, None)
        merged[key] = value
    return merged


async def autonomous_crawl_and_scan(
    target_url: Any,
    response_criteria: str = "",
    victim_token: str | None = None,
    attacker_token: str | None = None,
    tenant: str | None = None,
    log_cb: LogCallback | None = None,
) -> list[dict[str, Any]]:
    """Run reconnaissance, Engine A, and safe authorization checks for one target."""
    config: dict[str, Any] = target_url if isinstance(target_url, dict) else {}
    url_str = config.get("target_url") if config else str(target_url)
    response_criteria = (
        config.get("victim_criteria", response_criteria)
        if isinstance(config, dict)
        else response_criteria
    )
    victim_token = config.get("victim_token", victim_token) if config else victim_token
    attacker_token = config.get("attacker_token", attacker_token) if config else attacker_token
    explicit_api = config.get("api_endpoint", "") if config else ""
    active_tenant = tenant or _scan_context.get().get("tenant") or tenant_from_url(url_str)

    validate_url(url_str)
    active_tenant = _sanitize_tenant(active_tenant)
    scan_findings: list[dict[str, Any]] = []

    await _emit(log_cb, f"[start] Scanning {url_str}")
    await _emit(log_cb, f"[vault] Session lookup tenant: sessions/{active_tenant}/")

    discovered_apis: dict[str, str] = {}
    browser = None
    context = None

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            async def handle_request(request: Request) -> None:
                method = request.method.upper()
                if method not in SAFE_METHODS:
                    return
                request_url = request.url
                if (
                    "/api/" in request_url
                    or "/v1/" in request_url
                    or "/v2/" in request_url
                    or re.search(r"/\d+(?=/|$)", urlparse(request_url).path)
                ):
                    discovered_apis.setdefault(request_url, method)
                    await _emit(log_cb, f"[discovered] {method} {request_url}")

            page.on("request", handle_request)

            try:
                await page.goto(url_str, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                content = await page.content()
            except Exception as error:
                content = ""
                await _emit(log_cb, f"[error] Browser navigation failed: {error}")

            # Engine A: client-side JavaScript secret detection.
            soup = BeautifulSoup(content, "html.parser")
            scripts = [
                script.get("src")
                for script in soup.find_all("script")
                if script.get("src")
            ]
            if explicit_api:
                try:
                    validate_url(explicit_api, "API endpoint")
                    discovered_apis.setdefault(explicit_api, "GET")
                except ValueError:
                    await _emit(log_cb, "[warn] Ignoring invalid optional API endpoint")

            await _emit(log_cb, f"[engine-a] Inspecting {len(scripts)} JavaScript assets")

            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
                headers={"User-Agent": "AuthLeak/1.3 (+authorized-security-testing)"},
            ) as client:
                for script_src in scripts:
                    full_script_url = urljoin(url_str, script_src)
                    try:
                        response = await client.get(full_script_url)
                        response.raise_for_status()
                        js_code = response.text
                    except Exception as error:
                        await _emit(log_cb, f"[engine-a] Could not fetch {full_script_url}: {error}")
                        continue

                    secrets = {
                        "AWS Access Key": re.findall(r"AKIA[0-9A-Z]{16}", js_code),
                        "Stripe API Key": re.findall(r"sk_live_[0-9a-zA-Z]{24}", js_code),
                        "Google API Key": re.findall(r"AIza[0-9A-Za-z_-]{35}", js_code),
                    }

                    for secret_name, matches in secrets.items():
                        for match in sorted(set(matches)):
                            finding = _make_finding(
                                finding_type="Exposed Secret / Information Disclosure",
                                title=f"Leaked {secret_name}",
                                severity="High",
                                description=(
                                    f"A client-side JavaScript asset contains a value matching the "
                                    f"{secret_name} pattern. Client bundles are readable by end users "
                                    "and should not contain privileged credentials."
                                ),
                                evidence=f"Pattern match in asset: {full_script_url}; value redacted in report.",
                                source=full_script_url,
                                curl=f"curl -s '{full_script_url}'",
                                python_code=(
                                    "import requests\n\n"
                                    f"r = requests.get({full_script_url!r}, timeout=10)\n"
                                    "print(r.text)"
                                ),
                                remediation=(
                                    "Remove privileged secrets from browser-delivered assets. Rotate the "
                                    "exposed credential, move secret usage server-side, and restrict any "
                                    "remaining public API keys by origin/scope."
                                ),
                            )
                            _record_finding(finding, scan_findings)
                            await _emit(log_cb, f"[finding] {finding['title']} in {full_script_url}")

            # Engine B: TokenSwap / authorization-boundary checks.
            if not response_criteria:
                await _emit(
                    log_cb,
                    "[tokenswap] Skipped: no response criteria configured. "
                    "Set AUTHLEAK_RESPONSE_CRITERIA for automated batch checks.",
                )
            elif not discovered_apis:
                await _emit(log_cb, "[tokenswap] No safe GET/HEAD/OPTIONS API routes discovered")
            else:
                victim_profile = _read_session_profile(
                    "victim",
                    target_url=url_str,
                    tenant=active_tenant,
                )
                attacker_profile = _read_session_profile(
                    "attacker",
                    target_url=url_str,
                    tenant=active_tenant,
                )
                victim_profile_headers = _headers_from_profile(victim_profile)
                attacker_profile_headers = _headers_from_profile(attacker_profile)
                explicit_victim_headers, explicit_attacker_headers = _token_headers(
                    victim_token,
                    attacker_token,
                )
                victim_headers = _merge_headers(victim_profile_headers, explicit_victim_headers)
                attacker_headers = _merge_headers(attacker_profile_headers, explicit_attacker_headers)

                if not attacker_headers:
                    await _emit(log_cb, "[tokenswap] No attacker session profile/token found; skipping")
                else:
                    await _emit(
                        log_cb,
                        f"[tokenswap] Testing {len(discovered_apis)} safe API routes with tenant session profiles",
                    )
                    async with httpx.AsyncClient(
                        timeout=HTTP_TIMEOUT_SECONDS,
                        follow_redirects=False,
                        headers={"User-Agent": "AuthLeak/1.3 (+authorized-security-testing)"},
                    ) as client:
                        for api_url, method in discovered_apis.items():
                            if method not in SAFE_METHODS:
                                continue
                            await _emit(log_cb, f"[tokenswap] Checking {api_url}")
                            try:
                                victim_response = None
                                if victim_headers:
                                    victim_response = await client.request(
                                        method,
                                        api_url,
                                        headers=victim_headers,
                                    )

                                attacker_response = await client.request(
                                    method,
                                    api_url,
                                    headers=attacker_headers,
                                )

                                victim_match = bool(
                                    victim_response
                                    and response_criteria in victim_response.text
                                    and victim_response.status_code < 400
                                )
                                attacker_match = (
                                    attacker_response.status_code < 400
                                    and response_criteria in attacker_response.text
                                )

                                if attacker_match and (
                                    victim_match or not victim_headers
                                ):
                                    confidence = (
                                        "Observed matching protected content with both victim and attacker "
                                        "sessions."
                                        if victim_match
                                        else "Attacker session received matching protected content without "
                                        "a local victim baseline."
                                    )
                                    evidence = (
                                        f"{confidence} HTTP {attacker_response.status_code}; "
                                        f"matched response criteria '{response_criteria}'."
                                    )
                                    finding = _make_finding(
                                        finding_type="Broken Object Level Authorization (IDOR)",
                                        title="Potential IDOR / Authorization Boundary Bypass",
                                        severity="Critical",
                                        description=(
                                            "A second authenticated session received protected response content "
                                            "matching the configured victim-response criteria from an API route. "
                                            "Manual verification is recommended before submission."
                                        ),
                                        evidence=evidence,
                                        source=api_url,
                                        curl=(
                                            f"curl -i -X {method} '{api_url}' "
                                            f"{_safe_curl_headers(attacker_headers)}"
                                        ),
                                        python_code=(
                                            "import requests\n\n"
                                            f"url = {api_url!r}\n"
                                            f"r = requests.{method.lower()}(url, headers={{" 
                                            "'Authorization': '<SESSION_REDACTED>'" 
                                            "}, timeout=10)\n"
                                            "print(r.status_code)\nprint(r.text)"
                                        ),
                                        remediation=(
                                            "Enforce object-level authorization on every resource access. "
                                            "Derive the allowed principal from the authenticated session and "
                                            "verify ownership/permission before returning protected records."
                                        ),
                                    )
                                    _record_finding(finding, scan_findings)
                                    await _emit(log_cb, f"[finding] {finding['title']} at {api_url}")
                            except Exception as error:
                                await _emit(log_cb, f"[tokenswap] Request failed for {api_url}: {error}")

            await _emit(
                log_cb,
                f"[complete] Target finished: {len(scan_findings)} findings in this asset",
            )
            return scan_findings
    finally:
        try:
            if context:
                await context.close()
        except Exception:
            pass
        try:
            if browser:
                await browser.close()
        except Exception:
            pass


async def sequential_batch_scan(
    scope_list: list[str],
    response_criteria: str,
) -> list[dict[str, Any]]:
    """Consume exactly one scope at a time and fully finish each target before advancing."""
    context = _scan_context.get()
    tenant = context.get("tenant")
    log_cb = context.get("log_cb")

    queue = deque(scope_list)
    total = len(queue)
    completed = 0
    failed = 0
    batch_findings: list[dict[str, Any]] = []

    await _emit(log_cb, f"[queue] Sequential batch initialized with {total} URL assets")
    await _progress(
        {
            "total": total,
            "completed": 0,
            "failed": 0,
            "current": None,
            "findings": 0,
            "status": "scanning",
        }
    )

    while queue:
        # Exactly one URL is removed from the queue before the scan begins.
        current_url = queue.popleft()
        current_index = completed + failed + 1
        target_tenant = tenant or tenant_from_url(current_url)

        await _emit(
            log_cb,
            f"[queue] Asset {current_index}/{total}: {current_url} (tenant={target_tenant})",
        )
        await _progress(
            {
                "total": total,
                "completed": completed,
                "failed": failed,
                "current": current_url,
                "findings": len(batch_findings),
                "status": "scanning",
            }
        )

        try:
            findings = await autonomous_crawl_and_scan(
                current_url,
                response_criteria=response_criteria,
                tenant=target_tenant,
                log_cb=log_cb,
            )
            batch_findings.extend(findings)
            completed += 1
            await _emit(log_cb, f"[queue] Finished asset {current_index}/{total}")
        except Exception as error:
            failed += 1
            await _emit(log_cb, f"[queue] Asset failed: {current_url} :: {error}")

        await _progress(
            {
                "total": total,
                "completed": completed,
                "failed": failed,
                "current": None,
                "findings": len(batch_findings),
                "status": "scanning" if queue else "finishing",
            }
        )

        if queue and INTER_ASSET_DELAY_SECONDS > 0:
            await asyncio.sleep(INTER_ASSET_DELAY_SECONDS)

    await _emit(
        log_cb,
        f"[queue] Sequential batch complete: {completed} succeeded, {failed} failed, "
        f"{len(batch_findings)} findings",
    )
    await _progress(
        {
            "total": total,
            "completed": completed,
            "failed": failed,
            "current": None,
            "findings": len(batch_findings),
            "status": "complete",
        }
    )
    return batch_findings


def write_markdown_report(findings: list[dict[str, Any]], target_label: str, report_prefix: str = "scan") -> Path:
    """Persist a triage-friendly Markdown report without writing session secrets."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = _sanitize_tenant(target_label)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = REPORTS_DIR / f"{report_prefix}_{safe_label}_{timestamp}.md"

    lines = [
        f"# AuthLeak Security Scan Report — {target_label}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Findings: {len(findings)}",
        "",
    ]

    if not findings:
        lines.extend(["No findings were confirmed by the automated checks.", ""])
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"## {index}. {finding.get('title', 'Untitled Finding')}",
                    "",
                    f"**Severity:** {finding.get('severity', 'Unknown')}",
                    f"**Type:** {finding.get('type', 'Unknown')}",
                    f"**Source:** {finding.get('source', 'N/A')}",
                    "",
                    finding.get("description", ""),
                    "",
                    "### Evidence",
                    "",
                    finding.get("evidence", ""),
                    "",
                    "### cURL",
                    "",
                    "```bash",
                    finding.get("curl", ""),
                    "```",
                    "",
                    "### Python",
                    "",
                    "```python",
                    finding.get("python", ""),
                    "```",
                    "",
                    "### Remediation",
                    "",
                    finding.get("remediation", ""),
                    "",
                ]
            )

    _write_private_json(report_path.with_suffix(".json"), {"target": target_label, "findings": findings})
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
