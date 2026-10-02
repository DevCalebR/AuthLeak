"""Browser-driven scanning and local session-profile handling for AuthLeak."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal
from playwright.async_api import async_playwright, Request, Response
from bs4 import BeautifulSoup
import httpx

LogCallback = Callable[[str], Awaitable[None]]
SessionType = Literal["victim", "attacker"]
SESSIONS_DIR = Path(__file__).parent / "sessions"
AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}

# Shared findings cache and session status tracks
findings_db = []
session_status: dict[str, str] = {}

def validate_url(url: str, label: str = "URL") -> None:
    """Helper validation rule to check web formats."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid {label}: Must begin with http:// or https://")

def _auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Filters dictionary keys down to known security credentials."""
    return {k: v for k, v in headers.items() if k.lower() in AUTH_HEADER_NAMES}

async def harvest_session(
    login_url: str, 
    session_type: SessionType, 
    log_cb: LogCallback
) -> dict[str, Any]:
    """
    Spawns a visible browser window, intercepts authorization headers or 
    incoming 'Set-Cookie' headers during authentication, saves the extracted 
    profile to disk, and snaps the window shut instantly.
    """
    SESSIONS_DIR.mkdir(exist_ok=True)
    session_id = f"{session_type}_{int(asyncio.get_event_loop().time())}"
    session_status[session_id] = "harvesting"
    
    await log_cb(f"[+] Launching active session harvester for {session_type.upper()} at {login_url}...")
    
    auth_captured = asyncio.Event()
    captured_data: dict[str, Any] = {
        "headers": {},
        "cookies": [],
        "captured_at": ""
    }

    async def handle_request(request: Request):
        if auth_captured.is_set():
            return
        try:
            headers = await request.all_headers()
            for name, value in headers.items():
                if name.lower() in AUTH_HEADER_NAMES:
                    captured_data["headers"][name] = value
                    await log_cb(f"[!] Intercepted outbound auth header: {name}")
                    auth_captured.set()
        except Exception:
            pass

    async def handle_response(response: Response):
        if auth_captured.is_set():
            return
        try:
            headers = await response.all_headers()
            if "set-cookie" in headers:
                await log_cb("[!] Intercepted incoming authentication cookie stream ('Set-Cookie')")
                context = response.frame.page.context
                captured_data["cookies"] = await context.cookies([response.url])
                
                if captured_data["cookies"]:
                    cookie_string = "; ".join([f"{c['name']}={c['value']}" for c in captured_data["cookies"]])
                    captured_data["headers"]["cookie"] = cookie_string
                    
                auth_captured.set()
        except Exception:
            pass

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("request", handle_request)
        page.on("response", handle_response)

        try:
            await page.goto(login_url, wait_until="domcontentloaded")
            
            try:
                await asyncio.wait_for(auth_captured.wait(), timeout=300.0)
                await log_cb("[+] Authentication signature extracted successfully. Terminating context.")
            except asyncio.TimeoutError:
                await log_cb("[-] Session harvest timed out after 5 minutes without identifying authorization state.")
                session_status[session_id] = "failed"
                return {}

            captured_data["captured_at"] = datetime.now().isoformat()
            
            # FIXED: Save directly to base sessions directory so main.py status endpoint finds it
            output_file = SESSIONS_DIR / f"session_{session_type.lower()}.json"
            output_file.write_text(json.dumps(captured_data, indent=2))
            await log_cb(f"[+] Saved structured credentials to {output_file.name}")
            
            session_status[session_id] = "completed"
            return captured_data

        finally:
            await context.close()
            await browser.close()

async def autonomous_crawl_and_scan(target_url: Any, response_criteria: str, victim_token: str = None, attacker_token: str = None):
    """Core autonomous scanner engine linking Playwright with fuzzer arrays."""
    # FIXED: Safely extract the target string if a configuration dictionary context block is received
    url_str = target_url.get("target_url") if isinstance(target_url, dict) else str(target_url)
    print(f"[start] Launching headless browser for: {url_str}")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        discovered_apis = set()
        
        async def handle_request(request):
            url = request.url
            if any(x in url for x in ["/api/", "/v1/", "/v2/"]) or re.search(r'/\d+(?=/|$)', url):
                discovered_apis.add(url)
                print(f"[discovered] Found dynamic API route: {url}")

        page.on("request", handle_request)
        
        try:
            await page.goto(url_str, wait_until="networkidle", timeout=15000)
            content = await page.content()
        except Exception as e:
            print(f"[error] Browser navigation failed: {e}")
            content = ""
            
        # ENGINE A: Secrets Scanner
        soup = BeautifulSoup(content, 'html.parser')
        scripts = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        
        async with httpx.AsyncClient() as client:
            for script_src in scripts:
                full_script_url = script_src if script_src.startswith('http') else f"{url_str.rstrip('/')}/{script_src.lstrip('/')}"
                try:
                    res = await client.get(full_script_url, timeout=10)
                    js_code = res.text
                    
                    secrets = {
                        "AWS Access Key": re.findall(r'AKIA[0-9A-Z]{16}', js_code),
                        "Stripe API Key": re.findall(r'sk_live_[0-9a-zA-Z]{24}', js_code),
                        "Google API Key": re.findall(r'AIza[0-9A-Za-z-_]{35}', js_code)
                    }
                    
                    for name, matches in secrets.items():
                        for match in matches:
                            finding = {
                                "type": "Exposed Secret / Information Disclosure",
                                "title": f"Leaked {name}",
                                "severity": "High",
                                "evidence": f"Found inside asset: {full_script_url}",
                                "poc_curl": f"curl -s {full_script_url}",
                                "remediation": "### Secure Fix\nMove keys to environment variables. Never bundle keys into client bundles."
                            }
                            if finding not in findings_db:
                                findings_db.append(finding)
                except Exception:
                    continue

        # ENGINE B: TokenSwap / Automated Fuzzer Engine
        # FIXED: Look directly in base sessions directory matching frontend tracking rules
        local_attacker_headers = {}
        if not attacker_token and (SESSIONS_DIR / "session_attacker.json").exists():
            try:
                prof = json.loads((SESSIONS_DIR / "session_attacker.json").read_text())
                local_attacker_headers = prof.get("headers", {})
            except Exception:
                pass
        else:
            local_attacker_headers = {"Authorization": attacker_token} if attacker_token else {}

        active_headers = local_attacker_headers
        if active_headers:
            for api_url in discovered_apis:
                print(f"[tokenswap] Fuzzing authorization bounds on endpoint: {api_url}")
                try:
                    async with httpx.AsyncClient() as client:
                        headers = {"Content-Type": "application/json"}
                        headers.update(active_headers)
                        response = await client.post(api_url, headers=headers, json={}, timeout=10)
                        
                        if response.status_code == 200 and response_criteria in response.text:
                            finding = {
                                "type": "Broken Object Level Authorization (IDOR)",
                                "title": "Potential IDOR / Token Swap Bypass",
                                "severity": "Critical",
                                "evidence": f"HTTP 200; matched response criteria: '{response_criteria}'\nSource: {api_url}",
                                "poc_curl": f"curl -i -X POST {api_url} -H 'Cookie: {active_headers.get('cookie', '')}'",
                                "remediation": "### Secure Fix\nValidate session principal ownership bounds explicitly on object mutations."
                            }
                            if finding not in findings_db:
                                findings_db.append(finding)
                except Exception as e:
                    print(f"[tokenswap error] Connection failed on endpoint {api_url}: {e}")

        await browser.close()
    return findings_db

