"""FastAPI orchestration for AuthLeak scans, session harvesting, and HackerOne sync."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from program_intelligence import build_recommendations, fetch_scope_exclusions, fetch_structured_scopes

from asset_inventory import AssetInventory
from authorization_compare import compare_authenticated_observations
from authorization_triage import build_authorization_triage
from authorization_verification import build_authorization_verification_artifact
from scope_policy import ScopePolicy

from scanner import (
    AuthenticatedObservation,
    autonomous_crawl_and_scan,
    bind_scan_context,
    harvest_session,
    replay_authenticated_endpoints,
    reset_scan_context,
    sequential_batch_scan,
    session_is_stored,
    tenant_from_url,
    validate_url,
    write_markdown_report,
)

app = FastAPI(title="AuthLeak", version="1.4.2")
INDEX_FILE = Path(__file__).with_name("index.html")

jobs: dict[str, dict[str, Any]] = {}
harvest_jobs: dict[str, dict[str, Any]] = {}
hackerone_jobs: dict[str, dict[str, Any]] = {}
subscribers: set[WebSocket] = set()

# Only one HackerOne batch is permitted at a time. The per-asset scanner is also
# strictly sequential, keeping browser/RAM usage bounded and reducing request bursts.
hackerone_job_lock = asyncio.Lock()
active_hackerone_job_id: str | None = None

# The route intentionally accepts only the three requested H1 fields. Automated
# TokenSwap criteria are read from an environment variable rather than logging or
# storing another credential-like value in the browser request.
H1_RESPONSE_CRITERIA = os.getenv("AUTHLEAK_RESPONSE_CRITERIA", "").strip()
H1_API_BASE = "https://api.hackerone.com/v1/hackers/programs"
H1_PAGE_SIZE = 100


class ScanConfig(BaseModel):
    target_url: str
    api_endpoint: str = ""
    payload: str = "{}"
    victim_token: str = ""
    attacker_token: str = ""
    victim_criteria: str = Field(default="", max_length=300)


class HarvestConfig(BaseModel):
    target_url: str
    session_type: Literal["victim", "attacker"]
    tenant: str = Field(default="", max_length=120)


class HackerOneSyncConfig(BaseModel):
    hackerone_username: str = Field(min_length=1, max_length=200)
    hackerone_api_token: str = Field(min_length=1, max_length=500)
    program_slug: str = Field(min_length=1, max_length=120)


class HackerOneIntelligenceConfig(BaseModel):
    hackerone_username: str = Field(min_length=1, max_length=200)
    hackerone_api_token: str = Field(min_length=1, max_length=500)
    shortlist_size: int = Field(default=12, ge=5, le=12)


class HackerOneScopeDetailConfig(BaseModel):
    hackerone_username: str = Field(min_length=1, max_length=200)
    hackerone_api_token: str = Field(min_length=1, max_length=500)
    program_slug: str = Field(min_length=1, max_length=120)


@app.get("/", response_class=FileResponse)
async def dashboard() -> FileResponse:
    return FileResponse(INDEX_FILE)


def _validate_program_slug(program_slug: str) -> str:
    slug = program_slug.strip().strip("/")
    if not slug or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in slug):
        raise ValueError("Invalid HackerOne program slug")
    return slug


async def publish(channel: str, message: str) -> None:
    """Store and broadcast a log line without ever exposing credentials."""
    store = None
    for collection in (jobs, harvest_jobs, hackerone_jobs):
        if channel in collection:
            store = collection[channel]
            break
    if store is not None:
        store.setdefault("logs", []).append(message)
        store["logs"] = store["logs"][-200:]

    stale: list[WebSocket] = []
    for socket in list(subscribers):
        try:
            await socket.send_json(
                {
                    "type": "log",
                    "job_id": channel,
                    "message": message,
                }
            )
        except Exception:
            stale.append(socket)
    for socket in stale:
        subscribers.discard(socket)


async def execute_scan(job_id: str, config: ScanConfig) -> None:
    try:
        tenant = tenant_from_url(config.target_url)
        await publish(job_id, f"[start] Manual scan target: {config.target_url}")
        inventory = AssetInventory()
        findings = await autonomous_crawl_and_scan(
            config.model_dump(),
            response_criteria=config.victim_criteria,
            victim_token=config.victim_token or None,
            attacker_token=config.attacker_token or None,
            tenant=tenant,
            log_cb=lambda message: publish(job_id, message),
            inventory=inventory,
        )
        report = write_markdown_report(findings, tenant, report_prefix="manual")
        jobs[job_id].update(
            status="complete",
            findings=findings,
            report=str(report),
            inventory=inventory.to_dict(),
        )
        await publish(job_id, f"[complete] Manual scan report: {report.name}")
    except Exception as error:
        jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] Scan aborted: {error}")


async def execute_harvest(job_id: str, config: HarvestConfig) -> None:
    try:
        tenant = config.tenant.strip() or tenant_from_url(config.target_url)
        path_data = await harvest_session(
            config.target_url,
            config.session_type,
            lambda message: publish(job_id, message),
            tenant=tenant,
        )
        if not path_data:
            harvest_jobs[job_id].update(status="error", error="No authentication profile was captured")
            return

        harvest_jobs[job_id].update(
            status="stored",
            tenant=tenant,
            stored=True,
        )
        await publish(job_id, f"[harvest] {config.session_type} session stored in tenant {tenant}")
    except Exception as error:
        harvest_jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] Session harvest aborted: {error}")


async def fetch_hackerone_structured_scopes(
    username: str,
    token: str,
    program_slug: str,
    log_cb,
) -> list[str]:
    """Fetch every structured scope and retain only eligible URL assets."""
    slug = _validate_program_slug(program_slug)
    endpoint = f"{H1_API_BASE}/{quote(slug, safe='')}/structured_scopes"
    imported_urls: list[str] = []
    last_id = 0

    await log_cb(f"[hackerone] Fetching structured scopes for program '{slug}'")
    await log_cb(f"[hackerone] API endpoint: {endpoint}")

    async with httpx.AsyncClient(
        auth=(username, token),
        timeout=20.0,
        follow_redirects=False,
        headers={
            "Accept": "application/json",
            "User-Agent": "AuthLeak/1.3 (+authorized-security-testing)",
        },
    ) as client:
        while True:
            params = {
                "page[size]": H1_PAGE_SIZE,
                "filter[id__gt]": last_id,
            }
            response = await client.get(endpoint, params=params)

            if response.status_code == 401:
                raise RuntimeError("HackerOne authentication failed (HTTP 401)")
            if response.status_code == 403:
                raise RuntimeError("HackerOne denied structured-scope access (HTTP 403)")
            if response.status_code == 404:
                raise RuntimeError(f"HackerOne program '{slug}' was not found (HTTP 404)")
            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "unspecified")
                raise RuntimeError(
                    f"HackerOne rate limit reached (HTTP 429, Retry-After: {retry_after})"
                )
            response.raise_for_status()

            payload = response.json()
            items = payload.get("data", [])
            if not isinstance(items, list):
                raise RuntimeError("Unexpected HackerOne structured-scope response format")

            eligible_in_page = 0
            max_id_seen = last_id
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    item_id = int(item.get("id", 0))
                except (TypeError, ValueError):
                    item_id = last_id
                max_id_seen = max(max_id_seen, item_id)

                attributes = item.get("attributes")
                if not isinstance(attributes, dict):
                    continue
                if attributes.get("asset_type") != "URL":
                    continue
                if attributes.get("eligible_for_submission") is not True:
                    continue

                asset_identifier = attributes.get("asset_identifier")
                if not isinstance(asset_identifier, str) or not asset_identifier.strip():
                    continue
                normalized = asset_identifier.strip()
                parsed_rule_policy = ScopePolicy.from_identifiers([normalized])
                if not parsed_rule_policy.rules:
                    await log_cb(
                        f"[hackerone] Dropped malformed or unsupported URL scope: {asset_identifier!r}"
                    )
                    continue

                if normalized not in imported_urls:
                    imported_urls.append(normalized)
                    eligible_in_page += 1

            await log_cb(
                f"[hackerone] Page imported {eligible_in_page} eligible URL assets; "
                f"cumulative={len(imported_urls)}"
            )

            if not items:
                break
            if len(items) < H1_PAGE_SIZE:
                break
            if max_id_seen <= last_id:
                raise RuntimeError("HackerOne scope pagination did not advance by ID")
            last_id = max_id_seen

    return imported_urls


async def execute_hackerone_sync(
    job_id: str,
    config: HackerOneSyncConfig,
) -> None:
    global active_hackerone_job_id

    try:
        slug = _validate_program_slug(config.program_slug)
        await publish(job_id, f"[sync] Preparing HackerOne program '{slug}'")
        await publish(
            job_id,
            "[sync] HackerOne API credentials are held in memory for this job and are not persisted.",
        )

        async def sync_log(message: str) -> None:
            await publish(job_id, message)

        scopes = await fetch_hackerone_structured_scopes(
            config.hackerone_username,
            config.hackerone_api_token,
            slug,
            sync_log,
        )
        scope_policy = ScopePolicy.from_identifiers(scopes)
        scan_targets = scope_policy.concrete_targets()

        hackerone_jobs[job_id].update(
            status="scanning" if scan_targets else "complete",
            program_slug=slug,
            imported_assets=len(scopes),
            total=len(scan_targets),
            completed=0,
            failed=0,
            current=None,
            scope=scope_policy.describe(),
        )
        await publish(
            job_id,
            f"[sync] Scope ingestion complete: {len(scopes)} eligible URL scope rules imported; "
            f"{len(scan_targets)} concrete scan seeds available",
        )

        if not scan_targets:
            report = write_markdown_report([], slug, report_prefix="hackerone")
            hackerone_jobs[job_id].update(
                status="complete",
                findings=[],
                report=str(report),
                inventory=AssetInventory().to_dict(),
                authenticated_observations=[],
                authenticated_observations_count=0,
                authorization_comparisons=[],
                authorization_comparison_count=0,
                authorization_candidate_count=0,
                authorization_triage=[],
                authorization_triage_count=0,
                authorization_verification_artifacts=[],
                authorization_verification_artifact_count=0,
            )
            await publish(
                job_id,
                "[complete] No concrete scan seed was available. Wildcard/path rules were retained "
                "as authorization policy without inventing targets.",
            )
            return

        response_criteria = H1_RESPONSE_CRITERIA

        async def batch_log(message: str) -> None:
            await publish(job_id, message)

        async def batch_progress(update: dict[str, Any]) -> None:
            hackerone_jobs[job_id].update(
                total=update.get("total", len(scan_targets)),
                completed=update.get("completed", 0),
                failed=update.get("failed", 0),
                current=update.get("current"),
                findings_count=update.get("findings", 0),
                inventory=update.get("inventory", hackerone_jobs[job_id].get("inventory", {})),
                status=update.get("status", "scanning"),
            )

        batch_inventory = AssetInventory()
        context_token = bind_scan_context(slug, batch_log, batch_progress)
        try:
            findings = await sequential_batch_scan(
                scan_targets,
                response_criteria,
                scope_policy=scope_policy,
                inventory=batch_inventory,
            )
        finally:
            reset_scan_context(context_token)

        authenticated_observations: list[dict[str, Any]] = []
        victim_observations: list[AuthenticatedObservation] = []
        attacker_observations: list[AuthenticatedObservation] = []

        for session_type in ("victim", "attacker"):
            if not session_is_stored(
                session_type,
                tenant=slug,
            ):
                await publish(
                    job_id,
                    f"[authenticated] No stored {session_type} session; skipping replay.",
                )
                continue

            observations = await replay_authenticated_endpoints(
                batch_inventory,
                session_type,
                tenant=slug,
                scope_policy=scope_policy,
                log_cb=batch_log,
            )

            authenticated_observations.extend(
                observation.to_dict() for observation in observations
            )

            if session_type == "victim":
                victim_observations.extend(observations)
            else:
                attacker_observations.extend(observations)

        authorization_comparisons = compare_authenticated_observations(
            victim_observations,
            attacker_observations,
        )
        authorization_comparison_records = [
            comparison.to_dict()
            for comparison in authorization_comparisons
        ]

        authorization_triage = [
            build_authorization_triage(comparison)
            for comparison in authorization_comparisons
        ]
        authorization_triage_records = [
            triage.to_dict()
            for triage in authorization_triage
        ]

        authorization_verification_artifacts = [
            build_authorization_verification_artifact(comparison)
            for comparison in authorization_comparisons
        ]
        authorization_verification_artifact_records = [
            artifact.to_dict()
            for artifact in authorization_verification_artifacts
        ]

        authorization_candidate_count = sum(
            1
            for comparison in authorization_comparisons
            if comparison.candidate
        )

        await publish(
            job_id,
            f"[authenticated] Replay complete: "
            f"{len(authenticated_observations)} observations; "
            f"{len(authorization_comparisons)} authorization comparisons; "
            f"{authorization_candidate_count} manual-review candidates; "
            f"{len(authorization_verification_artifacts)} verification artifacts.",
        )
        report = write_markdown_report(findings, slug, report_prefix="hackerone")
        hackerone_jobs[job_id].update(
            status="complete",
            current=None,
            findings=findings,
            findings_count=len(findings),
            report=str(report),
            inventory=batch_inventory.to_dict(),
            authenticated_observations=authenticated_observations,
            authenticated_observations_count=len(authenticated_observations),
            authorization_comparisons=authorization_comparison_records,
            authorization_comparison_count=len(authorization_comparisons),
            authorization_candidate_count=authorization_candidate_count,
            authorization_triage=authorization_triage_records,
            authorization_triage_count=len(authorization_triage),
            authorization_verification_artifacts=authorization_verification_artifact_records,
            authorization_verification_artifact_count=len(
                authorization_verification_artifacts
            ),
            scope=scope_policy.describe(),
        )
        await publish(job_id, f"[complete] HackerOne batch finished; report: {report.name}")
    except Exception as error:
        hackerone_jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] HackerOne sync/scan aborted: {error}")
    finally:
        active_hackerone_job_id = None


@app.post("/api/scans", status_code=202)
async def start_scan(config: ScanConfig) -> dict[str, str]:
    try:
        validate_url(config.target_url)
        if config.api_endpoint:
            validate_url(config.api_endpoint, "API endpoint")
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running", "findings": [], "logs": []}
    asyncio.create_task(execute_scan(job_id, config))
    return {"job_id": job_id, "status": "running"}


@app.get("/api/scans/{job_id}")
async def scan_status(job_id: str) -> dict[str, Any]:
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Unknown scan job")
    return jobs[job_id]


@app.post("/api/harvest", status_code=202)
async def start_harvest(config: HarvestConfig) -> dict[str, str]:
    try:
        validate_url(config.target_url, "Login URL")
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    job_id = str(uuid.uuid4())
    harvest_jobs[job_id] = {
        "status": "waiting_for_login",
        "session_type": config.session_type,
        "tenant": config.tenant.strip() or tenant_from_url(config.target_url),
        "stored": False,
        "logs": [],
    }
    asyncio.create_task(execute_harvest(job_id, config))
    return {"job_id": job_id, "status": "waiting_for_login"}


@app.get("/api/harvest/{job_id}")
async def harvest_status_endpoint(job_id: str) -> dict[str, Any]:
    if job_id not in harvest_jobs:
        raise HTTPException(status_code=404, detail="Unknown harvest job")
    return harvest_jobs[job_id]


@app.get("/api/sessions/status")
async def stored_sessions(target_url: str = "", program_slug: str = "") -> dict[str, Any]:
    if not target_url and not program_slug:
        raise HTTPException(status_code=422, detail="target_url or program_slug is required")

    tenant = program_slug.strip().strip("/") if program_slug else tenant_from_url(target_url)
    return {
        "tenant": tenant,
        "victim_stored": session_is_stored(
            "victim",
            target_url=target_url or None,
            tenant=tenant,
        ),
        "attacker_stored": session_is_stored(
            "attacker",
            target_url=target_url or None,
            tenant=tenant,
        ),
    }


@app.post("/api/hackerone/intelligence")
async def hackerone_intelligence(config: HackerOneIntelligenceConfig) -> dict[str, Any]:
    """Analyze all accessible H1 programs, then enrich only a small shortlist with structured scope data."""
    try:
        async def intelligence_log(message: str) -> None:
            # Keep credential values out of the dashboard log stream.
            print(message)

        result = await build_recommendations(
            config.hackerone_username,
            config.hackerone_api_token,
            shortlist_size=config.shortlist_size,
            log_cb=intelligence_log,
        )
        return result
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"HackerOne request failed: {error}") from error
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/hackerone/scope-detail")
async def hackerone_scope_detail(config: HackerOneScopeDetailConfig) -> dict[str, Any]:
    """Return the complete structured scope for a selected HackerOne program."""
    try:
        slug = _validate_program_slug(config.program_slug)

        async def scope_log(_message: str) -> None:
            return None

        scopes = await fetch_structured_scopes(
            config.hackerone_username,
            config.hackerone_api_token,
            slug,
            scope_log,
        )

        assets: list[dict[str, Any]] = []
        asset_type_counts: dict[str, int] = {}
        submission_assets = 0
        bounty_assets = 0
        url_assets = 0

        for item in scopes:
            if not isinstance(item, dict):
                continue
            attrs = item.get("attributes")
            if not isinstance(attrs, dict):
                continue
            asset_type = str(attrs.get("asset_type") or "unknown")
            identifier = str(attrs.get("asset_identifier") or "")
            submission = attrs.get("eligible_for_submission") is True
            bounty = attrs.get("eligible_for_bounty") is True
            asset_type_counts[asset_type] = asset_type_counts.get(asset_type, 0) + 1
            submission_assets += int(submission)
            bounty_assets += int(bounty)
            url_assets += int(asset_type == "URL")
            assets.append({
                "id": str(item.get("id") or ""),
                "asset_type": asset_type,
                "asset_identifier": identifier,
                "eligible_for_submission": submission,
                "eligible_for_bounty": bounty,
                "max_severity": attrs.get("max_severity"),
                "instruction": str(attrs.get("instruction") or ""),
            })

        exclusions: list[dict[str, Any]] = []
        exclusions_error = None
        try:
            raw_exclusions = await fetch_scope_exclusions(
                config.hackerone_username,
                config.hackerone_api_token,
                slug,
                scope_log,
            )
            for item in raw_exclusions:
                attrs = item.get("attributes") if isinstance(item, dict) else None
                attrs = attrs if isinstance(attrs, dict) else {}
                label = next((str(attrs.get(key)).strip() for key in ("name", "title", "category", "description") if attrs.get(key)), "Scope exclusion")
                exclusions.append({
                    "id": str(item.get("id") or ""),
                    "label": " ".join(label.split())[:240],
                    "instruction": str(attrs.get("instruction") or attrs.get("description") or ""),
                })
        except Exception as error:
            exclusions_error = str(error)

        return {
            "program_slug": slug,
            "summary": {
                "total_assets": len(assets),
                "submission_assets": submission_assets,
                "bounty_assets": bounty_assets,
                "url_assets": url_assets,
                "asset_type_counts": asset_type_counts,
            },
            "assets": assets,
            "scope_exclusions": exclusions,
            "scope_exclusions_error": exclusions_error,
        }
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"HackerOne request failed: {error}") from error
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/hackerone/sync", status_code=202)
async def hackerone_sync(config: HackerOneSyncConfig) -> dict[str, str]:
    global active_hackerone_job_id

    try:
        slug = _validate_program_slug(config.program_slug)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    if active_hackerone_job_id is not None:
        existing = hackerone_jobs.get(active_hackerone_job_id, {})
        raise HTTPException(
            status_code=409,
            detail={
                "message": "A HackerOne batch is already running",
                "job_id": active_hackerone_job_id,
                "status": existing.get("status", "running"),
            },
        )

    # Acquire/release around assignment to make a second request unable to start
    # another H1 batch during the tiny race between request handlers.
    if hackerone_job_lock.locked():
        raise HTTPException(status_code=409, detail="A HackerOne batch is already starting")
    async with hackerone_job_lock:
        if active_hackerone_job_id is not None:
            raise HTTPException(status_code=409, detail="A HackerOne batch is already running")
        job_id = str(uuid.uuid4())
        active_hackerone_job_id = job_id
        hackerone_jobs[job_id] = {
            "status": "syncing",
            "program_slug": slug,
            "imported_assets": 0,
            "total": 0,
            "completed": 0,
            "failed": 0,
            "current": None,
            "findings": [],
            "findings_count": 0,
            "report": None,
            "authenticated_observations": [],
            "authenticated_observations_count": 0,
            "authorization_comparisons": [],
            "authorization_comparison_count": 0,
            "authorization_candidate_count": 0,
            "authorization_triage": [],
            "authorization_triage_count": 0,
            "authorization_verification_artifacts": [],
            "authorization_verification_artifact_count": 0,
            "logs": [],
        }
        asyncio.create_task(execute_hackerone_sync(job_id, config.model_copy(update={"program_slug": slug})))

    return {"job_id": job_id, "status": "syncing"}


@app.get("/api/hackerone/{job_id}")
async def hackerone_status(job_id: str) -> dict[str, Any]:
    if job_id not in hackerone_jobs:
        raise HTTPException(status_code=404, detail="Unknown HackerOne job")
    return hackerone_jobs[job_id]


@app.websocket("/ws/logs")
async def scan_logs(websocket: WebSocket) -> None:
    await websocket.accept()
    subscribers.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        subscribers.discard(websocket)
    except Exception:
        subscribers.discard(websocket)
