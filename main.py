"""FastAPI orchestration for AuthLeak scans and local session harvesting."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scanner import autonomous_crawl_and_scan, harvest_session, session_status, validate_url

app = FastAPI(title="AuthLeak", version="0.3.0")
INDEX_FILE = Path(__file__).with_name("index.html")
jobs: dict[str, dict[str, Any]] = {}
harvest_jobs: dict[str, dict[str, Any]] = {}
subscribers: set[WebSocket] = set()


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


@app.get("/", response_class=FileResponse)
async def dashboard() -> FileResponse:
    return FileResponse(INDEX_FILE)


async def publish(channel: str, message: str) -> None:
    stale: list[WebSocket] = []
    for socket in subscribers:
        try:
            await socket.send_json({"type": "log", "job_id": channel, "message": message})
        except Exception:
            stale.append(socket)
    for socket in stale:
        subscribers.discard(socket)


async def execute_scan(job_id: str, config: dict[str, Any]) -> None:
    try:
        findings = await autonomous_crawl_and_scan(config, lambda message: publish(job_id, message))
        jobs[job_id].update(status="complete", findings=findings)
        await publish(job_id, "[complete] scan results are ready.")
    except Exception as error:
        jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] scan aborted: {error}")


async def execute_harvest(job_id: str, config: HarvestConfig) -> None:
    try:
        path = await harvest_session(config.target_url, config.session_type, lambda message: publish(job_id, message))
        harvest_jobs[job_id].update(status="stored", path=str(path))
        await publish(job_id, f"[harvest] profile stored at {path}")
    except Exception as error:
        harvest_jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] session harvest aborted: {error}")


@app.post("/api/scans", status_code=202)
async def start_scan(config: ScanConfig) -> dict[str, str]:
    try:
        validate_url(config.target_url)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running", "findings": []}
    asyncio.create_task(execute_scan(job_id, config.model_dump()))
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
    harvest_jobs[job_id] = {"status": "waiting_for_login", "session_type": config.session_type}
    asyncio.create_task(execute_harvest(job_id, config))
    return {"job_id": job_id, "status": "waiting_for_login"}


@app.get("/api/harvest/{job_id}")
async def harvest_status(job_id: str) -> dict[str, Any]:
    if job_id not in harvest_jobs:
        raise HTTPException(status_code=404, detail="Unknown harvest job")
    return harvest_jobs[job_id]


@app.get("/api/sessions/status")
async def stored_sessions():
    from pathlib import Path
    sessions_dir = Path(__file__).parent / "sessions"
    return {
        "victim": (sessions_dir / "session_victim.json").exists(),
        "attacker": (sessions_dir / "session_attacker.json").exists()
        }


@app.websocket("/ws/logs")
async def scan_logs(websocket: WebSocket) -> None:
    await websocket.accept()
    subscribers.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        subscribers.discard(websocket)
