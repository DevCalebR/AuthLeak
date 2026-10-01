"""AuthLeak's local FastAPI dashboard and scan orchestration API."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scanner import render_markdown_report, run_scan

app = FastAPI(title="AuthLeak", version="0.1.0")
INDEX_FILE = Path(__file__).with_name("index.html")
REPORTS_DIR = Path(__file__).with_name("reports")
jobs: dict[str, dict[str, Any]] = {}
subscribers: set[WebSocket] = set()
last_findings: list[dict[str, Any]] = []


class ScanConfig(BaseModel):
    target_url: str
    api_endpoint: str = ""
    payload: str = "{}"
    victim_token: str = ""
    attacker_token: str = ""
    victim_criteria: str = Field(default="", max_length=300)


@app.get("/", response_class=FileResponse)
async def dashboard() -> FileResponse:
    return FileResponse(INDEX_FILE)


async def publish(job_id: str, message: str) -> None:
    event = {"type": "log", "job_id": job_id, "message": message}
    stale: list[WebSocket] = []
    for socket in subscribers:
        try:
            await socket.send_json(event)
        except Exception:
            stale.append(socket)
    for socket in stale:
        subscribers.discard(socket)


async def execute_scan(job_id: str, config: dict[str, Any]) -> None:
    global last_findings
    try:
        results = await run_scan(config, lambda message: publish(job_id, message))
        jobs[job_id].update(status="complete", findings=results)
        last_findings = results
        await publish(job_id, "[complete] results are ready in the dashboard.")
    except Exception as error:
        jobs[job_id].update(status="error", error=str(error))
        await publish(job_id, f"[error] scan aborted: {error}")


@app.post("/api/scans", status_code=202)
async def start_scan(config: ScanConfig) -> dict[str, str]:
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running", "findings": []}
    asyncio.create_task(execute_scan(job_id, config.model_dump()))
    return {"job_id": job_id, "status": "running"}


@app.get("/api/scans/{job_id}")
async def scan_status(job_id: str) -> dict[str, Any]:
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Unknown scan job")
    return jobs[job_id]


@app.post("/api/report")
async def generate_report() -> dict[str, str]:
    """Write the findings from the latest completed scan to a Markdown report."""
    if not last_findings:
        raise HTTPException(status_code=409, detail="No findings from a completed scan are available for reporting.")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"authleak_report_{timestamp}.md"
    report_path = REPORTS_DIR / filename
    report_path.write_text(render_markdown_report(last_findings), encoding="utf-8")
    return {"path": f"/reports/{filename}"}


@app.websocket("/ws/logs")
async def scan_logs(websocket: WebSocket) -> None:
    await websocket.accept()
    subscribers.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        subscribers.discard(websocket)
