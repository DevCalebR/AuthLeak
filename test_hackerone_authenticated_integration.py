import asyncio

import main
from asset_inventory import AssetInventory
from scanner import AuthenticatedObservation


def test_execute_hackerone_sync_persists_authenticated_observations(monkeypatch):
    job_id = "test-authenticated-integration"
    main.hackerone_jobs.clear()
    main.hackerone_jobs[job_id] = {
        "status": "queued",
        "findings": [],
        "logs": [],
    }

    async def fake_fetch_scopes(username, token, slug, log_cb):
        assert username == "tester"
        assert token == "test-token"
        assert slug == "mock-program"
        return ["https://example.test"]

    async def fake_sequential_batch_scan(
        scan_targets,
        response_criteria,
        *,
        scope_policy,
        inventory,
    ):
        assert scan_targets == ["https://example.test"]
        inventory.record_request(
            "https://example.test/api/v1/account/123",
            method="GET",
            resource_type="fetch",
            api_like=True,
        )
        return []

    def fake_session_is_stored(session_type, *, tenant):
        assert tenant == "mock-program"
        return session_type == "victim"

    async def fake_replay_authenticated_endpoints(
        inventory,
        session_type,
        *,
        tenant,
        scope_policy,
        log_cb,
    ):
        assert session_type == "victim"
        assert tenant == "mock-program"
        assert inventory.endpoints

        return [
            AuthenticatedObservation(
                session_type="victim",
                method="GET",
                url="https://example.test/api/v1/account/123",
                status=200,
                resource_type="fetch",
                in_scope=True,
                authenticated=True,
                observed_at="2026-10-05T00:00:00+00:00",
            )
        ]

    monkeypatch.setattr(main, "fetch_hackerone_structured_scopes", fake_fetch_scopes)
    monkeypatch.setattr(main, "sequential_batch_scan", fake_sequential_batch_scan)
    monkeypatch.setattr(main, "session_is_stored", fake_session_is_stored)
    monkeypatch.setattr(
        main,
        "replay_authenticated_endpoints",
        fake_replay_authenticated_endpoints,
    )
    monkeypatch.setattr(
        main,
        "write_markdown_report",
        lambda findings, slug, report_prefix="hackerone": type(
            "FakeReport",
            (),
            {"name": "test-report.md", "__str__": lambda self: "test-report.md"},
        )(),
    )

    config = main.HackerOneSyncConfig(
        hackerone_username="tester",
        hackerone_api_token="test-token",
        program_slug="mock-program",
    )

    try:
        asyncio.run(main.execute_hackerone_sync(job_id, config))
        job = main.hackerone_jobs[job_id]
    finally:
        main.hackerone_jobs.clear()

    assert job["status"] == "complete", job
    assert job["authenticated_observations_count"] == 1
    assert job["authenticated_observations"] == [
        {
            "session_type": "victim",
            "method": "GET",
            "url": "https://example.test/api/v1/account/123",
            "status": 200,
            "resource_type": "fetch",
            "in_scope": True,
            "authenticated": True,
            "observed_at": "2026-10-05T00:00:00+00:00",
        }
    ]

    assert "test-token" not in str(job)
    assert "authorization" not in str(job).lower()
    assert "cookie" not in str(job).lower()
