import asyncio

import main


def test_intelligence_endpoint_does_not_start_scan(monkeypatch):
    calls = []

    async def fake_build(username, token, shortlist_size, log_cb):
        calls.append((username, token, shortlist_size))
        await log_cb("[intelligence] test")
        return {"programs_analyzed": 595, "scope_enriched": 12, "recommendations": []}

    monkeypatch.setattr(main, "build_recommendations", fake_build)
    config = main.HackerOneIntelligenceConfig(
        hackerone_username="tester",
        hackerone_api_token="do-not-log",
        shortlist_size=12,
    )
    result = asyncio.run(main.hackerone_intelligence(config))
    assert result["programs_analyzed"] == 595
    assert result["scope_enriched"] == 12
    assert calls == [("tester", "do-not-log", 12)]
    assert main.hackerone_jobs == {}
