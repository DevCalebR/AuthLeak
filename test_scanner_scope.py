import asyncio

import pytest

import scanner
from asset_inventory import AssetInventory
from scope_policy import ScopePolicy


def test_autonomous_scan_rejects_out_of_scope_before_browser_launch():
    policy = ScopePolicy.from_identifiers(["https://allowed.example.test"])
    inventory = AssetInventory()

    async def run():
        with pytest.raises(ValueError, match="Scope blocked"):
            await scanner.autonomous_crawl_and_scan(
                "https://evil.example.test/",
                scope_policy=policy,
                inventory=inventory,
            )

    asyncio.run(run())

    assert "https://evil.example.test/" in inventory.blocked_urls


def test_sequential_batch_blocks_out_of_scope_queue_items(monkeypatch):
    policy = ScopePolicy.from_identifiers(["https://allowed.example.test"])
    inventory = AssetInventory()
    scanned: list[str] = []

    async def fake_scan(target_url, **_kwargs):
        scanned.append(target_url)
        return []

    monkeypatch.setattr(scanner, "autonomous_crawl_and_scan", fake_scan)
    monkeypatch.setattr(scanner, "INTER_ASSET_DELAY_SECONDS", 0)

    async def run():
        return await scanner.sequential_batch_scan(
            [
                "https://allowed.example.test/",
                "https://evil.example.test/",
            ],
            "",
            scope_policy=policy,
            inventory=inventory,
        )

    findings = asyncio.run(run())

    assert findings == []
    assert scanned == ["https://allowed.example.test/"]
    assert "https://evil.example.test/" in inventory.blocked_urls
