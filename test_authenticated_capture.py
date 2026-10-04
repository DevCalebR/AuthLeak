import asyncio

from asset_inventory import AssetInventory
from scope_policy import ScopePolicy

import scanner


def test_authenticated_observation_contains_metadata_only():
    observation = scanner.AuthenticatedObservation(
        session_type="victim",
        method="GET",
        url="https://example.test/api/v1/account/123",
        status=200,
        resource_type="fetch",
        in_scope=True,
        authenticated=True,
        observed_at="2026-10-04T22:00:00+00:00",
    )

    result = observation.to_dict()

    assert result == {
        "session_type": "victim",
        "method": "GET",
        "url": "https://example.test/api/v1/account/123",
        "status": 200,
        "resource_type": "fetch",
        "in_scope": True,
        "authenticated": True,
        "observed_at": "2026-10-04T22:00:00+00:00",
    }


def test_authenticated_observation_does_not_store_credentials_or_body():
    observation = scanner.AuthenticatedObservation(
        session_type="attacker",
        method="GET",
        url="https://example.test/api/v1/account/123",
        status=403,
        authenticated=True,
    )

    result = observation.to_dict()

    assert "authorization" not in result
    assert "cookie" not in result
    assert "headers" not in result
    assert "token" not in result
    assert "response_body" not in result
    assert "body" not in result


def test_authenticated_observation_accepts_unauthenticated_metadata():
    observation = scanner.AuthenticatedObservation(
        session_type="victim",
        method="GET",
        url="https://example.test/api/v1/account/123",
        status=401,
        authenticated=False,
    )

    assert observation.status == 401
    assert observation.authenticated is False

def test_replay_authenticated_endpoints_uses_stored_session_without_exposing_credentials(
    monkeypatch,
):
    inventory = AssetInventory()
    inventory.record_request(
        "https://example.test/api/v1/account/123",
        method="GET",
        resource_type="fetch",
        api_like=True,
    )

    captured = {}

    class FakeResponse:
        status_code = 200

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, headers):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(headers)
            return FakeResponse()

    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        scanner,
        "_read_session_profile",
        lambda *args, **kwargs: {
            "headers": {
                "Authorization": "Bearer secret-token",
            }
        },
    )

    async def run():
        return await scanner.replay_authenticated_endpoints(
            inventory,
            "victim",
            target_url="https://example.test/",
        )

    observations = asyncio.run(run())

    assert len(observations) == 1
    assert captured["method"] == "GET"
    assert captured["url"] == "https://example.test/api/v1/account/123"
    assert captured["headers"]["Authorization"] == "Bearer secret-token"

    result = observations[0].to_dict()
    assert result["session_type"] == "victim"
    assert result["status"] == 200
    assert result["authenticated"] is True
    assert result["in_scope"] is True
    assert "secret-token" not in str(result)


def test_replay_authenticated_endpoints_skips_unsafe_methods(monkeypatch):
    inventory = AssetInventory()
    inventory.record_request(
        "https://example.test/api/v1/account",
        method="POST",
        resource_type="fetch",
        api_like=True,
    )

    calls = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, headers):
            calls.append((method, url))
            raise AssertionError("Unsafe method should not be replayed")

    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        scanner,
        "_read_session_profile",
        lambda *args, **kwargs: {
            "headers": {
                "Authorization": "Bearer secret-token",
            }
        },
    )

    async def run():
        return await scanner.replay_authenticated_endpoints(
            inventory,
            "victim",
            target_url="https://example.test/",
        )

    observations = asyncio.run(run())

    assert observations == []
    assert calls == []


def test_replay_authenticated_endpoints_blocks_out_of_scope_before_request(
    monkeypatch,
):
    inventory = AssetInventory()
    inventory.record_request(
        "https://evil.example.test/api/v1/account/123",
        method="GET",
        resource_type="fetch",
        api_like=True,
    )

    calls = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, headers):
            calls.append((method, url))
            raise AssertionError("Out-of-scope endpoint must not be requested")

    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(
        scanner,
        "_read_session_profile",
        lambda *args, **kwargs: {
            "headers": {
                "Authorization": "Bearer secret-token",
            }
        },
    )

    policy = ScopePolicy.from_identifiers(
        ["https://allowed.example.test"]
    )

    async def run():
        return await scanner.replay_authenticated_endpoints(
            inventory,
            "victim",
            target_url="https://evil.example.test/",
            scope_policy=policy,
        )

    observations = asyncio.run(run())

    assert observations == []
    assert calls == []
    assert (
        "https://evil.example.test/api/v1/account/123"
        in inventory.blocked_urls
    )
