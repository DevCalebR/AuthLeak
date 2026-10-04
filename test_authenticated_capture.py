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
