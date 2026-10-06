from scanner import AuthenticatedObservation
from authorization_compare import compare_authenticated_observations


def make_observation(
    session_type: str,
    *,
    status: int | None,
    url: str = "https://example.test/api/v1/account/123",
    method: str = "GET",
    authenticated: bool = True,
    in_scope: bool = True,
) -> AuthenticatedObservation:
    return AuthenticatedObservation(
        session_type=session_type,
        method=method,
        url=url,
        status=status,
        resource_type="api",
        in_scope=in_scope,
        authenticated=authenticated,
        observed_at="2026-10-05T00:00:00+00:00",
    )


def test_same_successful_access_outcome_is_candidate():
    victim = make_observation("victim", status=200)
    attacker = make_observation("attacker", status=200)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert len(comparisons) == 1
    comparison = comparisons[0]

    assert comparison.method == "GET"
    assert comparison.url == "https://example.test/api/v1/account/123"
    assert comparison.victim_status == 200
    assert comparison.attacker_status == 200
    assert comparison.victim_authenticated is True
    assert comparison.attacker_authenticated is True
    assert comparison.candidate is True
    assert comparison.reason == "same_successful_access_outcome"


def test_attacker_denied_is_not_candidate():
    victim = make_observation("victim", status=200)
    attacker = make_observation("attacker", status=403)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert len(comparisons) == 1
    assert comparisons[0].candidate is False
    assert comparisons[0].reason == "attacker_access_denied"


def test_attacker_access_exceeding_victim_is_candidate():
    victim = make_observation("victim", status=401)
    attacker = make_observation("attacker", status=200)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert len(comparisons) == 1
    assert comparisons[0].candidate is True
    assert comparisons[0].reason == "attacker_access_exceeds_victim"


def test_denied_for_both_is_not_candidate():
    victim = make_observation("victim", status=403)
    attacker = make_observation("attacker", status=404)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert len(comparisons) == 1
    assert comparisons[0].candidate is False
    assert comparisons[0].reason == "both_access_outcomes_denied"


def test_unsafe_methods_are_ignored():
    victim = make_observation("victim", status=200, method="POST")
    attacker = make_observation("attacker", status=200, method="POST")

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert comparisons == []


def test_out_of_scope_observations_are_ignored():
    victim = make_observation("victim", status=200, in_scope=False)
    attacker = make_observation("attacker", status=200)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert comparisons == []


def test_unauthenticated_observations_are_ignored():
    victim = make_observation("victim", status=200, authenticated=False)
    attacker = make_observation("attacker", status=200)

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert comparisons == []


def test_only_matching_method_and_url_are_compared():
    victim = make_observation("victim", status=200)
    attacker = make_observation(
        "attacker",
        status=200,
        url="https://example.test/api/v1/account/456",
    )

    comparisons = compare_authenticated_observations([victim], [attacker])

    assert comparisons == []


def test_comparison_contains_metadata_only():
    victim = make_observation("victim", status=200)
    attacker = make_observation("attacker", status=200)

    comparison = compare_authenticated_observations([victim], [attacker])[0]
    data = comparison.to_dict()

    serialized = repr(data).lower()

    assert "authorization" not in serialized
    assert "cookie" not in serialized
    assert "token" not in serialized
    assert "response_body" not in serialized
    assert "body" not in serialized
    assert "headers" not in serialized
