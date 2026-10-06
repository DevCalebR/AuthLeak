import scanner
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


def test_compare_response_fingerprints_detects_structural_difference():
    from authorization_compare import compare_response_fingerprints

    victim = {
        "content_type": "application/json",
        "content_length": 120,
        "representation": "json",
        "structure": (
            "$:object",
            "$.id:number",
            "$.name:string",
            "$.email:string",
        ),
        "shape": "json-root=dict",
    }

    attacker = {
        "content_type": "application/json",
        "content_length": 80,
        "representation": "json",
        "structure": (
            "$:object",
            "$.id:number",
            "$.name:string",
        ),
        "shape": "json-root=dict",
    }

    changed, differences = compare_response_fingerprints(victim, attacker)

    assert changed is True
    assert "content_length" in differences
    assert "structure" in differences


def test_compare_response_fingerprints_ignores_value_changes():
    from authorization_compare import compare_response_fingerprints

    victim = {
        "content_type": "application/json",
        "content_length": 42,
        "representation": "json",
        "structure": (
            "$:object",
            "$.id:number",
            "$.name:string",
        ),
        "shape": "json-root=dict",
    }

    attacker = {
        "content_type": "application/json",
        "content_length": 42,
        "representation": "json",
        "structure": (
            "$:object",
            "$.id:number",
            "$.name:string",
        ),
        "shape": "json-root=dict",
    }

    changed, differences = compare_response_fingerprints(victim, attacker)

    assert changed is False
    assert differences == ()


def test_compare_response_fingerprints_detects_content_type_change():
    from authorization_compare import compare_response_fingerprints

    victim = {
        "content_type": "application/json",
        "content_length": 10,
        "representation": "json",
        "structure": ("$:object",),
        "shape": "json-root=dict",
    }

    attacker = {
        "content_type": "text/html",
        "content_length": 10,
        "representation": "html",
        "structure": ("tag:html=1",),
        "shape": "title=0;forms=0;links=0;headings=0",
    }

    changed, differences = compare_response_fingerprints(victim, attacker)

    assert changed is True
    assert "content_type" in differences
    assert "representation" in differences
    assert "shape" in differences
    assert "structure" in differences


def test_authorization_comparison_includes_response_differential_metadata():
    from authorization_compare import compare_authenticated_observations

    victim = scanner.AuthenticatedObservation(
        session_type="victim",
        method="GET",
        url="https://example.test/api/account",
        status=200,
        authenticated=True,
        response_fingerprint={
            "content_type": "application/json",
            "content_length": 100,
            "representation": "json",
            "structure": (
                "$:object",
                "$.id:number",
                "$.email:string",
            ),
            "shape": "json-root=dict",
        },
    )

    attacker = scanner.AuthenticatedObservation(
        session_type="attacker",
        method="GET",
        url="https://example.test/api/account",
        status=200,
        authenticated=True,
        response_fingerprint={
            "content_type": "application/json",
            "content_length": 60,
            "representation": "json",
            "structure": (
                "$:object",
                "$.id:number",
            ),
            "shape": "json-root=dict",
        },
    )

    comparison = compare_authenticated_observations([victim], [attacker])[0]

    assert comparison.response_structure_changed is True
    assert "content_length" in comparison.response_differences
    assert "structure" in comparison.response_differences

    result = comparison.to_dict()
    assert "authorization" not in str(result).lower()
    assert "cookie" not in str(result).lower()
    assert "token" not in str(result).lower()
    assert "response_body" not in str(result).lower()
    assert "body" not in str(result).lower()
