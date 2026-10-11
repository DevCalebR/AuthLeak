from authorization_compare import AuthorizationComparison
from false_positive_suppression import (
    CandidateDisposition,
    classify_authorization_comparisons,
)


def make_comparison(
    *,
    method="GET",
    url="https://example.test/api/users/123",
    victim_status=200,
    attacker_status=200,
    victim_authenticated=True,
    attacker_authenticated=True,
    candidate=True,
):
    return AuthorizationComparison(
        method=method,
        url=url,
        victim_status=victim_status,
        attacker_status=attacker_status,
        victim_authenticated=victim_authenticated,
        attacker_authenticated=attacker_authenticated,
        candidate=candidate,
        reason="test_observation",
    )


def test_eligible_candidate_is_retained():
    decisions = classify_authorization_comparisons([make_comparison()])

    assert decisions[0].disposition == CandidateDisposition.RETAIN_FOR_REVIEW
    assert decisions[0].should_show_in_review_queue


def test_exact_duplicate_points_to_first_candidate():
    decisions = classify_authorization_comparisons(
        [make_comparison(), make_comparison()]
    )

    assert decisions[0].disposition == CandidateDisposition.RETAIN_FOR_REVIEW
    assert decisions[1].disposition == CandidateDisposition.DUPLICATE
    assert decisions[1].duplicate_of_index == 0


def test_url_fragments_do_not_create_distinct_duplicates():
    decisions = classify_authorization_comparisons([
        make_comparison(url="https://example.test/users/123#profile"),
        make_comparison(url="https://example.test/users/123#settings"),
    ])

    assert decisions[1].disposition == CandidateDisposition.DUPLICATE


def test_different_query_values_are_not_merged():
    decisions = classify_authorization_comparisons([
        make_comparison(url="https://example.test/users?id=123"),
        make_comparison(url="https://example.test/users?id=456"),
    ])

    assert all(
        item.disposition == CandidateDisposition.RETAIN_FOR_REVIEW
        for item in decisions
    )


def test_non_candidate_is_preserved_as_non_candidate():
    decisions = classify_authorization_comparisons([
        make_comparison(candidate=False)
    ])

    assert decisions[0].disposition == CandidateDisposition.NOT_A_CANDIDATE


def test_missing_status_is_incomplete():
    decisions = classify_authorization_comparisons([
        make_comparison(attacker_status=None)
    ])

    assert decisions[0].disposition == CandidateDisposition.INCOMPLETE


def test_unauthenticated_comparison_is_ineligible():
    decisions = classify_authorization_comparisons([
        make_comparison(attacker_authenticated=False)
    ])

    assert decisions[0].disposition == CandidateDisposition.INELIGIBLE


def test_unsafe_method_is_ineligible():
    decisions = classify_authorization_comparisons([
        make_comparison(method="POST")
    ])

    assert decisions[0].disposition == CandidateDisposition.INELIGIBLE


def test_invalid_url_is_ineligible():
    decisions = classify_authorization_comparisons([
        make_comparison(url="not-a-valid-http-url")
    ])

    assert decisions[0].disposition == CandidateDisposition.INELIGIBLE


def test_decision_serialization_does_not_expose_query_secret():
    comparison = make_comparison(
        url="https://example.test/users?token=secret-value"
    )

    decision = classify_authorization_comparisons([comparison])[0]

    assert "secret-value" not in repr(decision.to_dict())


def test_original_comparison_is_not_mutated():
    comparison = make_comparison()
    original_url = comparison.url

    classify_authorization_comparisons([comparison])

    assert comparison.url == original_url


def test_low_priority_does_not_mean_suppressed():
    comparison = make_comparison(
        victim_status=403,
        attacker_status=200,
    )

    decisions = classify_authorization_comparisons([comparison])

    assert decisions[0].disposition == CandidateDisposition.RETAIN_FOR_REVIEW


def test_default_ports_are_normalized_for_duplicate_detection():
    decisions = classify_authorization_comparisons([
        make_comparison(url="https://example.test:443/api/users"),
        make_comparison(url="https://example.test/api/users"),
    ])

    assert decisions[0].disposition == CandidateDisposition.RETAIN_FOR_REVIEW
    assert decisions[1].disposition == CandidateDisposition.DUPLICATE


def test_embedded_url_credentials_are_ineligible():
    decisions = classify_authorization_comparisons([
        make_comparison(url="https://user:password@example.test/api/users")
    ])

    assert decisions[0].disposition == CandidateDisposition.INELIGIBLE
