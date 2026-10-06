from authorization_compare import AuthorizationComparison
from authorization_triage import (
    AuthorizationTriage,
    TriageLevel,
    build_authorization_triage,
)


def make_comparison(
    *,
    candidate: bool = True,
    victim_status: int | None = 200,
    attacker_status: int | None = 200,
    response_structure_changed: bool = False,
    response_differences: tuple[str, ...] = (),
) -> AuthorizationComparison:
    return AuthorizationComparison(
        method="GET",
        url="https://example.test/account",
        victim_status=victim_status,
        attacker_status=attacker_status,
        victim_authenticated=True,
        attacker_authenticated=True,
        candidate=candidate,
        reason=(
            "attacker_access_exceeds_victim"
            if victim_status is not None
            and attacker_status is not None
            and victim_status >= 400 > attacker_status
            else "same_successful_access_outcome"
        ),
        response_structure_changed=response_structure_changed,
        response_differences=response_differences,
    )


def test_non_candidate_remains_neutral():
    comparison = make_comparison(candidate=False)
    triage = build_authorization_triage(comparison)

    assert triage.candidate is False
    assert triage.level is TriageLevel.LOW
    assert triage.score == 0
    assert triage.reasons == ()


def test_both_successful_responses_add_thirty_points():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    assert triage.score == 30
    assert triage.level is TriageLevel.MEDIUM
    assert triage.reasons == ("both_sessions_successful",)


def test_structural_change_adds_twenty_five_points_once():
    comparison = make_comparison(
        response_structure_changed=True,
        response_differences=("structure",),
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 55
    assert triage.level is TriageLevel.MEDIUM
    assert triage.reasons == (
        "both_sessions_successful",
        "response_structure_changed",
    )


def test_content_type_and_shape_changes_are_scored_individually():
    comparison = make_comparison(
        response_differences=("content_type", "shape"),
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 60
    assert triage.level is TriageLevel.HIGH
    assert triage.reasons == (
        "both_sessions_successful",
        "response_content_type_changed",
        "response_shape_changed",
    )


def test_status_differential_adds_fifteen_points():
    comparison = make_comparison(
        victim_status=200,
        attacker_status=403,
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 15
    assert triage.level is TriageLevel.LOW
    assert triage.reasons == ("suspicious_status_differential",)


def test_status_differential_combines_with_structural_change():
    comparison = make_comparison(
        victim_status=200,
        attacker_status=403,
        response_structure_changed=True,
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 40
    assert triage.level is TriageLevel.MEDIUM
    assert triage.reasons == (
        "response_structure_changed",
        "suspicious_status_differential",
    )


def test_attacker_access_exceeds_victim_is_a_valid_candidate():
    comparison = make_comparison(
        victim_status=403,
        attacker_status=200,
    )
    triage = build_authorization_triage(comparison)

    assert triage.candidate is True
    assert triage.score == 15
    assert triage.level is TriageLevel.LOW
    assert triage.reasons == ("suspicious_status_differential",)


def test_combined_scoring_signals_stays_within_one_hundred():
    comparison = make_comparison(
        victim_status=200,
        attacker_status=200,
        response_structure_changed=True,
        response_differences=("content_type", "shape"),
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 85
    assert triage.score <= 100


def test_missing_status_does_not_add_success_or_status_points():
    comparison = make_comparison(
        victim_status=None,
        attacker_status=None,
        response_structure_changed=True,
    )
    triage = build_authorization_triage(comparison)

    assert triage.score == 25
    assert triage.level is TriageLevel.LOW
    assert triage.reasons == ("response_structure_changed",)


def test_triage_serializes_to_dashboard_safe_dict():
    comparison = make_comparison(
        response_structure_changed=True,
        response_differences=("structure",),
    )
    triage = build_authorization_triage(comparison)

    assert triage.to_dict() == {
        "level": "medium",
        "score": 55,
        "reasons": [
            "both_sessions_successful",
            "response_structure_changed",
        ],
        "candidate": True,
    }


def test_triage_is_immutable():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    assert isinstance(triage, AuthorizationTriage)

    try:
        triage.score = 50
    except AttributeError:
        pass
    else:
        raise AssertionError("AuthorizationTriage should be immutable")
