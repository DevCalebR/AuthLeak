from authorization_compare import AuthorizationComparison
from authorization_verification import (
    build_authorization_verification_artifact,
)


def make_comparison(
    *,
    candidate: bool = True,
    victim_status: int | None = 403,
    attacker_status: int | None = 200,
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
            if candidate
            else "both_access_outcomes_denied"
        ),
        response_structure_changed=True,
        response_differences=("content_type", "shape"),
    )


def test_builds_verification_artifact_from_comparison():
    comparison = make_comparison()

    artifact = build_authorization_verification_artifact(comparison)

    assert artifact.method == comparison.method
    assert artifact.url == comparison.url
    assert artifact.victim_status == comparison.victim_status
    assert artifact.attacker_status == comparison.attacker_status
    assert artifact.candidate is True
    assert artifact.triage_level == "high"
    assert artifact.triage_score == 70
    assert artifact.manual_verification_required is True


def test_triage_reasons_are_composed_into_artifact():
    comparison = make_comparison()

    artifact = build_authorization_verification_artifact(comparison)

    assert artifact.triage_reasons == (
        "response_structure_changed",
        "response_content_type_changed",
        "response_shape_changed",
        "suspicious_status_differential",
    )


def test_non_candidate_produces_zero_score_low_artifact():
    comparison = make_comparison(candidate=False)

    artifact = build_authorization_verification_artifact(comparison)

    assert artifact.candidate is False
    assert artifact.triage_level == "low"
    assert artifact.triage_score == 0
    assert artifact.manual_verification_required is True


def test_artifact_preserves_response_differential_metadata():
    comparison = make_comparison()

    artifact = build_authorization_verification_artifact(comparison)

    assert artifact.response_structure_changed is True
    assert artifact.response_differences == (
        "content_type",
        "shape",
    )


def test_artifact_contains_no_raw_response_material():
    comparison = make_comparison()

    artifact = build_authorization_verification_artifact(comparison)
    serialized = artifact.to_dict()

    forbidden_fields = {
        "body",
        "response_body",
        "victim_body",
        "attacker_body",
        "cookies",
        "authorization",
        "authorization_header",
        "token",
        "access_token",
    }

    assert forbidden_fields.isdisjoint(serialized)
