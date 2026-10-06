from authorization_compare import AuthorizationComparison
from authorization_triage import build_authorization_triage
from verification_artifact import (
    VerificationArtifact,
    build_verification_artifact,
)


def make_comparison(
    *,
    candidate: bool = True,
    victim_status: int | None = 403,
    attacker_status: int | None = 200,
    response_structure_changed: bool = True,
    response_differences: tuple[str, ...] = (
        "content_type",
        "shape",
    ),
) -> AuthorizationComparison:
    return AuthorizationComparison(
        method="GET",
        url="https://example.test/account",
        victim_status=victim_status,
        attacker_status=attacker_status,
        victim_authenticated=True,
        attacker_authenticated=True,
        candidate=candidate,
        reason="attacker_access_exceeds_victim",
        response_structure_changed=response_structure_changed,
        response_differences=response_differences,
    )


def test_builds_artifact_from_comparison_and_triage():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    artifact = build_verification_artifact(comparison, triage)

    assert isinstance(artifact, VerificationArtifact)
    assert artifact.method == "GET"
    assert artifact.url == "https://example.test/account"
    assert artifact.victim_status == 403
    assert artifact.attacker_status == 200
    assert artifact.candidate is True
    assert artifact.candidate_reason == "attacker_access_exceeds_victim"
    assert artifact.response_structure_changed is True
    assert artifact.response_differences == ("content_type", "shape")
    assert artifact.triage_level == "high"
    assert artifact.triage_score == 70
    assert artifact.triage_reasons == (
        "response_structure_changed",
        "response_content_type_changed",
        "response_shape_changed",
        "suspicious_status_differential",
    )
    assert artifact.manual_verification_required is True


def test_artifact_serializes_to_json_safe_dict():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    artifact = build_verification_artifact(comparison, triage)

    assert artifact.to_dict() == {
        "method": "GET",
        "url": "https://example.test/account",
        "victim_status": 403,
        "attacker_status": 200,
        "victim_authenticated": True,
        "attacker_authenticated": True,
        "candidate": True,
        "candidate_reason": "attacker_access_exceeds_victim",
        "response_structure_changed": True,
        "response_differences": [
            "content_type",
            "shape",
        ],
        "triage_level": "high",
        "triage_score": 70,
        "triage_reasons": [
            "response_structure_changed",
            "response_content_type_changed",
            "response_shape_changed",
            "suspicious_status_differential",
        ],
        "manual_verification_required": True,
    }


def test_non_candidate_remains_non_candidate():
    comparison = make_comparison(candidate=False)
    triage = build_authorization_triage(comparison)

    artifact = build_verification_artifact(comparison, triage)

    assert artifact.candidate is False
    assert artifact.triage_score == 0
    assert artifact.triage_level == "low"
    assert artifact.manual_verification_required is True


def test_artifact_contains_no_raw_response_body_field():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    artifact = build_verification_artifact(comparison, triage)
    serialized = artifact.to_dict()

    forbidden_fields = {
        "body",
        "response_body",
        "victim_body",
        "attacker_body",
        "cookies",
        "authorization",
        "authorization_header",
    }

    assert forbidden_fields.isdisjoint(serialized)


def test_artifact_is_immutable():
    comparison = make_comparison()
    triage = build_authorization_triage(comparison)

    artifact = build_verification_artifact(comparison, triage)

    try:
        artifact.score = 100
    except AttributeError:
        pass
    else:
        raise AssertionError("VerificationArtifact should be immutable")
