from authorization_compare import AuthorizationComparison
from authorization_evidence import (
    AccessRelationship,
    EvidenceStrength,
    AuthorizationEvidence,
    build_authorization_evidence,
)
from authorization_triage import (
    AuthorizationTriage,
    TriageLevel,
)


def _comparison(
    *,
    victim_status: int | None = 200,
    attacker_status: int | None = 200,
    candidate: bool = True,
    reason: str = "same_successful_access_outcome",
    response_structure_changed: bool = False,
    response_differences: tuple[str, ...] = (),
) -> AuthorizationComparison:
    return AuthorizationComparison(
        method="GET",
        url="https://example.test/api/v1/account/123",
        victim_status=victim_status,
        attacker_status=attacker_status,
        victim_authenticated=True,
        attacker_authenticated=True,
        candidate=candidate,
        reason=reason,
        response_structure_changed=response_structure_changed,
        response_differences=response_differences,
    )


def _triage(
    *,
    level: TriageLevel = TriageLevel.MEDIUM,
    score: int = 30,
    reasons: tuple[str, ...] = ("both_sessions_successful",),
    candidate: bool = True,
) -> AuthorizationTriage:
    return AuthorizationTriage(
        level=level,
        score=score,
        reasons=reasons,
        candidate=candidate,
    )


def test_same_successful_access_is_moderate_evidence() -> None:
    evidence = build_authorization_evidence(
        _comparison(),
        _triage(),
    )

    assert evidence.access_relationship == AccessRelationship.SAME_SUCCESS
    assert evidence.evidence_strength == EvidenceStrength.MODERATE
    assert evidence.candidate is True
    assert evidence.manual_verification_required is True
    assert "both_authenticated_sessions_received_successful_access" in (
        evidence.evidence_reasons
    )


def test_attacker_success_where_victim_is_denied_is_strong() -> None:
    comparison = _comparison(
        victim_status=403,
        attacker_status=200,
        reason="attacker_access_exceeds_victim",
    )
    triage = _triage(
        level=TriageLevel.HIGH,
        score=60,
        reasons=("suspicious_status_differential",),
    )

    evidence = build_authorization_evidence(comparison, triage)

    assert (
        evidence.access_relationship
        == AccessRelationship.ATTACKER_EXCEEDS_VICTIM
    )
    assert evidence.evidence_strength == EvidenceStrength.STRONG
    assert "attacker_successful_where_victim_was_denied" in (
        evidence.evidence_reasons
    )


def test_victim_success_and_attacker_denied_is_not_candidate() -> None:
    comparison = _comparison(
        victim_status=200,
        attacker_status=403,
        candidate=False,
        reason="attacker_access_denied",
    )
    triage = _triage(
        level=TriageLevel.LOW,
        score=0,
        reasons=(),
        candidate=False,
    )

    evidence = build_authorization_evidence(comparison, triage)

    assert evidence.access_relationship == AccessRelationship.VICTIM_ONLY
    assert evidence.evidence_strength == EvidenceStrength.NONE
    assert evidence.evidence_reasons == ()
    assert evidence.candidate is False


def test_both_denied_is_not_candidate() -> None:
    comparison = _comparison(
        victim_status=403,
        attacker_status=403,
        candidate=False,
        reason="both_access_outcomes_denied",
    )
    triage = _triage(
        level=TriageLevel.LOW,
        score=0,
        reasons=(),
        candidate=False,
    )

    evidence = build_authorization_evidence(comparison, triage)

    assert evidence.access_relationship == AccessRelationship.BOTH_DENIED
    assert evidence.evidence_strength == EvidenceStrength.NONE


def test_missing_status_is_incomplete() -> None:
    comparison = _comparison(
        victim_status=None,
        attacker_status=200,
        candidate=False,
        reason="incomplete_access_outcome",
    )
    triage = _triage(
        level=TriageLevel.LOW,
        score=0,
        reasons=(),
        candidate=False,
    )

    evidence = build_authorization_evidence(comparison, triage)

    assert evidence.access_relationship == AccessRelationship.INCOMPLETE
    assert evidence.evidence_strength == EvidenceStrength.NONE


def test_structural_difference_is_preserved() -> None:
    comparison = _comparison(
        response_structure_changed=True,
        response_differences=("shape", "structure"),
    )
    triage = _triage(
        level=TriageLevel.HIGH,
        score=70,
        reasons=(
            "both_sessions_successful",
            "response_structure_changed",
            "response_shape_changed",
        ),
    )

    evidence = build_authorization_evidence(comparison, triage)

    assert evidence.response_structure_changed is True
    assert evidence.response_differences == ("shape", "structure")
    assert evidence.evidence_strength == EvidenceStrength.STRONG
    assert "response_structure_changed" in evidence.evidence_reasons
    assert "response_differences_present" in evidence.evidence_reasons


def test_to_dict_is_json_serializable_shape() -> None:
    evidence = build_authorization_evidence(
        _comparison(),
        _triage(),
    )

    serialized = evidence.to_dict()

    assert serialized["method"] == "GET"
    assert serialized["url"] == (
        "https://example.test/api/v1/account/123"
    )
    assert serialized["access_relationship"] == "same_success"
    assert serialized["evidence_strength"] == "moderate"
    assert serialized["triage_level"] == "medium"
    assert serialized["triage_score"] == 30
    assert serialized["triage_reasons"] == ["both_sessions_successful"]
    assert serialized["manual_verification_required"] is True


def test_evidence_does_not_store_raw_response_or_credentials() -> None:
    evidence = build_authorization_evidence(
        _comparison(),
        _triage(),
    )

    serialized = evidence.to_dict()
    serialized_text = repr(serialized).lower()

    assert "authorization" not in serialized_text
    assert "cookie" not in serialized_text
    assert "token" not in serialized_text
    assert "password" not in serialized_text
    assert "response_body" not in serialized_text


def test_builder_does_not_change_comparison_candidate() -> None:
    comparison = _comparison(candidate=True)
    triage = _triage(candidate=True)

    evidence = build_authorization_evidence(comparison, triage)

    assert comparison.candidate is True
    assert evidence.candidate is True
