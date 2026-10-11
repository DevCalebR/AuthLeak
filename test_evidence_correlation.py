import json

from authorization_compare import AuthorizationComparison
from authorization_evidence import (
    AccessRelationship,
    AuthorizationEvidence,
    EvidenceStrength,
)
from cross_account_relationships import (
    RelationshipConfidence,
    RelationshipType,
    ResourceRelationship,
)
from evidence_correlation import (
    CorrelationType,
    EvidenceLink,
    correlate_authorization_evidence,
)


def make_evidence(url, *, method="GET", candidate=True, authenticated=True,
                  access=AccessRelationship.SAME_SUCCESS):
    return AuthorizationEvidence(
        method=method,
        url=url,
        victim_status=200,
        attacker_status=200,
        victim_authenticated=authenticated,
        attacker_authenticated=authenticated,
        candidate=candidate,
        candidate_reason="test_candidate",
        access_relationship=access,
        response_structure_changed=False,
        response_differences=(),
        triage_level="medium",
        triage_score=30,
        triage_reasons=("test_reason",),
        evidence_strength=EvidenceStrength.MODERATE,
        evidence_reasons=("test_evidence",),
    )


def make_relationship(left_url, right_url, *, kind=RelationshipType.POSSIBLE_SAME_RESOURCE,
                      method="GET"):
    return ResourceRelationship(
        method=method,
        left_url=left_url,
        right_url=right_url,
        relationship=kind,
        confidence=RelationshipConfidence.MEDIUM,
        reasons=("test_relationship",),
    )


def test_matching_resource_link_is_correlated_as_signal():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/123"
    evidence = [make_evidence(left_url), make_evidence(right_url)]
    link = EvidenceLink(
        0, 1, make_relationship(left_url, right_url)
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.CORROBORATING_SIGNAL
    assert "correlation_is_not_vulnerability_confirmation" in result.reasons


def test_different_resources_remain_distinct_context():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [make_evidence(left_url), make_evidence(right_url)]
    link = EvidenceLink(
        0, 1,
        make_relationship(
            left_url, right_url,
            kind=RelationshipType.POSSIBLE_DIFFERENT_RESOURCES,
        ),
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.DISTINCT_RESOURCE_CONTEXT


def test_relationship_provenance_must_match_evidence_urls():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [make_evidence(left_url), make_evidence(right_url)]
    link = EvidenceLink(
        0, 1,
        make_relationship(
            "https://example.test/api/users/999", right_url
        ),
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.INDETERMINATE
    assert "relationship_provenance_mismatch" in result.reasons


def test_unsafe_method_is_not_correlated():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [
        make_evidence(left_url, method="POST"),
        make_evidence(right_url, method="POST"),
    ]
    link = EvidenceLink(
        0, 1, make_relationship(left_url, right_url, method="POST")
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.INDETERMINATE


def test_non_candidate_is_not_correlated():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [
        make_evidence(left_url, candidate=False),
        make_evidence(right_url),
    ]
    link = EvidenceLink(
        0, 1, make_relationship(left_url, right_url)
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.INDETERMINATE


def test_authorization_differential_is_reported_without_confirmation():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [
        make_evidence(
            left_url,
            access=AccessRelationship.ATTACKER_EXCEEDS_VICTIM,
        ),
        make_evidence(right_url),
    ]
    link = EvidenceLink(
        0, 1,
        make_relationship(
            left_url, right_url,
            kind=RelationshipType.POSSIBLE_DIFFERENT_RESOURCES,
        ),
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.authorization_differential_present is True
    assert "correlation_is_not_vulnerability_confirmation" in result.reasons


def test_invalid_indices_are_indeterminate():
    evidence = [make_evidence("https://example.test/api/users/123")]
    link = EvidenceLink(
        0, 7,
        make_relationship(
            "https://example.test/api/users/123",
            "https://example.test/api/users/456",
        ),
    )

    result = correlate_authorization_evidence(evidence, [link])[0]

    assert result.correlation == CorrelationType.INDETERMINATE
    assert "invalid_or_repeated_evidence_indices" in result.reasons


def test_output_does_not_copy_query_secrets():
    secret = "secret-token-xyz"
    left_url = f"https://example.test/api/users/123?token={secret}"
    right_url = f"https://example.test/api/users/456?token={secret}"
    evidence = [make_evidence(left_url), make_evidence(right_url)]
    link = EvidenceLink(
        0, 1,
        make_relationship(left_url, right_url),
    )

    output = json.dumps(
        [
            item.to_dict()
            for item in correlate_authorization_evidence(evidence, [link])
        ]
    )

    assert secret not in output
    assert "token=" not in output


def test_inputs_are_not_mutated():
    left_url = "https://example.test/api/users/123"
    right_url = "https://example.test/api/users/456"
    evidence = [make_evidence(left_url), make_evidence(right_url)]
    link = EvidenceLink(
        0, 1, make_relationship(left_url, right_url)
    )
    original_urls = [item.url for item in evidence]

    correlate_authorization_evidence(evidence, [link])

    assert [item.url for item in evidence] == original_urls
