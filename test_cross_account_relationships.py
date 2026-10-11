import json

from cross_account_relationships import (
    RelationshipConfidence,
    RelationshipType,
    compare_resource_relationship,
)


def test_matching_resource_paths_are_possible_same_resource():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/123",
    )

    assert result.relationship == RelationshipType.POSSIBLE_SAME_RESOURCE
    assert result.confidence == RelationshipConfidence.MEDIUM
    assert "matching_path_identifiers" in result.reasons


def test_different_identifiers_are_possible_different_resources():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/456",
    )

    assert (
        result.relationship
        == RelationshipType.POSSIBLE_DIFFERENT_RESOURCES
    )
    assert result.confidence == RelationshipConfidence.MEDIUM


def test_different_path_shapes_are_indeterminate():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/projects/123",
    )

    assert result.relationship == RelationshipType.INDETERMINATE


def test_out_of_scope_observation_is_not_compared():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/123",
        right_in_scope=False,
    )

    assert result.relationship == RelationshipType.INDETERMINATE
    assert "observations_not_eligible_for_comparison" in result.reasons


def test_unauthenticated_observation_is_not_compared():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/123",
        right_authenticated=False,
    )

    assert result.relationship == RelationshipType.INDETERMINATE


def test_different_hosts_are_not_compared():
    result = compare_resource_relationship(
        "https://one.example.test/api/users/123",
        "https://two.example.test/api/users/123",
    )

    assert result.relationship == RelationshipType.INDETERMINATE
    assert "host_missing_or_different" in result.reasons


def test_unsupported_methods_are_not_compared():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/123",
        left_method="POST",
        right_method="POST",
    )

    assert result.relationship == RelationshipType.INDETERMINATE


def test_query_secrets_are_not_retained():
    secret = "very-secret-token-999"
    result = compare_resource_relationship(
        f"https://example.test/api/users/123?token={secret}",
        f"https://example.test/api/users/123?token={secret}",
    )

    serialized = json.dumps(result.to_dict())
    assert secret not in serialized
    assert "token=" not in serialized


def test_matching_identifiers_do_not_confirm_a_vulnerability():
    result = compare_resource_relationship(
        "https://example.test/api/users/123",
        "https://example.test/api/users/123",
    )

    assert result.relationship == RelationshipType.POSSIBLE_SAME_RESOURCE
    assert "vulnerability_confirmed" not in result.reasons


def test_low_confidence_identifiers_remain_low_confidence():
    result = compare_resource_relationship(
        "https://example.test/api/version/123",
        "https://example.test/api/version/456",
    )

    assert (
        result.relationship
        == RelationshipType.POSSIBLE_DIFFERENT_RESOURCES
    )
    assert result.confidence == RelationshipConfidence.LOW
