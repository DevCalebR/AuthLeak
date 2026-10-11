import json

from resource_identity import (
    ResourceIdentifierType,
    ResourceIdentityConfidence,
    analyze_resource_identity,
)


def test_numeric_resource_ids_are_detected():
    result = analyze_resource_identity(
        "https://example.test/api/v1/accounts/123/projects/456"
    )

    assert len(result.identities) == 2

    account, project = result.identities

    assert account.identifier == "123"
    assert account.segment_index == 3
    assert account.identifier_type == ResourceIdentifierType.NUMERIC_ID
    assert account.resource_segment == "accounts"
    assert account.confidence == ResourceIdentityConfidence.HIGH

    assert project.identifier == "456"
    assert project.segment_index == 5
    assert project.identifier_type == ResourceIdentifierType.NUMERIC_ID
    assert project.resource_segment == "projects"
    assert project.confidence == ResourceIdentityConfidence.HIGH


def test_uuid_resource_ids_are_detected():
    result = analyze_resource_identity(
        "https://example.test/users/"
        "550e8400-e29b-41d4-a716-446655440000"
    )

    assert len(result.identities) == 1

    identity = result.identities[0]

    assert identity.identifier_type == ResourceIdentifierType.UUID
    assert identity.resource_segment == "users"
    assert identity.confidence == ResourceIdentityConfidence.HIGH


def test_opaque_ids_require_a_mixed_alphanumeric_shape():
    result = analyze_resource_identity(
        "https://example.test/documents/abc123xyz"
    )

    assert len(result.identities) == 1

    identity = result.identities[0]

    assert identity.identifier == "abc123xyz"
    assert identity.identifier_type == ResourceIdentifierType.OPAQUE_ID
    assert identity.resource_segment == "documents"
    assert identity.confidence == ResourceIdentityConfidence.MEDIUM


def test_non_identifier_segments_are_ignored():
    result = analyze_resource_identity(
        "https://example.test/api/v1/accounts/current/projects/list"
    )

    assert result.identities == ()


def test_query_values_are_never_analyzed():
    result = analyze_resource_identity(
        "https://example.test/api/users/list?user_id=123&token=abc123xyz"
    )

    assert result.identities == ()
    assert "123" not in result.path
    assert "abc123xyz" not in result.path


def test_root_and_empty_urls_are_safe():
    assert analyze_resource_identity("").path == "/"
    assert analyze_resource_identity("/").path == "/"
    assert analyze_resource_identity("/api").identities == ()


def test_serialization_is_json_safe():
    result = analyze_resource_identity(
        "https://example.test/accounts/123"
    )

    serialized = result.to_dict()

    assert json.loads(json.dumps(serialized)) == serialized
    assert serialized["identities"][0]["identifier"] == "123"


def test_analysis_is_immutable():
    result = analyze_resource_identity(
        "https://example.test/accounts/123"
    )

    try:
        result.url = "https://evil.test"
    except AttributeError:
        pass
    else:
        raise AssertionError("ResourceIdentityAnalysis must be immutable")


def test_numeric_identifier_without_resource_context_is_low_confidence():
    result = analyze_resource_identity(
        "https://example.test/api/version/123"
    )

    assert len(result.identities) == 1
    assert result.identities[0].confidence == ResourceIdentityConfidence.LOW


def test_uuid_without_resource_context_is_medium_confidence():
    result = analyze_resource_identity(
        "https://example.test/api/foo/"
        "550e8400-e29b-41d4-a716-446655440000"
    )

    assert len(result.identities) == 1
    assert result.identities[0].confidence == ResourceIdentityConfidence.MEDIUM


def test_opaque_identifier_without_resource_context_is_low_confidence():
    result = analyze_resource_identity(
        "https://example.test/api/foo/abc123xyz"
    )

    assert len(result.identities) == 1
    assert result.identities[0].confidence == ResourceIdentityConfidence.LOW


def test_serialization_removes_query_fragment_and_url_credentials():
    secret = "super-secret-token-987"
    result = analyze_resource_identity(
        f"https://alice:password@example.test/api/users/list"
        f"?token={secret}#private-fragment"
    )

    serialized = json.dumps(result.to_dict())
    assert secret not in serialized
    assert "password" not in serialized
    assert "alice" not in serialized
    assert "private-fragment" not in serialized
    assert result.url == "https://example.test/api/users/list"


def test_ambiguous_report_year_stays_low_confidence():
    result = analyze_resource_identity(
        "https://example.test/api/reports/2026"
    )

    assert len(result.identities) == 1
    assert result.identities[0].identifier == "2026"
    assert result.identities[0].confidence == ResourceIdentityConfidence.LOW


def test_multiple_resource_identifiers_are_independent():
    result = analyze_resource_identity(
        "https://example.test/api/items/123/comments/456"
    )

    assert len(result.identities) == 2
    item, comment = result.identities

    assert (item.identifier, item.resource_segment) == ("123", "items")
    assert item.confidence == ResourceIdentityConfidence.HIGH
    assert (comment.identifier, comment.resource_segment) == (
        "456", "comments"
    )
    assert comment.confidence == ResourceIdentityConfidence.HIGH


def test_uuid_shape_is_recognized_without_version_assumptions():
    result = analyze_resource_identity(
        "https://example.test/users/018f2a11-2222-7333-8444-abcdef123456"
    )

    assert len(result.identities) == 1
    assert result.identities[0].identifier_type == ResourceIdentifierType.UUID
