import httpx

from response_fingerprint import fingerprint_response


def make_response(
    body: str,
    *,
    content_type: str,
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": content_type},
        content=body.encode("utf-8"),
        request=httpx.Request("GET", "https://example.test/api"),
    )


def test_json_fingerprint_keeps_structure_but_not_values():
    response = make_response(
        '{"id":123,"name":"Alice","email":"alice@example.test"}',
        content_type="application/json",
    )

    fingerprint = fingerprint_response(response)

    assert fingerprint.representation == "json"
    assert fingerprint.content_type == "application/json"
    assert "path" not in repr(fingerprint).lower()
    assert any(item == "$:object" for item in fingerprint.structure)
    assert "$.field_1:string" in fingerprint.structure
    assert "$.field_2:number" in fingerprint.structure
    assert "$.field_3:string" in fingerprint.structure

    serialized = repr(fingerprint.to_dict()).lower()
    assert "alice" not in serialized
    assert "alice@example.test" not in serialized
    assert "123" not in serialized


def test_different_json_values_produce_same_structure():
    first = make_response(
        '{"id":123,"name":"Alice","active":true}',
        content_type="application/json",
    )
    second = make_response(
        '{"id":987,"name":"Bob","active":false}',
        content_type="application/json",
    )

    first_fingerprint = fingerprint_response(first)
    second_fingerprint = fingerprint_response(second)

    assert first_fingerprint.structure == second_fingerprint.structure
    assert first_fingerprint.shape == second_fingerprint.shape


def test_different_json_structure_produces_different_fingerprint():
    first = make_response(
        '{"id":123,"name":"Alice"}',
        content_type="application/json",
    )
    second = make_response(
        '{"id":123,"name":"Alice","email":"alice@example.test"}',
        content_type="application/json",
    )

    first_fingerprint = fingerprint_response(first)
    second_fingerprint = fingerprint_response(second)

    assert first_fingerprint.structure != second_fingerprint.structure


def test_json_array_structure_is_captured_without_values():
    response = make_response(
        '{"items":[{"id":1,"name":"one"},{"id":2,"name":"two"}]}',
        content_type="application/json",
    )

    fingerprint = fingerprint_response(response)

    assert "$.field_1:array[2]" in fingerprint.structure
    assert "$.field_1[]:object" in fingerprint.structure
    assert "$.field_1[].field_1:number" in fingerprint.structure
    assert "$.field_1[].field_2:string" in fingerprint.structure


def test_html_fingerprint_keeps_structure_but_not_text():
    response = make_response(
        """
        <html>
          <head><title>Private Account</title></head>
          <body>
            <h1>Alice's Account</h1>
            <form><input name="email"></form>
            <a href="/account/123">Account</a>
          </body>
        </html>
        """,
        content_type="text/html; charset=utf-8",
    )

    fingerprint = fingerprint_response(response)

    assert fingerprint.representation == "html"
    assert fingerprint.content_type == "text/html"
    assert "tag:form=1" in fingerprint.structure
    assert "tag:h1=1" in fingerprint.structure
    assert "tag:a=1" in fingerprint.structure

    serialized = repr(fingerprint.to_dict()).lower()
    assert "alice" not in serialized
    assert "private account" not in serialized
    assert "/account/123" not in serialized


def test_plain_text_fingerprint_contains_shape_only():
    response = make_response(
        "secret-account-data\nowner=alice\nstatus=active\n",
        content_type="text/plain",
    )

    fingerprint = fingerprint_response(response)

    assert fingerprint.representation == "text"
    assert "lines=3" in fingerprint.structure
    assert "words=3" in fingerprint.structure

    serialized = repr(fingerprint.to_dict()).lower()
    assert "secret-account-data" not in serialized
    assert "owner=alice" not in serialized


def test_invalid_json_falls_back_to_sanitized_text_shape():
    response = make_response(
        "not actually json secret-value",
        content_type="application/json",
    )

    fingerprint = fingerprint_response(response)

    assert fingerprint.representation == "invalid-json"

    serialized = repr(fingerprint.to_dict()).lower()
    assert "secret-value" not in serialized


def test_large_response_is_bounded():
    response = make_response(
        "x" * 400_000,
        content_type="text/plain",
    )

    fingerprint = fingerprint_response(response)

    assert fingerprint.content_length == 400_000
    assert fingerprint.representation == "text"
    assert fingerprint.shape.startswith("chars=")
    assert len(fingerprint.structure) == 2


def test_json_fingerprint_sanitizes_sensitive_field_names():
    response = make_response(
        '{"email":"alice@example.test","api_token":"secret-token",'
        '"account_number":"123456789"}',
        content_type="application/json",
    )

    fingerprint = fingerprint_response(response)
    serialized = repr(fingerprint.to_dict()).lower()

    assert "email" not in serialized
    assert "api_token" not in serialized
    assert "account_number" not in serialized
    assert "secret-token" not in serialized
    assert "123456789" not in serialized

    assert "$.field_1:string" in fingerprint.structure
    assert "$.field_2:string" in fingerprint.structure
    assert "$.field_3:string" in fingerprint.structure


def test_json_fingerprint_ignores_string_value_length_changes():
    first = make_response(
        '{"name":"A"}',
        content_type="application/json",
    )
    second = make_response(
        '{"name":"A much longer value"}',
        content_type="application/json",
    )

    first_fingerprint = fingerprint_response(first)
    second_fingerprint = fingerprint_response(second)

    assert first_fingerprint.structure == second_fingerprint.structure
    assert first_fingerprint.shape == second_fingerprint.shape


def test_content_length_difference_is_not_structural_change():
    from authorization_compare import compare_response_fingerprints

    victim = {
        "content_type": "application/json",
        "content_length": 100,
        "representation": "json",
        "structure": (
            "$:object",
            "$.field_1:number",
        ),
        "shape": "json-root=dict",
    }

    attacker = {
        "content_type": "application/json",
        "content_length": 500,
        "representation": "json",
        "structure": (
            "$:object",
            "$.field_1:number",
        ),
        "shape": "json-root=dict",
    }

    changed, differences = compare_response_fingerprints(victim, attacker)

    assert changed is False
    assert differences == ("content_length",)
