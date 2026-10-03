from program_intelligence import (
    classify_scope_identifier,
    final_compatibility_score,
    metadata_analysis,
    scope_load_classification,
    summarize_scope_exclusions,
    summarize_scopes,
)


def program(name="Demo", handle="demo", policy="", **attrs):
    return {"attributes": {"name": name, "handle": handle, **attrs, "policy": policy}}


def scope(asset, instruction="", bounty=True, submission=True, severity="high"):
    return {"id": str(abs(hash(asset)) % 100000), "type": "structured-scope", "attributes": {
        "asset_identifier": asset,
        "asset_type": "URL",
        "eligible_for_bounty": bounty,
        "eligible_for_submission": submission,
        "instruction": instruction,
        "max_severity": severity,
    }}


def test_placeholder_asset_is_not_usable():
    assert classify_scope_identifier("http://--your-own-1password-account--.1password.com") == "placeholder"
    assert classify_scope_identifier("https://<your-subdomain>.example.com") == "placeholder"
    assert classify_scope_identifier("*.example.com") == "wildcard"
    assert classify_scope_identifier("www.faraday.ai") == "usable"


def test_scope_summary_exposes_quality_and_density():
    result = summarize_scopes([
        scope("https://api.example.io/v1", "REST API authentication"),
        scope("https://identity.example.io", "OAuth login"),
        scope("https://www.example.io", "Web application"),
        scope("http://--your-own-account--.example.io", "your own account"),
        scope("*.example.io", "Wildcard in scope"),
    ])
    assert result["eligible_url_count"] == 5
    assert result["usable_url_count"] == 3
    assert result["placeholder_url_count"] == 1
    assert result["wildcard_url_count"] == 1
    assert result["api_like_url_count"] >= 1
    assert result["auth_like_url_count"] >= 1
    assert result["api_density"] > 0.0
    assert result["auth_density"] > 0.0


def test_large_scope_is_heavy_not_more_relevant_by_volume():
    generic = summarize_scopes([
        scope(f"https://app{i}.example.io", "Web application", bounty=True)
        for i in range(1, 201)
    ])
    focused = summarize_scopes([
        scope("https://api.example.io/v1", "REST API authentication", bounty=True),
        scope("https://identity.example.io", "OAuth authentication", bounty=True),
        scope("https://app.example.io", "Web application", bounty=True),
    ])
    assert generic["scan_load"] == "very_heavy"
    assert focused["scan_load"] == "light"
    metadata = metadata_analysis(program(
        submission_state="open",
        offers_bounties=True,
        triage_active=True,
        policy="API authentication web application testing",
    ))
    generic_score = final_compatibility_score(metadata, generic)["compatibility_score"]
    focused_score = final_compatibility_score(metadata, focused)["compatibility_score"]
    assert focused_score > generic_score


def test_non_bounty_scope_cannot_be_strong_fit():
    metadata = metadata_analysis(program(
        name="VDP-like",
        submission_state="open",
        offers_bounties=False,
        policy="Web application testing is in scope.",
    ))
    result = final_compatibility_score(metadata, summarize_scopes([
        scope("https://www.example.io", "Web application", bounty=False),
        scope("https://api.example.io", "REST API", bounty=False),
    ]))
    assert result["compatibility_tier"] in {"review", "low_fit"}
    assert result["compatibility_score"] < 65


def test_scope_exclusions_are_summarized():
    result = summarize_scope_exclusions([
        {"attributes": {"name": "Self-XSS"}},
        {"attributes": {"description": "Missing security headers"}},
    ])
    assert result["count"] == 2
    assert "Self-XSS" in result["examples"][0]
