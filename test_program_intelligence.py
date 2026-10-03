from program_intelligence import final_compatibility_score, metadata_analysis, summarize_scopes


def program(name="Demo", handle="demo", policy="", **attrs):
    return {"attributes": {"name": name, "handle": handle, **attrs, "policy": policy}}


def scope(asset, instruction="", bounty=True, submission=True, severity="high"):
    return {"id": "1", "type": "structured-scope", "attributes": {
        "asset_identifier": asset,
        "asset_type": "URL",
        "eligible_for_bounty": bounty,
        "eligible_for_submission": submission,
        "instruction": instruction,
        "max_severity": severity,
    }}


def test_metadata_keeps_unknown_automation_unknown():
    result = metadata_analysis(program(name="Unknown Automation", submission_state="open", offers_bounties=True, policy="Test web APIs and authentication."))
    assert result["automation_status"] == "unknown"
    assert result["policy_gate"] == "policy_review"


def test_scope_summary_detects_api_and_auth_surface():
    result = summarize_scopes([
        scope("https://api.example.com", "REST API authentication endpoint"),
        scope("https://www.example.com", "Web application dashboard"),
        scope("https://staging.example.com", "staging test environment"),
    ])
    assert result["eligible_url_count"] == 3
    assert result["api_like_url_count"] >= 1
    assert result["auth_like_url_count"] >= 1
    assert result["test_or_staging_url_count"] >= 1


def test_final_score_separates_technical_fit_from_policy():
    metadata = metadata_analysis(program(name="Fit", submission_state="open", offers_bounties=True, policy="API authentication web testing"))
    result = final_compatibility_score(metadata, summarize_scopes([scope("https://api.example.com", "REST API authentication")]))
    assert result["compatibility_score"] > metadata["metadata_score"]
    assert result["automation_status"] == "unknown"
    assert any("authorization" in x.lower() for x in result["cautions"])


def test_prohibited_program_is_blocked():
    result = metadata_analysis(program(name="Blocked", submission_state="open", offers_bounties=True, policy="Automated scanning is prohibited."))
    assert result["automation_status"] == "prohibited"
    assert result["policy_gate"] == "blocked"



def test_scope_quality_downgrades_non_bounty_vdp_scope():
    metadata = metadata_analysis(program(
        name="VDP-like",
        submission_state="open",
        offers_bounties=False,
        policy="Web application testing is in scope.",
    ))
    scope_summary = summarize_scopes([
        scope("https://www.example.com", "Web application", bounty=False),
        scope("https://api.example.com", "REST API authentication", bounty=False),
        scope("https://www2.example.com", "Web application", bounty=False),
    ])
    result = final_compatibility_score(metadata, scope_summary)
    assert result["compatibility_score"] < 65
    assert result["compatibility_tier"] in {"review", "low_fit"}
    assert any("bounty-eligible" in x.lower() for x in result["cautions"])


def test_scope_quality_prefers_bounty_api_auth_over_generic_url_volume():
    metadata = metadata_analysis(program(
        name="API-first",
        submission_state="open",
        offers_bounties=True,
        triage_active=True,
        policy="API authentication web application testing",
    ))
    api_scope = summarize_scopes([
        scope("https://api.example.com", "REST API authentication", bounty=True),
        scope("https://identity.example.com", "OAuth authentication", bounty=True),
        scope("https://app.example.com", "Web application", bounty=True),
    ])
    generic_scope = summarize_scopes([
        scope(f"https://app{i}.example.com", "Web application", bounty=True)
        for i in range(1, 21)
    ])
    api_result = final_compatibility_score(metadata, api_scope)
    generic_result = final_compatibility_score(metadata, generic_scope)
    assert api_result["compatibility_score"] > generic_result["compatibility_score"]
