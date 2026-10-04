from scope_policy import ScopePolicy


def test_exact_host_allows_paths_on_same_host():
    policy = ScopePolicy.from_identifiers(["https://app.example.test"])
    assert policy.allows("https://app.example.test/login")
    assert policy.allows("https://app.example.test/api/users")
    assert not policy.allows("https://other.example.test/api/users")


def test_wildcard_subdomain_does_not_include_apex():
    policy = ScopePolicy.from_identifiers(["https://*.example.test"])
    assert policy.allows("https://api.example.test/v1")
    assert policy.allows("https://deep.api.example.test/v1")
    assert not policy.allows("https://example.test/v1")


def test_path_prefix_is_not_path_sibling():
    policy = ScopePolicy.from_identifiers(["https://app.example.test/portal"])
    assert policy.allows("https://app.example.test/portal")
    assert policy.allows("https://app.example.test/portal/users")
    assert not policy.allows("https://app.example.test/portalist")


def test_path_wildcard_covers_nested_paths():
    policy = ScopePolicy.from_identifiers(["https://api.example.test/api/*"])
    assert policy.allows("https://api.example.test/api")
    assert policy.allows("https://api.example.test/api/v1/users")
    assert not policy.allows("https://api.example.test/admin")


def test_scheme_and_explicit_port_are_enforced():
    policy = ScopePolicy.from_identifiers(["http://app.example.test:8080"])
    assert policy.allows("http://app.example.test:8080/health")
    assert not policy.allows("https://app.example.test:8080/health")
    assert not policy.allows("http://app.example.test:9090/health")


def test_userinfo_is_rejected():
    policy = ScopePolicy.from_identifiers(["https://app.example.test"])
    decision = policy.decide("https://user:pass@app.example.test/secret")
    assert not decision.allowed
    assert "userinfo" in decision.reason.lower()


def test_query_and_fragment_do_not_expand_scope():
    policy = ScopePolicy.from_identifiers(["https://app.example.test/portal"])
    assert policy.allows("https://app.example.test/portal?next=/admin#fragment")
    assert not policy.allows("https://app.example.test/admin?from=/portal")


def test_block_decision_explains_scope_violation():
    policy = ScopePolicy.from_identifiers(["https://app.example.test"])
    decision = policy.decide("https://evil.example.test/")
    assert not decision.allowed
    assert decision.matched_rule is None
    assert "outside" in decision.reason.lower()


def test_concrete_and_wildcard_rule_counts():
    policy = ScopePolicy.from_identifiers(
        [
            "https://app.example.test",
            "https://*.example.test",
            "https://api.example.test/api/*",
        ]
    )
    description = policy.describe()
    assert description["rule_count"] == 3
    assert description["concrete_rule_count"] == 1
    assert description["wildcard_rule_count"] == 2
    assert policy.concrete_targets() == ["https://app.example.test"]
