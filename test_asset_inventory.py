from asset_inventory import AssetInventory, summarize_inventories


def test_inventory_deduplicates_and_tracks_request_metadata():
    inventory = AssetInventory(max_items=10)
    inventory.record_request(
        "https://api.example.test/v1/users",
        method="GET",
        resource_type="xhr",
        api_like=True,
    )
    inventory.record_request(
        "https://api.example.test/v1/users",
        method="GET",
        resource_type="xhr",
        api_like=True,
    )
    inventory.record_response(
        "https://api.example.test/v1/users",
        method="GET",
        status_code=200,
        resource_type="xhr",
    )

    result = inventory.to_dict()
    assert result["counts"]["discovered_urls"] == 1
    assert result["counts"]["api_urls"] == 1
    assert result["method_counts"]["GET"] == 3
    assert result["status_counts"]["200"] == 1
    assert result["host_counts"]["api.example.test"] == 3


def test_inventory_records_reference_types_and_blocked_urls():
    inventory = AssetInventory(max_items=10)
    inventory.record_script("https://app.example.test/static/app.js")
    inventory.record_link("https://app.example.test/account")
    inventory.record_form("https://app.example.test/account/update")
    inventory.record_blocked("https://evil.example.test/collect")

    result = inventory.to_dict()
    assert result["counts"]["script_urls"] == 1
    assert result["counts"]["link_urls"] == 1
    assert result["counts"]["form_urls"] == 1
    assert result["counts"]["blocked_urls"] == 1
    assert "https://evil.example.test/collect" in result["blocked_urls"]


def test_inventory_collections_are_bounded():
    inventory = AssetInventory(max_items=2)
    inventory.record_request("https://a.example.test/")
    inventory.record_request("https://b.example.test/")
    inventory.record_request("https://c.example.test/")

    result = inventory.to_dict()
    assert result["counts"]["discovered_urls"] == 2
    assert "https://c.example.test/" not in result["urls"]


def test_summarize_inventories_combines_deduplicated_urls_and_counters():
    first = AssetInventory()
    first.record_request("https://app.example.test/", method="GET", resource_type="document")
    second = AssetInventory()
    second.record_request("https://api.example.test/v1", method="GET", resource_type="xhr", api_like=True)

    result = summarize_inventories([first, second])
    assert result["counts"]["discovered_urls"] == 2
    assert result["counts"]["api_urls"] == 1
    assert result["method_counts"]["GET"] == 2
    assert result["resource_type_counts"]["document"] == 1
    assert result["resource_type_counts"]["xhr"] == 1
