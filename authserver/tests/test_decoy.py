import authserver.app as app_module


def assert_not_found(response):
    page = app_module.NOT_FOUND_PAGE
    expected = page.encode("utf-8") if isinstance(page, str) else page
    assert response.status_code == 404
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.content == expected
    assert b"detail" not in response.content.lower()
    assert b"fastapi" not in response.content.lower()
    assert response.headers["cache-control"] == "no-store"


def test_unknown_paths_and_documentation(client):
    for path in ("/docs", "/redoc", "/openapi.json", "/", "/favicon.ico", "/nope", "/admin"):
        assert_not_found(client.get(path))
    assert_not_found(client.post("/nope"))


def test_wrong_methods(client):
    for path in ("/client/session", "/client/redeem", "/admin/invites", "/node/heartbeat"):
        assert_not_found(client.get(path))
    assert_not_found(client.delete("/client/logout"))
    assert_not_found(client.post("/admin/accounts"))


def test_invalid_keys_are_identical_to_unknown_path(client, admin, node_key):
    baseline = client.get("/nope")
    expected = (baseline.status_code, baseline.headers["content-type"], baseline.content)
    cases = (
        ("GET", "/admin/accounts", ({}, {"X-Admin-Key": "wrong"},
                                     {"X-Admin-Key": node_key["X-Node-Key"]})),
        ("GET", "/node/allowed", ({}, {"X-Node-Key": "wrong"},
                                  {"X-Node-Key": admin["X-Admin-Key"]})),
        ("POST", "/node/heartbeat", ({}, {"X-Node-Key": "wrong"},
                                     {"X-Node-Key": admin["X-Admin-Key"]})),
    )
    for method, path, headers_cases in cases:
        for headers in headers_cases:
            response = client.request(method, path, headers=headers)
            assert_not_found(response)
            assert (response.status_code, response.headers["content-type"], response.content) == expected


def test_correct_keys_keep_json(client, admin, node_key):
    for path, headers in (("/admin/accounts", admin), ("/node/allowed", node_key)):
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")


def test_client_semantics_unchanged(client, enrolled, device):
    invalid = client.post("/client/session", json={"refresh_token": "fake"})
    assert invalid.status_code == 401
    assert invalid.headers["content-type"].startswith("application/json")
    assert "detail" in invalid.json()
    missing = client.post("/client/redeem", json={"code": "missing", "device": device})
    assert missing.status_code == 404
    assert missing.headers["content-type"].startswith("application/json")
    assert "detail" in missing.json()
    valid = client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})
    assert valid.status_code == 200
    assert valid.headers["content-type"].startswith("application/json")
