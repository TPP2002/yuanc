from concurrent.futures import ThreadPoolExecutor


def test_device_limit_and_rollback(enrolled, invite, redeem, app):
    second = redeem(invite(), "device-two", enrolled["refresh_token"])
    assert second.status_code == 200
    assert second.json()["account_id"] == enrolled["account_id"]
    assert second.json()["device_id"] != enrolled["device_id"]
    code = invite()
    with app.state.service.db.transaction() as conn:
        before = dict(conn.execute("SELECT * FROM accounts").fetchone())
        audit_count = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    rejected = redeem(code, "device-three", enrolled["refresh_token"])
    assert rejected.status_code == 409
    assert "设备" in rejected.json()["detail"]
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
        assert dict(conn.execute("SELECT * FROM accounts").fetchone()) == before
        assert conn.execute("SELECT used FROM invites WHERE code = ?", (code,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == audit_count


def test_revoke_keeps_row_and_rejects_session(client, admin, enrolled, app, clock, invite, redeem):
    endpoint = "/admin/devices/" + enrolled["device_id"] + "/revoke"
    assert client.post(endpoint, headers=admin).status_code == 200
    response = client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})
    assert response.status_code == 423
    with app.state.service.db.transaction() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (enrolled["device_id"],)).fetchone()
        original_revoked_at = row["revoked_at"]
        assert row["revoked_at"] is not None
        assert row["refresh_token_hash"] is not None
    clock.advance(seconds=1)
    assert client.post(endpoint, headers=admin).status_code == 200
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT revoked_at FROM devices WHERE id = ?",
                            (enrolled["device_id"],)).fetchone()[0] == original_revoked_at
    assert redeem(invite(), token=enrolled["refresh_token"]).status_code == 423


def test_same_fingerprint_initial_retry_is_idempotent(invite, redeem, app, client):
    code = invite()
    first = redeem(code).json()
    response = redeem(code)
    assert response.status_code == 200
    second = response.json()
    for field in ("account_id", "device_id", "expires_at"):
        assert second[field] == first[field]
    assert second["refresh_token"] != first["refresh_token"]
    assert client.post("/client/session", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.post("/client/session", json={"refresh_token": second["refresh_token"]}).status_code == 200
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert conn.execute("SELECT used FROM invites").fetchone()[0] == 1


def test_concurrent_device_registration_respects_limit(enrolled, invite, redeem, app):
    codes = [invite(), invite()]
    def add(index):
        return redeem(codes[index], "other-" + str(index), enrolled["refresh_token"]).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(add, [0, 1]))
    assert sorted(results) == [200, 409]
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2
