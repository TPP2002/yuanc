from datetime import datetime


def test_node_auth_is_separate(client, admin, node_key):
    for path, method in (("/node/allowed", client.get), ("/node/heartbeat", client.post)):
        assert method(path).status_code == 401
        assert method(path, headers=admin).status_code == 401
        assert method(path, headers={"X-Node-Key": "wrong"}).status_code == 401
        assert method(path, headers=node_key).status_code == 200


def test_allowed_filters_and_matches_credentials(client, admin, node_key, invite, redeem, clock):
    active = redeem(invite(30), "active").json()
    expired = redeem(invite(1), "expired").json()
    disabled = redeem(invite(30), "disabled").json()
    revoked = redeem(invite(30), "revoked").json()
    original = client.get("/node/allowed", headers=node_key).json()
    assert len(original["allowed"]) == 4
    assert client.post("/admin/accounts/" + disabled["account_id"] + "/disable",
                       headers=admin).status_code == 200
    assert client.post("/admin/devices/" + revoked["device_id"] + "/revoke",
                       headers=admin).status_code == 200
    before_expiry = client.get("/node/allowed", headers=node_key).json()
    clock.advance(days=1)
    response = client.get("/node/allowed", headers=node_key).json()
    assert response["version"] != before_expiry["version"]
    assert response["version"] == client.get("/node/allowed", headers=node_key).json()["version"]
    assert len(response["allowed"]) == 1
    row = response["allowed"][0]
    assert set(row) == {"uuid", "hy2_password", "account_id", "device_id"}
    assert row["account_id"] == active["account_id"]
    assert row["device_id"] == active["device_id"]
    assert row["account_id"] != expired["account_id"]
    session = client.post("/client/session", json={"refresh_token": active["refresh_token"]}).json()
    assert row["uuid"] == session["node"]["uuid"]
    assert row["hy2_password"] == session["node"]["hy2_password"]


def test_heartbeat_persisted_and_audited(client, node_key, app, clock):
    first = client.post("/node/heartbeat", headers=node_key)
    assert first.status_code == 200
    clock.advance(seconds=60)
    response = client.post("/node/heartbeat", headers=node_key)
    assert response.status_code == 200
    with app.state.service.db.transaction() as conn:
        heartbeat = conn.execute("SELECT * FROM node_heartbeat").fetchone()
        assert datetime.fromisoformat(heartbeat["at"]) == clock()
        assert heartbeat["ip"] == "testclient"
        assert conn.execute("SELECT COUNT(*) FROM node_heartbeat").fetchone()[0] == 1
        audits = conn.execute("SELECT * FROM audit WHERE who = 'node'").fetchall()
        assert len(audits) == 2
        assert all(row["what"] == "node.heartbeat" for row in audits)
