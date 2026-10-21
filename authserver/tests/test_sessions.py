from datetime import datetime, timedelta

import pytest
from authserver.service import Problem


def issue(client, enrolled):
    return client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})


def test_session_credentials_and_config(client, enrolled, settings, app):
    response = issue(client, enrolled)
    assert response.status_code == 200
    body = response.json()
    assert body["account_expires_at"] == enrolled["expires_at"]
    assert body["session_token"] != enrolled["refresh_token"]
    assert datetime.fromisoformat(body["session_expires_at"]) == (
        app.state.service.clock() + timedelta(hours=6))
    node = body["node"]
    for field, value in settings.node.model_dump().items():
        assert node[field] == value
    assert node["uuid"] and len(node["hy2_password"]) >= 32
    config = body["singbox_config"]
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    assert not any(item["type"] == "direct" for item in config["outbounds"])
    assert outbounds["main"]["uuid"] == node["uuid"]
    assert outbounds["backup"]["password"] == node["hy2_password"]
    assert outbounds["main"]["tls"]["reality"]["public_key"] == node["reality_public_key"]
    assert outbounds["urltest"]["outbounds"] == ["main", "backup"]
    assert outbounds["block"]["type"] == "block"
    assert config["inbounds"][0]["type"] == "tun"
    assert config["inbounds"][0]["strict_route"] is True
    assert any(":" in address for address in config["inbounds"][0]["address"])
    assert {"ip_version": 6, "outbound": "block"} in config["route"]["rules"]
    assert config["route"]["final"] == "urltest"
    assert all(server["detour"] == "urltest" for server in config["dns"]["servers"])
    assert config["dns"]["strategy"] == "ipv4_only"
    assert response.headers["cache-control"] == "no-store"


def test_expired_account_boundary(client, enrolled, clock):
    clock.advance(days=30)
    response = issue(client, enrolled)
    assert response.status_code == 410
    assert "到期" in response.json()["detail"]


def test_disabled_account(client, enrolled, admin):
    prefix = "/admin/accounts/" + enrolled["account_id"]
    assert client.post(prefix + "/disable", headers=admin).status_code == 200
    assert issue(client, enrolled).status_code == 403
    assert client.post(prefix + "/enable", headers=admin).status_code == 200
    assert issue(client, enrolled).status_code == 200


def test_forged_token(client):
    response = client.post("/client/session", json={"refresh_token": "forged"})
    assert response.status_code == 401
    assert "令牌" in response.json()["detail"]


def test_six_hour_session_boundary(client, enrolled, clock, app):
    token = issue(client, enrolled).json()["session_token"]
    clock.advance(hours=6, microseconds=-1)
    assert app.state.service.authenticate_session(token)["id"] == enrolled["device_id"]
    clock.advance(microseconds=1)
    with pytest.raises(Problem) as error:
        app.state.service.authenticate_session(token)
    assert error.value.status == 401
    response = client.post("/client/logout", json={"session_token": token})
    assert response.status_code == 401
    # A refresh token can obtain a new session after the old session expires.
    assert issue(client, enrolled).status_code == 200


@pytest.mark.parametrize("token_field", ["session_token", "refresh_token"])
def test_logout_invalidates_credentials(client, enrolled, app, node_key, token_field):
    session = issue(client, enrolled).json()
    raw = session["session_token"] if token_field == "session_token" else enrolled["refresh_token"]
    assert client.post("/client/logout", json={token_field: raw}).status_code == 200
    assert issue(client, enrolled).status_code == 401
    with pytest.raises(Problem):
        app.state.service.authenticate_session(session["session_token"])
    assert client.get("/node/allowed", headers=node_key).json()["allowed"] == []
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert conn.execute("SELECT what FROM audit ORDER BY id DESC").fetchone()[0] == "client.logout"


def test_session_checks_account_on_every_use(client, enrolled, app, clock):
    clock.advance(days=29, hours=23)
    token = issue(client, enrolled).json()["session_token"]
    clock.advance(hours=1)
    with pytest.raises(Problem) as error:
        app.state.service.authenticate_session(token)
    assert error.value.status == 410
