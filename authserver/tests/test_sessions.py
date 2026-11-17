import re
from datetime import datetime, timedelta

import pytest
from authserver.app import create_app
from authserver.config import Settings
from authserver.service import Problem
from fastapi.testclient import TestClient


def issue(client, enrolled):
    return client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})


def test_node_environment_defaults_empty(settings):
    assert settings.node.time_zone == ""
    assert settings.node.country == ""


@pytest.mark.parametrize("zone,country", [("Australia/Perth", "AU"), ("", "")])
def test_session_node_environment_fields(client, enrolled, settings, app, zone, country):
    app.state.service.settings = Settings.model_validate(node_values(settings, time_zone=zone, country=country))
    response = issue(client, enrolled)
    assert response.status_code == 200
    body = response.json()
    assert body["node"]["time_zone"] == zone
    assert body["node"]["country"] == country


@pytest.mark.parametrize("field,value,reason", [
    ("time_zone", "bad;zone", "时区"),
    ("time_zone", "a" * 65, "时区"),
    ("country", "au", "国家码"),
    ("country", "AUS", "国家码"),
])
def test_invalid_node_environment_config(settings, field, value, reason):
    with pytest.raises(ValueError, match=reason):
        Settings.model_validate(node_values(settings, **{field: value}))


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
    assert "singbox_config" not in body
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


def test_expired_sessions_are_pruned(client, enrolled, clock, app):
    assert issue(client, enrolled).status_code == 200
    clock.advance(hours=7)
    assert issue(client, enrolled).status_code == 200
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


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


OBFS_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}")


def node_values(settings, **changes):
    values = settings.node.model_dump(exclude={"hy2_certificate", "hy2_obfs_password"})
    values["hy2_certificate_path"] = settings.node.hy2_certificate_path
    values["hy2_obfs_password_path"] = settings.node.hy2_obfs_password_path
    values.update(changes)
    return {
        "security": {name: getattr(settings.security, name).get_secret_value()
                     for name in ("admin_key", "node_key", "token_salt")},
        "node": values,
    }


def test_session_carries_obfs_password_into_node_and_backup(client, enrolled, settings):
    body = issue(client, enrolled).json()
    password = body["node"]["hy2_obfs_password"]
    assert OBFS_PATTERN.fullmatch(password)
    assert password == settings.node.hy2_obfs_password
    assert password not in repr(settings) and password not in repr(settings.node)


def test_empty_obfs_path_sends_empty_password_and_no_obfs(tmp_path, settings, clock, device):
    plain = Settings.model_validate(node_values(settings, hy2_obfs_password_path=""))
    assert plain.node.hy2_obfs_password == ""
    with TestClient(create_app(plain, tmp_path / "plain.sqlite3", clock)) as client:
        admin = {"X-Admin-Key": plain.security.admin_key.get_secret_value()}
        code = client.post("/admin/invites", headers=admin,
                           json={"days": 30, "max_uses": 1, "note": "测试"}).json()["code"]
        enrolled = client.post("/client/redeem", json={"code": code, "device": device}).json()
        body = issue(client, enrolled).json()
    assert body["node"]["hy2_obfs_password"] == ""


@pytest.mark.parametrize("content", [None, "", "   \n", "has space 0123456789", "a" * 15,
                                     "a" * 129, "with=equals-0123456789"])
def test_bad_obfs_file_rejects_settings(tmp_path, settings, content):
    path = tmp_path / "bad.obfs"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="混淆") as error:
        Settings.model_validate(node_values(settings, hy2_obfs_password_path=str(path)))
    assert str(path) in str(error.value)
    if content and content.strip():
        assert content.strip() not in str(error.value)
