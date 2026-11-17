import hashlib
import logging

import pytest
from authserver.app import create_app
from authserver.config import Settings, load_config
from authserver.security import hash_token
from fastapi.testclient import TestClient


def test_database_has_no_plaintext_tokens_or_keys(client, enrolled, app, settings):
    response = client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})
    assert response.status_code == 200
    session = response.json()
    with app.state.service.db.transaction() as conn:
        dump = "\n".join(conn.iterdump())
        salt = settings.security.token_salt.get_secret_value()
        stored_refresh = conn.execute("SELECT refresh_token_hash FROM devices").fetchone()[0]
        stored_session = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored_refresh == hashlib.sha256((salt + enrolled["refresh_token"]).encode()).hexdigest()
    assert stored_session == hash_token(session["session_token"], salt)
    with open(app.state.service.db.path, "rb") as database_file:
        database_bytes = database_file.read()
    for secret in (enrolled["refresh_token"], session["session_token"],
                   session["node"]["hy2_password"], salt,
                   settings.security.admin_key.get_secret_value(),
                   settings.security.node_key.get_secret_value()):
        assert secret not in dump
        assert secret.encode() not in database_bytes


@pytest.mark.parametrize("missing", ["admin_key", "node_key", "token_salt"])
def test_missing_security_fails_startup(tmp_path, monkeypatch, missing):
    config = tmp_path / "bad.toml"
    values = {"admin_key": "only-test-admin", "node_key": "only-test-node",
              "token_salt": "only-test-salt"}
    del values[missing]
    config.write_text("[security]\n" + "\n".join(f'{k} = "{v}"' for k, v in values.items()),
                      encoding="utf-8")
    monkeypatch.setenv("AUTHSERVER_CONFIG", str(config))
    with pytest.raises(ValueError, match="配置无效") as error:
        create_app(db_path=tmp_path / "never.sqlite3")
    assert not (tmp_path / "never.sqlite3").exists()
    assert not any(secret in str(error.value) for secret in values.values())


def test_missing_config_path_fails(monkeypatch):
    monkeypatch.delenv("AUTHSERVER_CONFIG", raising=False)
    with pytest.raises(ValueError, match="AUTHSERVER_CONFIG"):
        create_app()


def test_example_cannot_be_started():
    from pathlib import Path

    path = Path(__file__).parents[1] / "examples" / "config.example.toml"
    with pytest.raises(ValueError, match="配置无效"):
        load_config(path)


def test_redeem_ip_limit_and_window_reset(client, device, clock):
    for index in range(10):
        response = client.post("/client/redeem", json={"code": "missing", "device": device},
                               headers={"X-Forwarded-For": "198.51.100." + str(index)})
        assert response.status_code == 404
    response = client.post("/client/redeem", json={"code": "missing", "device": device})
    assert response.status_code == 429
    assert "频繁" in response.json()["detail"]
    assert response.headers["retry-after"] == "3600"
    clock.advance(hours=1)
    assert client.post("/client/redeem", json={"code": "missing", "device": device}).status_code == 404


def test_session_ip_limit(client, enrolled):
    for _ in range(10):
        assert client.post("/client/session", json={"refresh_token": "fake"}).status_code == 401
    assert client.post("/client/session",
                       json={"refresh_token": enrolled["refresh_token"]}).status_code == 200


def test_session_limit_is_separate_and_configurable(tmp_path, settings, clock, device):
    values = {
        "security": {name: getattr(settings.security, name).get_secret_value()
                     for name in ("admin_key", "node_key", "token_salt")},
        "node": {
            **settings.node.model_dump(exclude={"hy2_certificate", "hy2_obfs_password"}),
            "hy2_certificate_path": settings.node.hy2_certificate_path,
            "hy2_obfs_password_path": settings.node.hy2_obfs_password_path,
        },
        "limits": {"session_per_ip_per_hour": 3},
    }
    custom = Settings.model_validate(values)
    with TestClient(create_app(custom, tmp_path / "limited.sqlite3", clock)) as limited_client:
        admin = {"X-Admin-Key": custom.security.admin_key.get_secret_value()}
        code = limited_client.post("/admin/invites", headers=admin,
                                   json={"days": 30}).json()["code"]
        enrolled = limited_client.post(
            "/client/redeem", json={"code": code, "device": device}).json()
        for _ in range(3):
            response = limited_client.post("/client/session",
                                           json={"refresh_token": enrolled["refresh_token"]})
            assert response.status_code == 200
        blocked = limited_client.post("/client/session",
                                      json={"refresh_token": enrolled["refresh_token"]})
        assert blocked.status_code == 429
        assert blocked.headers["retry-after"] == "3600"
        assert "频繁" in blocked.json()["detail"]
        assert limited_client.post("/client/redeem",
                                   json={"code": "missing", "device": device}).status_code == 404


def test_logs_and_validation_do_not_echo_tokens(client, enrolled, caplog, device):
    caplog.set_level(logging.DEBUG)
    response = client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})
    assert response.status_code == 200
    session_token = response.json()["session_token"]
    invalid = client.post("/client/session", json={"refresh_token": {"raw": enrolled["refresh_token"]}})
    assert invalid.status_code == 422
    assert enrolled["refresh_token"] not in invalid.text
    invalid = client.post("/client/logout", json={"session_token": session_token,
                                                 "refresh_token": enrolled["refresh_token"]})
    assert invalid.status_code == 422
    assert session_token not in invalid.text
    assert client.post("/client/redeem", json={"code": "missing", "device": device,
                                             "refresh_token": enrolled["refresh_token"]}).status_code == 404
    assert enrolled["refresh_token"] not in caplog.text
    assert session_token not in caplog.text


def test_empty_supplied_refresh_is_not_initial_redemption(invite, redeem, app):
    code = invite()
    assert redeem(code, token="").status_code == 401
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
