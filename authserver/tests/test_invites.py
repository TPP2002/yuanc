import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from authserver.admin_cli import main


@pytest.mark.parametrize("days", [1, 7, 30, 43])
def test_create_and_redeem_days(days, client, admin, device, clock):
    response = client.post("/admin/invites", headers=admin,
                           json={"days": days, "max_uses": 1, "note": "送给朋友"})
    assert response.status_code == 200
    code = response.json()["code"]
    assert re.fullmatch(r"[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){2}", code)
    clock.advance(minutes=17)
    response = client.post("/client/redeem", json={"code": code, "device": device})
    assert response.status_code == 200
    account = response.json()
    assert datetime.fromisoformat(account["expires_at"]) == clock() + timedelta(days=days)
    assert account["account_id"] and account["device_id"] and account["refresh_token"]
    stored = client.get("/admin/accounts/" + account["account_id"], headers=admin).json()
    assert stored["expires_at"] == account["expires_at"]
    assert stored["device_limit"] == 2


@pytest.mark.parametrize("headers", [{}, {"X-Admin-Key": "wrong"}, {"X-Node-Key": "test-node-only"}])
def test_admin_requires_own_key(client, headers):
    response = client.post("/admin/invites", headers=headers, json={"days": 1})
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    for path in ("accounts", "devices", "audit"):
        response = client.get("/admin/" + path, headers=headers)
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("body", [{"days": 0}, {"days": -1}, {"days": True},
                                  {"days": "7"}, {"days": 7, "max_uses": 0}])
def test_parameters_chinese(client, admin, body):
    response = client.post("/admin/invites", headers=admin, json=body)
    assert response.status_code == 422
    assert "参数" in response.json()["detail"]


def test_exhausted_and_unknown(invite, redeem):
    code = invite(uses=2)
    assert redeem(code, "first").status_code == 200
    assert redeem(code, "second").status_code == 200
    exhausted = redeem(code, "third")
    assert exhausted.status_code == 409  # 固定契约：次数用完 = 409。
    assert "次数" in exhausted.json()["detail"]
    assert redeem("DOES-NOT-EXIST").status_code == 404


def test_renewal_adds_to_existing_expiry(enrolled, invite, redeem, clock, app):
    clock.advance(days=5)
    code = invite(days=7)
    renewal = redeem(code, token=enrolled["refresh_token"])
    assert renewal.status_code == 200
    result = renewal.json()
    assert result["account_id"] == enrolled["account_id"]
    assert result["device_id"] == enrolled["device_id"]
    assert datetime.fromisoformat(result["expires_at"]) == (
        datetime.fromisoformat(enrolled["expires_at"]) + timedelta(days=7))
    # A network retry must not spend another use or extend twice.
    repeated = redeem(code, token=enrolled["refresh_token"])
    assert repeated.status_code == 200
    assert repeated.json() == result
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT used FROM invites WHERE code = ?", (code,)).fetchone()[0] == 1


def test_expired_account_can_redeem_to_extend(invite, redeem, clock):
    initial = redeem(invite(days=1)).json()
    clock.advance(days=2)
    result = redeem(invite(days=7), token=initial["refresh_token"])
    assert result.status_code == 200
    assert datetime.fromisoformat(result.json()["expires_at"]) == clock() + timedelta(days=7)


def test_long_expired_account_redeem_counts_from_now(client, invite, redeem, clock):
    initial = redeem(invite(days=1)).json()
    clock.advance(days=10)
    result = redeem(invite(days=7), token=initial["refresh_token"])
    assert result.status_code == 200
    assert datetime.fromisoformat(result.json()["expires_at"]) == clock() + timedelta(days=7)
    session = client.post("/client/session",
                          json={"refresh_token": result.json()["refresh_token"]})
    assert session.status_code == 200


def test_admin_extend_expired_account_counts_from_now(client, admin, enrolled, clock):
    clock.advance(days=40)
    changed = client.post("/admin/accounts/" + enrolled["account_id"] + "/extend",
                          headers=admin, json={"days": 3})
    assert changed.status_code == 200
    assert datetime.fromisoformat(changed.json()["expires_at"]) == clock() + timedelta(days=3)


def test_concurrent_last_use_cannot_overspend(invite, redeem, app):
    code = invite(uses=1)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda fp: redeem(code, fp).status_code, ["a", "b"]))
    assert sorted(results) == [200, 409]
    with app.state.service.db.transaction() as conn:
        assert conn.execute("SELECT used FROM invites WHERE code = ?", (code,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1


def test_admin_extend_disable_enable_and_audit(client, admin, enrolled, app):
    prefix = "/admin/accounts/" + enrolled["account_id"]
    changed = client.post(prefix + "/extend", headers=admin, json={"days": 3})
    assert changed.status_code == 200
    assert datetime.fromisoformat(changed.json()["expires_at"]) == (
        datetime.fromisoformat(enrolled["expires_at"]) + timedelta(days=3))
    assert client.post(prefix + "/disable", headers=admin).json()["status"] == "disabled"
    assert client.post(prefix + "/enable", headers=admin).json()["status"] == "active"
    assert client.get("/admin/accounts/missing", headers=admin).status_code == 404
    entries = client.get("/admin/audit", headers=admin).json()
    for action in ("invite.create", "account.extend", "account.disable", "account.enable"):
        assert any(row["what"].startswith(action) and row["who"] == "admin" for row in entries)
    assert all(row["at"].endswith("+00:00") and row["ip"] for row in entries)
    # Initializing again must preserve the database and audit history.
    app.state.service.db.initialize()
    assert client.get("/admin/audit", headers=admin).json() == entries


def test_offline_cli(tmp_path, app, enrolled, capsys, settings):
    config = tmp_path / "config.toml"
    config.write_text('''[security]
admin_key = "test-admin-only"
node_key = "test-node-only"
token_salt = "test-salt-only"
[node]
host = "192.0.2.23"
reality_port = 443
hy2_port = 24443
reality_public_key = "test-public-key"
short_id = "abcd1234"
sni = "example.test"
''' + 'hy2_certificate_path = ' + json.dumps(settings.node.hy2_certificate_path) + '\n',
                      encoding="utf-8")
    args = ["--config", str(config), "--db", app.state.service.db.path]
    assert main(args + ["invite", "--days", "30", "--uses", "2", "--note", "离线"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["days"] == 30 and output["max_uses"] == 2 and output["note"] == "离线"
    assert main(args + ["accounts"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == enrolled["account_id"]
    assert main(args + ["devices"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["id"] == enrolled["device_id"]
    assert main(args + ["extend", enrolled["account_id"], "--days", "5"]) == 0
    assert datetime.fromisoformat(json.loads(capsys.readouterr().out)["expires_at"]) == (
        datetime.fromisoformat(enrolled["expires_at"]) + timedelta(days=5))
    assert main(args + ["revoke", enrolled["device_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["revoked"] is True
