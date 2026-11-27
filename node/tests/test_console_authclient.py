import base64
import datetime
import hashlib
import json
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from exitnode.console.authclient import AuthClient, AuthError

ADMIN_KEY = "test-admin-only"


def fake_transport(status=200, payload=b"", content_type="application/json"):
    calls = []

    def send(method, path, body, headers):
        calls.append({"method": method, "path": path, "body": body, "headers": dict(headers)})
        if isinstance(payload, bytes):
            data = payload
        else:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return status, content_type, data

    return send, calls


ACCOUNT = {"id": "acc-1", "invite_code": "ABC", "status": "active",
           "expires_at": "2026-12-01T00:00:00+00:00", "device_limit": 2,
           "created_at": "2026-11-01T00:00:00+00:00"}
DEVICE = {"id": "dev-1", "account_id": "acc-1", "platform": "windows", "name": "测试电脑",
          "last_seen": "2026-11-01T00:00:00+00:00", "revoked_at": None}


def test_maps_success_and_whitelists_fields():
    send, calls = fake_transport(payload=[
        {"code": "ABC", "days": 30, "max_uses": 2, "used": 1, "note": "备注",
         "created_at": "2026-11-01T00:00:00+00:00", "created_by": "admin"}])
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.invites() == [{"code": "ABC", "days": 30, "max_uses": 2, "used": 1,
                                 "note": "备注", "created_at": "2026-11-01T00:00:00+00:00"}]
    assert calls[0]["method"] == "GET" and calls[0]["path"] == "/admin/invites"
    assert calls[0]["headers"]["X-Admin-Key"] == ADMIN_KEY

    send, calls = fake_transport(payload={
        "code": "NEW", "days": 7, "max_uses": 1, "used": 0, "note": "",
        "created_at": "2026-11-01T00:00:00+00:00", "created_by": "admin"})
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.create_invite(7, 1, "给朋友") == {
        "code": "NEW", "days": 7, "max_uses": 1, "used": 0, "note": ""}
    assert json.loads(calls[0]["body"]) == {"days": 7, "max_uses": 1, "note": "给朋友"}
    assert calls[0]["headers"]["Content-Type"] == "application/json"

    send, calls = fake_transport(payload=[dict(ACCOUNT, devices=[])])
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.accounts() == [ACCOUNT]
    assert calls[0]["path"] == "/admin/accounts"

    send, calls = fake_transport(payload=[DEVICE])
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.devices() == [DEVICE]
    assert calls[0]["path"] == "/admin/devices"

    send, calls = fake_transport(payload=dict(ACCOUNT, extra="x"))
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.account_action("acc-1", "extend", 7) == ACCOUNT
    assert calls[0]["path"] == "/admin/accounts/acc-1/extend"
    assert json.loads(calls[0]["body"]) == {"days": 7}

    for action in ("disable", "enable"):
        send, calls = fake_transport(payload=ACCOUNT)
        client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
        assert client.account_action("acc-1", action) == ACCOUNT
        assert calls[0]["path"] == f"/admin/accounts/acc-1/{action}"
        assert calls[0]["body"] is None

    send, calls = fake_transport(payload={"device_id": "dev-1", "revoked": True, "extra": 1})
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    assert client.revoke("dev-1") == {"device_id": "dev-1", "revoked": True}
    assert calls[0]["path"] == "/admin/devices/dev-1/revoke"
    assert calls[0]["body"] is None


def test_decoy_404_means_key_rejected():
    send, _ = fake_transport(status=404, payload=b"<!DOCTYPE html><html></html>",
                             content_type="text/html; charset=utf-8")
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.status == 502
    assert error.value.code == "admin_key_rejected"
    assert "管理密钥" in str(error.value)
    assert ADMIN_KEY not in str(error.value)


def test_json_error_passes_detail_through():
    send, _ = fake_transport(status=404, payload={"detail": "账号不存在"},
                             content_type="application/json")
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=send)
    with pytest.raises(AuthError) as error:
        client.account_action("missing", "extend", 3)
    assert (error.value.status, error.value.code, error.value.detail) == (
        404, "authserver_error", "账号不存在")
    assert str(error.value) == "账号不存在"


def test_unreachable_and_bad_response():
    def explode(method, path, body, headers):
        raise OSError("connection refused")

    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=explode)
    with pytest.raises(AuthError) as error:
        client.invites()
    assert (error.value.status, error.value.code) == (502, "authserver_unreachable")

    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY,
                        transport=fake_transport(payload=b"not json")[0])
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.code == "authserver_bad_response"

    big = b"x" * (4194304 + 1)
    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY,
                        transport=fake_transport(payload=big)[0])
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.code == "authserver_bad_response"

    client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY,
                        transport=fake_transport(payload=["not-a-row"])[0])
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.code == "authserver_bad_response"

    # 真连一个没人听的端口。
    client = AuthClient("http://127.0.0.1:1", "", ADMIN_KEY)
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.code == "authserver_unreachable"


def test_admin_key_never_in_errors():
    cases = (
        fake_transport(status=404, payload=b"<html></html>", content_type="text/html")[0],
        fake_transport(status=500, payload=b"boom", content_type="text/plain")[0],
        fake_transport(status=400, payload={"detail": "天数必须为正整数"},
                       content_type="application/json")[0],
    )
    for transport in cases:
        client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=transport)
        with pytest.raises(AuthError) as error:
            client.create_invite(1, 1, "")
        assert ADMIN_KEY not in str(error.value)
        assert ADMIN_KEY not in repr(error.value)
        assert ADMIN_KEY not in (error.value.detail or "")


def make_certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return cert_path, key_path, pin


class OneShotServer(threading.Thread):
    """在 127.0.0.1 上跑一次 TLS 握手并记录应用层收到的字节数。"""

    payload = b"[]"

    def __init__(self, cert_path, key_path):
        super().__init__(daemon=True)
        self.received = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        self.context = context
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]

    def run(self):
        try:
            raw, _ = self.listener.accept()
            try:
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    connection.settimeout(5)
                    data = connection.recv(65536)
                    self.received = len(data)
                    if not data:
                        return
                    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: " + str(len(self.payload)).encode("ascii")
                            + b"\r\nConnection: close\r\n\r\n")
                    connection.sendall(head + self.payload)
            except (OSError, ssl.SSLError):
                pass
        finally:
            self.listener.close()


def test_https_pin_accepts_match_and_rejects_mismatch_before_sending(tmp_path):
    cert_path, key_path, pin = make_certificate(tmp_path)

    server = OneShotServer(cert_path, key_path)
    server.start()
    client = AuthClient(f"https://127.0.0.1:{server.port}", pin, ADMIN_KEY)
    assert client.invites() == []
    server.join(5)
    assert server.received > 0

    server = OneShotServer(cert_path, key_path)
    server.start()
    client = AuthClient(f"https://127.0.0.1:{server.port}", "A" * 43 + "=", ADMIN_KEY)
    with pytest.raises(AuthError) as error:
        client.invites()
    assert error.value.code == "authserver_pin_mismatch"
    assert ADMIN_KEY not in str(error.value)
    server.join(5)
    # 指纹不对时必须在发出任何请求字节之前断开。
    assert server.received == 0


class RealClock:
    def __init__(self):
        self.value = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=datetime.UTC)

    def __call__(self):
        return self.value


def test_against_real_authserver_app(tmp_path):
    from authserver.app import create_app
    from authserver.config import Settings
    from fastapi.testclient import TestClient

    vector = json.loads((Path(__file__).parents[2] / "node/tests/golden/proxy/inputs.json")
                        .read_text(encoding="utf-8"))
    certificate = tmp_path / "hy2.crt"
    certificate.write_text("\n".join(vector["context"]["hy2_certificate"]), encoding="utf-8")
    obfs = tmp_path / "hy2.obfs"
    obfs.write_text(vector["context"]["hy2_obfs_password"] + "\n", encoding="utf-8")
    settings = Settings.model_validate({
        "security": {"admin_key": ADMIN_KEY, "node_key": "test-node-only",
                     "token_salt": "test-salt-only"},
        "node": {"host": "192.0.2.23", "reality_port": 443, "hy2_port": 24443,
                 "reality_public_key": "test-public-key", "short_id": "abcd1234",
                 "sni": "example.test", "hy2_certificate_path": str(certificate),
                 "hy2_obfs_password_path": str(obfs)},
    })
    app = create_app(settings, tmp_path / "auth.sqlite3", RealClock())
    with TestClient(app) as api:
        def transport(method, path, body, headers):
            response = api.request(method, path, content=body, headers=headers)
            return (response.status_code, response.headers.get("content-type", ""),
                    response.content)

        client = AuthClient("http://127.0.0.1:8000", "", ADMIN_KEY, transport=transport)
        invite = client.create_invite(30, 1, "测试")
        assert set(invite) == {"code", "days", "max_uses", "used", "note"}
        assert client.invites()[0]["code"] == invite["code"]
        redeemed = api.post("/client/redeem", json={
            "code": invite["code"],
            "device": {"platform": "windows", "name": "测试电脑", "fingerprint": "device-one"}})
        assert redeemed.status_code == 200, redeemed.text
        account_id = redeemed.json()["account_id"]
        assert client.accounts()[0]["id"] == account_id
        device_id = client.devices()[0]["id"]
        assert client.account_action(account_id, "extend", 5)["id"] == account_id
        assert client.account_action(account_id, "disable")["status"] == "disabled"
        assert client.account_action(account_id, "enable")["status"] == "active"
        assert client.revoke(device_id) == {"device_id": device_id, "revoked": True}
