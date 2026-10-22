import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from authserver.app import create_app
from authserver.config import Settings
from fastapi.testclient import TestClient


class Clock:
    def __init__(self):
        self.value = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.value

    def advance(self, **kwargs):
        self.value += timedelta(**kwargs)


@pytest.fixture
def settings(tmp_path):
    vector = json.loads((Path(__file__).parents[2] / "node/tests/golden/proxy/inputs.json")
                        .read_text(encoding="utf-8"))
    certificate = tmp_path / "hy2.crt"
    certificate.write_text("\n".join(vector["context"]["hy2_certificate"]), encoding="utf-8")
    # 节点 secrets/hy2.obfs 的测试副本；与节点黄金输入同一个测试向量。
    obfs = tmp_path / "hy2.obfs"
    obfs.write_text(vector["context"]["hy2_obfs_password"] + "\n", encoding="utf-8")
    return Settings.model_validate({
        "security": {"admin_key": "test-admin-only", "node_key": "test-node-only",
                     "token_salt": "test-salt-only"},
        "node": {"host": "192.0.2.23", "reality_port": 443, "hy2_port": 24443,
                 "reality_public_key": "test-public-key", "short_id": "abcd1234",
                 "sni": "example.test", "hy2_certificate_path": str(certificate),
                 "hy2_obfs_password_path": str(obfs)},
    })


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(tmp_path, settings, clock):
    return create_app(settings, tmp_path / "auth.sqlite3", clock)


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


@pytest.fixture
def admin(settings):
    return {"X-Admin-Key": settings.security.admin_key.get_secret_value()}


@pytest.fixture
def node_key(settings):
    return {"X-Node-Key": settings.security.node_key.get_secret_value()}


@pytest.fixture
def device():
    return {"platform": "windows", "name": "测试电脑", "fingerprint": "device-one"}


@pytest.fixture
def invite(client, admin):
    def make(days=30, uses=1, note="测试"):
        response = client.post("/admin/invites", headers=admin,
                               json={"days": days, "max_uses": uses, "note": note})
        assert response.status_code == 200, response.text
        return response.json()["code"]
    return make


@pytest.fixture
def redeem(client, device):
    def perform(code, fingerprint=None, token=None):
        info = dict(device)
        if fingerprint is not None:
            info["fingerprint"] = fingerprint
        body = {"code": code, "device": info}
        if token is not None:
            body["refresh_token"] = token
        return client.post("/client/redeem", json=body)
    return perform


@pytest.fixture
def enrolled(invite, redeem):
    result = redeem(invite())
    assert result.status_code == 200, result.text
    return result.json()
