import json
from pathlib import Path

import pytest
from authserver.app import create_app
from authserver.config import Node, load_config


def write_config(tmp_path, settings, **changes):
    node = settings.node.model_dump(exclude={"hy2_certificate", "hy2_obfs_password"})
    node["hy2_certificate_path"] = settings.node.hy2_certificate_path
    node["hy2_obfs_password_path"] = settings.node.hy2_obfs_password_path
    node.update(changes)
    sections = {
        "security": {name: getattr(settings.security, name).get_secret_value()
                     for name in ("admin_key", "node_key", "token_salt")},
        "node": {k: v for k, v in node.items() if v is not None},
    }
    path = tmp_path / "auth.toml"
    path.write_text("\n".join(
        f"[{section}]\n" + "\n".join(f"{k} = {json.dumps(v)}" for k, v in values.items())
        for section, values in sections.items()), encoding="utf-8")
    return path


@pytest.mark.parametrize("failure", ["missing", "not_found", "permission", "encoding", "empty"])
def test_bad_certificate_prevents_startup(tmp_path, settings, monkeypatch, failure):
    cert = Path(settings.node.hy2_certificate_path)
    path = write_config(tmp_path, settings,
                        hy2_certificate_path=None if failure == "missing" else str(cert))
    if failure == "not_found":
        cert.unlink()
    elif failure == "permission":
        read = Path.read_text

        def denied(self, *args, **kwargs):
            if self == cert:
                raise PermissionError("MUST-NOT-ECHO-CERTIFICATE-CONTENT")
            return read(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", denied)
    elif failure == "encoding":
        cert.write_bytes(b"MUST-NOT-ECHO-CERTIFICATE-CONTENT\xff")
    elif failure == "empty":
        cert.write_text("\n   \n", encoding="utf-8")
    monkeypatch.setenv("AUTHSERVER_CONFIG", str(path))
    database = tmp_path / "must-not-create.sqlite3"
    with pytest.raises(ValueError, match="备用通道证书") as error:
        create_app(db_path=database)
    assert not database.exists()
    assert "MUST-NOT-ECHO" not in str(error.value)
    for field in ("admin_key", "node_key", "token_salt"):
        assert getattr(settings.security, field).get_secret_value() not in str(error.value)


def test_certificate_loaded_once_and_blank_lines_removed(tmp_path, settings):
    cert = Path(settings.node.hy2_certificate_path)
    lines = settings.node.hy2_certificate
    cert.write_text("\n\n".join(lines) + "\n   \n", encoding="utf-8")
    config = load_config(write_config(tmp_path, settings))
    assert config.node.hy2_certificate == lines
    assert config.node.hy2_server_name == "exitnode"
    cert.unlink()
    assert config.node.hy2_certificate == lines
    assert "hy2_certificate_path" not in config.node.model_dump()


def test_default_certificate_name(settings):
    values = settings.node.model_dump(
        exclude={"hy2_server_name", "hy2_certificate", "hy2_obfs_password"})
    values["hy2_certificate_path"] = settings.node.hy2_certificate_path
    assert Node.model_validate(values).hy2_server_name == "exitnode"


def test_session_has_eleven_node_keys_and_explicit_backup_trust(client, enrolled, settings):
    settings.node.hy2_server_name = "backup.example.test"
    response = client.post("/client/session", json={"refresh_token": enrolled["refresh_token"]})
    assert response.status_code == 200
    body = response.json()
    node = body["node"]
    assert set(node) == {"host", "reality_port", "hy2_port", "sni", "reality_public_key",
                         "short_id", "uuid", "hy2_password", "hy2_server_name", "hy2_certificate",
                         "hy2_obfs_password"}
    assert node["hy2_certificate"] == settings.node.hy2_certificate
    backup = next(o for o in body["singbox_config"]["outbounds"] if o["type"] == "hysteria2")
    assert backup["tls"] == {"enabled": True, "server_name": "backup.example.test",
                              "certificate": settings.node.hy2_certificate}
    assert "hy2_certificate_path" not in response.text
    assert "hy2_obfs_password_path" not in response.text
