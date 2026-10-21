"""Cross-package contract: pairing and authenticated sessions carry identical TLS inputs."""

import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from authserver.app import DeviceInput
from authserver.clientconfig import render
from authserver.config import Settings
from authserver.db import Database
from authserver.service import Service
from exitnode.device import render_pair
from exitnode.proxy.client_config import render_client_windows
from exitnode.proxy.context import ProxyContext
from exitnode.proxy.keys import RealityKeys
from exitnode.proxy.registry import Device
from exitnode.proxy.server_config import render_server
from exitnode.proxy.subscription import vless_link


def test_pair_session_and_tls_parity(tmp_path):
    data = json.loads((Path(__file__).parent / "golden/proxy/inputs.json").read_text("utf-8"))
    values = data["context"]
    values["reality"] = RealityKeys(**values["reality"])
    ctx = ProxyContext(**values)
    device = Device(**data["device"])
    # Distinct names and a non-default port detect accidental reuse of SNI or 443.
    ctx = replace(ctx, reality_port=14443, hy2_server_name="backup.example.test")
    pair = render_pair(ctx, device, ctx.server_host, device.created_at)
    cert = tmp_path / "hy2.crt"
    cert.write_text("\n".join(ctx.hy2_certificate), encoding="utf-8")
    settings = Settings.model_validate({
        "security": {"admin_key": "test-admin", "node_key": "test-node", "token_salt": "test-salt"},
        "node": {k: v for k, v in pair["node"].items()
                 if k not in {"uuid", "hy2_password", "hy2_certificate"}}
                | {"hy2_certificate_path": str(cert)},
    })
    db = Database(tmp_path / "auth.sqlite3")
    db.initialize()
    service = Service(db, settings)
    invite = service.create_invite(30)
    enrolled = service.redeem(invite["code"], DeviceInput(
        platform="windows", name="test", fingerprint="parity-test",
    ))
    session = service.session(enrolled["refresh_token"])
    expected = {"host", "reality_port", "hy2_port", "sni", "reality_public_key", "short_id",
                "uuid", "hy2_password", "hy2_server_name", "hy2_certificate"}
    assert set(pair["node"]) == set(session["node"]) == expected
    assert pair["format"] == "ycpair/2"
    client = render_client_windows(ctx, device)
    auth = render(session["node"], session["node"])
    assert client["outbounds"][1]["tls"] == auth["outbounds"][1]["tls"] == {
        "enabled": True, "server_name": ctx.hy2_server_name,
        "certificate": list(ctx.hy2_certificate),
    }
    assert client["outbounds"][0]["server_port"] == 14443
    assert urlsplit(vless_link(ctx, device)).port == 14443
    assert render_server(ctx, [device])["inbounds"][0]["listen_port"] == 14443
    assert pair["node"]["reality_port"] == 14443
