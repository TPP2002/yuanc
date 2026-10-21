import json
from dataclasses import replace
from pathlib import Path

import pytest
from exitnode.proxy.context import ProxyContext
from exitnode.proxy.keys import RealityKeys
from exitnode.proxy.registry import Device
from exitnode.proxy.server_config import render_server

GOLDEN = Path(__file__).parent / "golden" / "proxy"


@pytest.fixture
def inputs():
    data = json.loads((GOLDEN / "inputs.json").read_text(encoding="utf-8"))
    ctx = data["context"]
    ctx["reality"] = RealityKeys(**ctx["reality"])
    return ProxyContext(**ctx), Device(**data["device"])


def test_server_exact_golden_and_revoked_exclusion(inputs):
    ctx, device = inputs
    revoked = replace(device, device_id="old", uuid="00000000-0000-4000-8000-000000000002",
                      revoked_at="2026-10-22T01:00:00+00:00")
    config = render_server(ctx, [device, revoked])
    actual = {"_comment": "测试向量,不是真凭据", **config}
    assert json.dumps(actual, ensure_ascii=False, indent=2) + "\n" == (
        GOLDEN / "server.json"
    ).read_text(encoding="utf-8")
    main, backup = config["inbounds"]
    assert (main["type"], main["listen_port"]) == ("vless", 443)
    assert main["tls"]["reality"]["enabled"] is True
    assert backup["type"] == "hysteria2"
    assert revoked.uuid not in json.dumps(config)
    assert backup["users"] == [{"name": device.device_id, "password": device.hy2_password}]
    assert config["log"] == {"disabled": True}


def test_server_custom_targets_and_certificate_paths(inputs):
    ctx, device = inputs
    ctx = replace(ctx, sni="cover.example", handshake_server="handshake.example",
                  hy2_port=34567, masquerade="https://cover.example",
                  hy2_certificate_path="/srv/secrets/tls.crt", hy2_key_path="/srv/secrets/tls.key")
    main, backup = render_server(ctx, [device])["inbounds"]
    assert main["tls"]["server_name"] == "cover.example"
    assert main["tls"]["reality"]["handshake"]["server"] == "handshake.example"
    assert backup["listen_port"] == 34567
    assert backup["masquerade"] == "https://cover.example"
    assert backup["tls"]["key_path"] == "/srv/secrets/tls.key"
    with pytest.raises(ValueError, match="secrets"):
        render_server(replace(ctx, hy2_key_path="/public/key.pem"), [device])


def test_empty_allowlist_has_no_users(inputs):
    ctx, _ = inputs
    assert all(not inbound["users"] for inbound in render_server(ctx, [])["inbounds"])
