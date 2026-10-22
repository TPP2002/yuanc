import json
from dataclasses import replace
from pathlib import Path

import pytest
from exitnode.proxy.context import ProxyContext, validate_context
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


def test_admin_route_uses_configured_listener(inputs):
    ctx, device = inputs
    config = render_server(replace(ctx, admin_bind="127.0.0.2", admin_port=9443), [device])
    assert config["route"]["rules"][0] == {
        "ip_cidr": ["198.18.255.1/32"], "outbound": "admin-local"}
    assert config["route"]["final"] == "direct"
    assert next(v for v in config["outbounds"] if v["tag"] == "admin-local") == {
        "type": "direct", "tag": "admin-local", "override_address": "127.0.0.2",
        "override_port": 9443}


def test_private_route_order_without_maintenance(inputs):
    ctx, device = inputs
    config = render_server(ctx, [device])
    assert config["route"] == {
        "rules": [
            {"ip_cidr": ["198.18.255.1/32"], "outbound": "admin-local"},
            {"ip_is_private": True, "outbound": "block"},
            {"ip_cidr": ["198.18.0.0/15"], "outbound": "block"},
        ],
        "final": "direct",
    }
    assert [outbound["tag"] for outbound in config["outbounds"]] == [
        "direct", "block", "admin-local"]


def test_maintenance_only_allows_active_registered_device_ssh(inputs):
    ctx, device = inputs
    revoked = replace(device, device_id="revoked", uuid="00000000-0000-4000-8000-000000000002",
                      revoked_at="2026-10-22T01:00:00+00:00")
    ctx = replace(ctx, maintenance_device_ids=("revoked", "missing", device.device_id))
    config = render_server(ctx, [revoked, device])
    assert config["route"] == {
        "rules": [
            {"ip_cidr": ["198.18.255.1/32"], "outbound": "admin-local"},
            {"auth_user": [device.device_id], "ip_is_private": True,
             "port": [22], "outbound": "direct"},
            {"ip_is_private": True, "outbound": "block"},
            {"ip_cidr": ["198.18.0.0/15"], "outbound": "block"},
        ],
        "final": "direct",
    }


def test_maintenance_users_sorted_and_inbound_names_match_devices(inputs):
    ctx, device = inputs
    other = replace(device, device_id="aaa", uuid="00000000-0000-4000-8000-000000000002",
                    hy2_password="TEST-ONLY-other-password")
    ctx = replace(ctx, maintenance_device_ids=(device.device_id, other.device_id))
    config = render_server(ctx, [device, other])
    assert config["route"]["rules"][1]["auth_user"] == [other.device_id, device.device_id]
    main, backup = config["inbounds"]
    assert main["users"] == [
        {"name": d.device_id, "uuid": d.uuid, "flow": "xtls-rprx-vision"}
        for d in (other, device)
    ]
    assert backup["users"] == [
        {"name": d.device_id, "password": d.hy2_password} for d in (other, device)
    ]


def test_unmatched_maintenance_has_no_auth_user_rule(inputs):
    ctx, device = inputs
    revoked = replace(device, device_id="revoked", uuid="00000000-0000-4000-8000-000000000002",
                      revoked_at="2026-10-22T01:00:00+00:00")
    ctx = replace(ctx, maintenance_device_ids=("revoked", "missing"))
    config = render_server(ctx, [device, revoked])
    assert not any("auth_user" in rule for rule in config["route"]["rules"])


@pytest.mark.parametrize("ids", [("",), ("same", "same"), (123,), (None,)])
def test_context_rejects_invalid_maintenance_ids(inputs, ids):
    ctx, _ = inputs
    with pytest.raises(ValueError, match="维护设备"):
        validate_context(replace(ctx, maintenance_device_ids=ids))
