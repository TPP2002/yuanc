import json
from dataclasses import replace
from pathlib import Path

import pytest
from exitnode.proxy.client_config import render_client_windows
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
    ctx = replace(ctx, sni="cover.example", handshake_server="cover.example",
                  hy2_port=34567, masquerade="https://cover.example",
                  hy2_certificate_path="/srv/secrets/tls.crt", hy2_key_path="/srv/secrets/tls.key")
    main, backup = render_server(ctx, [device])["inbounds"]
    assert main["tls"]["server_name"] == "cover.example"
    assert main["tls"]["reality"]["handshake"]["server"] == "cover.example"
    assert backup["listen_port"] == 34567
    assert backup["masquerade"] == "https://cover.example"
    assert backup["tls"]["key_path"] == "/srv/secrets/tls.key"
    with pytest.raises(ValueError, match="secrets"):
        render_server(replace(ctx, hy2_key_path="/public/key.pem"), [device])


def test_camouflage_target_and_handshake_must_match(inputs):
    ctx, device = inputs
    mismatched = replace(ctx, sni="cover.example", handshake_server="handshake.example")
    with pytest.raises(ValueError, match="必须相同"):
        validate_context(mismatched)
    with pytest.raises(ValueError, match="必须相同"):
        render_server(mismatched, [device])


def test_empty_allowlist_has_no_users(inputs):
    ctx, _ = inputs
    assert all(not inbound["users"] for inbound in render_server(ctx, [])["inbounds"])


def test_admin_route_uses_configured_listener(inputs):
    ctx, device = inputs
    config = render_server(replace(ctx, admin_bind="127.0.0.2", admin_port=9443), [device])
    assert config["route"]["rules"][1] == {
        "ip_cidr": ["198.18.255.1/32"], "action": "route", "outbound": "direct",
        "override_address": "127.0.0.2", "override_port": 9443}
    assert config["route"]["final"] == "direct"
    assert config["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert not any(rule.get("outbound") in {"block", "admin-local"}
                   for rule in config["route"]["rules"])


def test_private_route_order_without_maintenance(inputs):
    ctx, device = inputs
    config = render_server(ctx, [device])
    assert config["route"] == {
        "rules": [
            {"action": "resolve"},
            {"ip_cidr": ["198.18.255.1/32"], "action": "route", "outbound": "direct",
             "override_address": ctx.admin_bind, "override_port": ctx.admin_port},
            {"ip_is_private": True, "action": "reject"},
            {"ip_cidr": ["198.18.0.0/15", "100.64.0.0/10"], "action": "reject"},
        ],
        "final": "direct",
    }
    assert config["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert all("address" not in server for server in config["dns"]["servers"])


def test_resolve_is_first_rule_before_any_ip_rule(inputs):
    ctx, device = inputs
    revoked = replace(device, device_id="revoked", uuid="00000000-0000-4000-8000-000000000002",
                      revoked_at="2026-10-22T01:00:00+00:00")
    for render_ctx, render_devices in (
        (ctx, [device]),
        (replace(ctx, maintenance_device_ids=(device.device_id,)), [device, revoked]),
    ):
        rules = render_server(render_ctx, render_devices)["route"]["rules"]
        assert rules[0] == {"action": "resolve"}
        ip_rule_indexes = [
            i for i, rule in enumerate(rules)
            if "ip_cidr" in rule or "ip_is_private" in rule
        ]
        assert ip_rule_indexes and min(ip_rule_indexes) > 0


def test_carrier_nat_range_rejected(inputs):
    ctx, device = inputs
    rules = render_server(ctx, [device])["route"]["rules"]
    assert rules[-1] == {"ip_cidr": ["198.18.0.0/15", "100.64.0.0/10"], "action": "reject"}


def test_maintenance_only_allows_active_registered_device_ssh(inputs):
    ctx, device = inputs
    revoked = replace(device, device_id="revoked", uuid="00000000-0000-4000-8000-000000000002",
                      revoked_at="2026-10-22T01:00:00+00:00")
    ctx = replace(ctx, maintenance_device_ids=("revoked", "missing", device.device_id))
    config = render_server(ctx, [revoked, device])
    assert config["route"] == {
        "rules": [
            {"action": "resolve"},
            {"ip_cidr": ["198.18.255.1/32"], "action": "route", "outbound": "direct",
             "override_address": ctx.admin_bind, "override_port": ctx.admin_port},
            {"auth_user": [device.device_id], "ip_is_private": True,
             "port": [22], "outbound": "direct"},
            {"ip_is_private": True, "action": "reject"},
            {"ip_cidr": ["198.18.0.0/15", "100.64.0.0/10"], "action": "reject"},
        ],
        "final": "direct",
    }


def test_maintenance_users_sorted_and_inbound_names_match_devices(inputs):
    ctx, device = inputs
    other = replace(device, device_id="aaa", uuid="00000000-0000-4000-8000-000000000002",
                    hy2_password="TEST-ONLY-other-password")
    ctx = replace(ctx, maintenance_device_ids=(device.device_id, other.device_id))
    config = render_server(ctx, [device, other])
    assert config["route"]["rules"][2]["auth_user"] == [other.device_id, device.device_id]
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


def test_console_rule_only_for_local_devices_when_enabled(inputs):
    ctx, device = inputs
    assert not any(rule.get("ip_cidr") == ["198.18.255.2/32"]
                   for rule in render_server(ctx, [device])["route"]["rules"])

    local = replace(device, device_id="local-1", account_id="local")
    other = replace(device, device_id="other-1", account_id="acc-2",
                    uuid="00000000-0000-4000-8000-000000000002",
                    hy2_password="TEST-ONLY-other-password")
    revoked = replace(device, device_id="local-revoked", account_id="local",
                      uuid="00000000-0000-4000-8000-000000000003",
                      hy2_password="TEST-ONLY-revoked-password",
                      revoked_at="2026-10-22T01:00:00+00:00")
    rules = render_server(replace(ctx, console_port=8444), [local, other, revoked])["route"]["rules"]
    indexes = [i for i, rule in enumerate(rules) if rule.get("ip_cidr") == ["198.18.255.2/32"]]
    assert len(indexes) == 1
    assert rules[indexes[0]] == {
        "ip_cidr": ["198.18.255.2/32"], "auth_user": ["local-1"],
        "action": "route", "outbound": "direct",
        "override_address": "127.0.0.1", "override_port": 8444}
    admin_index = next(i for i, rule in enumerate(rules)
                       if rule.get("ip_cidr") == ["198.18.255.1/32"])
    assert admin_index < indexes[0]

    # 没有本机自用设备时整条规则不加；其余设备照旧落到 198.18.0.0/15 的拒绝规则。
    enabled = render_server(replace(ctx, console_port=8444), [other])["route"]["rules"]
    assert not any(rule.get("ip_cidr") == ["198.18.255.2/32"] for rule in enabled)


def test_obfs_key_order_and_shared_password(inputs):
    ctx, device = inputs
    backup = render_server(ctx, [device])["inbounds"][1]
    assert list(backup) == ["type", "tag", "listen", "listen_port", "users", "obfs", "tls"]
    assert backup["obfs"] == {"type": "salamander", "password": ctx.hy2_obfs_password}
    client = render_client_windows(ctx, device)["outbounds"][1]
    assert list(client) == ["type", "tag", "server", "server_port", "password", "obfs", "tls"]
    assert client["obfs"] == backup["obfs"]


def test_empty_obfs_password_renders_without_obfs(inputs):
    ctx, device = inputs
    ctx = replace(ctx, hy2_obfs_password="")
    validate_context(ctx)
    assert "obfs" not in render_server(ctx, [device])["inbounds"][1]
    assert "obfs" not in render_client_windows(ctx, device)["outbounds"][1]


@pytest.mark.parametrize("password", [
    "contains space 0123456789", "a" * 15, "a" * 129, "has=equals-0123456789", None, 123,
])
def test_context_rejects_invalid_obfs_password(inputs, password):
    ctx, device = inputs
    with pytest.raises(ValueError, match="备用通道混淆密码格式不正确"):
        validate_context(replace(ctx, hy2_obfs_password=password))
    with pytest.raises(ValueError, match="混淆"):
        render_server(replace(ctx, hy2_obfs_password=password), [device])


@pytest.mark.parametrize("password", ["a" * 16, "A-z_9" * 25 + "abc"])
def test_context_accepts_boundary_obfs_password(inputs, password):
    ctx, _ = inputs
    validate_context(replace(ctx, hy2_obfs_password=password))


def test_obfs_password_not_in_context_repr(inputs):
    ctx, _ = inputs
    assert ctx.hy2_obfs_password not in repr(ctx)
