import ipaddress
import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from exitnode.proxy.client_config import render_client_windows
from exitnode.proxy.context import ProxyContext, validate_context
from exitnode.proxy.keys import RealityKeys
from exitnode.proxy.registry import Device
from exitnode.proxy.subscription import render_android_subscription, vless_link

GOLDEN = Path(__file__).parent / "golden" / "proxy"


@pytest.fixture
def inputs():
    data = json.loads((GOLDEN / "inputs.json").read_text(encoding="utf-8"))
    ctx = data["context"]
    ctx["reality"] = RealityKeys(**ctx["reality"])
    return ProxyContext(**ctx), Device(**data["device"])


def assert_no_fallback(config):
    outbounds = {o["tag"]: o for o in config["outbounds"]}
    assert {o["type"] for o in outbounds.values()} == {"vless", "hysteria2", "urltest"}
    assert outbounds["proxy"]["outbounds"] == ["main", "backup"]
    assert config["route"]["final"] == "proxy"
    assert config["route"]["auto_detect_interface"] is True
    assert config["route"]["rules"][0] == {"action": "sniff"}
    assert {"ip_version": 6, "action": "reject"} in config["route"]["rules"]
    assert {"protocol": "dns", "action": "hijack-dns"} in config["route"]["rules"]
    assert config["dns"]["strategy"] == "ipv4_only"
    assert config["dns"]["final"] == "dns-remote"
    assert all(s["detour"] == "proxy" and s["type"] == "https" and s["server"] == "1.1.1.1"
               for s in config["dns"]["servers"])
    assert all("address" not in s for s in config["dns"]["servers"])
    assert "rules" not in config["dns"]
    tun = config["inbounds"][0]
    assert tun["auto_route"] is True and tun["strict_route"] is True
    assert "sniff" not in tun and tun["stack"] == "system"
    assert "172.19.0.1/30" in tun["address"]
    assert any(ipaddress.ip_interface(a).version == 6 for a in tun["address"])
    assert not tun.get("route_exclude_address")
    for tag in ("main", "backup"):
        assert ipaddress.ip_address(outbounds[tag]["server"]).version == 4
        assert not outbounds[tag]["tls"].get("insecure", False)


def test_windows_exact_golden_and_no_fallback(inputs):
    ctx, device = inputs
    config = render_client_windows(ctx, device)
    actual = {"_comment": "测试向量,不是真凭据", **config}
    assert json.dumps(actual, ensure_ascii=False, indent=2) + "\n" == (
        GOLDEN / "client-windows.json"
    ).read_text(encoding="utf-8")
    assert_no_fallback(config)
    assert ctx.reality.private_key not in json.dumps(config)
    assert config["outbounds"][1]["obfs"] == {
        "type": "salamander", "password": ctx.hy2_obfs_password}
    assert "obfs" not in config["outbounds"][0]


def test_urltest_tolerance_key_order_and_validation(inputs):
    ctx, device = inputs
    urltest = render_client_windows(ctx, device)["outbounds"][2]
    assert list(urltest) == ["type", "tag", "outbounds", "url", "interval", "tolerance"]
    assert urltest["tolerance"] == 300
    for bad in (True, -1, 10001, "300"):
        with pytest.raises(ValueError, match="容差"):
            validate_context(replace(ctx, urltest_tolerance_ms=bad))
    for good in (0, 10000):
        validate_context(replace(ctx, urltest_tolerance_ms=good))


def test_android_subscription_keeps_obfs_and_vless_link_omits_it(inputs):
    ctx, device = inputs
    android = render_android_subscription(ctx, device)
    assert android["outbounds"][1]["obfs"]["password"] == ctx.hy2_obfs_password
    assert ctx.hy2_obfs_password not in vless_link(ctx, device)
    plain = replace(ctx, hy2_obfs_password="")
    assert "obfs" not in render_android_subscription(plain, device)["outbounds"][1]


@pytest.mark.parametrize("host", ["node.example", "::1", "", "203.0.113.999", 2130706433, None])
@pytest.mark.parametrize("render", [render_client_windows, render_android_subscription, vless_link])
def test_connection_address_must_be_ipv4(inputs, host, render):
    ctx, device = inputs
    with pytest.raises(ValueError) as error:
        render(replace(ctx, server_host=host), device)
    assert str(error.value) == "连接地址必须是 IPv4 数字地址,由鉴权服务器下发"


def test_android_and_vless_export(inputs):
    ctx, device = inputs
    android = render_android_subscription(ctx, device)
    assert_no_fallback(android)
    assert android["inbounds"][0]["platform"] == {"http_proxy": {"enabled": False}}
    assert android["outbounds"] == render_client_windows(ctx, device)["outbounds"]
    parsed = urlsplit(vless_link(ctx, device))
    assert (parsed.scheme, parsed.hostname, parsed.port) == ("vless", ctx.server_host, 443)
    assert parsed.username == device.uuid
    query = parse_qs(parsed.query)
    assert query == {
        "encryption": ["none"], "security": ["reality"], "type": ["tcp"],
        "flow": ["xtls-rprx-vision"], "sni": [ctx.sni], "fp": ["chrome"],
        "pbk": [ctx.reality.public_key], "sid": [ctx.reality.short_id],
    }
    assert unquote(parsed.fragment) == device.name


def test_revoked_device_cannot_export(inputs):
    ctx, device = inputs
    for render in (render_client_windows, render_android_subscription, vless_link):
        with pytest.raises(ValueError, match="吊销"):
            render(ctx, replace(device, revoked_at="2026-10-22T01:00:00+00:00"))


def test_self_signed_trust_and_sni_are_explicit(inputs):
    ctx, device = inputs
    config = render_client_windows(replace(ctx, sni="cover.example",
        handshake_server="cover.example", hy2_server_name="node-cert.example", hy2_certificate=("TEST-CERTIFICATE",)), device)
    main, backup = config["outbounds"][:2]
    assert main["server"] == backup["server"] == ctx.server_host
    assert main["tls"]["server_name"] == "cover.example"
    assert backup["tls"]["server_name"] == "node-cert.example"
    assert backup["tls"]["certificate"] == ["TEST-CERTIFICATE"]
    assert "insecure" not in backup["tls"]
