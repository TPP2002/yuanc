"""netinfo 分层、状态文案与看门狗共用的假主机用例。"""

import pytest
from exitnode import netinfo, selftest
from exitnode.config import load
from exitnode.runner import CompletedResult
from exitnode.status import evaluate
from exitnode.watchdog import probes
from test_cli import CONFIG, fake

LISTEN_TCP = CompletedResult(out="LISTEN 0 128 *:443 *:*\n")
LISTEN_UDP = CompletedResult(out="UNCONN 0 0 [::]:24443 [::]:*\n")
NOT_LISTENING = CompletedResult(out="")


def prepared():
    runner = fake()
    config = load(CONFIG, runner)
    runner.responses[("ss", "-ltnH")] = LISTEN_TCP
    runner.responses[("ss", "-lunH")] = LISTEN_UDP
    return config, runner


def probe_result(main, backup, loc="AU"):
    values = {}
    for tag, flag, address in (("main", main, "203.0.113.9"),
                               ("backup", backup, "198.51.100.7")):
        values[tag] = ({"ok": True, "ip": address, "loc": loc} if flag
                       else {"ok": False, "ip": None, "loc": None})
    return values


def checked(config, runner):
    return {item["layer"]: item for item in netinfo.check(runner, config)["layers"]}


@pytest.mark.parametrize("tcp,udp,result,reason", [
    (LISTEN_TCP, LISTEN_UDP, "通过", "主入口 TCP 443 与备用入口 UDP 24443 都在监听"),
    (NOT_LISTENING, LISTEN_UDP, "失败", "本机入口没有全部打开：主入口 TCP 443 没有监听"),
    (LISTEN_TCP, NOT_LISTENING, "失败", "本机入口没有全部打开：备用入口 UDP 24443 没有监听"),
    (CompletedResult(127), CompletedResult(127), "未知", "无法读取监听信息，暂不据此判断入口"),
])
def test_entry_layer_pass_fail_unknown(tcp, udp, result, reason, monkeypatch):
    config, runner = prepared()
    runner.responses[("ss", "-ltnH")] = tcp
    runner.responses[("ss", "-lunH")] = udp
    monkeypatch.setattr(selftest, "run", lambda *args: {"skipped": "测试跳过"})
    entry = checked(config, runner)["entry"]
    assert entry["result"] == result
    assert entry["reason"] == reason


def test_self_test_skipped_when_upstream_fails(monkeypatch):
    config, runner = prepared()
    runner.connections.clear()
    monkeypatch.setattr(selftest, "run", lambda *args: pytest.fail("网络不通时不应自测"))
    result = checked(config, runner)
    for layer in ("proxy", "egress"):
        assert result[layer]["result"] == "跳过"
        assert result[layer]["reason"] == "网络或上游不通，暂不自测隧道"
    assert not any(c[0] == "run" and tuple(c[1][:3]) == (config.proxy.binary, "tools", "fetch")
                   for c in runner.calls)


@pytest.mark.parametrize("main,backup,proxy_result,proxy_reason,egress_result", [
    (True, True, "通过", "主通道与备用通道自测都能连通", "通过"),
    (True, False, "通过", "主通道能连通；备用通道自测不通，请检查 UDP 24443", "通过"),
    (False, True, "通过", "备用通道能连通；主通道自测不通，请检查 TCP 443", "通过"),
    (False, False, "失败", "主通道与备用通道自测都不通", "失败"),
])
def test_proxy_and_egress_layers_from_channels(main, backup, proxy_result, proxy_reason,
                                               egress_result, monkeypatch):
    config, runner = prepared()
    monkeypatch.setattr(selftest, "run", lambda *args: probe_result(main, backup))
    result = checked(config, runner)
    assert result["proxy"]["result"] == proxy_result
    assert result["proxy"]["reason"] == proxy_reason
    assert result["proxy"]["channels"] == {"main": main, "backup": backup}
    assert result["egress"]["result"] == egress_result
    if egress_result == "通过":
        ipv4 = "203.0.113.9" if main else "198.51.100.7"
        assert result["egress"]["ipv4"] == ipv4
        assert result["egress"]["reason"] == f"经隧道出口 {ipv4}，地区 AU"
    else:
        assert "ipv4" not in result["egress"]
        assert result["egress"]["reason"] == "两条通道都不通，无法经隧道上网"


@pytest.mark.parametrize("loc,country,result,reason", [
    (None, "AU", "未知", "经隧道出口 203.0.113.9，取不到地区"),
    ("US", "AU", "失败", "经隧道出口 203.0.113.9 的地区是 US，配置的国家是 AU"),
    ("US", "", "通过", "经隧道出口 203.0.113.9，地区 US"),
])
def test_egress_country_mismatch_and_missing(loc, country, result, reason, monkeypatch):
    config, runner = prepared()
    config.node.country = country
    monkeypatch.setattr(selftest, "run", lambda *args: probe_result(True, True, loc))
    egress = checked(config, runner)["egress"]
    assert egress["result"] == result
    assert egress["reason"] == reason


def test_layer_order_and_keys_unchanged(monkeypatch):
    config, runner = prepared()
    monkeypatch.setattr(selftest, "run", lambda *args: probe_result(True, True))
    layers = netinfo.check(runner, config)["layers"]
    assert [item["layer"] for item in layers] == [
        "network", "upstream", "entry", "proxy", "egress", "tunnel"]
    assert [item["name"] for item in layers] == [
        "网卡与默认路由", "上游连通", "入口可达", "代理进程", "真实出口", "隧道服务"]
    for item in layers:
        assert {"layer", "name", "result", "reason"} <= set(item)
    assert layers[3]["channels"] == {"main": True, "backup": True}
    assert layers[4]["ipv4"] == "203.0.113.9"


def status_layers(egress, channels):
    layers = [{"layer": "network", "name": "网卡与默认路由", "result": "通过", "reason": ""},
              {"layer": "upstream", "name": "上游连通", "result": "通过", "reason": ""}]
    proxy = {"layer": "proxy", "name": "代理进程", "result": "通过", "reason": ""}
    if channels is not None:
        proxy["channels"] = channels
    layers.append(proxy)
    if egress is not None:
        layers.append(egress)
    return {"network": {"iface": "eth0"}, "layers": layers}


@pytest.mark.parametrize("channels,egress_result,egress_reason,path,reason", [
    ({"main": True, "backup": True}, "通过", "经隧道出口 203.0.113.9，地区 AU",
     "main", "检查通过，经隧道可以上网"),
    ({"main": True, "backup": False}, "通过", "经隧道出口 203.0.113.9，地区 AU",
     "main", "检查通过，经主通道可以上网；备用通道自测不通"),
    ({"main": False, "backup": True}, "通过", "经隧道出口 198.51.100.7，地区 AU",
     "backup", "检查通过，经备用通道可以上网；主通道自测不通"),
    ({"main": False, "backup": False}, "跳过", "节点尚未完成安装，无法自测隧道", "unknown",
     "检查通过，但尚不能确认可上网：节点尚未完成安装，无法自测隧道"),
    (None, None, None, "unknown", "检查通过，但尚不能确认可上网：缺少隧道自测结果"),
])
def test_status_reason_and_path(channels, egress_result, egress_reason, path, reason):
    egress = None
    if egress_result is not None:
        egress = {"layer": "egress", "name": "真实出口", "result": egress_result,
                  "reason": egress_reason}
    status = evaluate(status_layers(egress, channels))
    assert status.path == path
    assert status.reason == reason


def test_watchdog_listen_uses_shared_helper():
    assert probes._listen is netinfo.listen_state
