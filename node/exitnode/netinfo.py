"""按路由、网卡、上游顺序探测；未知信息不猜测。"""

import ipaddress
import json
import re

from . import service


def listen_state(runner, argv, port):
    try:
        result = runner.run(argv, check=False)
    except FileNotFoundError:
        return "未知"
    except (OSError, RuntimeError):
        # Runner 隐藏了命令缺失与超时的底层异常；二者均无法确知监听情况。
        return "未知"
    if result.code == 127:
        return "未知"
    if result.code:
        return "失败"
    for line in result.out.splitlines():
        columns = line.split()
        # ss -H: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
        if len(columns) >= 5 and columns[3].rsplit(":", 1)[-1] == str(port):
            return "通过"
    return "失败"


def public_ipv4(runner):
    for url, trace in (("https://1.1.1.1/cdn-cgi/trace", True),
                       ("https://api.ipify.org", False)):
        try:
            result = runner.run(["curl", "-4", "-s", "--max-time", "5", url], check=False)
            if result.code:
                continue
            candidates = ([line[3:] for line in result.out.splitlines() if line.startswith("ip=")]
                          if trace else [result.out.strip()])
            if len(candidates) != 1 or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
                                                      candidates[0]):
                continue
            return str(ipaddress.IPv4Address(candidates[0]))
        except (OSError, RuntimeError, ValueError):
            continue
    return None


def read_network(runner, iface="auto"):
    network = {"iface": None, "gateway": None, "dhcp": "unknown", "addr": None}
    try:
        routes = json.loads(runner.run(["ip", "-j", "route"]).out)
        addresses = json.loads(runner.run(["ip", "-j", "addr"]).out)
        defaults = [r for r in routes if r.get("dst") == "default" and r.get("dev")
                    and (iface == "auto" or r["dev"] == iface)]
        if not defaults:
            return network, False, "未找到所选网卡的默认路由"
        route = min(defaults, key=lambda r: r.get("metric", 0))
        network.update(iface=route["dev"], gateway=route.get("gateway"))
        device = next((a for a in addresses if a.get("ifname") == route["dev"]), None)
        if not device or "UP" not in device.get("flags", []):
            return network, False, "默认网卡未启用"
        addr = next((a.get("local") for a in device.get("addr_info", [])
                     if a.get("family") == "inet" and a.get("scope") == "global"), None)
        network["addr"] = addr
        if not addr:
            return network, False, "默认网卡尚未取得地址"
        index = device.get("ifindex")
        if type(index) is int and index > 0:
            lease = f"/run/systemd/netif/leases/{index}"
            if runner.exists(lease):
                content = dict(line.split("=", 1) for line in runner.read_file(lease).splitlines()
                               if "=" in line and not line.startswith("#"))
                if content.get("ADDRESS") == addr:
                    network["dhcp"] = True
        return network, True, "网卡与默认路由可用"
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return network, False, "无法读取网卡或路由，请检查网络工具与权限"


def probe_upstream(runner, targets):
    results = []
    for target in targets:
        try:
            ok = runner.tcp_connect(target, 443, 3.0)
        except (OSError, RuntimeError):
            ok = False
        results.append({"target": target, "ok": ok})
    return {"ok": any(item["ok"] for item in results), "targets": results}


def check(runner, config):
    network, ok, reason = read_network(runner, config.network.iface)
    layers = [{"layer": "network", "name": "网卡与默认路由",
               "result": "通过" if ok else "失败", "reason": reason}]
    upstream = probe_upstream(runner, config.network.probe_targets)
    layers.append({"layer": "upstream", "name": "上游连通",
                   "result": "通过" if upstream["ok"] else "失败",
                   "reason": "至少一个目标可连通" if upstream["ok"] else "所有上游目标均无法连通",
                   "targets": upstream["targets"]})
    r, h = config.proxy.reality_port, config.proxy.hy2_port
    states = [(f"主入口 TCP {r}", listen_state(runner, ["ss", "-ltnH"], r)),
              (f"备用入口 UDP {h}", listen_state(runner, ["ss", "-lunH"], h))]
    missing = [name for name, state in states if state == "失败"]
    if all(state == "通过" for _, state in states):
        entry = {"result": "通过", "reason": f"主入口 TCP {r} 与备用入口 UDP {h} 都在监听"}
    elif missing:
        entry = {"result": "失败",
                 "reason": "本机入口没有全部打开：" + "、".join(missing) + " 没有监听"}
    else:
        entry = {"result": "未知", "reason": "无法读取监听信息，暂不据此判断入口"}
    layers.append({"layer": "entry", "name": "入口可达", **entry})
    if layers[0]["result"] != "通过" or layers[1]["result"] != "通过":
        for key, name in (("proxy", "代理进程"), ("egress", "真实出口")):
            layers.append({"layer": key, "name": name, "result": "跳过",
                           "reason": "网络或上游不通，暂不自测隧道"})
        layers.append(service.check(runner, config))
        return {"network": network, "layers": layers}
    from . import selftest

    probe = selftest.run(config, runner)
    if "skipped" in probe:
        for key, name in (("proxy", "代理进程"), ("egress", "真实出口")):
            layers.append({"layer": key, "name": name, "result": "跳过",
                           "reason": probe["skipped"]})
    elif "error" in probe:
        layers.append({"layer": "proxy", "name": "代理进程", "result": "失败",
                       "reason": probe["error"]})
        layers.append({"layer": "egress", "name": "真实出口", "result": "跳过",
                       "reason": "隧道自测没有完成，无法确认出口"})
    else:
        main_ok, backup_ok = probe["main"]["ok"], probe["backup"]["ok"]
        if main_ok and backup_ok:
            proxy_result = "通过"
            proxy_reason = "主通道与备用通道自测都能连通"
        elif main_ok:
            proxy_result, proxy_reason = "通过", f"主通道能连通；备用通道自测不通，请检查 UDP {h}"
        elif backup_ok:
            proxy_result, proxy_reason = "通过", f"备用通道能连通；主通道自测不通，请检查 TCP {r}"
        else:
            proxy_result, proxy_reason = "失败", "主通道与备用通道自测都不通"
        layers.append({"layer": "proxy", "name": "代理进程", "result": proxy_result,
                       "reason": proxy_reason,
                       "channels": {"main": main_ok, "backup": backup_ok}})
        if not main_ok and not backup_ok:
            layers.append({"layer": "egress", "name": "真实出口", "result": "失败",
                           "reason": "两条通道都不通，无法经隧道上网"})
        else:
            chosen = probe["main"] if main_ok else probe["backup"]
            ipv4, loc = chosen["ip"], chosen["loc"]
            if loc is None:
                egress_result, egress_reason = "未知", f"经隧道出口 {ipv4}，取不到地区"
            elif config.node.country and loc != config.node.country:
                egress_result = "失败"
                egress_reason = (f"经隧道出口 {ipv4} 的地区是 {loc}，"
                                 f"配置的国家是 {config.node.country}")
            else:
                egress_result, egress_reason = "通过", f"经隧道出口 {ipv4}，地区 {loc}"
            layers.append({"layer": "egress", "name": "真实出口", "result": egress_result,
                           "reason": egress_reason, "ipv4": ipv4})
    layers.append(service.check(runner, config))
    return {"network": network, "layers": layers}
