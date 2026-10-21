"""按路由、网卡、上游顺序探测；未知信息不猜测。"""

import ipaddress
import json
import re

from . import service


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
    for key, name in (("entry", "入口可达"), ("proxy", "代理进程"), ("egress", "真实出口")):
        layers.append({"layer": key, "name": name, "result": "未接入",
                       "reason": "本阶段未接入此项检查，不能据此判断出口可用"})
    layers.append(service.check(runner, config))
    return {"network": network, "layers": layers}
