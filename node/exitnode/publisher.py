"""定时向路由器申请入口映射。"""

import ipaddress
import json
import re
from contextlib import suppress
from datetime import UTC, datetime

from .runner import RunnerError

TOOL = "/usr/bin/upnpc"
LEASE = 3600
DESCRIPTION = "exitnode"
ERRORS = {"未安装 miniupnpc", "没找到支持 UPnP 的路由器", "路由器拒绝了映射",
          "执行失败", "路由器外网口不是公网地址"}


def _path(config):
    return config.node.data_dir.rstrip("/") + "/publisher.json"


def _empty():
    return {"updated_at": None, "last_ok_at": None, "consecutive_failures": 0,
            "last_error": None, "external_ipv4": None, "ports": []}


def status(config, runner):
    try:
        value = json.loads(runner.read_file(_path(config)))
        if not isinstance(value, dict) or set(value) != set(_empty()):
            raise ValueError
        if type(value["consecutive_failures"]) is not int or value["consecutive_failures"] < 0:
            raise ValueError
        for key in ("updated_at", "last_ok_at"):
            if value[key] is not None:
                parsed = datetime.fromisoformat(value[key])
                if parsed.tzinfo is None:
                    raise ValueError
        if value["last_error"] is not None and value["last_error"] not in ERRORS:
            raise ValueError
        if value["external_ipv4"] is not None:
            ipaddress.IPv4Address(value["external_ipv4"])
        if not isinstance(value["ports"], list):
            raise ValueError
        for port in value["ports"]:
            if (not isinstance(port, dict) or set(port) != {"port", "protocol", "mapped", "lease"}
                    or type(port["port"]) is not int or not 1 <= port["port"] <= 65535
                    or port["protocol"] not in ("tcp", "udp") or type(port["mapped"]) is not bool
                    or (port["mapped"] and (type(port["lease"]) is not int
                                             or port["lease"] not in (0, LEASE)))
                    or (not port["mapped"] and port["lease"] is not None)):
                raise ValueError
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return _empty()


def _ports(config):
    return [(config.proxy.reality_port, "tcp"), (config.proxy.hy2_port, "udp")]


def _address(text):
    for line in text.splitlines():
        match = re.fullmatch(r"\s*ExternalIPAddress\s*=\s*(\S+)\s*", line)
        if match:
            try:
                return str(ipaddress.IPv4Address(match.group(1)))
            except ValueError:
                continue
    return None


def _map(runner, port, protocol):
    for lease in (LEASE, 0):
        try:
            result = runner.run([TOOL, "-e", DESCRIPTION, "-a", "@", str(port), str(port),
                                 protocol, str(lease)], check=False, timeout=20)
        except RunnerError:
            return None, None, "执行失败"
        if result.code == 0:
            return lease, _address(result.out), None
        if result.code == 1:
            return None, None, "没找到支持 UPnP 的路由器"
        if result.code != 2:
            return None, None, "执行失败"
    return None, None, "路由器拒绝了映射"


def tick(config, runner):
    if config.publisher.mode != "upnp":
        return 0
    value = status(config, runner)
    rows, errors, addresses = [], [], []
    missing = not runner.exists(TOOL)
    stop = "未安装 miniupnpc" if missing else None
    for port, protocol in _ports(config):
        lease, address, error = (None, None, stop) if stop else _map(runner, port, protocol)
        rows.append({"port": port, "protocol": protocol, "mapped": error is None, "lease": lease})
        if error:
            errors.append(error)
            if error in ("没找到支持 UPnP 的路由器", "执行失败"):
                stop = error
        if address:
            addresses.append(address)
    address = next((a for a in addresses if not ipaddress.IPv4Address(a).is_global),
                   addresses[0] if addresses else None)
    error = errors[0] if errors else ("路由器外网口不是公网地址" if address
                                      and not ipaddress.IPv4Address(address).is_global else None)
    now = datetime.fromtimestamp(runner.now(), UTC).isoformat()
    value.update(updated_at=now, last_error=error, external_ipv4=address, ports=rows,
                 consecutive_failures=value["consecutive_failures"] + 1 if error else 0)
    if not error:
        value["last_ok_at"] = now
    path = _path(config)
    runner.mkdir(config.node.data_dir, 0o700)
    runner.write_file(path + ".tmp", json.dumps(value, ensure_ascii=False) + "\n", 0o600)
    runner.replace(path + ".tmp", path)
    tcp, udp = config.proxy.reality_port, config.proxy.hy2_port
    if error:
        print(f"入口端口:未能自动映射({error});请在路由器上手动把 TCP {tcp} 和 UDP {udp} 转发到本机")
        return 1
    print(f"入口端口:TCP {tcp}、UDP {udp} 已向路由器申请映射")
    return 0


def remove(config, runner):
    if config.publisher.mode != "upnp" or not runner.exists(TOOL):
        return
    for port, protocol in _ports(config):
        with suppress(RunnerError):
            runner.run([TOOL, "-d", str(port), protocol], check=False, timeout=20)


def summary(config, runner):
    if config.publisher.mode != "upnp":
        return "未启用自动映射"
    value = status(config, runner)
    if not value["updated_at"]:
        return "尚无映射记录"
    if value["last_error"] is None:
        return "已向路由器申请映射"
    return f"未能自动映射({value['last_error']}),需在路由器上手动转发"


def check(config, runner):
    result, reason = "失败", "端口映射定时器未运行"
    try:
        active = runner.run(["systemctl", "is-active", "exitnode-publisher.timer"], check=False)
        if active.code == 0 and active.out.strip() == "active":
            reason = "半小时内没有端口映射记录"
            value = status(config, runner)
            at = value["updated_at"]
            age = runner.now() - datetime.fromisoformat(at).timestamp() if at else None
            if age is not None and 0 <= age <= 1800:
                if value["last_error"] is None:
                    result, reason = "通过", "两个端口已向路由器申请映射"
                else:
                    result = "需手动转发"
                    reason = value["last_error"] + "，请在路由器上手动转发"
    except (OSError, RuntimeError, ValueError, TypeError):
        pass
    return {"layer": "publisher", "name": "入口端口映射", "result": result, "reason": reason}
