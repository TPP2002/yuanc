"""用节点自己的两个入口探测一次，判断隧道能否连通。"""

import ipaddress
import json

from . import device
from .proxy.client_config import render_client_windows

TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
PROBE_NAME = "selftest-probe.json"
FETCH_TIMEOUT = 15
CHANNELS = ("main", "backup")


def _fail():
    return {"ok": False, "ip": None, "loc": None}


def _judge(code, output):
    if code:
        return _fail()
    lines = output.splitlines()
    addresses = [line[3:] for line in lines if line.startswith("ip=")]
    if len(addresses) != 1:
        return _fail()
    address = addresses[0].strip()
    try:
        canonical = str(ipaddress.IPv4Address(address)) == address
    except ValueError:
        canonical = False
    if not canonical:
        return _fail()
    loc = None
    for line in lines:
        if line.startswith("loc="):
            candidate = line[4:].strip()
            if (len(candidate) == 2 and candidate.isascii() and candidate.isalpha()
                    and candidate.isupper()):
                loc = candidate
            break
    return {"ok": True, "ip": address, "loc": loc}


def run(config, runner) -> dict:
    secrets = config.node.secrets_dir.rstrip("/")
    if not runner.exists(secrets + "/reality.json"):
        return {"skipped": "节点尚未完成安装，无法自测隧道"}
    try:
        devices = device.registry(config, runner).all()
        active = next((item for item in devices if item.revoked_at is None), None)
        if active is None:
            return {"skipped": "没有未吊销的设备，无法自测隧道"}
        ctx = device._context(config, runner, "127.0.0.1")
        client = render_client_windows(ctx, active)
        outbounds = {item["tag"]: item for item in client["outbounds"]}
        probe = {"log": {"disabled": True},
                 "outbounds": [outbounds["main"], outbounds["backup"]]}
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        return {"error": "无法生成自测配置，请检查节点凭据"}
    path = secrets + "/" + PROBE_NAME
    results = {}
    try:
        runner.write_file(path, json.dumps(probe, ensure_ascii=False), 0o600)
        for tag in CHANNELS:
            argv = [config.proxy.binary, "tools", "fetch", "-c", path, "-o", tag, TRACE_URL]
            try:
                result = runner.run(argv, check=False, timeout=FETCH_TIMEOUT)
            except (OSError, RuntimeError):
                results[tag] = _fail()
                continue
            results[tag] = _judge(result.code, result.out)
    finally:
        try:
            if runner.exists(path):
                runner.write_file(path, "", 0o600)
                runner.remove(path)
        except (OSError, RuntimeError):
            pass
    return results
