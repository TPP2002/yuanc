"""定时获取并发布鉴权服务器的设备名单。"""

import json
import re
import unicodedata
from datetime import UTC, datetime

from . import device, service
from .proxy import sync
from .proxy.registry import validate_devices

KEY_PATH = service.SECRETS + "/authserver-node-key"


def _path(config, name):
    return config.node.data_dir.rstrip("/") + "/" + name


def status(config, runner):
    default = {"version": None, "last_ok_at": None, "updated_at": None,
               "consecutive_failures": 0, "last_error": None, "heartbeat_ok": None}
    try:
        value = json.loads(runner.read_file(_path(config, "authsync.json")))
        if not isinstance(value, dict) or set(value) != set(default):
            return default
        if type(value["consecutive_failures"]) is not int or value["consecutive_failures"] < 0:
            return default
        for key in ("version", "last_ok_at", "updated_at", "last_error"):
            if value[key] is not None and not isinstance(value[key], str):
                return default
        if value["heartbeat_ok"] is not None and type(value["heartbeat_ok"]) is not bool:
            return default
        return value
    except (OSError, ValueError, TypeError):
        return default


def _save(config, runner, value):
    value["updated_at"] = datetime.fromtimestamp(runner.now(), UTC).isoformat()
    path = _path(config, "authsync.json")
    runner.write_file(path + ".tmp", json.dumps(value, ensure_ascii=False) + "\n", 0o600)
    runner.replace(path + ".tmp", path)


def _failure(config, runner, error):
    value = status(config, runner)
    value["consecutive_failures"] += 1
    value["last_error"] = error
    _save(config, runner, value)
    return 1


def _request(config, runner, key, endpoint, post=False):
    https = config.authsync.url.startswith("https://")
    argv = ["curl", "--silent", "--show-error", "--fail", "--connect-timeout", "5",
            "--max-time", "15", "--max-filesize", "4194304", "--proto",
            "=https" if https else "=http", "-H", "@-"]
    if https:
        argv.extend(["--insecure", "--pinnedpubkey", "sha256//" + config.authsync.spki_sha256])
    if post:
        argv.extend(["-X", "POST"])
    argv.append(config.authsync.url + endpoint)
    try:
        return runner.run(argv, check=False, input="X-Node-Key: " + key + "\n")
    except (OSError, RuntimeError):
        return None


def tick(config, runner):
    if not config.authsync.enabled:
        return 0
    lock = _path(config, "registry.lock")
    if runner.lock_busy(_path(config, "updater.lock")) or not runner.acquire_lock(lock):
        return 0
    try:
        try:
            # 文件末尾的换行是写文件时带上的，不属于密钥。
            key = runner.read_file(KEY_PATH).rstrip("\r\n")
            if not key or len(key) > 512 or any(unicodedata.category(c) == "Cc" for c in key):
                raise ValueError
        except (OSError, ValueError, UnicodeError):
            return _failure(config, runner, "节点密钥文件缺失或无效")
        response = _request(config, runner, key, "/node/allowed")
        if response is None or response.code:
            return _failure(config, runner, "取名单失败")
        try:
            payload = json.loads(response.out)
            version, allowed = payload["version"], payload["allowed"]
            if (not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{64}", version)
                    or not isinstance(allowed, list)
                    or len(allowed) > 5000 or any(not isinstance(v, dict)
                    or v.get("account_id") == "local" for v in allowed)):
                raise ValueError
            original = device.registry(config, runner).all()
            remote = [d for d in original if d.account_id != "local"]
            planned, diff = sync.plan(remote, allowed)
            updates = iter(planned[:len(remote)])
            merged = [d if d.account_id == "local" else next(updates) for d in original]
            merged.extend(planned[len(remote):])
            validate_devices(merged)
        except (ValueError, TypeError, KeyError, AttributeError):
            return _failure(config, runner, "名单格式不对")
        heartbeat = _request(config, runner, key, "/node/heartbeat", post=True)
        if merged != original:
            try:
                service.publish(config, runner, devices=merged)
            except ValueError:
                return _failure(config, runner, "发布失败")
        value = status(config, runner)
        value.update(version=version, last_ok_at=datetime.fromtimestamp(runner.now(), UTC).isoformat(),
                     consecutive_failures=0, last_error=None,
                     heartbeat_ok=heartbeat is not None and heartbeat.code == 0)
        _save(config, runner, value)
        print(f"名单同步:新增 {len(diff['added'])},移除 {len(diff['removed'])},保持 {diff['unchanged']}")
        return 0
    finally:
        runner.release_lock(lock)


def check(config, runner):
    ok = False
    try:
        active = runner.run(["systemctl", "is-active", "exitnode-authsync.timer"], check=False)
        last = status(config, runner)["last_ok_at"]
        age = runner.now() - datetime.fromisoformat(last).timestamp() if last else None
        ok = active.code == 0 and active.out.strip() == "active" and age is not None and 0 <= age <= 600
    except (OSError, RuntimeError, ValueError, TypeError):
        pass
    return {"layer": "authsync", "name": "名单同步", "result": "通过" if ok else "失败",
            "reason": "定时器运行且十分钟内同步成功" if ok else "定时器未运行或最近同步已过期"}
