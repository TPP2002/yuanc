"""先验证完整三件套，再发布文件与最后的索引；主机写入均经过 Runner。"""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath

VERSION = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
FILENAME = re.compile(r"YuanC-Client-" + VERSION + r"(?:\.exe|\.manifest\.json(?:\.sig)?)")


def version_key(value):
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        raise ValueError("客户端版本号格式不正确")
    release, _, pre = value.partition("-")
    identifiers = tuple((0, int(part)) if part.isdigit() else (1, part)
                        for part in pre.split(".")) if pre else ()
    return tuple(map(int, release.split("."))), not bool(pre), identifiers


def releases(config):
    return config.node.data_dir.rstrip("/") + "/winclient/releases"


def latest(config, runner):
    path = releases(config) + "/latest.json"
    if not runner.exists(path):
        return None
    try:
        value = json.loads(runner.read_file(path))
        version_key(value["version"])
        if type(value["size"]) is not int or value["size"] < 0:
            raise ValueError
        datetime.fromisoformat(value["published_at"])
        return value
    except (ValueError, KeyError, TypeError):
        raise ValueError("客户端发布记录损坏，请联系维护人员") from None


def _atomic(runner, path, data):
    temporary = path + ".tmp"
    try:
        runner.write_bytes(temporary, data, 0o644)
        runner.replace(temporary, path)
    finally:
        if runner.exists(temporary):
            runner.remove(temporary)


def publish(config, runner, exe, manifest, signature, *, allow_downgrade=False):
    paths = tuple(str(p) for p in (exe, manifest, signature))
    try:
        payload, raw, signed = (runner.read_bytes(p) for p in paths)
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("product") != "YuanC-Client":
            raise ValueError
        version_key(value.get("version"))
        stem = "YuanC-Client-" + value["version"]
        names = (stem + ".exe", stem + ".manifest.json", stem + ".manifest.json.sig")
        if (tuple(PurePosixPath(p.replace("\\", "/")).name for p in paths) != names
                or value.get("file") != names[0]
                or not isinstance(value.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
                or hashlib.sha256(payload).hexdigest() != value["sha256"]
                or type(value.get("size")) is not int or value["size"] != len(payload)
                or not signed):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ValueError("客户端发布包校验失败，文件未发布") from None
    current = latest(config, runner)
    if (current and version_key(value["version"]) < version_key(current["version"])
            and not allow_downgrade):
        raise ValueError("拒绝发布比当前更旧的客户端版本")
    root = releases(config)
    contents = (payload, raw, signed)
    # A published version is immutable: repeating it must not change signed bytes.
    for name, content in zip(names, contents, strict=True):
        path = root + "/" + name
        if runner.exists(path) and runner.read_bytes(path) != content:
            raise ValueError("同版本客户端包内容不同，请使用新的版本号")
    if current and current["version"] == value["version"] and all(
            runner.exists(root + "/" + name) for name in names):
        return current
    runner.mkdir(config.node.data_dir.rstrip("/") + "/winclient", 0o755)
    runner.mkdir(root, 0o755)
    for name, content in zip(names, contents, strict=True):
        _atomic(runner, root + "/" + name, content)
    index = {"version": value["version"], "file": names[0], "manifest": names[1],
             "signature": names[2], "size": value["size"], "sha256": value["sha256"],
             "published_at": datetime.fromtimestamp(runner.now(), UTC).isoformat()}
    _atomic(runner, root + "/latest.json",
            json.dumps(index, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return index
