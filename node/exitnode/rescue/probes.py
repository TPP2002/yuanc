"""只检查本地程序完整性与运行能力，不探测网络。"""

import hashlib
import json
import re
import subprocess
from pathlib import PurePosixPath

from . import state

ROOT = "/opt/exitnode"
CURRENT = ROOT + "/current"
RELEASES = ROOT + "/releases"
RESCUE = "/opt/exitnode-rescue"
FACTORY = RESCUE + "/factory"
BINARY = CURRENT + "/bin/sing-box"
LIVE = "/var/lib/exitnode/secrets/sing-box.json"
LAST_GOOD = "/var/lib/exitnode/secrets/sing-box.last-good.json"
WATCHDOG = "/var/lib/exitnode/watchdog/state.json"
UPDATES = "/var/lib/exitnode/updater/history.jsonl"
LOCK = "/var/lib/exitnode/updater.lock"


def hashes(runner, directory):
    result = {}

    def walk(path, prefix=""):
        if runner.readlink(path) is not None:
            raise ValueError("程序目录不能包含链接")
        for name in runner.list(path):
            if name == "__pycache__" or name.endswith(".pyc"):
                continue
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise ValueError("程序路径不安全")
            child = path + "/" + name
            if runner.readlink(child) is not None:
                raise ValueError("程序目录不能包含链接")
            if runner.is_dir(child):
                walk(child, prefix + name + "/")
            else:
                result[prefix + name] = hashlib.sha256(runner.read(child)).hexdigest()

    if not runner.is_dir(directory):
        raise ValueError("程序目录不存在")
    walk(directory)
    return result


def release(runner, directory):
    try:
        manifest = json.loads(runner.read(directory + "/manifest.json"))
        version = manifest["version"]
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version):
            return None
        actual = hashes(runner, directory)
        actual.pop("manifest.json", None)
        if (not {"exitnode/__init__.py", "bin/sing-box"} <= actual.keys()
                or actual != manifest["files"]):
            return None
        return version
    except (OSError, ValueError, TypeError, KeyError):
        return None


def current(runner):
    target = runner.readlink(CURRENT)
    if target is None:
        return None
    if not target.startswith("/"):
        target = ROOT + "/" + target
    path = PurePosixPath(target)
    if path.parent != PurePosixPath(RELEASES) or ".." in path.parts:
        return None
    if runner.readlink(target) is not None or not runner.is_dir(target):
        return None
    return target


def command(runner, argv):
    try:
        return runner.run(argv, timeout=30).code == 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return False


def probe(runner):
    target = current(runner)
    p1 = target is not None and release(runner, target) is not None
    p2 = command(runner, ["env", "PYTHONPATH=" + CURRENT, "python3", "-c",
                          "import exitnode, exitnode.cli"])
    p3 = command(runner, [BINARY, "version"])
    p4 = command(runner, [BINARY, "check", "-c", LIVE])
    try:
        p5 = runner.run(["systemctl", "is-failed", "exitnode-proxy.service"],
                        timeout=30).out.strip() != "failed"
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        p5 = False
    return dict(zip(("P1", "P2", "P3", "P4", "P5"), (p1, p2, p3, p4, p5), strict=True))


def watchdog(runner):
    try:
        value = json.loads(runner.read(WATCHDOG))
        if value["state"] not in {"normal", "degraded", "manual"}:
            return None
        state.timestamp(value["updated_at"])
        return {"state": value["state"], "updated_at": value["updated_at"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
