"""检查记录：root 定时任务每分钟写一份脱敏快照，网页只读它。"""

import json
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__, device, netinfo, report
from ..log import redact


def path(config):
    return config.node.data_dir.rstrip("/") + "/console/status.json"


def collect(config, runner):
    base = netinfo.check(runner, config)
    checked = report.check_result(config, runner, base=base)
    status = report.status_result(config, runner, base=base)
    try:
        local = [item for item in device.registry(config, runner).all()
                 if item.account_id == "local"]
    except (ValueError, OSError, TypeError):
        local = []
    layers = [{"layer": redact(str(layer.get("layer", ""))),
               "name": redact(str(layer.get("name", ""))),
               "result": redact(str(layer.get("result", ""))),
               "reason": redact(str(layer.get("reason", "")))}
              for layer in checked["layers"]]
    return {
        "version": 1,
        "generated_at": datetime.fromtimestamp(runner.now(), UTC).isoformat(),
        "node_name": config.node.name,
        "program_version": __version__,
        "state": status.state.value,
        "reason": redact(status.reason),
        "public_ipv4": status.public_ipv4,
        "layers": layers,
        "local_devices": [{"name": item.name, "platform": item.platform,
                           "created_at": item.created_at, "revoked_at": item.revoked_at}
                          for item in local],
    }


def write(config, runner, value):
    target = path(config)
    directory = target.rsplit("/", 1)[0]
    runner.mkdir(directory, 0o755)
    # 定时单元可能带 UMask=0077，必须显式放宽，否则网页账户读不到。
    runner.chmod(directory, 0o755)
    temporary = target + ".tmp"
    runner.write_file(temporary, json.dumps(value, ensure_ascii=False), 0o644)
    runner.chmod(temporary, 0o644)
    runner.replace(temporary, target)


def load(file_path, now):
    try:
        value = json.loads(Path(file_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {"available": False}
    if not isinstance(value, dict) or value.get("version") != 1:
        return {"available": False}
    if any(key not in value for key in
           ("generated_at", "state", "reason", "layers", "local_devices")):
        return {"available": False}
    try:
        age = now - datetime.fromisoformat(value["generated_at"]).timestamp()
    except (ValueError, TypeError, OverflowError):
        return {"available": False}
    return {
        "available": True,
        "age_seconds": int(age),
        "stale": age > 180 or age < -60,
        "generated_at": value["generated_at"],
        "node_name": value.get("node_name"),
        "program_version": value.get("program_version"),
        "state": value["state"],
        "reason": value["reason"],
        "public_ipv4": value.get("public_ipv4"),
        "layers": value["layers"],
        "local_devices": value["local_devices"],
    }
