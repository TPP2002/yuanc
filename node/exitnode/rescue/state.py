"""状态与历史原子保存，计数按五分钟轮次而非调用次数累加。"""

import json
import math
from datetime import UTC, datetime

DATA = "/var/lib/exitnode/rescue"
STATE = DATA + "/state.json"
HISTORY = DATA + "/history.jsonl"


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("时间缺少时区")
    return result.timestamp()


def iso(now):
    return datetime.fromtimestamp(now, UTC).isoformat()


def fresh():
    return {"state": "normal", "reason": "尚未检查", "updated_at": None,
            "counts": {p: 0 for p in ("P1", "P2", "P3", "P4", "P5")},
            "counted_at": None, "reinstall_times": [], "restart_times": [],
            "probes": {}, "watchdog_state": None, "corrupt": False}


def read(runner):
    if not runner.exists(STATE):
        return fresh()
    try:
        value = json.loads(runner.read(STATE))
        if not isinstance(value, dict) or not fresh().keys() <= value.keys():
            raise ValueError
        if value["state"] not in {"normal", "processing", "manual"}:
            raise ValueError
        if set(value["counts"]) != set(fresh()["counts"]):
            raise ValueError
        if any(type(n) is not int or n < 0 for n in value["counts"].values()):
            raise ValueError
        for key in ("reinstall_times", "restart_times"):
            if not isinstance(value[key], list):
                raise ValueError
            for n in value[key]:
                if type(n) not in (int, float) or not math.isfinite(n):
                    raise ValueError
        if value["counted_at"] is not None and (
                type(value["counted_at"]) not in (int, float)
                or not math.isfinite(value["counted_at"])):
            raise ValueError
        if value["updated_at"] is not None:
            timestamp(value["updated_at"])
        if type(value["corrupt"]) is not bool:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        value = fresh()
        value.update(state="manual", reason="救援记录损坏，频率额度不可确认", corrupt=True)
        return value


def atomic(runner, path, data):
    runner.mkdir(DATA, 0o700)
    runner.write(path + ".tmp", data, 0o600)
    runner.replace(path + ".tmp", path)


def save(runner, value):
    value["updated_at"] = iso(runner.now())
    atomic(runner, STATE, json.dumps(value, ensure_ascii=False).encode())


def history(runner, action, status, version=None):
    previous = runner.read(HISTORY) if runner.exists(HISTORY) else b""
    row = {"action": action, "status": status, "version": version, "at": iso(runner.now())}
    atomic(runner, HISTORY, previous + json.dumps(row).encode() + b"\n")


def count(value, probes, now):
    due = value["counted_at"] is None or now - value["counted_at"] >= 300
    for key, ok in probes.items():
        if ok:
            value["counts"][key] = 0
        elif due:
            value["counts"][key] += 1
    if due:
        value["counted_at"] = now
    value["probes"] = probes
    return due


def summary(value):
    labels = {"normal": "正常", "processing": "处理中", "manual": "需人工处理"}
    return ("救援单元：" + labels.get(value.get("state"), "尚未检查")
            + "；" + value.get("reason", "尚未检查")
            + "；最近检查：" + (value.get("updated_at") or "暂无"))
