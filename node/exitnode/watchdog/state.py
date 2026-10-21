"""原子保存恢复进度；频率记录独立于最近五十条动作。"""

import json
from datetime import datetime

from ..log import redact


def path(config):
    return config.node.data_dir.rstrip("/") + "/watchdog/state.json"


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("时间缺少时区")
    return result


def fresh():
    return {"state": "normal", "consecutive_failures": 0, "first_failure_at": None,
            "last_ok_at": None, "actions": [], "restart_count_window": 0,
            "restart_times": [], "last_rollback_at": None, "last_reboot_at": None,
            "updated_at": None, "last_failure_tick_at": None, "next_action_at": None,
            "rollback_attempted": False, "reason": "尚未检查", "probes": []}


def record(value, name, now, reason):
    value["actions"] = (value["actions"] + [
        {"action": name, "at": now.isoformat(), "reason": redact(reason)}])[-50:]


def read(config, runner):
    """不存在返回 None；损坏抛 ValueError，由 tick 重建，查询命令不改文件。"""
    if not runner.exists(path(config)):
        return None
    try:
        raw = json.loads(runner.read_file(path(config)))
        if not isinstance(raw, dict) or not fresh().keys() <= raw.keys():
            raise ValueError
        value = {key: raw[key] for key in fresh()}
        if value["state"] not in {"normal", "degraded", "manual"}:
            raise ValueError
        for key in ("consecutive_failures", "restart_count_window"):
            if type(value[key]) is not int or value[key] < 0:
                raise ValueError
        for key in ("first_failure_at", "last_ok_at", "last_rollback_at", "last_reboot_at",
                    "updated_at", "last_failure_tick_at", "next_action_at"):
            if value[key] is not None:
                timestamp(value[key])
        if type(value["rollback_attempted"]) is not bool or not isinstance(value["reason"], str):
            raise ValueError
        if not isinstance(value["restart_times"], list):
            raise ValueError
        for at in value["restart_times"]:
            timestamp(at)
        if not isinstance(value["actions"], list) or not isinstance(value["probes"], list):
            raise ValueError
        for item in value["actions"]:
            if not isinstance(item["action"], str) or not isinstance(item["reason"], str):
                raise ValueError
            timestamp(item["at"])
        value["actions"] = value["actions"][-50:]
        return value
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError("看门狗记录损坏，需要重新检查") from exc


def save(config, runner, value, now):
    value["updated_at"] = now.isoformat()
    value["actions"] = value["actions"][-50:]
    target = path(config)
    runner.mkdir(target.rsplit("/", 1)[0], 0o700)
    runner.write_file(target + ".tmp", redact(json.dumps(value, ensure_ascii=False)), 0o600)
    runner.replace(target + ".tmp", target)


def load(config, runner, now):
    try:
        return read(config, runner) or fresh()
    except ValueError:
        value = fresh()
        # 额度历史已不可知，先冷却，不能把损坏当作取得新的重启额度。
        value.update(state="manual", reason="看门狗记录损坏，已重建并暂停恢复动作",
                     first_failure_at=now.isoformat(), last_reboot_at=now.isoformat(),
                     last_rollback_at=now.isoformat(), rollback_attempted=True,
                     restart_times=[now.isoformat()] * config.watchdog.restart_limit_per_hour,
                     restart_count_window=config.watchdog.restart_limit_per_hour)
        record(value, "rebuild_state", now, value["reason"])
        return value
