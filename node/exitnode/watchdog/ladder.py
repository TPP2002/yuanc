"""每次只执行一级恢复动作，普通重启与回滚分别计费率。"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..proxy.lastgood import prune_revoked
from ..service import LAST_GOOD, LIVE, SECRETS, SERVICE_GROUP
from . import state as storage

ALLOWED_SERVICES = {"exitnode-proxy.service", "exitnode-admin.service"}


@dataclass
class Action:
    name: str
    state: dict
    now: datetime
    reason: str
    unit: str = "exitnode-proxy.service"


CLOCK_SKEW_TOLERANCE_SEC = 300


def is_future(at, now):
    return (storage.timestamp(at) - now).total_seconds() > CLOCK_SKEW_TOLERANCE_SEC


def elapsed(at, now, seconds):
    if at is None:
        return True
    if is_future(at, now):
        return True  # 未来时间戳视为失效，不能把自动恢复永久锁死。
    return (now - storage.timestamp(at)).total_seconds() >= seconds


def sanitize_clock(state, now):
    """丢弃晚于当前时间超过容差的频率记录，返回改动条数。"""
    changed = 0
    kept = [at for at in state["restart_times"] if not is_future(at, now)]
    changed += len(state["restart_times"]) - len(kept)
    if len(kept) != len(state["restart_times"]):
        state["restart_times"] = kept
        state["restart_count_window"] = len(kept)
    for key in ("first_failure_at", "last_ok_at", "last_rollback_at", "last_reboot_at",
                "updated_at", "last_failure_tick_at", "next_action_at"):
        if state[key] is not None and is_future(state[key], now):
            # 连续失联时长从现在重新计，回拨不能立刻满足整机重启条件。
            state[key] = now.isoformat() if key == "first_failure_at" else None
            changed += 1
    if changed:
        storage.record(state, "clock_adjusted", now, "检测到时间回拨，已丢弃未来时间的频率记录")
    return changed


def refresh_window(state, now):
    state["restart_times"] = [at for at in state["restart_times"]
                              if not elapsed(at, now, 3600)]
    state["restart_count_window"] = len(state["restart_times"])


def reboot_allowed(state, now, config):
    settings = config.watchdog
    return (settings.enabled and settings.reboot_enabled and state["state"] == "manual"
            and state["first_failure_at"] is not None
            and elapsed(state["first_failure_at"], now, settings.reboot_after_minutes * 60)
            and elapsed(state["last_reboot_at"], now, settings.reboot_min_interval_hours * 3600))


def decide(state, probes, now, config):
    refresh_window(state, now)
    failure = next((p for p in probes if p["result"] == "失败"), None)
    if not failure:
        return Action("normal", state, now, "本轮检查通过")
    reason = failure["reason"]
    if failure["layer"] == "L-public":
        return Action("wait_public", state, now, reason)
    if state["state"] == "manual" or state["rollback_attempted"]:
        state["state"] = "manual"
        return Action("reboot" if reboot_allowed(state, now, config) else "manual",
                      state, now, reason + "；自动恢复未奏效，请联系维护人员")
    settings = config.watchdog
    if state["consecutive_failures"] < settings.restart_after_failures:
        return Action("wait", state, now, reason + "；等待下次检查")
    if failure["layer"] not in {"L-proxy", "L-listen"}:
        state["state"] = "manual"
        return Action("reboot" if reboot_allowed(state, now, config) else "manual",
                      state, now, reason + "；请检查网线、路由器或宽带")
    if state["restart_count_window"] < settings.restart_limit_per_hour:
        if not elapsed(state["next_action_at"], now, 0):
            return Action("wait", state, now, reason + "；恢复动作冷却中")
        return Action("restart_service", state, now, reason + "；尝试重新启动隧道服务")
    if elapsed(state["last_rollback_at"], now, settings.rollback_min_interval_hours * 3600):
        return Action("rollback_config", state, now, reason + "；尝试恢复上次可用配置")
    return Action("manual", state, now, reason + "；回滚次数已达上限，请联系维护人员")


def execute(action, runner, config):
    state, now, name = action.state, action.now, action.name
    settings = config.watchdog
    if not settings.enabled:
        return
    if name in {"restart_service", "rollback_config"} and action.unit not in ALLOWED_SERVICES:
        raise ValueError("只允许重启本项目的隧道或管理服务")
    refresh_window(state, now)
    if name == "restart_service" and state["restart_count_window"] >= settings.restart_limit_per_hour:
        name = "wait"
        action.reason = "本小时重启次数已达上限"
    if name == "rollback_config":
        if not elapsed(state["last_rollback_at"], now, settings.rollback_min_interval_hours * 3600):
            name, action.reason = "manual", "回滚次数已达上限，请联系维护人员"
        elif not runner.exists(LAST_GOOD):
            name, action.reason = "manual", "没有上次可用配置，请联系维护人员"
    if name == "reboot" and not reboot_allowed(state, now, config):
        name, action.reason = "manual", "尚未满足整机重启条件，请联系维护人员"
    state["state"] = "manual" if name in {"manual", "reboot"} else "degraded"
    state["reason"] = action.reason
    storage.record(state, name, now, action.reason)
    if name == "restart_service":
        state["restart_times"].append(now.isoformat())
        refresh_window(state, now)
        delay = min(settings.max_backoff_seconds,
                    settings.retry_interval_seconds * 2 ** min(state["restart_count_window"] - 1, 16))
        state["next_action_at"] = (now + timedelta(seconds=delay)).isoformat()
    elif name == "rollback_config":
        state["last_rollback_at"] = now.isoformat()
        state["rollback_attempted"] = True
    elif name == "reboot":
        state["last_reboot_at"] = now.isoformat()
    storage.save(config, runner, state, now)
    registry_corrupt = False
    try:
        if name == "restart_service":
            # 先清启动限制；失败不影响后续 restart，也不记原文。
            runner.run(["systemctl", "reset-failed", action.unit], check=False)
            runner.run(["systemctl", "restart", action.unit])
        elif name == "rollback_config":
            # 检查暂存副本，替换的必须是刚刚校验过的同一份内容。
            temporary = LIVE + ".watchdog.tmp"
            try:
                text = runner.read_file(LAST_GOOD)
                devices_path = SECRETS + "/devices.json"
                try:
                    devices_text = (runner.read_file(devices_path)
                                    if runner.exists(devices_path) else None)
                    text, removed = prune_revoked(text, devices_text)
                except ValueError:
                    registry_corrupt = True
                    raise
                # 线上配置 0640 root:exitnode，降权运行的隧道服务靠属组读取。
                runner.write_file(temporary, text, 0o640)
                valid = runner.run([config.proxy.binary, "check", "-c", temporary], check=False)
                if valid.code:
                    raise ValueError("上次配置校验未通过，当前配置未更改，请联系维护人员")
                runner.chown(temporary, "root", SERVICE_GROUP)
                runner.replace(temporary, LIVE)
                runner.run(["systemctl", "reset-failed", "exitnode-proxy.service"], check=False)
                runner.run(["systemctl", "restart", "exitnode-proxy.service"])
                if removed:
                    state["reason"] += f"；已剔除 {removed} 条不在登记表上的用户记录"
                    storage.save(config, runner, state, now)
            finally:
                if runner.exists(temporary):
                    runner.remove(temporary)
        elif name == "reboot":
            runner.run(["systemctl", "reboot"])
    except (OSError, RuntimeError, ValueError):
        # 不转印异常或内核输出，可能带有凭据。
        state["reason"] = "恢复动作未完成，请检查服务权限、磁盘或配置；详细输出已隐藏"
        if registry_corrupt:
            state["reason"] = "设备登记表损坏，无法核对上次可用配置，请联系维护人员"
        if name in {"rollback_config", "reboot"}:
            state["state"] = "manual"
        storage.record(state, "action_failed", now, state["reason"])
        storage.save(config, runner, state, now)
