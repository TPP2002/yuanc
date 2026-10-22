"""定时检查入口；时间由调用方注入。"""

from datetime import UTC, datetime

from ..service import LIVE
from . import ladder, probes, state


def tick(config, runner, clock=lambda: datetime.now(UTC)):
    if not config.watchdog.enabled:
        return 0
    now = clock()
    value = state.load(config, runner, now)
    ladder.sanitize_clock(value, now, config.watchdog.max_backoff_seconds)  # 有改动时下面任一分支都会保存。
    rows = probes.probe(config, runner)
    failed = any(p["result"] == "失败" for p in rows)
    if failed and value["consecutive_failures"] == 0:
        state.record(value, "reprobe", now, "首次发现异常，立即再检查一次")
        rows = probes.probe(config, runner)
        failed = any(p["result"] == "失败" for p in rows)
    value["probes"] = rows
    ladder.refresh_window(value, now)
    if not failed:
        # 未知监听不算失败；隧道进程与配置仍必须明确通过。
        if next(p for p in rows if p["layer"] == "L-proxy")["result"] == "通过":
            text = runner.read_file(LIVE)
            if not runner.exists(ladder.LAST_GOOD) or runner.read_file(ladder.LAST_GOOD) != text:
                temporary = ladder.LAST_GOOD + ".tmp"
                runner.write_file(temporary, text, 0o600)
                runner.replace(temporary, ladder.LAST_GOOD)
        value.update(state="normal", consecutive_failures=0, first_failure_at=None,
                     last_ok_at=now.isoformat(), last_failure_tick_at=None,
                     next_action_at=None, rollback_attempted=False, reason="本轮检查通过")
        state.save(config, runner, value, now)
        return 0
    value["first_failure_at"] = value["first_failure_at"] or now.isoformat()
    if ladder.elapsed(value["last_failure_tick_at"], now, config.watchdog.retry_interval_seconds):
        value["consecutive_failures"] += 1
        value["last_failure_tick_at"] = now.isoformat()
    action = ladder.decide(value, rows, now, config)
    ladder.execute(action, runner, config)
    return 2 if value["state"] == "manual" else 1


def summary(config, runner):
    value = state.read(config, runner)
    if value is None:
        return None
    return {"state": value["state"], "last_ok_at": value["last_ok_at"],
            "consecutive_failures": value["consecutive_failures"],
            "last_action": value["actions"][-1] if value["actions"] else None,
            "reason": value["reason"]}


def check(config, runner, clock=lambda: datetime.now(UTC)):
    reason = "定时检查未运行"
    try:
        active = runner.run(["systemctl", "is-active", "exitnode-watchdog.timer"], check=False)
        timer_active = active.code == 0 and active.out.strip() == "active"
        if timer_active:
            reason = "十分钟内没有检查记录"
        value = state.read(config, runner)
        age = ((clock() - state.timestamp(value["updated_at"])).total_seconds()
               if value and value["updated_at"] else None)
        result = runner.run(["systemctl", "show", "exitnode-watchdog.service",
                             "-p", "Result", "--value"], check=False)
        limited = result.out.strip() == "start-limit-hit"
        fresh = age is not None and 0 <= age < 600
        ok = timer_active and fresh and not limited
        if timer_active and fresh and limited:
            reason = ("检查任务被 systemd 启动频率限制拦下,请执行 "
                      "systemctl reset-failed exitnode-watchdog.service 并核对单元文件")
    except (OSError, RuntimeError, ValueError):
        ok = False
    return {"layer": "watchdog", "name": "看门狗", "result": "通过" if ok else "失败",
            "reason": "定时检查已启动且记录新鲜" if ok else reason}
