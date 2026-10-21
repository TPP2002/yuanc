"""所有主机交互均为 FakeRunner；时钟固定，不等待、不访问真实系统。"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from exitnode.config import load
from exitnode.runner import CompletedResult, RunnerError
from exitnode.service import LIVE
from exitnode.watchdog import check, probes, state, tick
from exitnode.watchdog.ladder import LAST_GOOD, Action, decide, execute
from test_cli import CONFIG, fake

NOW = datetime(2026, 10, 22, 0, 0, tzinfo=UTC)
RESTART = ("systemctl", "restart", "exitnode-proxy.service")
REBOOT = ("systemctl", "reboot")


def setup():
    runner = fake(pairing=True)
    config = load(CONFIG, runner)
    runner.responses[("systemctl", "is-active", "exitnode-proxy.service")] = CompletedResult(out="active\n")
    runner.responses[("ss", "-ltnH")] = CompletedResult(out="LISTEN 0 128 *:443 *:*\n")
    runner.responses[("ss", "-lunH")] = CompletedResult(out="UNCONN 0 0 [::]:24443 [::]:*\n")
    runner.files[LIVE] = '{"password":"SECRET-PASSWORD","uuid":"test-identity"}'
    return config, runner


def commands(runner):
    return [c[1] for c in runner.calls if c[0] == "run"]


def run_at(config, runner, minutes=0):
    return tick(config, runner, lambda: NOW + timedelta(minutes=minutes))


def broken(runner, layer="L-proxy"):
    if layer == "L-link":
        runner.responses[("ip", "-j", "route")] = CompletedResult(out="[]")
    elif layer == "L-upstream":
        runner.connections.clear()
    elif layer == "L-proxy":
        runner.responses[("systemctl", "is-active", "exitnode-proxy.service")] = CompletedResult(3, "inactive")
    elif layer == "L-listen":
        runner.responses[("ss", "-ltnH")] = CompletedResult(out="")
    elif layer == "L-public":
        runner.responses[("curl",)] = CompletedResult(1)


def exhausted(config, runner, *, rollback=False):
    value = state.fresh()
    value.update(state="degraded", consecutive_failures=9,
                 first_failure_at=(NOW - timedelta(minutes=10)).isoformat(),
                 restart_times=[NOW.isoformat()] * 3, restart_count_window=3,
                 rollback_attempted=rollback)
    state.save(config, runner, value, NOW)
    return value


def test_normal_snapshot_changes_only_and_resets_failures():
    config, runner = setup()
    value = exhausted(config, runner)
    assert run_at(config, runner) == 0
    saved = state.read(config, runner)
    assert saved["state"] == "normal" and saved["consecutive_failures"] == 0
    assert saved["first_failure_at"] is None and saved["last_ok_at"] == NOW.isoformat()
    assert saved["restart_times"] == value["restart_times"]  # 恢复成功也不洗掉频率历史。
    assert runner.files[LAST_GOOD] == runner.files[LIVE]
    assert runner.modes[LAST_GOOD] == runner.modes[state.path(config)] == 0o600
    def writes():
        return [c for c in runner.calls if c[:2] == ("write_file", LAST_GOOD + ".tmp")]
    assert len(writes()) == 1
    assert run_at(config, runner, 1) == 0
    assert len(writes()) == 1
    runner.files[LIVE] = '{"password":"CHANGED"}'
    assert run_at(config, runner, 2) == 0
    assert len(writes()) == 2 and runner.files[LAST_GOOD] == runner.files[LIVE]
    assert "SECRET-PASSWORD" not in runner.files[state.path(config)]
    assert "test-identity" not in runner.files[state.path(config)]
    assert state.path(config) + ".tmp" not in runner.files


def test_first_tick_reprobes_once_and_recovery_can_succeed():
    config, runner = setup()
    runner.responses[("systemctl", "is-active", "exitnode-proxy.service")] = [
        CompletedResult(3), CompletedResult(out="active")]
    assert run_at(config, runner) == 0
    assert commands(runner).count(("ip", "-j", "route")) == 2
    assert [a["action"] for a in state.read(config, runner)["actions"]] == ["reprobe"]
    assert RESTART not in commands(runner)


@pytest.mark.parametrize("layer", ["L-proxy", "L-listen"])
def test_first_three_failures_wait_and_fourth_restarts_only_proxy(layer):
    config, runner = setup()
    broken(runner, layer)
    for minute in range(3):
        assert run_at(config, runner, minute) == 1
        assert RESTART not in commands(runner)
        assert state.read(config, runner)["consecutive_failures"] == minute + 1
    assert commands(runner).count(("ip", "-j", "route")) == 4
    assert run_at(config, runner, 3) == 1
    assert commands(runner).count(RESTART) == 1
    assert LAST_GOOD not in runner.files
    assert state.read(config, runner)["actions"][-1]["action"] == "restart_service"


def test_fast_ticks_do_not_advance_failure_minutes_or_bypass_backoff():
    config, runner = setup()
    broken(runner)
    for _ in range(8):
        assert run_at(config, runner) == 1
    assert state.read(config, runner)["consecutive_failures"] == 1
    assert RESTART not in commands(runner)
    for minute in (1, 2, 3, 4, 5, 6):
        run_at(config, runner, minute)
    assert commands(runner).count(RESTART) == 3
    # 第二次后的等待时间为两分钟；第三次后四分钟。
    restarts = [a for a in state.read(config, runner)["actions"] if a["action"] == "restart_service"]
    assert [a["at"] for a in restarts] == [(NOW + timedelta(minutes=m)).isoformat() for m in (3, 4, 6)]


def test_fourth_plain_restart_is_rejected_and_window_expires():
    config, runner = setup()
    value = state.fresh()
    for minute in (0, 1, 2, 3):
        execute(Action("restart_service", value, NOW + timedelta(minutes=minute), "测试"), runner, config)
    assert commands(runner).count(RESTART) == 3
    assert value["restart_count_window"] == 3
    assert value["actions"][-1]["action"] == "wait"
    execute(Action("restart_service", value, NOW + timedelta(hours=1), "测试"), runner, config)
    assert commands(runner).count(RESTART) == 4
    assert value["restart_count_window"] == 3


def test_exhausted_plain_budget_rolls_back_immediately_with_independent_restart():
    config, runner = setup()
    broken(runner)
    value = exhausted(config, runner)
    value["next_action_at"] = (NOW + timedelta(minutes=4)).isoformat()
    state.save(config, runner, value, NOW)
    runner.files[LAST_GOOD] = "LAST-GOOD-CONTENT"
    assert run_at(config, runner) == 1
    assert runner.files[LIVE] == "LAST-GOOD-CONTENT"
    calls = runner.calls
    validation = next(i for i, c in enumerate(calls) if c[0] == "run" and c[1] ==
                      (config.proxy.binary, "check", "-c", LIVE + ".watchdog.tmp"))
    replacement = next(i for i, c in enumerate(calls) if c[:3] ==
                       ("replace", LIVE + ".watchdog.tmp", LIVE))
    restart = next(i for i, c in enumerate(calls) if c[0] == "run" and c[1] == RESTART)
    assert validation < replacement < restart
    saved = state.read(config, runner)
    assert saved["last_rollback_at"] == NOW.isoformat()
    assert saved["restart_count_window"] == 3
    assert saved["actions"][-1]["action"] == "rollback_config"
    assert run_at(config, runner, 1) == 2
    assert state.read(config, runner)["state"] == "manual"
    assert commands(runner).count(RESTART) == 1


def test_bad_rollback_check_never_touches_live_or_restarts():
    config, runner = setup()
    broken(runner)
    exhausted(config, runner)
    runner.files[LAST_GOOD] = "BAD"
    original = runner.files[LIVE]
    runner.responses[(config.proxy.binary, "check", "-c", LIVE + ".watchdog.tmp")] = CompletedResult(1, err="password=HIDDEN-SECRET")
    assert run_at(config, runner) == 2
    assert runner.files[LIVE] == original
    assert RESTART not in commands(runner)
    assert LIVE + ".watchdog.tmp" not in runner.files
    assert "HIDDEN-SECRET" not in runner.files[state.path(config)]


def test_second_rollback_in_six_hours_is_rejected_even_after_recovery():
    config, runner = setup()
    runner.files[LAST_GOOD] = "GOOD"
    value = state.fresh()
    execute(Action("rollback_config", value, NOW, "测试"), runner, config)
    assert run_at(config, runner, 1) == 0
    value = state.read(config, runner)
    execute(Action("rollback_config", value, NOW + timedelta(hours=5, minutes=59), "测试"), runner, config)
    assert commands(runner).count(RESTART) == 1
    assert value["state"] == "manual"
    execute(Action("rollback_config", value, NOW + timedelta(hours=6), "测试"), runner, config)
    assert commands(runner).count(RESTART) == 2


def test_missing_last_good_goes_manual_without_rollback():
    config, runner = setup()
    broken(runner)
    exhausted(config, runner)
    assert run_at(config, runner) == 2
    assert "没有上次可用配置" in state.read(config, runner)["reason"]
    assert RESTART not in commands(runner)
    assert not any(a["action"] == "rollback_config" for a in state.read(config, runner)["actions"])


@pytest.mark.parametrize("layer", ["L-link", "L-upstream", "L-proxy", "L-listen"])
def test_manual_29_no_reboot_30_reboot_and_record_precedes_command(layer):
    config, runner = setup()
    broken(runner, layer)
    value = state.fresh()
    value.update(state="manual", consecutive_failures=20, first_failure_at=NOW.isoformat())
    state.save(config, runner, value, NOW)
    assert run_at(config, runner, 29) == 2
    assert REBOOT not in commands(runner)
    assert run_at(config, runner, 30) == 2
    assert commands(runner).count(REBOOT) == 1
    reboot_index = next(i for i, c in enumerate(runner.calls) if c[0] == "run" and c[1] == REBOOT)
    preceding = runner.calls[:reboot_index]
    write = [c for c in preceding if c[:2] == ("write_file", state.path(config) + ".tmp")][-1]
    assert json.loads(write[2])["last_reboot_at"] == (NOW + timedelta(minutes=30)).isoformat()
    assert preceding[-1] == ("replace", state.path(config) + ".tmp", state.path(config))
    assert run_at(config, runner, 389) == 2
    assert commands(runner).count(REBOOT) == 1
    assert run_at(config, runner, 390) == 2
    assert commands(runner).count(REBOOT) == 2
    assert RESTART not in commands(runner)


@pytest.mark.parametrize("layer", ["L-link", "L-upstream"])
def test_network_failure_never_restarts_services_but_reaches_manual(layer):
    config, runner = setup()
    broken(runner, layer)
    for minute in range(4):
        assert run_at(config, runner, minute) == (1 if minute < 3 else 2)
    assert run_at(config, runner, 30) == 2
    assert REBOOT in commands(runner) and RESTART not in commands(runner)
    assert not any(cmd[0] == "curl" for cmd in commands(runner))


def test_reboot_disabled_and_nonmanual_cannot_reboot():
    config, runner = setup()
    broken(runner)
    value = state.fresh()
    value.update(state="manual", first_failure_at=NOW.isoformat(), consecutive_failures=30)
    state.save(config, runner, value, NOW)
    config.watchdog.reboot_enabled = False
    assert run_at(config, runner, 1200) == 2
    assert REBOOT not in commands(runner)
    config.watchdog.reboot_enabled = True
    value["state"] = "degraded"
    execute(Action("reboot", value, NOW + timedelta(days=1), "测试"), runner, config)
    assert REBOOT not in commands(runner)


def test_public_failure_only_degrades_even_after_thirty_minutes():
    config, runner = setup()
    broken(runner, "L-public")
    for minute in (0, 1, 2, 3, 30, 360, 999):
        assert run_at(config, runner, minute) == 1
    assert RESTART not in commands(runner) and REBOOT not in commands(runner)
    assert state.read(config, runner)["state"] == "degraded"
    assert LAST_GOOD not in runner.files


@pytest.mark.parametrize("result", [CompletedResult(127), RunnerError("命令不存在")])
def test_missing_ss_is_unknown_and_not_failure(result):
    config, runner = setup()
    runner.responses[("ss", "-ltnH")] = result
    runner.responses[("ss", "-lunH")] = result
    assert run_at(config, runner) == 0
    rows = state.read(config, runner)["probes"]
    assert next(p for p in rows if p["layer"] == "L-listen")["result"] == "未知"


def test_listener_matches_local_port_not_peer_or_suffix():
    config, runner = setup()
    runner.responses[("ss", "-ltnH")] = CompletedResult(out="LISTEN 0 128 *:1443 *:443\n")
    assert next(p for p in probes.probe(config, runner) if p["layer"] == "L-listen")["result"] == "失败"


def test_proxy_requires_active_text_and_valid_check():
    config, runner = setup()
    runner.responses[("systemctl", "is-active", "exitnode-proxy.service")] = CompletedResult(out="inactive")
    assert run_at(config, runner) == 1
    assert LAST_GOOD not in runner.files
    runner.responses[("systemctl", "is-active", "exitnode-proxy.service")] = CompletedResult(out="active")
    runner.responses[(config.proxy.binary, "check", "-c", LIVE)] = CompletedResult(1)
    assert run_at(config, runner, 1) == 1
    assert LAST_GOOD not in runner.files


@pytest.mark.parametrize("content", ["{bad", "[]", '{"state":"normal"}'])
def test_corrupt_state_rebuilt_and_recorded_without_resetting_limits(content):
    config, runner = setup()
    broken(runner)
    runner.files[state.path(config)] = content
    assert run_at(config, runner) == 2
    value = state.read(config, runner)
    assert any(a["action"] == "rebuild_state" for a in value["actions"])
    assert value["restart_count_window"] == 3
    assert RESTART not in commands(runner) and REBOOT not in commands(runner)


def test_action_history_capped_redacted_and_does_not_lose_limits():
    config, runner = setup()
    value = exhausted(config, runner)
    for index in range(60):
        state.record(value, "wait", NOW, f"password=DO-NOT-LEAK-{index}")
    state.save(config, runner, value, NOW)
    value = state.read(config, runner)
    assert len(value["actions"]) == 50 and "DO-NOT-LEAK" not in runner.files[state.path(config)]
    execute(Action("restart_service", value, NOW, "测试"), runner, config)
    assert RESTART not in commands(runner)


def test_state_write_failure_prevents_reboot(monkeypatch):
    config, runner = setup()
    value = state.fresh()
    value.update(state="manual", first_failure_at=(NOW - timedelta(hours=1)).isoformat())

    def fail(source, target):
        raise OSError("磁盘写入失败")

    monkeypatch.setattr(runner, "replace", fail)
    with pytest.raises(OSError):
        execute(Action("reboot", value, NOW, "测试"), runner, config)
    assert REBOOT not in commands(runner)


@pytest.mark.parametrize("unit", ["ssh.service", "exitnode-foreign.service", "--all"])
def test_only_explicit_project_services_can_restart(unit):
    config, runner = setup()
    with pytest.raises(ValueError):
        execute(Action("restart_service", state.fresh(), NOW, "测试", unit), runner, config)
    assert not commands(runner)


def test_disabled_tick_has_no_side_effects():
    config, runner = setup()
    config.watchdog.enabled = False
    before = list(runner.calls)
    assert run_at(config, runner) == 0
    assert runner.calls == before


def test_check_requires_timer_and_record_younger_than_one_day():
    config, runner = setup()
    runner.responses[("systemctl", "is-active", "exitnode-watchdog.timer")] = CompletedResult(out="active")
    assert check(config, runner, lambda: NOW)["result"] == "失败"
    state.save(config, runner, state.fresh(), NOW)
    assert check(config, runner, lambda: NOW + timedelta(hours=23, minutes=59))["result"] == "通过"
    assert check(config, runner, lambda: NOW + timedelta(hours=24))["result"] == "失败"
    runner.responses[("systemctl", "is-active", "exitnode-watchdog.timer")] = CompletedResult(3, "inactive")
    assert check(config, runner, lambda: NOW)["result"] == "失败"


def test_decision_rejects_second_rollback_and_plain_restart_respects_window():
    config, runner = setup()
    broken(runner)
    value = exhausted(config, runner)
    value["last_rollback_at"] = (NOW - timedelta(hours=5)).isoformat()
    assert decide(value, probes.probe(config, runner), NOW, config).name == "manual"
    value["last_rollback_at"] = (NOW - timedelta(hours=6)).isoformat()
    assert decide(value, probes.probe(config, runner), NOW, config).name == "rollback_config"


def test_listener_uses_configured_reality_port():
    from dataclasses import replace
    config, runner = setup()
    config = replace(config, proxy=replace(config.proxy, reality_port=14443))
    assert next(p for p in probes.probe(config, runner) if p["layer"] == "L-listen")["result"] == "失败"
    runner.responses[("ss", "-ltnH")] = CompletedResult(out="LISTEN 0 128 *:14443 *:*\n")
    assert next(p for p in probes.probe(config, runner) if p["layer"] == "L-listen")["result"] == "通过"
