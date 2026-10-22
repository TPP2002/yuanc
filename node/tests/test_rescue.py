"""救援用自己的内存主机；不运行真实命令，不读取真实 Linux 路径。"""

import errno
import hashlib
import json
import subprocess

import pytest
from exitnode.rescue import actions
from exitnode.rescue import probes as p
from exitnode.rescue import state as s
from exitnode.rescue.__main__ import main
from exitnode.rescue.runner import FakeRunner, RealRunner, Result

IMPORT = ("env", "PYTHONPATH=" + p.CURRENT, "python3", "-c", "import exitnode, exitnode.cli")


def put(runner, directory, version="0.1.0"):
    files = {"exitnode/__init__.py": version.encode(), "bin/sing-box": b"kernel"}
    for name, data in files.items():
        runner.files[directory + "/" + name] = data
    runner.files[directory + "/manifest.json"] = json.dumps({
        "version": version,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }).encode()


def ready():
    runner = FakeRunner(responses={IMPORT: Result(), (p.BINARY,): Result(),
                                  ("systemctl",): Result()})
    put(runner, p.FACTORY)
    put(runner, p.RELEASES + "/0.2.0", "0.2.0")
    runner.symlink(p.RELEASES + "/0.2.0", p.CURRENT)
    runner.files[p.LIVE] = b"private-live-content"
    runner.files[p.LAST_GOOD] = b"private-last-good-content"
    runner.calls.clear()
    return runner


def mutations(runner):
    return [c for c in runner.calls if c[0] in {
        "write", "replace", "copy_tree", "remove_tree", "mkdir", "symlink"}]


def service_actions(runner):
    return [c[1] for c in runner.calls if c[0] == "run"
            and c[1][:2] in (("systemctl", "restart"), ("systemctl", "reset-failed"),
                            ("systemctl", "daemon-reload"))]


def damage(runner, probe):
    if probe == "P1":
        runner.files[p.RELEASES + "/0.2.0/bin/sing-box"] = b"corrupt"
    elif probe == "P2":
        runner.responses[IMPORT] = [Result(1), Result(1), Result()]
    else:
        runner.responses[(p.BINARY, "version")] = [Result(1), Result(1), Result()]


@pytest.mark.parametrize("failure", ["P1", "P2", "P3"])
def test_two_rounds_reinstall_atomic_switch_restore_and_three_restarts(failure):
    runner = ready()
    damage(runner, failure)
    assert actions.tick(runner) == 1
    assert not service_actions(runner)
    assert not any(c[0] == "copy_tree" for c in runner.calls)
    runner.clock += 300
    assert actions.tick(runner) == 0
    assert runner.links[p.CURRENT] == p.RELEASES + "/0.1.0"
    assert p.release(runner, runner.links[p.CURRENT]) == "0.1.0"
    assert runner.files[p.LIVE] == runner.files[p.LAST_GOOD]
    assert ("replace", p.CURRENT + ".new", p.CURRENT) in runner.calls
    assert service_actions(runner) == [
        ("systemctl", "daemon-reload"), ("systemctl", "restart", "exitnode-proxy.service"),
        ("systemctl", "restart", "exitnode-admin.service"),
        ("systemctl", "restart", "exitnode-watchdog.timer")]
    assert json.loads(runner.files[s.HISTORY].splitlines()[-1])["status"] == "ok"
    assert all(c[2] == 30 for c in runner.calls if c[0] == "run")


def test_fast_reruns_do_not_increment_and_success_clears_counts():
    runner = ready()
    damage(runner, "P1")
    actions.tick(runner)
    runner.clock += 59
    actions.tick(runner)
    assert s.read(runner)["counts"]["P1"] == 1
    assert not service_actions(runner)
    put(runner, p.RELEASES + "/0.2.0", "0.2.0")
    assert actions.tick(runner) == 0
    assert set(s.read(runner)["counts"].values()) == {0}


def test_import_timeout_counts_as_program_failure():
    runner = ready()
    runner.responses[IMPORT] = subprocess.TimeoutExpired("hidden", 30)
    assert actions.tick(runner) == 1
    assert s.read(runner)["counts"]["P2"] == 1


def test_bad_factory_never_mutates_program_config_or_units():
    runner = ready()
    damage(runner, "P1")
    runner.files[p.FACTORY + "/bin/sing-box"] = b"bad factory"
    actions.tick(runner)
    before = dict(runner.files)
    runner.clock += 300
    runner.calls.clear()
    assert actions.tick(runner) == 2
    assert "出厂包损坏" in s.read(runner)["reason"]
    assert {k: v for k, v in runner.files.items() if not k.startswith(s.DATA)} == {
        k: v for k, v in before.items() if not k.startswith(s.DATA)}
    assert not service_actions(runner)
    assert not any(c[0] in {"copy_tree", "symlink"} for c in runner.calls)


@pytest.mark.parametrize("times", [[-300], [-80000, -22000]])
def test_reinstall_six_hour_and_daily_limit(times):
    runner = ready()
    damage(runner, "P1")
    value = s.fresh()
    value["reinstall_times"] = [runner.clock + at for at in times]
    value["counts"]["P1"] = 1
    s.save(runner, value)
    assert actions.tick(runner) == 2
    assert "频率超限" in s.read(runner)["reason"]
    assert not service_actions(runner)


def test_updater_lock_skips_entire_round_even_cleanup_and_state():
    runner = ready()
    runner.locks.add(p.LOCK)
    runner.files[p.RESCUE + "/factory.old-1/data"] = b"old"
    before = dict(runner.files)
    assert actions.tick(runner) == 1
    assert runner.files == before
    assert runner.calls == [("lock_busy", p.LOCK)]


@pytest.mark.parametrize("good", [True, False, None])
def test_bad_live_restores_only_checked_last_good(good):
    runner = ready()
    runner.responses[(p.BINARY, "check", "-c", p.LIVE)] = Result(1)
    if good is None:
        del runner.files[p.LAST_GOOD]
    elif not good:
        runner.responses[(p.BINARY, "check", "-c", p.LAST_GOOD + ".rescue.check.tmp")] = Result(1)
    assert actions.tick(runner) == 1
    assert runner.files[p.LIVE] == b"private-live-content"
    runner.clock += 300
    assert actions.tick(runner) == (1 if good else 2)
    if good:
        assert runner.files[p.LIVE] == b"private-last-good-content"
        check = next(i for i, c in enumerate(runner.calls)
                     if c[0] == "run" and c[1][-1] == p.LIVE + ".rescue.tmp")
        assert check < runner.calls.index(("replace", p.LIVE + ".rescue.tmp", p.LIVE))
        assert service_actions(runner) == [("systemctl", "restart", "exitnode-proxy.service")]
        before = list(service_actions(runner))
        runner.clock += 1
        assert actions.tick(runner) == 1
        assert service_actions(runner) == before
    else:
        assert runner.files[p.LIVE] == b"private-live-content"
        assert not service_actions(runner)


def test_failed_unit_reset_once_per_hour():
    runner = ready()
    runner.responses[("systemctl", "is-failed")] = Result(0, "failed\n")
    actions.tick(runner)
    runner.clock += 300
    assert actions.tick(runner) == 1
    assert service_actions(runner) == [("systemctl", "reset-failed", "exitnode-proxy.service"),
                                      ("systemctl", "restart", "exitnode-proxy.service")]
    before = service_actions(runner)
    runner.clock += 300
    assert actions.tick(runner) == 2
    assert service_actions(runner) == before


def watcher(runner, state="normal", age=0):
    runner.files[p.WATCHDOG] = json.dumps({"state": state,
                                         "updated_at": s.iso(runner.clock - age)}).encode()


def update_ok(runner, age=86400, status="ok", version="0.2.0"):
    runner.files[p.UPDATES] = json.dumps({"version": version, "status": status,
                                        "at": s.iso(runner.clock - age)}).encode() + b"\n"


def test_watchdog_manual_never_causes_program_reinstall_or_promotion():
    runner = ready()
    watcher(runner, "manual")
    update_ok(runner)
    assert actions.tick(runner) == 0
    runner.clock += 300
    assert actions.tick(runner) == 0
    assert not service_actions(runner)
    assert not any(c[0] == "copy_tree" for c in runner.calls)
    assert s.read(runner)["watchdog_state"] == "manual"
    damage(runner, "P1")
    actions.tick(runner)
    runner.clock += 300
    assert actions.tick(runner) == 2
    assert not service_actions(runner)


@pytest.mark.parametrize("missing", ["same-version", "watchdog", "stale", "not-normal",
                                     "history", "young", "bad-status", "wrong-version", None])
def test_auto_promote_requires_all_three_conditions(missing):
    runner = ready()
    watcher(runner)
    update_ok(runner)
    if missing == "same-version":
        put(runner, p.FACTORY, "0.2.0")
    elif missing == "watchdog":
        runner.files[p.WATCHDOG] = b"broken"
    elif missing == "stale":
        watcher(runner, age=601)
    elif missing == "not-normal":
        watcher(runner, "degraded")
    elif missing == "history":
        del runner.files[p.UPDATES]
    elif missing == "young":
        update_ok(runner, age=86399)
    elif missing == "bad-status":
        update_ok(runner, status="rolled_back")
    elif missing == "wrong-version":
        update_ok(runner, version="0.3.0")
    assert actions.tick(runner) == 0
    copies = [c for c in runner.calls if c[0] == "copy_tree"]
    assert bool(copies) == (missing is None)
    if missing is None:
        assert p.release(runner, p.FACTORY) == "0.2.0"
        assert ("replace", p.FACTORY + ".staging", p.FACTORY) in runner.calls
        assert json.loads(runner.files[s.HISTORY].splitlines()[-1])["status"] == "promoted"


def test_promote_checks_current_hash_and_entrypoints(capsys):
    runner = ready()
    damage(runner, "P1")
    before = {k: v for k, v in runner.files.items() if k.startswith(p.FACTORY)}
    assert main(["promote"], runner) == 2
    assert {k: v for k, v in runner.files.items() if k.startswith(p.FACTORY)} == before
    assert main(["status"], runner) == 2
    assert "需人工处理" in capsys.readouterr().out
    put(runner, p.RELEASES + "/0.2.0", "0.2.0")
    assert main(["promote"], runner) == 0
    assert main(["refresh-check"], runner) == 0


def test_state_history_permissions_atomic_and_no_secret_content():
    runner = ready()
    damage(runner, "P1")
    actions.tick(runner)
    runner.clock += 300
    actions.tick(runner)
    for path in (s.STATE, s.HISTORY):
        assert runner.modes[path] == 0o600
        assert ("replace", path + ".tmp", path) in runner.calls
        assert b"private-live-content" not in runner.files[path]
        assert b"private-last-good-content" not in runner.files[path]


@pytest.mark.parametrize("existing", [False, True])
def test_fake_replace_whole_directory_removes_old_contents(existing):
    runner = FakeRunner(files={"/src/new": b"new"})
    if existing:
        runner.files["/dst/old/deep"] = b"old"
    runner.replace("/src", "/dst")
    assert runner.files == {"/dst/new": b"new"}
    assert runner.calls[0] == ("replace", "/src", "/dst")


def test_tick_recovers_interrupted_two_rename_and_cleans_residue():
    runner = ready()
    runner.replace(p.FACTORY, p.FACTORY + ".old-100")
    runner.files[p.FACTORY + ".staging/partial"] = b"partial"
    runner.files[p.RESCUE + "/exitnode_rescue.new/partial"] = b"partial"
    runner.files[p.RELEASES + "/0.1.0.rescue-staging/partial"] = b"partial"
    assert actions.tick(runner) == 0
    assert p.release(runner, p.FACTORY) == "0.1.0"
    assert not any(".old-" in name or name.endswith(".staging") or ".rescue-staging/" in name
                   or ".new/" in name for name in runner.files)


def test_reinstall_reuses_verified_version_and_rebuilds_corrupt_version():
    for corrupt in (False, True):
        runner = ready()
        target = p.RELEASES + "/0.1.0"
        put(runner, target)
        if corrupt:
            runner.files[target + "/bin/sing-box"] = b"bad"
        assert actions.reinstall(runner) == "0.1.0"
        assert p.release(runner, target) == "0.1.0"
        assert any(c[0] == "copy_tree" for c in runner.calls) == corrupt


def test_reprobe_failure_records_failed_and_manual_and_counts_attempt():
    runner = ready()
    runner.responses[IMPORT] = Result(1)
    actions.tick(runner)
    runner.clock += 300
    assert actions.tick(runner) == 2
    assert len(s.read(runner)["reinstall_times"]) == 1
    assert json.loads(runner.files[s.HISTORY].splitlines()[-1])["status"] == "failed"


def test_corrupt_own_state_cannot_reset_rate_allowance():
    runner = ready()
    runner.files[s.STATE] = b"broken"
    assert actions.tick(runner) == 2
    assert s.read(runner)["corrupt"]
    assert not service_actions(runner)


@pytest.mark.parametrize("existing,exchange", [(False, False), (True, True), (True, False)])
def test_real_replace_routes_without_touching_real_files(monkeypatch, existing, exchange):
    from exitnode.rescue import runner as module

    real = object.__new__(RealRunner)
    calls = []
    monkeypatch.setattr(real, "exists", lambda path: existing)
    monkeypatch.setattr(real, "_exchange", lambda src, dst: calls.append(("exchange", src, dst)) or exchange)
    monkeypatch.setattr(real, "_sync_parent", lambda path: calls.append(("sync", path)))
    monkeypatch.setattr(real, "remove_tree", lambda path: calls.append(("remove", path)))
    monkeypatch.setattr(module.os, "rename", lambda src, dst: calls.append(("rename", src, dst)))
    monkeypatch.setattr(module.time, "time_ns", lambda: 123)
    real.replace("/source", "/target")
    renames = [c for c in calls if c[0] == "rename"]
    if not existing:
        assert renames == [("rename", "/source", "/target")]
    elif exchange:
        assert renames == []
        assert ("remove", "/source") in calls
    else:
        assert renames == [("rename", "/target", "/target.old-123"),
                           ("rename", "/source", "/target")]
        assert calls.index(("sync", "/target")) < calls.index(renames[1])
        assert ("remove", "/target.old-123") in calls


def test_real_fallback_second_rename_error_is_not_swallowed(monkeypatch):
    from exitnode.rescue import runner as module

    fake = FakeRunner(files={"/source/new": b"new", "/target/old": b"old"})
    real = object.__new__(RealRunner)
    monkeypatch.setattr(real, "exists", fake.exists)
    monkeypatch.setattr(real, "_exchange", lambda src, dst: False)
    monkeypatch.setattr(real, "_sync_parent", lambda path: None)
    monkeypatch.setattr(real, "remove_tree", fake.remove_tree)
    monkeypatch.setattr(module.time, "time_ns", lambda: 123)
    error = OSError(errno.EIO, "simulated failure")

    def rename(src, dst):
        if src == "/source":
            raise error
        fake.replace(src, dst)

    monkeypatch.setattr(module.os, "rename", rename)
    with pytest.raises(OSError) as exc:
        real.replace("/source", "/target")
    assert exc.value is error
    assert fake.files["/target.old-123/old"] == b"old"
    assert not fake.exists("/target")


@pytest.mark.parametrize("error", [errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV, errno.EACCES])
def test_exchange_unsupported_fallback_but_other_errors_propagate(monkeypatch, error):
    from exitnode.rescue import runner as module

    class Rename:
        def __call__(self, *args):
            assert args == (-100, b"/source", -100, b"/target", 2)
            return -1

    class Library:
        renameat2 = Rename()

    monkeypatch.setattr(module.ctypes, "CDLL", lambda *args, **kwargs: Library())
    monkeypatch.setattr(module.ctypes, "get_errno", lambda: error)
    if error == errno.EACCES:
        with pytest.raises(OSError) as exc:
            RealRunner._exchange("/source", "/target")
        assert exc.value.errno == error
    else:
        assert RealRunner._exchange("/source", "/target") is False


def test_exchange_missing_symbol_is_unsupported(monkeypatch):
    from exitnode.rescue import runner as module

    monkeypatch.setattr(module.ctypes, "CDLL", lambda *args, **kwargs: object())
    assert RealRunner._exchange("/source", "/target") is False


def test_reinstall_corrupt_factory_has_absolutely_no_mutations():
    runner = ready()
    runner.files[p.FACTORY + "/bin/sing-box"] = b"bad"
    before = dict(runner.files)
    with pytest.raises(ValueError, match="出厂包损坏"):
        actions.reinstall(runner)
    assert runner.files == before
    assert mutations(runner) == []


@pytest.mark.parametrize("target", ["/unrelated/version", "releases/../other", "releases/0.2.0"])
def test_current_link_must_be_direct_release_child(target):
    runner = ready()
    runner.links[p.CURRENT] = target
    assert p.probe(runner)["P1"] == (target == "releases/0.2.0")


def test_p1_checks_hashes_without_requiring_manifest_version_spelling_as_directory():
    runner = ready()
    put(runner, p.RELEASES + "/0.2.0", "v0.2.0")
    assert p.probe(runner)["P1"] is True


@pytest.mark.parametrize("busy", [False, True])
def test_real_flock_probe_is_nonblocking_and_released_immediately(monkeypatch, busy):
    import sys
    from types import SimpleNamespace

    from exitnode.rescue import runner as module

    calls = []

    def flock(fd, flags):
        calls.append(("flock", fd, flags))
        if busy:
            raise BlockingIOError

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(
        flock=flock, LOCK_EX=2, LOCK_NB=4, LOCK_UN=8))
    monkeypatch.setattr(module.os, "O_NOFOLLOW", 0x20000, raising=False)
    monkeypatch.setattr(module.os, "open", lambda *args: 123)
    monkeypatch.setattr(module.os, "close", lambda fd: calls.append(("close", fd)))
    real = object.__new__(RealRunner)
    assert real.lock_busy(p.LOCK) is busy
    assert calls == ([("flock", 123, 6), ("close", 123)] if busy else [
        ("flock", 123, 6), ("flock", 123, 8), ("close", 123)])


@pytest.mark.parametrize("reinstall", [False, True])
def test_rescue_prunes_both_checks_and_reports_record_count(monkeypatch, reinstall):
    from test_watchdog import last_good_fixture

    runner = ready()
    text, devices = last_good_fixture()
    runner.files[p.LAST_GOOD] = text.encode()
    runner.files["/var/lib/exitnode/secrets/devices.json"] = devices.encode()
    if reinstall:
        damage(runner, "P1")
    else:
        runner.responses[(p.BINARY, "check", "-c", p.LIVE)] = Result(1)
    checked_contents = []
    run = runner.run

    def capture(argv, timeout=30):
        if argv[:3] == [p.BINARY, "check", "-c"] and argv[-1] != p.LIVE:
            checked_contents.append(runner.read(argv[-1]))
        return run(argv, timeout=timeout)

    monkeypatch.setattr(runner, "run", capture)
    assert actions.tick(runner) == 1
    runner.clock += 300
    assert actions.tick(runner) == (0 if reinstall else 1)
    live = runner.files[p.LIVE]
    assert len(checked_contents) == 2
    assert checked_contents == [live, live]
    users = [row["users"] for row in json.loads(live)["inbounds"]]
    assert users == [[{"uuid": "保留凭据"}], [{"name": "保留设备", "password": "测试密码"}]]
    assert "已剔除 2 条不在登记表上的用户记录" in s.read(runner)["reason"]
    assert ("systemctl", "restart", "exitnode-proxy.service") in service_actions(runner)
    assert runner.modes[p.LIVE] == 0o600
    for path in (s.STATE, s.HISTORY):
        for secret in ("保留设备", "保留凭据", "吊销设备", "吊销凭据", "测试密码"):
            assert secret.encode() not in runner.files[path]


@pytest.mark.parametrize("devices", [b"broken", b"\xff"])
def test_rescue_corrupt_devices_refuses_restore_without_service_action(devices):
    runner = ready()
    runner.files["/var/lib/exitnode/secrets/devices.json"] = devices
    runner.responses[(p.BINARY, "check", "-c", p.LIVE)] = Result(1)
    original = runner.files[p.LIVE]
    assert actions.tick(runner) == 1
    runner.clock += 300
    assert actions.tick(runner) == 2
    assert s.read(runner)["reason"] == "设备登记表损坏，无法核对上次可用配置"
    assert runner.files[p.LIVE] == original
    assert not service_actions(runner)


@pytest.mark.parametrize("failed_path", [p.LAST_GOOD + ".rescue.check.tmp", p.LIVE + ".rescue.tmp"])
def test_pruned_rescue_still_requires_both_checks(failed_path):
    from test_watchdog import last_good_fixture

    runner = ready()
    text, devices = last_good_fixture()
    runner.files[p.LAST_GOOD] = text.encode()
    runner.files["/var/lib/exitnode/secrets/devices.json"] = devices.encode()
    runner.responses[(p.BINARY, "check", "-c", p.LIVE)] = Result(1)
    runner.responses[(p.BINARY, "check", "-c", failed_path)] = Result(1)
    original = runner.files[p.LIVE]
    assert actions.tick(runner) == 1
    runner.clock += 300
    assert actions.tick(runner) == 2
    assert runner.files[p.LIVE] == original
    assert runner.files[p.LAST_GOOD] == text.encode()
    assert not service_actions(runner)
    assert ("replace", p.LIVE + ".rescue.tmp", p.LIVE) not in runner.calls
    assert not runner.exists(p.LAST_GOOD + ".rescue.check.tmp")
    assert not runner.exists(p.LIVE + ".rescue.tmp")


def test_reinstall_with_corrupt_devices_keeps_live_and_completes():
    runner = ready()
    damage(runner, "P1")
    runner.files["/var/lib/exitnode/secrets/devices.json"] = b"broken"
    original = runner.files[p.LIVE]
    assert actions.tick(runner) == 1
    assert not service_actions(runner)
    assert not any(c[0] == "copy_tree" for c in runner.calls)
    runner.clock += 300
    assert actions.tick(runner) == 0
    assert runner.files[p.LIVE] == original
    assert runner.links[p.CURRENT] == p.RELEASES + "/0.1.0"
    assert p.release(runner, runner.links[p.CURRENT]) == "0.1.0"
    assert ("replace", p.CURRENT + ".new", p.CURRENT) in runner.calls
    assert service_actions(runner) == [
        ("systemctl", "daemon-reload"), ("systemctl", "restart", "exitnode-proxy.service"),
        ("systemctl", "restart", "exitnode-admin.service"),
        ("systemctl", "restart", "exitnode-watchdog.timer")]
    assert json.loads(runner.files[s.HISTORY].splitlines()[-1])["status"] == "ok"
    assert all(c[2] == 30 for c in runner.calls if c[0] == "run")


def test_rescue_package_only_imports_stdlib_and_itself():
    import ast
    import sys
    from pathlib import Path

    for source in Path(actions.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module]
            else:
                continue
            assert all(name.split(".")[0] in sys.stdlib_module_names for name in names)
