import io
import json
import logging
import zipfile
from pathlib import Path

import pytest
from exitnode.cli import main, parser
from exitnode.config import load
from exitnode.log import RedactingFormatter, configure
from exitnode.netinfo import check, probe_upstream, read_network
from exitnode.runner import CompletedResult, FakeRunner
from exitnode.status import State, evaluate

CONFIG = "/etc/exitnode/config.toml"
TEXT = (Path(__file__).parents[1] / "examples" / "config.example.toml").read_text(encoding="utf-8")


def fake(*, pairing=False):
    runner = FakeRunner(files={
        CONFIG: TEXT, "/usr/bin/sing-box": "测试内核",
        (Path(__file__).parents[1] / "exitnode" / "__init__.py").as_posix():
            '__version__ = "0.1.0"\n',
        "/var/lib/exitnode/secrets/hy2.crt": "测试证书",
        "/var/lib/exitnode/secrets/hy2.key": "测试私钥占位",
    }, responses={
        ("openssl", "x509"): CompletedResult(out="X509v3 Subject Alternative Name:\n    DNS:exitnode\n"),
        ("ip", "-j", "route"): CompletedResult(out='[{"dst":"default","dev":"eth0","gateway":"192.0.2.1"}]'),
        ("ip", "-j", "addr"): CompletedResult(out=json.dumps([
            {"ifname": "eth0", "ifindex": 2, "flags": ["UP"],
             "addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.2"}]}])),
        ("systemctl",): CompletedResult(),
        ("nft", "-j"): CompletedResult(out='{"nftables":[]}'),
        ("nft", "-f"): CompletedResult(),
        ("/usr/bin/sing-box", "check"): CompletedResult(),
    }, connections={("8.8.8.8", 443): True})
    source = (Path(__file__).parents[1] / "exitnode" / "rescue").as_posix()
    for name in ("__init__.py", "__main__.py", "runner.py", "state.py", "probes.py", "actions.py"):
        runner.files[source + "/" + name] = "# simulated rescue source\n"
    if pairing:
        runner.responses[("curl",)] = CompletedResult(out="ip=203.0.113.9\n")
    return runner


@pytest.mark.parametrize("command", ["init", "check", "status", "diagnose", "upgrade", "rollback", "uninstall"])
def test_seven_subcommands_parse(command):
    argv = [command] + (["--output", "/report.zip"] if command == "diagnose" else [])
    assert parser().parse_args(argv).command == command


def test_help_lists_all_commands_without_system_access(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"], FakeRunner())
    assert exc.value.code == 0
    text = capsys.readouterr().out
    for name in ("init", "check", "status", "diagnose", "upgrade", "rollback", "uninstall"):
        assert name in text


def test_status_json_fields_and_four_states(capsys):
    runner = fake()
    assert main(["status", "--json"], runner) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result) == {"state", "version", "network", "path", "last_ok_at", "reason",
                           "public_ipv4", "watchdog"}
    assert result["watchdog"] is None
    assert result["public_ipv4"] is None
    assert result["state"] == "normal"
    assert set(result["network"]) == {"iface", "gateway", "dhcp", "addr"}
    assert result["network"]["dhcp"] == "unknown"
    assert result["path"] == "unknown" and result["last_ok_at"] is None
    assert "未接入" in result["reason"]
    assert {s.value for s in State} == {"normal", "reconnecting", "reauth", "manual"}


def test_check_unintegrated_layers_are_not_passed(capsys, monkeypatch):
    from datetime import UTC, datetime

    from exitnode.watchdog import state

    runner = fake()
    monkeypatch.setattr("exitnode.admin.server.check", lambda config: {
        "layer": "winclient", "name": "客户端托管服务", "result": "通过", "reason": "测试响应"})
    config = load(CONFIG, runner)
    state.save(config, runner, state.fresh(), datetime.now(UTC))
    runner.responses[("systemctl", "is-active", "exitnode-watchdog.timer")] = CompletedResult(out="active")
    from exitnode.rescue import state as rescue_state

    runner.files[rescue_state.STATE] = json.dumps({"state": "normal", "reason": "正常",
                                                "updated_at": rescue_state.iso(runner.now())})
    runner.responses[("systemctl", "is-active", "exitnode-rescue.timer")] = CompletedResult(out="active")
    assert main(["check", "--json"], runner) == 0
    layers = json.loads(capsys.readouterr().out)["layers"]
    assert [layer["result"] for layer in layers] == ["通过", "通过", "未接入", "未接入", "未接入", "通过", "通过", "通过", "通过"]
    assert layers[-4]["name"] == "看门狗"
    assert layers[-3]["name"] == "救援单元"
    assert layers[-2]["name"] == "隧道服务"
    assert layers[-1]["name"] == "客户端托管服务"


def test_upgrade_is_explicit_failure_without_config_or_system(capsys):
    runner = FakeRunner()
    assert main(["upgrade", "--version", "0.2.0"], runner) == 2
    assert "未实现" in capsys.readouterr().err
    assert runner.calls == []
    assert main(["--placeholder", "proxy"], runner) == 2


def test_network_failure_and_multi_target_probe():
    runner = fake()
    config = load(CONFIG, runner)
    probe = probe_upstream(runner, config.network.probe_targets)
    assert probe["ok"] is True
    assert [item["ok"] for item in probe["targets"]] == [False, True]
    runner.connections.clear()
    assert evaluate(check(runner, config)).state == State.RECONNECTING
    runner = fake()
    runner.responses[("ip", "-j", "route")] = CompletedResult(out="[]")
    assert evaluate(check(runner, config)).state == State.RECONNECTING


def test_dhcp_requires_matching_lease_and_selected_iface_must_exist():
    runner = fake()
    lease = "/run/systemd/netif/leases/2"
    runner.files[lease] = "ADDRESS=192.0.2.2\n"
    assert read_network(runner)[0]["dhcp"] is True
    runner.files[lease] = "ADDRESS=192.0.2.99\n"
    assert read_network(runner)[0]["dhcp"] == "unknown"
    assert read_network(runner, "eth9")[1] is False


def test_log_redaction_including_formatted_args_and_exception(monkeypatch):
    stream = io.StringIO()
    logger = logging.getLogger("exitnode.tests.redaction")
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "level", logging.WARNING)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger.addHandler(handler)
    try:
        logger.warning("token=%s key=%s uuid=%s", "abcdefgh", "ijklmnop",
                       "12345678-1234-1234-1234-123456789abc")
        try:
            raise ValueError("token=EXCEPTIONVALUE")
        except ValueError:
            logger.exception("处理失败")
    finally:
        logger.removeHandler(handler)
        handler.close()
    text = stream.getvalue()
    assert "abcd***" in text and "ijkl***" in text and "1234***" in text
    assert "abcdefgh" not in text and "ijklmnop" not in text
    assert "12345678-1234" not in text and "EXCEPTIONVALUE" not in text


def test_runner_log_and_diagnostic_archive_do_not_read_secrets(capsys):
    runner = fake()
    logger = configure(runner, "/var/lib/exitnode/logs")
    logger.warning("token=abcdefgh key=ijklmnop")
    runner.files["/var/lib/exitnode/secrets/private"] = "DO-NOT-READ"
    assert main(["diagnose", "--output", "/diagnose.zip"], runner) == 0
    with zipfile.ZipFile(io.BytesIO(runner.files["/diagnose.zip"])) as archive:
        content = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
    assert "abcdefgh" not in content and "ijklmnop" not in content
    assert "DO-NOT-READ" not in content
    assert not any(c[0] == "read_file" and "/secrets/" in c[1] for c in runner.calls)
    assert runner.modes["/diagnose.zip"] == 0o600
    assert "诊断包已保存" in capsys.readouterr().out


def test_repeated_init_does_not_repeat_commands_and_uninstall_keeps_secrets():
    runner = fake(pairing=True)
    runner.files["/var/lib/exitnode/secrets/identity"] = "保留"
    assert main(["init"], runner) == 0
    assert runner.readlink("/opt/exitnode/current") == "/opt/exitnode/releases/0.1.0"
    saved_program = runner.read_bytes("/opt/exitnode/current/exitnode/__init__.py")
    steps = json.loads(runner.files["/var/lib/exitnode/manifest.json"])["steps"]
    program = next(s for s in steps if s["step"] == "安装程序目录")
    assert program["undo"] == {"kind": "remove_file", "path": "/opt/exitnode/releases", "preserve": True}
    names = [s["step"] for s in steps]
    assert names.index("启用看门狗定时器") < names.index("安装救援单元") < names.index("启用救援定时器")
    rescue = next(s for s in steps if s["step"] == "安装救援单元")
    assert rescue["undo"] == {"kind": "remove_file", "path": "/opt/exitnode-rescue", "preserve": True}
    saved_rescue = {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")}
    assert saved_rescue
    before = [c for c in runner.calls if c[0] == "run"]
    assert main(["init"], runner) == 0
    assert [c for c in runner.calls if c[0] == "run"] == before
    assert main(["uninstall"], runner) == 0
    assert runner.files["/var/lib/exitnode/secrets/identity"] == "保留"
    assert not any(p.startswith("/etc/systemd/system/exitnode-") for p in runner.files)
    assert main(["uninstall"], runner) == 0
    assert main(["uninstall", "--purge"], runner) == 0
    assert "/var/lib/exitnode/secrets/identity" not in runner.files
    assert runner.read_bytes("/opt/exitnode/current/exitnode/__init__.py") == saved_program
    assert {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")} == saved_rescue


def test_upgrade_none_source_is_chinese_and_has_no_mutations(capsys):
    runner = fake()
    before = dict(runner.files)
    assert main(["upgrade"], runner) == 1
    assert "只能使用 --file" in capsys.readouterr().out
    assert runner.files == before


def test_upgrade_new_flags_parse():
    args = parser().parse_args(["upgrade", "--check", "--file", "/pack", "--signature", "/sig"])
    assert args.check and args.file == "/pack" and args.signature == "/sig"


def test_init_failure_can_resume_without_rewriting_completed_units():
    runner = fake(pairing=True)
    runner.responses[("systemctl", "enable")] = CompletedResult(1)
    assert main(["init"], runner) == 1
    writes = [c[1] for c in runner.calls if c[0] == "write_file" and c[1].endswith(".service")]
    proxy_path = "/etc/systemd/system/exitnode-proxy.service"
    assert proxy_path not in writes
    assert writes and all(writes.count(path) == 1 for path in writes)
    boundary = len(runner.calls)
    runner.responses[("systemctl", "enable")] = CompletedResult()
    assert main(["init"], runner) == 0
    resumed = [c[1] for c in runner.calls if c[0] == "write_file" and c[1].endswith(".service")]
    assert all(resumed.count(path) == 1 for path in writes)
    assert resumed.count(proxy_path) == 1
    assert sum(c[0] == "write_file" and c[1] == proxy_path
               for c in runner.calls[boundary:]) == 1


def test_existing_unowned_service_is_not_overwritten_or_deleted():
    runner = fake()
    path = "/etc/systemd/system/exitnode-admin.service"
    runner.files[path] = "已有服务定义"
    assert main(["init"], runner) == 1
    assert main(["rollback"], runner) == 0
    assert runner.files[path] == "已有服务定义"


def test_device_help_and_subcommands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"], FakeRunner())
    assert exc.value.code == 0
    assert "device" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main(["device", "--help"], FakeRunner())
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert all(name in text for name in ("add", "list", "revoke", "export"))
    args = parser().parse_args(["device", "add", "--name", "电脑"])
    assert args.platform == "windows" and args.host is None


def test_watchdog_help_and_status_without_state(capsys):
    with pytest.raises(SystemExit):
        main(["--help"], FakeRunner())
    assert "watchdog" in capsys.readouterr().out
    assert main(["watchdog", "status"], fake()) == 0
    assert json.loads(capsys.readouterr().out) is None


@pytest.mark.parametrize("value,expected", [("manual", "manual"), ("degraded", "reconnecting")])
def test_status_uses_watchdog_reason(value, expected, capsys):
    from datetime import UTC, datetime

    from exitnode.watchdog import state

    runner = fake()
    config = load(CONFIG, runner)
    saved = state.fresh()
    saved.update(state=value, consecutive_failures=12, reason="隧道未恢复，请检查配置")
    state.record(saved, "wait", datetime.now(UTC), saved["reason"])
    state.save(config, runner, saved, datetime.now(UTC))
    assert main(["status", "--json"], runner) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == expected
    assert result["reason"] == saved["reason"]
    assert result["watchdog"]["state"] == value
    assert result["watchdog"]["consecutive_failures"] == 12
    assert result["watchdog"]["last_action"]["action"] == "wait"


def test_check_missing_watchdog_fails(capsys):
    assert main(["check", "--json"], fake()) == 1
    layers = json.loads(capsys.readouterr().out)["layers"]
    assert next(layer for layer in layers if layer["name"] == "看门狗")["result"] == "失败"


@pytest.mark.parametrize("command", ["rollback", "uninstall"])
def test_timer_hardware_init_is_idempotent_and_undo_is_reverse(command, capsys):
    from exitnode.manifest import Manifest

    runner = fake(pairing=True)
    runner.files["/dev/watchdog"] = "device"
    hardware_path = "/etc/systemd/system.conf.d/exitnode-watchdog.conf"
    timer = "exitnode-watchdog.timer"
    assert main(["init"], runner) == 0
    assert runner.files[hardware_path] == "[Manager]\nRuntimeWatchdogSec=60\nRebootWatchdogSec=10min\n"
    steps = Manifest("/var/lib/exitnode/manifest.json", runner).steps
    names = [step["step"] for step in steps]
    assert names.index("启用隧道服务") < names.index("启用看门狗定时器") < names.index("硬件看门狗")
    timer_step = next(s for s in steps if s["step"] == "启用看门狗定时器")
    assert timer_step["undo"] == {"kind": "systemctl", "unit": timer}
    calls = [c for c in runner.calls if c[0] == "run"]
    assert any(c[1] == ("systemctl", "enable", "--now", timer) for c in calls)
    timer_index = next(i for i, c in enumerate(calls) if c[1] == ("systemctl", "enable", "--now", timer))
    first_device = next(i for i, c in enumerate(calls) if c[1] == ("systemctl", "reload", "exitnode-proxy.service"))
    assert timer_index < first_device
    assert main(["init"], runner) == 0
    assert [c for c in runner.calls if c[0] == "run"] == calls
    boundary = len(runner.calls)
    assert main([command], runner) == 0
    undo = runner.calls[boundary:]
    removed = [c[1] for c in undo if c[0] == "remove"]
    assert removed.index(hardware_path) < removed.index("/etc/systemd/system/" + timer)
    assert hardware_path not in runner.files
    removal_index = undo.index(("remove", hardware_path))
    assert undo[removal_index + 1][1] == ("systemctl", "daemon-reexec")
    assert ("run", ("systemctl", "disable", "--now", timer), True, None) in undo


def test_foreign_hardware_file_is_neither_overwritten_nor_removed():
    runner = fake(pairing=True)
    runner.files["/dev/watchdog"] = "device"
    path = "/etc/systemd/system.conf.d/exitnode-watchdog.conf"
    runner.files[path] = "FOREIGN"
    assert main(["init"], runner) == 1
    assert main(["rollback"], runner) == 0
    assert runner.files[path] == "FOREIGN"


def test_absent_hardware_is_reported_as_skipped(capsys):
    runner = fake(pairing=True)
    assert main(["init"], runner) == 0
    assert "硬件看门狗：设备不存在，跳过" in capsys.readouterr().out
    assert not any(c[0] == "run" and c[1] == ("systemctl", "daemon-reexec") for c in runner.calls)


def test_disabled_watchdog_does_not_enable_timer_or_hardware():
    runner = fake(pairing=True)
    runner.files["/dev/watchdog"] = "device"
    runner.files[CONFIG] = runner.files[CONFIG].replace("enabled = true", "enabled = false").replace(
        "hardware = true", "hardware = false")
    assert main(["init"], runner) == 0
    assert not any(c[0] == "run" and c[1] == ("systemctl", "enable", "--now", "exitnode-watchdog.timer")
                   for c in runner.calls)
    assert "/etc/systemd/system.conf.d/exitnode-watchdog.conf" not in runner.files
    assert not any("weekly-reboot" in p for p in runner.files)


def test_watchdog_tick_dispatch(monkeypatch):
    from exitnode import cli

    calls = []

    def tick(config, runner):
        calls.append((config, runner))
        return 2

    monkeypatch.setattr(cli, "watchdog_tick", tick)
    runner = fake()
    assert main(["watchdog", "tick"], runner) == 2
    assert calls[0][1] is runner and calls[0][0].watchdog.enabled


@pytest.mark.parametrize("binary", ["/usr/bin/sing-box", "/usr/local/bin/sing-box", None])
def test_default_binary_first_install_fallback(binary, capsys):
    runner = fake(pairing=True)
    runner.files[CONFIG] = runner.files[CONFIG].replace('binary = "/usr/bin/sing-box"', "")
    del runner.files["/usr/bin/sing-box"]
    if binary:
        runner.files[binary] = b"prepared-kernel"
    runner.responses[("/opt/exitnode/current/bin/sing-box", "check")] = CompletedResult()
    assert main(["init"], runner) == (0 if binary else 1)
    if binary:
        assert runner.read_bytes("/opt/exitnode/current/bin/sing-box") == b"prepared-kernel"
        unit = runner.files["/etc/systemd/system/exitnode-proxy.service"]
        assert "ExecStart=/opt/exitnode/current/bin/sing-box run" in unit
    else:
        assert "未找到 sing-box" in capsys.readouterr().out
        assert not any(p.startswith("/etc/systemd/system/") for p in runner.files)
        assert not any(c[0] == "run" for c in runner.calls)


@pytest.mark.parametrize("command", [["rollback"], ["uninstall"], ["uninstall", "--purge"]])
def test_all_removal_paths_preserve_rescue(command):
    runner = fake(pairing=True)
    assert main(["init"], runner) == 0
    before = {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")}
    assert main(command, runner) == 0
    assert before == {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")}
    assert not any(p.startswith("/etc/systemd/system/exitnode-rescue") for p in runner.files)


def test_rescue_status_chinese_and_missing(capsys):
    from exitnode.rescue import state

    runner = fake()
    assert main(["rescue", "status"], runner) == 0
    assert "尚无救援记录" in capsys.readouterr().out
    runner.files[state.STATE] = json.dumps({"state": "manual", "reason": "重装频率超限",
                                          "updated_at": state.iso(runner.now())})
    assert main(["rescue", "status"], runner) == 0
    text = capsys.readouterr().out
    assert "需人工处理" in text and "重装频率超限" in text
    assert not any(c[0] == "run" for c in runner.calls)


@pytest.mark.parametrize("age,active,expected", [(0, True, "通过"), (86401, True, "失败"),
                                               (0, False, "失败"), (-1, True, "失败")])
def test_rescue_check_timer_and_freshness(age, active, expected, capsys):
    from exitnode.rescue import state

    runner = fake()
    runner.files[state.STATE] = json.dumps({"state": "normal", "reason": "正常",
                                          "updated_at": state.iso(runner.now() - age)})
    runner.responses[("systemctl", "is-active", "exitnode-rescue.timer")] = CompletedResult(
        0 if active else 3, "active" if active else "inactive")
    main(["check", "--json"], runner)
    layers = json.loads(capsys.readouterr().out)["layers"]
    assert next(v for v in layers if v["name"] == "救援单元")["result"] == expected


@pytest.mark.parametrize("import_ok", [True, False])
def test_rescue_refresh_uses_independent_runner_checks_before_replace(import_ok, monkeypatch):
    from exitnode.rescue.runner import FakeRunner as RescueFakeRunner
    from exitnode.rescue.runner import Result
    from exitnode.updater import layout

    source = "/running/exitnode/rescue"
    target = "/opt/exitnode-rescue/exitnode_rescue"
    files = {source + "/" + name: b"# new\n" for name in (
        "__init__.py", "__main__.py", "runner.py", "state.py", "probes.py", "actions.py")}
    files[target + "/old-file.py"] = b"old"
    rescue = RescueFakeRunner(files=files, responses={("python3",): Result(0 if import_ok else 1)})
    monkeypatch.setattr(layout, "running_package", lambda: "/running/exitnode")
    runner = fake()
    assert main(["rescue", "refresh"], runner, rescue_runner=rescue) == (0 if import_ok else 1)
    assert not any(c[0] in {"run", "replace", "write_file", "copy_tree"} for c in runner.calls)
    if import_ok:
        check = next(i for i, c in enumerate(rescue.calls) if c[0] == "run")
        assert check < rescue.calls.index(("replace", target + ".staging", target))
        assert not rescue.exists(target + "/old-file.py")
        assert rescue.read(target + "/runner.py") == b"# new\n"
    else:
        assert rescue.read(target + "/old-file.py") == b"old"
        assert not any(c == ("replace", target + ".staging", target) for c in rescue.calls)


def test_rescue_refresh_rejects_copy_hash_mismatch():
    from exitnode.cli import refresh
    from exitnode.rescue.runner import FakeRunner as RescueFakeRunner

    class DamagedCopy(RescueFakeRunner):
        def copy_tree(self, source, target):
            super().copy_tree(source, target)
            self.files[target + "/runner.py"] = b"damaged"

    files = {"/source/" + name: b"# source" for name in (
        "__init__.py", "__main__.py", "runner.py", "state.py", "probes.py", "actions.py")}
    files["/target/old"] = b"old"
    runner = DamagedCopy(files=files)
    with pytest.raises(ValueError, match="副本校验失败"):
        refresh("/source", "/target", runner)
    assert runner.files["/target/old"] == b"old"
    assert not any(c[0] == "run" for c in runner.calls)


def test_refresh_directory_exchange_error_records_manual_and_preserves_old():
    from exitnode.cli import refresh
    from exitnode.rescue import state
    from exitnode.rescue.runner import FakeRunner as RescueFakeRunner
    from exitnode.rescue.runner import Result

    error = OSError("simulated disk error")

    class FailingExchange(RescueFakeRunner):
        def replace(self, source, target):
            if target == "/target":
                raise error
            super().replace(source, target)

    files = {"/source/" + name: b"# source" for name in (
        "__init__.py", "__main__.py", "runner.py", "state.py", "probes.py", "actions.py")}
    files["/target/old"] = b"old"
    runner = FailingExchange(files=files, responses={("python3",): Result()})
    with pytest.raises(OSError) as exc:
        refresh("/source", "/target", runner)
    assert exc.value is error
    assert runner.files["/target/old"] == b"old"
    assert state.read(runner)["state"] == "manual"
    assert json.loads(runner.files[state.HISTORY].splitlines()[-1])["status"] == "failed"


def test_winclient_publish_status_and_parser(capsys):
    from test_admin_publish import package

    runner = fake()
    assert main(["winclient", "status"], runner) == 0
    assert "尚未托管客户端包" in capsys.readouterr().out
    paths, files = package()
    runner.files.update(files)
    assert main(["winclient", "publish", "--exe", paths[0], "--manifest", paths[1],
                 "--signature", paths[2]], runner) == 0
    assert main(["winclient", "status"], runner) == 0
    output = capsys.readouterr().out
    assert "1.2.3" in output and "7 字节" in output and "发布时间" in output
    assert "/var/lib" not in output and "/input" not in output


@pytest.mark.parametrize("argv", [["admin", "serve"], ["--placeholder", "admin"]])
def test_admin_entrypoints_are_equivalent(argv, monkeypatch):
    calls = []
    monkeypatch.setattr("exitnode.admin.server.serve", calls.append)
    assert main(argv, fake()) == 0
    assert len(calls) == 1 and calls[0].admin.bind == "127.0.0.1"
