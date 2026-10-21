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


def fake():
    return FakeRunner(files={CONFIG: TEXT}, responses={
        ("ip", "-j", "route"): CompletedResult(out='[{"dst":"default","dev":"eth0","gateway":"192.0.2.1"}]'),
        ("ip", "-j", "addr"): CompletedResult(out=json.dumps([
            {"ifname": "eth0", "ifindex": 2, "flags": ["UP"],
             "addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.2"}]}])),
        ("systemctl",): CompletedResult(),
        ("nft", "-j"): CompletedResult(out='{"nftables":[]}'),
        ("nft", "-f"): CompletedResult(),
    }, connections={("8.8.8.8", 443): True})


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
    assert set(result) == {"state", "version", "network", "path", "last_ok_at", "reason"}
    assert result["state"] == "normal"
    assert set(result["network"]) == {"iface", "gateway", "dhcp", "addr"}
    assert result["network"]["dhcp"] == "unknown"
    assert result["path"] == "unknown" and result["last_ok_at"] is None
    assert "未接入" in result["reason"]
    assert {s.value for s in State} == {"normal", "reconnecting", "reauth", "manual"}


def test_check_unintegrated_layers_are_not_passed(capsys):
    assert main(["check", "--json"], fake()) == 0
    layers = json.loads(capsys.readouterr().out)["layers"]
    assert [layer["result"] for layer in layers] == ["通过", "通过", "未接入", "未接入", "未接入"]


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
    runner = fake()
    runner.files["/var/lib/exitnode/secrets/identity"] = "保留"
    assert main(["init"], runner) == 0
    before = [c for c in runner.calls if c[0] == "run"]
    assert main(["init"], runner) == 0
    assert [c for c in runner.calls if c[0] == "run"] == before
    assert main(["uninstall"], runner) == 0
    assert runner.files["/var/lib/exitnode/secrets/identity"] == "保留"
    assert not any(p.startswith("/etc/systemd/system/exitnode-") for p in runner.files)
    assert main(["uninstall"], runner) == 0
    assert main(["uninstall", "--purge"], runner) == 0
    assert "/var/lib/exitnode/secrets/identity" not in runner.files


def test_init_failure_can_resume_without_rewriting_completed_units():
    runner = fake()
    runner.responses[("systemctl", "enable")] = CompletedResult(1)
    assert main(["init"], runner) == 1
    writes = len([c for c in runner.calls if c[0] == "write_file" and c[1].endswith(".service")])
    runner.responses[("systemctl", "enable")] = CompletedResult()
    assert main(["init"], runner) == 0
    assert len([c for c in runner.calls if c[0] == "write_file" and c[1].endswith(".service")]) == writes


def test_existing_unowned_service_is_not_overwritten_or_deleted():
    runner = fake()
    path = "/etc/systemd/system/exitnode-admin.service"
    runner.files[path] = "已有服务定义"
    assert main(["init"], runner) == 1
    assert main(["rollback"], runner) == 0
    assert runner.files[path] == "已有服务定义"
