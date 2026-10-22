"""仅使用内存 FakeRunner；所有固定凭据均为公开测试向量。"""

import json
from pathlib import Path
from uuid import UUID

import pytest
from exitnode import device, service
from exitnode.cli import main
from exitnode.config import load
from exitnode.proxy import registry as registry_module
from exitnode.runner import CompletedResult, RunnerError
from test_cli import CONFIG, fake

GOLDEN = Path(__file__).parent / "golden"
AT = "2026-10-22T00:00:00+00:00"
HOST = "203.0.113.10"
REGISTRY = service.SECRETS + "/devices.json"
CHECK = ("/usr/bin/sing-box", "check", "-c", service.LIVE + ".check.tmp")
RELOAD = ("systemctl", "reload", service.UNIT)


def test_revoke_updates_last_good_without_either_credential(installed):
    config, runner = installed
    first = device.add(config, runner, name="电脑", host=HOST)
    device.add(config, runner, name="手机", host=HOST)
    device.revoke(config, runner, name="电脑")
    backup = service.LIVE.replace(".json", ".last-good.json")
    assert runner.files[backup] == runner.files[service.LIVE]
    assert first.uuid not in runner.files[backup]
    assert first.hy2_password not in runner.files[backup]


@pytest.fixture
def installed():
    runner = fake(pairing=True)
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    service.publish(config, runner)
    runner.calls.clear()
    return config, runner


def commands(runner):
    return [c[1] for c in runner.calls if c[0] == "run"]


def test_add_credentials_permissions_and_checked_reload(installed, capsys):
    config, runner = installed
    first = device.add(config, runner, name="老板的电脑", host=HOST)
    assert UUID(first.uuid).version == 4 and len(first.hy2_password) >= 32
    assert first.account_id == "local" and first.platform == "windows"
    assert device.registry(config, runner).all() == [first]
    path = config.node.data_dir + "/export/老板的电脑.ycpair"
    pair = json.loads(runner.files[path])
    assert pair["node"]["uuid"] == first.uuid
    assert pair["node"]["hy2_password"] == first.hy2_password
    assert runner.modes[path] == runner.modes[REGISTRY] == 0o600
    assert all(c[3] == 0o600 for c in runner.calls
               if c[0] == "write_file" and "/export/" in c[1])
    assert commands(runner).index(CHECK) < commands(runner).index(RELOAD)
    assert not any(cmd[-1] == "sing-box" for cmd in commands(runner) if cmd[0] == "systemctl")
    output = capsys.readouterr().out
    assert path in output and f"vless://{first.uuid}@{HOST}:443?" in output
    assert "sudo apt install qrencode" in output
    assert first.hy2_password not in output
    for file, text in runner.files.items():
        if first.uuid in text or first.hy2_password in text:
            assert "/secrets/" in file or file.endswith(".ycpair")


def test_exact_pair_golden_and_session_node_keys(installed, monkeypatch):
    config, runner = installed
    vector = json.loads((GOLDEN / "proxy" / "inputs.json").read_text(encoding="utf-8"))
    runner.files[service.SECRETS + "/reality.json"] = json.dumps(vector["context"]["reality"])
    runner.files[service.SECRETS + "/hy2.crt"] = "\n".join(vector["context"]["hy2_certificate"])
    runner.files[service.SECRETS + "/hy2.obfs"] = vector["context"]["hy2_obfs_password"] + "\n"
    monkeypatch.setattr(registry_module, "uuid4", lambda: UUID(vector["device"]["uuid"]))
    monkeypatch.setattr(registry_module.secrets, "token_urlsafe", lambda _: "TEST-ONLY-hy2-password")
    monkeypatch.setattr(registry_module, "now", lambda: AT)
    first = device.add(config, runner, name="测试设备", host=HOST, clock=lambda: AT)
    assert first.created_at == AT
    path = config.node.data_dir + "/export/测试设备.ycpair"
    pair = json.loads(runner.files[path])
    actual = {"_comment": "测试向量,不是真凭据", **pair}
    assert json.dumps(actual, ensure_ascii=False, indent=2) + "\n" == (
        GOLDEN / "device" / "pair.ycpair.json"
    ).read_text(encoding="utf-8")
    # authserver/authserver/service.py Service.session(): Node.model_dump()
    # Node 导出的九个字段 + node.update 的两个凭据字段。
    assert set(pair["node"]) == {
        "host", "reality_port", "hy2_port", "sni", "reality_public_key", "short_id",
        "uuid", "hy2_password", "hy2_server_name", "hy2_certificate", "hy2_obfs_password",
    }
    assert set(pair) == {"format", "exported_at", "node"}
    assert pair["format"] == "ycpair/3"
    assert "private_key" not in runner.files[path]


def test_export_without_obfs_file_is_v2_without_key(installed, capsys):
    config, runner = installed
    del runner.files[service.SECRETS + "/hy2.obfs"]
    first = device.add(config, runner, name="电脑", host=HOST)
    pair = json.loads(runner.files[config.node.data_dir + "/export/电脑.ycpair"])
    assert pair["format"] == "ycpair/2"
    assert "hy2_obfs_password" not in pair["node"]
    assert pair["node"]["uuid"] == first.uuid
    live = json.loads(runner.files[service.LIVE])
    assert "obfs" not in live["inbounds"][1]


def test_obfs_password_exported_but_never_printed(installed, capsys):
    config, runner = installed
    password = runner.files[service.SECRETS + "/hy2.obfs"].strip()
    device.add(config, runner, name="电脑", host=HOST)
    pair = json.loads(runner.files[config.node.data_dir + "/export/电脑.ycpair"])
    assert pair["format"] == "ycpair/3" and pair["node"]["hy2_obfs_password"] == password
    assert password not in capsys.readouterr().out
    for file, text in runner.files.items():
        if password in text:
            assert "/secrets/" in file or file.endswith(".ycpair")


def test_corrupt_obfs_file_blocks_export(installed):
    config, runner = installed
    device.add(config, runner, name="电脑", host=HOST)
    runner.files[service.SECRETS + "/hy2.obfs"] = "bad password"
    with pytest.raises(ValueError, match="备用通道混淆密码格式不正确"):
        device.export(config, runner, name="电脑", host=HOST)


def test_same_name_is_idempotent_and_list_never_prints_credentials(installed, capsys):
    config, runner = installed
    first = device.add(config, runner, name="电脑", host=HOST)
    second = device.add(config, runner, name="电脑", platform="android", host=HOST)
    assert second == first and device.registry(config, runner).all() == [first]
    capsys.readouterr()
    for args in (["device", "list"], ["device", "list", "--json"]):
        assert main(args, runner) == 0
        text = capsys.readouterr().out
        assert first.uuid not in text and first.hy2_password not in text
        assert "电脑" in text and "windows" in text and first.created_at in text
        if "--json" in args:
            assert json.loads(text) == device.list_devices(config, runner)


def test_revoke_removes_both_users_and_rejects_export_and_add(installed, capsys):
    config, runner = installed
    first = device.add(config, runner, name="电脑", host=HOST)
    other = device.add(config, runner, name="手机", platform="android", host=HOST)
    capsys.readouterr()
    boundary = len(commands(runner))
    assert main(["device", "revoke", "--name", "电脑"], runner) == 0
    rows = device.registry(config, runner).all()
    assert rows[0].revoked_at and rows[0].created_at == first.created_at
    live = json.loads(runner.files[service.LIVE])
    assert live["inbounds"][0]["users"] == [
        {"name": other.device_id, "uuid": other.uuid, "flow": "xtls-rprx-vision"}]
    assert live["inbounds"][1]["users"] == [{"name": other.device_id, "password": other.hy2_password}]
    assert commands(runner)[boundary:] == [CHECK, RELOAD]
    for operation in (device.export, device.add):
        with pytest.raises(ValueError, match="已吊销"):
            operation(config, runner, name="电脑", host=HOST)
    assert first.uuid not in capsys.readouterr().out


@pytest.mark.parametrize("operation", ["add", "revoke"])
def test_check_failure_leaves_registry_and_live_untouched(installed, operation, capsys):
    config, runner = installed
    device.add(config, runner, name="电脑", host=HOST)
    capsys.readouterr()
    before = dict(runner.files)
    runner.calls.clear()
    runner.responses[CHECK] = CompletedResult(1, out="PRIVATE-OUTPUT", err="PASSWORD-OUTPUT")
    args = ["device", operation, "--name", "手机" if operation == "add" else "电脑"]
    if operation == "add":
        args += ["--host", HOST]
    assert main(args, runner) == 1
    assert runner.files == before
    assert commands(runner) == [CHECK]
    assert not any(c[0] == "replace" and c[2] in (REGISTRY, service.LIVE) for c in runner.calls)
    text = capsys.readouterr().err
    assert "PRIVATE-OUTPUT" not in text and "PASSWORD-OUTPUT" not in text
    assert "未变" in text


@pytest.mark.parametrize("response", [CompletedResult(127), RunnerError("系统命令无法执行")])
def test_missing_qr_is_success_and_link_is_only_in_stdin(installed, response, capsys):
    config, runner = installed
    runner.responses[("qrencode",)] = response
    assert main(["device", "add", "--name", "电脑", "--host", HOST], runner) == 0
    text = capsys.readouterr().out
    assert "vless://" in text and "apt install qrencode" in text
    call = next(c for c in runner.calls if c[0] == "run" and c[1][0] == "qrencode")
    assert call[1] == ("qrencode", "-t", "UTF8") and call[3].startswith("vless://")
    assert config.node.data_dir + "/export/电脑.ycpair" in runner.files


def test_qr_output_and_changed_host_export_without_new_credentials(installed, capsys):
    config, runner = installed
    runner.responses[("qrencode",)] = CompletedResult(out="█ ▀ █\n")
    first = device.add(config, runner, name="电脑", host=HOST)
    assert "█ ▀ █" in capsys.readouterr().out
    before = runner.files[REGISTRY], runner.files[service.LIVE]
    runner.calls.clear()
    assert main(["device", "export", "--name", "电脑", "--host", "203.0.113.20"], runner) == 0
    pair = json.loads(runner.files[config.node.data_dir + "/export/电脑.ycpair"])
    assert pair["node"]["host"] == "203.0.113.20" and pair["node"]["uuid"] == first.uuid
    assert (runner.files[REGISTRY], runner.files[service.LIVE]) == before
    assert commands(runner) == [("qrencode", "-t", "UTF8")]


@pytest.mark.parametrize("name", ["a/b", "a\\b", "a..b", "..", "", "!!!", "a" * 65])
def test_unsafe_name_rejected_before_changes(installed, name):
    config, runner = installed
    before = dict(runner.files)
    with pytest.raises(ValueError):
        device.add(config, runner, name=name, host=HOST)
    assert runner.files == before and commands(runner) == []


def test_sanitized_filename_and_collision_rejected(installed):
    config, runner = installed
    first = device.add(config, runner, name="老板 的电脑!", host=HOST)
    assert first.device_id == "老板的电脑"
    assert config.node.data_dir + "/export/老板的电脑.ycpair" in runner.files
    with pytest.raises(ValueError, match="占用"):
        device.add(config, runner, name="老板的电脑", host=HOST)


def test_automatic_host_and_missing_host_failure(installed):
    config, runner = installed
    device.add(config, runner, name="电脑")
    pair = json.loads(runner.files[config.node.data_dir + "/export/电脑.ycpair"])
    assert pair["node"]["host"] == "203.0.113.9"
    before = dict(runner.files)
    runner.responses[("curl",)] = CompletedResult(1)
    with pytest.raises(ValueError, match="--host"):
        device.add(config, runner, name="手机")
    assert runner.files == before


@pytest.mark.parametrize("host", ["host.example", "::1", "999.1.2.3", ""])
def test_invalid_host_does_not_register(installed, host):
    config, runner = installed
    before = dict(runner.files)
    with pytest.raises(ValueError, match="IPv4"):
        device.add(config, runner, name="电脑", host=host)
    assert runner.files == before


def test_init_issues_first_pair_once_and_second_run_is_unchanged(capsys):
    runner = fake(pairing=True)
    assert main(["init"], runner) == 0
    config = load(CONFIG, runner)
    rows = device.registry(config, runner).all()
    assert len(rows) == 1 and rows[0].name == "第一台电脑"
    assert rows[0].platform == "windows" and rows[0].revoked_at is None
    path = config.node.data_dir + "/export/第一台电脑.ycpair"
    assert path in runner.files and runner.modes[path] == 0o600
    text = capsys.readouterr().out
    assert path in text and "请把这个文件拷到 U 盘带去电脑" in text
    before, calls = dict(runner.files), commands(runner)
    assert main(["init"], runner) == 0
    assert runner.files == before and commands(runner) == calls


def test_registry_write_failure_restores_live_without_reload(installed, monkeypatch):
    config, runner = installed
    before = dict(runner.files)
    original = runner.replace

    def fail_registry(source, target):
        if target == REGISTRY:
            raise OSError("模拟写入失败")
        original(source, target)

    monkeypatch.setattr(runner, "replace", fail_registry)
    with pytest.raises(ValueError, match="已回退"):
        device.add(config, runner, name="电脑", host=HOST)
    assert runner.files == before and RELOAD not in commands(runner)


def test_reload_fallback_targets_only_our_service_and_failure_is_not_success(installed, capsys):
    config, runner = installed
    runner.responses[RELOAD] = CompletedResult(1)
    restart = ("systemctl", "restart", service.UNIT)
    runner.responses[restart] = CompletedResult(1)
    assert main(["device", "add", "--name", "电脑", "--host", HOST], runner) == 1
    assert commands(runner) == [CHECK, RELOAD, restart]
    assert "重载未成功" in capsys.readouterr().err
    assert config.node.data_dir + "/export/电脑.ycpair" not in runner.files
    registered = device.registry(config, runner).all()[0]
    runner.responses[RELOAD] = CompletedResult()
    assert device.add(config, runner, name="电脑", host=HOST) == registered
