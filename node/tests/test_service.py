"""Only the node FakeRunner is used; openssl side effects are in-memory fixtures."""

import json
import re

import pytest
from exitnode import service
from exitnode.cli import main
from exitnode.config import load
from exitnode.manifest import Manifest
from exitnode.proxy.keys import ensure_reality_keys
from exitnode.runner import CompletedResult
from exitnode.service import LIVE, SECRETS, UNIT, ProxyRunner, build_context, publish
from test_cli import CONFIG
from test_cli import fake as cli_fake

MANIFEST = "/var/lib/exitnode/manifest.json"
UNIT_PATH = "/etc/systemd/system/" + UNIT
CHECK = ("/usr/bin/sing-box", "check", "-c", LIVE + ".check.tmp")
ENABLE = ("systemctl", "enable", "--now", UNIT)


def fake():
    return cli_fake(pairing=True)


def commands(runner):
    return [c[1] for c in runner.calls if c[0] == "run"]


def new_install(monkeypatch):
    runner = fake()
    del runner.files[SECRETS + "/hy2.crt"]
    del runner.files[SECRETS + "/hy2.key"]
    runner.responses[("openssl",)] = CompletedResult()
    original = runner.run

    def run(argv, check=True, input=None):
        result = original(argv, check=check, input=input)
        if argv[0] == "openssl" and result.code == 0:
            runner.write_file(argv[argv.index("-keyout") + 1], "测试生成的私钥占位", 0o600)
            runner.write_file(argv[argv.index("-out") + 1], "测试生成的证书占位", 0o600)
        return result

    monkeypatch.setattr(runner, "run", run)
    return runner


def test_missing_binary_fails_before_writing_units(capsys):
    runner = fake()
    del runner.files["/usr/bin/sing-box"]
    assert main(["init"], runner) == 1
    assert "安装 sing-box" in capsys.readouterr().out
    assert not any(p.startswith("/etc/systemd/system/") for p in runner.files)
    assert commands(runner) == []


def test_install_manifest_order_permissions_and_repeat(monkeypatch, capsys):
    runner = new_install(monkeypatch)
    assert main(["init"], runner) == 0
    files = [SECRETS + "/" + name for name in
             ("reality.json", "hy2.crt", "hy2.key", "hy2.obfs", "devices.json", "sing-box.json")]
    assert all(path in runner.files for path in files)
    for name in ("reality.json", "hy2.obfs", "devices.json"):
        assert runner.modes[SECRETS + "/" + name] == 0o600
        assert SECRETS + "/" + name not in runner.owners
    for name in ("hy2.crt", "hy2.key", "sing-box.json"):
        assert runner.modes[SECRETS + "/" + name] == 0o640
        assert runner.owners[SECRETS + "/" + name] == ("root", "exitnode")
    assert runner.modes[SECRETS] == 0o710
    assert runner.owners[SECRETS] == ("root", "exitnode")
    assert runner.modes["/var/lib/exitnode"] == 0o711
    assert "/var/lib/exitnode" not in runner.owners
    backup = LIVE.replace(".json", ".last-good.json")
    assert runner.modes[backup] == 0o600 and backup not in runner.owners
    keys = json.loads(runner.files[files[0]])
    assert set(keys) == {"private_key", "public_key", "short_id"}
    assert len(keys["short_id"]) == 8
    devices = json.loads(runner.files[SECRETS + "/devices.json"])
    assert len(devices) == 1
    first = devices[0]
    assert first["name"] == "第一台电脑" and first["platform"] == "windows"
    assert first["revoked_at"] is None
    config = json.loads(runner.files[LIVE])
    assert config["inbounds"][0]["tls"]["reality"]["private_key"] == keys["private_key"]
    assert all(len(inbound["users"]) == 1 for inbound in config["inbounds"])
    assert config["inbounds"][0]["users"][0]["uuid"] == first["uuid"]
    assert config["inbounds"][1]["users"][0]["password"] == first["hy2_password"]
    steps = Manifest(MANIFEST, runner).steps
    names = [s["step"] for s in steps]
    for name in ("检查 sing-box 二进制", "生成 Reality 凭据", "生成备用通道证书",
                 "生成备用通道混淆密码", "准备设备登记表", "渲染隧道配置", "写入" + UNIT,
                 "重载隧道服务定义", "启用隧道服务"):
        assert names.count(name) == 1
    assert all(s["done_at"] for s in steps)
    assert names.index("启用管理面") < names.index("渲染隧道配置") < names.index("写入" + UNIT)
    assert names.index("写入" + UNIT) < names.index("重载隧道服务定义") < names.index("启用隧道服务")
    calls = commands(runner)
    assert calls.count(ENABLE) == 1 and calls.count(CHECK) == 2
    assert calls.index(CHECK) < calls.index(ENABLE)
    check_indices = [i for i, cmd in enumerate(calls) if cmd == CHECK]
    assert check_indices[1] > calls.index(ENABLE)
    assert check_indices[1] < calls.index(("systemctl", "reload", UNIT))
    openssl = next(cmd for cmd in calls if cmd[0] == "openssl")
    assert openssl == (
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", SECRETS + "/hy2.key.new.tmp",
        "-out", SECRETS + "/hy2.crt.new.tmp", "-days", "3650", "-subj", "/CN=exitnode",
        "-addext", "subjectAltName=DNS:exitnode",
    )
    assert "ExecReload=/bin/kill -HUP $MAINPID" in runner.files[UNIT_PATH]
    assert runner.files[LIVE + ".check.tmp"] == ""
    before = dict(runner.files)
    assert main(["init"], runner) == 0
    # 重复安装只新增一次只读版本查询，不重复执行写入类系统命令。
    assert commands(runner) == calls + [("/opt/exitnode/current/bin/sing-box", "version")]
    assert runner.files == before
    assert keys["private_key"] not in capsys.readouterr().out


def test_apply_permissions_fixes_old_modes_and_skips_missing_files():
    runner = fake()
    for name in ("sing-box.json", "reality.json", "hy2.obfs"):
        runner.write_file(SECRETS + "/" + name, "旧节点内容", 0o600)
    del runner.files[SECRETS + "/hy2.key"]
    service.apply_permissions(runner)
    assert runner.modes[LIVE] == runner.modes[SECRETS + "/hy2.crt"] == 0o640
    assert runner.owners[LIVE] == runner.owners[SECRETS + "/hy2.crt"] == ("root", "exitnode")
    assert SECRETS + "/hy2.key" not in runner.modes and SECRETS + "/hy2.key" not in runner.owners
    assert runner.modes[SECRETS + "/reality.json"] == runner.modes[SECRETS + "/hy2.obfs"] == 0o600
    assert runner.modes[SECRETS] == 0o710 and runner.owners[SECRETS] == ("root", "exitnode")
    assert runner.modes["/var/lib/exitnode"] == 0o711
    calls = list(runner.calls)
    service.apply_permissions(runner)
    assert [c for c in runner.calls[len(calls):] if c[0] in {"chmod", "chown"}] == [
        c for c in calls if c[0] in {"chmod", "chown"}]


def test_existing_credentials_reused_without_regeneration():
    runner = fake()
    ensure_reality_keys(SECRETS, ProxyRunner(runner))
    original = {p: content for p, content in runner.files.items() if p.startswith(SECRETS)}
    boundary = len(runner.calls)
    assert main(["init"], runner) == 0
    assert all(runner.files[p] == text for p, text in original.items())
    assert [cmd for cmd in commands(runner) if cmd[0] == "openssl"] == [
        ("openssl", "x509", "-in", SECRETS + "/hy2.crt", "-noout", "-ext", "subjectAltName")]
    assert not any(cmd[:2] == ("openssl", "req") for cmd in commands(runner))
    assert not any(c[0] == "write_file" and c[1] in original for c in runner.calls[boundary:])


def test_invalid_candidate_does_not_enable_or_write_unit(capsys):
    runner = fake()
    runner.responses[CHECK] = CompletedResult(1, out="PRIVATE-COMMAND-OUTPUT", err="PRIVATE-ERROR")
    assert main(["init"], runner) == 1
    assert LIVE not in runner.files and UNIT_PATH not in runner.files
    assert ENABLE not in commands(runner)
    assert not any(cmd[:2] == ("systemctl", "reload") for cmd in commands(runner))
    assert runner.files[LIVE + ".check.tmp"] == ""
    assert "PRIVATE" not in capsys.readouterr().out


def test_failed_republication_keeps_live_config(monkeypatch):
    runner = fake()
    assert main(["init"], runner) == 0
    live = runner.files[LIVE]
    manifest = json.loads(runner.files[MANIFEST])
    next(s for s in manifest["steps"] if s["step"] == "渲染隧道配置")["done_at"] = None
    runner.files[MANIFEST] = json.dumps(manifest)
    runner.responses[CHECK] = CompletedResult(1)
    boundary = len(commands(runner))
    assert main(["init"], runner) == 1
    assert runner.files[LIVE] == live
    # 每次安装先查内核版本，再校验待发布配置，失败后仍不得重载。
    assert commands(runner)[boundary:] == [("/opt/exitnode/current/bin/sing-box", "version"), CHECK]
    assert runner.files[LIVE + ".check.tmp"] == ""


@pytest.mark.parametrize("command", ["rollback", "uninstall"])
def test_reverse_removal_retains_credentials_until_purge(command):
    runner = fake()
    assert main(["init"], runner) == 0
    original = {p: runner.files[p] for p in (SECRETS + "/reality.json", SECRETS + "/hy2.crt",
                                            SECRETS + "/hy2.key", SECRETS + "/devices.json")}
    boundary = len(runner.calls)
    assert main([command], runner) == 0
    assert LIVE not in runner.files and UNIT_PATH not in runner.files
    assert all(runner.files[p] == text for p, text in original.items())
    removed = [c[1] for c in runner.calls[boundary:] if c[0] == "remove"]
    assert removed.index(UNIT_PATH) < removed.index(LIVE)
    assert ("systemctl", "disable", "--now", UNIT) in commands(runner)
    assert main(["uninstall", "--purge"], runner) == 0
    assert not any(p.startswith(SECRETS + "/") for p in runner.files)


@pytest.mark.parametrize("path", [UNIT_PATH, LIVE])
def test_foreign_files_never_overwritten_or_removed(path):
    runner = fake()
    runner.files[path] = "不属于本清单"
    assert main(["init"], runner) == 1
    assert main(["rollback"], runner) == 0
    assert runner.files[path] == "不属于本清单"


def test_openssl_failure_cleans_temporary_secrets(monkeypatch, capsys):
    runner = new_install(monkeypatch)
    runner.responses[("openssl",)] = CompletedResult(1, err="PRIVATE-COMMAND-OUTPUT")
    assert main(["init"], runner) == 1
    assert ENABLE not in commands(runner)
    assert not any(p.endswith(".new.tmp") for p in runner.files)
    assert SECRETS + "/hy2.crt" not in runner.files
    assert SECRETS + "/hy2.key" not in runner.files
    assert "PRIVATE" not in capsys.readouterr().out


def test_certificate_pair_publication_can_resume_without_regenerating(monkeypatch):
    runner = new_install(monkeypatch)
    original = runner.replace

    def replace(source, target):
        if target == SECRETS + "/hy2.crt":
            raise OSError("模拟证书发布中断")
        original(source, target)

    monkeypatch.setattr(runner, "replace", replace)
    assert main(["init"], runner) == 1
    key = runner.files[SECRETS + "/hy2.key"]
    assert SECRETS + "/hy2.crt" not in runner.files
    monkeypatch.setattr(runner, "replace", original)
    assert main(["init"], runner) == 0
    assert runner.files[SECRETS + "/hy2.key"] == key
    assert SECRETS + "/hy2.crt" in runner.files
    assert sum(cmd[0] == "openssl" for cmd in commands(runner)) == 1


def test_context_and_custom_binary_reach_service_and_check():
    runner = fake()
    runner.files[CONFIG] = runner.files[CONFIG].replace("/usr/bin/sing-box", "/opt/sing-box")
    runner.files["/opt/sing-box"] = "测试内核"
    runner.responses[("/opt/sing-box", "version")] = CompletedResult(out="sing-box version 1.13.21\n")
    runner.responses[("/opt/sing-box", "check")] = CompletedResult()
    assert main(["init"], runner) == 0
    config = load(CONFIG, runner)
    keys = ensure_reality_keys(SECRETS, ProxyRunner(runner))
    ctx = build_context(config, keys, runner)
    assert ctx.reality == keys and ctx.sni == config.proxy.sni
    assert ctx.handshake_server == config.proxy.handshake_server
    assert ctx.hy2_server_name == config.proxy.hy2_server_name
    assert ctx.hy2_port == config.proxy.hy2_port
    assert "ExecStart=/opt/sing-box run -c " + LIVE in runner.files[UNIT_PATH]
    assert ("/opt/sing-box", "check", "-c", LIVE + ".check.tmp") in commands(runner)


def test_build_context_passes_maintenance_device_ids():
    runner = fake()
    runner.files[CONFIG] = runner.files[CONFIG].replace(
        "[proxy]", '[proxy]\nmaintenance_device_ids = ["dev-b", "dev-a"]')
    config = load(CONFIG, runner)
    keys = ensure_reality_keys(SECRETS, ProxyRunner(runner))
    ctx = build_context(config, keys, runner)
    assert ctx.maintenance_device_ids == ("dev-b", "dev-a")


def test_adapter_atomic_failure_preserves_original_and_hides_scratch(monkeypatch):
    runner = fake()
    path = SECRETS + "/devices.json"
    runner.files[path] = "[]"

    def fail(source, target):
        raise OSError("模拟写盘失败")

    monkeypatch.setattr(runner, "replace", fail)
    adapter = ProxyRunner(runner)
    with pytest.raises(OSError):
        adapter.write_file(path, "不能泄露的内容", 0o600)
    assert runner.files[path] == "[]"
    assert path + ".write.tmp" not in runner.files
    runner.responses[("probe",)] = CompletedResult(7, "out", "err")
    assert adapter.run(["probe"]) == (7, "out", "err")


def test_publish_replace_failure_cleans_candidate(monkeypatch):
    runner = fake()
    assert main(["init"], runner) == 0
    old = runner.files[LIVE]
    manifest = json.loads(runner.files[MANIFEST])
    next(s for s in manifest["steps"] if s["step"] == "渲染隧道配置")["done_at"] = None
    runner.files[MANIFEST] = json.dumps(manifest)
    original = runner.replace

    def replace(source, target):
        if target == LIVE:
            raise OSError("模拟原子替换失败")
        original(source, target)

    monkeypatch.setattr(runner, "replace", replace)
    with pytest.raises(OSError):
        publish(load(CONFIG, runner), runner)
    assert runner.files[LIVE] == old
    assert runner.files[LIVE + ".check.tmp"] == ""


@pytest.mark.parametrize("active,valid", [(1, 0), (0, 1), (1, 1)])
def test_tunnel_check_requires_active_service_and_valid_config(active, valid, capsys):
    runner = fake()
    runner.responses[("systemctl", "is-active", "exitnode-proxy")] = CompletedResult(active)
    runner.responses[("/usr/bin/sing-box", "check")] = CompletedResult(valid)
    assert main(["check", "--json"], runner) == 1
    layer = json.loads(capsys.readouterr().out)["layers"][-2]
    assert layer["name"] == "隧道服务" and layer["result"] == "失败"


OBFS = SECRETS + "/hy2.obfs"
OBFS_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}")
UPGRADE_NOTICE = "备用通道已启用混淆,旧配对文件的备用线路将不可用,请重新导出"


def test_init_generates_obfs_password_once_and_live_uses_it(capsys):
    runner = fake()
    assert main(["init"], runner) == 0
    password = runner.files[OBFS]
    assert runner.modes[OBFS] == 0o600
    assert OBFS_PATTERN.fullmatch(password) and len(password) == 43
    assert OBFS + ".tmp" not in runner.files
    backup = json.loads(runner.files[LIVE])["inbounds"][1]
    assert backup["type"] == "hysteria2"
    assert backup["obfs"] == {"type": "salamander", "password": password}
    names = [s["step"] for s in Manifest(MANIFEST, runner).steps]
    assert names.index("生成备用通道混淆密码") < names.index("准备设备登记表")
    step = next(s for s in Manifest(MANIFEST, runner).steps if s["step"] == "生成备用通道混淆密码")
    assert step["undo"] == {"kind": "remove_file", "path": OBFS, "preserve": True}
    output = capsys.readouterr().out
    assert password not in output and UPGRADE_NOTICE not in output
    assert main(["init"], runner) == 0
    assert runner.files[OBFS] == password
    assert password not in capsys.readouterr().out


@pytest.mark.parametrize("content", ["", "   \n", "has space 0123456789abc", "short", "a" * 129,
                                     "with=equals-0123456789"])
def test_corrupt_obfs_file_fails_and_is_not_overwritten(content):
    runner = fake()
    runner.files[OBFS] = content
    with pytest.raises(ValueError, match="混淆密码文件损坏") as error:
        service.ensure_credentials(load(CONFIG, runner), runner)
    assert "已有文件未覆盖" in str(error.value)
    assert runner.files[OBFS] == content
    assert not any(c[0] in {"write_file", "replace", "remove"} and c[1].startswith(OBFS)
                   for c in runner.calls)


def test_existing_valid_obfs_file_is_kept_with_whitespace():
    runner = fake()
    runner.files[OBFS] = "TEST-ONLY-hy2-obfs-0123456789abcdef\n"
    config = load(CONFIG, runner)
    keys = service.ensure_credentials(config, runner)
    assert runner.files[OBFS] == "TEST-ONLY-hy2-obfs-0123456789abcdef\n"
    ctx = build_context(config, keys, runner)
    assert ctx.hy2_obfs_password == "TEST-ONLY-hy2-obfs-0123456789abcdef"


@pytest.mark.parametrize("registry,notice", [(None, False), ("[]", False), ("device", True)])
def test_upgrade_notice_only_when_devices_already_registered(capsys, registry, notice):
    from exitnode.proxy.registry import DeviceRegistry

    runner = fake()
    if registry == "device":
        DeviceRegistry(SECRETS + "/devices.json", ProxyRunner(runner)).add(
            "old-device", "local", "windows", "旧电脑")
    elif registry is not None:
        runner.files[SECRETS + "/devices.json"] = registry
    capsys.readouterr()
    service.ensure_credentials(load(CONFIG, runner), runner)
    output = capsys.readouterr().out
    assert (UPGRADE_NOTICE in output) is notice
    assert runner.files[OBFS] not in output
    service.ensure_credentials(load(CONFIG, runner), runner)
    assert UPGRADE_NOTICE not in capsys.readouterr().out


def test_build_context_without_obfs_file_is_plain_and_corrupt_file_fails():
    runner = fake()
    config = load(CONFIG, runner)
    keys = ensure_reality_keys(SECRETS, ProxyRunner(runner))
    assert OBFS not in runner.files
    assert build_context(config, keys, runner).hy2_obfs_password == ""
    runner.files[OBFS] = "not valid!"
    with pytest.raises(ValueError, match="备用通道混淆密码格式不正确"):
        build_context(config, keys, runner)


def test_corrupt_obfs_file_blocks_publication():
    runner = fake()
    assert main(["init"], runner) == 0
    live = runner.files[LIVE]
    runner.files[OBFS] = "broken obfs"
    with pytest.raises(ValueError, match="混淆"):
        service._publish_checked(load(CONFIG, runner), runner, [])
    assert runner.files[LIVE] == live


@pytest.mark.parametrize("registered", [False, True])
def test_publication_updates_last_good_after_success(registered):
    from exitnode.proxy.registry import DeviceRegistry

    runner = fake()
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    runner.files[LIVE] = "原配置"
    registry = DeviceRegistry(SECRETS + "/devices.json", ProxyRunner(runner))
    runner.calls.clear()
    service._publish_checked(config, runner, [], registry if registered else None)
    backup = LIVE.replace(".json", ".last-good.json")
    assert runner.files[backup] == runner.files[LIVE]
    assert runner.modes[backup] == 0o600
    assert backup not in runner.owners
    assert runner.modes[LIVE] == 0o640
    assert runner.owners[LIVE] == ("root", "exitnode")
    write = next(i for i, c in enumerate(runner.calls)
                 if c[:2] == ("write_file", backup + ".tmp"))
    replaced = runner.calls.index(("replace", LIVE + ".check.tmp", LIVE))
    chowned = runner.calls.index(("chown", LIVE + ".check.tmp", "root", "exitnode"))
    candidate = next(i for i, c in enumerate(runner.calls)
                     if c[:2] == ("write_file", LIVE + ".check.tmp"))
    assert runner.calls[candidate][3] == 0o640
    assert candidate < chowned < replaced
    assert replaced < write
    assert ("replace", backup + ".tmp", backup) in runner.calls
    if registered:
        reloaded = next(i for i, c in enumerate(runner.calls)
                        if c[:2] == ("run", ("systemctl", "reload", UNIT)))
        assert reloaded < write
    else:
        assert write == replaced + 1


@pytest.mark.parametrize("failure", ["check", "registry", "reload"])
@pytest.mark.parametrize("existing", [False, True])
def test_failed_publication_never_writes_last_good(monkeypatch, failure, existing):
    from exitnode.proxy.registry import DeviceRegistry

    runner = fake()
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    runner.files[LIVE] = "原配置"
    backup = LIVE.replace(".json", ".last-good.json")
    if existing:
        runner.files[backup] = "原副本"
    registry = DeviceRegistry(SECRETS + "/devices.json", ProxyRunner(runner))
    if failure == "check":
        runner.responses[CHECK] = CompletedResult(1)
    elif failure == "registry":
        def fail(_):
            raise OSError("模拟写入失败")
        monkeypatch.setattr(registry, "save", fail)
    else:
        runner.responses[("systemctl", "reload", UNIT)] = CompletedResult(1)
        runner.responses[("systemctl", "restart", UNIT)] = CompletedResult(1)
    runner.calls.clear()
    with pytest.raises(ValueError):
        service._publish_checked(config, runner, [], registry)
    assert runner.files.get(backup) == ("原副本" if existing else None)
    assert not any(c[0] == "write_file" and c[1].startswith(backup) for c in runner.calls)
    if failure != "reload":
        assert runner.files[LIVE] == "原配置"
    if failure == "registry":
        # 回退后线上配置仍可被降权运行的隧道服务读取。
        assert runner.modes[LIVE] == 0o640
        assert runner.owners[LIVE] == ("root", "exitnode")
