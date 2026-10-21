"""Only the node FakeRunner is used; openssl side effects are in-memory fixtures."""

import json

import pytest
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
             ("reality.json", "hy2.crt", "hy2.key", "devices.json", "sing-box.json")]
    assert all(path in runner.files and runner.modes[path] == 0o600 for path in files)
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
                 "准备设备登记表", "渲染隧道配置", "写入" + UNIT,
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
    assert commands(runner) == calls
    assert runner.files == before
    assert keys["private_key"] not in capsys.readouterr().out


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
    assert commands(runner)[boundary:] == [CHECK]
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
