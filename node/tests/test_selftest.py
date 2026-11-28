"""自测模块的假主机用例：不联网、不读真实凭据。"""

import json
from pathlib import Path

import pytest
from exitnode import device, selftest
from exitnode.cli import main
from exitnode.config import load
from exitnode.runner import CompletedResult, FakeRunner

CONFIG = "/etc/exitnode/config.toml"
BINARY = "/usr/bin/sing-box"
# 示例配置不写内核路径，这里补上夹具用的那一行。
TEXT = (Path(__file__).parents[1] / "examples" / "config.example.toml").read_text(
    encoding="utf-8").replace('hy2_server_name = "exitnode"\n',
                              f'hy2_server_name = "exitnode"\nbinary = "{BINARY}"\n')
SECRETS = "/var/lib/exitnode/secrets"
PROBE = SECRETS + "/" + selftest.PROBE_NAME
TRACE = CompletedResult(out="ip=203.0.113.9\nloc=AU\n")


def fake(*, pairing=True):
    runner = FakeRunner(files={
        CONFIG: TEXT, BINARY: "测试内核",
        (Path(__file__).parents[1] / "exitnode" / "__init__.py").as_posix():
            '__version__ = "0.1.0"\n',
        SECRETS + "/hy2.crt": "测试证书",
        SECRETS + "/hy2.key": "测试私钥占位",
    }, responses={
        (BINARY, "version"): CompletedResult(out="sing-box version 1.13.21\n"),
        ("/usr/local/bin/sing-box", "version"): CompletedResult(out="sing-box version 1.13.21\n"),
        ("/opt/exitnode/current/bin/sing-box", "version"): CompletedResult(
            out="sing-box version 1.13.21\n"),
        ("openssl", "x509"): CompletedResult(
            out="X509v3 Subject Alternative Name:\n    DNS:exitnode\n"),
        ("ip", "-j", "route"): CompletedResult(
            out='[{"dst":"default","dev":"eth0","gateway":"192.0.2.1"}]'),
        ("ip", "-j", "addr"): CompletedResult(out=json.dumps([
            {"ifname": "eth0", "ifindex": 2, "flags": ["UP"],
             "addr_info": [{"family": "inet", "scope": "global", "local": "192.0.2.2"}]}])),
        ("systemctl",): CompletedResult(),
        ("useradd",): CompletedResult(),
        ("nft", "-j"): CompletedResult(out='{"nftables":[]}'),
        ("nft", "-f"): CompletedResult(),
        (BINARY, "check"): CompletedResult(),
    }, connections={("8.8.8.8", 443): True})
    source = (Path(__file__).parents[1] / "exitnode" / "rescue").as_posix()
    for name in ("__init__.py", "__main__.py", "runner.py", "state.py", "probes.py",
                 "actions.py"):
        runner.files[source + "/" + name] = "# simulated rescue source\n"
    if pairing:
        runner.responses[("curl",)] = CompletedResult(out="ip=203.0.113.9\n")
    return runner


def installed():
    runner = fake()
    assert main(["init"], runner) == 0
    return load(CONFIG, runner), runner


def test_skips_when_not_installed():
    runner = fake()
    config = load(CONFIG, runner)
    assert selftest.run(config, runner) == {"skipped": "节点尚未完成安装，无法自测隧道"}


def test_skips_when_no_active_device():
    config, runner = installed()
    device.revoke(config, runner, name="第一台电脑")
    assert selftest.run(config, runner) == {"skipped": "没有未吊销的设备，无法自测隧道"}


def test_probe_config_uses_first_active_device_and_loopback():
    config, runner = installed()
    active = device.registry(config, runner).all()[0]
    assert active.revoked_at is None
    runner.responses[(BINARY, "tools", "fetch")] = TRACE
    selftest.run(config, runner)
    write = next(c for c in runner.calls if c[0] == "write_file" and c[1] == PROBE)
    probe = json.loads(write[2])
    assert set(probe) == {"log", "outbounds"}
    assert [item["tag"] for item in probe["outbounds"]] == ["main", "backup"]
    assert all(item["server"] == "127.0.0.1" for item in probe["outbounds"])
    assert probe["outbounds"][0]["uuid"] == active.uuid
    assert write[3] == 0o600
    assert PROBE.startswith(SECRETS + "/")


def test_fetch_argv_and_timeout(monkeypatch):
    config, runner = installed()
    runner.responses[(BINARY, "tools", "fetch")] = TRACE
    recorded = []
    original = runner.run

    def wrapped(argv, check=True, input=None, timeout=30):
        if tuple(argv[:3]) == (BINARY, "tools", "fetch"):
            recorded.append((list(argv), timeout))
        return original(argv, check=check, input=input, timeout=timeout)

    monkeypatch.setattr(runner, "run", wrapped)
    selftest.run(config, runner)
    assert len(recorded) == 2
    assert recorded[0][0] == [BINARY, "tools", "fetch", "-c", PROBE, "-o", "main",
                              selftest.TRACE_URL]
    assert recorded[1][0] == [BINARY, "tools", "fetch", "-c", PROBE, "-o", "backup",
                              selftest.TRACE_URL]
    assert [timeout for _, timeout in recorded] == [15, 15]


def test_probe_file_cleared_and_removed_even_on_error(monkeypatch):
    config, runner = installed()
    original = runner.run

    def broken(argv, check=True, input=None, timeout=30):
        if tuple(argv[:3]) == (BINARY, "tools", "fetch"):
            raise RuntimeError("模拟命令超时")
        return original(argv, check=check, input=input, timeout=timeout)

    monkeypatch.setattr(runner, "run", broken)
    result = selftest.run(config, runner)
    assert result == {"main": {"ok": False, "ip": None, "loc": None},
                      "backup": {"ok": False, "ip": None, "loc": None}}
    cleared = runner.calls.index(("write_file", PROBE, "", 0o600))
    removed = runner.calls.index(("remove", PROBE))
    assert cleared < removed
    assert PROBE not in runner.files


@pytest.mark.parametrize("response,expected", [
    (CompletedResult(out="ip=203.0.113.9\nloc=AU\n"),
     {"ok": True, "ip": "203.0.113.9", "loc": "AU"}),
    (CompletedResult(1, out="ip=203.0.113.9\nloc=AU\n"), {"ok": False, "ip": None, "loc": None}),
    (CompletedResult(out="loc=AU\n"), {"ok": False, "ip": None, "loc": None}),
    (CompletedResult(out="ip=203.0.113.9\nip=198.51.100.7\nloc=AU\n"),
     {"ok": False, "ip": None, "loc": None}),
    (CompletedResult(out="ip=203.0.113.09\nloc=AU\n"), {"ok": False, "ip": None, "loc": None}),
    (CompletedResult(out="ip=203.0.113.9\nloc=au\n"),
     {"ok": True, "ip": "203.0.113.9", "loc": None}),
])
def test_parses_ip_and_loc_and_rejects_bad_output(response, expected):
    config, runner = installed()
    runner.responses[(BINARY, "tools", "fetch")] = response
    result = selftest.run(config, runner)
    assert result["main"] == expected
    assert result["backup"] == expected


def test_result_has_no_secrets():
    config, runner = installed()
    active = device.registry(config, runner).all()[0]
    obfs = runner.files[SECRETS + "/hy2.obfs"]
    runner.responses[(BINARY, "tools", "fetch")] = TRACE
    result = selftest.run(config, runner)
    assert set(result) == {"main", "backup"}
    text = json.dumps(result, ensure_ascii=False)
    assert active.uuid not in text
    assert active.hy2_password not in text
    assert obfs not in text
