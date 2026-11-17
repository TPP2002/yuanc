import json

import pytest
from exitnode import authsync, device, service
from exitnode.config import load
from exitnode.proxy.registry import Device
from exitnode.runner import CompletedResult
from test_cli import CONFIG, fake

KEY = "仅用于测试的节点密钥"
PIN = "A" * 43 + "="
REGISTRY = service.SECRETS + "/devices.json"
KEY_PATH = service.SECRETS + "/authserver-node-key"
CHECK = ("/usr/bin/sing-box", "check", "-c", service.LIVE + ".check.tmp")
RELOAD = ("systemctl", "reload", service.UNIT)


@pytest.fixture
def installed():
    runner = fake(pairing=True)
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    service.publish(config, runner)
    config.authsync.enabled = True
    config.authsync.url = "https://example.com"
    config.authsync.spki_sha256 = PIN
    runner.files[KEY_PATH] = KEY
    runner.calls.clear()
    return config, runner


def row(n, account="remote"):
    return {"uuid": f"00000000-0000-4000-8000-{n:012d}",
            "hy2_password": f"test-password-{n}", "account_id": account,
            "device_id": f"device-{n}"}


def reply(runner, allowed, version="a" * 64, heartbeat=0):
    runner.responses[("curl",)] = [
        CompletedResult(out=json.dumps({"version": version, "allowed": allowed})),
        CompletedResult(heartbeat),
    ]


def commands(runner):
    return [c for c in runner.calls if c[0] == "run"]


def test_disabled_tick_is_noop(installed):
    config, runner = installed
    config.authsync.enabled = False
    assert authsync.tick(config, runner) == 0
    assert runner.calls == []


def test_tick_adds_and_revokes_remote_devices_and_keeps_local(installed, capsys):
    config, runner = installed
    local = Device("local", "local", "windows", "local", row(1)["uuid"], "local-pass", "now")
    old = Device("device-2", "remote", "unknown", "old", row(2)["uuid"], "old-pass", "now")
    device.registry(config, runner).save([local, old])
    reply(runner, [row(3)])
    assert authsync.tick(config, runner) == 0
    result = device.registry(config, runner).all()
    assert result[0] == local and result[1].revoked_at and result[2].uuid == row(3)["uuid"]
    assert CHECK in [c[1] for c in commands(runner)] and RELOAD in [c[1] for c in commands(runner)]
    assert runner.files[service.LAST_GOOD] == runner.files[service.LIVE]
    output = capsys.readouterr().out
    assert "新增 1,移除 1" in output
    assert all(v not in output for v in (local.uuid, old.uuid, row(3)["uuid"], "old-pass"))


def test_list_with_local_account_is_rejected(installed):
    config, runner = installed
    reply(runner, [row(1, "local")])
    assert authsync.tick(config, runner) == 1
    assert authsync.status(config, runner)["last_error"] == "名单格式不对"


def test_fetch_failure_changes_nothing_and_counts_failures(installed):
    config, runner = installed
    before = [runner.files[p] for p in (REGISTRY, service.LIVE, service.LAST_GOOD)]
    runner.responses[("curl",)] = CompletedResult(7)
    assert authsync.tick(config, runner) == authsync.tick(config, runner) == 1
    assert [runner.files[p] for p in (REGISTRY, service.LIVE, service.LAST_GOOD)] == before
    assert not any(c[1] in (CHECK, RELOAD) for c in commands(runner))
    assert authsync.status(config, runner)["consecutive_failures"] == 2


@pytest.mark.parametrize("payload", ["not json", json.dumps({"version": "a" * 64}),
    json.dumps({"version": "a" * 64, "allowed": 1}),
    json.dumps({"version": "a" * 64, "allowed": [row(1), row(1)]}),
    json.dumps({"version": "a" * 64, "allowed": [{}]}),
    json.dumps({"version": "", "allowed": []}),
    json.dumps({"version": "v1", "allowed": []}),
    json.dumps({"version": "A" * 64, "allowed": []}),
    json.dumps({"version": row(1)["uuid"], "allowed": []}),
    json.dumps({"version": "a" * 64, "allowed": [row(i) for i in range(5001)]})],
    ids=["json", "missing", "list", "duplicate", "field", "empty-version",
         "short-version", "uppercase-version", "device-id-version", "too-many"])
def test_invalid_payload_changes_nothing(installed, payload):
    config, runner = installed
    before = [runner.files[p] for p in (REGISTRY, service.LIVE, service.LAST_GOOD)]
    runner.responses[("curl",)] = CompletedResult(out=payload)
    assert authsync.tick(config, runner) == 1
    assert [runner.files[p] for p in (REGISTRY, service.LIVE, service.LAST_GOOD)] == before
    assert not any(c[1] in (CHECK, RELOAD) for c in commands(runner))
    state = authsync.status(config, runner)
    assert state["last_error"] == "名单格式不对" and state["consecutive_failures"] == 1


def test_unchanged_list_does_not_check_or_reload(installed):
    config, runner = installed
    reply(runner, [])
    assert authsync.tick(config, runner) == 0
    assert not any(c[1] in (CHECK, RELOAD) for c in commands(runner))


def test_node_key_goes_through_stdin_only(installed, capsys):
    config, runner = installed
    reply(runner, [])
    assert authsync.tick(config, runner) == 0
    calls = [c for c in commands(runner) if c[1][0] == "curl"]
    assert len(calls) == 2
    assert all(KEY not in str(c[1]) and c[3] == "X-Node-Key: " + KEY + "\n" for c in calls)
    assert KEY not in capsys.readouterr().out
    assert KEY not in json.dumps(authsync.status(config, runner), ensure_ascii=False)


def test_https_pins_public_key_and_never_follows_redirects(installed):
    config, runner = installed
    reply(runner, [])
    authsync.tick(config, runner)
    for call in commands(runner):
        argv = call[1]
        if argv[0] == "curl":
            assert "--pinnedpubkey" in argv and "sha256//" + PIN in argv
            assert "--proto" in argv and "=https" in argv
            assert "--location" not in argv and "-L" not in argv


def test_http_loopback_has_no_pin(installed):
    config, runner = installed
    config.authsync.url, config.authsync.spki_sha256 = "http://127.0.0.1:8000", ""
    reply(runner, [])
    assert authsync.tick(config, runner) == 0
    assert all("--pinnedpubkey" not in c[1] and "=http" in c[1]
               for c in commands(runner) if c[1][0] == "curl")


def test_missing_node_key_fails_before_network(installed):
    config, runner = installed
    del runner.files[KEY_PATH]
    assert authsync.tick(config, runner) == 1
    assert not commands(runner)
    assert authsync.status(config, runner)["last_error"] == "节点密钥文件缺失或无效"


@pytest.mark.parametrize("key", ["", "x\ny", "x\x7fy", "x" * 513])
def test_invalid_node_key_fails_before_network(installed, key):
    config, runner = installed
    runner.files[KEY_PATH] = key
    assert authsync.tick(config, runner) == 1
    assert not commands(runner)
    assert authsync.status(config, runner)["last_error"] == "节点密钥文件缺失或无效"


@pytest.mark.parametrize("name", ["updater.lock", "registry.lock"])
def test_busy_registry_lock_or_upgrade_lock_skips(installed, name):
    config, runner = installed
    runner.files[config.node.data_dir + "/" + name] = "occupied"
    assert authsync.tick(config, runner) == 0
    assert not commands(runner)
    assert config.node.data_dir + "/authsync.json" not in runner.files


def test_heartbeat_after_fetch_and_its_failure_is_not_fatal(installed):
    config, runner = installed
    reply(runner, [], heartbeat=7)
    assert authsync.tick(config, runner) == 0
    calls = [c[1] for c in commands(runner)]
    assert calls[0][-1].endswith("/node/allowed")
    assert calls[1][-1].endswith("/node/heartbeat") and "POST" in calls[1]
    assert authsync.status(config, runner)["heartbeat_ok"] is False


def test_publish_failure_keeps_registry_and_reports(installed):
    config, runner = installed
    before = runner.files[REGISTRY]
    runner.responses[CHECK] = CompletedResult(1)
    reply(runner, [row(1)])
    assert authsync.tick(config, runner) == 1
    assert runner.files[REGISTRY] == before
    assert authsync.status(config, runner)["last_error"] == "发布失败"


def test_check_layer_fresh_stale_and_timer(installed):
    config, runner = installed
    reply(runner, [])
    authsync.tick(config, runner)
    timer = ("systemctl", "is-active", "exitnode-authsync.timer")
    runner.responses[timer] = CompletedResult(out="active")
    assert authsync.check(config, runner)["result"] == "通过"
    runner.clock += 601
    assert authsync.check(config, runner)["result"] == "失败"
    runner.clock -= 601
    runner.responses[timer] = CompletedResult(3, "inactive")
    assert authsync.check(config, runner)["result"] == "失败"


def test_device_add_waits_for_registry_lock_when_enabled(installed):
    config, runner = installed
    path = config.node.data_dir + "/registry.lock"
    runner.files[path] = "occupied"
    before = runner.files[REGISTRY]
    with pytest.raises(ValueError, match="设备登记表正被名单同步占用"):
        device.add(config, runner, name="电脑", host="203.0.113.10")
    assert len([c for c in runner.calls if c[0] == "sleep"]) == 20
    assert runner.files[REGISTRY] == before
    config.authsync.enabled = False
    runner.calls.clear()
    device.add(config, runner, name="电脑", host="203.0.113.10")
    assert not any(c[0] in {"acquire_lock", "release_lock"} for c in runner.calls)
