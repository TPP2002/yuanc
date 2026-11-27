import json
from datetime import UTC, datetime

import pytest
from exitnode import netinfo, report
from exitnode.config import load
from exitnode.console import snapshot
from exitnode.log import redact
from exitnode.runner import FakeRunner
from test_cli import CONFIG, fake


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("exitnode.admin.server.check", lambda config: {
        "layer": "winclient", "name": "客户端托管服务", "result": "通过", "reason": "测试"})


def test_collect_matches_cli_check_and_status():
    runner = fake()
    config = load(CONFIG, runner)
    value = snapshot.collect(config, runner)
    base = netinfo.check(runner, config)
    checked = report.check_result(config, runner, base=base)
    status = report.status_result(config, runner, base=base)
    assert value["version"] == 1
    assert value["node_name"] == config.node.name
    assert value["state"] == status.state.value
    assert value["reason"] == redact(status.reason)
    assert value["public_ipv4"] == status.public_ipv4
    assert value["layers"] == [
        {"layer": layer["layer"], "name": layer["name"], "result": layer["result"],
         "reason": redact(layer["reason"])} for layer in checked["layers"]]
    assert value["generated_at"].endswith("+00:00")


def test_collect_probes_network_once():
    runner = fake()
    config = load(CONFIG, runner)
    snapshot.collect(config, runner)
    routes = [call for call in runner.calls
              if call[0] == "run" and tuple(call[1][:3]) == ("ip", "-j", "route")]
    assert len(routes) == 1


def test_local_devices_only_and_no_credentials():
    runner = fake()
    config = load(CONFIG, runner)
    local = {"device_id": "local-one", "account_id": "local", "platform": "windows",
             "name": "本机", "uuid": "11111111-1111-1111-1111-111111111111",
             "hy2_password": "local-secret-value", "created_at": "2026-11-01T00:00:00+00:00",
             "revoked_at": None}
    other = {"device_id": "acc-one", "account_id": "acc", "platform": "android",
             "name": "别人的手机", "uuid": "22222222-2222-2222-2222-222222222222",
             "hy2_password": "remote-secret-value", "created_at": "2026-11-01T00:00:00+00:00",
             "revoked_at": None}
    runner.files["/var/lib/exitnode/secrets/devices.json"] = json.dumps([local, other])
    value = snapshot.collect(config, runner)
    assert value["local_devices"] == [
        {"name": "本机", "platform": "windows", "created_at": "2026-11-01T00:00:00+00:00",
         "revoked_at": None}]
    text = json.dumps(value, ensure_ascii=False)
    assert "11111111-1111" not in text and "local-secret-value" not in text
    assert "22222222-2222" not in text and "remote-secret-value" not in text


def test_write_sets_modes_and_is_atomic():
    config = load(CONFIG, fake())
    runner = FakeRunner()
    snapshot.write(config, runner, {"version": 1})
    target = "/var/lib/exitnode/console/status.json"
    assert ("mkdir", "/var/lib/exitnode/console", 0o755) in runner.calls
    assert ("chmod", "/var/lib/exitnode/console", 0o755) in runner.calls
    assert ("write_file", target + ".tmp", '{"version": 1}', 0o644) in runner.calls
    assert ("chmod", target + ".tmp", 0o644) in runner.calls
    assert ("replace", target + ".tmp", target) in runner.calls
    assert runner.modes[target] == 0o644
    assert runner.files[target] == '{"version": 1}'


def test_load_states(tmp_path):
    now = 1800000000.0

    def stamp(offset):
        return datetime.fromtimestamp(now + offset, UTC).isoformat()

    def record(**overrides):
        value = {"version": 1, "generated_at": stamp(-10), "node_name": "节点",
                 "program_version": "0.1.0", "state": "normal", "reason": "正常",
                 "public_ipv4": None, "layers": [], "local_devices": []}
        value.update(overrides)
        return value

    target = tmp_path / "status.json"
    assert snapshot.load(str(target), now) == {"available": False}
    target.write_text("不是 JSON", encoding="utf-8")
    assert snapshot.load(str(target), now) == {"available": False}
    target.write_text(json.dumps(record(version=2)), encoding="utf-8")
    assert snapshot.load(str(target), now) == {"available": False}
    missing = record()
    del missing["reason"]
    target.write_text(json.dumps(missing), encoding="utf-8")
    assert snapshot.load(str(target), now) == {"available": False}
    target.write_text(json.dumps(record(generated_at="坏时间")), encoding="utf-8")
    assert snapshot.load(str(target), now) == {"available": False}

    target.write_text(json.dumps(record()), encoding="utf-8")
    value = snapshot.load(str(target), now)
    assert value["available"] is True
    assert value["age_seconds"] == 10 and value["stale"] is False
    assert value["state"] == "normal" and value["reason"] == "正常"

    target.write_text(json.dumps(record(generated_at=stamp(-200))), encoding="utf-8")
    assert snapshot.load(str(target), now)["stale"] is True
    target.write_text(json.dumps(record(generated_at=stamp(120))), encoding="utf-8")
    assert snapshot.load(str(target), now)["stale"] is True
    target.write_text(json.dumps(record(generated_at=stamp(-180))), encoding="utf-8")
    assert snapshot.load(str(target), now)["stale"] is False
