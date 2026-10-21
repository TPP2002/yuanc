from dataclasses import asdict
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from exitnode.proxy.context import ProxyContext
from exitnode.proxy.keys import RealityKeys
from exitnode.proxy.registry import Device, DeviceRegistry
from exitnode.proxy.reload import reload
from exitnode.proxy.runner_proto import FakeRunner
from exitnode.proxy.server_config import render_server
from exitnode.proxy.sync import apply_sync, sync_allowed


@pytest.fixture
def state(tmp_path):
    path = Path(__file__).parent / "golden" / "proxy" / "inputs.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    ctx_data = data["context"]
    ctx_data["reality"] = RealityKeys(**ctx_data["reality"])
    ctx = ProxyContext(**ctx_data)
    runner = FakeRunner()
    registry = DeviceRegistry(str(tmp_path / "secrets" / "devices.json"), runner)
    device = Device(**data["device"])
    registry.save([device])
    live = str(tmp_path / "secrets" / "sing-box.json")
    runner.write_file(live, json.dumps(render_server(ctx, [device])), 0o600)
    runner.responses[("sing-box", "check", "-c", live + ".check.tmp")] = (0, "", "")
    runner.responses[("systemctl", "reload", "sing-box")] = (0, "", "")
    return runner, registry, ctx, device, live


def allowed(device):
    return {k: v for k, v in asdict(device).items()
            if k in {"uuid", "hy2_password", "account_id", "device_id"}}


def test_diff_idempotence_removal_and_audit(state):
    runner, registry, _, device, _ = state
    other = registry.add("other", "account-1", "windows", "另一台")
    diff = sync_allowed(registry, [allowed(device)])
    assert diff == {"added": [], "removed": [other.uuid], "unchanged": 1}
    rows = registry.all()
    assert len(rows) == 2 and rows[1].revoked_at
    assert registry.active() == [device]
    writes = len(runner.writes)
    assert sync_allowed(registry, [allowed(device)]) == {"added": [], "removed": [], "unchanged": 1}
    assert len(runner.writes) == writes
    assert sync_allowed(registry, []) == {"added": [], "removed": [device.uuid], "unchanged": 0}
    assert not registry.active()
    assert all(d.revoked_at for d in registry.all())


def test_uuid_rotation_keeps_revoked_history(state):
    _, registry, _, device, _ = state
    new = allowed(device)
    new["uuid"] = "00000000-0000-4000-8000-000000000002"
    new["hy2_password"] = "TEST-ONLY-rotated"
    diff = sync_allowed(registry, [new])
    assert diff == {"added": [new["uuid"]], "removed": [device.uuid], "unchanged": 0}
    assert registry.all()[0].revoked_at
    assert registry.active()[0].uuid == new["uuid"]
    assert registry.active()[0].hy2_password == new["hy2_password"]
    assert registry.add(device.device_id, device.account_id, device.platform, device.name).uuid == new["uuid"]


def test_apply_checked_config_matches_registry(state, caplog):
    runner, registry, ctx, device, live = state
    new = {**allowed(device), "device_id": "phone",
           "uuid": "00000000-0000-4000-8000-000000000002", "hy2_password": "TEST-ONLY-new"}
    with caplog.at_level("INFO"):
        diff = apply_sync(registry, ctx, [new], runner, live)
    assert diff == {"added": [new["uuid"]], "removed": [device.uuid], "unchanged": 0}
    assert json.loads(runner.files[live]) == render_server(ctx, registry.active())
    assert registry.all()[0].revoked_at
    assert runner.commands == [["sing-box", "check", "-c", live + ".check.tmp"],
                               ["systemctl", "reload", "sing-box"]]
    assert runner.files[live + ".check.tmp"] == ""
    assert all(mode == 0o600 for _, mode in runner.writes)
    for secret in (device.uuid, device.hy2_password, ctx.reality.private_key, new["hy2_password"]):
        assert secret not in caplog.text


def test_failed_check_never_changes_live_or_registry_or_reloads(state, caplog):
    runner, registry, ctx, device, live = state
    original_config, original_registry = runner.files[live], runner.files[registry.path]
    runner.responses[("sing-box", "check", "-c", live + ".check.tmp")] = (
        1, device.uuid, ctx.reality.private_key + device.hy2_password,
    )
    with pytest.raises(ValueError, match="校验失败") as error:
        apply_sync(registry, ctx, [], runner, live)
    assert runner.files[live] == original_config
    assert runner.files[registry.path] == original_registry
    assert runner.commands == [["sing-box", "check", "-c", live + ".check.tmp"]]
    assert runner.files[live + ".check.tmp"] == ""
    for secret in (device.uuid, device.hy2_password, ctx.reality.private_key):
        assert secret not in str(error.value) + caplog.text


def test_reload_falls_back_once_and_never_logs_raw_output(state, caplog):
    runner, _, ctx, device, _ = state
    runner.responses[("systemctl", "reload", "sing-box")] = (1, device.uuid, device.hy2_password)
    runner.responses[("systemctl", "restart", "sing-box")] = (1, "", ctx.reality.private_key)
    with pytest.raises(RuntimeError, match="人工处理") as error:
        reload(runner)
    assert runner.commands == [["systemctl", "reload", "sing-box"],
                               ["systemctl", "restart", "sing-box"]]
    for secret in (device.uuid, device.hy2_password, ctx.reality.private_key):
        assert secret not in caplog.text + str(error.value)
    runner.responses[("systemctl", "restart", "sing-box")] = (0, "", "")
    reload(runner)


def test_bad_allowlist_rejected_without_mutation(state):
    runner, registry, ctx, device, live = state
    before = dict(runner.files)
    for invalid in ([allowed(device), allowed(device)], [{"uuid": "bad"}],
                    [{**allowed(device), "account_id": "different"}]):
        with pytest.raises(ValueError):
            apply_sync(registry, ctx, invalid, runner, live)
        assert runner.files == before
        assert not runner.commands


def test_registry_write_failure_rolls_back_live_without_reload(state):
    runner, registry, ctx, _, live = state
    before = runner.files[live], runner.files[registry.path]
    with patch.object(registry, "save", side_effect=OSError("disk full")):
        with pytest.raises(RuntimeError, match="回退"):
            apply_sync(registry, ctx, [], runner, live)
    assert (runner.files[live], runner.files[registry.path]) == before
    assert runner.commands == [["sing-box", "check", "-c", live + ".check.tmp"]]
