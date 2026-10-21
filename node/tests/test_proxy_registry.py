import json
from uuid import UUID

import pytest

from exitnode.proxy.registry import DeviceRegistry
from exitnode.proxy.runner_proto import FakeRunner


def test_add_idempotent_revoke_and_audit(tmp_path):
    runner = FakeRunner()
    registry = DeviceRegistry(str(tmp_path / "secrets" / "devices.json"), runner)
    assert registry.active() == []
    first = registry.add("phone", "owner", "android", "手机")
    assert UUID(first.uuid).version == 4
    assert len(first.hy2_password) >= 32
    assert first.uuid not in repr(first)
    assert first.hy2_password not in repr(first)
    second = registry.add("phone", "owner", "android", "手机")
    assert first == second
    assert len(runner.writes) == 1
    other = registry.add("pc", "owner", "windows", "电脑")
    assert first.uuid != other.uuid
    assert first.hy2_password != other.hy2_password
    registry.revoke("phone")
    rows = json.loads(runner.read_file(registry.path))
    assert len(rows) == 2
    assert rows[0]["revoked_at"]
    assert rows[0]["created_at"] == first.created_at
    assert registry.active() == [other]
    writes = len(runner.writes)
    registry.revoke("phone")
    registry.revoke("missing")
    assert registry.add("phone", "owner", "android", "手机").revoked_at is not None
    assert len(runner.writes) == writes
    assert all(mode == 0o600 for _, mode in runner.writes)


def test_existing_device_cannot_change_account(tmp_path):
    runner = FakeRunner()
    registry = DeviceRegistry(str(tmp_path / "secrets" / "devices.json"), runner)
    registry.add("pc", "alice", "windows", "电脑")
    before = dict(runner.files)
    with pytest.raises(ValueError, match="其他账户"):
        registry.add("pc", "bob", "windows", "电脑")
    assert runner.files == before


def test_invalid_file_or_path_fails_closed(tmp_path):
    runner = FakeRunner()
    with pytest.raises(ValueError, match="secrets"):
        DeviceRegistry(str(tmp_path / "devices.json"), runner)
    registry = DeviceRegistry(str(tmp_path / "secrets" / "devices.json"), runner)
    runner.files[registry.path] = "not-json"
    with pytest.raises(ValueError, match="损坏"):
        registry.add("pc", "a", "windows", "电脑")
    assert runner.files[registry.path] == "not-json"
