import json

import pytest
from exitnode.manifest import Manifest
from exitnode.runner import CompletedResult, FakeRunner

PATH = "/var/lib/exitnode/manifest.json"


def undo(path):
    return {"kind": "remove_file", "path": path}


def test_duplicate_and_resume_only_incomplete():
    runner = FakeRunner()
    calls = []
    manifest = Manifest(PATH, runner)
    manifest.apply("one", lambda: calls.append("one"), undo("/one"))

    def interrupted():
        calls.append("two-interrupted")
        raise RuntimeError("模拟中断")

    with pytest.raises(RuntimeError):
        manifest.apply("two", interrupted, undo("/two"))
    resumed = Manifest(PATH, runner)
    assert resumed.apply("one", lambda: calls.append("bad"), undo("/one")) is False
    resumed.apply("two", lambda: calls.append("two"), undo("/two"))
    assert calls == ["one", "two-interrupted", "two"]
    data = json.loads(runner.files[PATH])
    assert all(s["done_at"] for s in data["steps"])
    assert all(set(s) == {"step", "action", "target", "undo", "done_at"}
               for s in data["steps"])
    assert PATH + ".tmp" not in runner.files
    assert any(call[0] == "replace" for call in runner.calls)


def test_rollback_is_reverse_and_repeatable():
    runner = FakeRunner()
    manifest = Manifest(PATH, runner)
    for name in ("one", "two", "three"):
        manifest.apply(name, lambda n=name: runner.write_file("/" + n, n), undo("/" + name))
    report = manifest.rollback()
    assert report == {"removed": ["three", "two", "one"], "failed": []}
    assert [c[1] for c in runner.calls if c[0] == "remove"] == ["/three", "/two", "/one"]
    assert manifest.rollback() == {"removed": [], "failed": []}


def test_undo_failure_continues_and_can_retry():
    class FailingRunner(FakeRunner):
        fail = True

        def remove(self, path):
            if path == "/two" and self.fail:
                raise OSError("模拟文件被占用")
            super().remove(path)

    runner = FailingRunner()
    manifest = Manifest(PATH, runner)
    for name in ("one", "two", "three"):
        manifest.apply(name, lambda n=name: runner.write_file("/" + n, n), undo("/" + name))
    report = manifest.rollback()
    assert report["removed"] == ["three", "one"]
    assert report["failed"][0]["step"] == "two"
    assert [s["step"] for s in Manifest(PATH, runner).steps] == ["two"]
    runner.fail = False
    assert Manifest(PATH, runner).rollback()["removed"] == ["two"]


def test_write_ahead_recovers_action_completed_before_marker():
    class InterruptedRunner(FakeRunner):
        replacements = 0

        def replace(self, source, target):
            self.replacements += 1
            if self.replacements == 2:
                raise OSError("模拟断电")
            super().replace(source, target)

    runner = InterruptedRunner()
    with pytest.raises(OSError):
        Manifest(PATH, runner).apply("one", lambda: runner.write_file("/one", "内容"), undo("/one"))
    assert runner.files["/one"] == "内容"
    assert Manifest(PATH, runner).rollback()["removed"] == ["one"]
    assert "/one" not in runner.files


def test_partial_rollback_preserves_boundary_and_restores_backup():
    runner = FakeRunner(files={"/backup": "原内容"})
    manifest = Manifest(PATH, runner)
    manifest.apply("keep", lambda: None, undo("/keep"))
    manifest.apply("edit", lambda: runner.write_file("/config", "新内容"),
                   {"kind": "restore_file", "path": "/config", "backup": "/backup"})
    assert manifest.rollback("keep")["removed"] == ["edit"]
    assert runner.files["/config"] == "原内容"
    assert [s["step"] for s in manifest.steps] == ["keep"]


def test_service_and_table_undo_only_owned_resources():
    runner = FakeRunner(responses={
        ("systemctl",): CompletedResult(),
        ("nft", "-j"): CompletedResult(out='{"nftables":[{"table":{"family":"inet","name":"exitnode"}}]}'),
        ("nft", "delete"): CompletedResult(),
    }, files={"/etc/systemd/system/exitnode-admin.service": "单元"})
    manifest = Manifest(PATH, runner)
    manifest.apply("service", lambda: None, {"kind": "systemctl", "unit": "exitnode-admin.service"})
    manifest.apply("table", lambda: None, {"kind": "nft"})
    assert not manifest.rollback()["failed"]
    commands = [c[1] for c in runner.calls if c[0] == "run"]
    assert ("nft", "delete", "table", "inet", "exitnode") in commands
    assert ("systemctl", "disable", "--now", "exitnode-admin.service") in commands
    with pytest.raises(ValueError):
        manifest.apply("foreign", lambda: None, {"kind": "systemctl", "unit": "ssh.service"})
