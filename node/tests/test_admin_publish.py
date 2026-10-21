import hashlib
import json
from types import SimpleNamespace

import pytest
from exitnode.admin.publish import publish
from exitnode.runner import FakeRunner


def package(version="1.2.3", **changes):
    name = "YuanC-Client-" + version
    exe, manifest, signature = "/input/" + name + ".exe", "/input/" + name + ".manifest.json", "/input/" + name + ".manifest.json.sig"
    value = {"product": "YuanC-Client", "version": version, "file": name + ".exe",
             "sha256": hashlib.sha256(b"payload").hexdigest(), "size": 7}
    value.update(changes)
    return (exe, manifest, signature), {exe: b"payload", manifest: json.dumps(value), signature: b"signature"}


def config():
    return SimpleNamespace(node=SimpleNamespace(data_dir="/data"))


def test_publish_atomic_index_and_idempotence():
    paths, files = package()
    runner = FakeRunner(files=files)
    publish(config(), runner, *paths)
    index_path = "/data/winclient/releases/latest.json"
    index = json.loads(runner.read_file(index_path))
    assert set(index) == {"version", "file", "manifest", "signature", "size", "sha256", "published_at"}
    assert index["version"] == "1.2.3" and index["size"] == 7
    assert all("/" not in index[key] for key in ("file", "manifest", "signature"))
    assert runner.modes[index_path] == 0o644
    assert runner.modes["/data/winclient/releases"] == 0o755
    before = dict(runner.files)
    runner.clock += 60
    publish(config(), runner, *paths)
    assert runner.files == before
    assert not any(path.endswith(".tmp") for path in runner.files)


@pytest.mark.parametrize("changes", [{"product": "wrong"}, {"version": "../1"},
                                     {"file": "wrong.exe"}, {"sha256": "A" * 64},
                                     {"sha256": "0" * 64}, {"size": -1}, {"size": True}])
def test_validation_before_writes(changes):
    paths, files = package(**changes)
    runner = FakeRunner(files=files)
    with pytest.raises(ValueError):
        publish(config(), runner, *paths)
    assert runner.files == files


def test_downgrade_requires_explicit_flag():
    newer, files = package("1.2.10")
    older, oldfiles = package("1.2.9")
    runner = FakeRunner(files=files | oldfiles)
    publish(config(), runner, *newer)
    before = dict(runner.files)
    with pytest.raises(ValueError, match="旧"):
        publish(config(), runner, *older)
    assert runner.files == before
    publish(config(), runner, *older, allow_downgrade=True)
    assert json.loads(runner.read_file("/data/winclient/releases/latest.json"))["version"] == "1.2.9"


@pytest.mark.parametrize("which", [0, 1, 2])
def test_wrong_input_names_refused(which):
    paths, files = package()
    paths = list(paths)
    wrong = "/input/wrong"
    files[wrong] = files[paths[which]]
    paths[which] = wrong
    runner = FakeRunner(files=files)
    with pytest.raises(ValueError):
        publish(config(), runner, *paths)
    assert runner.files == files


def test_empty_signature_and_nonobject_manifest_refused():
    paths, files = package()
    for target, content in ((paths[2], b""), (paths[1], "[]")):
        runner = FakeRunner(files=files | {target: content})
        with pytest.raises(ValueError):
            publish(config(), runner, *paths)
        assert not runner.exists("/data/winclient/releases/latest.json")
