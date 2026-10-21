import base64
import json
import os
from pathlib import Path
import re
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from exitnode.proxy.keys import ensure_reality_keys
from exitnode.proxy.runner_proto import FakeRunner, LocalRunner


def test_generate_permissions_reuse_and_public_derivation(tmp_path):
    runner = FakeRunner()
    directory = tmp_path / "secrets"
    first = ensure_reality_keys(directory, runner)
    assert re.fullmatch(r"[0-9a-f]{8}", first.short_id)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first.private_key)
    private = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(first.private_key + "="))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    assert base64.urlsafe_b64encode(public).decode().rstrip("=") == first.public_key
    assert runner.writes == [(str(directory / "reality.json"), 0o600)]
    with patch("exitnode.proxy.keys.X25519PrivateKey.generate", side_effect=AssertionError):
        assert ensure_reality_keys(directory, runner) == first
    assert len(runner.writes) == 1
    assert first.private_key not in repr(first)


def test_corrupt_existing_keys_are_not_replaced(tmp_path):
    runner = FakeRunner()
    directory = tmp_path / "secrets"
    ensure_reality_keys(directory, runner)
    path = str(directory / "reality.json")
    data = json.loads(runner.files[path])
    data["public_key"] = "corrupt"
    runner.files[path] = json.dumps(data)
    before = dict(runner.files)
    with pytest.raises(ValueError, match="未覆盖"):
        ensure_reality_keys(directory, runner)
    assert runner.files == before
    assert len(runner.writes) == 1


def test_secrets_directory_required(tmp_path):
    with pytest.raises(ValueError, match="secrets"):
        ensure_reality_keys(tmp_path / "public", FakeRunner())


def test_local_runner_chmods_before_atomic_replace(tmp_path):
    path = tmp_path / "secrets" / "reality.json"
    events = []
    chmod, replace = os.chmod, os.replace

    def observe_chmod(name, mode):
        events.append(("chmod", mode))
        chmod(name, mode)

    def observe_replace(source, destination):
        assert Path(source).parent == path.parent
        assert events[-1] == ("chmod", 0o600)
        events.append(("replace", None))
        replace(source, destination)

    with patch("exitnode.proxy.runner_proto.os.chmod", side_effect=observe_chmod), patch(
        "exitnode.proxy.runner_proto.os.replace", side_effect=observe_replace,
    ):
        ensure_reality_keys(path.parent, LocalRunner())
    assert events == [("chmod", 0o600), ("replace", None)]
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert list(path.parent.iterdir()) == [path]


def test_atomic_write_failure_preserves_original(tmp_path):
    runner = LocalRunner()
    path = tmp_path / "secrets" / "test.json"
    runner.write_file(str(path), "original", 0o600)
    with patch("exitnode.proxy.runner_proto.os.replace", side_effect=OSError("disk error")):
        with pytest.raises(OSError):
            runner.write_file(str(path), "new", 0o600)
    assert path.read_text() == "original"
    assert list(path.parent.iterdir()) == [path]
