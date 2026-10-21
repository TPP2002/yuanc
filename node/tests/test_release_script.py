"""直接调用发布脚本函数；不启动外部进程，密钥仅在临时目录现生成。"""

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from exitnode.updater import package, trust

REPO = Path(__file__).parents[2]


def script(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "release" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def signing(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "key.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    monkeypatch.setattr(trust, "PUBLIC_KEY", key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return path


def test_complete_package_verified_and_every_file_hashed(tmp_path, signing):
    binary = tmp_path / "sing-box"
    binary.write_bytes(b"linux-binary-test-only")
    builder = script("build-node-package.py")
    archive, signature = builder.build("0.2.0", binary, signing, tmp_path / "out",
                                        sing_box_version="1.12.0")
    result = package.verify(archive.read_bytes(), signature.read_bytes(), 1)
    assert result.manifest["version"] == "0.2.0"
    assert result.manifest["sing_box_version"] == "1.12.0"
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes())) as packed:
        names = {m.name for m in packed if m.isfile()}
        assert names == set(result.manifest["files"]) | {"manifest.json"}
        for name, digest in result.manifest["files"].items():
            assert hashlib.sha256(packed.extractfile(name).read()).hexdigest() == digest
        assert '__version__ = "0.2.0"' in packed.extractfile("exitnode/__init__.py").read().decode()
        for name in ("cli.py", "runner.py", "updater/upgrade.py",
                     "templates/exitnode-proxy.service", "watchdog/__init__.py"):
            assert "exitnode/" + name in names
        assert packed.getmember("bin/sing-box").mode == 0o755
    data = archive.read_bytes()
    with pytest.raises(ValueError, match="签名"):
        package.verify(data[:-1] + bytes([data[-1] ^ 1]), signature.read_bytes())


def test_private_key_path_in_repo_refused_before_reading(tmp_path):
    builder = script("build-node-package.py")
    with pytest.raises(ValueError, match="仓库内"):
        builder.build("0.2.0", tmp_path / "missing", REPO / "must-not-exist.pem", tmp_path)
    assert not (REPO / "must-not-exist.pem").exists()


def test_generator_only_outputs_public_key_and_never_overwrites(tmp_path, capsys):
    generator = script("gen-key.py")
    path = tmp_path / "new-key.pem"
    assert generator.main(["--out", str(path)]) == 0
    private_data = path.read_bytes()
    key = serialization.load_pem_private_key(private_data, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    output = capsys.readouterr().out
    assert public.hex() in output
    assert private_data.decode() not in output
    assert generator.main(["--out", str(path)]) == 1
    assert path.read_bytes() == private_data
    with pytest.raises(ValueError, match="仓库内"):
        generator.generate(REPO / "must-not-exist.pem")


def test_published_minimum_config_version_is_required_metadata(tmp_path, signing):
    binary = tmp_path / "sing-box"
    binary.write_bytes(b"test")
    builder = script("build-node-package.py")
    archive, signature = builder.build("0.3.0", binary, signing, tmp_path / "out",
                                        min_config_version=2)
    with pytest.raises(ValueError, match="要求配置格式版本"):
        package.verify(archive.read_bytes(), signature.read_bytes(), 1)
    assert package.verify(archive.read_bytes(), signature.read_bytes(), 2)
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes())) as packed:
        manifest = json.load(packed.extractfile("manifest.json"))
        assert type(manifest["min_config_version"]) is int
