import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from test_release_script import REPO, script

PAYLOAD = b"test payload, not a real client"


def write_key(directory, key):
    path = directory / "temporary-key.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return path


def test_cross_language_vector(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    private = write_key(tmp_path, key)
    exe = tmp_path / "YuanC-Client-9.9.9.exe"
    exe.write_bytes(PAYLOAD)
    try:
        manifest, signature = script("sign-winclient.py").sign(exe, private)
    finally:
        private.unlink()
    raw = manifest.read_bytes()
    key.public_key().verify(signature.read_bytes(), raw, ec.ECDSA(hashes.SHA256()))
    value = json.loads(raw)
    assert value["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert value["size"] == len(PAYLOAD) and value["min_service_version"] == "0.1.0"
    assert raw == json.dumps(value, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    (tmp_path / "test-public-key.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


@pytest.mark.parametrize("kind", ["rsa", "ed25519", "p384"])
def test_other_key_types_rejected(tmp_path, kind):
    key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) if kind == "rsa"
           else ed25519.Ed25519PrivateKey.generate() if kind == "ed25519"
           else ec.generate_private_key(ec.SECP384R1()))
    private = write_key(tmp_path, key)
    exe = tmp_path / "YuanC-Client-1.0.0.exe"
    exe.write_bytes(PAYLOAD)
    with pytest.raises(ValueError, match="指定类型"):
        script("sign-winclient.py").sign(exe, private)
    assert not list(tmp_path.glob("*.manifest.json*"))


def test_repo_key_rejected_before_read_and_version_checked(tmp_path):
    signer = script("sign-winclient.py")
    with pytest.raises(ValueError, match="仓库内"):
        signer.sign(tmp_path / "missing.exe", REPO / "missing.pem")
    with pytest.raises(ValueError, match="版本"):
        signer.sign(tmp_path / "YuanC-Client-1.0.0.exe", tmp_path / "missing.pem", version="2.0.0")


def test_ec_generator_outputs_only_public(tmp_path, capsys):
    path = tmp_path / "generated.pem"
    assert script("gen-key.py").main(["--kind", "winclient", "--out", str(path)]) == 0
    private = path.read_bytes()
    key = serialization.load_pem_private_key(private, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)
    output = capsys.readouterr().out
    assert "BEGIN PUBLIC KEY" in output and private.decode() not in output


def test_existing_dotnet_vector_when_present():
    root = REPO / "winclient/WinClient.Tests/Fixtures/update"
    if not (root / "test-public-key.pem").exists():
        pytest.skip("首次生成跨语言夹具后再核对固定向量")
    key = serialization.load_pem_public_key((root / "test-public-key.pem").read_bytes())
    manifest = root / "YuanC-Client-9.9.9.manifest.json"
    key.verify(Path(str(manifest) + ".sig").read_bytes(), manifest.read_bytes(),
               ec.ECDSA(hashes.SHA256()))
    assert json.loads(manifest.read_bytes())["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
