"""对客户端清单原始字节签名；私钥仅从仓库外读取。"""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = Path(__file__).resolve().parents[2]
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"


def sign(exe, key, out=None, *, version=None, min_service_version="0.1.0"):
    key = Path(key).resolve()
    if key.is_relative_to(REPO):
        raise ValueError("私钥路径不许位于仓库内")
    exe = Path(exe)
    match = re.fullmatch(r"YuanC-Client-(" + VERSION + r")\.exe", exe.name)
    if (not match or version is not None and version != match[1]
            or not re.fullmatch(VERSION, min_service_version)):
        raise ValueError("客户端文件名、版本或最低后台版本不正确")
    signing_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(signing_key, ec.EllipticCurvePrivateKey) or not isinstance(
            signing_key.curve, ec.SECP256R1):
        raise ValueError("必须使用客户端指定类型的签名私钥")
    payload = exe.read_bytes()
    manifest = {"product": "YuanC-Client", "version": match[1], "file": exe.name,
                "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                "built_at": datetime.now(UTC).isoformat(), "min_service_version": min_service_version}
    raw = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    signature = signing_key.sign(raw, ec.ECDSA(hashes.SHA256()))
    directory = Path(out) if out is not None else exe.parent
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / (exe.stem + ".manifest.json")
    signature_path = directory / (manifest_path.name + ".sig")
    for path, content in ((manifest_path, raw), (signature_path, signature)):
        temporary = path.with_name(path.name + ".tmp")
        try:
            temporary.write_bytes(content)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    return manifest_path, signature_path


def main(argv=None):
    parser = argparse.ArgumentParser(description="签名 Windows 客户端发布清单")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--out")
    parser.add_argument("--version")
    parser.add_argument("--min-service-version", default="0.1.0")
    args = parser.parse_args(argv)
    try:
        manifest, signature = sign(args.exe, args.key, args.out, version=args.version,
                                   min_service_version=args.min_service_version)
    except Exception:
        print("签名失败：请检查客户端版本、文件及仓库外的签名私钥。", file=sys.stderr)
        return 1
    print(f"已生成 {manifest.name} 与 {signature.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
