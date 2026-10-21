"""生成一次性发布密钥；私钥只写入指定的仓库外文件。"""

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]


def generate(out, kind="node"):
    out = Path(out).resolve()
    if out.is_relative_to(REPO):
        raise ValueError("私钥路径不许位于仓库内")
    if kind not in {"node", "winclient"}:
        raise ValueError("签名密钥类型不正确")
    key = Ed25519PrivateKey.generate() if kind == "node" else ec.generate_private_key(ec.SECP256R1())
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    out.chmod(0o600)
    if kind == "winclient":
        return key.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description="生成节点更新签名密钥")
    parser.add_argument("--out", required=True, help="仓库外的私钥文件路径；父目录须已存在")
    parser.add_argument("--kind", choices=["node", "winclient"], default="node")
    args = parser.parse_args(argv)
    try:
        public = generate(args.out, args.kind)
    except Exception:
        print("生成失败：请选择仓库外尚不存在的私钥文件，并检查目录权限。", file=sys.stderr)
        return 1
    print("私钥已写入指定文件。以下仅为公钥，请写入节点信任配置：")
    print(public.decode("ascii") if args.kind == "winclient"
          else f'PUBLIC_KEY = bytes.fromhex("{public.hex()}")')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
