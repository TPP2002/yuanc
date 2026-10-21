"""在 Windows 或 Linux 开发机生成完整节点包与独立签名。"""

import argparse
import hashlib
import io
import json
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "node"))
from exitnode.updater.version import Version  # noqa: E402


def build(version, sing_box, key, out, *, sing_box_version="unknown", min_config_version=1):
    version = str(Version(version))
    key = Path(key).resolve()
    if key.is_relative_to(REPO):
        raise ValueError("私钥路径不许位于仓库内")
    if type(min_config_version) is not int or min_config_version <= 0:
        raise ValueError("最低配置格式版本须为正整数")
    if not isinstance(sing_box_version, str) or not sing_box_version.strip():
        raise ValueError("内核版本说明不能为空")
    signing_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise ValueError("必须使用指定类型的签名私钥")
    source = REPO / "node" / "exitnode"
    contents = {}
    for path in sorted(source.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError("程序源目录不允许包含链接")
        if path.is_file():
            contents["exitnode/" + path.relative_to(source).as_posix()] = path.read_bytes()
    # 包内版本必须与发布版本一致；修改副本，不改工作区源文件。
    import re

    init = contents["exitnode/__init__.py"].decode("utf-8")
    init, count = re.subn(r'^__version__\s*=\s*["\'][^"\']*["\']',
                          f'__version__ = "{version}"', init, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError("找不到程序版本声明")
    contents["exitnode/__init__.py"] = init.encode("utf-8")
    contents["bin/sing-box"] = Path(sing_box).read_bytes()
    if not contents["bin/sing-box"]:
        raise ValueError("内核文件不能为空")
    manifest = {"version": version, "min_config_version": min_config_version,
                "sing_box_version": sing_box_version,
                "built_at": datetime.now(UTC).isoformat(),
                "files": {name: hashlib.sha256(data).hexdigest()
                          for name, data in contents.items()}}
    contents["manifest.json"] = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in sorted(contents.items()):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o755 if name == "bin/sing-box" else 0o644
            archive.addfile(item, io.BytesIO(data))
    data = stream.getvalue()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    package = out / f"exitnode-{version}.tar.gz"
    signature = package.with_name(package.name + ".sig")
    package.with_suffix(".tmp").write_bytes(data)
    signature.with_suffix(".tmp.sig").write_bytes(signing_key.sign(data))
    package.with_suffix(".tmp").replace(package)
    signature.with_suffix(".tmp.sig").replace(signature)
    return package, signature


def main(argv=None):
    parser = argparse.ArgumentParser(description="打包并签名节点程序")
    parser.add_argument("--version", required=True)
    parser.add_argument("--sing-box", required=True, help="Linux 内核二进制路径")
    parser.add_argument("--key", required=True, help="仓库外的私钥文件")
    parser.add_argument("--out", required=True)
    parser.add_argument("--sing-box-version", default="unknown", help="内核的发布版本说明")
    parser.add_argument("--min-config-version", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        package, signature = build(args.version, args.sing_box, args.key, args.out,
                                    sing_box_version=args.sing_box_version,
                                    min_config_version=args.min_config_version)
    except Exception:
        print("打包失败：请检查版本、程序文件及仓库外的签名私钥。", file=sys.stderr)
        return 1
    print(f"已生成 {package.name} 与 {signature.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
