"""使用清单固定的缓存内核，严格检查三种配置且不在仓库写临时文件。"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def run(binary, *args):
    return subprocess.run(
        [str(binary), *map(str, args)], capture_output=True, text=True,
        check=False, creationflags=FLAGS, timeout=30,
    )


def verify(data, expected, name):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{name} 校验值不符")


def main():
    manifest = json.loads((ROOT / "winclient/third_party/manifest.json").read_text("utf-8"))
    item = next(item for item in manifest["items"] if item["name"] == "sing-box")
    cache = ROOT / "winclient/third_party/cache" / Path(urlsplit(item["url"]).path).name
    if not cache.is_file():
        print(f"缺少内核缓存 {cache},先跑 scripts/release/fetch-third-party.ps1")
        return 2
    try:
        verify(cache.read_bytes(), item["zip_sha256"], "压缩包")
        with tempfile.TemporaryDirectory(prefix="kernel-check-") as directory:
            temporary = Path(directory)
            with zipfile.ZipFile(cache) as archive:
                executable = archive.read(item["zip_member"])
            verify(executable, item["file_sha256"], "内核文件")
            binary = temporary / item["file"]
            binary.write_bytes(executable)
            version = run(binary, "version")
            if version.returncode or item["version"] not in version.stdout:
                raise ValueError("内核版本与清单不符")
            golden = ROOT / "node/tests/golden/proxy"
            client = json.loads((golden / "client-windows.json").read_text("utf-8"))
            server = json.loads((golden / "server.json").read_text("utf-8"))
            android = json.loads(json.dumps(client))
            android["inbounds"][0]["platform"] = {"http_proxy": {"enabled": False}}
            for inbound in server["inbounds"]:
                if inbound["type"] != "hysteria2":
                    continue
                tls = inbound["tls"]
                generated = run(binary, "generate", "tls-keypair", tls["server_name"])
                if generated.returncode:
                    raise ValueError("生成检查证书失败")
                # 生成输出含私钥，只解析并保存至临时目录，绝不打印。
                for label, field, filename in (
                    ("PRIVATE KEY", "key_path", "check.key"),
                    ("CERTIFICATE", "certificate_path", "check.crt"),
                ):
                    pem = re.search(
                        rf"-----BEGIN {label}-----.*?-----END {label}-----",
                        generated.stdout + generated.stderr, re.DOTALL,
                    )
                    if pem is None:
                        raise ValueError("生成检查证书的格式无法识别")
                    path = temporary / filename
                    path.write_text(pem.group() + "\n", encoding="utf-8")
                    tls[field] = str(path)
            failed = False
            for name, config in (("客户端", client), ("节点", server), ("安卓订阅", android)):
                config = {key: value for key, value in config.items() if not key.startswith("_")}
                path = temporary / f"{name}.json"
                path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
                result = run(binary, "check", "-c", path)
                output = result.stdout + result.stderr
                if result.returncode or output:
                    failed = True
                    print(f"未通过 {name}:{output[:500]}")
                else:
                    print(f"通过 {name}")
            return 1 if failed else 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        # 异常只打印类型，避免进程异常携带证书或配置输出。
        print(f"未通过 内核配置自检:{type(error).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
