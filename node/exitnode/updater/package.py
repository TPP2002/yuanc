"""只在内存中检查签名、归档路径和完整清单；此模块不写主机。"""

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from .trust import verify_signature
from .version import Version


@dataclass(frozen=True)
class Package:
    manifest: dict
    size: int

    @property
    def version(self):
        return str(Version(self.manifest["version"]))


def safe_name(name):
    if (not isinstance(name, str) or not name or name.startswith("/")
            or "\\" in name or ":" in name or any(ord(c) < 32 for c in name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise ValueError("升级包包含不安全路径")
    return name


def validate_manifest(value):
    if not isinstance(value, dict):
        raise ValueError("清单格式不正确")
    minimum = value.get("min_config_version")
    if (type(minimum) is not int or minimum <= 0 or not isinstance(value.get("files"), dict)
            or not value["files"] or not isinstance(value.get("sing_box_version"), str)
            or not value["sing_box_version"] or not isinstance(value.get("built_at"), str)
            or not value["built_at"]):
        raise ValueError("清单格式不正确")
    Version(value.get("version"))
    for name, digest in value["files"].items():
        safe_name(name)
        if (name == "manifest.json" or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("清单格式不正确")
    if not {"exitnode/__init__.py", "bin/sing-box"}.issubset(value["files"]):
        raise ValueError("升级包缺少程序或内核")
    return value


def verify(data: bytes, signature: bytes, config_version: int | None = None) -> Package:
    verify_signature(data, signature)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            contents, seen, size = {}, set(), 0
            for member in archive.getmembers():
                name = safe_name(member.name.rstrip("/") if member.isdir() else member.name)
                if name in seen or not (member.isfile() or member.isdir()):
                    raise ValueError("升级包包含重复路径、链接或特殊文件")
                seen.add(name)
                if member.isfile():
                    contents[name] = archive.extractfile(member).read()
                    size += member.size
            file_names = set(contents)
            # 包含 manifest.json 在内，文件不能成为任一归档条目的父目录。
            if any(str(parent) in file_names for name in seen
                   for parent in PurePosixPath(name).parents):
                raise ValueError("升级包包含冲突路径")
            manifest = validate_manifest(json.loads(contents.pop("manifest.json")))
            if contents.keys() != manifest["files"].keys():
                raise ValueError("升级包文件与清单不一致")
            for name, content in contents.items():
                if hashlib.sha256(content).hexdigest() != manifest["files"][name]:
                    raise ValueError("升级包文件哈希校验失败")
    except (tarfile.TarError, OSError, EOFError, KeyError, UnicodeError, json.JSONDecodeError):
        raise ValueError("清单格式不正确或升级包损坏") from None
    if config_version is not None and manifest["min_config_version"] > config_version:
        raise ValueError(f"升级包要求配置格式版本 ≥ {manifest['min_config_version']}，"
                         f"当前为 {config_version}，请先升级配置")
    return Package(manifest, size)
