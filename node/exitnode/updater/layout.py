"""版本目录、原子链接切换与初次安装；文件操作均经 Runner。"""

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from .. import __version__
from .package import validate_manifest
from .version import Version


def root(config):
    return config.updater.releases_dir.rstrip("/")


def releases(config):
    return root(config) + "/releases"


def incoming(config):
    return config.node.data_dir.rstrip("/") + "/updater/incoming"


def switch(config, runner, target):
    if not runner.is_dir(target):
        raise ValueError("目标程序目录不存在，未切换")
    current = root(config) + "/current"
    temporary = current + ".new"
    if runner.exists(temporary) or runner.readlink(temporary) is not None:
        runner.remove(temporary)
    runner.symlink(target, temporary)
    runner.replace(temporary, current)


def versions(config, runner):
    result = []
    for name in runner.list_dir(releases(config)):
        try:
            version = Version(name)
        except ValueError:
            continue
        directory = releases(config) + "/" + name
        if runner.is_dir(directory) and runner.readlink(directory) is None:
            result.append((version, directory))
    return sorted(result, key=lambda pair: pair[0])


def hashes(runner, directory):
    result = {}

    def walk(path, prefix=""):
        for name in runner.list_dir(path):
            if name == "__pycache__" or name.endswith(".pyc"):
                continue
            target = path + "/" + name
            if runner.readlink(target) is not None:
                raise ValueError("程序目录包含链接，请联系维护人员")
            if runner.is_dir(target):
                walk(target, prefix + name + "/")
            else:
                result[prefix + name] = hashlib.sha256(runner.read_bytes(target)).hexdigest()

    walk(directory)
    return result


def valid_release(runner, directory):
    try:
        manifest = validate_manifest(json.loads(runner.read_file(directory + "/manifest.json")))
        actual = hashes(runner, directory)
        actual.pop("manifest.json", None)
        return actual == manifest["files"]
    except (OSError, ValueError, KeyError, TypeError):
        return False


def repair(config, runner):
    current = root(config) + "/current"
    target = runner.readlink(current)
    if target is None or runner.exists(current):
        return False
    for _, directory in reversed(versions(config, runner)):
        if not runner.exists(directory + ".bad") and valid_release(runner, directory):
            switch(config, runner, directory)
            return True
    raise ValueError("当前程序链接失效且没有可恢复版本，请联系维护人员")


def cleanup(config, runner):
    runner.remove_tree(incoming(config))
    current = runner.readlink(root(config) + "/current")
    for name in runner.list_dir(releases(config)):
        if name.endswith(".staging"):
            path = releases(config) + "/" + name
            if path != current:
                runner.remove_tree(path)
    temporary = root(config) + "/current.new"
    if runner.readlink(temporary) is not None:
        runner.remove(temporary)


def running_package():
    spec = importlib.util.find_spec("exitnode")
    return Path(next(iter(spec.submodule_search_locations))).as_posix()


def bootstrap(config, runner):
    source = running_package()
    target = releases(config) + "/" + str(Version(__version__))
    current = root(config) + "/current"
    binary = current + "/bin/sing-box"
    if not runner.exists(binary):
        binary = config.proxy.binary
    # 在写入前完整读取源文件，避免半套源程序被误认为可安装。
    expected = {"exitnode/" + name: digest for name, digest in hashes(runner, source).items()}
    expected["bin/sing-box"] = hashlib.sha256(runner.read_bytes(binary)).hexdigest()
    if "exitnode/__init__.py" not in expected:
        raise ValueError("当前程序目录不完整，无法安装")
    if runner.exists(target):
        manifest = json.loads(runner.read_file(target + "/manifest.json"))
        if manifest.get("files") != expected or not valid_release(runner, target):
            raise ValueError("同版本程序内容不同，请联系维护人员；已有版本未覆盖")
    else:
        staging = target + ".staging"
        runner.remove_tree(staging)
        runner.mkdir(staging, 0o755)
        try:
            runner.copy_tree(source, staging + "/exitnode")
            runner.mkdir(staging + "/bin", 0o755)
            runner.write_bytes(staging + "/bin/sing-box", runner.read_bytes(binary), 0o755)
            manifest = {"version": __version__, "files": expected,
                        "sing_box_version": "unknown", "min_config_version": 1,
                        "built_at": datetime.fromtimestamp(runner.now(), UTC).isoformat()}
            runner.write_file(staging + "/manifest.json", json.dumps(manifest), 0o644)
            if not valid_release(runner, staging):
                raise ValueError("安装程序目录校验失败")
            runner.replace(staging, target)
        except Exception:
            runner.remove_tree(staging)
            raise
    if not runner.exists(current):
        switch(config, runner, target)


def current_target(config, runner):
    current = root(config) + "/current"
    target = runner.readlink(current)
    if target is None:
        raise ValueError("尚未安装程序目录，请先完成安装")
    if not target.startswith("/"):
        target = str(PurePosixPath(root(config)) / target)
    if (PurePosixPath(target).parent != PurePosixPath(releases(config))
            or not runner.is_dir(target) or runner.readlink(target) is not None):
        raise ValueError("当前程序链接不在版本目录内，请联系维护人员")
    return target
