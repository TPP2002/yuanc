"""独立系统边界；不依赖主程序，模拟器从不访问真实主机。"""

import ctypes
import errno
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class Result:
    code: int = 0
    out: str = ""
    err: str = ""


class Runner(Protocol):
    def run(self, argv: list[str], timeout: float = 30) -> Result: ...
    def read(self, path: str) -> bytes: ...
    def write(self, path: str, data: bytes, mode: int = 0o600) -> None: ...
    def exists(self, path: str) -> bool: ...
    def list(self, path: str) -> list[str]: ...
    def is_dir(self, path: str) -> bool: ...
    def symlink(self, target: str, link: str) -> None: ...
    def readlink(self, path: str) -> str | None: ...
    def replace(self, source: str, target: str) -> None: ...
    def remove_tree(self, path: str) -> None: ...
    def copy_tree(self, source: str, target: str) -> None: ...
    def mkdir(self, path: str, mode: int = 0o700) -> None: ...
    def now(self) -> float: ...
    def lock_busy(self, path: str) -> bool: ...


class RealRunner:
    def __init__(self):
        if sys.platform != "linux":
            raise OSError("救援执行器仅支持 Linux，测试须注入模拟执行器")

    def run(self, argv, timeout=30):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                check=False)
        return Result(result.returncode, result.stdout, result.stderr)

    def read(self, path):
        return Path(path).read_bytes()

    def write(self, path, data, mode=0o600):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def exists(self, path):
        return os.path.lexists(path)

    def list(self, path):
        return sorted(os.listdir(path)) if self.is_dir(path) else []

    def is_dir(self, path):
        return Path(path).is_dir()

    def readlink(self, path):
        return os.readlink(path) if Path(path).is_symlink() else None

    def symlink(self, target, link):
        os.symlink(target, link, target_is_directory=True)

    def mkdir(self, path, mode=0o700):
        Path(path).mkdir(mode=mode, parents=True, exist_ok=True)

    def remove_tree(self, path):
        if Path(path).is_symlink() or Path(path).is_file():
            Path(path).unlink()
        elif Path(path).exists():
            shutil.rmtree(path)

    def copy_tree(self, source, target):
        shutil.copytree(source, target, symlinks=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    def now(self):
        return time.time()

    @staticmethod
    def _exchange(source, target):
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            rename = libc.renameat2
        except AttributeError:
            return False
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(target), 2) == 0:
            return True
        code = ctypes.get_errno()
        if code in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV}:
            return False
        raise OSError(code, os.strerror(code), target)

    @staticmethod
    def _sync_parent(path):
        fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def replace(self, source, target):
        """整体替换非空目录；降级的旧副本由下轮 cleanup 恢复或清除。"""
        if not self.exists(target):
            os.rename(source, target)
        elif self._exchange(source, target):
            self._sync_parent(target)
            self.remove_tree(source)
        else:
            backup = target + ".old-" + str(time.time_ns())
            os.rename(target, backup)
            self._sync_parent(target)
            os.rename(source, target)
            self._sync_parent(target)
            self.remove_tree(backup)
        self._sync_parent(target)

    def lock_busy(self, path):
        import fcntl

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)


class FakeRunner:
    def __init__(self, files=None, responses=None, clock=1792627200):
        self.files = {p: v.encode() if isinstance(v, str) else v
                      for p, v in (files or {}).items()}
        self.responses = responses or {}
        self.clock = clock
        self.directories = set()
        self.links = {}
        self.modes = {}
        self.calls = []
        self.locks = set()

    def _resolve(self, path):
        for _ in range(40):
            link = next((p for p in sorted(self.links, key=len, reverse=True)
                         if path == p or path.startswith(p + "/")), None)
            if link is None:
                return path
            target = self.links[link]
            if not target.startswith("/"):
                target = str(Path(link).parent).replace("\\", "/") + "/" + target
            path = target + path[len(link):]
        raise OSError("模拟链接循环")

    def run(self, argv, timeout=30):
        self.calls.append(("run", tuple(argv), timeout))
        for prefix in sorted(self.responses, key=len, reverse=True):
            if tuple(argv[:len(prefix)]) == prefix:
                value = self.responses[prefix]
                result = value.pop(0) if isinstance(value, list) else value
                if isinstance(result, Exception):
                    raise result
                return result
        return Result(127)

    def read(self, path):
        self.calls.append(("read", path))
        resolved = self._resolve(path)
        if resolved not in self.files:
            raise FileNotFoundError(path)
        return self.files[resolved]

    def write(self, path, data, mode=0o600):
        self.calls.append(("write", path, mode))
        self.files[path] = data
        self.modes[path] = mode

    def exists(self, path):
        if path in self.links:
            return True
        path = self._resolve(path)
        return path in self.files or self.is_dir(path)

    def is_dir(self, path):
        path = self._resolve(path)
        return path in self.directories or any(
            p.startswith(path + "/") for p in self.files | self.links)

    def list(self, path):
        path = self._resolve(path)
        return sorted({p[len(path) + 1:].split("/")[0]
                       for p in set(self.files) | set(self.links) | self.directories
                       if p.startswith(path + "/")})

    def readlink(self, path):
        return self.links.get(path)

    def symlink(self, target, link):
        self.calls.append(("symlink", target, link))
        if self.exists(link):
            raise FileExistsError(link)
        self.links[link] = target

    def mkdir(self, path, mode=0o700):
        self.calls.append(("mkdir", path, mode))
        self.directories.add(path)
        self.modes[path] = mode

    def now(self):
        return self.clock

    def lock_busy(self, path):
        self.calls.append(("lock_busy", path))
        return path in self.locks

    def remove_tree(self, path):
        self.calls.append(("remove_tree", path))
        for mapping in (self.files, self.links, self.modes):
            for name in list(mapping):
                if name == path or name.startswith(path + "/"):
                    del mapping[name]
        self.directories = {p for p in self.directories
                            if p != path and not p.startswith(path + "/")}

    def copy_tree(self, source, target):
        self.calls.append(("copy_tree", source, target))
        source = self._resolve(source)
        if not self.is_dir(source):
            raise FileNotFoundError(source)
        if self.exists(target):
            raise FileExistsError(target)
        self.mkdir(target, 0o755)
        for mapping in (self.files, self.links, self.modes):
            for path, value in list(mapping.items()):
                if path.startswith(source + "/"):
                    relative = path[len(source):]
                    if "__pycache__" not in relative.split("/") and not relative.endswith(".pyc"):
                        mapping[target + relative] = value
        self.directories |= {target + p[len(source):] for p in list(self.directories)
                             if p.startswith(source + "/")}

    def replace(self, source, target):
        self.calls.append(("replace", source, target))
        if not self.exists(source):
            raise FileNotFoundError(source)
        self.remove_tree(target)
        for mapping in (self.files, self.links, self.modes):
            for path in list(mapping):
                if path == source or path.startswith(source + "/"):
                    mapping[target + path[len(source):]] = mapping.pop(path)
        self.directories = {target + p[len(source):]
                            if p == source or p.startswith(source + "/") else p
                            for p in self.directories}
