"""系统边界：业务代码不得直接访问主机。"""

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CompletedResult:
    code: int = 0
    out: str = ""
    err: str = ""


class RunnerError(RuntimeError):
    pass


class Runner(Protocol):
    def run(self, argv: list[str], check: bool = True,
            input: str | None = None, timeout: float = 30) -> CompletedResult: ...
    def write_file(self, path: str, text: str, mode: int = 0o600) -> None: ...
    def read_file(self, path: str) -> str: ...
    def exists(self, path: str) -> bool: ...
    def remove(self, path: str) -> None: ...
    def replace(self, source: str, target: str) -> None: ...
    def mkdir(self, path: str, mode: int = 0o700) -> None: ...
    def write_bytes(self, path: str, data: bytes, mode: int = 0o600) -> None: ...
    def tcp_connect(self, host: str, port: int, timeout: float) -> bool: ...
    def purge_secrets(self) -> None: ...
    def symlink(self, target: str, link: str) -> None: ...
    def readlink(self, path: str) -> str | None: ...
    def copy_tree(self, src: str, dst: str) -> None: ...
    def disk_free(self, path: str) -> int: ...
    def extract_tar(self, archive: str, dst: str) -> None: ...
    def read_bytes(self, path: str) -> bytes: ...
    def list_dir(self, path: str) -> list[str]: ...
    def is_dir(self, path: str) -> bool: ...
    def remove_tree(self, path: str) -> None: ...
    def acquire_lock(self, path: str) -> bool: ...
    def lock_busy(self, path: str) -> bool: ...
    def release_lock(self, path: str) -> None: ...
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class RealRunner:
    def __init__(self):
        if sys.platform != "linux":
            raise RunnerError("真实系统操作仅支持 Linux；测试请注入模拟执行器")
        self._locks = {}

    def symlink(self, target, link):
        os.symlink(target, link, target_is_directory=True)

    def readlink(self, path):
        return os.readlink(path) if Path(path).is_symlink() else None

    def copy_tree(self, src, dst):
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    def disk_free(self, path):
        parent = Path(path)
        while not parent.exists():
            parent = parent.parent
        return shutil.disk_usage(parent).free

    def read_bytes(self, path):
        return Path(path).read_bytes()

    def list_dir(self, path):
        return sorted(p.name for p in Path(path).iterdir()) if Path(path).is_dir() else []

    def is_dir(self, path):
        return Path(path).is_dir()

    def remove_tree(self, path):
        if Path(path).is_symlink():
            Path(path).unlink()
        elif Path(path).exists():
            shutil.rmtree(path)

    def extract_tar(self, archive, dst):
        with tarfile.open(fileobj=io.BytesIO(self.read_bytes(archive)), mode="r:gz") as source:
            source.extractall(dst, filter="data")

    def now(self):
        return time.time()

    def sleep(self, seconds):
        time.sleep(seconds)

    def acquire_lock(self, path):
        import fcntl

        if path in self._locks:
            return False
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        keep = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            # 另一个持有者可能在本进程打开文件后释放并删除了旧锁。
            if not Path(path).exists() or os.stat(path).st_ino != os.fstat(fd).st_ino:
                return False
            content = os.read(fd, 4096)
            if content:
                try:
                    lock = json.loads(content)
                    pid, at = lock["pid"], lock["at"]
                    if type(pid) is not int or pid <= 0 or type(at) not in (int, float):
                        return False
                    if self.now() - at <= 7200:
                        return False
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        return False
                    else:
                        return False
                except (ValueError, KeyError, TypeError):
                    return False
            os.fchmod(fd, 0o600)
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps({"pid": os.getpid(), "at": self.now()}).encode())
            os.fsync(fd)
            self._locks[path] = fd
            keep = True
            return True
        finally:
            if not keep:
                os.close(fd)

    def lock_busy(self, path):
        import fcntl

        if path in self._locks:
            return True
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            content = os.read(fd, 4096)
            if not content:
                return False
            try:
                value = json.loads(content)
                if (type(value["pid"]) is not int or value["pid"] <= 0
                        or type(value["at"]) not in (int, float)
                        or self.now() - value["at"] <= 7200):
                    return True
                os.kill(value["pid"], 0)
            except ProcessLookupError:
                return False
            except (PermissionError, ValueError, TypeError, KeyError):
                return True
            return True
        finally:
            os.close(fd)

    def release_lock(self, path):
        fd = self._locks.pop(path)
        try:
            if Path(path).exists() and os.stat(path).st_ino == os.fstat(fd).st_ino:
                os.unlink(path)
        finally:
            os.close(fd)

    def run(self, argv, check=True, input=None, timeout=30):
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            result = subprocess.run(argv, input=input, capture_output=True, text=True,
                                    timeout=timeout, creationflags=flags, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError("系统命令无法执行或执行超时") from exc
        answer = CompletedResult(result.returncode, result.stdout, result.stderr)
        if check and answer.code:
            raise RunnerError(f"系统命令执行失败（退出值 {answer.code}）")
        return answer

    def write_file(self, path, text, mode=0o600):
        self.write_bytes(path, text.encode("utf-8"), mode)

    def write_bytes(self, path, data, mode=0o600):
        # 在打开时指定权限，避免敏感内容出现短暂的宽权限窗口。
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def read_file(self, path):
        return Path(path).read_text(encoding="utf-8")

    def exists(self, path):
        return Path(path).exists()

    def remove(self, path):
        target = Path(path)
        if target.is_symlink() or target.is_file():
            target.unlink(missing_ok=True)
        elif target.is_dir():
            # 不递归删除，已有用户文件会阻止删除目录。
            target.rmdir()

    def replace(self, source, target):
        os.replace(source, target)
        fd = os.open(str(Path(target).parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def mkdir(self, path, mode=0o700):
        Path(path).mkdir(mode=mode, parents=True, exist_ok=True)

    def tcp_connect(self, host, port, timeout):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def purge_secrets(self):
        path = Path("/var/lib/exitnode/secrets")
        if path.is_symlink():
            raise RunnerError("凭据目录不能为链接")
        if path.exists():
            shutil.rmtree(path)


class FakeRunner:
    """未知命令默认失败，防止测试把未配置的探测当成成功。"""

    def __init__(self, responses=None, files=None, connections=None):
        self.responses = responses or {}
        self.files = dict(files or {})
        self.connections = connections or {}
        self.directories = set()
        self.modes = {}
        self.calls = []
        self.links = {}
        self.free_bytes = 10 * 1024 ** 3
        self.clock = 1800000000.0
        self.pid = 100
        self.live_pids = {self.pid}
        self._locks = set()

    def _resolve(self, path):
        path = str(path).replace("\\", "/").rstrip("/") or "/"
        for _ in range(40):
            link = next((p for p in sorted(self.links, key=len, reverse=True)
                         if path == p or path.startswith(p + "/")), None)
            if link is None:
                return path
            target = self.links[link]
            if not target.startswith("/") and ":/" not in target:
                target = link.rsplit("/", 1)[0] + "/" + target
            path = target + path[len(link):]
        raise OSError("模拟链接循环")

    def symlink(self, target, link):
        self.calls.append(("symlink", target, link))
        if link in self.links or self.exists(link):
            raise FileExistsError("模拟链接已存在")
        self.links[link] = target

    def readlink(self, path):
        self.calls.append(("readlink", path))
        return self.links.get(path)

    def list_dir(self, path):
        path = self._resolve(path).rstrip("/") + "/"
        self.calls.append(("list_dir", path))
        return sorted({p[len(path):].split("/")[0]
                       for p in set(self.files) | self.directories | set(self.links)
                       if p.startswith(path) and p != path})

    def is_dir(self, path):
        path = self._resolve(path)
        return path in self.directories or any(p.startswith(path + "/") for p in self.files)

    def copy_tree(self, src, dst):
        self.calls.append(("copy_tree", src, dst))
        src = self._resolve(src)
        if not self.exists(src):
            raise FileNotFoundError("模拟程序目录不存在")
        if self.exists(dst):
            raise FileExistsError("模拟目标目录已存在")
        self.mkdir(dst, 0o755)
        for path, content in list(self.files.items()):
            if path.startswith(src + "/"):
                relative = path[len(src) + 1:]
                if "__pycache__" in relative.split("/") or relative.endswith(".pyc"):
                    continue
                target = dst + "/" + relative
                self.mkdir(target.rsplit("/", 1)[0], 0o755)
                self.files[target] = content
                self.modes[target] = self.modes.get(path, 0o644)

    def disk_free(self, path):
        self.calls.append(("disk_free", path))
        return self.free_bytes

    def read_bytes(self, path):
        self.calls.append(("read_bytes", str(path)))
        data = self.files[self._resolve(path)]
        return data.encode("utf-8") if isinstance(data, str) else data

    def remove_tree(self, path):
        self.calls.append(("remove_tree", path))
        if path in self.links:
            self.links.pop(path)
            return
        for mapping in (self.files, self.modes, self.links):
            for name in list(mapping):
                if name == path or name.startswith(path + "/"):
                    del mapping[name]
        self.directories = {p for p in self.directories
                            if p != path and not p.startswith(path + "/")}

    def extract_tar(self, archive, dst):
        self.calls.append(("extract_tar", archive, dst))
        with tarfile.open(fileobj=io.BytesIO(self.read_bytes(archive)), mode="r:gz") as source:
            members = source.getmembers()
            # Fake 不调用 data_filter 的真实文件系统解析；拒绝所有链接和特殊文件。
            for item in members:
                if (item.name.startswith("/") or "\\" in item.name or ":" in item.name
                        or ".." in item.name.split("/") or not (item.isfile() or item.isdir())):
                    raise ValueError("升级包包含不安全路径")
            for item in members:
                path = dst + "/" + item.name.rstrip("/")
                if item.isdir():
                    self.mkdir(path, 0o755)
                else:
                    self.mkdir(path.rsplit("/", 1)[0], 0o755)
                    self.write_bytes(path, source.extractfile(item).read(), item.mode & 0o755)

    def now(self):
        return self.clock

    def sleep(self, seconds):
        self.calls.append(("sleep", seconds))
        self.clock += seconds

    def acquire_lock(self, path):
        self.calls.append(("acquire_lock", path))
        if self.lock_busy(path):
            return False
        self._locks.add(path)
        self.write_file(path, json.dumps({"pid": self.pid, "at": self.now()}))
        return True

    def lock_busy(self, path):
        self.calls.append(("lock_busy", path))
        if path in self._locks:
            return True
        if path in self.files:
            try:
                value = json.loads(self.files[path])
                if (type(value["pid"]) is not int or value["pid"] <= 0
                        or type(value["at"]) not in (int, float)
                        or self.now() - value["at"] <= 7200
                        or value["pid"] in self.live_pids):
                    return True
            except (ValueError, TypeError, KeyError):
                return True
        return False

    def release_lock(self, path):
        self.calls.append(("release_lock", path))
        self._locks.remove(path)
        self.remove(path)

    def run(self, argv, check=True, input=None, timeout=30):
        self.calls.append(("run", tuple(argv), check, input))
        result = CompletedResult(127, err="模拟命令未配置")
        for prefix in sorted(self.responses, key=len, reverse=True):
            if tuple(argv[:len(prefix)]) == tuple(prefix):
                value = self.responses[prefix]
                result = value.pop(0) if isinstance(value, list) else value
                break
        if isinstance(result, Exception):
            raise result
        if check and result.code:
            raise RunnerError(f"模拟命令失败（退出值 {result.code}）")
        return result

    def write_file(self, path, text, mode=0o600):
        self.calls.append(("write_file", str(path), text, mode))
        self.files[str(path)] = text
        self.modes[str(path)] = mode

    def write_bytes(self, path, data, mode=0o600):
        self.calls.append(("write_bytes", str(path), mode))
        self.files[str(path)] = data
        self.modes[str(path)] = mode

    def read_file(self, path):
        self.calls.append(("read_file", str(path)))
        path = self._resolve(path)
        if path not in self.files:
            raise FileNotFoundError("模拟文件不存在")
        value = self.files[path]
        return value.decode("utf-8") if isinstance(value, bytes) else value

    def exists(self, path):
        self.calls.append(("exists", str(path)))
        path = self._resolve(path)
        return (path in self.files or path in self.directories
                or any(p.startswith(path + "/") for p in self.files))

    def remove(self, path):
        path = str(path)
        self.calls.append(("remove", path))
        if path in self.links:
            self.links.pop(path)
            return
        if path in self.directories:
            if any(p.startswith(path + "/") for p in set(self.files) | self.directories):
                raise OSError("目录不为空")
            self.directories.remove(path)
        self.files.pop(path, None)
        self.modes.pop(path, None)

    def replace(self, source, target):
        self.calls.append(("replace", source, target))
        if source in self.links:
            self.links[target] = self.links.pop(source)
            return
        if source in self.directories:
            if self.exists(target):
                raise FileExistsError("模拟替换目标已存在")
            for mapping in (self.files, self.modes, self.links):
                for path in list(mapping):
                    if path == source or path.startswith(source + "/"):
                        mapping[target + path[len(source):]] = mapping.pop(path)
            self.directories = {target + p[len(source):]
                                if p == source or p.startswith(source + "/") else p
                                for p in self.directories}
        else:
            self.files[target] = self.files.pop(source)
            self.modes[target] = self.modes.pop(source, 0o600)

    def mkdir(self, path, mode=0o700):
        self.calls.append(("mkdir", path, mode))
        self.directories.add(path)
        self.modes[path] = mode

    def tcp_connect(self, host, port, timeout):
        self.calls.append(("tcp_connect", host, port, timeout))
        return self.connections.get((host, port), False)

    def purge_secrets(self):
        self.calls.append(("purge_secrets",))
        prefix = "/var/lib/exitnode/secrets"
        for path in list(self.files):
            if path.startswith(prefix + "/"):
                del self.files[path]
        self.directories = {p for p in self.directories
                            if p != prefix and not p.startswith(prefix + "/")}
