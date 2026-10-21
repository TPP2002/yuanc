"""系统边界：业务代码不得直接访问主机。"""

import os
import shutil
import socket
import subprocess
import sys
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
            input: str | None = None) -> CompletedResult: ...
    def write_file(self, path: str, text: str, mode: int = 0o600) -> None: ...
    def read_file(self, path: str) -> str: ...
    def exists(self, path: str) -> bool: ...
    def remove(self, path: str) -> None: ...
    def replace(self, source: str, target: str) -> None: ...
    def mkdir(self, path: str, mode: int = 0o700) -> None: ...
    def write_bytes(self, path: str, data: bytes, mode: int = 0o600) -> None: ...
    def tcp_connect(self, host: str, port: int, timeout: float) -> bool: ...
    def purge_secrets(self) -> None: ...


class RealRunner:
    def __init__(self):
        if sys.platform != "linux":
            raise RunnerError("真实系统操作仅支持 Linux；测试请注入模拟执行器")

    def run(self, argv, check=True, input=None):
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            result = subprocess.run(argv, input=input, capture_output=True, text=True,
                                    timeout=30, creationflags=flags, check=False)
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

    def run(self, argv, check=True, input=None):
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
        if str(path) not in self.files:
            raise FileNotFoundError("模拟文件不存在")
        return self.files[str(path)]

    def exists(self, path):
        self.calls.append(("exists", str(path)))
        return str(path) in self.files or str(path) in self.directories

    def remove(self, path):
        path = str(path)
        self.calls.append(("remove", path))
        if path in self.directories:
            if any(p.startswith(path + "/") for p in set(self.files) | self.directories):
                raise OSError("目录不为空")
            self.directories.remove(path)
        self.files.pop(path, None)
        self.modes.pop(path, None)

    def replace(self, source, target):
        self.calls.append(("replace", source, target))
        self.files[target] = self.files.pop(source)
        self.modes[target] = self.modes.pop(source)

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
