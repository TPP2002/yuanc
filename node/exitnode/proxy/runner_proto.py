"""Local boundary; write_file must atomically replace a file, with mode set first.

Callers must serialize operations on one registry/configuration pair. Integration
with the node runner is deliberately outside this package's construction scope.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol


class Runner(Protocol):
    def run(self, argv: list[str]) -> tuple[int, str, str]: ...

    def write_file(self, path: str, text: str, mode: int) -> None:
        """Atomically replace path; failures leave the previous file intact."""
        ...

    def read_file(self, path: str) -> str: ...

    def exists(self, path: str) -> bool: ...


def secret_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    if "secrets" not in resolved.parts or resolved.name == "secrets":
        raise ValueError("凭据文件必须位于 secrets 目录")
    return str(resolved)


class LocalRunner:
    """Standard-library adapter; never prints command output or file contents."""

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        result = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=30, creationflags=flags,
        )
        return result.returncode, result.stdout, result.stderr

    def write_file(self, path: str, text: str, mode: int) -> None:
        target = Path(secret_path(path))
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".proxy-", dir=target.parent)
        try:
            os.chmod(temporary, mode)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if fd != -1:
                os.close(fd)
            if os.path.exists(temporary):
                os.unlink(temporary)

    def read_file(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8")

    def exists(self, path: str) -> bool:
        return Path(path).exists()


class FakeRunner:
    """Memory-only files; commands must have explicitly preset responses."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.modes: dict[str, int] = {}
        self.writes: list[tuple[str, int]] = []
        self.commands: list[list[str]] = []
        self.responses: dict[tuple[str, ...], tuple[int, str, str]] = {}

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        self.commands.append(list(argv))
        return self.responses[tuple(argv)]

    def write_file(self, path: str, text: str, mode: int) -> None:
        self.files[str(path)] = text
        self.modes[str(path)] = mode
        self.writes.append((str(path), mode))

    def read_file(self, path: str) -> str:
        return self.files[str(path)]

    def exists(self, path: str) -> bool:
        return str(path) in self.files
