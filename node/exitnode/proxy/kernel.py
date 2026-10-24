"""识别连接内核版本；命令输出仅用于解析，不写日志。"""

import re

from .runner_proto import Runner

MIN_KERNEL = (1, 13, 0)


def kernel_version(runner: Runner, path: str) -> tuple[int, int, int] | None:
    code, stdout, _ = runner.run([path, "version"])
    match = re.search(r"sing-box version (\d+)\.(\d+)\.(\d+)", stdout)
    if code != 0 or match is None:
        return None
    return tuple(int(part) for part in match.groups())


def require_kernel(runner: Runner, path: str) -> None:
    version = kernel_version(runner, path)
    if version is None or version < MIN_KERNEL:
        current = "未知" if version is None else ".".join(map(str, version))
        raise ValueError(
            f"sing-box 内核版本过低或无法识别(当前 {current}),"
            "需要 1.13.0 及以上;请先升级内核"
        )
