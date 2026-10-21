"""Bounded reload/restart; child process output may contain secrets, never log it."""

import logging
from subprocess import TimeoutExpired

from .runner_proto import Runner

logger = logging.getLogger(__name__)


def reload(runner: Runner) -> None:
    try:
        code, _, _ = runner.run(["systemctl", "reload", "sing-box"])
    except (OSError, TimeoutError, TimeoutExpired):
        code = 1
    if code == 0:
        return
    logger.warning("隧道配置重载失败，尝试重启；命令输出已隐藏")
    try:
        code, _, _ = runner.run(["systemctl", "restart", "sing-box"])
    except (OSError, TimeoutError, TimeoutExpired):
        raise RuntimeError("隧道重启未成功，需人工处理；命令输出已隐藏") from None
    if code != 0:
        raise RuntimeError("隧道重启未成功，需人工处理；命令输出已隐藏")
