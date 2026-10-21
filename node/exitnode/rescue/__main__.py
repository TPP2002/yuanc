"""独立入口；只使用标准库和相对导入。"""

import argparse
import subprocess

from . import actions, probes, state
from .runner import RealRunner


def main(argv=None, runner=None):
    parser = argparse.ArgumentParser(description="本地程序救援")
    parser.add_argument("command", choices=("tick", "status", "promote", "refresh-check"))
    args = parser.parse_args(argv)
    runner = runner if runner is not None else RealRunner()
    if args.command == "tick":
        return actions.tick(runner)
    if args.command == "status":
        value = state.read(runner)
        print(state.summary(value))
        return {"normal": 0, "processing": 1, "manual": 2}[value["state"]]
    if args.command == "refresh-check":
        return 0  # 到达此处已导入所有救援模块，不执行主机动作。
    try:
        if runner.lock_busy(probes.LOCK):
            return 1
        actions.promote(runner)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        value = state.read(runner)
        value.update(state="manual", reason="出厂包提升失败，未确认完成")
        state.save(runner, value)
        state.history(runner, "promote", "failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
