"""检查结果与运行状态的组装，命令行与管理网页共用。"""

import copy
import json

from . import authsync, netinfo, publisher, service
from .admin import server as admin_server
from .rescue import state as rescue_state
from .status import evaluate
from .watchdog import check as watchdog_check
from .watchdog import summary as watchdog_summary


def rescue_record(runner):
    if not runner.exists(rescue_state.STATE):
        return {"state": "manual", "reason": "尚无救援记录", "updated_at": None}
    try:
        value = json.loads(runner.read_file(rescue_state.STATE))
        if value["state"] not in {"normal", "processing", "manual"}:
            raise ValueError
        rescue_state.timestamp(value["updated_at"])
        return {"state": value["state"], "reason": str(value["reason"]),
                "updated_at": value["updated_at"]}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {"state": "manual", "reason": "救援记录损坏", "updated_at": None}


def rescue_check(runner):
    value = rescue_record(runner)
    active = runner.run(["systemctl", "is-active", "exitnode-rescue.timer"], check=False)
    recent = (value["updated_at"] is not None
              and 0 <= runner.now() - rescue_state.timestamp(value["updated_at"]) <= 86400)
    ok = active.code == 0 and active.out.strip() == "active" and recent
    return {"layer": "rescue", "name": "救援单元", "result": "通过" if ok else "失败",
            "reason": "定时器运行且最近一天有检查记录" if ok else "救援定时器未运行或记录已过期"}


def check_result(config, runner, base=None):
    result = copy.deepcopy(base) if base is not None else netinfo.check(runner, config)
    result["layers"].insert(-1, watchdog_check(config, runner))
    result["layers"].insert(-1, rescue_check(runner))
    result["layers"].insert(-1, service.harden_check(runner))
    if config.authsync.enabled:
        result["layers"].insert(-1, authsync.check(config, runner))
    if config.publisher.mode == "upnp":
        result["layers"].insert(-1, publisher.check(config, runner))
    result["layers"].append(admin_server.check(config))
    if config.console.enabled:
        # 延迟导入：服务器模块会经检查记录模块回头引用本模块。
        from .console import server as console_server

        result["layers"].append(console_server.check(config))
    return result


def status_result(config, runner, base=None):
    result = copy.deepcopy(base) if base is not None else netinfo.check(runner, config)
    result["public_ipv4"] = netinfo.public_ipv4(runner)
    result["publisher"] = (publisher.status(config, runner)
                           if config.publisher.mode == "upnp" else None)
    try:
        result["watchdog"] = watchdog_summary(config, runner)
    except ValueError:
        result["watchdog"] = {"state": "manual", "last_ok_at": None,
                              "consecutive_failures": 0, "last_action": None,
                              "reason": "看门狗记录损坏，请联系维护人员"}
    return evaluate(result)
