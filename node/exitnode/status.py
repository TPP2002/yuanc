"""四档状态；正常仅表示已接入检查通过。"""

import ipaddress
import json
from dataclasses import asdict, dataclass
from enum import Enum

from . import __version__
from .log import redact


class State(str, Enum):
    NORMAL = "normal"
    RECONNECTING = "reconnecting"
    REAUTH = "reauth"
    MANUAL = "manual"


@dataclass
class Status:
    state: State
    version: str
    network: dict
    path: str = "unknown"
    last_ok_at: str | None = None
    reason: str = ""
    public_ipv4: str | None = None
    watchdog: dict | None = None
    publisher: dict | None = None

    def to_json(self):
        return redact(json.dumps(asdict(self), ensure_ascii=False))


def evaluate(check_result):
    layers = {item["layer"]: item for item in check_result["layers"]}
    channels = layers.get("proxy", {}).get("channels") or {}
    if channels.get("main"):
        path = "main"
    elif channels.get("backup"):
        path = "backup"
    else:
        path = "unknown"
    failures = [layers[key] for key in ("network", "upstream")
                if layers.get(key, {}).get("result") != "通过"]
    if failures:
        state = State.RECONNECTING
        reason = "；".join(layer["reason"] for layer in failures)
    elif any(layer["result"] == "需重新授权" for layer in layers.values()):
        state, reason = State.REAUTH, "授权已失效，请重新授权"
    elif any(layer["result"] == "失败" for layer in layers.values()):
        state, reason = State.MANUAL, "网络可用，但服务检查失败，请联系维护人员"
    else:
        state = State.NORMAL
        egress = layers.get("egress")
        if egress and egress.get("result") == "通过":
            if channels.get("main") and channels.get("backup"):
                reason = "检查通过，经隧道可以上网"
            elif channels.get("main"):
                reason = "检查通过，经主通道可以上网；备用通道自测不通"
            elif channels.get("backup"):
                reason = "检查通过，经备用通道可以上网；主通道自测不通"
            else:
                reason = "检查通过，但尚不能确认可上网：" + egress.get("reason", "")
        else:
            reason = ("检查通过，但尚不能确认可上网："
                      + (egress["reason"] if egress else "缺少隧道自测结果"))
    watchdog = check_result.get("watchdog")
    if watchdog and watchdog["state"] in {"manual", "degraded"}:
        state = State.MANUAL if watchdog["state"] == "manual" else State.RECONNECTING
        reason = redact(watchdog["reason"])
    address = check_result.get("public_ipv4")
    if address and ipaddress.IPv4Address(address) in ipaddress.IPv4Network("100.64.0.0/10"):
        reason += "；疑似运营商内网地址(CGNAT),外网无法直连"
    return Status(state, __version__, check_result["network"], path=path, reason=reason,
                  public_ipv4=address, watchdog=watchdog, publisher=check_result.get("publisher"))
