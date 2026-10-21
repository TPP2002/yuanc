"""四档状态；正常仅表示已接入检查通过。"""

import json
from dataclasses import asdict, dataclass
from enum import Enum

from . import __version__


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

    def to_json(self):
        return json.dumps(asdict(self), ensure_ascii=False)


def evaluate(check_result):
    layers = {item["layer"]: item for item in check_result["layers"]}
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
        reason = "已接入的网络检查通过；入口、代理和真实出口未接入，尚不能确认可上网"
    return Status(state, __version__, check_result["network"], reason=reason)
