"""恢复前按登记表过滤用户；独立副本仅依赖标准库。"""

import json


def prune_revoked(text: str, devices_text: str | None) -> tuple[str, int]:
    try:
        devices = [] if devices_text is None else json.loads(devices_text)
        if not isinstance(devices, list):
            raise ValueError
        for device in devices:
            if (not isinstance(device, dict)
                    or not isinstance(device.get("device_id"), str)
                    or not isinstance(device.get("uuid"), str)
                    or "revoked_at" not in device
                    or (device["revoked_at"] is not None
                        and not isinstance(device["revoked_at"], str))):
                raise ValueError
    except (ValueError, TypeError):
        raise ValueError("设备登记表损坏，无法核对上次可用配置") from None
    active_ids = {d["device_id"] for d in devices if d["revoked_at"] is None}
    active_uuids = {d["uuid"] for d in devices if d["revoked_at"] is None}
    try:
        config = json.loads(text)
    except ValueError:
        return text, 0
    if (not isinstance(config, dict) or not isinstance(config.get("inbounds"), list)
            or any(not isinstance(row, dict) or not isinstance(row.get("users"), list)
                   for row in config["inbounds"])):
        return text, 0
    removed = 0
    for inbound in config["inbounds"]:
        kept = []
        for user in inbound["users"]:
            if isinstance(user, dict):
                key, allowed = ("uuid", active_uuids) if "uuid" in user else ("name", active_ids)
                if isinstance(user.get(key), str) and user[key] in allowed:
                    kept.append(user)
        removed += len(inbound["users"]) - len(kept)
        inbound["users"] = kept
    if not removed:
        return text, 0
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n", removed
