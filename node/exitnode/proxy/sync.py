"""Allowlist diff and checked publication. Caller serializes sync operations."""

import json
import logging
from dataclasses import replace
from subprocess import TimeoutExpired
from typing import TypedDict
from uuid import UUID

from .context import ProxyContext
from .registry import Device, DeviceRegistry, now, validate_devices
from .reload import reload
from .runner_proto import Runner, secret_path
from .server_config import render_server

logger = logging.getLogger(__name__)


class Diff(TypedDict):
    added: list[str]
    removed: list[str]
    unchanged: int


def _plan(devices: list[Device], allowed_list: list[dict]) -> tuple[list[Device], Diff]:
    wanted: dict[str, dict] = {}
    device_ids: set[str] = set()
    for item in allowed_list:
        try:
            if not all(isinstance(item[k], str) and item[k] for k in (
                "uuid", "hy2_password", "account_id", "device_id",
            )):
                raise ValueError
            if str(UUID(item["uuid"])) != item["uuid"]:
                raise ValueError
            if item["uuid"] in wanted or item["device_id"] in device_ids:
                raise ValueError
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError("放行名单无效或含重复设备，未应用") from None
        wanted[item["uuid"]] = item
        device_ids.add(item["device_id"])
    active = {d.uuid for d in devices if d.revoked_at is None}
    diff = Diff(
        added=sorted(wanted.keys() - active), removed=sorted(active - wanted.keys()),
        unchanged=len(active & wanted.keys()),
    )
    timestamp = now()
    result = []
    seen = set()
    for device in devices:
        item = wanted.get(device.uuid)
        if item is None:
            result.append(replace(device, revoked_at=device.revoked_at or timestamp))
            continue
        if item["device_id"] != device.device_id or item["account_id"] != device.account_id:
            raise ValueError("放行名单不能将已有凭据转移给其他设备或账户")
        seen.add(device.uuid)
        result.append(replace(device, hy2_password=item["hy2_password"], revoked_at=None))
    for uuid in sorted(wanted.keys() - seen):
        item = wanted[uuid]
        previous = next((d for d in reversed(devices) if d.device_id == item["device_id"]), None)
        if previous and previous.account_id != item["account_id"]:
            raise ValueError("放行名单不能将已有设备转移给其他账户")
        result.append(Device(
            item["device_id"], item["account_id"], previous.platform if previous else "unknown",
            previous.name if previous else item["device_id"], uuid, item["hy2_password"], timestamp,
        ))
    validate_devices(result)
    return result, diff


def sync_allowed(registry: DeviceRegistry, allowed_list: list[dict]) -> Diff:
    original = registry.all()
    devices, diff = _plan(original, allowed_list)
    if devices != original:
        registry.save(devices)
    return diff


def apply_sync(
    registry: DeviceRegistry, ctx: ProxyContext, allowed_list: list[dict],
    runner: Runner, live_path: str, *, last_good_path: str | None = None,
) -> Diff:
    """Validate before either durable state changes; then publish and reload.

    Live config and registry are separate files: not a crash-atomic two-file
    transaction. A write error restores the prior config before propagating.
    A service failure is raised, never reported as applied. Scheduling the <=60s
    sync and verifying active sessions belong to the integration caller.
    """
    live_path = secret_path(live_path)
    if live_path == registry.path:
        raise ValueError("线上配置不能覆盖设备登记表")
    if last_good_path is None:
        last_good_path = (live_path[:-5] + ".last-good.json" if live_path.endswith(".json")
                          else live_path + ".last-good")
    last_good_path = secret_path(last_good_path)
    if last_good_path in {registry.path, live_path}:
        raise ValueError("上次可用配置不能覆盖设备登记表或线上配置")
    temporary = live_path + ".check.tmp"
    if temporary == registry.path:
        raise ValueError("校验文件不能覆盖设备登记表")
    original = registry.all()
    devices, diff = _plan(original, allowed_list)
    text = json.dumps(render_server(ctx, devices), ensure_ascii=False, indent=2) + "\n"
    runner.write_file(temporary, text, 0o600)
    try:
        try:
            code, _, _ = runner.run(["sing-box", "check", "-c", temporary])
        except (OSError, TimeoutExpired):
            raise RuntimeError("隧道配置校验未完成；命令输出已隐藏") from None
        if code != 0:
            raise ValueError("隧道配置校验失败，线上配置与登记表未变；命令输出已隐藏")
        had_live = runner.exists(live_path)
        old_text = runner.read_file(live_path) if had_live else ""
        runner.write_file(live_path, text, 0o600)
        try:
            registry.save(devices)
        except (OSError, ValueError, TypeError):
            # For a first install there was no service config: use a valid,
            # empty allowlist configuration rather than retain new credentials.
            rollback = old_text if had_live else json.dumps(render_server(ctx, original)) + "\n"
            runner.write_file(live_path, rollback, 0o600)
            raise RuntimeError("登记表写入失败，线上配置已回退，未重载") from None
        reload(runner)
        runner.write_file(last_good_path, text, 0o600)
        logger.info("放行名单已应用；凭据字段 uuid/password/private_key=[已打码]")
        return diff
    finally:
        # The minimal runner has no unlink operation; erase the candidate's
        # secrets, retaining an empty private scratch file for reuse.
        runner.write_file(temporary, "", 0o600)
