"""自用设备登记与配对导出；主机读写和外部命令全部经过 Runner。"""

import json
import re
from contextlib import contextmanager
from dataclasses import replace
from typing import NotRequired, TypedDict

from . import service
from .netinfo import public_ipv4
from .proxy.context import ipv4_host, validate_context
from .proxy.keys import ensure_reality_keys
from .proxy.registry import DeviceRegistry, now, validate_devices
from .proxy.subscription import vless_link


class PairNode(TypedDict):
    host: str
    reality_port: int
    hy2_port: int
    sni: str
    reality_public_key: str
    short_id: str
    uuid: str
    hy2_password: str
    hy2_server_name: str
    hy2_certificate: list[str]
    # ycpair/2 没有这个键；ycpair/3 多一个节点级混淆密码，绝不写空串。
    hy2_obfs_password: NotRequired[str]
    time_zone: NotRequired[str]
    country: NotRequired[str]


class PairFile(TypedDict):
    format: str
    exported_at: str
    node: PairNode


def safe_name(name):
    if not isinstance(name, str) or any(part in name for part in ("/", "\\", "..")):
        raise ValueError("设备名字不能含路径分隔符或连续两个点")
    result = re.sub(r"[^A-Za-z0-9_\-\u3400-\u4dbf\u4e00-\u9fff]", "", name)
    if not 1 <= len(result) <= 64:
        raise ValueError("设备名字安全化后须为 1 至 64 个字母、数字、中划线、下划线或汉字")
    return result


def render_pair(ctx, device, host, exported_at) -> PairFile:
    if device.revoked_at is not None:
        raise ValueError("设备已吊销，不能导出配对文件")
    validate_devices([device])
    host = ipv4_host(replace(ctx, server_host=host))
    validate_context(ctx)
    node = PairNode(
        host=host, reality_port=ctx.reality_port, hy2_port=ctx.hy2_port, sni=ctx.sni,
        reality_public_key=ctx.reality.public_key, short_id=ctx.reality.short_id,
        uuid=device.uuid, hy2_password=device.hy2_password,
        hy2_server_name=ctx.hy2_server_name, hy2_certificate=list(ctx.hy2_certificate),
    )
    if ctx.time_zone:
        node["time_zone"] = ctx.time_zone
    if ctx.country:
        node["country"] = ctx.country
    if not ctx.hy2_obfs_password:
        return PairFile(format="ycpair/2", exported_at=exported_at, node=node)
    node["hy2_obfs_password"] = ctx.hy2_obfs_password
    return PairFile(format="ycpair/3", exported_at=exported_at, node=node)


def registry(config, runner):
    return DeviceRegistry(config.node.secrets_dir.rstrip("/") + "/devices.json",
                          service.ProxyRunner(runner))


class _CandidateRegistry(DeviceRegistry):
    """只在内存中复用登记规则，通过校验后才发布到真实登记表。"""

    def __init__(self, devices):
        self.devices = devices[:]

    def all(self):
        return self.devices[:]

    def save(self, devices):
        validate_devices(devices)
        self.devices = devices[:]


def _context(config, runner, host):
    adapter = service.ProxyRunner(runner)
    if not adapter.exists(config.node.secrets_dir.rstrip("/") + "/reality.json"):
        raise ValueError("节点尚未准备好凭据，请先完成 init")
    keys = ensure_reality_keys(config.node.secrets_dir, adapter)
    ctx = service.build_context(config, keys, runner)
    address = host if host is not None else public_ipv4(runner)
    if address is None:
        raise ValueError("未取得公网 IPv4，请用 --host 手填节点公网 IPv4 地址")
    try:
        address = ipv4_host(replace(ctx, server_host=address))
    except ValueError:
        raise ValueError("--host 必须为 IPv4 数字地址") from None
    return replace(ctx, server_host=address)


def _find(devices, name):
    device_id = safe_name(name)
    for device in reversed(devices):
        if device.device_id == device_id:
            if device.name != name or device.account_id != "local":
                raise ValueError("安全化后的名字已被其他设备占用，请换一个名字")
            return device
    raise ValueError("设备未登记，请先添加设备")


def qr(runner, text):
    # 链接走标准输入，避免凭据出现在进程参数列表里。
    try:
        result = runner.run(["qrencode", "-t", "UTF8"], check=False, input=text)
    except (OSError, RuntimeError):
        result = None
    if result is None or result.code == 127:
        return "未找到 qrencode；如需二维码，请运行 sudo apt install qrencode。"
    if result.code:
        return "二维码生成失败，仍可使用配对文件或链接；命令输出已隐藏。"
    return result.out


def _export(config, runner, ctx, device, clock):
    pair = render_pair(ctx, device, ctx.server_host, clock())
    directory = config.node.data_dir.rstrip("/") + "/export"
    path = directory + "/" + safe_name(device.name) + ".ycpair"
    runner.mkdir(directory, 0o700)
    # 暂存仍用配对文件扩展名，且在打开时即指定私有权限。
    temporary = path + ".tmp.ycpair"
    try:
        runner.write_file(temporary, json.dumps(pair, ensure_ascii=False, indent=2) + "\n", 0o600)
        runner.replace(temporary, path)
    finally:
        if runner.exists(temporary):
            runner.write_file(temporary, "", 0o600)
            runner.remove(temporary)
    link = vless_link(ctx, device)
    print("配对文件：" + path)
    print(link)
    print(qr(runner, link))
    return path


@contextmanager
def _registry_lock(config, runner):
    if not config.authsync.enabled:
        yield
        return
    path = config.node.data_dir.rstrip("/") + "/registry.lock"
    for _ in range(20):
        if runner.acquire_lock(path):
            try:
                yield
            finally:
                runner.release_lock(path)
            return
        runner.sleep(0.5)
    raise ValueError("设备登记表正被名单同步占用,请稍后重试")


def add(config, runner, *, name, platform="windows", host=None, clock=now):
    with _registry_lock(config, runner):
        return _add(config, runner, name=name, platform=platform, host=host, clock=clock)


def _add(config, runner, *, name, platform="windows", host=None, clock=now):
    device_id = safe_name(name)
    if platform not in {"windows", "android"}:
        raise ValueError("设备平台只能为 windows 或 android")
    candidate = _CandidateRegistry(registry(config, runner).all())
    if any(d.device_id == device_id for d in candidate.all()):
        device = _find(candidate.all(), name)
        if device.revoked_at is not None:
            raise ValueError("设备已吊销，不能重新添加或导出，请使用新的设备名字")
    ctx = _context(config, runner, host)
    device = candidate.add(device_id, "local", platform, name)
    # 同名不换凭据；仍重新校验发布，可恢复上次登记后的重载失败。
    service.publish(config, runner, devices=candidate.all())
    _export(config, runner, ctx, device, clock)
    return device


def list_devices(config, runner):
    return [{"name": d.name, "platform": d.platform, "created_at": d.created_at,
             "revoked_at": d.revoked_at} for d in registry(config, runner).all()]


def revoke(config, runner, *, name):
    with _registry_lock(config, runner):
        _revoke(config, runner, name=name)


def _revoke(config, runner, *, name):
    candidate = _CandidateRegistry(registry(config, runner).all())
    device = _find(candidate.all(), name)
    candidate.revoke(device.device_id)
    service.publish(config, runner, devices=candidate.all())


def export(config, runner, *, name, host=None, clock=now):
    device = _find(registry(config, runner).all(), name)
    if device.revoked_at is not None:
        raise ValueError("设备已吊销，不能导出配对文件")
    return _export(config, runner, _context(config, runner, host), device, clock)
