"""Explicit render inputs; this module does not resolve names or fetch credentials."""

import ipaddress
import re
from dataclasses import dataclass, field

from .keys import RealityKeys

HY2_OBFS_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}")
HY2_OBFS_ERROR = "备用通道混淆密码格式不正确"


def valid_hy2_obfs_password(value) -> bool:
    return isinstance(value, str) and HY2_OBFS_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True)
class ProxyContext:
    reality: RealityKeys = field(repr=False)
    server_host: str = ""
    reality_port: int = 443
    # Configurable camouflage target; operator may select an Australian local site.
    sni: str = "www.microsoft.com"
    handshake_server: str = "www.microsoft.com"
    hy2_port: int = 24443
    hy2_server_name: str = "exitnode"
    hy2_certificate_path: str = "/var/lib/exitnode/secrets/hy2.crt"
    hy2_key_path: str = "/var/lib/exitnode/secrets/hy2.key"
    # A self-signed certificate can be explicitly trusted by the client here.
    hy2_certificate: tuple[str, ...] = ()
    # Node-level salamander obfuscation password; empty string disables obfuscation.
    hy2_obfs_password: str = field(default="", repr=False)
    masquerade: str = ""
    urltest_url: str = "https://www.gstatic.com/generate_204"
    urltest_interval: str = "1m"
    # 主线路不比备用线路慢超过此毫秒数就不切换,避免长期走备用 UDP 线路。
    urltest_tolerance_ms: int = 300
    admin_bind: str = "127.0.0.1"
    admin_port: int = 8443
    maintenance_device_ids: tuple[str, ...] = ()


def ipv4_host(ctx: ProxyContext) -> str:
    message = "连接地址必须是 IPv4 数字地址,由鉴权服务器下发"
    try:
        address = ipaddress.ip_address(ctx.server_host)
    except (ValueError, TypeError):
        raise ValueError(message) from None
    # Require the canonical textual address, rejecting integer/bytes inputs too.
    if address.version != 4 or str(address) != ctx.server_host:
        raise ValueError(message)
    return str(address)


def validate_context(ctx: ProxyContext) -> None:
    seen = set()
    for device_id in ctx.maintenance_device_ids:
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("维护设备编号必须为非空字符串")
        if device_id in seen:
            raise ValueError("维护设备编号不能重复")
        seen.add(device_id)
    if isinstance(ctx.hy2_port, bool) or not isinstance(ctx.hy2_port, int):
        raise TypeError("备用通道端口无效")
    if not 1 <= ctx.hy2_port <= 65535:
        raise ValueError("备用通道端口无效")
    if not ctx.sni or not ctx.handshake_server or not ctx.hy2_server_name:
        raise ValueError("证书名称与伪装目标不能为空")
    if ctx.sni != ctx.handshake_server:
        raise ValueError("伪装目标与握手名称必须相同")
    if type(ctx.urltest_tolerance_ms) is not int or not 0 <= ctx.urltest_tolerance_ms <= 10000:
        raise ValueError("线路选择容差须为 0 至 10000 毫秒的整数")
    if ctx.hy2_obfs_password != "" and not valid_hy2_obfs_password(ctx.hy2_obfs_password):
        raise ValueError(HY2_OBFS_ERROR)
