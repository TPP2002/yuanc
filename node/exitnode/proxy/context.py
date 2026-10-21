"""Explicit render inputs; this module does not resolve names or fetch credentials."""

import ipaddress
from dataclasses import dataclass, field

from .keys import RealityKeys


@dataclass(frozen=True)
class ProxyContext:
    reality: RealityKeys = field(repr=False)
    server_host: str = ""
    # Configurable camouflage target; operator may select an Australian local site.
    sni: str = "www.microsoft.com"
    handshake_server: str = "www.microsoft.com"
    hy2_port: int = 24443
    hy2_server_name: str = "exitnode"
    hy2_certificate_path: str = "/var/lib/exitnode/secrets/hy2.crt"
    hy2_key_path: str = "/var/lib/exitnode/secrets/hy2.key"
    # A self-signed certificate can be explicitly trusted by the client here.
    hy2_certificate: tuple[str, ...] = ()
    masquerade: str = ""
    urltest_url: str = "https://www.gstatic.com/generate_204"
    urltest_interval: str = "1m"


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
    if isinstance(ctx.hy2_port, bool) or not isinstance(ctx.hy2_port, int):
        raise TypeError("备用通道端口无效")
    if not 1 <= ctx.hy2_port <= 65535:
        raise ValueError("备用通道端口无效")
    if not ctx.sni or not ctx.handshake_server or not ctx.hy2_server_name:
        raise ValueError("证书名称与伪装目标不能为空")
