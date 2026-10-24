"""客户端配置采用 sing-box 1.13 格式，只使用两条隧道。"""

from .context import ProxyContext, ipv4_host, validate_context
from .registry import Device, validate_devices


def render_client_windows(ctx: ProxyContext, device: Device) -> dict:
    host = ipv4_host(ctx)
    validate_context(ctx)
    validate_devices([device])
    if device.revoked_at is not None:
        raise ValueError("设备已吊销，不能导出连接配置")
    hy2_tls = {"enabled": True, "server_name": ctx.hy2_server_name}
    if ctx.hy2_certificate:
        hy2_tls["certificate"] = list(ctx.hy2_certificate)
    backup = {
        "type": "hysteria2", "tag": "backup", "server": host,
        "server_port": ctx.hy2_port, "password": device.hy2_password,
    }
    if ctx.hy2_obfs_password:
        backup["obfs"] = {"type": "salamander", "password": ctx.hy2_obfs_password}
    backup["tls"] = hy2_tls
    return {
        "log": {"disabled": True},
        "dns": {
            "servers": [{
                "type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "proxy",
            }],
            "final": "dns-remote", "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            # 同时接入 IPv6，让拒绝规则处理，绝不转发。
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": True, "strict_route": True, "stack": "system",
        }],
        "outbounds": [
            {
                "type": "vless", "tag": "main", "server": host, "server_port": ctx.reality_port,
                "uuid": device.uuid, "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True, "server_name": ctx.sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True, "public_key": ctx.reality.public_key,
                        "short_id": ctx.reality.short_id,
                    },
                },
            },
            backup,
            {
                "type": "urltest", "tag": "proxy", "outbounds": ["main", "backup"],
                "url": ctx.urltest_url, "interval": ctx.urltest_interval,
                "tolerance": ctx.urltest_tolerance_ms,
            },
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {"action": "sniff"},
                {"ip_version": 6, "action": "reject"},
                {"protocol": "dns", "action": "hijack-dns"},
            ],
            "auto_detect_interface": True,
        },
    }
