"""Client settings: only two tunnels, no direct outbound or local DNS."""

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
    return {
        "log": {"disabled": True},
        "dns": {
            "servers": [{
                "tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy",
            }],
            "rules": [{"outbound": "any", "server": "dns-remote"}],
            "final": "dns-remote", "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            # Capture IPv6 too so the block rule can see it; never forward it.
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": True, "strict_route": True, "stack": "system", "sniff": True,
        }],
        "outbounds": [
            {
                "type": "vless", "tag": "main", "server": host, "server_port": 443,
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
            {
                "type": "hysteria2", "tag": "backup", "server": host,
                "server_port": ctx.hy2_port, "password": device.hy2_password, "tls": hy2_tls,
            },
            {
                "type": "urltest", "tag": "proxy", "outbounds": ["main", "backup"],
                "url": ctx.urltest_url, "interval": ctx.urltest_interval,
            },
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {"ip_version": 6, "outbound": "block"},
                {"protocol": "dns", "outbound": "dns-out"},
            ],
            "auto_detect_interface": True,
        },
    }
