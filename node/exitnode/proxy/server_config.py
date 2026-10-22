"""Server configuration in the official sing-box 1.10 JSON format."""

from .context import ProxyContext, validate_context
from .registry import Device, validate_devices
from .runner_proto import secret_path


def render_server(ctx: ProxyContext, devices: list[Device]) -> dict:
    validate_context(ctx)
    validate_devices(devices)
    secret_path(ctx.hy2_key_path)
    active = sorted((d for d in devices if d.revoked_at is None), key=lambda d: d.device_id)
    maintenance = [d.device_id for d in active if d.device_id in ctx.maintenance_device_ids]
    rules = [{"ip_cidr": ["198.18.255.1/32"], "outbound": "admin-local"}]
    if maintenance:
        rules.append({"auth_user": maintenance, "ip_is_private": True,
                      "port": [22], "outbound": "direct"})
    rules.extend([
        {"ip_is_private": True, "outbound": "block"},
        {"ip_cidr": ["198.18.0.0/15"], "outbound": "block"},
    ])
    hy2 = {
        "type": "hysteria2", "tag": "in-hy2", "listen": "::", "listen_port": ctx.hy2_port,
        "users": [{"name": d.device_id, "password": d.hy2_password} for d in active],
    }
    if ctx.hy2_obfs_password:
        hy2["obfs"] = {"type": "salamander", "password": ctx.hy2_obfs_password}
    hy2["tls"] = {
        "enabled": True, "server_name": ctx.hy2_server_name,
        "certificate_path": ctx.hy2_certificate_path, "key_path": ctx.hy2_key_path,
    }
    if ctx.masquerade:
        hy2["masquerade"] = ctx.masquerade
    return {
        "log": {"disabled": True},
        "dns": {"servers": [{"tag": "upstream", "address": "1.1.1.1"}], "final": "upstream"},
        "inbounds": [
            {
                "type": "vless", "tag": "in-reality", "listen": "::",
                "listen_port": ctx.reality_port,
                "users": [{"name": d.device_id, "uuid": d.uuid, "flow": "xtls-rprx-vision"}
                          for d in active],
                "tls": {
                    "enabled": True, "server_name": ctx.sni,
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": ctx.handshake_server, "server_port": 443},
                        "private_key": ctx.reality.private_key,
                        "short_id": [ctx.reality.short_id],
                    },
                },
            },
            hy2,
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"},
            {"type": "direct", "tag": "admin-local", "override_address": ctx.admin_bind,
             "override_port": ctx.admin_port},
        ],
        "route": {"rules": rules, "final": "direct"},
    }
