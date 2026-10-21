"""Android VPN profile and an explicitly credential-bearing VLESS share link."""

from urllib.parse import quote, urlencode

from .client_config import render_client_windows
from .context import ProxyContext
from .registry import Device


def render_android_subscription(ctx: ProxyContext, device: Device) -> dict:
    # SFA provides the VPN interface. No app exclusions or HTTP proxy bypasses.
    config = render_client_windows(ctx, device)
    config["inbounds"][0]["platform"] = {"http_proxy": {"enabled": False}}
    return config


def vless_link(ctx: ProxyContext, device: Device) -> str:
    config = render_client_windows(ctx, device)
    main = config["outbounds"][0]
    params = urlencode({
        "encryption": "none", "security": "reality", "type": "tcp",
        "flow": "xtls-rprx-vision", "sni": ctx.sni, "fp": "chrome",
        "pbk": ctx.reality.public_key, "sid": ctx.reality.short_id,
    })
    return (
        f"vless://{device.uuid}@{main['server']}:{ctx.reality_port}?{params}"
        f"#{quote(device.name, safe='')}"
    )
