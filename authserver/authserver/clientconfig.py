# TODO(PROXY-CONFIG-1023): 后续统一卡将此渲染器与节点侧配置生成合并到一处。
"""仅渲染客户端配置；不导入并行施工的 node 包。"""


def render(node_ctx, device) -> dict:
    reality_tls = {
        "enabled": True,
        "server_name": node_ctx["sni"],
        "utls": {"enabled": True, "fingerprint": "chrome"},
        "reality": {"enabled": True, "public_key": node_ctx["reality_public_key"],
                    "short_id": node_ctx["short_id"]},
    }
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [{"tag": "remote", "address": "tls://1.1.1.1", "detour": "urltest"}],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": "exitnode-tun",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": True, "strict_route": True, "stack": "mixed", "sniff": True,
        }],
        "outbounds": [
            {"type": "vless", "tag": "main", "server": node_ctx["host"],
             "server_port": node_ctx["reality_port"], "uuid": device["uuid"],
             "flow": "xtls-rprx-vision", "tls": reality_tls},
            {"type": "hysteria2", "tag": "backup", "server": node_ctx["host"],
             "server_port": node_ctx["hy2_port"], "password": device["hy2_password"],
             "tls": {"enabled": True, "server_name": node_ctx["sni"]}},
            {"type": "urltest", "tag": "urltest", "outbounds": ["main", "backup"],
             "url": "https://www.gstatic.com/generate_204", "interval": "1m",
             "tolerance": 50},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [{"ip_version": 6, "outbound": "block"},
                      {"protocol": "dns", "outbound": "dns-out"},
                      {"port": 53, "outbound": "dns-out"}],
            "final": "urltest",
        },
    }
