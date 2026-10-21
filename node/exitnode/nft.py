"""只操作固定名称的自管表，不改变其他表或全局防火墙策略。"""

import ipaddress
import json
from uuid import uuid4


def render_ruleset(ctx):
    ports = {key: ctx[key] for key in ("reality_port", "hy2_port", "admin_port")}
    if any(type(p) is not int or not 1 <= p <= 65535 for p in ports.values()):
        raise ValueError("规则端口须为 1 至 65535 的整数")
    bind = ipaddress.ip_address(ctx.get("admin_bind", "127.0.0.1"))
    family = "ip6" if bind.version == 6 else "ip"
    return (
        "# 仅维护本项目规则；管理入口限配置的监听地址。\n"
        "table inet exitnode {\n"
        "    chain input {\n"
        "        type filter hook input priority 0; policy accept;\n"
        f"        tcp dport {ports['reality_port']} accept\n"
        f"        udp dport {ports['hy2_port']} accept\n"
        f"        {family} daddr {bind} tcp dport {ports['admin_port']} accept\n"
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority 0; policy accept;\n"
        "        # 出口转发规则由后续代理接入卡提供，当前不扩大转发权限。\n"
        "    }\n"
        "    chain postrouting {\n"
        "        type nat hook postrouting priority 100; policy accept;\n"
        "        # 待确定隧道源地址后添加受限 masquerade 规则。\n"
        "    }\n"
        "}\n"
    )


def _exists(runner):
    # list tables 成功而列表不含本表才算不存在；权限错误不可当不存在。
    result = runner.run(["nft", "-j", "list", "tables"])
    try:
        items = json.loads(result.out)["nftables"]
        return any(item.get("table", {}).get("family") == "inet"
                   and item["table"].get("name") == "exitnode" for item in items)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("无法解析本机规则表列表") from exc


def apply(runner, ctx=None):
    ctx = ctx or {"reality_port": 443, "hy2_port": 24443, "admin_port": 8443}
    text = render_ruleset(ctx)
    if _exists(runner):
        # 同一个批次原子提交：重复安装不会累加规则。
        text = "delete table inet exitnode\n" + text
    path = f"/run/exitnode-{uuid4().hex}.nft"
    runner.write_file(path, text, 0o600)
    try:
        runner.run(["nft", "-f", path])
    finally:
        runner.remove(path)


def remove(runner):
    if _exists(runner):
        runner.run(["nft", "delete", "table", "inet", "exitnode"])
