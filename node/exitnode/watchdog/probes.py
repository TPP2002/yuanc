"""逐层检查，不将系统输出或凭据带入原因文案。"""

from .. import netinfo
from ..netinfo import listen_state
from ..service import LIVE


def row(layer, name, result, reason):
    return {"layer": layer, "name": name, "result": result, "reason": reason}


_listen = listen_state


def probe(config, runner):
    _, ok, reason = netinfo.read_network(runner, config.network.iface)
    rows = [row("L-link", "网卡与默认路由", "通过" if ok else "失败", reason)]
    upstream = netinfo.probe_upstream(runner, config.network.probe_targets)["ok"]
    rows.append(row("L-upstream", "上游连接", "通过" if upstream else "失败",
                    "外网连接可用" if upstream else "无法连接外网，请检查路由器或宽带"))
    try:
        active = runner.run(["systemctl", "is-active", "exitnode-proxy.service"], check=False)
        valid = runner.run([config.proxy.binary, "check", "-c", LIVE], check=False)
        ok = active.code == 0 and active.out.strip() == "active" and valid.code == 0
    except (OSError, RuntimeError):
        ok = False
    rows.append(row("L-proxy", "隧道服务", "通过" if ok else "失败",
                    "服务运行且配置可用" if ok else "隧道服务未运行或配置不能使用"))
    results = [_listen(runner, ["ss", "-ltnH"], config.proxy.reality_port),
               _listen(runner, ["ss", "-lunH"], config.proxy.hy2_port)]
    result = "失败" if "失败" in results else "未知" if "未知" in results else "通过"
    rows.append(row("L-listen", "本机连接入口", result,
                    {"失败": "本机连接入口没有打开", "未知": "无法读取监听信息，暂不据此判故障",
                     "通过": "两个本机入口均已打开"}[result]))
    if all(item["result"] != "失败" for item in rows):
        address = netinfo.public_ipv4(runner)
        rows.append(row("L-public", "公网地址", "通过" if address else "失败",
                        "已取得公网地址" if address else "暂时无法取得公网地址，等待外网恢复"))
    else:
        rows.append(row("L-public", "公网地址", "跳过", "前面的检查未通过，暂不检查公网地址"))
    return rows
