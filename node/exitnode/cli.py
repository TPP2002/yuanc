"""面向维护人员的七个命令，所有主机副作用通过 Runner。"""

import argparse
import io
import json
import sys
import zipfile
from pathlib import PurePosixPath

from . import __version__, device, nft, service, systemd
from .config import ConfigError, load
from .log import redact
from .manifest import UNITS, Manifest
from .netinfo import check, public_ipv4
from .runner import RealRunner, RunnerError
from .status import State, evaluate
from .watchdog import check as watchdog_check
from .watchdog import state as watchdog_state
from .watchdog import summary as watchdog_summary
from .watchdog import tick as watchdog_tick


class ChineseParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, add_help=False, **kwargs)
        self.add_argument("-h", "--help", action="help", help="显示帮助并退出")
        self._positionals.title = "命令"
        self._optionals.title = "选项"

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "参数错误：请查看帮助，检查命令名称、必填参数及参数取值。\n")

    def format_usage(self):
        return super().format_usage().replace("usage:", "用法：")

    def format_help(self):
        return super().format_help().replace("usage:", "用法：")


def parser():
    root = ChineseParser(prog="exitnode", description="出口节点安装、检查与撤回工具")
    root.add_argument("--config", default="/etc/exitnode/config.toml", help="配置文件路径")
    root.add_argument("--placeholder", choices=["admin", "proxy"], help=argparse.SUPPRESS)
    sub = root.add_subparsers(dest="command", title="可用命令")
    descriptions = {"init": "安装基础组件", "check": "按层检查网络", "status": "查看运行状态",
                    "diagnose": "导出脱敏诊断包", "upgrade": "更新程序（尚未实现）",
                    "rollback": "撤回安装步骤", "uninstall": "卸载本项目组件"}
    for name, description in descriptions.items():
        command = sub.add_parser(name, help=description, description=description)
        command.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
        if name in {"check", "status"}:
            command.add_argument("--json", action="store_true", help="输出机器可读结果")
        if name == "diagnose":
            command.add_argument("--output", required=True, help="诊断压缩包保存路径")
        if name == "upgrade":
            command.add_argument("--version", help="目标版本")
        if name == "rollback":
            command.add_argument("--to-step", help="保留该步骤及之前的步骤")
        if name == "uninstall":
            command.add_argument("--purge", action="store_true", help="同时永久删除凭据目录")
    devices = sub.add_parser("device", help="管理自用设备与配对文件", description="管理自用设备与配对文件")
    devices.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    actions = devices.add_subparsers(dest="device_action", title="设备操作", required=True)
    for name, description in {"add": "添加设备并导出配对文件", "list": "列出设备（不含凭据）",
                              "revoke": "停用设备", "export": "重新导出配对文件"}.items():
        action = actions.add_parser(name, help=description, description=description)
        action.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
        if name == "list":
            action.add_argument("--json", action="store_true", help="输出机器可读结果")
        else:
            action.add_argument("--name", required=True, help="设备名字")
        if name in {"add", "export"}:
            action.add_argument("--host", help="节点公网 IPv4 地址；不填则自动获取")
        if name == "add":
            action.add_argument("--platform", choices=["windows", "android"], default="windows",
                                help="设备平台（默认 windows）")
    watcher = sub.add_parser("watchdog", help="运行或查看看门狗", description="运行或查看看门狗")
    watcher.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    actions = watcher.add_subparsers(dest="watchdog_action", required=True, title="看门狗操作")
    for name, description in (("tick", "执行一轮检查与恢复"), ("status", "读取最近检查记录")):
        action = actions.add_parser(name, help=description, description=description)
        action.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    return root


def _install(config, config_path, runner, manifest):
    successful = []

    def apply(step, action, undo):
        changed = manifest.apply(step, action, undo)
        successful.append(step + ("：已完成" if changed else "：已完成，跳过"))

    try:
        # 先做无命令的前置核对，缺内核时不得写入任何服务单元。
        if not runner.exists(config.proxy.binary):
            raise ValueError("未找到 sing-box，请先安装 sing-box 二进制并确认 proxy.binary 路径；不会自动下载")
        for name, directory in (("数据目录", config.node.data_dir),
                                ("凭据目录", config.node.secrets_dir)):
            # 数据与凭据在撤回时保留，卸载只清除清单管理的产物。
            apply(name, lambda p=directory: runner.mkdir(p),
                  {"kind": "remove_file", "path": directory, "preserve": True})
        for unit in sorted(UNITS - {service.UNIT}):
            path = "/etc/systemd/system/" + unit
            text = systemd.render(unit, {"config_path": config_path})
            step = "写入" + unit

            def write_unit(p=path, content=text, step_id=step):
                if runner.exists(p) and runner.read_file(p) != content:
                    raise ValueError("已有服务文件与安装内容不同，请先由维护人员确认")
                runner.write_file(p, content, 0o644)

            # 初次碰到已有文件时拒绝认领，避免撤回删除别人管理的文件。
            if runner.exists(path) and not any(s["step"] == step for s in manifest.steps):
                raise ValueError("已有同名服务文件未在本安装清单中，请联系维护人员")
            apply(step, write_unit, {"kind": "systemctl", "unit": unit})
        apply("重载服务定义", lambda: runner.run(["systemctl", "daemon-reload"]),
              {"kind": "systemctl", "unit": "exitnode-admin.service", "reload_only": True})
        apply("启用管理面", lambda: runner.run(["systemctl", "enable", "exitnode-admin.service"]),
              {"kind": "systemctl", "unit": "exitnode-admin.service"})
        if not any(s["step"] == "安装网络规则" for s in manifest.steps) and nft._exists(runner):
            raise ValueError("已有同名规则表未在本安装清单中，请联系维护人员")
        context = {"reality_port": config.proxy.reality_port, "hy2_port": config.proxy.hy2_port,
                   "admin_port": config.admin.port, "admin_bind": config.admin.bind}
        apply("安装网络规则", lambda: nft.apply(runner, context), {"kind": "nft"})
        apply("检查 sing-box 二进制", lambda: None,
              {"kind": "remove_file", "path": config.proxy.binary, "preserve": True})
        service.ensure_credentials(config, runner)
        manifest.steps = Manifest(manifest.path, runner).steps
        successful.append("生成隧道凭据：已完成")
        service.publish(config, runner)
        manifest.steps = Manifest(manifest.path, runner).steps
        successful.append("渲染隧道配置：已完成")
        path = "/etc/systemd/system/" + service.UNIT
        step = "写入" + service.UNIT
        if runner.exists(path) and not any(s["step"] == step for s in manifest.steps):
            raise ValueError("已有同名服务文件未在本安装清单中，请联系维护人员")
        text = systemd.render(service.UNIT, {"config_path": config_path}, binary=config.proxy.binary)

        def write_proxy():
            if runner.exists(path) and runner.read_file(path) != text:
                raise ValueError("已有服务文件与安装内容不同，请先由维护人员确认")
            runner.write_file(path, text, 0o644)

        apply(step, write_proxy, {"kind": "systemctl", "unit": service.UNIT})
        apply("重载隧道服务定义", lambda: runner.run(["systemctl", "daemon-reload"]),
              {"kind": "systemctl", "unit": service.UNIT, "reload_only": True})
        apply("启用隧道服务",
              lambda: runner.run(["systemctl", "enable", "--now", service.UNIT]),
              {"kind": "systemctl", "unit": service.UNIT})
        if config.watchdog.enabled:
            apply("启用看门狗定时器",
                  lambda: runner.run(["systemctl", "enable", "--now", "exitnode-watchdog.timer"]),
                  {"kind": "systemctl", "unit": "exitnode-watchdog.timer"})
        if config.watchdog.hardware:
            if runner.exists("/dev/watchdog"):
                hardware_path = "/etc/systemd/system.conf.d/exitnode-watchdog.conf"
                if (runner.exists(hardware_path)
                        and not any(s["step"] == "硬件看门狗" for s in manifest.steps)):
                    raise ValueError("已有硬件看门狗文件未在本安装清单中，请联系维护人员")

                def hardware():
                    runner.mkdir("/etc/systemd/system.conf.d", 0o755)
                    runner.write_file(hardware_path,
                                      "[Manager]\nRuntimeWatchdogSec=60\nRebootWatchdogSec=10min\n",
                                      0o644)
                    runner.run(["systemctl", "daemon-reexec"])

                apply("硬件看门狗", hardware,
                      {"kind": "remove_file", "path": hardware_path, "daemon_reexec": True})
            else:
                successful.append("硬件看门狗：设备不存在，跳过")
        if not device.registry(config, runner).all():
            device.add(config, runner, name="第一台电脑")
            print("请把这个文件拷到 U 盘带去电脑")
    except (OSError, RuntimeError, ValueError) as exc:
        print("成功项：" + ("；".join(successful) or "无"))
        print("失败项：" + redact(str(exc)))
        print("下一步：排除问题后重新安装以续跑，或使用撤回命令。")
        return 1
    print("成功项：" + "；".join(successful))
    print("失败项：无。隧道配置已校验，服务已启用；请用 check 检查当前运行状态。"
          "请导入配对文件后检查外网实际连接。")
    return 0


def _diagnose(runner, config, result, output):
    log_path = config.node.data_dir.rstrip("/") + "/logs/exitnode.log"
    tail = "暂无日志"
    if runner.exists(log_path):
        tail = "\n".join(runner.read_file(log_path).splitlines()[-100:])
    payload = {"version": __version__, "check": result, "config": config.sanitized()}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("诊断.json", redact(json.dumps(payload, ensure_ascii=False, indent=2)))
        archive.writestr("最近日志.txt", redact(tail))
    runner.write_bytes(output, stream.getvalue(), 0o600)
    print("诊断包已保存，凭据已打码；分享前请再次检查其中的网络和设备信息。")


def main(argv=None, runner=None):
    args = parser().parse_args(argv)
    if args.placeholder:
        print("服务尚未接入，此入口仅为安装占位。", file=sys.stderr)
        return 2
    if not args.command:
        parser().print_help()
        return 0
    if args.command == "upgrade":
        print("未实现，见卡 UPDATER", file=sys.stderr)
        return 2
    try:
        runner = runner if runner is not None else RealRunner()
        config = load(args.config, runner)
        if args.command == "watchdog":
            if args.watchdog_action == "tick":
                return watchdog_tick(config, runner)
            print(redact(json.dumps(watchdog_state.read(config, runner), ensure_ascii=False)))
            return 0
        if args.command == "device":
            if args.device_action == "add":
                device.add(config, runner, name=args.name, platform=args.platform, host=args.host)
            elif args.device_action == "export":
                device.export(config, runner, name=args.name, host=args.host)
            elif args.device_action == "revoke":
                device.revoke(config, runner, name=args.name)
                print("设备已停用，服务配置已更新。")
            else:
                rows = device.list_devices(config, runner)
                if args.json:
                    print(redact(json.dumps(rows, ensure_ascii=False)))
                else:
                    for row in rows:
                        print(redact(f"{row['name']} | {row['platform']} | {row['created_at']} | "
                                     + ("已吊销" if row["revoked_at"] else "未吊销")))
            return 0
        if args.command in {"check", "status", "diagnose"}:
            result = check(runner, config)
            if args.command == "check":
                result["layers"].insert(-1, watchdog_check(config, runner))
            if args.command == "status":
                result["public_ipv4"] = public_ipv4(runner)
                try:
                    result["watchdog"] = watchdog_summary(config, runner)
                except ValueError:
                    result["watchdog"] = {"state": "manual", "last_ok_at": None,
                                          "consecutive_failures": 0, "last_action": None,
                                          "reason": "看门狗记录损坏，请联系维护人员"}
            status = evaluate(result)
            if args.command == "check":
                if args.json:
                    print(json.dumps(result, ensure_ascii=False))
                else:
                    for layer in result["layers"]:
                        print(f"{layer['name']}：{layer['result']}；{layer['reason']}")
            elif args.command == "status":
                if args.json:
                    print(status.to_json())
                else:
                    labels = {State.NORMAL: "正常", State.RECONNECTING: "重连中",
                              State.REAUTH: "需重新授权", State.MANUAL: "需人工处理"}
                    print(labels[status.state] + "：" + status.reason)
                    print("公网 IPv4：" + (status.public_ipv4 or "未取得"))
            else:
                _diagnose(runner, config, result, args.output)
                return 0
            return 0 if status.state == State.NORMAL else 1
        manifest_path = str(PurePosixPath(config.node.data_dir) / "manifest.json")
        manifest = Manifest(manifest_path, runner)
        if args.command == "init":
            return _install(config, args.config, runner, manifest)
        summary = manifest.rollback(getattr(args, "to_step", None))
        if args.command == "uninstall" and not summary["failed"]:
            if args.purge:
                runner.purge_secrets()
            runner.remove(manifest_path)
            # 保留仍含凭据、日志或其他用户数据的目录。
            try:
                runner.remove(config.node.data_dir)
            except OSError:
                print("数据目录中仍有保留内容，未删除该目录。")
        print(json.dumps(summary, ensure_ascii=False))
        if args.command == "uninstall" and not args.purge:
            print("凭据已保留；只有明确使用清除凭据选项才会删除。")
        return 1 if summary["failed"] else 0
    except (ConfigError, RunnerError, OSError, ValueError) as exc:
        print("操作失败：" + redact(str(exc)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
