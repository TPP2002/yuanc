"""面向维护人员的七个命令，所有主机副作用通过 Runner。"""

import argparse
import io
import json
import sys
import zipfile
from pathlib import PurePosixPath

from . import __version__, nft, systemd
from .config import ConfigError, load
from .log import redact
from .manifest import UNITS, Manifest
from .netinfo import check
from .runner import RealRunner, RunnerError
from .status import State, evaluate


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
    return root


def _install(config, config_path, runner, manifest):
    successful = []

    def apply(step, action, undo):
        changed = manifest.apply(step, action, undo)
        successful.append(step + ("：已完成" if changed else "：已完成，跳过"))

    try:
        for name, directory in (("数据目录", config.node.data_dir),
                                ("凭据目录", config.node.secrets_dir)):
            # 数据与凭据在撤回时保留，卸载只清除清单管理的产物。
            apply(name, lambda p=directory: runner.mkdir(p),
                  {"kind": "remove_file", "path": directory, "preserve": True})
        for unit in sorted(UNITS):
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
    except (OSError, RuntimeError, ValueError) as exc:
        print("成功项：" + ("；".join(successful) or "无"))
        print("失败项：" + redact(str(exc)))
        print("下一步：排除问题后重新安装以续跑，或使用撤回命令。")
        return 1
    print("成功项：" + "；".join(successful))
    print("失败项：无。下一步：接入管理与代理实现后再验真实出口；当前仅安装基础组件。")
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
        if args.command in {"check", "status", "diagnose"}:
            result = check(runner, config)
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
