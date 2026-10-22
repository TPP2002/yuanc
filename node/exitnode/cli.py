"""面向维护人员的七个命令，所有主机副作用通过 Runner。"""

import argparse
import io
import ipaddress
import json
import subprocess
import sys
import zipfile
from pathlib import PurePosixPath

from . import __version__, device, nft, service, systemd
from .admin import publish as winclient_publish
from .admin import server as admin_server
from .config import ConfigError, load
from .log import redact
from .manifest import UNITS, Manifest
from .netinfo import check, public_ipv4
from .rescue import probes as rescue_probes
from .rescue import state as rescue_state
from .rescue.runner import RealRunner as RescueRealRunner
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
                    "diagnose": "导出脱敏诊断包", "upgrade": "检查并安全更新程序",
                    "rollback": "撤回安装步骤", "uninstall": "卸载本项目组件"}
    for name, description in descriptions.items():
        command = sub.add_parser(name, help=description, description=description)
        command.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
        if name in {"check", "status"}:
            command.add_argument("--json", action="store_true", help="输出机器可读结果")
        if name == "diagnose":
            command.add_argument("--output", required=True, help="诊断压缩包保存路径")
        if name == "upgrade":
            command.add_argument("--version", help=argparse.SUPPRESS)
            command.add_argument("--file", help="本地升级包路径")
            command.add_argument("--signature", help="签名路径，默认升级包路径加 .sig")
            command.add_argument("--check", action="store_true", help="只检查升级包，不安装")
            command.add_argument("--allow-downgrade", action="store_true",
                                 help="允许安装比当前版本或已安装过的最高版本更低的版本")
            command.add_argument("--switch", metavar="版本",
                                 help="切换到已安装且未标记失败的版本，不下载升级包")
            command.add_argument("--recover", action="store_true",
                                 help="只收尾上次未完成的更新，不检查网络、不下载")
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
    rescue = sub.add_parser("rescue", help="查看或维护独立救援程序")
    rescue.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    actions = rescue.add_subparsers(dest="rescue_action", required=True, title="救援操作")
    for name, description in (("status", "查看最近救援记录"), ("refresh", "手动更新救援程序")):
        action = actions.add_parser(name, help=description)
        action.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    packages = sub.add_parser("winclient", help="托管 Windows 客户端包")
    packages.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    actions = packages.add_subparsers(dest="winclient_action", required=True)
    upload = actions.add_parser("publish", help="发布客户端包")
    upload.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    for name in ("exe", "manifest", "signature"):
        upload.add_argument("--" + name, required=True, help="待发布文件路径")
    upload.add_argument("--allow-downgrade", action="store_true", help="允许发布旧版本")
    status = actions.add_parser("status", help="查看已托管版本")
    status.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    admin = sub.add_parser("admin", help="客户端包托管服务")
    admin.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    actions = admin.add_subparsers(dest="admin_action", required=True)
    foreground = actions.add_parser("serve", help="前台运行只读托管服务")
    foreground.add_argument("--config", default=argparse.SUPPRESS, help="配置文件路径")
    return root


def refresh(source_dir, target_dir, rescue_runner=None):
    """显式更新独立副本；主程序 Runner 不参与目录交换。"""
    runner = rescue_runner if rescue_runner is not None else RescueRealRunner()
    expected = rescue_probes.hashes(runner, source_dir)
    if not {"__init__.py", "__main__.py", "runner.py", "state.py", "probes.py", "actions.py"} <= expected.keys():
        raise ValueError("救援源码不完整，未更新")
    staging = target_dir + ".staging"
    runner.remove_tree(staging)
    runner.copy_tree(source_dir, staging)
    if rescue_probes.hashes(runner, staging) != expected:
        raise ValueError("救援副本校验失败，未更新")
    # 暂存目录尚未改名，用显式包搜索路径导入，不能误查已安装的旧副本。
    code = ("import importlib.util,sys; "
            "p=sys.argv[1]; "
            "s=importlib.util.spec_from_file_location('exitnode_rescue',p+'/__init__.py',"
            "submodule_search_locations=[p]); "
            "m=importlib.util.module_from_spec(s); sys.modules['exitnode_rescue']=m; "
            "s.loader.exec_module(m); import exitnode_rescue.__main__")
    try:
        import_result = runner.run(["python3", "-P", "-c", code, staging], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("救援副本导入失败或超时，未更新") from None
    if import_result.code:
        raise ValueError("救援副本不能导入，未更新")
    if rescue_probes.hashes(runner, staging) != expected:
        raise ValueError("救援副本导入后内容变化，未更新")
    try:
        runner.replace(staging, target_dir)
    except OSError:
        value = rescue_state.read(runner)
        value.update(state="manual", reason="救援代码替换失败，请人工检查残留目录")
        try:
            rescue_state.save(runner, value)
            rescue_state.history(runner, "refresh", "failed")
        except OSError:
            pass  # 磁盘不可写时不能保证记录成功，仍将原异常交给调用方。
        raise


def _rescue_record(runner):
    if not runner.exists(rescue_state.STATE):
        return {"state": "manual", "reason": "尚无救援记录", "updated_at": None}
    try:
        value = json.loads(runner.read_file(rescue_state.STATE))
        if value["state"] not in {"normal", "processing", "manual"}:
            raise ValueError
        rescue_state.timestamp(value["updated_at"])
        return {"state": value["state"], "reason": str(value["reason"]),
                "updated_at": value["updated_at"]}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {"state": "manual", "reason": "救援记录损坏", "updated_at": None}


def _rescue_check(runner):
    value = _rescue_record(runner)
    active = runner.run(["systemctl", "is-active", "exitnode-rescue.timer"], check=False)
    recent = (value["updated_at"] is not None
              and 0 <= runner.now() - rescue_state.timestamp(value["updated_at"]) <= 86400)
    ok = active.code == 0 and active.out.strip() == "active" and recent
    return {"layer": "rescue", "name": "救援单元", "result": "通过" if ok else "失败",
            "reason": "定时器运行且最近一天有检查记录" if ok else "救援定时器未运行或记录已过期"}


def _install(config, config_path, runner, manifest):
    successful = []

    def apply(step, action, undo):
        changed = manifest.apply(step, action, undo)
        successful.append(step + ("：已完成" if changed else "：已完成，跳过"))
        return changed

    try:
        from .updater import layout

        layout.repair(config, runner)
        program_path = layout.root(config) + "/current"
        # 先做无命令的前置核对，缺内核时不得写入任何服务单元。
        if not any(runner.exists(path) for path in (program_path + "/bin/sing-box",
                   config.proxy.binary, "/usr/bin/sing-box", "/usr/local/bin/sing-box")):
            raise ValueError("未找到 sing-box，请先安装 sing-box 内核；不会自动下载")
        # 托管服务以动态账户运行、没有任何能力，只能监听高端口并只收本机连接。
        if config.admin.port < 1024:
            raise ValueError("托管服务已降权运行，admin.port 须不小于 1024")
        if not ipaddress.ip_address(config.admin.bind).is_loopback:
            raise ValueError("托管服务只允许监听回环地址(IPAddressAllow=localhost 只放本机连接)")
        for name, directory in (("数据目录", config.node.data_dir),
                                ("凭据目录", config.node.secrets_dir)):
            # 数据与凭据在撤回时保留，卸载只清除清单管理的产物。
            apply(name, lambda p=directory: runner.mkdir(p),
                  {"kind": "remove_file", "path": directory, "preserve": True})

        def create_account():
            if runner.run(["getent", "passwd", service.SERVICE_USER], check=False).code:
                runner.run(["useradd", "--system", "--no-create-home",
                            "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
                            "--user-group", service.SERVICE_USER])

        apply("创建服务账户", create_account, {"kind": "user", "name": service.SERVICE_USER})
        # 配置文件按设计不含凭据(凭据只在 secrets 目录)，托管服务以动态账户读取它。
        apply("配置文件权限", lambda: runner.chmod(config_path, 0o644),
              {"kind": "remove_file", "path": config_path, "preserve": True})
        if not apply("安装程序目录", lambda: layout.bootstrap(config, runner),
                     {"kind": "remove_file", "path": layout.releases(config), "preserve": True}):
            layout.bootstrap(config, runner)
        rescue_units = {"exitnode-rescue.service", "exitnode-rescue.timer"}
        recover_unit = "exitnode-recover.service"
        # 收尾单元排在隧道服务单元之后单独写入。
        for unit in sorted(UNITS - {service.UNIT, recover_unit} - rescue_units):
            path = "/etc/systemd/system/" + unit
            text = systemd.render(unit, {"config_path": config_path, "program_path": program_path})
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
        # 规则已由上一步加载，只设开机重新加载，不加 --now。
        apply("启用防火墙规则单元",
              lambda: runner.run(["systemctl", "enable", "exitnode-nft.service"]),
              {"kind": "systemctl", "unit": "exitnode-nft.service"})
        apply("检查 sing-box 二进制", lambda: None,
              {"kind": "remove_file", "path": config.proxy.binary, "preserve": True})
        service.ensure_credentials(config, runner)
        manifest.steps = Manifest(manifest.path, runner).steps
        successful.append("生成隧道凭据：已完成")
        service.publish(config, runner)
        manifest.steps = Manifest(manifest.path, runner).steps
        successful.append("渲染隧道配置：已完成")
        # 老节点再跑 init 时这一步把旧的 0600 修成新权限。
        apply("设置凭据文件权限", lambda: service.apply_permissions(runner),
              {"kind": "remove_file", "path": service.SECRETS, "preserve": True})
        path = "/etc/systemd/system/" + service.UNIT
        step = "写入" + service.UNIT
        if runner.exists(path) and not any(s["step"] == step for s in manifest.steps):
            raise ValueError("已有同名服务文件未在本安装清单中，请联系维护人员")
        text = systemd.render(service.UNIT,
                              {"config_path": config_path, "program_path": program_path},
                              binary=config.proxy.binary)

        def write_proxy():
            if runner.exists(path) and runner.read_file(path) != text:
                raise ValueError("已有服务文件与安装内容不同，请先由维护人员确认")
            runner.write_file(path, text, 0o644)

        apply(step, write_proxy, {"kind": "systemctl", "unit": service.UNIT})
        recover_path = "/etc/systemd/system/" + recover_unit
        recover_step = "写入exitnode-recover.service"
        if runner.exists(recover_path) and not any(s["step"] == recover_step
                                                   for s in manifest.steps):
            raise ValueError("已有同名服务文件未在本安装清单中，请联系维护人员")
        recover_text = systemd.render(recover_unit,
                                      {"config_path": config_path, "program_path": program_path})

        def write_recover():
            if runner.exists(recover_path) and runner.read_file(recover_path) != recover_text:
                raise ValueError("已有服务文件与安装内容不同，请先由维护人员确认")
            runner.write_file(recover_path, recover_text, 0o644)

        apply(recover_step, write_recover, {"kind": "systemctl", "unit": recover_unit})
        apply("重载隧道服务定义", lambda: runner.run(["systemctl", "daemon-reload"]),
              {"kind": "systemctl", "unit": service.UNIT, "reload_only": True})
        apply("启用隧道服务",
              lambda: runner.run(["systemctl", "enable", "--now", service.UNIT]),
              {"kind": "systemctl", "unit": service.UNIT})
        # 只在开机时运行收尾，不加 --now。
        apply("启用更新收尾服务",
              lambda: runner.run(["systemctl", "enable", recover_unit]),
              {"kind": "systemctl", "unit": recover_unit})
        if config.watchdog.enabled:
            apply("启用看门狗定时器",
                  lambda: runner.run(["systemctl", "enable", "--now", "exitnode-watchdog.timer"]),
                  {"kind": "systemctl", "unit": "exitnode-watchdog.timer"})

        def install_rescue():
            current = layout.current_target(config, runner)
            if not layout.valid_release(runner, current):
                raise ValueError("当前程序校验失败，未安装救援包")
            source = current + "/exitnode/rescue"
            if not runner.exists(source + "/__main__.py"):
                raise ValueError("救援源码不完整")
            runner.mkdir(rescue_probes.RESCUE, 0o755)
            for src, dst in ((source, rescue_probes.RESCUE + "/exitnode_rescue"),
                             (current, rescue_probes.FACTORY)):
                if runner.exists(dst):
                    if layout.hashes(runner, src) != layout.hashes(runner, dst):
                        raise ValueError("已有救援包内容不同，请维护人员确认；更新代码请用 rescue refresh")
                else:
                    runner.copy_tree(src, dst)
            for unit in sorted(rescue_units):
                path = "/etc/systemd/system/" + unit
                text = systemd.render(unit, {"config_path": config_path, "program_path": program_path})

                def write_rescue_unit(p=path, content=text):
                    if runner.exists(p):
                        if runner.read_file(p) != content:
                            raise ValueError("已有救援服务文件内容不同，请维护人员确认")
                        return
                    runner.write_file(p, content, 0o644)

                apply("写入" + unit, write_rescue_unit, {"kind": "systemctl", "unit": unit})
            runner.run(["systemctl", "daemon-reload"])

        apply("安装救援单元", install_rescue,
              {"kind": "remove_file", "path": rescue_probes.RESCUE, "preserve": True})
        apply("启用救援定时器",
              lambda: runner.run(["systemctl", "enable", "--now", "exitnode-rescue.timer"]),
              {"kind": "systemctl", "unit": "exitnode-rescue.timer"})
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


def main(argv=None, runner=None, rescue_runner=None):
    args = parser().parse_args(argv)
    if args.placeholder == "proxy":
        print("服务尚未接入，此入口仅为安装占位。", file=sys.stderr)
        return 2
    if args.placeholder == "admin":
        args.command, args.admin_action = "admin", "serve"
    if not args.command:
        parser().print_help()
        return 0
    if args.command == "upgrade" and args.version:
        print("按版本号选择未实现，请使用 --file 或配置发布来源。", file=sys.stderr)
        return 2
    if args.command == "upgrade" and args.switch is not None and (args.file or args.signature):
        print("--switch 不能与 --file 或 --signature 同时使用", file=sys.stderr)
        return 2
    if args.command == "upgrade" and args.recover and (
            args.file or args.signature or args.switch is not None
            or args.check or args.allow_downgrade):
        print("--recover 不能与其他升级参数同时使用", file=sys.stderr)
        return 2
    try:
        runner = runner if runner is not None else RealRunner()
        config = load(args.config, runner)
        if args.command == "admin":
            from .log import configure

            configure(runner, level=config.node.log_level)
            try:
                admin_server.serve(config)
                return 0
            except OSError:
                print(redact("客户端包托管服务启动失败，请检查监听配置。"), file=sys.stderr)
                return 1
        if args.command == "winclient":
            try:
                if args.winclient_action == "publish":
                    value = winclient_publish.publish(config, runner, args.exe, args.manifest,
                                                      args.signature,
                                                      allow_downgrade=args.allow_downgrade)
                    print("客户端包已发布：" + value["version"])
                else:
                    value = winclient_publish.latest(config, runner)
                    print((f"客户端版本：{value['version']}；大小：{value['size']} 字节；"
                           f"发布时间：{value['published_at']}") if value else "尚未托管客户端包")
                return 0
            except (OSError, ValueError):
                print(redact("客户端包操作失败，请检查文件和发布版本。"), file=sys.stderr)
                return 1
        if args.command == "rescue":
            if args.rescue_action == "status":
                print(redact(rescue_state.summary(_rescue_record(runner))))
            else:
                from .updater.layout import running_package

                refresh(running_package() + "/rescue",
                        rescue_probes.RESCUE + "/exitnode_rescue", rescue_runner)
                print("独立救援程序已更新。")
            return 0
        if args.command == "upgrade":
            try:
                from .updater.upgrade import recover, upgrade

                if args.recover:
                    return recover(config, runner, config_path=args.config)
                if args.signature and not args.file:
                    print("签名路径须与本地升级包一起指定。", file=sys.stderr)
                    return 2
                return upgrade(config, runner, file=args.file, signature=args.signature,
                               check=args.check, config_path=args.config,
                               allow_downgrade=args.allow_downgrade, switch=args.switch)
            except Exception:
                print("更新失败：更新组件异常，请联系维护人员。", file=sys.stderr)
                return 1
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
                result["layers"].insert(-1, _rescue_check(runner))
                result["layers"].insert(-1, service.harden_check(runner))
                result["layers"].append(admin_server.check(config))
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
