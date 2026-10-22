"""隧道安装边界：主机操作只通过节点 Runner，完成步骤由清单复用。"""

import json
import re
import secrets
from pathlib import PurePosixPath

from .manifest import Manifest
from .proxy.context import HY2_OBFS_ERROR, ProxyContext, valid_hy2_obfs_password
from .proxy.keys import ensure_reality_keys
from .proxy.registry import DeviceRegistry
from .proxy.reload import reload
from .proxy.server_config import render_server

SECRETS = "/var/lib/exitnode/secrets"
LIVE = SECRETS + "/sing-box.json"
LAST_GOOD = LIVE.replace(".json", ".last-good.json")
UNIT = "exitnode-proxy.service"
HY2_OBFS = SECRETS + "/hy2.obfs"
HY2_OBFS_CORRUPT = "备用通道混淆密码文件损坏，请联系维护人员；已有文件未覆盖"


class ProxyRunner:
    """提供元组结果和原子写入；兼容 proxy 在 Windows 测试中解析的路径。"""

    def __init__(self, runner):
        self.runner = runner

    @staticmethod
    def path(path):
        path = str(path).replace("\\", "/")
        path = re.sub(r"^[A-Za-z]:", "", path)
        if not path.startswith(SECRETS + "/") or ".." in PurePosixPath(path).parts:
            raise ValueError("凭据文件必须位于指定凭据目录")
        return path

    def run(self, argv):
        result = self.runner.run(argv, check=False)
        return result.code, result.out, result.err

    def write_file(self, path, text, mode):
        path = self.path(path)
        temporary = path + ".write.tmp"
        try:
            self.runner.write_file(temporary, text, mode)
            self.runner.replace(temporary, path)
        finally:
            if self.runner.exists(temporary):
                self.runner.write_file(temporary, "", 0o600)
                self.runner.remove(temporary)

    def read_file(self, path):
        return self.runner.read_file(self.path(path))

    def exists(self, path):
        return self.runner.exists(self.path(path))


def _manifest(config, runner):
    return Manifest(config.node.data_dir.rstrip("/") + "/manifest.json", runner)


def ensure_credentials(config, runner):
    manifest = _manifest(config, runner)
    adapter = ProxyRunner(runner)

    def preserve(path):
        return {"kind": "remove_file", "path": path, "preserve": True}

    manifest.apply("生成 Reality 凭据",
                   lambda: ensure_reality_keys(config.node.secrets_dir, adapter),
                   preserve(SECRETS + "/reality.json"))

    crt, key = SECRETS + "/hy2.crt", SECRETS + "/hy2.key"
    crt_tmp, key_tmp = crt + ".new.tmp", key + ".new.tmp"
    certificate_step = "生成备用通道证书"
    if (not any(s["step"] == certificate_step for s in manifest.steps)
            and any(runner.exists(path) for path in (crt_tmp, key_tmp))):
        raise ValueError("已有证书临时文件未在本安装清单中，请联系维护人员")

    def certificate():
        have_crt, have_key = runner.exists(crt), runner.exists(key)
        regenerated = False
        if have_crt and have_key:
            result = runner.run([
                "openssl", "x509", "-in", crt, "-noout", "-ext", "subjectAltName",
            ], check=False)
            if result.code:
                raise ValueError("备用通道证书检查失败；命令输出已隐藏，已有文件未覆盖")
            names = re.findall(r"DNS:([^,\s]+)", result.out)
            if config.proxy.hy2_server_name in names:
                return
            for path in (crt, key):
                runner.write_file(path, "", 0o600)
            for path in (crt, key):
                runner.remove(path)
            regenerated = True
        elif have_crt or have_key:
            raise ValueError("备用通道证书与私钥不成对，请联系维护人员；已有文件未覆盖")
        # 命令已完成但完成标记未落盘时，复用完整暂存对，不重新生成。
        if all(runner.exists(path) and runner.read_file(path) for path in (crt_tmp, key_tmp)):
            return
        try:
            for path in (crt_tmp, key_tmp):
                runner.write_file(path, "", 0o600)
            result = runner.run([
                "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key_tmp,
                "-out", crt_tmp, "-days", "3650", "-subj",
                "/CN=" + config.proxy.hy2_server_name,
                "-addext", "subjectAltName=DNS:" + config.proxy.hy2_server_name,
            ], check=False)
            if result.code:
                raise ValueError("备用通道证书生成失败，请检查 openssl；命令输出已隐藏")
            if not runner.read_file(crt_tmp) or not runner.read_file(key_tmp):
                raise ValueError("备用通道证书生成未产生完整文件")
            if regenerated:
                print("备用通道证书已重新生成,旧配对文件需重新导出")
        except (OSError, RuntimeError, ValueError):
            for path in (crt_tmp, key_tmp):
                if runner.exists(path):
                    runner.write_file(path, "", 0o600)
                    runner.remove(path)
            raise

    manifest.apply(certificate_step, certificate, preserve(SECRETS))
    # 分别登记发布动作：任一替换或标记保存中断后，原证书对仍可继续发布。
    for name, temporary, target in (("保存备用通道私钥", key_tmp, key),
                                    ("保存备用通道证书", crt_tmp, crt)):
        def install_certificate(source=temporary, destination=target):
            if runner.exists(destination):
                return
            if not runner.exists(source) or not runner.read_file(source):
                raise ValueError("备用通道证书暂存文件缺失，请联系维护人员")
            runner.replace(source, destination)

        manifest.apply(name, install_certificate, preserve(target))
    registry = DeviceRegistry(SECRETS + "/devices.json", adapter)

    def obfuscation():
        if runner.exists(HY2_OBFS):
            if not valid_hy2_obfs_password(runner.read_file(HY2_OBFS).strip()):
                raise ValueError(HY2_OBFS_CORRUPT)
            return
        upgraded = adapter.exists(registry.path) and bool(registry.all())
        temporary = HY2_OBFS + ".tmp"
        try:
            runner.write_file(temporary, secrets.token_urlsafe(32), 0o600)
            runner.replace(temporary, HY2_OBFS)
        finally:
            if runner.exists(temporary):
                runner.write_file(temporary, "", 0o600)
                runner.remove(temporary)
        if upgraded:
            print("备用通道已启用混淆,旧配对文件的备用线路将不可用,请重新导出")

    manifest.apply("生成备用通道混淆密码", obfuscation, preserve(HY2_OBFS))

    def create_registry():
        if adapter.exists(registry.path):
            registry.all()
        else:
            registry.save([])

    manifest.apply("准备设备登记表", create_registry, preserve(SECRETS + "/devices.json"))
    return ensure_reality_keys(config.node.secrets_dir, adapter)


def read_hy2_obfs_password(runner):
    """未生成时返回空串(按不混淆发布);文件存在但格式不对时拒绝发布。"""
    if not runner.exists(HY2_OBFS):
        return ""
    value = runner.read_file(HY2_OBFS).strip()
    if not valid_hy2_obfs_password(value):
        raise ValueError(HY2_OBFS_ERROR)
    return value


def build_context(config, keys, runner):
    return ProxyContext(
        reality=keys, sni=config.proxy.sni, handshake_server=config.proxy.handshake_server,
        reality_port=config.proxy.reality_port,
        maintenance_device_ids=tuple(config.proxy.maintenance_device_ids),
        admin_bind=config.admin.bind, admin_port=config.admin.port,
        hy2_port=config.proxy.hy2_port, hy2_server_name=config.proxy.hy2_server_name,
        hy2_certificate_path=SECRETS + "/hy2.crt", hy2_key_path=SECRETS + "/hy2.key",
        hy2_certificate=tuple(line for line in
                              runner.read_file(SECRETS + "/hy2.crt").splitlines()
                              if line.strip()),
        hy2_obfs_password=read_hy2_obfs_password(runner),
    )


class ReloadRunner(ProxyRunner):
    """将代理层重载操作限定到本项目安装的服务。"""

    def run(self, argv):
        if argv[:2] in (["systemctl", "reload"], ["systemctl", "restart"]):
            argv = [*argv[:2], UNIT]
        return super().run(argv)


def _publish_checked(config, runner, devices, registry=None):
    adapter = ProxyRunner(runner)
    keys = ensure_reality_keys(config.node.secrets_dir, adapter)
    text = json.dumps(render_server(build_context(config, keys, runner), devices),
                      ensure_ascii=False, indent=2) + "\n"
    temporary = LIVE + ".check.tmp"
    try:
        runner.write_file(temporary, text, 0o600)
        result = runner.run([config.proxy.binary, "check", "-c", temporary], check=False)
        if result.code:
            raise ValueError("隧道配置校验失败，线上配置与登记表未变；命令输出已隐藏")
        old_text = runner.read_file(LIVE) if registry is not None else None
        runner.replace(temporary, LIVE)
        if registry is not None:
            try:
                registry.save(devices)
            except (OSError, RuntimeError, ValueError):
                adapter.write_file(LIVE, old_text, 0o600)
                raise ValueError("登记表写入失败，线上配置已回退，未重载") from None
            try:
                reload(ReloadRunner(runner))
            except (OSError, RuntimeError):
                raise ValueError("设备已登记但服务重载未成功，请联系维护人员") from None
        runner.write_file(LAST_GOOD + ".tmp", text, 0o600)
        runner.replace(LAST_GOOD + ".tmp", LAST_GOOD)
    finally:
        runner.write_file(temporary, "", 0o600)


def publish(config, runner, *, devices=None):
    manifest = _manifest(config, runner)
    step = "渲染隧道配置"
    if runner.exists(LIVE) and not any(s["step"] == step for s in manifest.steps):
        raise ValueError("已有隧道配置未在本安装清单中，请联系维护人员")

    if devices is not None:
        if not runner.exists(LIVE):
            raise ValueError("节点尚未安装成功，请先完成 init")
        registry = DeviceRegistry(SECRETS + "/devices.json", ProxyRunner(runner))
        _publish_checked(config, runner, devices, registry)
        return

    def action():
        adapter = ProxyRunner(runner)
        registry = DeviceRegistry(SECRETS + "/devices.json", adapter)
        _publish_checked(config, runner, registry.all())

    manifest.apply(step, action, {"kind": "remove_file", "path": LIVE})


def check(runner, config):
    try:
        active = runner.run(["systemctl", "is-active", "exitnode-proxy"], check=False)
        valid = runner.run([config.proxy.binary, "check", "-c", LIVE], check=False)
        ok = active.code == 0 and valid.code == 0
    except (OSError, RuntimeError):
        ok = False
    return {"layer": "tunnel", "name": "隧道服务", "result": "通过" if ok else "失败",
            "reason": "服务运行且配置校验通过" if ok else "隧道服务未运行或配置校验失败"}
