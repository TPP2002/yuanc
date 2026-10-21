"""隧道安装边界：主机操作只通过节点 Runner，完成步骤由清单复用。"""

import json
import re
from pathlib import PurePosixPath

from .manifest import Manifest
from .proxy.context import ProxyContext
from .proxy.keys import ensure_reality_keys
from .proxy.registry import DeviceRegistry
from .proxy.server_config import render_server

SECRETS = "/var/lib/exitnode/secrets"
LIVE = SECRETS + "/sing-box.json"
UNIT = "exitnode-proxy.service"


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
        if have_crt and have_key:
            return
        if have_crt or have_key:
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
            ], check=False)
            if result.code:
                raise ValueError("备用通道证书生成失败，请检查 openssl；命令输出已隐藏")
            if not runner.read_file(crt_tmp) or not runner.read_file(key_tmp):
                raise ValueError("备用通道证书生成未产生完整文件")
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

    def create_registry():
        if adapter.exists(registry.path):
            registry.all()
        else:
            registry.save([])

    manifest.apply("准备设备登记表", create_registry, preserve(SECRETS + "/devices.json"))
    return ensure_reality_keys(config.node.secrets_dir, adapter)


def build_context(config, keys):
    return ProxyContext(
        reality=keys, sni=config.proxy.sni, handshake_server=config.proxy.handshake_server,
        hy2_port=config.proxy.hy2_port, hy2_server_name=config.proxy.hy2_server_name,
        hy2_certificate_path=SECRETS + "/hy2.crt", hy2_key_path=SECRETS + "/hy2.key",
    )


def publish(config, runner):
    manifest = _manifest(config, runner)
    step = "渲染隧道配置"
    if runner.exists(LIVE) and not any(s["step"] == step for s in manifest.steps):
        raise ValueError("已有隧道配置未在本安装清单中，请联系维护人员")

    def action():
        adapter = ProxyRunner(runner)
        keys = ensure_reality_keys(config.node.secrets_dir, adapter)
        registry = DeviceRegistry(SECRETS + "/devices.json", adapter)
        text = json.dumps(render_server(build_context(config, keys), registry.all()),
                          ensure_ascii=False, indent=2) + "\n"
        temporary = LIVE + ".check.tmp"
        try:
            runner.write_file(temporary, text, 0o600)
            result = runner.run([config.proxy.binary, "check", "-c", temporary], check=False)
            if result.code:
                raise ValueError("隧道配置校验失败，线上配置未变；命令输出已隐藏")
            runner.replace(temporary, LIVE)
        finally:
            # 无论校验还是替换失败，都不在临时文件中遗留凭据。
            runner.write_file(temporary, "", 0o600)

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
