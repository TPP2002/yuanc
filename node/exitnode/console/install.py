"""管理网页的安装准备：放行附加配置、管理密码与局域网地址。"""

import ipaddress
from urllib.parse import urlsplit

from .. import netinfo, service
from . import auth

DROPIN_DIR = "/etc/systemd/system/exitnode-console.service.d"
DROPIN = DROPIN_DIR + "/authserver.conf"
LAN = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
       ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("169.254.0.0/16"))
PASSWORD = service.SECRETS + "/console-password"
ADMIN_KEY = service.SECRETS + "/authserver-admin-key"


def extra_allow(config):
    """鉴权服务搬到公网地址时，需要多放行的那一个地址；本机与局域网返回 None。"""
    if not config.authsync.enabled:
        return None
    try:
        host = urlsplit(config.authsync.url).hostname
        address = ipaddress.IPv4Address(host)
    except (ValueError, TypeError, AttributeError):
        return None
    if address.is_loopback or any(address in network for network in LAN):
        return None
    return str(address) + "/32"


def dropin_text(config):
    lines = ["# 由 exitnode init 按配置 authsync.url 生成,不要手改", "[Service]"]
    extra = extra_allow(config)
    if extra is not None:
        lines.append("IPAddressAllow=" + extra)
    return "\n".join(lines) + "\n"


def sync_dropin(config, runner):
    """每次 init 都按当前配置比对；内容不同才重写，返回是否写过。"""
    runner.mkdir(DROPIN_DIR, 0o755)
    content = dropin_text(config)
    if runner.exists(DROPIN) and runner.read_file(DROPIN) == content:
        return False
    runner.write_file(DROPIN, content, 0o644)
    return True


def prepare(config, runner):
    """首次安装生成管理密码并留一份空的管理密钥文件；返回新密码或 None。"""
    password = None
    if not runner.exists(PASSWORD):
        password = auth.generate_password()
        temporary = PASSWORD + ".tmp"
        runner.write_file(temporary, auth.hash_password(password), 0o600)
        runner.replace(temporary, PASSWORD)
    if not runner.exists(ADMIN_KEY):
        # systemd 的 LoadCredential 要求文件存在；空内容由网页识别为「还没填管理密钥」。
        runner.write_file(ADMIN_KEY, "", 0o600)
    return password


def urls(config, runner):
    """安装完成后提示可用的网址：局域网一项（能取到地址时）加隧道一项。"""
    result = []
    if config.console.lan:
        try:
            network, _, _ = netinfo.read_network(runner, config.network.iface)
        except Exception:
            network = {}
        address = network.get("addr")
        if address:
            result.append("http://" + address + ":" + str(config.console.port) + "/")
    result.append("http://198.18.255.2/")
    return result
