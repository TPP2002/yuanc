"""不包含凭据内容的严格配置模型。"""

import ipaddress
import re
import tomllib
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import PurePosixPath

from .runner import RealRunner, Runner


class ConfigError(ValueError):
    pass


@dataclass
class Node:
    name: str
    data_dir: str = "/var/lib/exitnode"
    secrets_dir: str = "/var/lib/exitnode/secrets"
    log_level: str = "INFO"


@dataclass
class Network:
    iface: str = "auto"
    probe_targets: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])


@dataclass
class Proxy:
    hy2_port: int
    reality_port: int = 443
    # 可改为澳洲本地大站，客户端须使用相同的握手名称。
    sni: str = "www.microsoft.com"
    handshake_server: str = "www.microsoft.com"
    hy2_server_name: str = "exitnode"
    binary: str = "/usr/bin/sing-box"


@dataclass
class Admin:
    bind: str
    port: int


@dataclass
class Publisher:
    mode: str
    ddns_provider: str
    domain: str


@dataclass
class Updater:
    channel: str
    check_interval: int


@dataclass
class Config:
    node: Node
    network: Network
    proxy: Proxy
    admin: Admin
    publisher: Publisher
    updater: Updater

    def sanitized(self):
        return asdict(self)


def load(path: str, runner: Runner | None = None) -> Config:
    runner = runner if runner is not None else RealRunner()

    def invalid(key, reason):
        raise ConfigError(f"配置 {path} 的 {key}：{reason}")

    try:
        raw = tomllib.loads(runner.read_file(str(path)))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        # 不转印原文：TOML 错误附近可能包含操作者误填的凭据。
        raise ConfigError(f"配置 {path}：文件无法读取或格式不正确") from exc
    models = {"node": Node, "network": Network, "proxy": Proxy, "admin": Admin,
              "publisher": Publisher, "updater": Updater}
    for name in raw.keys() - models.keys():
        invalid(name, "未知配置项")
    values = {}
    for name, model in models.items():
        if name not in raw:
            invalid(name, "缺少配置段")
        section = raw[name]
        if not isinstance(section, dict):
            invalid(name, "应为配置段")
        expected = {f.name: f for f in fields(model)}
        for key in section.keys() - expected.keys():
            invalid(f"{name}.{key}", "未知配置项")
        for key, spec in expected.items():
            if key not in section:
                if spec.default is MISSING and spec.default_factory is MISSING:
                    invalid(f"{name}.{key}", "缺少必填字段")
                continue
            value = section[key]
            if spec.type == list[str]:
                valid = (type(value) is list and bool(value)
                         and all(type(v) is str and v.strip() for v in value))
            else:
                valid = type(value) is spec.type
            if not valid:
                invalid(f"{name}.{key}", "字段类型不正确")
            if isinstance(value, str) and (not value or any(ord(c) < 32 for c in value)):
                invalid(f"{name}.{key}", "不能为空或含控制字符")
        values[name] = model(**section)
    config = Config(**values)
    for name in ("sni", "handshake_server", "hy2_server_name"):
        hostname = getattr(config.proxy, name)
        if len(hostname) > 253 or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", hostname
        ):
            invalid(f"proxy.{name}", "主机名格式不正确")
    binary = PurePosixPath(config.proxy.binary)
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", config.proxy.binary)
            or ".." in binary.parts or str(binary) == "/"):
        invalid("proxy.binary", "必须为安全的可执行文件绝对路径")
    for key, value in (("node.data_dir", config.node.data_dir),
                       ("node.secrets_dir", config.node.secrets_dir)):
        p = PurePosixPath(value)
        if not p.is_absolute() or ".." in p.parts or str(p) == "/":
            invalid(key, "必须为非根目录的绝对路径")
    if config.node.secrets_dir != "/var/lib/exitnode/secrets":
        invalid("node.secrets_dir", "凭据必须保存到 /var/lib/exitnode/secrets/")
    if config.node.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        invalid("node.log_level", "日志级别不支持")
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", config.network.iface):
        invalid("network.iface", "网卡名称格式不正确")
    for target in config.network.probe_targets:
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", target) or target.startswith("-"):
            invalid("network.probe_targets", "探测目标须为主机名或地址")
    for key, port in (("proxy.reality_port", config.proxy.reality_port),
                      ("proxy.hy2_port", config.proxy.hy2_port),
                      ("admin.port", config.admin.port)):
        if not 1 <= port <= 65535:
            invalid(key, "端口须在 1 至 65535 之间")
    try:
        ipaddress.ip_address(config.admin.bind)
    except ValueError:
        invalid("admin.bind", "须为监听地址")
    if config.publisher.mode not in {"upnp", "relay"}:
        invalid("publisher.mode", "只支持 upnp 或 relay")
    if config.updater.check_interval <= 0:
        invalid("updater.check_interval", "检查间隔须为正整数秒数")
    return config
