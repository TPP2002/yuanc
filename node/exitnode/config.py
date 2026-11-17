"""不包含凭据内容的严格配置模型。"""

import ipaddress
import re
import tomllib
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .runner import RealRunner, Runner


class ConfigError(ValueError):
    pass


@dataclass
class Node:
    name: str
    config_version: int = 1
    data_dir: str = "/var/lib/exitnode"
    secrets_dir: str = "/var/lib/exitnode/secrets"
    log_level: str = "INFO"
    time_zone: str = ""
    country: str = ""


@dataclass
class Network:
    iface: str = "auto"
    probe_targets: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])


@dataclass
class Proxy:
    hy2_port: int
    # 伪装目标必填无默认,sni 与 handshake_server 必须相同,推荐澳洲本地大站。
    sni: str
    handshake_server: str
    reality_port: int = 443
    hy2_server_name: str = "exitnode"
    binary: str = "/opt/exitnode/current/bin/sing-box"
    maintenance_device_ids: list[str] = field(default_factory=list)


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
    source: str = "none"
    github_repo: str = ""
    health_timeout_sec: int = 120
    # 首次通过后继续观察的稳定窗秒数；0 表示关闭稳定窗。
    health_stable_sec: int = 30
    releases_dir: str = "/opt/exitnode"


@dataclass
class Watchdog:
    enabled: bool = True
    restart_limit_per_hour: int = 3
    rollback_min_interval_hours: int = 6
    reboot_enabled: bool = True
    reboot_after_minutes: int = 30
    reboot_min_interval_hours: int = 6
    hardware: bool = True
    weekly_reboot: bool = False
    restart_after_failures: int = 4
    retry_interval_seconds: int = 60
    max_backoff_seconds: int = 300


@dataclass
class AuthSync:
    enabled: bool = False
    url: str = ""
    spki_sha256: str = ""


@dataclass
class Config:
    node: Node
    network: Network
    proxy: Proxy
    admin: Admin
    publisher: Publisher
    updater: Updater
    watchdog: Watchdog = field(default_factory=Watchdog)
    authsync: AuthSync = field(default_factory=AuthSync)

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
              "publisher": Publisher, "updater": Updater, "watchdog": Watchdog,
              "authsync": AuthSync}
    for name in raw.keys() - models.keys():
        invalid(name, "未知配置项")
    values = {}
    for name, model in models.items():
        if name not in raw:
            if name in {"watchdog", "authsync"}:
                values[name] = model()
                continue
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
            if (name == "node" and key == "config_version"
                    and (type(value) is not int or value <= 0)):
                invalid("node.config_version", "须为正整数")
            if (name == "updater" and key == "health_stable_sec"
                    and (type(value) is not int or value < 0)):
                invalid("updater.health_stable_sec", "须为非负整数秒数")
            if spec.type == list[str]:
                allow_empty = name == "proxy" and key == "maintenance_device_ids"
                valid = (type(value) is list and (allow_empty or bool(value))
                         and all(type(v) is str and v.strip() for v in value))
            else:
                valid = type(value) is spec.type
            if not valid:
                invalid(f"{name}.{key}", "字段类型不正确")
            if (isinstance(value, str) and (not value or any(ord(c) < 32 for c in value))
                    and not (name == "updater" and key == "github_repo" and value == "")
                    and not (name == "authsync" and key in {"url", "spki_sha256"}
                             and value == "")
                    # 可选环境字段的空串与格式由下方专用校验处理，保留对应中文错误。
                    and not (name == "node" and key in {"time_zone", "country"})):
                invalid(f"{name}.{key}", "不能为空或含控制字符")
        values[name] = model(**section)
    config = Config(**values)
    if config.authsync.enabled:
        url = config.authsync.url
        try:
            parts = urlsplit(url)
            host, port = parts.hostname, parts.port
            valid_url = (parts.scheme in {"http", "https"} and host and not parts.username
                         and not parts.password and not parts.path and not parts.query
                         and not parts.fragment and not url.endswith(("/", ":"))
                         and "?" not in url and "#" not in url and "@" not in url
                         and (port is None or 1 <= port <= 65535)
                         and re.fullmatch(r"[A-Za-z0-9.-]+", host)
                         and (parts.scheme != "http" or host == "127.0.0.1"))
        except ValueError:
            valid_url = False
        if not valid_url:
            invalid("authsync.url", "须为 HTTPS 主机地址或本机 HTTP 地址，不能带路径")
        pin = config.authsync.spki_sha256
        if parts.scheme == "https" and not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pin):
            invalid("authsync.spki_sha256", "HTTPS 须填写有效的公钥指纹")
        if parts.scheme == "http" and pin:
            invalid("authsync.spki_sha256", "HTTP 地址不能填写公钥指纹")
    if config.node.time_zone and not re.fullmatch(r"[A-Za-z0-9 ._+/()-]{1,64}", config.node.time_zone):
        invalid("node.time_zone", "须为 IANA 时区名(如 Australia/Sydney)或 Windows 时区标识")
    if config.node.country and not re.fullmatch(r"[A-Z]{2}", config.node.country):
        invalid("node.country", "须为两位大写国家码(如 AU)")
    for key in ("restart_limit_per_hour", "rollback_min_interval_hours",
                "reboot_min_interval_hours", "retry_interval_seconds", "max_backoff_seconds"):
        if getattr(config.watchdog, key) <= 0:
            invalid("watchdog." + key, "须为正整数")
    if config.watchdog.reboot_after_minutes < 5:
        invalid("watchdog.reboot_after_minutes", "不得少于 5 分钟")
    if config.watchdog.restart_after_failures < 4:
        invalid("watchdog.restart_after_failures", "不得少于 4 次")
    if config.watchdog.max_backoff_seconds < config.watchdog.retry_interval_seconds:
        invalid("watchdog.max_backoff_seconds", "不得小于重试间隔")
    for name in ("sni", "handshake_server", "hy2_server_name"):
        hostname = getattr(config.proxy, name)
        if len(hostname) > 253 or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", hostname
        ):
            invalid(f"proxy.{name}", "主机名格式不正确")
    if config.proxy.sni != config.proxy.handshake_server:
        invalid("proxy.handshake_server",
                "必须与 proxy.sni 相同:伪装目标与握手名称不一致是 Reality 配错的典型特征")
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
    if config.updater.source not in {"none", "github"}:
        invalid("updater.source", "只支持 none 或 github")
    if config.updater.health_timeout_sec <= 0:
        invalid("updater.health_timeout_sec", "须为正整数秒数")
    repo = config.updater.github_repo
    if ((repo or config.updater.source == "github")
            and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", repo)):
        invalid("updater.github_repo", "须为 owner/repo 格式")
    directory = config.updater.releases_dir
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", directory)
            or ".." in PurePosixPath(directory).parts or str(PurePosixPath(directory)) == "/"):
        invalid("updater.releases_dir", "须为安全的非根目录绝对路径")
    if config.updater.releases_dir != "/opt/exitnode":
        invalid("updater.releases_dir", "救援程序按固定布局工作,当前只支持 /opt/exitnode")
    if config.node.data_dir != "/var/lib/exitnode":
        invalid("node.data_dir", "救援程序按固定布局工作,当前只支持 /var/lib/exitnode")
    return config
