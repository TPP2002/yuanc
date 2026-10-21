"""仅渲染服务定义；占位入口明确失败，不伪装为正在运行的服务。"""

from importlib.resources import files
from string import Template

from .manifest import UNITS


def render(name, ctx, binary="/opt/exitnode/current/bin/sing-box"):
    if name not in UNITS:
        raise ValueError("未知的本项目服务模板")
    config_path = ctx.get("config_path", "/etc/exitnode/config.toml")
    if any(c in config_path for c in '\n\r\x00"\\%$') or not config_path.startswith("/"):
        raise ValueError("服务配置路径含不支持的字符")
    if (any(c.isspace() or c in '\x00"\\%$' for c in binary)
            or not binary.startswith("/") or ".." in binary.split("/")):
        raise ValueError("服务程序路径含不支持的字符")
    template = files("exitnode").joinpath("templates", name).read_text(encoding="utf-8")
    program_path = ctx.get("program_path", "/opt/exitnode/current")
    if (any(c.isspace() or c in '\x00"\\%$' for c in program_path)
            or not program_path.startswith("/") or ".." in program_path.split("/")):
        raise ValueError("服务程序目录含不支持的字符")
    return Template(template).substitute(config_path=config_path, binary=binary,
                                         program_path=program_path)
