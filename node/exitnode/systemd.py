"""仅渲染服务定义；占位入口明确失败，不伪装为正在运行的服务。"""

from importlib.resources import files
from string import Template

from .manifest import UNITS


def render(name, ctx):
    if name not in UNITS:
        raise ValueError("未知的本项目服务模板")
    config_path = ctx.get("config_path", "/etc/exitnode/config.toml")
    if any(c in config_path for c in '\n\r\x00"\\%$') or not config_path.startswith("/"):
        raise ValueError("服务配置路径含不支持的字符")
    template = files("exitnode").joinpath("templates", name).read_text(encoding="utf-8")
    return Template(template).substitute(config_path=config_path)
