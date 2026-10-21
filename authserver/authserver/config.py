"""配置必须由部署方提供；无内置密钥。"""

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Server(Section):
    bind: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)


class Security(Section):
    admin_key: SecretStr
    node_key: SecretStr
    token_salt: SecretStr

    @field_validator("admin_key", "node_key", "token_salt")
    @classmethod
    def require_secret(cls, value):
        raw = value.get_secret_value()
        if not raw.strip() or raw.startswith("<"):
            raise ValueError("必须设置真实的安全配置，不能使用空值或示例占位符")
        return value


class Node(Section):
    host: str = Field(min_length=1)
    reality_port: int = Field(ge=1, le=65535)
    hy2_port: int = Field(ge=1, le=65535)
    reality_public_key: str = Field(min_length=1)
    short_id: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}){1,8}$")
    sni: str = Field(min_length=1)


class Limits(Section):
    session_hours: int = Field(default=6, ge=1)
    default_device_limit: int = Field(default=2, ge=1)
    redeem_per_ip_per_hour: int = Field(default=10, ge=1)


class Settings(Section):
    server: Server = Field(default_factory=Server)
    security: Security
    node: Node
    limits: Limits = Field(default_factory=Limits)


def load_config(path: str | Path) -> Settings:
    with Path(path).open("rb") as stream:
        data = tomllib.load(stream)
    # Do not include pydantic's input values (which may contain secrets) in startup logs.
    try:
        return Settings.model_validate(data)
    except ValueError:
        raise ValueError("鉴权服务器配置无效：请检查安全密钥、节点参数及限制") from None
