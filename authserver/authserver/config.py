"""配置必须由部署方提供；无内置密钥。"""

import re
import tomllib
from pathlib import Path

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)

HY2_OBFS_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}")


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
    time_zone: str = ""
    country: str = ""
    host: str = Field(min_length=1)
    reality_port: int = Field(ge=1, le=65535)
    hy2_port: int = Field(ge=1, le=65535)
    reality_public_key: str = Field(min_length=1)
    short_id: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}){1,8}$")
    sni: str = Field(min_length=1)
    hy2_server_name: str = Field(default="exitnode", min_length=1)
    hy2_certificate_path: str = Field(min_length=1, exclude=True, repr=False)
    # 节点 secrets/hy2.obfs 的本地副本；留空表示节点未启用混淆。
    hy2_obfs_password_path: str = Field(default="", exclude=True, repr=False)
    _certificate: list[str] = PrivateAttr(default_factory=list)
    _obfs_password: str = PrivateAttr(default="")

    @field_validator("time_zone")
    @classmethod
    def validate_time_zone(cls, value):
        if value and not re.fullmatch(r"[A-Za-z0-9 ._+/()-]{1,64}", value):
            raise ValueError("须为 IANA 时区名(如 Australia/Sydney)或 Windows 时区标识")
        return value

    @field_validator("country")
    @classmethod
    def validate_country(cls, value):
        if value and not re.fullmatch(r"[A-Z]{2}", value):
            raise ValueError("须为两位大写国家码(如 AU)")
        return value

    @model_validator(mode="after")
    def read_certificate(self):
        try:
            self._certificate = [line for line in Path(self.hy2_certificate_path)
                                 .read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, UnicodeError):
            raise ValueError("无法读取备用通道证书：" + self.hy2_certificate_path) from None
        if not self._certificate:
            raise ValueError("备用通道证书为空：" + self.hy2_certificate_path)
        return self

    @model_validator(mode="after")
    def read_obfs_password(self):
        path = self.hy2_obfs_password_path
        if not path:
            self._obfs_password = ""
            return self
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise ValueError("无法读取备用通道混淆密码：" + path) from None
        if not HY2_OBFS_PATTERN.fullmatch(value):
            raise ValueError("备用通道混淆密码格式不正确：" + path)
        self._obfs_password = value
        return self

    @computed_field
    @property
    def hy2_certificate(self) -> list[str]:
        return list(self._certificate)

    @computed_field(repr=False)
    @property
    def hy2_obfs_password(self) -> str:
        return self._obfs_password


class Limits(Section):
    session_hours: int = Field(default=6, ge=1)
    default_device_limit: int = Field(default=2, ge=1)
    redeem_per_ip_per_hour: int = Field(default=10, ge=1)
    session_per_ip_per_hour: int = Field(default=120, ge=1)


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
        raise ValueError("鉴权服务器配置无效：请检查安全密钥、节点参数及限制，"
                         "备用通道证书路径必填且文件必须可读取；"
                         "如配置了备用通道混淆密码路径，文件必须可读取且格式正确") from None
