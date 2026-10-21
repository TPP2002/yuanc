"""令牌不写日志；密钥只在配置和内存中出现。"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime


def now():
    return datetime.now(UTC)


def iso(value):
    if value.tzinfo is None:
        raise ValueError("时钟必须返回带时区的时间")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def hash_token(raw: str, salt: str) -> str:
    return hashlib.sha256((salt + raw).encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_invite_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def hy2_password(device_uuid: str, salt: str) -> str:
    # Deterministic domain-separated credential: no plaintext password in the database.
    return hmac.new(salt.encode(), ("hy2:" + device_uuid).encode(), hashlib.sha256).hexdigest()
