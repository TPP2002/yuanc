"""发布信任根。首次发布前由维护人员填入公钥；未配置时拒绝更新。"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY = bytes.fromhex("1363592e51ed392b5ce1e940537f22a67b4093632b6a8f6e55d055c05a3d1d3d")  # 2026-10-22 生成;私钥在维护机仓库外 .secrets/yuanc-exitnode-signing.pem


def verify_signature(data: bytes, signature: bytes) -> None:
    if not PUBLIC_KEY:
        raise ValueError("尚未配置升级签名公钥，请联系维护人员")
    try:
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(signature, data)
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("升级包签名校验失败") from None
