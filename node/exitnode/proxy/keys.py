"""Persistent X25519 Reality material; no credential logging."""

import base64
import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .runner_proto import Runner, secret_path


@dataclass(frozen=True)
class RealityKeys:
    private_key: str = field(repr=False)
    public_key: str
    short_id: str


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _public(key: X25519PrivateKey) -> str:
    return _encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))


def ensure_reality_keys(secrets_dir: str | Path, runner: Runner) -> RealityKeys:
    path = secret_path(Path(secrets_dir) / "reality.json")
    if runner.exists(path):
        try:
            data = json.loads(runner.read_file(path))
            keys = RealityKeys(**data)
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", keys.private_key):
                raise ValueError
            key = X25519PrivateKey.from_private_bytes(
                base64.urlsafe_b64decode(keys.private_key + "="),
            )
            if keys.public_key != _public(key) or not re.fullmatch(
                r"[0-9a-f]{8}", keys.short_id,
            ):
                raise ValueError
            return keys
        except (ValueError, TypeError, KeyError):
            raise ValueError("已有 Reality 凭据损坏，未覆盖") from None
    key = X25519PrivateKey.generate()
    keys = RealityKeys(
        _encode(key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )),
        _public(key), secrets.token_hex(4),
    )
    runner.write_file(path, json.dumps({
        "private_key": keys.private_key,
        "public_key": keys.public_key,
        "short_id": keys.short_id,
    }, indent=2) + "\n", 0o600)
    return keys
