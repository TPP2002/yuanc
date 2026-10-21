"""Auditable device registry, persisted only under secrets/ with atomic writes."""

import json
import secrets
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

from .runner_proto import Runner, secret_path


def now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Device:
    device_id: str
    account_id: str
    platform: str
    name: str
    uuid: str = field(repr=False)
    hy2_password: str = field(repr=False)
    created_at: str
    revoked_at: str | None = None


def validate_devices(devices: list[Device]) -> None:
    ids, uuids = set(), set()
    for device in devices:
        try:
            valid_uuid = str(UUID(device.uuid)) == device.uuid
        except (ValueError, TypeError, AttributeError):
            valid_uuid = False
        if not valid_uuid or not device.hy2_password or not device.account_id or not device.device_id:
            raise ValueError("设备登记数据无效")
        if (device.revoked_at is None and device.device_id in ids) or device.uuid in uuids:
            raise ValueError("设备标识或凭据重复")
        if device.revoked_at is None:
            ids.add(device.device_id)
        uuids.add(device.uuid)


class DeviceRegistry:
    """Single-writer registry; repeated add never resurrects a revoked device."""

    def __init__(self, path: str, runner: Runner):
        self.path = secret_path(path)
        self.runner = runner

    def all(self) -> list[Device]:
        if not self.runner.exists(self.path):
            return []
        try:
            devices = [Device(**item) for item in json.loads(self.runner.read_file(self.path))]
            validate_devices(devices)
            return devices
        except (ValueError, TypeError, KeyError):
            raise ValueError("设备登记表损坏，未覆盖") from None

    def save(self, devices: list[Device]) -> None:
        validate_devices(devices)
        text = json.dumps([asdict(d) for d in devices], ensure_ascii=False, indent=2) + "\n"
        self.runner.write_file(self.path, text, 0o600)

    def add(self, device_id: str, account_id: str, platform: str, name: str) -> Device:
        devices = self.all()
        for device in reversed(devices):
            if device.device_id == device_id:
                if device.account_id != account_id:
                    raise ValueError("设备已属于其他账户")
                return device
        device = Device(
            device_id, account_id, platform, name, str(uuid4()), secrets.token_urlsafe(32), now(),
        )
        self.save([*devices, device])
        return device

    def revoke(self, device_id: str) -> None:
        devices = self.all()
        updated = [
            replace(d, revoked_at=now()) if d.device_id == device_id and not d.revoked_at else d
            for d in devices
        ]
        if updated != devices:
            self.save(updated)

    def active(self) -> list[Device]:
        return [d for d in self.all() if d.revoked_at is None]
