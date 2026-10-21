"""先记录撤回方案再执行，完成标记以原子替换保存。"""

import json
from datetime import UTC, datetime
from pathlib import PurePosixPath

from .runner import Runner

UNITS = {"exitnode-admin.service", "exitnode-proxy.service",
         "exitnode-watchdog.service", "exitnode-watchdog.timer"}


class Manifest:
    def __init__(self, path: str, runner: Runner):
        self.path = str(path)
        self.runner = runner
        self.steps = []
        if runner.exists(self.path):
            try:
                content = json.loads(runner.read_file(self.path))
                self.steps = content["steps"]
                if not isinstance(self.steps, list):
                    raise TypeError
                seen = set()
                for item in self.steps:
                    if not isinstance(item, dict) or not {
                        "step", "action", "target", "undo", "done_at"
                    }.issubset(item) or item["step"] in seen:
                        raise ValueError
                    seen.add(item["step"])
                    self._validate_undo(item["undo"])
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError("安装清单损坏，请保留文件并联系维护人员") from exc

    def _save(self):
        self.runner.mkdir(str(PurePosixPath(self.path).parent))
        temporary = self.path + ".tmp"
        self.runner.write_file(temporary, json.dumps({"steps": self.steps},
                                                    ensure_ascii=False, indent=2), 0o600)
        self.runner.replace(temporary, self.path)

    @staticmethod
    def _validate_undo(spec):
        if not isinstance(spec, dict):
            raise TypeError("撤回方案格式错误")
        kind = spec.get("kind")
        if kind not in {"remove_file", "restore_file", "systemctl", "nft"}:
            raise ValueError("撤回方案类型不支持")
        if kind in {"remove_file", "restore_file"}:
            path = PurePosixPath(spec.get("path", ""))
            if not path.is_absolute() or str(path) == "/" or ".." in path.parts:
                raise ValueError("撤回目标必须为安全的绝对路径")
        if kind == "restore_file" and not spec.get("backup"):
            raise ValueError("恢复文件需要备份路径")
        if kind == "systemctl" and spec.get("unit") not in UNITS:
            raise ValueError("只允许撤回本项目的服务")
        if kind == "nft" and spec.get("table", "exitnode") != "exitnode":
            raise ValueError("只允许撤回本项目的规则表")

    def apply(self, step_id, do, undo_spec):
        self._validate_undo(undo_spec)
        item = next((s for s in self.steps if s["step"] == step_id), None)
        if item and item["done_at"]:
            return False
        if item is None:
            item = {"step": step_id, "action": undo_spec.get("action", step_id),
                    "target": undo_spec.get("path", undo_spec.get("unit", "exitnode")),
                    "undo": undo_spec, "done_at": None}
            self.steps.append(item)
            self._save()
        elif item["undo"] != undo_spec:
            raise ValueError("未完成步骤的撤回方案已变化，请先撤回原安装")
        # do 必须幂等；进程可能在动作完成后、保存完成标记前停止。
        do()
        item["done_at"] = datetime.now(UTC).isoformat()
        self._save()
        return True

    def _undo(self, spec):
        kind = spec["kind"]
        if kind == "remove_file":
            if not spec.get("preserve", False):
                self.runner.remove(spec["path"])
        elif kind == "restore_file":
            self.runner.write_file(spec["path"], self.runner.read_file(spec["backup"]),
                                   spec.get("mode", 0o600))
        elif kind == "systemctl":
            unit = spec["unit"]
            path = "/etc/systemd/system/" + unit
            if not spec.get("reload_only") and self.runner.exists(path):
                self.runner.run(["systemctl", "disable", "--now", unit])
                self.runner.remove(path)
            self.runner.run(["systemctl", "daemon-reload"])
        elif kind == "nft":
            from .nft import remove
            remove(self.runner)

    def rollback(self, to_step=None):
        if to_step is not None and not any(s["step"] == to_step for s in self.steps):
            raise ValueError("清单中找不到指定的保留步骤")
        summary = {"removed": [], "failed": []}
        for item in list(reversed(self.steps)):
            if item["step"] == to_step:
                break
            try:
                self._undo(item["undo"])
            except (OSError, RuntimeError, ValueError):
                # 不记录命令输出，避免泄露误传的凭据。
                summary["failed"].append({"step": item["step"], "reason": "撤回失败，请重试"})
                continue
            self.steps.remove(item)
            self._save()
            summary["removed"].append(item["step"])
        return summary
