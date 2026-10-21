"""有界本地救援；每轮最多一个恢复或提升动作。"""

import json
import subprocess

from . import probes as p
from . import state as s


def cleanup(runner):
    # 仅处理本项目拥有的目录，不走进版本包、凭据或别人的目录。
    for directory in (p.RESCUE, p.ROOT, p.RELEASES, s.DATA):
        names = runner.list(directory)
        for name in sorted(names, reverse=True):
            if ".old-" not in name:
                continue
            target = directory + "/" + name.split(".old-", 1)[0]
            old = directory + "/" + name
            if not runner.exists(target):
                runner.replace(old, target)
            else:
                runner.remove_tree(old)
        for name in runner.list(directory):
            if name.endswith((".staging", ".rescue-staging", ".new")):
                runner.remove_tree(directory + "/" + name)


def checked(runner, argv):
    if runner.run(argv, timeout=30).code:
        raise OSError("本项目单元操作失败")


def restore(runner, *, required):
    if not runner.exists(p.LAST_GOOD) or not p.command(
            runner, [p.BINARY, "check", "-c", p.LAST_GOOD]):
        if required:
            raise ValueError("没有可校验通过的上次可用配置")
        return False
    temporary = p.LIVE + ".rescue.tmp"
    runner.write(temporary, runner.read(p.LAST_GOOD), 0o600)
    # 再查实际发布的副本，避免上次可用配置被并发改变。
    if not p.command(runner, [p.BINARY, "check", "-c", temporary]):
        runner.remove_tree(temporary)
        raise ValueError("上次可用配置校验失败")
    runner.replace(temporary, p.LIVE)
    return True


def reinstall(runner):
    version = p.release(runner, p.FACTORY)
    if version is None:
        raise ValueError("出厂包损坏")
    target = p.RELEASES + "/" + version
    if p.release(runner, target) != version:
        if runner.exists(target):
            runner.remove_tree(target)
        staging = target + ".rescue-staging"
        runner.remove_tree(staging)
        runner.mkdir(p.RELEASES, 0o755)
        runner.copy_tree(p.FACTORY, staging)
        if p.release(runner, staging) != version:
            raise ValueError("出厂包复制校验失败")
        runner.replace(staging, target)
    temporary = p.CURRENT + ".new"
    runner.remove_tree(temporary)
    runner.symlink(target, temporary)
    runner.replace(temporary, p.CURRENT)
    restore(runner, required=False)
    checked(runner, ["systemctl", "daemon-reload"])
    for unit in ("exitnode-proxy.service", "exitnode-admin.service", "exitnode-watchdog.timer"):
        checked(runner, ["systemctl", "restart", unit])
    after = p.probe(runner)
    if not all(after[key] for key in ("P1", "P2", "P3", "P4")):
        raise ValueError("重装后程序检查未通过")
    return version


def promote(runner):
    target = p.current(runner)
    version = p.release(runner, target) if target else None
    if version is None:
        raise ValueError("当前程序校验失败，未提升出厂包")
    staging = p.FACTORY + ".staging"
    runner.remove_tree(staging)
    runner.copy_tree(target, staging)
    if p.release(runner, staging) != version:
        raise ValueError("出厂包副本校验失败")
    runner.replace(staging, p.FACTORY)
    s.history(runner, "promote", "promoted", version)


def promotable(runner, watcher):
    target = p.current(runner)
    version = p.release(runner, target) if target else None
    if not version or version == p.release(runner, p.FACTORY) or not watcher:
        return False
    if watcher["state"] != "normal" or not 0 <= runner.now() - s.timestamp(watcher["updated_at"]) <= 600:
        return False
    try:
        rows = runner.read(p.UPDATES).splitlines()
    except OSError:
        return False
    for line in rows:
        try:
            row = json.loads(line)
            if (row["version"] == version and row["status"] == "ok"
                    and runner.now() - s.timestamp(row["at"]) >= 86400):
                return True
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
    return False


def limit(times, now, seconds, maximum):
    # 时钟倒退不重新获得额度。
    return sum(now - at < seconds for at in times) >= maximum


def tick(runner):
    value = s.fresh()
    action = "tick"
    try:
        if runner.lock_busy(p.LOCK):
            return 1  # 更新器持锁时整轮零写入，清理也延后。
        cleanup(runner)
        value = s.read(runner)
        if value["corrupt"]:
            s.save(runner, value)
            return 2
        result = p.probe(runner)
        watcher = p.watchdog(runner)
        value["watchdog_state"] = watcher["state"] if watcher else None
        new_round = s.count(value, result, runner.now())
        previous_state, previous_reason = value["state"], value["reason"]
        value.update(state="processing", reason="等待下一轮本地检查")
        counts = value["counts"]
        if all(result.values()):
            value.update(state="normal", reason="本地程序检查通过")
            if watcher and watcher["state"] == "manual":
                value["reason"] = "本地程序正常；看门狗需人工处理，救援不干预网络"
            elif new_round and promotable(runner, watcher):
                action = "promote"
                promote(runner)
                value["reason"] = "本地程序正常，已提升出厂包"
        elif watcher and watcher["state"] == "manual":
            value.update(state="manual", reason="看门狗需人工处理，救援只记录不动作")
        elif not new_round:
            if previous_state == "manual":
                value.update(state="manual", reason=previous_reason)
        elif any(counts[key] >= 2 for key in ("P1", "P2", "P3")):
            action = "reinstall"
            if p.release(runner, p.FACTORY) is None:
                raise ValueError("出厂包损坏")
            if (limit(value["reinstall_times"], runner.now(), 21600, 1)
                    or limit(value["reinstall_times"], runner.now(), 86400, 2)):
                raise ValueError("重装频率超限：六小时最多一次，二十四小时最多两次")
            value["reinstall_times"].append(runner.now())
            s.save(runner, value)  # 先占额度，失败或中断也计入。
            version = reinstall(runner)
            s.history(runner, action, "ok", version)
            value.update(state="normal", reason="已恢复出厂程序，复查通过")
            value["counts"] = s.fresh()["counts"]
        elif all(result[key] for key in ("P1", "P2", "P3")) and counts["P4"] >= 2:
            action = "restore"
            restore(runner, required=True)
            checked(runner, ["systemctl", "restart", "exitnode-proxy.service"])
            s.history(runner, action, "ok")
            value["reason"] = "已恢复上次可用配置，等待下轮检查"
        elif all(result[key] for key in ("P1", "P2", "P3", "P4")) and counts["P5"] >= 2:
            action = "restart"
            if limit(value["restart_times"], runner.now(), 3600, 1):
                raise ValueError("重启频率超限：一小时最多一次")
            value["restart_times"].append(runner.now())
            s.save(runner, value)
            checked(runner, ["systemctl", "reset-failed", "exitnode-proxy.service"])
            checked(runner, ["systemctl", "restart", "exitnode-proxy.service"])
            s.history(runner, action, "ok")
            value["reason"] = "已解除失败状态并重启，等待下轮检查"
        s.save(runner, value)
        return {"normal": 0, "processing": 1, "manual": 2}[value["state"]]
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        # 只允许自己生成的固定原因；系统异常和内核输出可能包含凭据。
        reason = str(exc) if type(exc) is ValueError else "救援文件或服务操作失败，请人工处理"
        value.update(state="manual", reason=reason)
        try:
            s.save(runner, value)
            s.history(runner, action, "failed")
        except OSError:
            pass  # 磁盘本身不可写时仍返回 manual，不能伪报已记录。
        return 2
