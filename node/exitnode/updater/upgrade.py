"""有锁的更新事务；所有主机操作、时间和等待均经 Runner。"""

import json
import re
from datetime import UTC, datetime

from ..log import redact
from . import layout, package
from .version import Version


class UpdateError(ValueError):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def _request(config, runner, url, output=None):
    argv = ["curl", "--silent", "--show-error", "--fail", "--location",
            "--connect-timeout", "5", "--max-time", "20", "--proto", "=https",
            "--proto-redir", "=https", "--write-out", "\n%{http_code}"]
    if output is not None:
        argv.extend(["--output", output, "-H", "Accept: application/octet-stream"])
    else:
        argv.extend(["-H", "Accept: application/vnd.github+json"])
    headers = None
    try:
        secret = config.node.secrets_dir + "/github-token"
        if runner.exists(secret):
            # 不缓存令牌，不拼入 URL 或错误消息，只在即将发出的请求头中使用。
            headers = "Authorization: Bearer " + runner.read_file(secret).strip()
            if any(ord(c) < 32 for c in headers):
                raise UpdateError("发布源令牌格式不正确，请检查令牌")
            headers += "\n"
            argv.extend(["-H", "@-"])
        argv.append(url)
        result = runner.run(argv, check=False, input=headers)
    except Exception:
        raise UpdateError("下载升级包失败：连不上发布源") from None
    finally:
        # 不在后续异常栈的局部参数中保留请求头。
        argv.clear()
        headers = None
    body, _, status = result.out.rpartition("\n")
    if status in {"401", "403"}:
        raise UpdateError("发布源拒绝访问，请检查令牌")
    if result.code:
        raise UpdateError("下载升级包失败：连不上发布源")
    if status != "200":
        raise UpdateError("下载升级包失败：发布源返回异常")
    return body


def _github(config, runner, destination):
    base = "https://api.github.com/repos/" + config.updater.github_repo
    try:
        release = json.loads(_request(config, runner, base + "/releases/latest"))
        version = str(Version(release["tag_name"]))
        name = "exitnode-" + version + ".tar.gz"
        assets = release["assets"]
        urls = []
        for expected in (name, name + ".sig"):
            matches = [a for a in assets if a.get("name") == expected]
            if len(matches) != 1:
                raise ValueError
            url = matches[0]["url"]
            if not re.fullmatch(re.escape(base) + r"/releases/assets/[0-9]+", url):
                raise ValueError
            urls.append(url)
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("发布源清单格式不正确，无法取得升级包") from None
    archive = destination + "/package.tar.gz"
    signature = archive + ".sig"
    _request(config, runner, urls[0], archive)
    _request(config, runner, urls[1], signature)
    return archive, signature, version


def _fetch(config, runner, file, signature):
    destination = layout.incoming(config)
    runner.mkdir(destination, 0o700)
    if file is None:
        return _github(config, runner, destination)
    # 先读完两份源文件，再写工作副本；同一校验入口处理推包和下载。
    data = runner.read_bytes(file)
    signed = runner.read_bytes(signature or file + ".sig")
    archive = destination + "/package.tar.gz"
    runner.write_bytes(archive, data, 0o600)
    runner.write_bytes(archive + ".sig", signed, 0o600)
    return archive, archive + ".sig", None


def _restart(runner):
    # 即使一个单元重启失败，也要尝试另一个；外层负责回退。
    failed = False
    for argv in (["systemctl", "restart", "exitnode-proxy.service"],
                 ["systemctl", "restart", "exitnode-admin.service"],
                 ["systemctl", "daemon-reload"]):
        try:
            failed = runner.run(argv, check=False).code != 0 or failed
        except Exception:
            failed = True
    if failed:
        raise UpdateError("本项目服务重启失败")


def _healthy(config, runner, config_path):
    deadline = runner.now() + config.updater.health_timeout_sec
    while runner.now() < deadline:
        try:
            # env 确保检查的是刚切换的程序，而非安装更新器时的旧进程路径。
            result = runner.run(["env", "PYTHONPATH=" + layout.root(config) + "/current",
                                 "python3", "-m", "exitnode", "--config", config_path,
                                 "check", "--json"], check=False,
                                 timeout=min(30, deadline - runner.now()))
            payload = json.loads(result.out)
            if (runner.now() <= deadline
                    and any(layer.get("name") == "隧道服务" and layer.get("result") == "通过"
                            for layer in payload["layers"])):
                return True
        except Exception:
            pass  # 单次探测失败仍在同一固定截止时间内继续。
        remaining = deadline - runner.now()
        if remaining <= 0:
            return False
        runner.sleep(min(5, remaining))
    return False


def _state_path(config, name):
    return config.node.data_dir.rstrip("/") + "/updater/" + name


def _highest(config, runner):
    try:
        return Version(json.loads(runner.read_file(_state_path(config, "highest.json")))["version"])
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        return None


def _record_highest(config, runner, old, version):
    highest = _highest(config, runner)
    value = max(Version(old.rsplit("/", 1)[-1]), Version(version))
    if highest is not None:
        value = max(highest, value)
    path = _state_path(config, "highest.json")
    runner.write_file(path + ".tmp", json.dumps({"version": str(value)}), 0o600)
    runner.replace(path + ".tmp", path)


def _check_downgrade(config, runner, candidate, current, allow_downgrade):
    highest = _highest(config, runner)
    floor = max(current, highest) if highest is not None else current
    if candidate < floor and not allow_downgrade:
        raise UpdateError(f"拒绝降级到 {candidate}：当前或已安装过的最高版本为 {floor}；"
                          "确需回退请加 --allow-downgrade", 1)


def _check_release(runner, target):
    if runner.exists(target + ".bad"):
        raise UpdateError("此版本已有失败标记，请联系维护人员")
    if not layout.valid_release(runner, target):
        raise UpdateError("已安装的同版本目录校验失败，请联系维护人员", 1)


def _history(config, runner, version, status):
    path = _state_path(config, "history.jsonl")
    previous = runner.read_file(path) if runner.exists(path) else ""
    row = {"version": version, "status": status,
           "at": datetime.fromtimestamp(runner.now(), UTC).isoformat()}
    runner.write_file(path + ".tmp", previous + json.dumps(row) + "\n", 0o600)
    runner.replace(path + ".tmp", path)


def _rollback(config, runner, old, target, version):
    layout.switch(config, runner, old)
    # 先落标记；重启失败仍能让下次启动避开这个版本。
    runner.write_file(target + ".bad", "健康检查或更新事务失败，已切回旧版\n", 0o600)
    try:
        _restart(runner)
    finally:
        _history(config, runner, version, "rolled_back")


def _recover(config, runner):
    path = _state_path(config, "pending.json")
    if not runner.exists(path):
        return
    try:
        pending = json.loads(runner.read_file(path))
        old, target = pending["old"], pending["target"]
        version = str(Version(pending["version"]))
        allowed = {p for _, p in layout.versions(config, runner)}
        if old not in allowed or target != layout.releases(config) + "/" + version:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise UpdateError("未完成更新的记录损坏，请联系维护人员") from None
    _rollback(config, runner, old, target, version)
    runner.remove(path)


def _install(config, runner, info, archive, config_path):
    target = layout.releases(config) + "/" + info.version
    staging = target + ".staging"
    old = layout.current_target(config, runner)
    runner.mkdir(layout.releases(config), 0o755)
    runner.mkdir(staging, 0o755)
    pending = _state_path(config, "pending.json")
    switched = False
    try:
        runner.extract_tar(archive, staging)
        if not layout.valid_release(runner, staging):
            raise UpdateError("解包后程序校验失败")
        runner.replace(staging, target)
        runner.write_file(pending + ".tmp", json.dumps({"old": old, "target": target,
                                                       "version": info.version}), 0o600)
        runner.replace(pending + ".tmp", pending)
        # replace 可能已经成功、但目录同步失败；此后任何异常均恢复旧链接。
        switched = True
        layout.switch(config, runner, target)
        _restart(runner)
        if not _healthy(config, runner, config_path):
            raise UpdateError("新版健康检查未通过")
        _history(config, runner, info.version, "ok")
        runner.remove(pending)
    except Exception:
        if switched:
            try:
                _rollback(config, runner, old, target, info.version)
                runner.remove(pending)
            except Exception:
                raise UpdateError("新版启动失败，自动恢复未全部完成，请联系维护人员") from None
            raise UpdateError("新版启动失败，已恢复旧版") from None
        raise UpdateError("升级包安装失败，当前版本未切换") from None
    finally:
        runner.remove_tree(staging)
    _record_highest(config, runner, old, info.version)


def _switch(config, runner, target, version, config_path):
    old = layout.current_target(config, runner)
    pending = _state_path(config, "pending.json")
    switched = False
    try:
        runner.write_file(pending + ".tmp", json.dumps({"old": old, "target": target,
                                                       "version": version}), 0o600)
        runner.replace(pending + ".tmp", pending)
        # 与安装路径一样，切换后的目录同步异常也必须回退。
        switched = True
        layout.switch(config, runner, target)
        _restart(runner)
        if not _healthy(config, runner, config_path):
            raise UpdateError("新版健康检查未通过")
        _history(config, runner, version, "ok")
        runner.remove(pending)
    except Exception:
        if switched:
            try:
                _rollback(config, runner, old, target, version)
                runner.remove(pending)
            except Exception:
                raise UpdateError("新版启动失败，自动恢复未全部完成，请联系维护人员") from None
            raise UpdateError("新版启动失败，已恢复旧版") from None
        raise UpdateError("程序切换失败，当前版本未切换") from None
    _record_highest(config, runner, old, version)
    print("切换完成，健康检查通过。")


def _switch_requested(config, runner, switch, current, allow_downgrade, check, config_path):
    try:
        candidate = Version(switch)
    except ValueError:
        raise UpdateError("版本号格式不正确", 1) from None
    target = next((path for version, path in layout.versions(config, runner)
                   if version == candidate), None)
    if target is None:
        raise UpdateError("目标版本未安装，无法切换", 1)
    if candidate == current:
        raise UpdateError("该版本已是当前版本，无需切换", 1)
    _check_release(runner, target)
    _check_downgrade(config, runner, candidate, current, allow_downgrade)
    # 沿用真实目录名，保证恢复记录与现有目录布局一致。
    version = target.rsplit("/", 1)[-1]
    if check:
        print(f"可以切换到 {version}，未执行。")
    else:
        _switch(config, runner, target, version, config_path)
    return 0


def upgrade(config, runner, *, file=None, signature=None, check=False,
            config_path="/etc/exitnode/config.toml", allow_downgrade=False, switch=None):
    """返回命令退出码；错误不回显主机命令输出或第三方异常。"""
    locked = False
    lock = config.node.data_dir.rstrip("/") + "/updater.lock"
    try:
        if not switch and file is None and config.updater.source == "none":
            raise UpdateError("未配置更新来源，只能使用 --file 指定升级包")
        if runner.lock_busy(lock):
            raise UpdateError("已有更新任务正在执行，请稍后重试", 4)
        # 断网必须零文件变更，所以锁、修复和清理均排在探测之后。
        if not switch and not any(runner.tcp_connect(host, 443, 3)
                                  for host in config.network.probe_targets):
            raise UpdateError("网络不可用，稍后重试", 3)
        runner.mkdir(config.node.data_dir, 0o700)
        if not runner.acquire_lock(lock):
            raise UpdateError("已有更新任务正在执行，请稍后重试", 4)
        locked = True
        runner.mkdir(_state_path(config, "").rstrip("/"), 0o700)
        _recover(config, runner)
        layout.repair(config, runner)
        layout.cleanup(config, runner)
        current = Version(layout.current_target(config, runner).rsplit("/", 1)[-1])
        if switch:
            return _switch_requested(config, runner, switch, current, allow_downgrade,
                                     check, config_path)
        archive, signed, tag_version = _fetch(config, runner, file, signature)
        data, signed_data = runner.read_bytes(archive), runner.read_bytes(signed)
        try:
            info = package.verify(data, signed_data, config.node.config_version)
        except ValueError as exc:
            raise UpdateError(str(exc)) from None
        candidate = Version(info.version)
        if tag_version is not None and Version(tag_version) != candidate:
            raise UpdateError("发布源标签版本与升级包内版本不一致，拒绝安装", 1)
        if candidate == current:
            raise UpdateError("同版本程序已经安装，拒绝重复升级")
        _check_downgrade(config, runner, candidate, current, allow_downgrade)
        if runner.exists(layout.releases(config) + "/" + info.version + ".bad"):
            raise UpdateError("此版本已有失败标记，请联系维护人员")
        target = next((path for version, path in layout.versions(config, runner)
                       if version == candidate), None)
        if target is not None:
            _check_release(runner, target)
            installed = json.loads(runner.read_file(target + "/manifest.json"))
            if installed["files"] != info.manifest["files"]:
                raise UpdateError("同版本程序已安装但内容不同，请联系维护人员；已有版本未覆盖", 1)
            if check:
                print("升级包检查通过，未安装。")
            else:
                _switch(config, runner, target, target.rsplit("/", 1)[-1], config_path)
            return 0
        if runner.disk_free(layout.root(config)) < info.size * 2 + 50 * 1024 * 1024:
            raise UpdateError("磁盘空间不足，未安装升级包")
        if check:
            print("升级包检查通过，未安装。")
        else:
            _install(config, runner, info, archive, config_path)
            print("升级完成，健康检查通过。")
        return 0
    except UpdateError as exc:
        print(redact(str(exc)))
        return exc.code
    except Exception:
        print("更新失败：程序或文件操作异常，请联系维护人员。")
        return 1
    finally:
        if locked:
            try:
                runner.remove_tree(layout.incoming(config))
            finally:
                runner.release_lock(lock)
