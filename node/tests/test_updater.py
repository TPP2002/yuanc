"""更新事务使用内存主机、内存包和本次测试生成的签名密钥。"""

import hashlib
import io
import json
import tarfile
import traceback

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from exitnode import runner as runner_module
from exitnode.cli import main
from exitnode.config import load
from exitnode.runner import CompletedResult, FakeRunner
from exitnode.updater import layout, package, trust
from exitnode.updater.upgrade import UpdateError, _healthy, _request, _restart, recover, upgrade
from exitnode.updater.version import Version
from test_cli import CONFIG, TEXT

ROOT = "/opt/exitnode"
RELEASES = ROOT + "/releases"
OLD = RELEASES + "/0.1.0"
NEW = RELEASES + "/0.2.0"
CURRENT = ROOT + "/current"
DATA = "/var/lib/exitnode"
INCOMING = DATA + "/updater/incoming"
LOCK = DATA + "/updater.lock"
HEALTH = ("env", "PYTHONPATH=" + CURRENT, "python3", "-P", "-m", "exitnode")
IS_ACTIVE = ("systemctl", "is-active", "exitnode-proxy.service")
NRESTARTS = ("systemctl", "show", "exitnode-proxy.service", "-p", "NRestarts", "--value")


def archive_bytes(version="0.2.0", *, minimum=1, corrupt_hash=False, extra=None,
                  min_missing=False, link=False):
    files = {"exitnode/__init__.py": f'__version__ = "{version}"\n'.encode(),
             "exitnode/__main__.py": b"from .cli import main\n",
             "exitnode/templates/exitnode-admin.service": b"[Service]\n",
             "bin/sing-box": b"linux-test-binary"}
    if extra:
        files.update(extra)
    manifest = {"version": version, "min_config_version": minimum,
                "sing_box_version": "1.12.0", "built_at": "2026-10-22T00:00:00Z",
                "files": {p: hashlib.sha256(data).hexdigest() for p, data in files.items()}}
    if min_missing:
        del manifest["min_config_version"]
    if corrupt_hash:
        manifest["files"]["bin/sing-box"] = "0" * 64
    files["manifest.json"] = json.dumps(manifest).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == "bin/sing-box" else 0o644
            archive.addfile(info, io.BytesIO(data))
        if link:
            info = tarfile.TarInfo("exitnode/escape")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc"
            archive.addfile(info)
    return stream.getvalue()


def put_release(runner, version):
    directory = RELEASES + "/" + version
    runner.mkdir(directory, 0o755)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes(version)), mode="r:gz") as archive:
        for item in archive:
            runner.files[directory + "/" + item.name] = archive.extractfile(item).read()
    return directory


@pytest.fixture
def signing(monkeypatch):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(trust, "PUBLIC_KEY", public)
    return key


def prepared(signing, **package_options):
    runner = FakeRunner(files={CONFIG: TEXT}, connections={("1.1.1.1", 443): True},
                        responses={("systemctl",): CompletedResult(), HEALTH: CompletedResult(
                            out=json.dumps({"layers": [{"name": "隧道服务", "result": "通过"}]})),
                            IS_ACTIVE: CompletedResult(0, "active\n")})
    put_release(runner, "0.1.0")
    runner.symlink(OLD, CURRENT)
    data = archive_bytes(**package_options)
    runner.files["/push/update.tar.gz"] = data
    runner.files["/push/update.tar.gz.sig"] = signing.sign(data)
    runner.calls.clear()
    return load(CONFIG, runner), runner


def run(config, runner, **options):
    return upgrade(config, runner, file="/push/update.tar.gz", **options)


def release_snapshot(runner):
    return ({p: v for p, v in runner.files.items() if p.startswith(RELEASES + "/")},
            {p for p in runner.directories if p.startswith(RELEASES + "/")})


def assert_clean(runner):
    assert not any(p.startswith(INCOMING) for p in runner.files)
    assert not any(p.startswith(INCOMING) for p in runner.directories)
    assert not any(p.endswith(".staging") for p in runner.directories)
    assert LOCK not in runner.files


@pytest.mark.parametrize("reason", ["signature", "hash", "compatibility", "same", "space"])
def test_rejected_package_never_writes_releases(signing, reason, capsys):
    options = {"corrupt_hash": reason == "hash", "minimum": 2 if reason == "compatibility" else 1,
               "version": "0.1.0" if reason == "same" else "0.2.0"}
    config, runner = prepared(signing, **options)
    if reason == "signature":
        runner.files["/push/update.tar.gz.sig"] = b"wrong"
    if reason == "space":
        runner.free_bytes = 0
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert release_snapshot(runner) == before
    assert runner.readlink(CURRENT) == OLD
    assert not any(c[0] in {"write_file", "write_bytes", "mkdir", "extract_tar", "replace"}
                   and any(isinstance(v, str) and v.startswith(RELEASES + "/") for v in c[1:])
                   for c in runner.calls)
    assert_clean(runner)
    if reason == "compatibility":
        assert "要求配置格式版本 ≥ 2，当前为 1，请先升级配置" in capsys.readouterr().out


def test_success_switches_atomically_restarts_records_and_cleans(signing):
    config, runner = prepared(signing)
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert runner.read_bytes(CURRENT + "/bin/sing-box") == b"linux-test-binary"
    assert runner.modes[NEW + "/bin/sing-box"] == 0o755
    assert ("symlink", NEW, CURRENT + ".new") in runner.calls
    assert ("replace", CURRENT + ".new", CURRENT) in runner.calls
    commands = [c[1] for c in runner.calls if c[0] == "run"]
    for unit in ("exitnode-proxy.service", "exitnode-admin.service"):
        assert ("systemctl", "restart", unit) in commands
    assert ("systemctl", "daemon-reload") in commands
    assert commands[-1] == (*HEALTH, "--config", CONFIG, "check", "--json")
    health = commands[-1]
    assert health[health.index("python3") + 1:health.index("python3") + 3] == ("-P", "-m")
    history = runner.read_file(DATA + "/updater/history.jsonl").splitlines()
    assert len(history) == 1 and json.loads(history[0])["status"] == "ok"
    assert_clean(runner)


@pytest.mark.parametrize("failure", ["health", "restart", "invalid-json"])
def test_failure_restores_old_and_marks_bad(signing, failure):
    config, runner = prepared(signing)
    config.updater.health_timeout_sec = 10
    runner.responses[HEALTH] = CompletedResult(out="not-json" if failure == "invalid-json"
                                              else '{"layers":[]}')
    if failure == "restart":
        runner.responses[("systemctl", "restart", "exitnode-proxy.service")] = [
            CompletedResult(1), CompletedResult()]
    assert run(config, runner) == 1
    assert runner.readlink(CURRENT) == OLD
    assert NEW + ".bad" in runner.files
    commands = [c[1] for c in runner.calls if c[0] == "run"]
    for unit in ("exitnode-proxy.service", "exitnode-admin.service"):
        assert commands.count(("systemctl", "restart", unit)) == 2
    assert json.loads(runner.read_file(DATA + "/updater/history.jsonl"))["status"] == "rolled_back"
    assert sum(c[1] for c in runner.calls if c[0] == "sleep") <= 10
    assert_clean(runner)


def test_network_offline_does_not_mutate_any_files_even_stale_scratch(signing):
    config, runner = prepared(signing)
    runner.connections.clear()
    runner.files[INCOMING + "/old"] = b"leftover"
    runner.mkdir(NEW + ".staging")
    before = dict(runner.files), set(runner.directories), dict(runner.links), dict(runner.modes)
    assert run(config, runner) == 3
    assert (runner.files, runner.directories, runner.links, runner.modes) == before


@pytest.mark.parametrize("age,alive,expected", [(7201, False, 0), (7200, False, 4),
                                               (7201, True, 4), (0, True, 4)])
def test_stale_lock_requires_both_age_and_dead_pid(signing, age, alive, expected):
    config, runner = prepared(signing)
    runner.files[LOCK] = json.dumps({"pid": 200, "at": runner.now() - age})
    if alive:
        runner.live_pids.add(200)
    assert run(config, runner) == expected
    if expected == 0:
        assert_clean(runner)
    else:
        assert not any(c[0] == "sleep" for c in runner.calls)
        assert runner.readlink(CURRENT) == OLD


def test_second_upgrade_cannot_clean_first_upgrade_files(signing, monkeypatch):
    config, runner = prepared(signing)
    original = runner.extract_tar
    results = []

    def extract(archive, destination):
        before = dict(runner.files)
        probes = sum(c[0] == "tcp_connect" for c in runner.calls)
        results.append(run(config, runner))
        assert runner.files == before
        assert sum(c[0] == "tcp_connect" for c in runner.calls) == probes
        original(archive, destination)

    monkeypatch.setattr(runner, "extract_tar", extract)
    assert run(config, runner) == 0
    assert results == [4]


def test_cleanup_staging_and_incoming_before_new_attempt(signing):
    config, runner = prepared(signing)
    runner.files[INCOMING + "/leftover"] = b"old"
    runner.mkdir(RELEASES + "/0.9.0.staging")
    runner.files[RELEASES + "/0.9.0.staging/partial"] = b"old"
    assert run(config, runner) == 0
    assert not runner.exists(RELEASES + "/0.9.0.staging")
    assert_clean(runner)


def test_dangling_current_repairs_latest_good_pep440_version(signing):
    config, runner = prepared(signing)
    put_release(runner, "0.9.0")
    expected = put_release(runner, "0.10.0")
    bad = put_release(runner, "0.11.0")
    runner.files[bad + ".bad"] = "bad"
    runner.links[CURRENT] = RELEASES + "/missing"
    assert layout.repair(config, runner)
    assert runner.readlink(CURRENT) == expected


def test_killed_after_switch_completes_when_healthy(signing, capsys):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    runner.links[CURRENT] = NEW
    # 旧记录没有 stage 字段，按已切换处理；现场健康检查通过即转正。
    runner.files[DATA + "/updater/pending.json"] = json.dumps({
        "old": OLD, "target": NEW, "version": "0.2.0"})
    assert run(config, runner) == 1  # 收尾转正后，同版本已是当前版本，拒绝再次安装。
    assert "同版本程序已经安装" in capsys.readouterr().out
    assert runner.readlink(CURRENT) == NEW and NEW + ".bad" not in runner.files
    assert DATA + "/updater/pending.json" not in runner.files
    history = runner.read_file(DATA + "/updater/history.jsonl").splitlines()
    assert json.loads(history[-1])["status"] == "ok"
    assert json.loads(runner.read_file(DATA + "/updater/highest.json")) == {"version": "0.2.0"}


@pytest.mark.parametrize("options", [{"extra": {"../outside": b"bad"}},
                                      {"extra": {"/etc/escape": b"bad"}}, {"link": True}])
def test_unsafe_archive_rejected_before_extract(signing, options):
    config, runner = prepared(signing, **options)
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert release_snapshot(runner) == before
    assert not any(c[0] == "extract_tar" for c in runner.calls)
    assert_clean(runner)


def test_file_parent_conflict_rejected_before_writing_releases(signing):
    config, runner = prepared(signing, extra={"manifest.json/child": b"conflict"})
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert release_snapshot(runner) == before
    assert not any(c[0] == "extract_tar" for c in runner.calls)


def test_health_timeout_bounds_even_the_last_system_command(signing, monkeypatch):
    config, runner = prepared(signing)
    config.updater.health_timeout_sec = 7
    original = runner.run
    timeouts = []

    def run_slow(argv, check=True, input=None, timeout=30):
        if tuple(argv[:len(HEALTH)]) == HEALTH:
            timeouts.append(timeout)
            runner.clock += timeout
            raise TimeoutError("模拟命令挂起")
        return original(argv, check, input, timeout)

    monkeypatch.setattr(runner, "run", run_slow)
    before = runner.clock
    assert run(config, runner) == 1
    assert runner.clock - before == 7 and timeouts == [7]
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files


def test_failure_after_link_replace_also_restores_old(signing, monkeypatch):
    config, runner = prepared(signing)
    original = runner.replace
    failed_once = False

    def replace(source, target):
        nonlocal failed_once
        original(source, target)
        if target == CURRENT and not failed_once:
            failed_once = True
            raise OSError("模拟切换后目录同步失败")

    monkeypatch.setattr(runner, "replace", replace)
    assert run(config, runner) == 1
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files


def test_extraction_failure_cleans_partial_directory_without_switch(signing, monkeypatch):
    config, runner = prepared(signing)

    def fail(archive, directory):
        runner.write_bytes(directory + "/partial", b"partial")
        raise OSError("模拟写盘失败")

    monkeypatch.setattr(runner, "extract_tar", fail)
    assert run(config, runner) == 1
    assert runner.readlink(CURRENT) == OLD
    assert not runner.exists(NEW)
    assert_clean(runner)


@pytest.mark.parametrize("minimum,missing", [(None, True), (0, False), (-1, False),
                                           (True, False), ("1", False), (1.0, False)])
def test_min_config_version_is_required_positive_integer(signing, minimum, missing, capsys):
    config, runner = prepared(signing, minimum=minimum, min_missing=missing)
    assert run(config, runner) == 1
    assert "清单格式不正确" in capsys.readouterr().out
    assert_clean(runner)


def test_old_config_without_version_defaults_to_one_and_can_upgrade(signing):
    _, runner = prepared(signing)
    runner.files[CONFIG] = TEXT.replace("config_version = 1\n", "")
    config = load(CONFIG, runner)
    assert config.node.config_version == 1
    assert run(config, runner) == 0


def test_explicit_config_version_two_accepts_new_format(signing):
    _, runner = prepared(signing, minimum=2)
    runner.files[CONFIG] = TEXT.replace("config_version = 1", "config_version = 2")
    assert run(load(CONFIG, runner), runner) == 0


def test_check_verifies_without_installing(signing):
    config, runner = prepared(signing)
    before = release_snapshot(runner)
    assert run(config, runner, check=True) == 0
    assert release_snapshot(runner) == before and runner.readlink(CURRENT) == OLD
    assert not any(c[0] == "run" for c in runner.calls)
    assert_clean(runner)


@pytest.mark.parametrize("output", [None, INCOMING + "/package.tar.gz"])
def test_github_token_only_passed_via_stdin(signing, output):
    config, runner = prepared(signing)
    token = "GHTOKEN-STDIN-ONLY"
    runner.files[config.node.secrets_dir + "/github-token"] = token
    runner.responses[("curl",)] = CompletedResult(out="body\n200")
    assert _request(config, runner, "https://api.github.com/repos/owner/repo/releases/latest",
                    output) == "body"
    calls = [call for call in runner.calls if call[0] == "run"]
    assert len(calls) == 1
    _, argv, check, input = calls[0]
    assert all("Bearer" not in arg and token not in arg for arg in argv)
    assert any(argv[i:i + 2] == ("-H", "@-") for i in range(len(argv) - 1))
    assert input == "Authorization: Bearer " + token + "\n"
    assert check is False


def test_github_without_token_has_no_stdin_header(signing):
    config, runner = prepared(signing)
    assert not runner.exists(config.node.secrets_dir + "/github-token")
    runner.responses[("curl",)] = CompletedResult(out="body\n200")
    assert _request(config, runner,
                    "https://api.github.com/repos/owner/repo/releases/latest") == "body"
    calls = [call for call in runner.calls if call[0] == "run"]
    assert len(calls) == 1
    _, argv, check, input = calls[0]
    assert "@-" not in argv
    assert input is None
    assert check is False


@pytest.mark.parametrize("failure", ["401", "connect"])
def test_github_token_never_in_output_logs_exceptions_or_state(signing, failure, capsys, caplog):
    config, runner = prepared(signing)
    config.updater.source, config.updater.github_repo = "github", "owner/repo"
    token = "GHTOKEN-DO-NOT-LEAK"
    secret = config.node.secrets_dir + "/github-token"
    runner.files[secret] = token
    runner.responses[("curl",)] = (CompletedResult(22, out=token + "\n401", err=token)
                                    if failure == "401" else OSError(token))
    with pytest.raises(UpdateError) as error:
        _request(config, runner, "https://api.github.com/repos/owner/repo/releases/latest")
    assert token not in "".join(traceback.format_exception(error.value))
    assert upgrade(config, runner) == 1
    output = capsys.readouterr()
    assert token not in output.out + output.err + caplog.text
    for path, content in runner.files.items():
        if path != secret and isinstance(content, str):
            assert token not in content
    assert_clean(runner)


def test_github_downloads_matching_assets_then_uses_same_verifier(signing, monkeypatch):
    config, runner = prepared(signing)
    config.updater.source, config.updater.github_repo = "github", "owner/repo"
    base = "https://api.github.com/repos/owner/repo/releases/"
    metadata = {"tag_name": "v0.2.0", "assets": [
        {"name": "exitnode-0.2.0.tar.gz", "url": base + "assets/1"},
        {"name": "exitnode-0.2.0.tar.gz.sig", "url": base + "assets/2"}]}
    original = runner.run

    def request(argv, check=True, input=None, timeout=30):
        if argv[0] != "curl":
            return original(argv, check, input, timeout)
        runner.calls.append(("run", tuple(argv), check, input))
        if argv[-1].endswith("latest"):
            return CompletedResult(out=json.dumps(metadata) + "\n200")
        suffix = ".sig" if argv[-1].endswith("/2") else ""
        runner.write_bytes(argv[argv.index("--output") + 1],
                           runner.read_bytes("/push/update.tar.gz" + suffix))
        return CompletedResult(out="\n200")

    monkeypatch.setattr(runner, "run", request)
    assert upgrade(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW


def test_signature_modified_package_rejected(signing):
    data = archive_bytes()
    signature = signing.sign(data)
    assert package.verify(data, signature).version == "0.2.0"
    with pytest.raises(ValueError, match="签名"):
        package.verify(data[:-1] + bytes([data[-1] ^ 1]), signature)


@pytest.mark.parametrize("left,right", [("1.9", "1.10"), ("1.dev1", "1a1"),
                                        ("1a1", "1b1"), ("1rc1", "1"),
                                        ("1", "1.post1"), ("1.post1.dev1", "1.post1"),
                                        ("1+abc", "1+2"), ("9.9", "1!1.0")])
def test_pep440_order(left, right):
    assert Version(left) < Version(right)
    assert Version("v1.0.0") == Version("1")


def test_bootstrap_same_hash_idempotent_and_changed_hash_refused(signing, monkeypatch):
    config, runner = prepared(signing)
    source = "/running/exitnode"
    monkeypatch.setattr(layout, "running_package", lambda: source)
    runner.files[source + "/__init__.py"] = b"original"
    runner.remove_tree(OLD)
    runner.remove(CURRENT)
    runner.files[config.proxy.binary] = b"kernel"
    layout.bootstrap(config, runner)
    before = dict(runner.files)
    layout.bootstrap(config, runner)
    assert runner.files == before
    runner.files[source + "/__init__.py"] = b"changed"
    with pytest.raises(ValueError, match="同版本"):
        layout.bootstrap(config, runner)
    assert runner.files[OLD + "/exitnode/__init__.py"] == b"original"


def test_cli_file_and_check(signing):
    _, runner = prepared(signing)
    assert main(["upgrade", "--file", "/push/update.tar.gz", "--check"], runner) == 0
    assert runner.readlink(CURRENT) == OLD
    assert main(["upgrade", "--file", "/push/update.tar.gz"], runner) == 0
    assert runner.readlink(CURRENT) == NEW


@pytest.mark.parametrize("available", ["/usr/bin/sing-box", "/usr/local/bin/sing-box", None])
def test_bootstrap_default_binary_fallback(signing, monkeypatch, available):
    config, runner = prepared(signing)
    runner.files[CONFIG] = runner.files[CONFIG].replace('binary = "/usr/bin/sing-box"', "")
    config = load(CONFIG, runner)
    source = "/running/exitnode"
    monkeypatch.setattr(layout, "running_package", lambda: source)
    runner.files[source + "/__init__.py"] = b"original"
    runner.remove_tree(OLD)
    runner.remove(CURRENT)
    if available:
        runner.files[available] = b"fallback-kernel"
        layout.bootstrap(config, runner)
        assert runner.read_bytes(CURRENT + "/bin/sing-box") == b"fallback-kernel"
    else:
        before = dict(runner.files)
        with pytest.raises(ValueError, match="未找到 sing-box"):
            layout.bootstrap(config, runner)
        assert runner.files == before


def test_upgrade_never_changes_independent_rescue(signing):
    config, runner = prepared(signing)
    runner.files["/opt/exitnode-rescue/exitnode_rescue/runner.py"] = b"independent-code"
    runner.files["/opt/exitnode-rescue/factory/manifest.json"] = b"independent-factory"
    before = {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")}
    assert run(config, runner) == 0
    assert {p: v for p, v in runner.files.items() if p.startswith("/opt/exitnode-rescue/")} == before


HIGHEST = DATA + "/updater/highest.json"
PENDING = DATA + "/updater/pending.json"


def assert_releases_untouched(runner, before):
    assert release_snapshot(runner) == before
    assert not any(c[0] in {"write_file", "write_bytes", "mkdir", "extract_tar", "replace"}
                   and any(isinstance(v, str) and v.startswith(RELEASES + "/") for v in c[1:])
                   for c in runner.calls)
    assert_clean(runner)


def test_downgrade_rejected_without_writing_releases(signing, capsys):
    config, runner = prepared(signing, version="0.0.9")
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert "降级" in capsys.readouterr().out
    assert runner.readlink(CURRENT) == OLD
    assert_releases_untouched(runner, before)


def test_allowed_downgrade_preserves_old_floor_for_next_package(signing, capsys):
    config, runner = prepared(signing, version="0.0.9")
    assert run(config, runner, allow_downgrade=True) == 0
    assert runner.readlink(CURRENT) == RELEASES + "/0.0.9"
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.1.0"}
    data = archive_bytes("0.0.9.post1")
    runner.files["/push/update.tar.gz"] = data
    runner.files["/push/update.tar.gz.sig"] = signing.sign(data)
    runner.calls.clear()
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert "降级" in capsys.readouterr().out
    assert_releases_untouched(runner, before)


def test_success_records_highest_atomically_and_privately(signing):
    config, runner = prepared(signing)
    assert run(config, runner) == 0
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.2.0"}
    assert runner.modes[HIGHEST] == 0o600
    assert ("replace", HIGHEST + ".tmp", HIGHEST) in runner.calls
    assert not runner.exists(HIGHEST + ".tmp")
    assert_clean(runner)


def test_historical_highest_gates_install_and_never_decreases(signing, capsys):
    config, runner = prepared(signing)
    runner.files[HIGHEST] = json.dumps({"version": "0.3.0"})
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert "降级" in capsys.readouterr().out
    assert_releases_untouched(runner, before)
    assert run(config, runner, allow_downgrade=True) == 0
    assert runner.readlink(CURRENT) == NEW
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.3.0"}
    assert_clean(runner)


@pytest.mark.parametrize("content", ["broken-json", '{"version":"invalid"}', "[]",
                                     "null", "{}", '{"version":12}'])
def test_invalid_highest_is_ignored(signing, content):
    config, runner = prepared(signing)
    runner.files[HIGHEST] = content
    assert run(config, runner) == 0
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.2.0"}
    assert_clean(runner)


def test_github_tag_and_package_version_must_match(signing, monkeypatch, capsys):
    config, runner = prepared(signing)
    config.updater.source, config.updater.github_repo = "github", "owner/repo"
    base = "https://api.github.com/repos/owner/repo/releases/"
    metadata = {"tag_name": "v0.3.0", "assets": [
        {"name": "exitnode-0.3.0.tar.gz", "url": base + "assets/1"},
        {"name": "exitnode-0.3.0.tar.gz.sig", "url": base + "assets/2"}]}
    original = runner.run

    def request(argv, check=True, input=None, timeout=30):
        if argv[0] != "curl":
            return original(argv, check, input, timeout)
        runner.calls.append(("run", tuple(argv), check, input))
        if argv[-1].endswith("latest"):
            return CompletedResult(out=json.dumps(metadata) + "\n200")
        suffix = ".sig" if argv[-1].endswith("/2") else ""
        runner.write_bytes(argv[argv.index("--output") + 1],
                           runner.read_bytes("/push/update.tar.gz" + suffix))
        return CompletedResult(out="\n200")

    monkeypatch.setattr(runner, "run", request)
    before = release_snapshot(runner)
    assert upgrade(config, runner) == 1
    assert "不一致" in capsys.readouterr().out
    assert_releases_untouched(runner, before)


def test_existing_complete_package_switches_without_extracting(signing, capsys):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    runner.calls.clear()
    before = release_snapshot(runner)
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert_releases_untouched(runner, before)
    commands = [c[1] for c in runner.calls if c[0] == "run"]
    for unit in ("exitnode-proxy.service", "exitnode-admin.service"):
        assert ("systemctl", "restart", unit) in commands
    assert (*HEALTH, "--config", CONFIG, "check", "--json") in commands
    assert json.loads(runner.read_file(DATA + "/updater/history.jsonl"))['status'] == "ok"
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.2.0"}
    assert not runner.exists(PENDING)
    assert "切换完成" in capsys.readouterr().out


@pytest.mark.parametrize("damage,message", [("different", "内容不同"), ("missing", "校验失败"),
                                            ("bad", "失败标记")])
def test_existing_package_refuses_changed_incomplete_or_bad_release(signing, damage, message, capsys):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    if damage == "different":
        runner.files[NEW + "/bin/sing-box"] = b"different-binary"
        manifest = json.loads(runner.read_file(NEW + "/manifest.json"))
        manifest["files"]["bin/sing-box"] = hashlib.sha256(b"different-binary").hexdigest()
        runner.files[NEW + "/manifest.json"] = json.dumps(manifest)
        assert layout.valid_release(runner, NEW)
    elif damage == "missing":
        del runner.files[NEW + "/bin/sing-box"]
    else:
        runner.files[NEW + ".bad"] = "失败"
    runner.calls.clear()
    before = release_snapshot(runner)
    assert run(config, runner) == 1
    assert message in capsys.readouterr().out
    assert runner.readlink(CURRENT) == OLD
    assert_releases_untouched(runner, before)


@pytest.mark.parametrize("explicit", [False, True])
def test_switch_health_failure_rolls_back_and_marks_bad(signing, explicit, capsys):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    config.updater.health_timeout_sec = 5
    runner.responses[HEALTH] = CompletedResult(out='{"layers":[]}')
    result = upgrade(config, runner, switch="0.2.0") if explicit else run(config, runner)
    assert result == 1
    assert "新版启动失败，已恢复旧版" in capsys.readouterr().out
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files
    assert json.loads(runner.read_file(DATA + "/updater/history.jsonl"))["status"] == "rolled_back"
    assert not runner.exists(PENDING)
    assert not runner.exists(HIGHEST)
    assert_clean(runner)


def test_cli_switch_works_offline_without_source_or_package(signing, capsys):
    _, runner = prepared(signing)
    put_release(runner, "0.2.0")
    runner.connections.clear()
    del runner.files["/push/update.tar.gz"]
    del runner.files["/push/update.tar.gz.sig"]
    runner.calls.clear()
    before = release_snapshot(runner)
    assert main(["upgrade", "--switch", "0.2.0"], runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert not any(c[0] == "tcp_connect" or c[0] == "run" and c[1][0] == "curl"
                   for c in runner.calls)
    assert "切换完成" in capsys.readouterr().out
    assert_releases_untouched(runner, before)


def test_restart_try_restarts_console_without_failing_upgrade(signing):
    console = ("systemctl", "try-restart", "exitnode-console.service")
    config, runner = prepared(signing)
    runner.responses[console] = CompletedResult(5)
    _restart(runner)
    assert console in [c[1] for c in runner.calls if c[0] == "run"]
    # 退出码非 0 只影响网页自己，升级照常成功。
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW

    config, runner = prepared(signing)
    runner.responses[console] = OSError("模拟命令失败")
    _restart(runner)
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW

    # 隧道与托管服务重启失败仍然报错，不受管理网页影响。
    _, runner = prepared(signing)
    runner.responses[("systemctl", "restart", "exitnode-admin.service")] = CompletedResult(1)
    with pytest.raises(UpdateError, match="重启失败"):
        _restart(runner)

    _, runner = prepared(signing)
    runner.responses[("systemctl", "restart", "exitnode-proxy.service")] = OSError("模拟命令失败")
    with pytest.raises(UpdateError, match="重启失败"):
        _restart(runner)


@pytest.mark.parametrize("target,damage,message", [
    ("0.3.0", None, "未安装"), ("0.1.0", None, "已是当前"),
    ("invalid", None, "版本号格式不正确"), ("0.2.0", "bad", "失败标记"),
    ("0.2.0", "missing", "校验失败"), ("0.3.0", "link", "未安装")])
def test_switch_target_validation(signing, target, damage, message, capsys):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    if damage == "bad":
        runner.files[NEW + ".bad"] = "失败"
    elif damage == "missing":
        del runner.files[NEW + "/bin/sing-box"]
    elif damage == "link":
        runner.symlink(NEW, RELEASES + "/0.3.0")
    runner.calls.clear()
    before = release_snapshot(runner)
    assert upgrade(config, runner, switch=target) == 1
    assert message in capsys.readouterr().out
    assert runner.readlink(CURRENT) == OLD
    assert_releases_untouched(runner, before)


def test_cli_switch_downgrade_requires_flag_and_preserves_floor(signing, capsys):
    _, runner = prepared(signing)
    target = put_release(runner, "0.0.9")
    runner.calls.clear()
    before = release_snapshot(runner)
    assert main(["upgrade", "--switch", "0.0.9"], runner) == 1
    assert "降级" in capsys.readouterr().out
    assert_releases_untouched(runner, before)
    assert main(["upgrade", "--switch", "0.0.9", "--allow-downgrade"], runner) == 0
    assert runner.readlink(CURRENT) == target
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.1.0"}
    assert runner.modes[HIGHEST] == 0o600
    assert_clean(runner)


@pytest.mark.parametrize("option", ["--file", "--signature"])
def test_cli_switch_rejects_package_options_without_system_calls(option, capsys):
    runner = FakeRunner()
    assert main(["upgrade", "--switch", "0.2.0", option, "/unused"], runner) == 2
    assert "--switch 不能与 --file 或 --signature 同时使用" in capsys.readouterr().err
    assert runner.calls == []


def test_cli_switch_check_does_not_restart_or_change_current(signing, capsys):
    _, runner = prepared(signing)
    put_release(runner, "0.2.0")
    runner.calls.clear()
    before = release_snapshot(runner)
    assert main(["upgrade", "--switch", "0.2.0", "--check"], runner) == 0
    assert "可以切换到 0.2.0，未执行。" in capsys.readouterr().out
    assert runner.readlink(CURRENT) == OLD
    assert not any(c[0] == "run" for c in runner.calls)
    assert not runner.exists(HIGHEST)
    assert not runner.exists(PENDING)
    assert_releases_untouched(runner, before)


CHECK = (*HEALTH, "--config", CONFIG, "check", "--json")
HISTORY = DATA + "/updater/history.jsonl"
RESTART = ("systemctl", "restart", "exitnode-proxy.service")


def put_pending(runner, stage=None, current=NEW):
    put_release(runner, "0.2.0")
    runner.links[CURRENT] = current
    record = {"old": OLD, "target": NEW, "version": "0.2.0"}
    if stage is not None:
        record["stage"] = stage
    runner.files[PENDING] = json.dumps(record)
    runner.calls.clear()


def statuses(runner):
    return [json.loads(line)["status"] for line in runner.read_file(HISTORY).splitlines()]


def commands(runner):
    return [c[1] for c in runner.calls if c[0] == "run"]


def test_pending_records_stage_staged_then_switched(signing, monkeypatch):
    config, runner = prepared(signing)
    stages = []
    original = runner.replace

    def replace(source, target):
        original(source, target)
        if target == PENDING:
            stages.append((json.loads(runner.files[PENDING])["stage"], runner.readlink(CURRENT)))

    monkeypatch.setattr(runner, "replace", replace)
    assert run(config, runner) == 0
    assert stages == [("staged", OLD), ("switched", NEW)]
    switched = next(i for i, c in enumerate(runner.calls)
                    if c[0] == "write_file" and c[1] == PENDING + ".tmp"
                    and json.loads(c[2])["stage"] == "switched")
    assert switched < runner.calls.index(("run", RESTART, False, None))


def test_switch_pending_records_stage_staged_then_switched(signing, monkeypatch):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    stages = []
    original = runner.replace

    def replace(source, target):
        original(source, target)
        if target == PENDING:
            stages.append(json.loads(runner.files[PENDING])["stage"])

    monkeypatch.setattr(runner, "replace", replace)
    assert upgrade(config, runner, switch="0.2.0") == 0
    assert stages == ["staged", "switched"]


def test_recover_switched_and_healthy_completes_offline(signing, capsys):
    config, runner = prepared(signing)
    runner.connections.clear()
    put_pending(runner, "switched")
    assert recover(config, runner, config_path=CONFIG) == 0
    assert "未完成的更新已收尾。" in capsys.readouterr().out
    assert runner.readlink(CURRENT) == NEW and NEW + ".bad" not in runner.files
    assert not runner.exists(PENDING)
    assert statuses(runner)[-1] == "ok"
    assert json.loads(runner.read_file(HIGHEST)) == {"version": "0.2.0"}
    # 收尾只做现场健康检查，不先重启服务，也不探网、不取包。
    assert RESTART not in commands(runner)
    assert not any(c[0] == "tcp_connect" for c in runner.calls)
    assert not any(c[0] == "read_bytes" and c[1].startswith("/push/") for c in runner.calls)
    assert_clean(runner)


def test_recover_switched_unhealthy_rolls_back(signing):
    config, runner = prepared(signing)
    put_pending(runner, "switched")
    runner.responses[IS_ACTIVE] = CompletedResult(3, "failed\n")
    assert recover(config, runner, config_path=CONFIG) == 0
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files
    assert statuses(runner)[-1] == "rolled_back"
    assert not runner.exists(PENDING)
    assert not runner.exists(HIGHEST)
    assert_clean(runner)


def test_recover_staged_never_switched_aborts_without_bad_mark(signing):
    config, runner = prepared(signing)
    put_pending(runner, "staged", current=OLD)
    runner.mkdir(NEW + ".staging")
    runner.files[NEW + ".staging/partial"] = b"partial"
    assert recover(config, runner, config_path=CONFIG) == 0
    assert runner.readlink(CURRENT) == OLD
    assert not runner.exists(NEW) and not runner.exists(NEW + ".staging")
    assert NEW + ".bad" not in runner.files
    assert statuses(runner) == ["aborted"]
    assert not runner.exists(PENDING)
    assert not any(c[0] == "systemctl" for c in commands(runner))
    assert_clean(runner)
    runner.calls.clear()
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert statuses(runner) == ["aborted", "ok"]


def test_recover_switched_but_link_already_old_rolls_back(signing):
    config, runner = prepared(signing)
    put_pending(runner, "switched", current=OLD)
    assert recover(config, runner, config_path=CONFIG) == 0
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files
    assert statuses(runner)[-1] == "rolled_back"
    assert not runner.exists(PENDING)


@pytest.mark.parametrize("entry", ["recover", "upgrade"])
def test_recover_unknown_stage_is_corrupt(signing, entry, capsys):
    config, runner = prepared(signing)
    put_pending(runner, "half-done")
    result = (recover(config, runner, config_path=CONFIG) if entry == "recover"
              else run(config, runner))
    assert result == 1
    assert "未完成更新的记录损坏" in capsys.readouterr().out
    assert runner.exists(PENDING)
    assert runner.readlink(CURRENT) == NEW and NEW + ".bad" not in runner.files


def test_recover_without_pending_is_offline_noop(signing, capsys):
    config, runner = prepared(signing)
    runner.connections.clear()
    assert recover(config, runner, config_path=CONFIG) == 0
    assert "没有未完成的更新。" in capsys.readouterr().out
    assert not any(c[0] == "tcp_connect" for c in runner.calls)
    assert not any(c[0] == "read_bytes" and c[1].startswith("/push/") for c in runner.calls)
    assert not any(c[0] == "run" for c in runner.calls)
    assert runner.readlink(CURRENT) == OLD
    assert_clean(runner)


def test_recover_lock_held_by_live_process(signing, capsys):
    config, runner = prepared(signing)
    put_pending(runner, "switched")
    runner.files[LOCK] = json.dumps({"pid": 200, "at": runner.now()})
    runner.live_pids.add(200)
    assert recover(config, runner, config_path=CONFIG) == 4
    assert "已有更新任务正在执行" in capsys.readouterr().out
    assert runner.exists(PENDING) and runner.readlink(CURRENT) == NEW


def test_recover_takes_over_lock_written_before_boot(signing):
    config, runner = prepared(signing)
    put_pending(runner, "switched")
    runner.uptime = 50
    runner.files[LOCK] = json.dumps({"pid": 200, "at": runner.now() - 100})
    runner.live_pids.add(200)
    assert recover(config, runner, config_path=CONFIG) == 0
    assert not runner.exists(PENDING) and statuses(runner)[-1] == "ok"
    assert LOCK not in runner.files


def stable_config(signing, seconds=30):
    config, runner = prepared(signing)
    config.updater.health_stable_sec = seconds
    return config, runner


def assert_rolled_back(runner):
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files
    assert statuses(runner)[-1] == "rolled_back"
    assert not runner.exists(PENDING)


def test_stable_window_service_dies_on_second_round(signing):
    config, runner = stable_config(signing)
    runner.responses[IS_ACTIVE] = [CompletedResult(0, "active\n"), CompletedResult(3, "failed\n")]
    assert run(config, runner) == 1
    assert_rolled_back(runner)
    assert sum(c == IS_ACTIVE for c in commands(runner)) == 2


def test_stable_window_restart_count_changes(signing):
    config, runner = stable_config(signing)
    runner.responses[NRESTARTS] = [CompletedResult(0, "0\n"), CompletedResult(0, "0\n"),
                                   CompletedResult(0, "1\n")]
    assert run(config, runner) == 1
    assert_rolled_back(runner)


def test_stable_window_port_not_listening(signing):
    config, runner = stable_config(signing)
    runner.responses[("ss", "-ltnH")] = CompletedResult(0, "LISTEN 0 4096 *:8443 *:*\n")
    assert run(config, runner) == 1
    assert_rolled_back(runner)


def test_stable_window_tunnel_layer_fails_later(signing):
    config, runner = stable_config(signing)
    passed = CompletedResult(out=json.dumps({"layers": [{"name": "隧道服务", "result": "通过"}]}))
    runner.responses[HEALTH] = [passed, passed, CompletedResult(out='{"layers":[]}')]
    assert run(config, runner) == 1
    assert_rolled_back(runner)


def test_stable_window_all_pass_waits_full_window(signing):
    config, runner = stable_config(signing)
    runner.responses[NRESTARTS] = CompletedResult(0, "2\n")
    runner.responses[("ss", "-ltnH")] = CompletedResult(0, "LISTEN 0 4096 *:443 *:*\n")
    runner.responses[("ss", "-lunH")] = CompletedResult(0, "UNCONN 0 0 *:24443 *:*\n")
    before = runner.clock
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert runner.clock - before >= 30
    ran = commands(runner)
    assert ran[-1] == CHECK
    assert ran.count(IS_ACTIVE) >= 2
    assert ("ss", "-ltnH") in ran and ("ss", "-lunH") in ran
    assert statuses(runner) == ["ok"]


def test_stable_window_disabled_sends_no_extra_commands(signing):
    config, runner = stable_config(signing, 0)
    assert run(config, runner) == 0
    assert runner.readlink(CURRENT) == NEW
    assert not any(c[:2] in {("systemctl", "is-active"), ("systemctl", "show")} or c[0] == "ss"
                   for c in commands(runner))
    assert commands(runner)[-1] == CHECK


def test_health_total_time_bounded_by_timeout_plus_stable(signing, monkeypatch):
    config, runner = prepared(signing)
    config.updater.health_timeout_sec = 7
    config.updater.health_stable_sec = 5
    original = runner.run
    seen = []

    def run_timed(argv, check=True, input=None, timeout=30):
        seen.append((tuple(argv), timeout, runner.clock))
        if tuple(argv[:len(HEALTH)]) == HEALTH and len(seen) == 1:
            runner.clock += 6  # 第一段恰在第 6 秒通过。
        return original(argv, check, input, timeout)

    monkeypatch.setattr(runner, "run", run_timed)
    start = runner.clock
    assert _healthy(config, runner, CONFIG) is True
    assert runner.clock - start <= 12
    assert seen[0][1] <= 7
    for _, timeout, at in seen:
        assert 0 < timeout <= min(30, start + 12 - at)


def test_lock_written_before_boot_is_stale_in_fake_runner():
    runner = FakeRunner()
    runner.uptime = 50
    runner.files[LOCK] = json.dumps({"pid": 200, "at": runner.clock - 100})
    runner.live_pids.add(200)
    assert runner.lock_busy(LOCK) is False
    assert runner.acquire_lock(LOCK) is True
    assert json.loads(runner.files[LOCK])["pid"] == runner.pid
    other = FakeRunner()
    other.uptime = 1000
    other.files[LOCK] = json.dumps({"pid": 200, "at": other.clock - 100})
    other.live_pids.add(200)
    assert other.lock_busy(LOCK) is True
    assert other.acquire_lock(LOCK) is False


def test_real_runner_uptime_reads_proc_or_returns_infinity(monkeypatch):
    real = object.__new__(runner_module.RealRunner)
    monkeypatch.setattr(runner_module, "_read_proc_uptime", lambda: "12345.67 54321.00\n")
    assert real.uptime_seconds() == 12345.67

    def unreadable():
        raise OSError("模拟读取失败")

    monkeypatch.setattr(runner_module, "_read_proc_uptime", unreadable)
    assert real.uptime_seconds() == float("inf")
    monkeypatch.setattr(runner_module, "_read_proc_uptime", lambda: "garbage")
    assert real.uptime_seconds() == float("inf")
