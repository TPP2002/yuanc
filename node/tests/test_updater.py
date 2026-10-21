"""更新事务使用内存主机、内存包和本次测试生成的签名密钥。"""

import hashlib
import io
import json
import tarfile
import traceback

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from exitnode.cli import main
from exitnode.config import load
from exitnode.runner import CompletedResult, FakeRunner
from exitnode.updater import layout, package, trust
from exitnode.updater.upgrade import UpdateError, _request, upgrade
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
HEALTH = ("env", "PYTHONPATH=" + CURRENT, "python3", "-m", "exitnode")


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
                            out=json.dumps({"layers": [{"name": "隧道服务", "result": "通过"}]}))})
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


def test_killed_after_switch_rolls_back_before_next_package(signing):
    config, runner = prepared(signing)
    put_release(runner, "0.2.0")
    runner.links[CURRENT] = NEW
    runner.files[DATA + "/updater/pending.json"] = json.dumps({
        "old": OLD, "target": NEW, "version": "0.2.0"})
    assert run(config, runner) == 1  # 恢复旧版后，同版本已存在，拒绝再次安装。
    assert runner.readlink(CURRENT) == OLD and NEW + ".bad" in runner.files
    assert DATA + "/updater/pending.json" not in runner.files
    assert json.loads(runner.read_file(DATA + "/updater/history.jsonl"))["status"] == "rolled_back"


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
