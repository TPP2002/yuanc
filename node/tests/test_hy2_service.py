"""Certificate migration and distribution use only the in-memory node Runner."""

import json
from dataclasses import replace

import pytest
from exitnode import service
from exitnode.config import load
from exitnode.runner import CompletedResult
from test_cli import CONFIG, fake

CRT = service.SECRETS + "/hy2.crt"
KEY = service.SECRETS + "/hy2.key"
INSPECT = ("openssl", "x509", "-in", CRT, "-noout", "-ext", "subjectAltName")


@pytest.mark.parametrize("san", ["", "DNS:exitnode.wrong", "DNS:other"])
def test_without_matching_san_regenerates_pair(monkeypatch, capsys, san):
    runner = fake()
    runner.responses[INSPECT] = CompletedResult(out=san)
    runner.responses[("openssl", "req")] = CompletedResult()
    original = runner.run

    def run(argv, check=True, input=None):
        result = original(argv, check=check, input=input)
        if argv[:2] == ["openssl", "req"]:
            runner.write_file(argv[argv.index("-out") + 1], "new-test-certificate", 0o600)
            runner.write_file(argv[argv.index("-keyout") + 1], "new-test-key", 0o600)
        return result

    monkeypatch.setattr(runner, "run", run)
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    commands = [c[1] for c in runner.calls if c[0] == "run"]
    assert commands[0] == INSPECT
    assert len(commands) == 2 and commands[1][:2] == ("openssl", "req")
    assert commands[1][-4:] == ("-subj", "/CN=exitnode", "-addext", "subjectAltName=DNS:exitnode")
    for path, content in ((CRT, "new-test-certificate"), (KEY, "new-test-key")):
        assert runner.files[path] == content
        wiped = runner.calls.index(("write_file", path, "", 0o600))
        removed = runner.calls.index(("remove", path))
        assert wiped < removed
    assert "备用通道证书已重新生成,旧配对文件需重新导出" in capsys.readouterr().out
    before = list(commands)
    service.ensure_credentials(config, runner)
    assert [c[1] for c in runner.calls if c[0] == "run"] == before


def test_matching_san_reuses_existing_pair():
    runner = fake()
    before = {p: runner.files[p] for p in (CRT, KEY)}
    service.ensure_credentials(load(CONFIG, runner), runner)
    assert {p: runner.files[p] for p in (CRT, KEY)} == before
    assert [c[1] for c in runner.calls if c[0] == "run"] == [INSPECT]
    assert not any(c[0] in {"write_file", "remove"} and c[1] in before for c in runner.calls)


@pytest.mark.parametrize("missing", [CRT, KEY])
def test_incomplete_pair_still_fails(missing):
    runner = fake()
    del runner.files[missing]
    remaining = KEY if missing == CRT else CRT
    before = runner.files[remaining]
    with pytest.raises(ValueError, match="不成对"):
        service.ensure_credentials(load(CONFIG, runner), runner)
    assert runner.files[remaining] == before
    assert not any(c[0] == "run" for c in runner.calls)


def test_inspection_failure_keeps_pair_and_hides_output():
    runner = fake()
    runner.responses[INSPECT] = CompletedResult(1, out="secret-output", err="secret-error")
    before = {p: runner.files[p] for p in (CRT, KEY)}
    with pytest.raises(ValueError, match="证书检查失败") as error:
        service.ensure_credentials(load(CONFIG, runner), runner)
    assert "secret" not in str(error.value)
    assert {p: runner.files[p] for p in (CRT, KEY)} == before


def test_context_reads_certificate_lines_and_configured_port():
    runner = fake()
    config = load(CONFIG, runner)
    config = replace(config, proxy=replace(config.proxy, reality_port=14443))
    keys = service.ensure_credentials(config, runner)
    runner.files[CRT] = "first\n\n   \nsecond\n"
    context = service.build_context(config, keys, runner)
    assert context.reality_port == 14443
    assert context.hy2_certificate == ("first", "second")


def test_completed_certificate_step_skips_inspection():
    runner = fake()
    config = load(CONFIG, runner)
    service.ensure_credentials(config, runner)
    manifest = json.loads(runner.files[config.node.data_dir + "/manifest.json"])
    assert next(s for s in manifest["steps"] if s["step"] == "生成备用通道证书")["done_at"]
    runner.calls.clear()
    service.ensure_credentials(config, runner)
    assert not any(c[0] == "run" for c in runner.calls)
