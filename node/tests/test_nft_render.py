from pathlib import Path

import pytest
from exitnode.nft import RULES, apply, remove, render_ruleset
from exitnode.runner import CompletedResult, FakeRunner

CTX = {"reality_port": 443, "hy2_port": 24443, "admin_port": 8443}


def test_ruleset_matches_golden_and_only_owns_one_table():
    text = render_ruleset(CTX)
    assert text == (Path(__file__).parent / "golden" / "exitnode.nft").read_text(encoding="utf-8")
    assert text.count("table ") == 1
    assert "table inet exitnode {" in text
    forbidden = "flush" + " ruleset"
    for source in (Path(__file__).parents[1] / "exitnode").rglob("*.py"):
        assert forbidden not in source.read_text(encoding="utf-8")


def test_ruleset_comment_is_not_misleading():
    text = render_ruleset(CTX)
    assert "管理入口限配置的监听地址" not in text
    first = text.splitlines()[0]
    assert "占位" in first and "exitnode-nft.service" in first and "IPAddressAllow" in first


def test_apply_writes_rule_file_in_one_batch_and_loads_it():
    runner = FakeRunner(responses={
        ("nft", "-j"): CompletedResult(out='{"nftables":[{"table":{"family":"inet","name":"exitnode"}}]}'),
        ("nft", "-f"): CompletedResult(),
        ("nft", "delete"): CompletedResult(),
    })
    apply(runner, CTX)
    writes = [c for c in runner.calls if c[0] == "write_file"]
    assert len(writes) == 1
    assert writes[0][1] == RULES + ".tmp" and writes[0][3] == 0o600
    expected = "table inet exitnode\ndelete table inet exitnode\n" + render_ruleset(CTX)
    assert writes[0][2] == expected
    assert runner.files == {RULES: expected}
    assert runner.modes[RULES] == 0o600
    replaced = runner.calls.index(("replace", RULES + ".tmp", RULES))
    loaded = runner.calls.index(("run", ("nft", "-f", RULES), True, None))
    assert replaced < loaded
    # 不再探测是否已有本表，也不写 /run 临时文件。
    assert not any(c[0] == "run" and c[1][:2] == ("nft", "-j") for c in runner.calls)
    assert not any(c[0] == "write_file" and c[1].startswith("/run/") for c in runner.calls)
    remove(runner)
    assert ("run", ("nft", "delete", "table", "inet", "exitnode"), True, None) in runner.calls
    assert RULES not in runner.files


def test_missing_table_removal_is_noop_and_command_failure_is_not_hidden():
    runner = FakeRunner(responses={("nft", "-j"): CompletedResult(out='{"nftables":[]}')})
    remove(runner)
    assert not any(c[0] == "run" and c[1][:2] == ("nft", "delete") for c in runner.calls)
    assert not any(c[0] == "remove" for c in runner.calls)
    with pytest.raises(RuntimeError):
        apply(runner, CTX)
    runner.calls.clear()
    remove(runner)
    assert not any(c[0] == "run" and c[1][:2] == ("nft", "delete") for c in runner.calls)
    assert ("remove", RULES) in runner.calls
    assert not runner.files


def test_ports_cannot_inject_rules():
    with pytest.raises(ValueError):
        render_ruleset({**CTX, "admin_port": "443; delete table inet other"})
