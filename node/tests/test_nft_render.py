from pathlib import Path

import pytest
from exitnode.nft import apply, remove, render_ruleset
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


def test_apply_replaces_only_owned_table_in_one_batch_and_cleans_temp():
    runner = FakeRunner(responses={
        ("nft", "-j"): CompletedResult(out='{"nftables":[{"table":{"family":"inet","name":"exitnode"}}]}'),
        ("nft", "-f"): CompletedResult(),
        ("nft", "delete"): CompletedResult(),
    })
    apply(runner, CTX)
    writes = [c for c in runner.calls if c[0] == "write_file"]
    assert len(writes) == 1
    assert writes[0][2] == "delete table inet exitnode\n" + render_ruleset(CTX)
    assert not runner.files
    remove(runner)
    assert ("run", ("nft", "delete", "table", "inet", "exitnode"), True, None) in runner.calls


def test_missing_table_removal_is_noop_and_command_failure_is_not_hidden():
    runner = FakeRunner(responses={("nft", "-j"): CompletedResult(out='{"nftables":[]}')})
    remove(runner)
    assert len(runner.calls) == 1
    with pytest.raises(RuntimeError):
        apply(runner, CTX)
    assert not runner.files


def test_ports_cannot_inject_rules():
    with pytest.raises(ValueError):
        render_ruleset({**CTX, "admin_port": "443; delete table inet other"})
