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


def test_output_chain_sets_ttl_only_for_service_originated_connections():
    text = render_ruleset(CTX)
    assert "chain output {" in text
    assert "type filter hook output priority mangle; policy accept;" in text
    for rule in ("ip ttl set 128", "ip6 hoplimit set 128"):
        assert text.count(rule) == 1
        line = next(line for line in text.splitlines() if rule in line)
        assert 'meta skuid "exitnode"' in line
        assert "ct direction original" in line
    # 固定基点的三条链，避免黄金文件同步更新掩盖既有规则变化。
    original_chains = (
        "    chain input {\n"
        "        type filter hook input priority 0; policy accept;\n"
        "        tcp dport 443 accept\n"
        "        udp dport 24443 accept\n"
        "        ip daddr 127.0.0.1 tcp dport 8443 accept\n"
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority 0; policy accept;\n"
        "        # 出口转发规则由后续代理接入卡提供，当前不扩大转发权限。\n"
        "    }\n"
        "    chain postrouting {\n"
        "        type nat hook postrouting priority 100; policy accept;\n"
        "        # 待确定隧道源地址后添加受限 masquerade 规则。\n"
        "    }\n"
    )
    assert text.split("table inet exitnode {\n", 1)[1].split("    chain output {", 1)[0] == (
        original_chains
    )
    for source in (Path(__file__).parents[1] / "exitnode").rglob("*.py"):
        content = source.read_text(encoding="utf-8")
        assert "ip_default_ttl" not in content
        assert "sysctl" not in content


def test_service_user_cannot_inject_rules():
    for user in ('exitnode" accept; delete table inet other', "Root"):
        with pytest.raises(ValueError, match="服务账户名不合法"):
            render_ruleset({**CTX, "service_user": user})
    text = render_ruleset({**CTX, "service_user": "svc-user_1"})
    for rule in ("ip ttl set 128", "ip6 hoplimit set 128"):
        assert f'meta skuid "svc-user_1" ct direction original {rule}' in text
