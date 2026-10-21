import json

import pytest
from exitnode.cli import main
from exitnode.netinfo import public_ipv4
from exitnode.runner import CompletedResult, FakeRunner, RunnerError
from test_cli import fake

TRACE = ("curl", "-4", "-s", "--max-time", "5", "https://1.1.1.1/cdn-cgi/trace")
IPIFY = ("curl", "-4", "-s", "--max-time", "5", "https://api.ipify.org")


def test_trace_address_and_no_fallback():
    runner = FakeRunner(responses={TRACE: CompletedResult(out="fl=1\nip=203.0.113.9\nloc=AU\n")})
    assert public_ipv4(runner) == "203.0.113.9"
    assert [c[1] for c in runner.calls if c[0] == "run"] == [TRACE]


@pytest.mark.parametrize("failure", [CompletedResult(1), RunnerError("未找到 curl"),
                                     CompletedResult(out="not an address")])
def test_fallback(failure):
    runner = FakeRunner(responses={TRACE: failure, IPIFY: CompletedResult(out="203.0.113.10\n")})
    assert public_ipv4(runner) == "203.0.113.10"
    assert [c[1] for c in runner.calls if c[0] == "run"] == [TRACE, IPIFY]


def test_both_failed_return_null():
    runner = FakeRunner(responses={TRACE: CompletedResult(1), IPIFY: CompletedResult(1)})
    assert public_ipv4(runner) is None


@pytest.mark.parametrize("value", ["hello", "2001:db8::1", "999.1.1.1", "1.2.3.4<script>",
                                 "1.2.3.4 5.6.7.8", "01.2.3.4", "", "1.2.3"])
def test_malformed_or_ipv6_never_enters_status(value):
    runner = FakeRunner(responses={TRACE: CompletedResult(out="ip=" + value),
                                   IPIFY: CompletedResult(out=value)})
    assert public_ipv4(runner) is None


def test_ambiguous_trace_and_multiline_ipify_return_null():
    runner = FakeRunner(responses={TRACE: CompletedResult(out="ip=1.2.3.4\nip=5.6.7.8"),
                                   IPIFY: CompletedResult(out="1.2.3.4\n5.6.7.8")})
    assert public_ipv4(runner) is None


@pytest.mark.parametrize("address,cgnat", [("100.64.1.2", True), ("100.127.255.255", True),
                                         ("100.63.255.255", False), ("100.128.0.0", False),
                                         ("203.0.113.9", False)])
def test_status_reports_public_ipv4_and_cgnat(address, cgnat, capsys):
    runner = fake()
    runner.responses[TRACE] = CompletedResult(out="ip=" + address)
    assert main(["status", "--json"], runner) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["public_ipv4"] == address
    assert ("疑似运营商内网地址(CGNAT),外网无法直连" in result["reason"]) is cgnat


def test_text_status_shows_address(capsys):
    runner = fake()
    runner.responses[TRACE] = CompletedResult(out="ip=203.0.113.9")
    assert main(["status"], runner) == 0
    assert "公网 IPv4：203.0.113.9" in capsys.readouterr().out
