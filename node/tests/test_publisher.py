import pytest
from exitnode import publisher
from exitnode.config import load
from exitnode.runner import CompletedResult, RunnerError
from test_cli import CONFIG, fake


@pytest.fixture
def setup():
    runner = fake()
    runner.files[publisher.TOOL] = "工具"
    runner.responses[(publisher.TOOL,)] = CompletedResult(out="ExternalIPAddress = 8.8.8.8\n")
    return load(CONFIG, runner), runner


def calls(runner):
    return [c[1] for c in runner.calls if c[0] == "run" and c[1][0] == publisher.TOOL]


def test_relay_mode_is_noop(setup):
    config, runner = setup
    config.publisher.mode = "relay"
    before = dict(runner.files)
    assert publisher.tick(config, runner) == 0
    assert not calls(runner) and runner.files == before


def test_missing_tool_reports_without_running(setup):
    config, runner = setup
    del runner.files[publisher.TOOL]
    assert publisher.tick(config, runner) == 1
    assert not calls(runner)
    assert publisher.status(config, runner)["last_error"] == "未安装 miniupnpc"


def test_maps_both_ports_with_lease_and_records_external_address(setup):
    config, runner = setup
    assert publisher.tick(config, runner) == 0
    assert calls(runner) == [(publisher.TOOL, "-e", "exitnode", "-a", "@", str(port),
                               str(port), proto, "3600") for port, proto in
                              ((config.proxy.reality_port, "tcp"), (config.proxy.hy2_port, "udp"))]
    state = publisher.status(config, runner)
    assert state["external_ipv4"] == "8.8.8.8"
    assert all(p["mapped"] and p["lease"] == 3600 for p in state["ports"])
    assert runner.modes[config.node.data_dir + "/publisher.json"] == 0o600


def test_rejected_lease_retries_permanent(setup):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = [CompletedResult(2), CompletedResult(),
                                           CompletedResult(2), CompletedResult()]
    assert publisher.tick(config, runner) == 0
    assert [c[-1] for c in calls(runner)] == ["3600", "0", "3600", "0"]
    assert all(p["lease"] == 0 for p in publisher.status(config, runner)["ports"])


def test_rejected_both_ways_reports_router_refused(setup):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = CompletedResult(2)
    assert publisher.tick(config, runner) == 1
    assert publisher.status(config, runner)["last_error"] == "路由器拒绝了映射"
    assert len(calls(runner)) == 4


def test_no_gateway_skips_second_port(setup):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = CompletedResult(1)
    assert publisher.tick(config, runner) == 1
    assert len(calls(runner)) == 1
    assert publisher.status(config, runner)["last_error"] == "没找到支持 UPnP 的路由器"


def test_runner_error_is_reported_as_failure(setup):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = RunnerError("秘密原文")
    assert publisher.tick(config, runner) == 1
    assert len(calls(runner)) == 1
    assert publisher.status(config, runner)["last_error"] == "执行失败"


@pytest.mark.parametrize("address", ["100.64.1.2", "192.168.1.2"])
def test_private_wan_address_is_reported(setup, address):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = CompletedResult(out="ExternalIPAddress = " + address)
    assert publisher.tick(config, runner) == 1
    assert publisher.status(config, runner)["last_error"] == "路由器外网口不是公网地址"


def test_failure_keeps_last_ok_and_counts(setup):
    config, runner = setup
    assert publisher.tick(config, runner) == 0
    before = publisher.status(config, runner)["last_ok_at"]
    runner.responses[(publisher.TOOL,)] = CompletedResult(1)
    runner.clock += 10
    assert publisher.tick(config, runner) == 1
    assert publisher.tick(config, runner) == 1
    state = publisher.status(config, runner)
    assert state["last_ok_at"] == before and state["consecutive_failures"] == 2


def test_output_and_state_never_contain_raw_tool_output(setup, capsys):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = CompletedResult(out="RAW_SECRET_MARKER\nExternalIPAddress = 8.8.8.8")
    assert publisher.tick(config, runner) == 0
    assert "RAW_SECRET_MARKER" not in capsys.readouterr().out
    assert "RAW_SECRET_MARKER" not in runner.files[config.node.data_dir + "/publisher.json"]


def test_remove_deletes_both_and_swallows_errors(setup):
    config, runner = setup
    runner.responses[(publisher.TOOL,)] = [RunnerError("原文"), CompletedResult(2)]
    publisher.remove(config, runner)
    assert calls(runner) == [(publisher.TOOL, "-d", str(config.proxy.reality_port), "tcp"),
                             (publisher.TOOL, "-d", str(config.proxy.hy2_port), "udp")]


def test_check_layer_states(setup):
    config, runner = setup
    timer = ("systemctl", "is-active", "exitnode-publisher.timer")
    assert publisher.check(config, runner)["reason"] == "端口映射定时器未运行"
    runner.responses[timer] = CompletedResult(out="active")
    assert publisher.check(config, runner)["reason"] == "半小时内没有端口映射记录"
    assert publisher.tick(config, runner) == 0
    assert publisher.check(config, runner)["result"] == "通过"
    runner.clock += 1801
    assert publisher.check(config, runner)["result"] == "失败"
    runner.responses[(publisher.TOOL,)] = CompletedResult(2)
    assert publisher.tick(config, runner) == 1
    assert publisher.check(config, runner)["result"] == "需手动转发"


def test_summary_sentences(setup):
    config, runner = setup
    assert publisher.summary(config, runner) == "尚无映射记录"
    publisher.tick(config, runner)
    assert publisher.summary(config, runner) == "已向路由器申请映射"
    runner.responses[(publisher.TOOL,)] = CompletedResult(1)
    publisher.tick(config, runner)
    assert publisher.summary(config, runner) == "未能自动映射(没找到支持 UPnP 的路由器),需在路由器上手动转发"
    runner.files[config.node.data_dir + "/publisher.json"] = "损坏"
    assert publisher.status(config, runner)["ports"] == []
    config.publisher.mode = "relay"
    assert publisher.summary(config, runner) == "未启用自动映射"
