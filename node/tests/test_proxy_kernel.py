"""版本下限与安装前拒绝检查。"""

import pytest
from exitnode.cli import main
from exitnode.proxy.kernel import kernel_version, require_kernel
from exitnode.proxy.runner_proto import FakeRunner
from exitnode.runner import CompletedResult
from test_cli import fake


@pytest.mark.parametrize("version", ["1.13.0", "1.13.21"])
def test_supported_kernel(version):
    runner = FakeRunner()
    runner.responses[("sing-box", "version")] = (0, f"sing-box version {version}\n", "")
    assert kernel_version(runner, "sing-box") == tuple(map(int, version.split(".")))
    require_kernel(runner, "sing-box")


@pytest.mark.parametrize("code,stdout,current", [
    (0, "sing-box version 1.12.9\n", "1.12.9"),
    (0, "无法解析", "未知"),
    (1, "sing-box version 1.13.21\n", "未知"),
])
def test_rejected_kernel_has_no_service_writes(code, stdout, current, capsys):
    runner = FakeRunner()
    runner.responses[("sing-box", "version")] = (code, stdout, "不可输出的内容")
    with pytest.raises(ValueError, match=f"当前 {current}.*需要 1.13.0 及以上"):
        require_kernel(runner, "sing-box")
    if current == "未知":
        assert kernel_version(runner, "sing-box") is None
    node = fake()
    before = dict(node.files)
    node.responses[("/usr/bin/sing-box", "version")] = CompletedResult(code, stdout, "不可输出的内容")
    assert main(["init"], node) != 0
    assert not any(path.startswith("/etc/systemd/system/") for path in node.files)
    assert all(node.files[path] == text for path, text in before.items())
    output = capsys.readouterr()
    assert "不可输出的内容" not in output.out + output.err


def test_first_existing_kernel_is_checked():
    node = fake()
    node.files["/opt/exitnode/current/bin/sing-box"] = "旧内核"
    node.responses[("/opt/exitnode/current/bin/sing-box", "version")] = CompletedResult(
        out="sing-box version 1.12.9\n")
    assert main(["init"], node) != 0
    assert not any(path.startswith("/etc/systemd/system/") for path in node.files)
