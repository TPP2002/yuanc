"""过滤层 53 端口单 yc-wfp-dns-guard-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
PLANNER = WIN / "WinClient.Core/Firewall/WfpPlanner.cs"
CLASSIFIER = WIN / "WinClient.Core/Diagnostics/LeakClassifier.cs"
FORMATTER = WIN / "WinClient.Core/Diagnostics/LeakReportFormatter.cs"
TESTS = WIN / "WinClient.Tests"
HARDEN = ROOT / "docs/winclient/断网保护加固说明.md"
LEAK = ROOT / "docs/winclient/泄漏检测说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Firewall/WfpPlanner.cs",
    "winclient/WinClient.Core/Diagnostics/LeakClassifier.cs",
    "winclient/WinClient.Core/Diagnostics/LeakReportFormatter.cs",
    "winclient/WinClient.Tests/WfpPlannerTests.cs",
    "winclient/WinClient.Tests/WfpApplierTests.cs",
    "winclient/WinClient.Tests/WfpLiveTests.cs",
    "winclient/WinClient.Tests/LeakCaptureTests.cs",
    "docs/winclient/断网保护加固说明.md",
    "docs/winclient/泄漏检测说明.md",
}
HINT = "其中发往局域网 53 端口的是域名查询:路由器会把它转给所在地运营商的解析器。"
SECTION = "## 域名查询端口不随局域网放行"
NEW_TESTS = {
    "WfpPlannerTests.cs": [
        "GlobalHasExactlyTwentyTwoInContractOrder",
        "DnsPortBlockSitsBetweenLanAndExactPermits",
        "AppsPlanHasNoDnsBlock",
    ],
    "WfpApplierTests.cs": ["GlobalPolicyKeepsDnsBlockAcrossNodeUpdateAndAppsDropIt"],
    "WfpLiveTests.cs": ["DnsPortBlockBeatsLanPermitButNotExactPermit"],
    "LeakCaptureTests.cs": [
        "LanDnsQueryIsSuspiciousInGlobalMode",
        "LanDnsQueryIsNotFlaggedInAppsMode",
        "SummaryExplainsLanDnsFlow",
    ],
}
# 真机用例的安全闸与既有五个用例必须原样保留。
LIVE_KEEP = [
    "安全闸拒绝安装：每条过滤器的全部远端地址必须落在 192.0.2.0/24 内。",
    "Assert.InRange(prefix, 24, 32);",
    "Assert.Equal(WfpLayer.ConnectV4, filter.Layer);",
    "BlockDeniesWithinThreeSecondsAndRemoveReleases",
    "HigherWeightPermitWinsWithinTestSublayer",
    "AppIdBlockAppliesToCurrentProcess",
    "PersistentFiltersSurviveEngineSessionAndCanBeRemovedByAnotherInstance",
    "RepeatedInstallLeavesExactlyOneCompleteSet",
    "fe19d24e-6ba0-4b85-ae90-2bc0de30600c",
    "84fa614c-c2b5-45d7-8c0c-19fb4c6b4dc5",
]


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def fail(problems):
    for item in problems:
        print("未通过:", item)
    sys.exit(1 if problems else 0)


def shape():
    bad = []
    planner = text(PLANNER)
    for name, kind, value in [
        ("ExactPermitWeight", "byte", "12"),
        ("DnsBlockWeight", "byte", "11"),
        ("PermitWeight", "byte", "10"),
        ("BlockWeight", "byte", "0"),
        ("DnsPort", "int", "53"),
    ]:
        if not re.search(rf"public\s+const\s+{kind}\s+{name}\s*=\s*{value}\s*;", planner):
            bad.append(f"WfpPlanner 缺常量 {name} = {value}")
    if '"Dns53-"' not in planner:
        bad.append("WfpPlanner 缺 Dns53- 过滤器名")
    head, sep, apps = planner.partition("PlanApps(")
    if not sep:
        bad.append("WfpPlanner 找不到 PlanApps")
    for word in ("Dns53", "DnsBlockWeight", "ExactPermitWeight", "DnsPort"):
        if word in apps:
            bad.append("PlanApps 不许出现 " + word)
    classifier = text(CLASSIFIER)
    if "53" not in classifier or "AppsMode" not in classifier:
        bad.append("LeakClassifier 缺局域网 53 端口规则")
    if HINT not in text(FORMATTER):
        bad.append("LeakReportFormatter 缺提示句原文")
    fail(bad)


def tests():
    bad = []
    for name, methods in NEW_TESTS.items():
        body = text(TESTS / name)
        for method in methods:
            if " " + method + "(" not in body:
                bad.append(f"{name} 缺用例 {method}")
    if " GlobalHasExactlyTwentyInContractOrder(" in text(TESTS / "WfpPlannerTests.cs"):
        bad.append("旧用例名 GlobalHasExactlyTwentyInContractOrder 应已改名")
    live = text(TESTS / "WfpLiveTests.cs")
    for word in LIVE_KEEP:
        if word not in live:
            bad.append("WfpLiveTests 既有内容被改动:" + word)
    for word in ("WfpPlanner.DnsBlockWeight", "WfpPlanner.ExactPermitWeight", "WfpPlanner.PermitWeight", "ProtocolType.Udp"):
        if word not in live:
            bad.append("WfpLiveTests 新用例缺 " + word)
    if live.count("[WfpLiveFact]") != 6:
        bad.append("WfpLiveTests 应恰有 6 个真机门控用例")
    if re.search(r"\[Fact\]", live):
        bad.append("WfpLiveTests 不许出现无门控的 [Fact]")
    fail(bad)


def docs():
    bad = []
    harden = text(HARDEN)
    if SECTION not in harden:
        bad.append(f"加固说明缺小节「{SECTION}」")
    for word in ("YuanC-WFP-Dns53-ConnectV4", "YuanC-WFP-Dns53-ConnectV6", "22 条", "23 条"):
        if word not in harden:
            bad.append("加固说明缺 " + word)
    if harden.find(SECTION) < harden.find("## 局域网放行"):
        bad.append("新小节应放在「局域网放行」之后")
    leak = text(LEAK)
    for word in ("53 端口", "域名查询"):
        if word not in leak:
            bad.append("泄漏检测说明缺 " + word)
    # 文档只写产品行为,不写施工过程。加固说明只查新小节之后的部分(旧小节里本来就有「自检」等词)。
    for body, name in ((harden.partition(SECTION)[2].partition("\n## ")[0], "加固说明新小节"), (leak, "泄漏检测说明")):
        for word in ("申请记录", "git 写操作", "工人"):
            if word in body:
                bad.append(f"{name} 混进了施工过程用语:{word}")
    fail(bad)


def scope():
    def git(*args):
        out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
        return [line.strip() for line in out.decode("utf-8").split("\n") if line.strip()]

    base = git("merge-base", "origin/main", "HEAD")[0]
    changed = set(git("diff", "--name-only", base)) | set(git("ls-files", "--others", "--exclude-standard"))
    fail(sorted("改了允许清单以外的文件:" + path for path in changed if path not in ALLOWED))


if __name__ == "__main__":
    commands = {"shape": shape, "tests": tests, "docs": docs, "scope": scope}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("用法:python 本文件 shape|tests|docs|scope")
        sys.exit(2)
    commands[sys.argv[1]]()
