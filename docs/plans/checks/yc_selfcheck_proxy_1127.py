"""系统代理自检单 yc-selfcheck-proxy-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
PROBE = WIN / "WinClient.Core/Environment/ProxySettingsProbe.cs"
SELFCHECK = WIN / "WinClient.Core/Environment/EnvironmentSelfCheck.cs"
CONTROLLER = WIN / "WinClient.Core/Client/ClientController.cs"
RUNTIME = WIN / "WinClient.Core/Client/ClientRuntime.cs"
TESTS = WIN / "WinClient.Tests"
ENV_DOC = ROOT / "docs/winclient/环境一致性说明.md"
ARCH_DOC = ROOT / "docs/winclient/架构说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Environment/ProxySettingsProbe.cs",
    "winclient/WinClient.Core/Environment/EnvironmentSelfCheck.cs",
    "winclient/WinClient.Core/Client/ClientController.cs",
    "winclient/WinClient.Core/Client/ClientRuntime.cs",
    "winclient/WinClient.Tests/ProxySettingsProbeTests.cs",
    "winclient/WinClient.Tests/EnvironmentSelfCheckTests.cs",
    "winclient/WinClient.Tests/ControllerTests.cs",
    "docs/winclient/环境一致性说明.md",
    "docs/winclient/架构说明.md",
}
TEXTS = [
    "system_proxy",
    "未设系统代理",
    "没有发现系统代理、自动代理脚本或命令行代理环境变量",
    "这些设置会让浏览器或命令行程序先把流量交给那个代理,查到的地址可能不是节点地址;连接期间请关掉系统代理并退出其他代理软件",
    "未取得代理设置",
]
PROBE_WORDS = [
    "interface IProxySettingsProbe", "class RegistryProxySettingsProbe", "static class ProxySettings",
    "record ProxySnapshot", "record ProxyUserValues", "S-1-5-21", "Internet Settings", "ProxyEnable",
    "ProxyServer", "AutoConfigURL", "ProxySettingsPerUser", "Session Manager", "HTTP_PROXY", "HTTPS_PROXY",
    "ALL_PROXY", "系统代理", "自动代理脚本", "环境变量 ",
]
NEW_TESTS = {
    "ProxySettingsProbeTests.cs": [
        "NoSettingsGivesEmptyFindings",
        "EnabledProxyWithServerIsReported",
        "AutoConfigUrlIsReported",
        "ProxyEnvironmentVariablesAreReportedCaseInsensitively",
        "MachineWideProxyCountsOnlyWhenPolicyDisablesPerUser",
        "FindingsNeverContainValues",
        "FindingsAreDeduplicatedAndOrdered",
        "ReadSystemDoesNotThrow",
    ],
    "EnvironmentSelfCheckTests.cs": [
        "ProxyItemPassesWhenNoFindings",
        "ProxyItemFailsAndNamesSettingsWithoutValues",
        "ProxyItemUnverifiableWhenSnapshotMissing",
        "ProxyItemEvaluatedInAppsMode",
    ],
    "ControllerTests.cs": ["SelfCheckIncludesProxyFindingsFromProbe"],
}


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def fail(problems):
    for item in problems:
        print("未通过:", item)
    sys.exit(1 if problems else 0)


def shape():
    bad = []
    if not PROBE.exists():
        fail(["缺文件 ProxySettingsProbe.cs"])
    probe = text(PROBE)
    bad += ["ProxySettingsProbe 缺 " + word for word in PROBE_WORDS if word not in probe]
    for word in ("Registry.SetValue", ".SetValue(", "DeleteValue", "CreateSubKey", "OpenSubKey(name, true", "writable: true"):
        if word in probe:
            bad.append("ProxySettingsProbe 只许读注册表,出现了 " + word)
    for word in ("Process.Start", "ProcessStartInfo"):
        if word in probe:
            bad.append("ProxySettingsProbe 不许起子进程")
    selfcheck = text(SELFCHECK)
    bad += ["EnvironmentSelfCheck 缺原文:" + word for word in TEXTS if word not in selfcheck]
    if "ProxyFindings" not in selfcheck:
        bad.append("SelfCheckInput 缺 ProxyFindings")
    controller = text(CONTROLLER)
    if "IProxySettingsProbe" not in controller or "ProxyFindings" not in controller:
        bad.append("ClientController 没接上代理设置探测")
    if "new RegistryProxySettingsProbe(" not in text(RUNTIME):
        bad.append("ClientRuntime 没接上 RegistryProxySettingsProbe")
    fail(bad)


def tests():
    bad = []
    for name, methods in NEW_TESTS.items():
        path = TESTS / name
        if not path.exists():
            bad.append("缺测试文件 " + name)
            continue
        body = text(path)
        bad += ["%s 缺用例 %s" % (name, method) for method in methods if " " + method + "(" not in body]
    selfcheck_tests = text(TESTS / "EnvironmentSelfCheckTests.cs")
    if selfcheck_tests.count("12 项通过") < 5:
        bad.append("EnvironmentSelfCheckTests 里「12 项通过」应不少于 5 处")
    fail(bad)


def docs():
    bad = []
    env = text(ENV_DOC)
    for word in ("system_proxy", "未设系统代理", "十二项", "12 项通过", "自动代理脚本", "HTTPS_PROXY"):
        if word not in env:
            bad.append("环境一致性说明缺 " + word)
    if "执行十一项自检" in env or "全好时显示「环境自检:11 项通过」" in env:
        bad.append("环境一致性说明的总条数还是十一项")
    arch = text(ARCH_DOC)
    if "十二项" not in arch or "未设系统代理" not in arch:
        bad.append("架构说明没同步成十二项")
    for body, name in ((env, "环境一致性说明"), (arch, "架构说明")):
        for word in ("申请记录", "git 写操作", "工人"):
            if word in body:
                bad.append("%s 混进了施工过程用语:%s" % (name, word))
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
