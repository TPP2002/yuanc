"""工单 yc-overinstall-health-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNNER = "winclient/WinClient.App/Hosting/InstallerRunner.cs"
HELPER = "winclient/WinClient.Core/Hosting/SwitchedStart.cs"
TESTS = "winclient/WinClient.Tests/SwitchedStartTests.cs"
ALLOWED = {RUNNER, HELPER, TESTS}

# InstallerRunner.cs 里这些成员一个字不许动。
UNTOUCHED = [
    "public static ServiceControllerStatus? ServiceStatus()",
    "public static string? RegisteredServiceExecutable()",
    "public static UiHandoverDecision HandoverDecision()",
    "public static ProcessStartInfo ElevationInfo(string action)",
    "public static async Task<bool> ElevateAsync(string action)",
    "public async Task<int> RunAsync(string action)",
    "private async Task StartAsync()",
    "private async Task UninstallAsync()",
    "private async Task StopServiceAsync()",
    "private async Task RunCommandAsync(string[] arguments, string error)",
    "private static async Task WaitForAsync(ServiceControllerStatus expected)",
    "private static InvalidOperationException SafeError(string message)",
    "private static void Report(IReadOnlyList<string> failed, string suffix)",
    "private static void EnsureDataDirectory()",
]
OLD_CALL = "if (ServiceInstaller.SwitchesExecutable(previous, destination)) await StartSwitchedAsync(previous);"
NEW_CALL = ("if (ServiceInstaller.SwitchesExecutable(previous, destination)) "
            "await StartSwitchedAsync(previous, ServiceInstaller.ReleaseVersion(version));")
HELPER_LINES = [
    "public static class SwitchedStart",
    'public const string RolledBackMessage = "新版本的后台服务未能启动，已改回原来的版本。";',
    'public const string NoPreviousMessage = "新版本的后台服务未能启动，原来的版本已经不在，没有改回。请重新安装，或联系管理员。";',
    'public const string RollbackNotRunningMessage = "新版本的后台服务未能启动，已改回原来的版本，但原来的后台服务也没能启动。请重启电脑，或联系管理员。";',
    "public static readonly TimeSpan HealthBudget = TimeSpan.FromSeconds(60);",
    "public static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(2);",
    "public static async Task<bool> WaitHealthyAsync(",
    "Func<CancellationToken, Task<ControlResponse?>> readStatus",
    "string expectedVersion",
    "Func<DateTimeOffset> now",
    "Func<TimeSpan, CancellationToken, Task> delay",
    "public static string FailureMessage(bool previousAvailable, bool previousRunning)",
]
# 帮手类只许用传进来的时钟和等待,不许自己看表、自己睡、起进程;也不许把「连上了」当成判据。
HELPER_FORBIDDEN = ["Task.Delay(", "Thread.Sleep(", "DateTimeOffset.UtcNow", "DateTimeOffset.Now", "DateTime.UtcNow",
                    "DateTime.Now", "Stopwatch", "Process.Start", "ConnectionState."]
NEW_TESTS = {
    "HealthyOnceStatusReportsExpectedVersion": ["WaitHealthyAsync(", "Assert.True("],
    "OtherVersionIsNotHealthy": ["WaitHealthyAsync(", "Assert.False(", "SwitchedStart.HealthBudget"],
    "FailedResponsesAreNotHealthy": ["WaitHealthyAsync(", "Assert.False("],
    "ProbeTimeoutCountsAsNoResponse": ["WaitHealthyAsync(", "OperationCanceledException", "Assert.True("],
    "OuterCancellationStopsWaiting": ["WaitHealthyAsync(", "OperationCanceledException", "Assert.Throws"],
    "FailureMessageSaysWhatHappened": ["SwitchedStart.FailureMessage("],
    "MessagesAreTheAgreedTexts": ["SwitchedStart.RolledBackMessage", "SwitchedStart.NoPreviousMessage",
                                  "SwitchedStart.RollbackNotRunningMessage", "SwitchedStart.HealthBudget",
                                  "SwitchedStart.ProbeInterval"],
}
SKIPS = r"\bSkip\s*=|\bAssert\.Skip\w*\s*\(|\bSkip\.If\w*\s*\(|\bSkippable(?:Fact|Theory)\b"


def text(path):
    return Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    return git("show", f"{base()}:{path}").replace("\r\n", "\n")


def member(source, signature):
    """取一个方法从签名到配对右花括号的全文;找不到返回空串。"""
    start = source.find(signature)
    if start < 0:
        return ""
    depth = 0
    for index in range(source.index("{", start), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return ""


def shape_problems(runner, old_runner, helper):
    bad = []
    for signature in UNTOUCHED:
        was = member(old_runner, signature)
        if not was:
            bad.append(f"检查脚本在改动前的 InstallerRunner.cs 里找不到 {signature},请交 blocked 告诉派单方")
        elif member(runner, signature) != was:
            bad.append(f"InstallerRunner.cs 的 {signature} 不许动")
    install = member(runner, "private async Task InstallAsync()")
    if NEW_CALL not in install:
        bad.append("InstallAsync 里要把新版本号传给 StartSwitchedAsync:" + NEW_CALL)
    elif install.replace(NEW_CALL, OLD_CALL) != member(old_runner, "private async Task InstallAsync()"):
        bad.append("InstallAsync 除了调用 StartSwitchedAsync 的那一行,其余不许动")
    switched = member(runner, "private async Task StartSwitchedAsync(string? previous, string version)")
    if not switched:
        bad.append("缺 private async Task StartSwitchedAsync(string? previous, string version)")
    else:
        for token, why in (("SwitchedStart.WaitHealthyAsync(", "要等新后台应答出新版本号"),
                           ("ReadStatusAsync", "读状态用更新助手现成的那条路(会核验后台身份)"),
                           ("SwitchedStart.FailureMessage(", "失败时按实际结果选提示语"),
                           ("ServiceInstaller.Configure(previous", "旧程序还在时把服务改回旧版"),
                           ("ServiceInstaller.RunValue(previous", "旧程序还在时把登录自启值改回旧版"),
                           ("File.Exists(previous)", "先看旧程序文件还在不在")):
            if token not in switched:
                bad.append(f"StartSwitchedAsync 里没有 {token}:{why}")
        if switched.count("await StopServiceAsync();") < 2:
            bad.append("StartSwitchedAsync 里改回旧版之前要先停一次服务(新版可能还在运行)")
        for token, why in (("Task.Delay(", "不许再用固定等几秒的办法判断"),
                           ("ServiceStatus() == ServiceControllerStatus.Running", "不许再只看服务是不是在运行"),
                           ("ConnectionState.", "不许把「连上了」当成安装成功的条件")):
            if token in switched:
                bad.append(f"StartSwitchedAsync 里还有 {token}:{why}")
    if "已改回原来的版本" in runner:
        bad.append("InstallerRunner.cs 里不许再写死「已改回原来的版本」,三句提示语都放在 SwitchedStart 里")
    if not helper:
        bad.append("缺 " + HELPER)
        return bad
    for line in HELPER_LINES:
        if line not in helper:
            bad.append(f"SwitchedStart.cs 里没有:{line}")
    for token in HELPER_FORBIDDEN:
        if token in helper:
            bad.append(f"SwitchedStart.cs 里不许出现 {token}")
    wait = member(helper, "public static async Task<bool> WaitHealthyAsync(")
    for token, why in ((".ServiceVersion", "要比对后台报的版本号"), ("expectedVersion", "要比对后台报的版本号"),
                       ("HealthBudget", "总时限用 HealthBudget"), ("ProbeInterval", "间隔用 ProbeInterval"),
                       ("ThrowIfCancellationRequested", "外层取消要抛出,不许当成没起来")):
        if token not in wait:
            bad.append(f"WaitHealthyAsync 里没有 {token}:{why}")
    return bad


def tests_problems(tests):
    bad = []
    if not tests:
        return ["缺 " + TESTS]
    declared = re.findall(r"\[(?:Fact|Theory)[^\]\n]*\]\s*\n(?:\s*\[InlineData[^\n]*\n)*\s*public (?:async Task|void) (\w+)\(", tests)
    for name, tokens in NEW_TESTS.items():
        body = member(tests, f" {name}(")
        if name not in declared or not body:
            bad.append(f"缺用例 {name}")
            continue
        for token in tokens:
            if token not in body:
                bad.append(f"用例 {name} 里没有契约要求的 {token}")
        if "Assert." not in body:
            bad.append(f"用例 {name} 没有断言")
    for token in ("Task.Delay(", "Thread.Sleep("):
        if token in tests:
            bad.append(f"SwitchedStartTests.cs 里不许真的等时间({token}),用假时钟")
    if re.search(SKIPS, tests):
        bad.append("SwitchedStartTests.cs 里有跳过")
    if tests.count("[InlineData(") < 6:
        bad.append("FailedResponsesAreNotHealthy 要覆盖三种应答、FailureMessageSaysWhatHappened 要覆盖四种组合,用 InlineData 列出")
    return bad


def present(path):
    target = ROOT / path
    return text(target) if target.exists() else ""


def shape():
    return shape_problems(present(RUNNER), before(RUNNER), present(HELPER))


def tests():
    return tests_problems(present(TESTS))


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
