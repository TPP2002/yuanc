"""内核残留单 yc-kernel-orphan-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
CORE = WIN / "WinClient.Core"
JOB = CORE / "Process/KernelJob.cs"
SWEEPER = CORE / "Process/StrayKernelSweeper.cs"
LAUNCHER = CORE / "Process/ISingBoxLauncher.cs"
MANAGER = CORE / "Process/SingBoxProcessManager.cs"
TRANSPORT = CORE / "Client/TunnelTransport.cs"
RUNTIME = CORE / "Client/ClientRuntime.cs"
NEW_TESTS_FILE = WIN / "WinClient.Tests/KernelLifetimeTests.cs"
OLD_TESTS_FILE = WIN / "WinClient.Tests/ProcessStorageTests.cs"
DOC = ROOT / "docs/winclient/服务化与自启说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Process/KernelJob.cs",
    "winclient/WinClient.Core/Process/StrayKernelSweeper.cs",
    "winclient/WinClient.Core/Process/ISingBoxLauncher.cs",
    "winclient/WinClient.Core/Process/SingBoxProcessManager.cs",
    "winclient/WinClient.Core/Client/TunnelTransport.cs",
    "winclient/WinClient.Core/Client/ClientRuntime.cs",
    "winclient/WinClient.Tests/KernelLifetimeTests.cs",
    "winclient/WinClient.Tests/ProcessStorageTests.cs",
    "docs/winclient/服务化与自启说明.md",
}
SWEEP_LOG = "已结束上次残留的连接内核 "
NOT_STOPPED = "上次残留的连接内核没能结束，请重启电脑后再连接。"
BIND_FAILED = "连接内核未能绑定到后台服务，后台服务意外退出时它可能残留。"
NEW_TESTS = [
    "JobKillsChildWhenHandleCloses",
    "LauncherPutsKernelInSharedJob",
    "SweeperKillsSamePathCopyOnly",
    "SweeperMatchesOwnedBinDirectoryOnly",
    "SweeperSkipsSelfAndUnreadablePaths",
    "SweeperThrowsWhenStrayWillNotExit",
    "ManagerSweepsBeforeEveryLaunch",
    "TransportWaitsForStaleAdapterBeforeLaunch",
    "TransportRequiresSettledChildWhenAdapterStayed",
    "TransportFailsWhenKernelExitsDuringSettle",
]
OLD_TESTS = [
    "ProcessConfigIsAtomicAndLaunchHiddenAndExitReported",
    "MissingKernelGivesChineseError",
    "ConfigRenderingDoesNotModifyServerObject",
]


def text(path):
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def fail(problems):
    for item in problems:
        print("未通过:", item)
    sys.exit(1 if problems else 0)


def need(body, words, name, bad):
    for word in words:
        if word not in body:
            bad.append(f"{name} 缺 {word}")


def before(body, first, second, name, bad):
    a = body.find(first)
    b = body.find(second)
    if a < 0 or b < 0 or a > b:
        bad.append(f"{name}:{first} 要出现在 {second} 之前")


def between(body, start, end):
    head, found, rest = body.partition(start)
    if not found:
        return ""
    return rest.partition(end)[0]


def shape():
    bad = []
    job = text(JOB)
    need(job, ["public sealed class KernelJob : IDisposable", "CreateJobObject", "IntPtr.Zero", "0x2000",
               "SetInformationJobObject", "AssignProcessToJobObject", "IsProcessInJob", "SafeHandle",
               "public static KernelJob Create()", "public void Assign(", "public bool Contains("], "KernelJob.cs", bad)
    if "bInheritHandle = true" in job or "InheritHandle = 1" in job:
        bad.append("KernelJob.cs:作业句柄不许可继承")
    sweeper = text(SWEEPER)
    need(sweeper, ["public sealed record KernelProcessInfo(int Id, string? ImagePath);",
                   "public interface IKernelProcessTable", "public sealed class SystemKernelProcessTable",
                   "public sealed class StrayKernelSweeper", "GetProcessesByName", "QueryFullProcessImageName",
                   "0x1000", "Kill(entireProcessTree: true)", "Environment.ProcessId", "\"sing-box.exe\"",
                   "StringComparison.OrdinalIgnoreCase", "TimeSpan.FromSeconds(5)",
                   "public const string NotStoppedMessage = \"" + NOT_STOPPED + "\";", SWEEP_LOG,
                   "public int Sweep(string executablePath, string? ownedDirectory, Action<string>? log = null)"],
         "StrayKernelSweeper.cs", bad)
    launcher = text(LAUNCHER)
    need(launcher, ["SharedJob", "KernelJob", ".Assign(", BIND_FAILED, "CreateNoWindow = true",
                    "UseShellExecute = false", "internal System.Diagnostics.Process Process"], "ISingBoxLauncher.cs", bad)
    before(launcher, "process.Start()", ".Assign(", "ISingBoxLauncher.cs", bad)
    before(launcher, ".Assign(", "process.BeginOutputReadLine()", "ISingBoxLauncher.cs", bad)
    need(launcher, ["ISingBoxProcess Start(ProcessStartInfo startInfo, Action<string> onLog, Action<int> onExit);"],
         "ISingBoxLauncher.cs(接口签名不许改)", bad)
    manager = text(MANAGER)
    need(manager, ["StrayKernelSweeper? sweeper = null", "public int StopAndSweep()", "OwnedKernelDirectory",
                   "\"bin\""], "SingBoxProcessManager.cs", bad)
    start = between(manager, "public void Start(JsonElement config)", "public static ProcessStartInfo CreateStartInfo")
    before(start, "StopCore();", ".Sweep(", "SingBoxProcessManager.Start", bad)
    before(start, ".Sweep(", "launcher.Start(", "SingBoxProcessManager.Start", bad)
    before(start, ".Sweep(", "WriteConfigAtomically(config);", "SingBoxProcessManager.Start", bad)
    transport = text(TRANSPORT)
    need(transport, ["Func<TimeSpan, CancellationToken, Task>? delay = null", "StopAndSweep()",
                     "连接内核在启动期间退出。", "连接内核尚未建立虚拟网卡。"], "TunnelTransport.cs", bad)
    start = between(transport, "public async Task StartAsync", "public static JsonElement RenderConfiguration")
    before(start, "StopAndSweep()", "manager.Start(", "TunnelTransport.StartAsync", bad)
    need(transport, ["internal const int StaleAdapterPolls = 20;", "internal const int ReadyPolls = 40;",
                     "internal const int SettlePolls = 8;", "TimeSpan.FromMilliseconds(250)"], "TunnelTransport.cs(次数常量)", bad)
    need(start, ["StaleAdapterPolls", "ReadyPolls", "SettlePolls"], "TunnelTransport.StartAsync", bad)
    runtime = text(RUNTIME)
    create = between(runtime, "public static async Task<ClientRuntime> CreateAsync", "internal static IKillSwitch GuardFor")
    need(create, ["StrayKernelSweeper", ".Sweep("], "ClientRuntime.CreateAsync", bad)
    before(create, ".Sweep(", "firewall.RecoverAsync()", "ClientRuntime.CreateAsync", bad)
    before(create, ".Sweep(", "installer.Ensure()", "ClientRuntime.CreateAsync", bad)
    fail(bad)


def tests():
    bad = []
    body = text(NEW_TESTS_FILE)
    if not body:
        bad.append("缺文件 WinClient.Tests/KernelLifetimeTests.cs")
    for method in NEW_TESTS:
        if " " + method + "(" not in body:
            bad.append("KernelLifetimeTests 缺用例 " + method)
    need(body, ["PING.EXE", "CreateNoWindow = true", "RedirectStandardOutput = true", "File.Copy(",
                "Kill(entireProcessTree: true)", "finally"], "KernelLifetimeTests", bad)
    for word in ("WfpEngine.CreateProduction", "new RouteGuard(", "Set-NetFirewall", "CommonApplicationData",
                 "GetProcessesByName(\"sing-box\")", "Thread.Sleep(60000"):
        if word in body:
            bad.append("KernelLifetimeTests 不许碰真系统或真内核:" + word)
    old = text(OLD_TESTS_FILE)
    for method in OLD_TESTS:
        if " " + method + "(" not in old:
            bad.append("ProcessStorageTests 既有用例缺失或改名:" + method)
    need(old, ['Assert.Equal(new[] { "run", "-c", manager.ConfigPath }, launcher.Info.ArgumentList);',
               "Assert.True(launcher.Info.CreateNoWindow);",
               'Assert.Contains("未找到连接内核"'], "ProcessStorageTests(不许动的断言)", bad)
    fail(bad)


def docs():
    bad = []
    doc = text(DOC)
    section = between(doc, "## 内核跟着后台服务走", "\n## ")
    if not section:
        bad.append("服务化与自启说明.md 缺「## 内核跟着后台服务走」一节")
    need(section, ["作业", SWEEP_LOG, NOT_STOPPED, BIND_FAILED, "ProgramData", "bin", "5 秒", "2 秒",
                   "真机"], "「内核跟着后台服务走」一节", bad)
    checklist = between(doc, "## 真机待验证清单", "\n## ")
    need(checklist, ["结束后台服务进程", "内核"], "真机待验证清单", bad)
    fail(bad)


def scope():
    def git(*args):
        out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
        return [line.strip() for line in out.decode("utf-8").split("\n") if line.strip()]

    base = git("merge-base", "origin/main", "HEAD")[0]
    changed = set(git("diff", "--name-only", base))
    changed |= set(git("ls-files", "--others", "--exclude-standard"))
    fail(sorted("改了允许清单以外的文件:" + path for path in changed if path not in ALLOWED))


if __name__ == "__main__":
    commands = {"shape": shape, "tests": tests, "docs": docs, "scope": scope}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print("用法:python 本文件 shape|tests|docs|scope")
        sys.exit(2)
    commands[sys.argv[1]]()
