"""工单 yc-entry-points-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ENTRY = "winclient/WinClient.Core/Hosting/EntryPoints.cs"
SHORTCUT = "winclient/WinClient.Core/Hosting/ShellShortcut.cs"
INSTALLER = "winclient/WinClient.App/Hosting/InstallerRunner.cs"
PROMPT = "winclient/WinClient.App/Hosting/UninstallPrompt.cs"
PROGRAM = "winclient/WinClient.App/Program.cs"
APPLIER = "winclient/WinClient.App/Hosting/UpdateApplier.cs"
HOST = "winclient/WinClient.App/Hosting/UpdateWindowsHost.cs"
ENTRY_TESTS = "winclient/WinClient.Tests/EntryPointTests.cs"
UPDATE_TESTS = "winclient/WinClient.Tests/UpdateApplierTests.cs"
ALLOWED = {ENTRY, SHORTCUT, INSTALLER, PROMPT, PROGRAM, APPLIER, HOST, ENTRY_TESTS, UPDATE_TESTS}
CONSTANTS = [
    'public const string DisplayName = "澳洲出口客户端";',
    'public const string ShortcutFileName = "澳洲出口客户端.lnk";',
    'public const string Publisher = "YuanC";',
    'public const string UninstallParentPath = @"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";',
    'public const string UninstallKeyName = "YuanC";',
    'public const string UninstallRole = "--uninstall-prompt";',
    'public const string StartMenuItem = "开始菜单图标";',
    'public const string DesktopItem = "桌面图标";',
    'public const string UninstallItem = "卸载入口";',
    'public const string ApplyFailedSuffix = "没有建成，重新安装一次可以补上。";',
    'public const string RemoveFailedSuffix = "没有删掉，可以手动删除。";',
    'public const string UninstallConfirmText = "确定卸载澳洲出口客户端吗？卸载会断开连接并撤掉断网保护，电脑恢复原来的网络。配对文件和日志会保留。";',
    'public const string UninstallDoneText = "已卸载。配对文件和日志还留在电脑上，重新安装后可以接着用。";',
    'public const string UninstallFailedText = "卸载没有完成。请再试一次，或联系管理员。";',
]
SHELL_LINK_ORDER = [
    "GetPath", "GetIDList", "SetIDList", "GetDescription", "SetDescription", "GetWorkingDirectory",
    "SetWorkingDirectory", "GetArguments", "SetArguments", "GetHotkey", "SetHotkey", "GetShowCmd",
    "SetShowCmd", "GetIconLocation", "SetIconLocation", "SetRelativePath", "Resolve", "SetPath",
]
ENTRY_TEST_NAMES = [
    "ConstantsAndCommandAreExact",
    "ShortcutRoundTripsThroughShellLink",
    "ApplyCreatesShortcutsAndUninstallEntry",
    "ApplyTwiceDoesNotRewriteAndFollowsNewExecutable",
    "RemoveDeletesAllAndToleratesMissing",
    "ApplyReportsOnlyTheFailedItem",
]
UPDATE_NEW_TESTS = ["EntryPointsFollowServiceExecutable", "EntryPointFailureCannotUndoSuccessfulServiceSwitch"]
UPDATE_OLD_TESTS = [
    "CommandsAndRecoveryBranches",
    "SilentPipeChecksRunningServiceImageBeforeMarkingBad",
    "LogWriteFailureCannotUndoSuccessfulServiceSwitch",
    "MissingOrCorruptPendingReturnsTwoWithoutCommands",
    "StartupRecoversOnlyStalePending",
]
OLD_TEXTS = [
    "未能撤销断网保护，卸载已停止，请联系管理员。",
    "无法联系后台服务，将在停止服务后直接恢复网络。",
    "后台服务身份核验失败，按未联系上处理。",
    "新版本的后台服务未能启动，已改回原来的版本。",
    "此操作需要管理员确认，请从客户端窗口点击安装或修复。",
]


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def between(source, start, end):
    """取 start 到 end 之间的正文;找不到返回空串。"""
    parts = source.split(start, 1)
    return parts[1].split(end, 1)[0] if len(parts) == 2 else ""


def need(source, tokens, where, bad):
    for token in tokens:
        if token not in source:
            bad.append(f"{where} 缺 {token}")


def shape():
    bad = []
    entry = text(ENTRY)
    if not entry:
        bad.append("缺文件 EntryPoints.cs")
    for line in CONSTANTS:
        if line not in entry:
            bad.append(f"EntryPoints.cs 缺常量或文字与契约不一致:{line[:48]}")
    need(entry, ['[SupportedOSPlatform("windows")]', "namespace WinClient.Core.Hosting;",
                 "public sealed class EntryPoints(string programsDirectory, string desktopDirectory, RegistryKey hive)",
                 "public static EntryPoints ForMachine()", "SpecialFolder.CommonPrograms",
                 "SpecialFolder.CommonDesktopDirectory", "Registry.LocalMachine",
                 "public static string UninstallCommand(string executable)",
                 "public static string? Describe(IReadOnlyList<string> failed, string suffix)",
                 "public IReadOnlyList<string> Apply(string executable, string version)",
                 "public IReadOnlyList<string> Remove()", "ShellShortcut.Read(", "ShellShortcut.Write(",
                 "RegistryValueKind.DWord", "DeleteSubKeyTree(UninstallKeyName"], "EntryPoints.cs", bad)

    shortcut = text(SHORTCUT)
    if not shortcut:
        bad.append("缺文件 ShellShortcut.cs")
    need(shortcut, ['[SupportedOSPlatform("windows")]', "public static class ShellShortcut",
                    "public sealed record Link(string Target, string Arguments, string WorkingDirectory, string Description);",
                    "public static void Write(string linkPath, Link link)", "public static Link? Read(string linkPath)",
                    "00021401-0000-0000-C000-000000000046", "000214F9-0000-0000-C000-000000000046",
                    "IPersistFile", "FinalReleaseComObject"], "ShellShortcut.cs", bad)
    order = re.findall(r"^\s*void\s+(\w+)\(", between(shortcut, "interface IShellLinkW", "\n    }"), flags=re.M)
    if order != SHELL_LINK_ORDER:
        bad.append("ShellShortcut.cs 里 IShellLinkW 的方法个数或顺序与系统接口不一致(照契约 ③ 抄)")
    for path, source in ((ENTRY, entry), (SHORTCUT, shortcut)):
        for word in ("Process.Start", "ProcessStartInfo", "powershell", "WScript", "cmd.exe"):
            if word.lower() in source.lower():
                bad.append(f"{path} 里出现了 {word}(本单不起子进程)")

    installer = text(INSTALLER)
    install = between(installer, "private async Task InstallAsync()", "private async Task StartSwitchedAsync(")
    apply_call = "Report(EntryPoints.ForMachine().Apply(destination, ServiceInstaller.ReleaseVersion(version)), EntryPoints.ApplyFailedSuffix);"
    if apply_call not in install:
        bad.append("InstallAsync 里没有按契约 ⑦ 建图标与卸载入口")
    elif install.index(apply_call) < install.index("else await StartAsync();"):
        bad.append("InstallAsync 里建图标那一行要放在启动后台服务之后")
    uninstall = between(installer, "private async Task UninstallAsync()", "private async Task StopServiceAsync()")
    remove_call = "Report(EntryPoints.ForMachine().Remove(), EntryPoints.RemoveFailedSuffix);"
    if remove_call not in uninstall:
        bad.append("UninstallAsync 里没有按契约 ⑧ 删图标与卸载入口")
    elif "DeleteValue(ServiceInstaller.RunValueName" not in uninstall or \
            uninstall.index(remove_call) < uninstall.index("DeleteValue(ServiceInstaller.RunValueName"):
        bad.append("UninstallAsync 里删图标那一行要放在删登录自启值之后")
    need(installer, ["private static void Report(IReadOnlyList<string> failed, string suffix)",
                     'if (action is not ("--install" or "--repair" or "--uninstall"))',
                     "await Task.Delay(TimeSpan.FromSeconds(3));"] + OLD_TEXTS, "InstallerRunner.cs", bad)

    prompt = text(PROMPT)
    if not prompt:
        bad.append("缺文件 UninstallPrompt.cs")
    need(prompt, ["public static class UninstallPrompt", "public static int Run()",
                  "EntryPoints.UninstallConfirmText", "EntryPoints.UninstallDoneText", "EntryPoints.UninstallFailedText",
                  "MessageBoxButton.YesNo", "MessageBoxResult.No", 'RunAsync("--uninstall")',
                  'ElevateAsync("--uninstall")', "GetProcessesByName(", "Environment.ProcessId",
                  "CallerIdentity.IsTrusted(", "UpdatePlanner.DefaultAppRoot", ".Kill()"], "UninstallPrompt.cs", bad)
    for word in ("Process.Start(", "ProcessStartInfo"):
        if word in prompt:
            bad.append(f"UninstallPrompt.cs 里出现了 {word}(提权只走 InstallerRunner.ElevateAsync)")

    program = text(PROGRAM)
    need(program, ['case "--uninstall-prompt":', "UninstallPrompt.Run()", 'case "--install":', 'case "--uninstall":',
                   'case "--repair":', 'case "--apply-update":', 'case "--leak-check":', 'case "--service":',
                   "无法识别启动参数，请使用客户端快捷方式打开。"], "Program.cs", bad)

    applier = text(APPLIER)
    need(applier, ["void SetEntryPoints(string executable, string version);",
                   "private static void RefreshEntryPoints(IUpdateHost host, string executable, string version, ILog log)",
                   "开始菜单图标、桌面图标或卸载入口未能更新。"], "UpdateApplier.cs", bad)
    if applier.count("host.SetEntryPoints(") != 1:
        bad.append("UpdateApplier.cs 里 host.SetEntryPoints 只许在 RefreshEntryPoints 里调一次")
    if applier.count("RefreshEntryPoints(host,") != 2:
        bad.append("UpdateApplier.cs 里 RefreshEntryPoints 只许调两处(更新成功、回滚)")
    complete = between(applier, "internal static void Complete(", "private static bool HasLinks(")
    if not re.search(r"host\.SetRunValue\(pending\.NewExe\);\s*\n\s*RefreshEntryPoints\(host, pending\.NewExe, pending\.NewVersion, log\);", complete):
        bad.append("Complete 里 SetRunValue(新版) 的下一行不是 RefreshEntryPoints(新版)")
    if not re.search(r"host\.SetRunValue\(pending\.OldExe\);\s*\n\s*RefreshEntryPoints\(host, pending\.OldExe, pending\.OldVersion, log\);", applier):
        bad.append("回滚段里 SetRunValue(旧版) 的下一行不是 RefreshEntryPoints(旧版)")
    host = text(HOST)
    need(host, ["public void SetEntryPoints(string executable, string version)",
                "EntryPoints.ForMachine().Apply(executable, version)", "public void SetRunValue(string executable)"],
         "UpdateWindowsHost.cs", bad)
    return bad


def tests():
    bad = []
    body = text(ENTRY_TESTS)
    if not body:
        bad.append("缺测试文件 EntryPointTests.cs")
    need(body, ['[SupportedOSPlatform("windows")]', "public sealed class EntryPointTests", "Registry.CurrentUser",
                "YuanC-Tests", "AppContext.BaseDirectory"], "EntryPointTests.cs", bad)
    for name in ENTRY_TEST_NAMES:
        if not re.search(rf"public (?:async Task|void) {name}\(", body):
            bad.append(f"EntryPointTests.cs 缺用例 {name}")
    for word, label in (("Registry.LocalMachine", "真的机器注册表"), ("ForMachine()", "真的开始菜单与桌面"),
                        ("SpecialFolder.", "系统目录"), ("GetTempPath", "系统临时目录(路径可能是短名,读回对不上)"),
                        ("TempDirectory", "TempDirectory(它建在系统临时目录下)"), ("Skip", "跳过"),
                        ("Process.Start", "子进程")):
        if word in body:
            bad.append(f"EntryPointTests.cs 里用了{label}:{word}")

    update = text(UPDATE_TESTS)
    old = git("show", f"{base()}:{UPDATE_TESTS}").replace("\r\n", "\n")
    for name in UPDATE_OLD_TESTS:
        before, after = between(old, f" {name}(", "\n    }\n"), between(update, f" {name}(", "\n    }\n")
        if not after:
            bad.append(f"UpdateApplierTests.cs 里既有用例 {name} 不见了")
        elif before != after:
            bad.append(f"UpdateApplierTests.cs 里既有用例 {name} 被改了")
    for name in UPDATE_NEW_TESTS:
        if not re.search(rf"public async Task {name}\(", update):
            bad.append(f"UpdateApplierTests.cs 缺新用例 {name}")
    need(update, ["public void SetEntryPoints(string exe, string version)", "EntriesThrow"], "UpdateApplierTests.cs", bad)

    def count(source):
        return len(re.findall(r"^\s*\[(?:Fact|Theory)", source, flags=re.M))

    if count(update) < count(old) + len(UPDATE_NEW_TESTS):
        bad.append(f"UpdateApplierTests.cs 用例数不对:原有 {count(old)} 个,现在 {count(update)} 个")
    if update.count("Skip") > old.count("Skip"):
        bad.append("UpdateApplierTests.cs 里新增了跳过")
    return bad


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
