"""界面换位单 yc-ui-handover-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WIN = ROOT / "winclient"
HANDOVER = WIN / "WinClient.Core/Hosting/UiHandover.cs"
INSTALLER_PLAN = WIN / "WinClient.Core/Hosting/ServiceInstaller.cs"
RUNNER = WIN / "WinClient.App/Hosting/InstallerRunner.cs"
MODEL = WIN / "WinClient.App/MainViewModel.cs"
APP = WIN / "WinClient.App/App.xaml.cs"
PRESENTATION = WIN / "WinClient.App/Presentation/StatusPresentation.cs"
SERVICE_DOC = ROOT / "docs/winclient/服务化与自启说明.md"
RELEASE_DOC = ROOT / "docs/winclient/打包与发布说明.md"
ALLOWED = {
    "winclient/WinClient.Core/Hosting/UiHandover.cs",
    "winclient/WinClient.Core/Hosting/ServiceInstaller.cs",
    "winclient/WinClient.App/Hosting/InstallerRunner.cs",
    "winclient/WinClient.App/MainViewModel.cs",
    "winclient/WinClient.App/App.xaml.cs",
    "winclient/WinClient.App/Presentation/StatusPresentation.cs",
    "winclient/WinClient.Tests/UiHandoverTests.cs",
    "winclient/WinClient.UiTests/StatusPresentationTests.cs",
    "winclient/WinClient.UiTests/ViewModelTests.cs",
    "docs/winclient/服务化与自启说明.md",
    "docs/winclient/打包与发布说明.md",
}
UPGRADE_SUBTITLE = "这个文件比电脑上装的版本新"
UPGRADE_MESSAGE_TAIL = "点「安装这个版本」换成新版，需管理员确认一次。"
HANDOVER_FAILED = "无法打开已安装的客户端"
HANDOVER_FAILED_HINT = "请从右下角托盘图标打开客户端，或重启电脑后再试。"
ROLLBACK = "新版本的后台服务未能启动，已改回原来的版本。"
SECTION = "### 界面换到安装目录里的那一份"
RELEASE_SENTENCE = (
    "界面随即换成安装目录里的那一份，之后再双击下载的文件，打开的也是安装目录里的那一份"
    "（细则见服务化与自启说明「界面换到安装目录里的那一份」）；"
)
NEW_TESTS = {
    "winclient/WinClient.Tests/UiHandoverTests.cs": [
        "ServiceExecutableReadsQuotedPathFromServiceCommand",
        "ServiceExecutableRejectsOtherShapes",
        "StaysWhenAlreadyUnderAppRoot",
        "HandsOverToIdenticalInstalledCopy",
        "OffersUpgradeWhenThisFileIsNewerThanInstalled",
        "HandsOverWhenInstalledIsSameOrNewerOrUnparsable",
        "ReinstallWhenInstalledCopyIsUnusable",
        "SameContentNeedsEqualLengthAndHash",
        "SwitchesExecutableOnlyWhenRegisteredPathDiffers",
    ],
    "winclient/WinClient.UiTests/StatusPresentationTests.cs": ["可安装新版本时主按钮是安装这个版本"],
    "winclient/WinClient.UiTests/ViewModelTests.cs": [
        "首次安装成功后界面交接给已安装的程序",
        "界面在安装目录外且已装同一份时直接交接",
        "交接失败时停在可重试的提示",
        "这个文件比已装的新时先提示安装再交接",
        "安装没完成时不交接",
        "服务登记的程序不可用时回到安装",
        "界面已在安装目录时照旧判断服务状态",
    ],
}
# 后台服务的核验、既有界面用例必须原样保留。
MODEL_KEEP = [
    "if (!PipePeer.VerifyServer(pipe, UpdatePlanner.DefaultAppRoot))",
    'Update(snapshot with { Status = "无法连接后台服务", Message = "无法连接后台服务,请重启电脑或联系管理员" });',
    'Update(snapshot with { Message = "操作未完成，请重试或联系管理员。" });',
]
VIEWMODEL_TESTS_KEEP = [
    "更新提示超过一秒才出现",
    "更新结束立即隐藏且再开始重新计时",
    "预览声明连接可用时按钮启用且可用性仍受后台状态约束",
    "浏览器提醒随快照更新且没有后台连接不能继续",
    "强制恢复在连接保护或后台不可用时禁用",
    "浏览器复核无需后台且保留主消息",
    "专用浏览器无需后台且不修改主消息",
    "自检明细解析并映射四种结果",
    "预览不建立连接且保留消息和版本",
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


def shape():
    bad = []
    handover = text(HANDOVER)
    if not handover:
        bad.append("缺文件 WinClient.Core/Hosting/UiHandover.cs")
    if not re.search(
        r"public\s+enum\s+UiHandoverKind\s*\{\s*Stay\s*,\s*Handover\s*,\s*Upgrade\s*,\s*Reinstall\s*\}",
        handover,
    ):
        bad.append("UiHandoverKind 应恰为 Stay, Handover, Upgrade, Reinstall")
    need(
        handover,
        [
            "namespace WinClient.Core.Hosting",
            "record UiHandoverDecision(",
            "InstalledVersion",
            "public static string? ServiceExecutable(string? imagePath)",
            "public static UiHandoverDecision Decide(",
            "public static bool SameContent(string first, string second)",
            "ServerIdentity.IsImageUnderRoot",
            "UpdateVersion",
            "SHA256",
        ],
        "UiHandover.cs",
        bad,
    )
    for word in ("Process.Start", "Registry", "runas"):
        if word in handover:
            bad.append("UiHandover.cs 是纯判定,不许出现 " + word)
    need(
        text(INSTALLER_PLAN),
        ["public static bool SwitchesExecutable(string? previous, string destination)"],
        "ServiceInstaller.cs",
        bad,
    )
    runner = text(RUNNER)
    need(
        runner,
        [
            "public static string? RegisteredServiceExecutable()",
            "public static UiHandoverDecision HandoverDecision()",
            '"ImagePath"',
            "ServiceInstaller.SwitchesExecutable(",
            ROLLBACK,
            # 既有的提权入口与隐藏窗口写法不许动。
            'Arguments = action, Verb = "runas", UseShellExecute = true, CreateNoWindow = true',
        ],
        "InstallerRunner.cs",
        bad,
    )
    if runner.count('Verb = "runas"') != 1:
        bad.append("InstallerRunner.cs 的提权入口应恰好一处")
    presentation = text(PRESENTATION)
    if not re.search(
        r"enum\s+ServiceAvailability\s*\{\s*Unavailable\s*,\s*NeedInstall\s*,\s*NeedRepair\s*,"
        r"\s*Ready\s*,\s*NeedUpgrade\s*\}",
        presentation,
    ):
        bad.append("ServiceAvailability 应在末尾追加 NeedUpgrade,既有四个值次序不动")
    need(
        presentation,
        ['"可安装新版本"', '"安装这个版本"', f'"{UPGRADE_SUBTITLE}"'],
        "StatusPresentation.cs",
        bad,
    )
    model = text(MODEL)
    need(
        model,
        [
            "ServiceStatusProvider",
            "DecideHandoverAsync",
            "ElevateAsync",
            "public Func<string, bool>? Handover { get; set; }",
            "ServiceAvailability.NeedUpgrade",
            f'"{HANDOVER_FAILED}"',
            f'"{HANDOVER_FAILED_HINT}"',
            UPGRADE_MESSAGE_TAIL,
            '"后台服务 · "',
            *MODEL_KEEP,
        ],
        "MainViewModel.cs",
        bad,
    )
    for word in ("Process.Start", "runas"):
        if word in model:
            bad.append("MainViewModel.cs 不许出现 " + word)
    app = text(APP)
    need(
        app,
        ["Model.Handover", "UseShellExecute = false", "CreateNoWindow = true", '"--tray"'],
        "App.xaml.cs",
        bad,
    )
    if "runas" in app or "Verb" in app:
        bad.append("App.xaml.cs 启动已安装的程序不许提权")
    fail(bad)


def tests():
    bad = []
    for name, methods in NEW_TESTS.items():
        body = text(ROOT / name)
        if not body:
            bad.append("缺文件 " + name)
            continue
        for method in methods:
            if " " + method + "(" not in body:
                bad.append(f"{name} 缺用例 {method}")
    view = text(ROOT / "winclient/WinClient.UiTests/ViewModelTests.cs")
    for method in VIEWMODEL_TESTS_KEEP:
        if " " + method + "(" not in view:
            bad.append("ViewModelTests 既有用例被改名或删除:" + method)
    for word in (".Wait(", ".Result", "NamedPipe"):
        if word in view:
            bad.append("ViewModelTests 不许出现 " + word)
    # 既有四处同步取结果原样保留,新用例不许再加。
    if view.count("GetAwaiter().GetResult()") != 4:
        bad.append("ViewModelTests 的 GetAwaiter().GetResult() 应仍是既有的 4 处,新用例不许阻塞等待")
    if "IsCompletedSuccessfully" not in view:
        bad.append("ViewModelTests 新用例要断言初始化任务当场完成(IsCompletedSuccessfully)")
    presentation = text(ROOT / "winclient/WinClient.UiTests/StatusPresentationTests.cs")
    row = (
        '[InlineData(ServiceAvailability.NeedUpgrade, "可安装新版本", "安装这个版本", '
        "Tone.N, Glyph.Plug, TrayIcon.N)]"
    )
    if row not in presentation:
        bad.append("StatusPresentationTests 的「服务优先于连接状态」缺 NeedUpgrade 一行")
    for row in (
        '[InlineData(ServiceAvailability.NeedInstall, "需安装后台服务", "安装后台服务", '
        "Tone.N, Glyph.Plug, TrayIcon.N)]",
        '[InlineData(ServiceAvailability.NeedRepair, "后台服务未运行", "修复后台服务", '
        "Tone.Warn, Glyph.Bang, TrayIcon.Warn)]",
        '[InlineData(ServiceAvailability.Unavailable, "后台服务连接已中断", "重新连接后台服务", '
        "Tone.Bad, Glyph.X, TrayIcon.Bad)]",
    ):
        if row not in presentation:
            bad.append("StatusPresentationTests 既有数据行被改动")
    core = text(ROOT / "winclient/WinClient.Tests/UiHandoverTests.cs")
    for word in ("Registry", "Process.Start", "ServiceController"):
        if word in core:
            bad.append("UiHandoverTests 不许碰真系统:" + word)
    fail(bad)


def docs():
    bad = []
    service = text(SERVICE_DOC)
    if SECTION not in service:
        bad.append(f"服务化与自启说明缺小节「{SECTION}」")
    else:
        if not (
            service.find("## 角色、权限与安装位置")
            < service.find(SECTION)
            < service.find("## 后台与界面分离")
        ):
            bad.append("新小节应放在「角色、权限与安装位置」一节的末尾")
        part = service.partition(SECTION)[2].partition("\n## ")[0]
        need(
            part,
            [
                "ImagePath",
                "SHA256",
                "Local\\YuanC-ShowWindow",
                "--tray",
                "可安装新版本",
                "安装这个版本",
                "需安装后台服务",
                HANDOVER_FAILED,
                ROLLBACK,
                "版本号",
            ],
            "新小节",
            bad,
        )
        if part.count("\n|") < 6:
            bad.append("新小节要用表格列出五种情形")
        for word in ("申请记录", "git 写操作", "工人", "派单"):
            if word in part:
                bad.append("新小节混进了施工过程用语:" + word)
    if "- 首次运行换位：" not in service:
        bad.append("服务化与自启说明的真机清单缺「- 首次运行换位：」一条")
    if "- 覆盖安装：" not in service:
        bad.append("服务化与自启说明的真机清单缺「- 覆盖安装：」一条")
    release = text(RELEASE_DOC)
    if "安装后服务自动启动，" + RELEASE_SENTENCE not in release:
        bad.append("打包与发布说明「客户电脑首次运行」缺换位那一句原文")
    if "版本号必须比已装的高" not in release:
        bad.append("打包与发布说明缺「版本号必须比已装的高」")
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
