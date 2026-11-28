"""验收脚本:别的页也显示提示语、诊断说明改字(WINCLIENT-ERROR-HINT-ONLY-ON-CONNECT-PAGE-1127、
WINCLIENT-DIAG-HINT-TEXT-OUTDATED-1128)。用法:python <本文件> shape|tests|scope"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SHELL = "winclient/WinClient.App/Views/MainShell.xaml"
UPDATE = "winclient/WinClient.App/Views/UpdatePage.xaml"
MODEL = "winclient/WinClient.App/MainViewModel.cs"
MODEL_TESTS = "winclient/WinClient.UiTests/ViewModelPageNoticeTests.cs"
SHELL_TESTS = "winclient/WinClient.UiTests/ShellPageNoticeTests.cs"
ALLOWED = {SHELL, UPDATE, MODEL, MODEL_TESTS, SHELL_TESTS}

# MainShell.xaml:原来的内容区那一行换成下面五行,</ContentControl> 后面加一行 </DockPanel>;别的行不动(缩进随意)。
OLD_HOST = ('<ContentControl x:Name="PageHost" Grid.Column="1" Margin="32,24" Content="{Binding}" '
            'HorizontalContentAlignment="Stretch" VerticalContentAlignment="Stretch">')
NEW_HOST = ('<ContentControl x:Name="PageHost" Margin="32,24" Content="{Binding}" '
            'HorizontalContentAlignment="Stretch" VerticalContentAlignment="Stretch">')
SHELL_OPEN = [
    '<DockPanel Grid.Column="1" LastChildFill="True">',
    '<Border x:Name="PageNotice" DockPanel.Dock="Bottom" BorderBrush="{DynamicResource Yc.Line}" BorderThickness="0,1,0,0" '
    'Padding="32,8,32,12" Visibility="{Binding PageNoticeText, Converter={x:Static t:VisibilityConverter.Instance}}">',
    '<TextBlock Text="{Binding PageNoticeText}" FontSize="{DynamicResource Yc.FontSize.Sm}" TextWrapping="Wrap" '
    't:SemanticText.NormalKey="Yc.Text2" t:SemanticText.Tone="{Binding Hero.SubtitleTone}" AutomationProperties.LiveSetting="Polite"/>',
    "</Border>",
    NEW_HOST,
]
HOST_END = "</ContentControl>"
SHELL_CLOSE = "</DockPanel>"

# UpdatePage.xaml:只换「诊断」下面那句说明。
OLD_TEXT = "把防火墙审计和环境自检报告合成一个文件(不含出口 IP),发给管理员排查。"
NEW_TEXT = "把连接状态、日志末尾、防火墙与网卡现状、环境自检合成一个文件，发给管理员排查。不含出口 IP、节点地址和配对内容。"

# MainViewModel.cs:只加行。加的代码行只能是下面这两种(注释行随意)。
PROPERTY = 'public string PageNoticeText => CurrentPage == PageKind.Connect ? "" : Message.Trim();'
NOTIFY = "Notify(nameof(PageNoticeText));"
SETTER_BEFORE = "currentPage = value; Notify();"
SETTER_AFTER = "if (value == PageKind.Environment) _ = LoadSelfCheckAsync();"
REFRESH_START = "private void Refresh()"
REFRESH_END = "public Task ExportDiagnosticsAsync(string path) => RunAsync(async () =>"

FAILED = "操作未完成，请检查后台服务或联系管理员。"
PAGES = ["[InlineData(PageKind.Routing)]", "[InlineData(PageKind.Environment)]", "[InlineData(PageKind.Account)]",
         "[InlineData(PageKind.Update)]"]
NEW_TESTS = {
    MODEL_TESTS: {
        "NoticeEmptyOnConnectPage": ["PageNoticeText", 'Assert.Equal("", '],
        "NoticeMirrorsMessageOnOtherPages": [*PAGES, "model.Message.Trim()", "PageNoticeText"],
        "NoticeEmptyWhenNoMessage": ["ControlSnapshot.CurrentVersion", "PageNoticeText"],
        "NoticeCarriesVersionReminderWithoutLeadingSpace": ['StartsWith("后台已更新到', "PageNoticeText"],
        "SwitchingPageRaisesNoticeChange": ["PropertyChanged", "nameof(MainViewModel.PageNoticeText)", "PageKind.Account"],
        "FailedOperationOnAccountPageShowsNotice": ["RedeemCommand.Execute(null)", FAILED, "PageKind.Account"],
    },
    SHELL_TESTS: {
        "NoticeDockedAtBottomOnOtherPages": [*PAGES, '"PageNotice"', '"PageHost"', "notice.TranslatePoint(", "notice.ActualWidth",
                                             "host.ActualHeight", "PageNoticeText"],
        "NoticeCollapsedOnConnectPage": ['"PageNotice"', "Assert.Equal(Visibility.Collapsed, notice.Visibility)",
                                         "Assert.Equal(552, host.ActualHeight"],
        "NoticeCollapsedWithoutMessageKeepsPageArea": ["ControlSnapshot.CurrentVersion", "Assert.Equal(Visibility.Collapsed, notice.Visibility)",
                                                       "Assert.Equal(552, host.ActualHeight"],
        "NoticeAppearsAfterFailedOperation": ["RedeemCommand.Execute(null)", "UpdateLayout()",
                                              "Assert.Equal(Visibility.Visible, notice.Visibility)", FAILED],
    },
}
SKIPS = r"\bSkip\s*=|\bAssert\.Skip\w*\s*\(|\bSkip\.If\w*\s*\(|\bSkippable(?:Fact|Theory)\b"
REAL_WAITS = r"\bTask\.Delay\s*\(|\bThread\.Sleep\s*\("


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT, stderr=subprocess.DEVNULL)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    try:
        return git("show", f"{base()}:{path}").replace("\r\n", "\n")
    except subprocess.CalledProcessError:
        return ""


def stripped(source):
    return [line.strip() for line in source.lstrip("﻿").split("\n") if line.strip()]


def first_difference(got, want):
    for number, (a, b) in enumerate(zip(got, want, strict=False), 1):
        if a != b:
            return f"第 {number} 个非空行应为「{b[:90]}」,现在是「{a[:90]}」"
    return f"非空行数应为 {len(want)},现在是 {len(got)}"


def shell_problems(new, old):
    lines = stripped(old)
    if lines.count(OLD_HOST) != 1 or lines.count(HOST_END) != 1:
        return [f"{SHELL} 改动前的样子和契约对不上,交 blocked"]
    want = []
    for line in lines:
        if line == OLD_HOST:
            want += SHELL_OPEN
        elif line == HOST_END:
            want += [HOST_END, SHELL_CLOSE]
        else:
            want.append(line)
    got = stripped(new)
    return [] if got == want else [f"{SHELL} 和定稿不一样:" + first_difference(got, want)]


def update_problems(new, old):
    if old.count(OLD_TEXT) != 1:
        return [f"{UPDATE} 改动前的样子和契约对不上,交 blocked"]
    want = [line.rstrip() for line in old.replace(OLD_TEXT, NEW_TEXT).split("\n")]
    got = [line.rstrip() for line in new.split("\n")]
    return [] if got == want else [f"{UPDATE} 只许换那一句说明:" + first_difference(got, want)]


def model_problems(new, old):
    bad = []
    old_lines = [line.rstrip() for line in old.split("\n")]
    new_lines = [line.rstrip() for line in new.split("\n")]
    added = []
    position = 0
    for line in new_lines:
        if position < len(old_lines) and line == old_lines[position]:
            position += 1
        else:
            added.append(line.strip())
    if position != len(old_lines):
        return [f"{MODEL} 只许加行:原来的第 {position + 1} 行「{old_lines[position].strip()[:80]}」被改了或删了"]
    code = [line for line in added if line and not line.startswith("//")]
    if code.count(PROPERTY) != 1:
        bad.append(f"{MODEL} 要正好加一行:{PROPERTY}")
    if code.count(NOTIFY) != 2:
        bad.append(f"{MODEL} 要正好加两行:{NOTIFY}(页码的 set 里一行、Refresh 里一行)")
    extra = [line for line in code if line not in (PROPERTY, NOTIFY)]
    if extra:
        bad.append(f"{MODEL} 多加了别的代码:{extra[0][:90]}")
    flat = [line.strip() for line in new_lines]
    spots = [index for index, line in enumerate(flat) if line == NOTIFY]
    if len(spots) == 2 and not bad:
        setter = (flat.index(SETTER_BEFORE), flat.index(SETTER_AFTER))
        refresh = (flat.index(REFRESH_START), flat.index(REFRESH_END))
        if not setter[0] < spots[0] < setter[1]:
            bad.append(f"{MODEL} 第一行 {NOTIFY} 要加在「{SETTER_BEFORE}」和「{SETTER_AFTER}」之间")
        if not refresh[0] < spots[1] < refresh[1]:
            bad.append(f"{MODEL} 第二行 {NOTIFY} 要加在 Refresh 方法里")
    return bad


def shape_problems(new, old):
    return (shell_problems(new[SHELL], old[SHELL]) + update_problems(new[UPDATE], old[UPDATE])
            + model_problems(new[MODEL], old[MODEL]))


def tests_problems(new):
    bad = []
    for path, cases in NEW_TESTS.items():
        source = new[path]
        if not source:
            bad.append(f"缺测试文件 {path}")
            continue
        if re.search(SKIPS, source):
            bad.append(f"{path} 里不许跳过用例")
        if re.search(REAL_WAITS, source):
            bad.append(f"{path} 里不许真的等时间(Task.Delay / Thread.Sleep)")
        if '[Collection("界面线程")]' not in source:
            bad.append(f'{path} 的测试类要标 [Collection("界面线程")]')
        starts = [(match.start(), match.group(1)) for match in re.finditer(
            r"((?:\[Fact\]|\[Theory\])\s*(?:\[InlineData\([^\n]*\)\]\s*)*)public (?:void|async Task) \w+\(", source)]
        for name, tokens in cases.items():
            match = re.search(r"((?:\[Fact\]|\[Theory\])\s*(?:\[InlineData\([^\n]*\)\]\s*)*)public (?:void|async Task) "
                              + name + r"\(", source)
            if not match:
                bad.append(f"{path} 缺用例 {name}(要标 [Fact] 或 [Theory],签名 public void 或 public async Task)")
                continue
            later = [start for start, _ in starts if start > match.start()]
            body = source[match.start():later[0] if later else len(source)]
            if body.count("Assert.") < 2:
                bad.append(f"{path} 的 {name} 至少要两处 Assert.")
            for token in tokens:
                if token not in body:
                    bad.append(f"{path} 的 {name} 里要出现:{token}")
    return bad


def shape():
    paths = (SHELL, UPDATE, MODEL)
    return shape_problems({path: text(path) for path in paths}, {path: before(path) for path in paths})


def tests():
    return tests_problems({path: text(path) for path in NEW_TESTS})


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
