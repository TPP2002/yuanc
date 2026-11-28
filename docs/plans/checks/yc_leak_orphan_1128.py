"""验收脚本:泄漏检测做到一半进程被结束,留下的系统抓包由后台服务启动时清掉(WINCLIENT-LEAKCHECK-ORPHAN-CAPTURE-1128)。
用法:python <本文件> shape|tests|scope|write-tests"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CAPTURE = "winclient/WinClient.Core/Diagnostics/LeakCapture.cs"
SERVICE = "winclient/WinClient.Core/Diagnostics/LeakCheckService.cs"
TESTS = "winclient/WinClient.Tests/LeakOrphanCaptureTests.cs"
REFERENCE = "docs/plans/checks/yc_leak_orphan_1128_tests.txt"
ALLOWED = {CAPTURE, SERVICE, TESTS}

# 每个文件的改法,一条是(怎么改, 改动前文件里正好出现一次的那一行, 要加进去或换上去的行)。
# after 是加在那一行后面,before 是加在那一行前面,replace 是把那一行换掉。
# 比对时每行去掉首尾空白;空行、以 // 开头的注释行不算。
CAPTURE_EDITS = [
    ("after", 'public const string NodeMissing = "未找到隧道内核的连接，请先连接，或用 --node 指定节点地址";', [
        'public const string RunningMarker = "capture.running";',
    ]),
    ("after", 'var pcap = Path.Combine(options.OutputDirectory, "capture.pcapng");', [
        "var marker = Path.Combine(options.OutputDirectory, RunningMarker);",
    ]),
    ("after", 'if (await Step(["filter", "remove"], token) is { } filterFailed) return Unable(filterFailed);', [
        "TryWrite(marker);",
    ]),
    ("after", "if (!options.KeepCapture) { TryDelete(etl); TryDelete(pcap); }", [
        "TryDelete(marker);",
    ]),
    ("before", "private static LeakCheckResult Analyze(LeakCheckOptions options, string pcap, IReadOnlySet<IPAddress> local,", [
        "public async Task<int> CleanupOrphansAsync(string root, CancellationToken token)",
        "{",
        "string[] markers;",
        "try",
        "{",
        "if (!Directory.Exists(root)) return 0;",
        "markers = Directory.GetDirectories(root).Select(directory => Path.Combine(directory, RunningMarker)).Where(File.Exists).ToArray();",
        "}",
        "catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }",
        "if (markers.Length == 0) return 0;",
        'try { await Step(["stop"], token).ConfigureAwait(false); }',
        "catch (OperationCanceledException) { return 0; }",
        "foreach (var marker in markers)",
        "{",
        "var directory = Path.GetDirectoryName(marker)!;",
        'TryDelete(Path.Combine(directory, "capture.etl"));',
        'TryDelete(Path.Combine(directory, "capture.pcapng"));',
        "TryDelete(marker);",
        "}",
        "return markers.Length;",
        "}",
    ]),
    ("before", "private static IReadOnlySet<IPAddress>? SystemLocalAddresses()", [
        "private static void TryWrite(string path)",
        "{",
        'try { File.WriteAllText(path, ""); }',
        "catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }",
        "}",
    ]),
]
SERVICE_EDITS = [
    ("replace", "Func<string?> node, Func<DateTime> now, string root, Action<string, string>? write = null) : ILeakChecker", [
        "Func<string?> node, Func<DateTime> now, string root, Action<string, string>? write = null,",
        "Func<Task>? cleanup = null) : ILeakChecker",
    ]),
    ("after", "private readonly Action<string, string> writeReport = write ?? WriteReport;", [
        "private readonly Task startup = cleanup is null ? Task.CompletedTask : Task.Run(cleanup);",
    ]),
    ("before", "var started = now();", [
        "await Task.WhenAny(startup).ConfigureAwait(false);",
    ]),
    ("replace", "() => LeakCheckPlan.NodeFromKernelConfig(LeakCheckPlan.KernelConfigPath), () => DateTime.Now, LeakCheckPlan.OutputRoot);", [
        "() => LeakCheckPlan.NodeFromKernelConfig(LeakCheckPlan.KernelConfigPath), () => DateTime.Now, LeakCheckPlan.OutputRoot,",
        "cleanup: () => CleanupAsync(capture, LeakCheckPlan.OutputRoot));",
    ]),
    ("before", "private static void WriteReport(string path, string text)", [
        "private static async Task CleanupAsync(LeakCapture capture, string root)",
        "{",
        "using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(15));",
        "await capture.CleanupOrphansAsync(root, limit.Token).ConfigureAwait(false);",
        "}",
    ]),
]
EDITS = {CAPTURE: CAPTURE_EDITS, SERVICE: SERVICE_EDITS}


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


def code_lines(source):
    """去掉首尾空白后的代码行:空行和注释行不算。"""
    rows = [line.strip() for line in source.lstrip("﻿").replace("\r\n", "\n").split("\n")]
    return [row for row in rows if row and not row.startswith("//")]


def edited(rows, edits):
    """把改法套到改动前的代码行上;改动前的样子和契约对不上时返回 None。"""
    out = list(rows)
    for how, anchor, added in edits:
        if out.count(anchor) != 1:
            return None
        at = out.index(anchor)
        if how == "after":
            out[at + 1:at + 1] = added
        elif how == "before":
            out[at:at] = added
        else:
            out[at:at + 1] = added
    return out


def file_problems(path, new, old, edits):
    if not old:
        return [f"{path} 改动前不存在,和契约对不上,交 blocked"]
    if not new:
        return [f"缺文件 {path}"]
    want = edited(code_lines(old), edits)
    if want is None:
        return [f"{path} 改动前的样子和契约对不上,交 blocked"]
    got = code_lines(new)
    if got == want:
        return []
    for number, (a, b) in enumerate(zip(got, want, strict=False), 1):
        if a != b:
            return [f"{path} 和定稿不一样:第 {number} 个代码行(空行、注释行不算)应为「{b[:110]}」,现在是「{a[:110]}」"]
    return [f"{path} 和定稿不一样:代码行数应为 {len(want)},现在是 {len(got)}"]


def shape_problems(new, old):
    bad = []
    for path, edits in EDITS.items():
        bad += file_problems(path, new[path], old[path], edits)
    return bad


def shape():
    return shape_problems({path: text(path) for path in EDITS}, {path: before(path) for path in EDITS})


def lines(source):
    out = [line.rstrip() for line in source.replace("\r\n", "\n").split("\n")]
    while out and not out[-1]:
        out.pop()
    return out


def tests_problems(actual, reference):
    if not reference:
        return [f"缺文件 {REFERENCE},和契约对不上,交 blocked"]
    if not actual:
        return [f"缺文件 {TESTS}"]
    got, want = lines(actual), lines(reference)
    if got == want:
        return []
    for number, (a, b) in enumerate(zip(got, want, strict=False), 1):
        if a != b:
            return [f"{TESTS} 第 {number} 行应为「{b[:100]}」,现在是「{a[:100]}」;测试文件不许手改,用 write-tests 写出"]
    return [f"{TESTS} 行数应为 {len(want)},现在是 {len(got)};测试文件不许手改,用 write-tests 写出"]


def tests():
    return tests_problems(text(TESTS), text(REFERENCE))


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


def write_tests():
    reference = text(REFERENCE)
    if not reference:
        return [f"缺文件 {REFERENCE}"]
    (ROOT / TESTS).write_text(reference, encoding="utf-8", newline="\n")
    print(f"已把 {REFERENCE} 写成 {TESTS}")
    return []


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope, "write-tests": write_tests}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
