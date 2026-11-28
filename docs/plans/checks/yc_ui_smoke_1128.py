"""验收脚本:出包后界面试跑(WINCLIENT-PACKAGE-UI-SMOKE-1128)。用法:python <本文件> shape|run|scope"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SMOKE = "scripts/release/ui-smoke.ps1"
BUILD = "scripts/release/build-winclient.ps1"
ALLOWED = {SMOKE, BUILD}
BOM = b"\xef\xbb\xbf"

# 出包脚本:只换第一行、只加下面这一段,别的行一个字不动。
OLD_PARAM = "param([string]$Version, [switch]$TestBuild)"
NEW_PARAM = "param([string]$Version, [switch]$TestBuild, [switch]$UiSmoke)"
BEFORE_LINE = "    [IO.Directory]::CreateDirectory($release) | Out-Null"
BLOCK = [
    "    if ($UiSmoke) {",
    "        # 交出去之前先自动点一遍界面;没通过或没法试都不出包。",
    "        $smokeVersion = ($Version -split '\\+')[0]",
    "        & (Join-Path $PSScriptRoot 'ui-smoke.ps1') -Exe $executable -OutDir (Join-Path $root 'build/ui-smoke') -ExpectVersion $smokeVersion -ExpectTestBuild:$TestBuild",
    "        if ($LASTEXITCODE -ne 0) { throw \"界面试跑没有通过（退出码 $LASTEXITCODE），没有出包。\" }",
    "    }",
]

# 试跑脚本里必须原样出现的片段。
NEEDED = [
    "[Parameter(Mandatory)][string]$Exe",
    "[Parameter(Mandatory)][string]$OutDir",
    "[string]$ExpectVersion",
    "[switch]$ExpectTestBuild",
    "$ErrorActionPreference = 'Stop'",
    "Set-StrictMode -Off",
    "Add-Type -AssemblyName UIAutomationClient",
    "Add-Type -AssemblyName UIAutomationTypes",
    "public static class NativeDialog",
    "界面试跑没通过:找不到程序 ",
    "[Environment]::UserInteractive",
    "界面试跑没法做:当前不是看得到桌面的登录会话。",
    "Get-Service -Name 'YuanCService' -ErrorAction SilentlyContinue",
    "界面试跑没法做:这台电脑装了本产品的后台服务,新程序一启动就会转交给已安装的那一份。",
    "界面试跑没法做:已有客户端进程在运行:",
    "$process = Start-Process -FilePath $Exe -PassThru",
    "'*测试包*'",
    "这是测试包,首页却没有「测试包」字样",
    "这不是测试包,首页却出现了:",
    "'更新与诊断'",
    "'导出诊断*'",
    "「更新与诊断」页没有显示版本号 ",
    "'^澳洲出口客户端-诊断-\\d{8}-\\d{6}(\\.json)?$'",
    "保存对话框的默认文件名不对:",
    "'Text:已导出：*'",
    "if ($before -notcontains [long]$w.HWND)",
    "'diag-smoke.json'",
    "$json.schema -ne 1",
    "$json.ui.version -ne $ExpectVersion",
    "界面试跑没通过:",
    "界面试跑通过:",
    "if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }",
    "exit $code",
]
# 这些各只许出现一次:只启动被试的程序、只结束它、只关这次新开的文件夹窗口。
ONCE = ["Start-Process", "Stop-Process", ".Quit()"]
# 不许出现:不点安装、不点连接、不碰服务与系统设置、不起别的命令行窗口。
BANNED = [
    "安装后台服务", "'连接'", "\"连接\"", "--install", "--repair", "--uninstall", "Start-Service", "Stop-Service", "New-Service", "sc.exe",
    "netsh", "NetFirewall", "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "reg.exe", "-Recurse", "Invoke-Expression", "iex ",
    "Invoke-WebRequest", "Invoke-RestMethod", "cmd.exe", "cmd /c", "powershell.exe", "Start-Sleep -Seconds 60", "SendKeys", "taskkill",
]
MISSING_EXE_TEXT = "界面试跑没通过:找不到程序 "
# 这几处在脚本里的先后次序:先加载界面自动化,再依次判四种情况,最后才启动程序。
ORDER = [
    "Add-Type -AssemblyName UIAutomationClient",
    MISSING_EXE_TEXT,
    "[Environment]::UserInteractive",
    "Get-Service -Name 'YuanCService'",
    "界面试跑没法做:已有客户端进程在运行:",
    "$process = Start-Process -FilePath $Exe -PassThru",
]


def raw(path):
    file = ROOT / path
    return file.read_bytes() if file.exists() else b""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT, stderr=subprocess.DEVNULL)
    return out


def base():
    return git("merge-base", "origin/main", "HEAD").decode("utf-8").strip()


def before(path):
    try:
        return git("show", f"{base()}:{path}")
    except subprocess.CalledProcessError:
        return b""


def decode(data, path, bad):
    if not data:
        bad.append(f"缺文件 {path}")
        return None
    if not data.startswith(BOM):
        bad.append(f"{path} 要存成带 BOM 的 UTF-8(Windows PowerShell 5.1 靠它认中文)")
        return None
    try:
        return data[len(BOM):].decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError:
        bad.append(f"{path} 不是合法的 UTF-8")
        return None


def build_problems(new, old):
    bad = []
    new_text = decode(new, BUILD, bad)
    old_text = decode(old, BUILD, [])
    if new_text is None or old_text is None:
        return bad or [f"{BUILD} 改动前的样子和契约对不上,交 blocked"]
    old_lines = [line.rstrip() for line in old_text.rstrip("\n").split("\n")]
    if old_lines[0] != OLD_PARAM or old_lines.count(BEFORE_LINE) != 1:
        return [f"{BUILD} 改动前的样子和契约对不上,交 blocked"]
    at = old_lines.index(BEFORE_LINE)
    want = [NEW_PARAM] + old_lines[1:at] + BLOCK + old_lines[at:]
    got = [line.rstrip() for line in new_text.rstrip("\n").split("\n")]
    if got != want:
        for number, (a, b) in enumerate(zip(got, want, strict=False), 1):
            if a != b:
                bad.append(f"{BUILD} 第 {number} 行应为「{b[:100]}」,现在是「{a[:100]}」")
                break
        else:
            bad.append(f"{BUILD} 行数应为 {len(want)},现在是 {len(got)}")
    return bad


def smoke_problems(new):
    bad = []
    text = decode(new, SMOKE, bad)
    if text is None:
        return bad
    if "\t" in text:
        bad.append(f"{SMOKE} 不用制表符缩进")
    for token in NEEDED:
        if token not in text:
            bad.append(f"{SMOKE} 里要原样出现:{token}")
    for token in ONCE:
        if text.count(token) != 1:
            bad.append(f"{SMOKE} 里 {token} 要正好出现一次,现在 {text.count(token)} 次")
    for token in BANNED:
        if token in text:
            bad.append(f"{SMOKE} 里不许出现:{token}")
    spots = [text.find(token) for token in ORDER]
    if -1 not in spots and spots != sorted(spots):
        bad.append(f"{SMOKE} 的次序要是:先加载界面自动化,再依次判「找不到程序」「不是桌面会话」「装了后台服务」「已有客户端进程」,最后才启动程序")
    lines = text.split("\n")
    if "'@" not in lines or not any(line.rstrip().endswith("@'") for line in lines):
        bad.append(f"{SMOKE} 里那段 C# 要放在 @' … '@ 里,结尾的 '@ 顶格单独一行")
    return bad


def shape_problems(new, old):
    return smoke_problems(new[SMOKE]) + build_problems(new[BUILD], old[BUILD])


def powershell(command, env_extra):
    env = dict(os.environ, **env_extra)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT, env=env, capture_output=True, timeout=110, creationflags=flags, check=False)


def run_problems(script):
    """不开界面的两步实跑:脚本能被 PowerShell 5.1 解析;给一个不存在的程序路径,应当退出码 1 并说找不到程序。"""
    bad = []
    script = Path(script)
    if not script.exists():
        return [f"缺文件 {SMOKE}"]
    parse = powershell(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $e = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile($env:YC_SMOKE_SCRIPT, [ref]$null, [ref]$e); "
        "foreach ($x in $e) { [Console]::Out.WriteLine([string]$x.Extent.StartLineNumber + ':' + $x.Message) }; exit $e.Count",
        {"YC_SMOKE_SCRIPT": str(script)})
    if parse.returncode != 0:
        detail = parse.stdout.decode("utf-8", "replace").strip().splitlines()[:3]
        return [f"{SMOKE} 解析不过:" + " / ".join(detail or [f"退出码 {parse.returncode}"])]
    with tempfile.TemporaryDirectory() as out_dir:
        missing = str(Path(out_dir) / "没有这个程序.exe")
        result = powershell(
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; & $env:YC_SMOKE_SCRIPT -Exe $env:YC_SMOKE_EXE -OutDir $env:YC_SMOKE_OUT; exit $LASTEXITCODE",
            {"YC_SMOKE_SCRIPT": str(script), "YC_SMOKE_EXE": missing, "YC_SMOKE_OUT": str(Path(out_dir) / "out")})
        output = result.stdout.decode("utf-8", "replace")
        if result.returncode != 1:
            tail = (output + result.stderr.decode("utf-8", "replace")).strip().splitlines()[-3:]
            bad.append(f"给一个不存在的程序路径,{SMOKE} 应当退出码 1,现在是 {result.returncode}:" + " / ".join(tail))
        elif MISSING_EXE_TEXT + missing not in output:
            bad.append(f"给一个不存在的程序路径,{SMOKE} 应当输出「{MISSING_EXE_TEXT}<路径>」,现在输出:{output.strip()[:160]}")
    return bad


def shape():
    return shape_problems({SMOKE: raw(SMOKE), BUILD: raw(BUILD)}, {BUILD: before(BUILD)})


def run():
    return run_problems(ROOT / SMOKE)


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).decode("utf-8").splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").decode("utf-8").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "run": run, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
