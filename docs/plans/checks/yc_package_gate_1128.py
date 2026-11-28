"""验收脚本:出包检查进自动检查(CI-WINCLIENT-PUBLISH-GATE-1127)。用法:python <本文件> shape|scope"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ".github/workflows/winclient-package.yml"
ALLOWED = {WORKFLOW}

# 流程文件的定稿内容。工单里「照抄」的那一段就是从这里生成的,两边是同一份。
EXPECTED = """\
name: 客户端出包检查

# 照发布时的命令把正式包打一遍:打不出来、发布目录里多出外置文件、包超过自动更新肯收的大小,这里就红。
# 只改文档、节点、登录服务器或说明文件时不跑(改动的文件全都落在 paths-ignore 里才跳过),别的改动都跑。
# push 和 pull_request 两处 paths-ignore 保持一样。
# 跑在哪和 ci.yml 一样由仓库变量 CI_RUNS_ON 定(见 docs/开工须知.md §5.1)。不签名,不上传安装包。
on:
  push:
    branches: [main]
    paths-ignore:
      - 'docs/**'
      - 'node/**'
      - 'authserver/**'
      - '**.md'
  pull_request:
    paths-ignore:
      - 'docs/**'
      - 'node/**'
      - 'authserver/**'
      - '**.md'

permissions:
  contents: read

jobs:
  package:
    name: Windows 客户端出包检查
    runs-on: ${{ vars.CI_RUNS_ON || 'windows-latest' }}
    timeout-minutes: 20
    steps:
      - name: 获取代码
        uses: actions/checkout@v4
      - name: 准备客户端编译工具
        if: vars.CI_RUNS_ON == ''
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0.x'
      - name: 打一遍正式包并检查
        run: powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File scripts/release/build-winclient.ps1
"""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT, stderr=subprocess.DEVNULL)
    return out.decode("utf-8")


def lines(value):
    """按行比:不计行尾空格、回车和文件末尾的空行。"""
    out = [line.rstrip() for line in value.replace("\r\n", "\n").split("\n")]
    while out and not out[-1]:
        out.pop()
    return out


def shape_problems(raw):
    """raw 是流程文件的原始字节;文件不在时传 None。"""
    if raw is None:
        return [f"缺文件 {WORKFLOW}"]
    bad = []
    if raw.startswith(b"\xef\xbb\xbf"):
        bad.append("文件开头带了 BOM,要存成不带 BOM 的 UTF-8")
        raw = raw[3:]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return bad + ["文件不是 UTF-8 编码"]
    if "\t" in value:
        bad.append("文件里有制表符,缩进一律用空格")
    got, want = lines(value), lines(EXPECTED)
    differing = [(number, a, b) for number, (a, b) in enumerate(zip(got, want, strict=False), 1) if a != b]
    for number, a, b in differing[:5]:
        bad.append(f"第 {number} 行和定稿不一样:应为「{b}」,现在是「{a}」")
    if len(differing) > 5:
        bad.append(f"另有 {len(differing) - 5} 行和定稿不一样")
    if len(got) != len(want):
        bad.append(f"行数不对:应为 {len(want)} 行,现在 {len(got)} 行")
    return bad


def shape():
    file = ROOT / WORKFLOW
    return shape_problems(file.read_bytes() if file.exists() else None)


def scope():
    base = git("merge-base", "origin/main", "HEAD").strip()
    names = [line.strip() for line in git("diff", "--name-only", base).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
