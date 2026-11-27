"""页面小修单 yc-node-console-polish-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "node/exitnode/console/static"
SAMPLE = ROOT / "docs/design/2026-11-27-节点管理网页/样张.html"
ALLOWED = {
    "node/exitnode/console/static/console.js",
    "node/exitnode/console/static/console.css",
    "docs/design/2026-11-27-节点管理网页/样张.html",
    "node/tests/test_console_page.py",
}
TESTS = {
    "node/tests/test_console_page.py": [
        "test_account_order_kept_after_actions",
        "test_codes_never_truncated_on_phone",
    ],
}
ACCT_MONO = ".acct-title.mono { white-space: normal; overflow-wrap: anywhere; }"
INV_CODE_NEW = "  .inv .code { flex: 1 1 100%; width: auto; white-space: nowrap; }"
INV_CODE_OLD = "  .inv .code { flex: 1; width: auto; }"


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def shape():
    bad = []
    js = text(STATIC / "console.js")
    for snippet in ("var accountOrder = [];", "function loadDirectory(keepOrder) {",
                    "renderAccounts(keepOrder);", "function renderAccounts(keepOrder) {",
                    "function orderIndex(id) {"):
        if snippet not in js:
            bad.append(f"console.js 缺「{snippet}」")
    if js.count("loadDirectory(true);") != 4:
        bad.append(f"console.js 里 loadDirectory(true); 应有 4 处,现在 {js.count('loadDirectory(true);')} 处")
    if js.count("loadDirectory();") != 1:
        bad.append(f"console.js 里 loadDirectory(); 应只剩切页那 1 处,现在 {js.count('loadDirectory();')} 处")
    for name, body in (("console.css", text(STATIC / "console.css")), ("样张.html", text(SAMPLE))):
        if ACCT_MONO not in body:
            bad.append(f"{name} 缺「{ACCT_MONO}」")
        if INV_CODE_NEW not in body:
            bad.append(f"{name} 手机段缺「{INV_CODE_NEW.strip()}」")
        if INV_CODE_OLD in body:
            bad.append(f"{name} 手机段仍有旧写法「{INV_CODE_OLD.strip()}」")
    return bad


def tests():
    bad = []
    for file, names in TESTS.items():
        body = text(ROOT / file) if (ROOT / file).exists() else ""
        bad += [f"缺用例 {file}:{n}" for n in names if f"def {n}(" not in body]
    return bad


def scope():
    def git(*args):
        out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
        return [line.strip() for line in out.decode("utf-8").splitlines() if line.strip()]

    base = git("merge-base", "origin/main", "HEAD")[0]
    changed = set(git("diff", "--name-only", base)) | set(git("ls-files", "--others", "--exclude-standard"))
    return [f"改了圈外文件 {p}" for p in sorted(changed - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
