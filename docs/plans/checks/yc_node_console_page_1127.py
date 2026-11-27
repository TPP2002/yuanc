"""页面单 yc-node-console-page-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "node/exitnode/console/static"
DESIGN = ROOT / "docs/design/2026-11-27-节点管理网页"
TEST = ROOT / "node/tests/test_console_page.py"
ALLOWED = {
    "node/exitnode/console/static/index.html",
    "node/exitnode/console/static/console.css",
    "node/exitnode/console/static/console.js",
    "node/tests/test_console_page.py",
}
TESTS = [
    "test_css_is_the_design_sample_block",
    "test_index_is_the_design_skeleton",
    "test_index_has_no_inline_code_or_external_refs",
    "test_js_avoids_html_injection_and_external_calls",
    "test_js_uses_every_api_path_with_session_and_csrf",
    "test_js_contains_contract_texts",
    "test_js_element_ids_exist_in_index",
    "test_static_dir_has_only_three_files",
]
FORBIDDEN_JS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
    "localStorage", "sessionStorage", "XMLHttpRequest", "http://", "https://", "import(",
    "console.log", "?.", "??",
]
NATIVE_DIALOG = re.compile(r"(?<![A-Za-z0-9_$])(alert|confirm|prompt)\s*\(")
API = [
    "/api/session", "/api/login", "/api/logout", "/api/status", "/api/directory", "/api/invites",
    "/api/accounts/", "/extend", "/disable", "/enable", "/api/devices/", "/revoke",
    "X-Console-CSRF", "same-origin", "application/json",
]
TEXTS = [
    "连不上节点,请检查网络后再试", "管理网页出错了,请稍后再试", "登录已过期,请重新登录", "请填管理密码",
    "密码不对。忘了密码可以在节点上运行 exitnode console password 换一个", "正在登录", "节点管理",
    "正常", "正在重连", "需要重新授权", "需要处理", "还没有检查记录",
    "装好两分钟后仍没有,请在节点上运行 exitnode check", "未取到", "刚刚", " 分钟前", " 小时前", " 天前",
    "时间不对", "这份记录是", "的,节点上的定时检查可能停了", "这份记录的时间比现在还晚,节点时钟可能不准",
    "通过", "失败", "需重新授权", "需手动转发", "未接入", "跳过", "Windows", "安卓", " 加入", "已吊销",
    "天数要填 1 到 3650 的整数", "人数要填 1 到 100 的整数", "备注最多 200 个字,不能换行",
    "正在生成", " 人可用", "已复制", "浏览器不让自动复制,邀请码已选中,请手动复制", " 天 · 已用 ", " 生成",
    "已用完", "使用中", "已过期", "已停用", " 到期 · 还剩 ", " 到期 · 已过期", "原定 ", "邀请码 ", "设备 ",
    " 台", " 注册", "延期", "停用", "恢复", "正在延期", "正在停用", "正在恢复", "延长", "延长天数", "确定",
    "取消", "常用天数", "吊销后这台设备不能再连,不能撤回", "确认吊销", "正在吊销", "最近在线 ", "没上过线",
    "正在退出",
]
BEGIN = "/* ==== 搬进 console.css:开始"
END = "/* ==== 搬进 console.css:结束 ==== */"


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def css_block():
    sample = text(DESIGN / "样张.html")
    start = sample.index(BEGIN)
    stop = sample.index(END) + len(END)
    return sample[start:stop]


def shape():
    bad = []
    names = sorted(p.name for p in STATIC.iterdir()) if STATIC.is_dir() else []
    if names != ["console.css", "console.js", "index.html"]:
        bad.append(f"static 目录应恰好三件文件,实际 {names}")
        return bad
    if text(STATIC / "console.css").strip() != css_block().strip():
        bad.append("console.css 与样张正本段不一致")
    if text(STATIC / "index.html").strip() != text(DESIGN / "骨架.html").strip():
        bad.append("index.html 与骨架.html 不一致")
    js = text(STATIC / "console.js")
    bad += [f"console.js 出现禁用写法 {w}" for w in FORBIDDEN_JS if w in js]
    bad += [f"console.js 用了浏览器原生弹窗 {m}" for m in sorted(set(NATIVE_DIALOG.findall(js)))]
    bad += [f"console.js 缺接口 {w}" for w in API if w not in js]
    bad += [f"console.js 缺文字 {w}" for w in TEXTS if w not in js]
    index = text(STATIC / "index.html")
    ids = set(re.findall(r'id="([^"]+)"', index))
    used = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]", js))
    bad += [f"console.js 引用了骨架里没有的 id {i}" for i in sorted(used - ids)]
    if not used:
        bad.append("console.js 没有用 getElementById 取骨架里的元素")
    return bad


def tests():
    body = text(TEST) if TEST.exists() else ""
    return [f"缺用例 {n}" for n in TESTS if f"def {n}(" not in body]


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
