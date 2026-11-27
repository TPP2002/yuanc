"""页面单 yc-node-console-page-1127 的静态检查:只读仓库文件,不起服务、不写文件。"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "node" / "exitnode" / "console" / "static"
DESIGN = ROOT / "docs" / "design" / "2026-11-27-节点管理网页"

BEGIN = "/* ==== 搬进 console.css:开始"
END = "/* ==== 搬进 console.css:结束 ==== */"

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
    "正在生成", " 人可用", "已复制", "浏览器不让自动复制,邀请码已选中,请手动复制", " 天 · 已用 ",
    " 生成", "已用完", "使用中", "已过期", "已停用", " 到期 · 还剩 ", " 到期 · 已过期", "原定 ",
    "邀请码 ", "设备 ", " 台", " 注册", "延期", "停用", "恢复", "正在延期", "正在停用", "正在恢复",
    "延长", "延长天数", "确定", "取消", "常用天数", "吊销后这台设备不能再连,不能撤回", "确认吊销",
    "正在吊销", "最近在线 ", "没上过线", "正在退出",
]


def read_text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def sample_css_block():
    sample = read_text(DESIGN / "样张.html")
    start = sample.index(BEGIN)
    stop = sample.index(END) + len(END)
    return sample[start:stop]


def console_js():
    return read_text(STATIC / "console.js")


def console_css():
    return read_text(STATIC / "console.css")


def phone_css_block():
    """只取 640px 窄屏那一段,按花括号配平截出来。"""
    css = console_css()
    marker = "@media (max-width: 640px) {"
    start = css.index(marker)
    depth = 0
    for index in range(start, len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start:index + 1]
    raise AssertionError("console.css 的 640px 段没有闭合")


def test_account_order_kept_after_actions():
    js = console_js()
    for snippet in (
        "var accountOrder = [];",
        "function loadDirectory(keepOrder) {",
        "renderAccounts(keepOrder);",
        "function renderAccounts(keepOrder) {",
        "function orderIndex(id) {",
    ):
        assert snippet in js, f"console.js 缺「{snippet}」"
    refreshed = js.count("loadDirectory(true);")
    assert refreshed == 4, f"操作后刷新 loadDirectory(true); 应有 4 处,实际 {refreshed} 处"
    plain = js.count("loadDirectory();")
    assert plain == 1, f"切页刷新 loadDirectory(); 应保留 1 处,实际 {plain} 处"


def test_codes_never_truncated_on_phone():
    css = console_css()
    assert ".acct-title.mono { white-space: normal; overflow-wrap: anywhere; }" in css
    phone = phone_css_block()
    assert ".inv .code { flex: 1 1 100%; width: auto; white-space: nowrap; }" in phone
    assert ".inv .code { flex: 1; width: auto; }" not in phone


def index_html():
    return read_text(STATIC / "index.html")


def test_css_is_the_design_sample_block():
    assert read_text(STATIC / "console.css").strip() == sample_css_block().strip()


def test_index_is_the_design_skeleton():
    assert index_html().strip() == read_text(DESIGN / "骨架.html").strip()


def test_index_has_no_inline_code_or_external_refs():
    html = index_html()
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S)
    assert scripts, "index.html 应至少有一个 script 标签"
    for attrs, body in scripts:
        assert "src=" in attrs, "script 标签必须带 src"
        assert body.strip() == "", "script 标签内不许有内容"
    assert not re.search(r"\sstyle\s*=", html, re.I), "不许有 style 属性"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "不许有内联事件属性"
    refs = set(re.findall(r'(?:href|src)\s*=\s*"([^"]*)"', html))
    assert refs == {"/console.css", "/console.js"}, f"页面只许引用两个同源文件,实际 {refs}"
    for bad in ("http://", "https://", 'src="//"', 'href="//"'):
        assert bad not in html, f"index.html 出现外部引用 {bad}"
    assert re.search(r'<html[^>]*lang="zh-CN"', html), "html 标签要带 lang=zh-CN"
    viewport = re.search(r'<meta name="viewport" content="([^"]*)"', html)
    assert viewport, "缺少 viewport"
    assert "user-scalable=no" not in viewport.group(1)
    assert "maximum-scale" not in viewport.group(1)


def test_js_avoids_html_injection_and_external_calls():
    js = console_js()
    for word in FORBIDDEN_JS:
        assert word not in js, f"console.js 出现禁用写法 {word}"
    assert not NATIVE_DIALOG.search(js), "console.js 用了浏览器原生弹窗"


def test_js_uses_every_api_path_with_session_and_csrf():
    js = console_js()
    for word in API:
        assert word in js, f"console.js 缺接口 {word}"


def test_js_contains_contract_texts():
    js = console_js()
    for word in TEXTS:
        assert word in js, f"console.js 缺文字 {word}"


def test_js_element_ids_exist_in_index():
    ids = set(re.findall(r'id="([^"]+)"', index_html()))
    used = set(re.findall(r"getElementById\(\s*['\"]([^'\"]+)['\"]", console_js()))
    assert used, "console.js 没有用 getElementById 取骨架里的元素"
    assert used <= ids, f"console.js 引用了骨架里没有的 id {sorted(used - ids)}"


def test_static_dir_has_only_three_files():
    assert STATIC.is_dir(), "static 目录不存在"
    names = sorted(p.name for p in STATIC.iterdir())
    assert names == ["console.css", "console.js", "index.html"], f"static 目录应恰好三件文件,实际 {names}"