"""验收脚本:发给客户端的节点地址跟着节点心跳的来源走(AUTH-NODE-HOST-STATIC-1117)。
用法:python <本文件> shape|tests|scope|write-tests"""

import ast
import difflib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SERVICE = "authserver/authserver/service.py"
CONFIG = "authserver/authserver/config.py"
EXAMPLE = "authserver/examples/config.example.toml"
TESTS = "authserver/tests/test_node_host.py"
REFERENCE = "docs/plans/checks/yc_auth_node_host_1128_tests.txt"
ALLOWED = {SERVICE, CONFIG, EXAMPLE, TESTS}

# 业务代码里必须原样出现的片段。
SERVICE_NEEDED = [
    "import ipaddress",
    "NOT_PUBLIC = tuple(ipaddress.ip_network(value) for value in (",
    '"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",',
    '"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"))',
    "def public_ipv4(value):",
    "if not isinstance(value, str):",
    "address = ipaddress.ip_address(value)",
    "address = address.ipv4_mapped",
    "if any(address in network for network in NOT_PUBLIC):",
]
# 取会话那个函数里必须原样出现的片段。
SESSION_NEEDED = [
    "node = self.settings.node.model_dump()",
    "if self.settings.node.host_from_heartbeat:",
    'conn.execute("SELECT ip FROM node_heartbeat WHERE id = 1").fetchone()',
    'reported = None if beat is None else public_ipv4(beat["ip"])',
    'node["host"] = reported',
    'node.update(uuid=device["uuid"], hy2_password=hy2_password(device["uuid"], self.salt))',
]
# 不许出现:不用各版本解释器判法不一样的现成属性,不打印,不改配置对象。
SERVICE_BANNED = ["is_global", "is_private", "print(", "time.sleep(", "self.settings.node.host =", "datetime.now("]
# 业务代码里这些函数和改动前逐字一样(只有取会话的 Service.session 许改)。
SERVICE_UNCHANGED = [
    "Problem.__init__", "required", "add_days", "extend_from", "Service.__init__", "Service.time",
    "Service.create_invite", "Service.accounts", "Service.invites", "Service._devices", "Service.devices",
    "Service.audits", "Service.change_account", "Service.revoke", "Service._by_refresh", "Service._check",
    "Service.redeem", "Service.authenticate_session", "Service._session_device", "Service.logout",
    "Service.allowed", "Service.heartbeat",
]
# 配置代码只许多出这两行(一行注释、一行字段),紧跟在混淆密码路径那一行后面。
CONFIG_AFTER = '    hy2_obfs_password_path: str = Field(default="", exclude=True, repr=False)'
CONFIG_LINES = [
    "    # 发给客户端的节点地址跟不跟节点心跳的来源地址走；节点前面有中继时填 false。",
    "    host_from_heartbeat: bool = Field(default=True, exclude=True)",
]
# 示例配置只许多出这两行,紧跟在节点地址那一行后面。
EXAMPLE_AFTER = 'host = "<节点地址>"'
EXAMPLE_LINES = [
    "# 节点的公网地址变了以后，发给客户端的地址跟着节点心跳的来源走；节点前面有中继、心跳来源不是客户端该连的地址时填 false。",
    "host_from_heartbeat = true",
]


def text(path):
    file = ROOT / path
    return file.read_text(encoding="utf-8").replace("\r\n", "\n") if file.exists() else ""


def git(*args):
    return subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT, stderr=subprocess.DEVNULL).decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


def before(path):
    try:
        return git("show", f"{base()}:{path}").replace("\r\n", "\n")
    except subprocess.CalledProcessError:
        return ""


def lines(source):
    out = [line.rstrip() for line in source.replace("\r\n", "\n").split("\n")]
    while out and not out[-1]:
        out.pop()
    return out


def functions(source):
    """按「类名.函数名」取出每个函数的源码(去掉行尾空格)。"""
    out = {}
    tree = ast.parse(source)
    for node in tree.body:
        members = node.body if isinstance(node, ast.ClassDef) else [node]
        prefix = node.name + "." if isinstance(node, ast.ClassDef) else ""
        for item in members:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                segment = ast.get_source_segment(source, item) or ""
                out[prefix + item.name] = "\n".join(line.rstrip() for line in segment.split("\n"))
    return out


def service_problems(new, old):
    if not new:
        return [f"缺文件 {SERVICE}"]
    try:
        new_functions = functions(new)
    except SyntaxError as error:
        return [f"{SERVICE} 语法错:第 {error.lineno} 行"]
    old_functions = functions(old)
    bad = []
    for token in SERVICE_NEEDED:
        if token not in new:
            bad.append(f"{SERVICE} 里要原样出现:{token}")
    for token in SERVICE_BANNED:
        if token in new:
            bad.append(f"{SERVICE} 里不许出现:{token}")
    session = new_functions.get("Service.session", "")
    for token in SESSION_NEEDED:
        if token not in session:
            bad.append(f"{SERVICE} 的 Service.session 里要原样出现:{token}")
    if "public_ipv4" not in new_functions:
        bad.append(f"{SERVICE} 里要有模块级函数 public_ipv4")
    for name in SERVICE_UNCHANGED:
        if name not in old_functions:
            bad.append(f"{SERVICE} 改动前没有 {name},和契约对不上,交 blocked")
        elif new_functions.get(name) != old_functions[name]:
            bad.append(f"{SERVICE} 里 {name} 要和改动前逐字一样")
    extra = sorted(set(new_functions) - set(old_functions) - {"public_ipv4"})
    if extra:
        bad.append(f"{SERVICE} 里只许新增 public_ipv4 一个函数,多出了:{'、'.join(extra)}")
    return bad


def inserted_problems(path, new, old, after, wanted):
    """这个文件相对改动前只许多出 wanted 这几行,并且紧跟在 after 那一行后面。"""
    if not old:
        return [f"{path} 改动前不存在,和契约对不上,交 blocked"]
    if not new:
        return [f"缺文件 {path}"]
    got, was = lines(new), lines(old)
    if was.count(after) != 1:
        return [f"{path} 改动前应当正好有一行「{after}」,和契约对不上,交 blocked"]
    at = was.index(after) + 1
    want = was[:at] + wanted + was[at:]
    if got == want:
        return []
    for row in difflib.unified_diff(want, got, "应当是", "现在是", n=0, lineterm=""):
        if row.startswith(("+", "-")) and not row.startswith(("+++", "---")):
            return [f"{path} 只许在「{after}」后面多出契约写的 {len(wanted)} 行,别的不动;第一处对不上:{row[:120]}"]
    return [f"{path} 和契约写的对不上"]


def shape():
    bad = service_problems(text(SERVICE), before(SERVICE))
    bad += inserted_problems(CONFIG, text(CONFIG), before(CONFIG), CONFIG_AFTER, CONFIG_LINES)
    bad += inserted_problems(EXAMPLE, text(EXAMPLE), before(EXAMPLE), EXAMPLE_AFTER, EXAMPLE_LINES)
    return bad


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
