"""验收脚本:半开连接不再占满客户端包托管服务(NODE-ADMIN-HALFOPEN-1127)。
用法:python <本文件> shape|tests|stable|scope|write-tests"""

import ast
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SERVER = "node/exitnode/admin/server.py"
TESTS = "node/tests/test_admin_server.py"
REFERENCE = "docs/plans/checks/yc_admin_halfopen_1128_tests.txt"
ALLOWED = {SERVER, TESTS}

# 托管服务代码里必须原样出现的片段。
NEEDED = [
    "import selectors",
    "MAX_HEADER_BYTES = 8192",
    "class PackageServer(ThreadingHTTPServer):",
    "daemon_threads = True",
    "request_queue_size = 64",
    "def __init__(self, *args, max_connections=32, header_timeout=5, max_waiting=256, **kwargs):",
    "self._slots = threading.BoundedSemaphore(max_connections)",
    "def serve_forever(self, poll_interval=0.5):",
    "selectors.DefaultSelector()",
    "def shutdown(self):",
    "def process_request_thread(self, request, client_address):",
    "def setup(self):",
    "def create_server(bind, port, root, *, max_connections=32, timeout=15, header_timeout=5, max_waiting=256):",
    "min(header_timeout, timeout)",
]
# 不许出现:不靠睡眠轮询、不另开常驻线程、不打印、不用有 1024 上限的老式 select。
BANNED = ["time.sleep(", "print(", "select.select(", "threading.Timer", "socketserver.ForkingMixIn", "os.fork("]
# 这些函数和改动前逐字一样(探测逻辑、取文件的逻辑、响应头、启动与收信号都不动)。
UNCHANGED = ["PackageServer.handle_error", "PackageHandler.log_message", "PackageHandler._headers", "PackageHandler.send_error",
             "PackageHandler.do_HEAD", "PackageHandler.do_GET", "PackageHandler._serve", "serve", "check"]
# 整份代码里 threading.Thread( 只许有改动前那一处(收到停止信号时用来叫停服务)。
THREAD_TOKEN = "threading.Thread("


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


def shape_problems(new, old):
    if not new:
        return [f"缺文件 {SERVER}"]
    bad = []
    try:
        new_functions = functions(new)
    except SyntaxError as error:
        return [f"{SERVER} 语法错:第 {error.lineno} 行"]
    old_functions = functions(old)
    for token in NEEDED:
        if token not in new:
            bad.append(f"{SERVER} 里要原样出现:{token}")
    for token in BANNED:
        if token in new:
            bad.append(f"{SERVER} 里不许出现:{token}")
    if new.count(THREAD_TOKEN) != 1:
        bad.append(f"{SERVER} 里 {THREAD_TOKEN} 只许有改动前那一处,现在 {new.count(THREAD_TOKEN)} 处")
    for name in UNCHANGED:
        if name not in old_functions:
            bad.append(f"{SERVER} 改动前没有 {name},和契约对不上,交 blocked")
        elif new_functions.get(name) != old_functions[name]:
            bad.append(f"{SERVER} 里 {name} 要和改动前逐字一样")
    if "PackageServer.process_request" in new_functions:
        bad.append(f"{SERVER} 里 PackageServer 不再重写 process_request(并发名额改到收齐请求头之后再取)")
    return bad


def normalized(source):
    lines = [line.rstrip() for line in source.replace("\r\n", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return lines


def tests_problems(actual, reference):
    if not reference:
        return [f"缺文件 {REFERENCE},和契约对不上,交 blocked"]
    if not actual:
        return [f"缺文件 {TESTS}"]
    got, want = normalized(actual), normalized(reference)
    if got == want:
        return []
    for number, (a, b) in enumerate(zip(got, want, strict=False), 1):
        if a != b:
            return [f"{TESTS} 第 {number} 行应为「{b[:100]}」,现在是「{a[:100]}」;测试文件不许手改,用 write-tests 写出"]
    return [f"{TESTS} 行数应为 {len(want)},现在是 {len(got)};测试文件不许手改,用 write-tests 写出"]


def stable_problems(rounds=3):
    """把托管服务的测试文件连跑几遍,每遍都要全过:这组测试带时限,偶尔才过的不算过。"""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    for number in range(1, rounds + 1):
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", TESTS], cwd=ROOT, env=dict(os.environ),
                                capture_output=True, timeout=600, creationflags=flags, check=False)
        if result.returncode != 0:
            tail = result.stdout.decode("utf-8", "replace").strip().splitlines()[-12:]
            return [f"第 {number} 遍没全过(退出码 {result.returncode}):"] + tail
    return []


def shape():
    return shape_problems(text(SERVER), before(SERVER))


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
    problems = {"shape": shape, "tests": tests, "stable": stable_problems, "scope": scope, "write-tests": write_tests}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
