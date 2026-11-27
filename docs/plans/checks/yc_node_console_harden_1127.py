"""加固单 yc-node-console-harden-1127 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "node/exitnode/console"
ALLOWED = {
    "node/exitnode/console/auth.py",
    "node/exitnode/console/server.py",
    "node/tests/test_console_auth.py",
    "node/tests/test_console_server.py",
}
TESTS = {
    "node/tests/test_console_auth.py": [
        "test_throttle_attempt_counts_before_verify_and_is_atomic",
        "test_throttle_loopback_exempt_from_global_limit",
        "test_verify_password_rejects_bad_format_without_scrypt",
    ],
    "node/tests/test_console_server.py": [
        "test_login_concurrency_gate_returns_429",
        "test_malformed_requests_get_decoy",
        "test_cookie_header_parsing",
    ],
}


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def shape():
    bad = []
    server = text(CONSOLE / "server.py")
    auth = text(CONSOLE / "auth.py")
    if "SimpleCookie" in server or "http.cookies" in server:
        bad.append("server.py 仍在用 http.cookies 解析 Cookie")
    if "def send_error(" not in server:
        bad.append("server.py 没有重写 send_error")
    decoy = server.split("def _decoy(", 1)[-1].split("\n    def ", 1)[0]
    if "close_connection = True" not in decoy:
        bad.append("server.py 的 _decoy 没有断开连接")
    if "BoundedSemaphore(2)" not in server:
        bad.append("server.py 没有验密码的并发闸 BoundedSemaphore(2)")
    if "def attempt(" not in auth:
        bad.append("auth.py 的 LoginThrottle 没有 attempt 方法")
    if "def fail(" in auth:
        bad.append("auth.py 的 LoginThrottle 仍保留 fail 方法")
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
