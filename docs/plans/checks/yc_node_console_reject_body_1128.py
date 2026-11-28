"""工单 yc-node-console-reject-body-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "node/exitnode/console/server.py"
TEST_FILE = ROOT / "node/tests/test_console_server.py"
ALLOWED = {
    "node/exitnode/console/server.py",
    "node/tests/test_console_server.py",
}
OLD_TESTS = [
    "test_static_files_and_security_headers",
    "test_unknown_paths_methods_and_missing_static_get_decoy",
    "test_no_server_header_anywhere",
    "test_disallowed_source_gets_decoy",
    "test_bad_host_header_gets_decoy",
    "test_login_success_sets_cookie_and_session",
    "test_login_wrong_password_and_throttle",
    "test_login_concurrency_gate_returns_429",
    "test_malformed_requests_get_decoy",
    "test_cookie_header_parsing",
    "test_password_missing_returns_409",
    "test_api_requires_session",
    "test_post_requires_csrf_and_same_origin",
    "test_logout_clears_session",
    "test_status_available_stale_and_missing",
    "test_directory_and_actions_forwarded",
    "test_invite_and_extend_validation",
    "test_invite_mode_off_and_admin_key_missing_codes",
    "test_ids_in_path_are_validated",
    "test_oversized_body_rejected",
    "test_check_layer",
    "test_load_credentials_from_env_and_secrets",
    "test_secrets_never_logged",
]
NEW_TESTS = [
    "test_rejected_post_waits_for_body_then_answers",
    "test_stalled_body_closes_without_reply",
]


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else ""


def method(source, name):
    """取类里一个方法的正文:从 def 那行到下一个同级 def 之前。"""
    parts = source.split(f"    def {name}(", 1)
    return parts[1].split("\n    def ", 1)[0] if len(parts) == 2 else ""


def function(source, name):
    """取模块级一个函数的正文:从 def 那行到下一个顶格语句之前。"""
    parts = source.split(f"\ndef {name}(", 1)
    return re.split(r"\n(?=\S)", parts[1], maxsplit=1)[0] if len(parts) == 2 else ""


def shape():
    bad = []
    server = text(SERVER)
    take = method(server, "_take_body")
    api = method(server, "_api")
    read = method(server, "_read_body")
    decoy = method(server, "_decoy")
    if not take:
        bad.append("server.py 没有 _take_body 方法")
    elif "rfile.read(" not in take:
        bad.append("_take_body 没有读请求体")
    if "_take_body(" not in api:
        bad.append("_api 没有调 _take_body")
    else:
        first = api.index("_take_body(")
        for token, label in (("LOGIN_REQUIRED", "登录检查"), ("CSRF_DETAIL", "来源页与防伪头检查")):
            if token in api and api.index(token) < first:
                bad.append(f"_api 里{label}排在读请求体之前")
    if not read:
        bad.append("server.py 的 _read_body 不见了")
    elif "rfile.read" in read:
        bad.append("_read_body 还在自己读套接字")
    if "close_connection = True" not in decoy or "_drain_input()" not in decoy:
        bad.append("_decoy 回完不再断开连接或不再读掉后到的字节")
    if server.count("_drain_input()") != 1:
        bad.append("_drain_input 的调用处变了(本单不动它,只许 _decoy 里那一处)")
    if "16384" not in server:
        bad.append("请求体 16384 字节的上限不见了")
    if "HTTP/1.1" in server:
        bad.append("server.py 改了 HTTP 版本")
    if "time.sleep(" in server:
        bad.append("server.py 用了 time.sleep")
    return bad


def tests():
    bad = []
    body = text(TEST_FILE)
    bad += [f"缺既有用例 {name}" for name in OLD_TESTS if f"\ndef {name}(" not in body]
    for name in NEW_TESTS:
        source = function(body, name)
        if not source:
            bad.append(f"缺新用例 {name}")
            continue
        if re.search(r"\bexcept\b", source):
            bad.append(f"{name} 里有 except,连接被重置会被吞掉")
        if "read_until_close(" in source:
            bad.append(f"{name} 用了会吞掉重置的 read_until_close")
    for word in ("flaky", "rerun", "retry", "retries"):
        if word in body.lower():
            bad.append(f"测试文件里出现了 {word}")
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
