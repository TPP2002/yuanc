"""工单 yc-node-console-conn-budget-1128 的验收检查。派单器按「python 本文件 子命令」调用;工人不许改本文件。"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "node/exitnode/console/server.py"
TEST_PATH = "node/tests/test_console_server.py"
ALLOWED = {
    "node/exitnode/console/server.py",
    TEST_PATH,
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
    "test_rejected_post_waits_for_body_then_answers",
    "test_stalled_body_closes_without_reply",
]
OLD_HELPERS = ["make", "call", "login", "origin_of", "read_until_close"]
NEW_TESTS = [
    "test_slow_header_is_cut_at_total_deadline",
    "test_slow_body_is_cut_at_total_deadline",
    "test_decoy_drain_is_bounded",
    "test_source_quota_refuses_extra_connection",
    "test_other_source_is_not_blocked_by_full_quota",
    "test_idle_connections_release_quota_at_deadline",
]


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else ""


def git(*args):
    out = subprocess.check_output(["git", "-c", "core.quotepath=false", *args], cwd=ROOT)
    return out.decode("utf-8")


def base():
    return git("merge-base", "origin/main", "HEAD").strip()


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
    for token, label in (("total_timeout = 30", "每条连接的总时限 total_timeout = 30"),
                         ("drain_seconds = 1.0", "读掉后到字节的时长上限 drain_seconds = 1.0"),
                         ("drain_bytes = 65536", "读掉后到字节的字节上限 drain_bytes = 65536"),
                         ("per_source = 8", "每个来源的并发上限 per_source = 8"),
                         ("io.RawIOBase", "继承 io.RawIOBase 的读取器"),
                         ("io.BufferedReader(", "包住读取器的 io.BufferedReader"),
                         ("io.DEFAULT_BUFFER_SIZE", "缓冲大小 io.DEFAULT_BUFFER_SIZE"),
                         ("time.monotonic()", "用 time.monotonic() 算剩余时间"),
                         ("recv_into(", "读取器里的 recv_into"),
                         ("max_connections=32", "总并发上限 max_connections=32"),
                         ("timeout = 15", "每次读的超时 timeout = 15")):
        if token not in server:
            bad.append(f"server.py 缺{label}")
    if not method(server, "setup"):
        bad.append("ConsoleHandler 没有覆盖 setup()")
    drain = method(server, "_drain_input")
    if not drain:
        bad.append("server.py 的 _drain_input 不见了")
    else:
        if re.search(r"while self\.rfile\.read1\(65536\):\s*\n\s*pass", drain):
            bad.append("_drain_input 还是没有上限的循环")
        for token in ("drain_seconds", "drain_bytes"):
            if token not in drain:
                bad.append(f"_drain_input 没有用到 {token}")
    decoy = method(server, "_decoy")
    if "close_connection = True" not in decoy or "_drain_input()" not in decoy:
        bad.append("_decoy 回完不再断开连接或不再读掉后到的字节")
    process = method(server, "process_request")
    if "per_source" not in process:
        bad.append("process_request 没有按来源限并发")
    if "shutdown_request(" not in process:
        bad.append("process_request 超限时不再直接关连接")
    api = method(server, "_api")
    if "_take_body(" not in api:
        bad.append("_api 不再先读请求体")
    else:
        first = api.index("_take_body(")
        for token, label in (("LOGIN_REQUIRED", "登录检查"), ("CSRF_DETAIL", "来源页与防伪头检查")):
            if token in api and api.index(token) < first:
                bad.append(f"_api 里{label}排在读请求体之前")
    for token, label in (("time.sleep(", "time.sleep"), ("threading.Timer", "threading.Timer"),
                         ("HTTP/1.1", "HTTP/1.1")):
        if token in server:
            bad.append(f"server.py 里出现了 {label}")
    if server.count("threading.Thread(") != 1:
        bad.append("server.py 新增了线程(只许 serve 里原有的那一处)")
    return bad


def tests():
    bad = []
    body = text(ROOT / TEST_PATH)
    old = git("show", f"{base()}:{TEST_PATH}").replace("\r\n", "\n")
    for name in OLD_TESTS + OLD_HELPERS:
        before, after = function(old, name), function(body, name)
        if not after:
            bad.append(f"既有的 {name} 不见了")
        elif before and before != after:
            bad.append(f"既有的 {name} 被改了")
    if "\nclass Running:" not in body:
        bad.append("既有的 Running 不见了")
    if not function(body, "wait_closed"):
        bad.append("缺辅助函数 wait_closed")
    for name in NEW_TESTS:
        source = function(body, name)
        if not source:
            bad.append(f"缺新用例 {name}")
            continue
        if re.search(r"\bexcept\b", source):
            bad.append(f"{name} 里有 except(只有 wait_closed 可以写)")
        if "read_until_close(" in source:
            bad.append(f"{name} 用了会吞掉重置的 read_until_close")
    for word in ("flaky", "rerun", "retry", "retries", "pytest.mark.skip", "xfail"):
        if word in body.lower() and word not in old.lower():
            bad.append(f"测试文件里新出现了 {word}")
    return bad


def scope():
    names = [line.strip() for line in git("diff", "--name-only", base()).splitlines() if line.strip()]
    names += [line.strip() for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line.strip()]
    return [f"改了圈外文件 {p}" for p in sorted(set(names) - ALLOWED)]


if __name__ == "__main__":
    problems = {"shape": shape, "tests": tests, "scope": scope}[sys.argv[1]]()
    for line in problems:
        print(line)
    print("通过" if not problems else f"不通过:{len(problems)} 项")
    sys.exit(1 if problems else 0)
