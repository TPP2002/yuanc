import http.client
import json
import socket
import threading
from datetime import UTC, datetime

import pytest
from exitnode.config import load
from exitnode.console import server as console_server
from exitnode.console.auth import hash_password
from exitnode.runner import FakeRunner
from test_cli import TEXT

# 管理密码固定 20 位、只用这套字母表；测试值本身就能过格式检查。
PASSWORD = "ABCDE-FGHJK-LMNPQ-RSTUV"
WRONG_PASSWORD = "ABCDE-FGHJK-LMNPQ-RSTUW"
ADMIN_KEY = "test-admin-only"
PASSWORD_HASH = hash_password(PASSWORD)

STATIC_FILES = {
    "index.html": b"<!DOCTYPE html><html><body>page</body></html>",
    "console.js": b"console.log('page');",
    "console.css": b"body { color: #333; }",
}

ACCOUNT = {"id": "acc-1", "invite_code": "ABC", "status": "active",
           "expires_at": "2026-12-01T00:00:00+00:00", "device_limit": 2,
           "created_at": "2026-11-01T00:00:00+00:00"}
DEVICE = {"id": "dev-1", "account_id": "acc-1", "platform": "windows", "name": "测试电脑",
          "last_seen": "2026-11-01T00:00:00+00:00", "revoked_at": None}


def build_config(*, authsync=False, console=False):
    # 示例配置末尾可能带管理网页段，先切掉，下面按需再拼，免得段落重复。
    text = TEXT.split("\n[console]\n")[0]
    if authsync:
        text = text.replace('[authsync]\nenabled = false\nurl = ""',
                            '[authsync]\nenabled = true\nurl = "http://127.0.0.1:8000"')
    if console:
        text += "\n[console]\nenabled = true\n"
    return load("/config", FakeRunner(files={"/config": text}))


class Clock:
    def __init__(self, value=1800000000.0):
        self.value = value

    def __call__(self):
        return self.value

    def tick(self, seconds):
        self.value += seconds


class FakeClient:
    def __init__(self):
        self.calls = []
        self.error = None

    def _maybe(self):
        if self.error is not None:
            raise self.error

    def invites(self):
        self.calls.append(("invites",))
        self._maybe()
        return [{"code": "A1", "days": 30, "max_uses": 1, "used": 0, "note": "",
                 "created_at": "2026-11-01T00:00:00+00:00"}]

    def accounts(self):
        self.calls.append(("accounts",))
        self._maybe()
        return [ACCOUNT]

    def devices(self):
        self.calls.append(("devices",))
        self._maybe()
        return [DEVICE]

    def create_invite(self, days, max_uses, note):
        self.calls.append(("create_invite", days, max_uses, note))
        self._maybe()
        return {"code": "NEW", "days": days, "max_uses": max_uses, "used": 0, "note": note}

    def account_action(self, account_id, action, days=None):
        self.calls.append(("account_action", account_id, action, days))
        self._maybe()
        status = "disabled" if action == "disable" else "active"
        return dict(ACCOUNT, id=account_id, status=status)

    def revoke(self, device_id):
        self.calls.append(("revoke", device_id))
        self._maybe()
        return {"device_id": device_id, "revoked": True}


def make(tmp_path, *, config=None, credentials=None, client=None, clock=None,
         sources=None, static_dir=None, snapshot_path=None):
    if static_dir is None:
        static_dir = tmp_path / "static"
        static_dir.mkdir(exist_ok=True)
        for name, data in STATIC_FILES.items():
            (static_dir / name).write_bytes(data)
    return console_server.create_server(
        config or build_config(),
        credentials=credentials or {"password": PASSWORD_HASH, "admin_key": ADMIN_KEY},
        static_dir=static_dir,
        snapshot_path=snapshot_path or tmp_path / "status.json",
        client=client,
        clock=clock or Clock(),
        sources=sources,
        bind="127.0.0.1",
        port=0)


class Running:
    def __init__(self, server):
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def call(server, path, method="GET", *, headers=None, json_body=None, cookie=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    try:
        request_headers = dict(headers or {})
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        if cookie:
            request_headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        return (response.status,
                {key.lower(): value for key, value in response.getheaders()},
                response.read())
    finally:
        connection.close()


def login(server):
    status, headers, body = call(server, "/api/login", "POST", json_body={"password": PASSWORD})
    assert status == 200, body
    return json.loads(body), headers["set-cookie"].split(";")[0]


def origin_of(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_static_files_and_security_headers(tmp_path):
    expected = {"/": ("index.html", "text/html; charset=utf-8"),
                "/console.js": ("console.js", "text/javascript; charset=utf-8"),
                "/console.css": ("console.css", "text/css; charset=utf-8")}
    with Running(make(tmp_path)) as server:
        for path, (name, content_type) in expected.items():
            status, headers, body = call(server, path)
            assert status == 200
            assert body == STATIC_FILES[name]
            assert headers["content-type"] == content_type
            assert headers["cache-control"] == "no-store"
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["referrer-policy"] == "no-referrer"
            assert headers["x-frame-options"] == "DENY"
            assert headers["content-security-policy"].startswith("default-src 'none'")


def test_unknown_paths_methods_and_missing_static_get_decoy(tmp_path):
    import authserver.app as authserver_app

    page = authserver_app.NOT_FOUND_PAGE.encode("utf-8")
    with Running(make(tmp_path)) as server:
        cases = [("GET", "/nope"), ("GET", "/api/nope"), ("GET", "/api/login"),
                 ("POST", "/api/session"), ("POST", "/api/status"),
                 ("PUT", "/"), ("DELETE", "/api/session"), ("OPTIONS", "/api/session")]
        for method, path in cases:
            status, headers, body = call(server, path, method)
            assert status == 404
            assert headers["content-type"] == "text/html; charset=utf-8"
            assert body == page
        status, headers, body = call(server, "/", "HEAD")
        assert status == 404 and headers["content-type"] == "text/html; charset=utf-8"
        assert body == b""
    empty = tmp_path / "empty"
    empty.mkdir()
    with Running(make(tmp_path, static_dir=empty)) as server:
        status, _, body = call(server, "/")
        assert status == 404 and body == page


def test_no_server_header_anywhere(tmp_path):
    with Running(make(tmp_path)) as server:
        cases = [("GET", "/", {}), ("GET", "/api/session", {}), ("GET", "/nope", {}),
                 ("POST", "/api/login", {"json_body": {"password": WRONG_PASSWORD}})]
        for method, path, options in cases:
            _, headers, _ = call(server, path, method, **options)
            assert "server" not in headers


def test_disallowed_source_gets_decoy(tmp_path):
    import authserver.app as authserver_app

    with Running(make(tmp_path, sources=("10.0.0.0/8",))) as server:
        status, headers, body = call(server, "/api/session")
        assert status == 404
        assert body == authserver_app.NOT_FOUND_PAGE.encode("utf-8")


def test_bad_host_header_gets_decoy(tmp_path):
    with Running(make(tmp_path)) as server:
        assert call(server, "/api/session", headers={"Host": "evil.example"})[0] == 404
        assert call(server, "/", headers={"Host": "evil.example"})[0] == 404
        sock = socket.create_connection(server.server_address, timeout=5)
        try:
            sock.sendall(b"GET /api/session HTTP/1.0\r\n\r\n")
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()
        assert data.startswith(b"HTTP/1.0 404")
        port = server.server_address[1]
        for host in ("192.168.1.52:8444", "localhost", f"127.0.0.1:{port}"):
            assert call(server, "/api/session", headers={"Host": host})[0] == 200


def test_login_success_sets_cookie_and_session(tmp_path):
    with Running(make(tmp_path)) as server:
        status, headers, body = call(server, "/api/login", "POST",
                                     json_body={"password": PASSWORD})
        assert status == 200
        data = json.loads(body)
        assert data["logged_in"] is True and data["csrf"]
        assert data["node_name"] == "请填写节点名称"
        assert data["invite_mode"] is False
        cookie = headers["set-cookie"]
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        assert "Path=/" in cookie and "Max-Age=43200" in cookie
        key = cookie.split(";")[0]
        session = json.loads(call(server, "/api/session", cookie=key)[2])
        assert session == {"logged_in": True, "csrf": data["csrf"],
                           "node_name": "请填写节点名称", "invite_mode": False}


def test_login_wrong_password_and_throttle(tmp_path):
    clock = Clock()
    with Running(make(tmp_path, clock=clock)) as server:
        for _ in range(5):
            status, _, body = call(server, "/api/login", "POST",
                                   json_body={"password": WRONG_PASSWORD})
            assert status == 401
            assert json.loads(body) == {"detail": "密码不对", "code": "wrong_password"}
        status, _, body = call(server, "/api/login", "POST", json_body={"password": PASSWORD})
        assert status == 429
        assert json.loads(body)["code"] == "throttled"
        clock.tick(901)
        assert call(server, "/api/login", "POST", json_body={"password": PASSWORD})[0] == 200


def test_login_concurrency_gate_returns_429(tmp_path, monkeypatch):
    # 把验密码换成一个卡在闸里的替身：同时只准两个进去，第三个立刻被挡。
    entered = threading.Event()
    release = threading.Event()
    counter = {"now": 0}
    counter_lock = threading.Lock()

    def stuck(raw, stored):
        with counter_lock:
            counter["now"] += 1
            if counter["now"] >= 2:
                entered.set()
        release.wait(timeout=10)
        return True

    monkeypatch.setattr("exitnode.console.auth.verify_password", stuck)

    results = {}

    def attempt(name):
        try:
            results[name] = call(server, "/api/login", "POST",
                                 json_body={"password": PASSWORD})
        except OSError as error:  # pragma: no cover - 只在连接被断开时出现
            results[name] = error

    with Running(make(tmp_path)) as server:
        first = threading.Thread(target=attempt, args=("first",))
        second = threading.Thread(target=attempt, args=("second",))
        first.start()
        second.start()
        assert entered.wait(timeout=10)
        try:
            status, _, body = call(server, "/api/login", "POST",
                                   json_body={"password": PASSWORD})
            assert status == 429
            assert json.loads(body)["code"] == "throttled"
        finally:
            release.set()
        first.join(timeout=10)
        second.join(timeout=10)
    for name in ("first", "second"):
        status, _, body = results[name]
        assert status == 200, body
        assert json.loads(body)["logged_in"] is True


def read_until_close(address, payload):
    sock = socket.create_connection(address, timeout=10)
    try:
        sock.sendall(payload)
        raw = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except ConnectionResetError:  # pragma: no cover - 只在系统直接重置时出现
                break
            if not chunk:
                break
            raw += chunk
        return raw
    finally:
        sock.close()


def test_malformed_requests_get_decoy(tmp_path):
    page = console_server.NOT_FOUND_PAGE.encode("utf-8")
    with Running(make(tmp_path)) as server:
        address = server.server_address
        host = f"127.0.0.1:{address[1]}\r\n"
        cases = {
            "PATCH": f"PATCH / HTTP/1.0\r\nHost: {host}\r\n",
            "FOO": f"FOO / HTTP/1.0\r\nHost: {host}\r\n",
            # 坏请求行：只发那一行，服务器读完就回通用 404。
            "bad-line": "GARBAGE\r\n",
            # 请求行 65537 个字节，刚超过 65536 的上限，服务器读到就 414。
            "long-line": "GET /" + "a" * 65532,
            # 101 个请求头超过上限 100，服务器读完第 101 个就 431。
            "many-headers": (f"GET / HTTP/1.0\r\nHost: {host}"
                             + "".join(f"X-Pad-{index}: 1\r\n" for index in range(100))),
        }
        for name, request in cases.items():
            raw = read_until_close(address, request.encode("ascii"))
            # 读到连接关闭才停：通用 404 回完就断开，不再搭理后续请求。
            assert page in raw, name
            for banned in (b"Error response", b"Python", b"BaseHTTP", b"Server:"):
                assert banned not in raw, (name, banned)


def test_cookie_header_parsing(tmp_path):
    with Running(make(tmp_path)) as server:
        data, cookie = login(server)
        value = cookie.split("=", 1)[1]
        # 夹在别的 cookie 中间也认得出来。
        session = call(server, "/api/session", cookie=f"a=1; yc_console={value}; b=2")[2]
        assert json.loads(session)["logged_in"] is True
        # 超长 Cookie 头当没带（同一个值放在末尾也不认）。
        long_header = "a=" + "1" * 4100 + f"; yc_console={value}"
        assert json.loads(call(server, "/api/session", cookie=long_header)[2]) == {
            "logged_in": False}
        # 值里带引号或逗号当没带。
        for bad in (f'yc_console="{value}"', f"yc_console={value},x"):
            assert json.loads(call(server, "/api/session", cookie=bad)[2]) == {
                "logged_in": False}
        # 只有冒号后面空着也算没带。
        assert json.loads(call(server, "/api/session", cookie="yc_console=")[2]) == {
            "logged_in": False}
        assert data["csrf"]


def test_password_missing_returns_409(tmp_path):
    credentials = {"password": None, "admin_key": ADMIN_KEY}
    with Running(make(tmp_path, credentials=credentials)) as server:
        status, _, body = call(server, "/api/login", "POST", json_body={"password": PASSWORD})
        assert status == 409
        assert json.loads(body)["code"] == "password_missing"


def test_api_requires_session(tmp_path):
    with Running(make(tmp_path)) as server:
        cases = [("GET", "/api/status"), ("GET", "/api/directory"),
                 ("POST", "/api/logout"), ("POST", "/api/invites")]
        for method, path in cases:
            options = {"json_body": {}} if method == "POST" else {}
            status, _, body = call(server, path, method, **options)
            assert status == 401
            assert json.loads(body) == {"detail": "请先登录", "code": "login_required"}


def test_post_requires_csrf_and_same_origin(tmp_path):
    with Running(make(tmp_path, client=FakeClient())) as server:
        data, cookie = login(server)
        origin = origin_of(server)
        assert call(server, "/api/logout", "POST", json_body={}, cookie=cookie)[0] == 403
        status, _, body = call(server, "/api/logout", "POST", json_body={}, cookie=cookie,
                               headers={"X-Console-CSRF": "wrong"})
        assert status == 403 and json.loads(body)["code"] == "csrf"
        status, _, body = call(server, "/api/invites", "POST",
                               json_body={"days": 1, "max_uses": 1, "note": ""}, cookie=cookie,
                               headers={"X-Console-CSRF": data["csrf"],
                                        "Origin": "http://evil.example"})
        assert status == 403 and json.loads(body)["code"] == "csrf"
        assert call(server, "/api/login", "POST", json_body={"password": PASSWORD},
                    headers={"Origin": "http://evil.example"})[0] == 403
        status, _, _ = call(server, "/api/invites", "POST",
                            json_body={"days": 1, "max_uses": 1, "note": ""}, cookie=cookie,
                            headers={"X-Console-CSRF": data["csrf"], "Origin": origin})
        assert status == 200


def test_logout_clears_session(tmp_path):
    with Running(make(tmp_path)) as server:
        data, cookie = login(server)
        status, headers, body = call(server, "/api/logout", "POST", json_body={}, cookie=cookie,
                                     headers={"X-Console-CSRF": data["csrf"]})
        assert status == 200 and json.loads(body) == {"logged_in": False}
        assert "max-age=0" in headers["set-cookie"].lower()
        assert call(server, "/api/session", cookie=cookie)[2] == b'{"logged_in":false}'
        assert call(server, "/api/status", cookie=cookie)[0] == 401


def test_status_available_stale_and_missing(tmp_path):
    clock = Clock()
    target = tmp_path / "status.json"
    record = {"version": 1, "node_name": "节点", "program_version": "0.1.0",
              "state": "normal", "reason": "正常", "public_ipv4": None,
              "layers": [], "local_devices": []}
    with Running(make(tmp_path, clock=clock, snapshot_path=target)) as server:
        data, cookie = login(server)
        assert call(server, "/api/status", cookie=cookie)[2] == b'{"available":false}'

        record["generated_at"] = datetime.fromtimestamp(clock.value - 10, UTC).isoformat()
        target.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        value = json.loads(call(server, "/api/status", cookie=cookie)[2])
        assert value["available"] is True
        assert value["age_seconds"] == 10 and value["stale"] is False
        assert value["state"] == "normal" and value["reason"] == "正常"

        record["generated_at"] = datetime.fromtimestamp(clock.value - 200, UTC).isoformat()
        target.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        value = json.loads(call(server, "/api/status", cookie=cookie)[2])
        assert value["stale"] is True and value["age_seconds"] == 200
        assert data["csrf"]


def test_directory_and_actions_forwarded(tmp_path):
    client = FakeClient()
    with Running(make(tmp_path, client=client)) as server:
        data, cookie = login(server)
        csrf = {"X-Console-CSRF": data["csrf"]}
        status, _, body = call(server, "/api/directory", cookie=cookie)
        assert status == 200
        assert json.loads(body) == {"invites": client.invites(),
                                    "accounts": [ACCOUNT], "devices": [DEVICE]}
        assert ("invites",) in client.calls and ("accounts",) in client.calls

        status, _, body = call(server, "/api/invites", "POST",
                               json_body={"days": 30, "max_uses": 2, "note": "  说明  "},
                               headers=csrf, cookie=cookie)
        assert json.loads(body) == {"invite": {"code": "NEW", "days": 30, "max_uses": 2,
                                               "used": 0, "note": "说明"}}
        assert ("create_invite", 30, 2, "说明") in client.calls

        status, _, body = call(server, f"/api/accounts/{ACCOUNT['id']}/extend", "POST",
                               json_body={"days": 7}, headers=csrf, cookie=cookie)
        assert json.loads(body)["account"]["id"] == ACCOUNT["id"]
        assert ("account_action", ACCOUNT["id"], "extend", 7) in client.calls

        for action in ("disable", "enable"):
            status, _, _ = call(server, f"/api/accounts/{ACCOUNT['id']}/{action}", "POST",
                                json_body={}, headers=csrf, cookie=cookie)
            assert status == 200
            assert ("account_action", ACCOUNT["id"], action, None) in client.calls

        status, _, body = call(server, f"/api/devices/{DEVICE['id']}/revoke", "POST",
                               json_body={}, headers=csrf, cookie=cookie)
        assert json.loads(body) == {"device_id": DEVICE["id"], "revoked": True}
        assert ("revoke", DEVICE["id"]) in client.calls


def test_invite_and_extend_validation(tmp_path):
    with Running(make(tmp_path, client=FakeClient())) as server:
        data, cookie = login(server)
        csrf = {"X-Console-CSRF": data["csrf"]}
        for days in (0, 3651, "7", True, 7.0):
            status, _, body = call(server, "/api/invites", "POST",
                                   json_body={"days": days, "max_uses": 1, "note": ""},
                                   headers=csrf, cookie=cookie)
            assert status == 422
            assert json.loads(body) == {"detail": "天数要填 1 到 3650 的整数",
                                        "code": "bad_request"}
        for uses in (0, 101, "2", True):
            status, _, body = call(server, "/api/invites", "POST",
                                   json_body={"days": 1, "max_uses": uses, "note": ""},
                                   headers=csrf, cookie=cookie)
            assert status == 422
            assert json.loads(body)["detail"] == "人数要填 1 到 100 的整数"
        for note in ("字" * 201, "第一行\n第二行"):
            status, _, body = call(server, "/api/invites", "POST",
                                   json_body={"days": 1, "max_uses": 1, "note": note},
                                   headers=csrf, cookie=cookie)
            assert status == 422
            assert json.loads(body)["detail"] == "备注最多 200 个字,不能换行"
        status, _, body = call(server, "/api/invites", "POST",
                               json_body={"days": 1, "max_uses": 1, "note": "", "extra": 1},
                               headers=csrf, cookie=cookie)
        assert status == 422 and json.loads(body)["detail"] == "请求格式不对"
        status, _, body = call(server, f"/api/accounts/{ACCOUNT['id']}/extend", "POST",
                               json_body={"days": 0}, headers=csrf, cookie=cookie)
        assert status == 422
        assert json.loads(body)["detail"] == "天数要填 1 到 3650 的整数"


def test_invite_mode_off_and_admin_key_missing_codes(tmp_path):
    with Running(make(tmp_path)) as server:
        data, cookie = login(server)
        csrf = {"X-Console-CSRF": data["csrf"]}
        status, _, body = call(server, "/api/invites", "POST",
                               json_body={"days": 1, "max_uses": 1, "note": ""},
                               headers=csrf, cookie=cookie)
        assert status == 409
        assert json.loads(body) == {"detail": "这台节点没开邀请码模式",
                                    "code": "invite_mode_off"}
        status, _, body = call(server, "/api/directory", cookie=cookie)
        assert status == 409 and json.loads(body)["code"] == "invite_mode_off"

    config = build_config(authsync=True)
    credentials = {"password": PASSWORD_HASH, "admin_key": None}
    with Running(make(tmp_path, config=config, credentials=credentials)) as server:
        data, cookie = login(server)
        status, _, body = call(server, "/api/directory", cookie=cookie)
        assert status == 409
        assert json.loads(body) == {
            "detail": "还没填鉴权服务的管理密钥,请在节点上运行 exitnode console admin-key",
            "code": "admin_key_missing"}


def test_ids_in_path_are_validated(tmp_path):
    client = FakeClient()
    with Running(make(tmp_path, client=client)) as server:
        data, cookie = login(server)
        csrf = {"X-Console-CSRF": data["csrf"]}
        for account_id in ("bad.id", "a" * 65, "bad/id"):
            status, _, _ = call(server, f"/api/accounts/{account_id}/extend", "POST",
                                json_body={"days": 1}, headers=csrf, cookie=cookie)
            assert status == 404
        assert call(server, "/api/devices/bad.id/revoke", "POST", json_body={},
                    headers=csrf, cookie=cookie)[0] == 404
        status, _, _ = call(server, "/api/accounts/acc-1_2/extend", "POST",
                            json_body={"days": 1}, headers=csrf, cookie=cookie)
        assert status == 200
        assert ("account_action", "acc-1_2", "extend", 1) in client.calls


def test_oversized_body_rejected(tmp_path):
    with Running(make(tmp_path, client=FakeClient())) as server:
        data, cookie = login(server)
        request = (
            "POST /api/invites HTTP/1.0\r\n"
            f"Host: 127.0.0.1:{server.server_address[1]}\r\n"
            f"Cookie: {cookie}\r\n"
            f"X-Console-CSRF: {data['csrf']}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 40000\r\n\r\n"
        ).encode("ascii")
        sock = socket.create_connection(server.server_address, timeout=5)
        try:
            sock.sendall(request)
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        finally:
            sock.close()
        assert raw.startswith(b"HTTP/1.0 422")
        body = raw.split(b"\r\n\r\n", 1)[1]
        assert json.loads(body) == {"detail": "请求格式不对", "code": "bad_request"}


def test_check_layer(tmp_path):
    config = build_config()
    server = make(tmp_path, config=config)
    with Running(server):
        config.console.port = server.server_address[1]
        result = console_server.check(config)
        assert result == {"layer": "console", "name": "管理网页", "result": "通过",
                          "reason": "管理网页可以打开"}
    result = console_server.check(config)
    assert result["result"] == "失败" and result["reason"] == "管理网页打不开"


def test_load_credentials_from_env_and_secrets(tmp_path, monkeypatch):
    directory = tmp_path / "credentials"
    directory.mkdir()
    (directory / "console-password").write_text(PASSWORD_HASH + "\r\n", encoding="utf-8")
    (directory / "authserver-admin-key").write_text("  " + ADMIN_KEY + "  \n",
                                                    encoding="utf-8")
    value = console_server.load_credentials({"CREDENTIALS_DIRECTORY": str(directory)})
    assert value == {"password": PASSWORD_HASH, "admin_key": ADMIN_KEY}

    (directory / "console-password").write_text("plain-text-password\n", encoding="utf-8")
    (directory / "authserver-admin-key").write_text("bad\x01key", encoding="utf-8")
    value = console_server.load_credentials({"CREDENTIALS_DIRECTORY": str(directory)})
    assert value == {"password": None, "admin_key": None}

    (directory / "console-password").write_text(PASSWORD_HASH, encoding="utf-8")
    (directory / "authserver-admin-key").write_text("k" * 600, encoding="utf-8")
    assert console_server.load_credentials(
        {"CREDENTIALS_DIRECTORY": str(directory)})["admin_key"] is None

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "console-password").write_text(PASSWORD_HASH + "\n", encoding="utf-8")
    (secrets / "authserver-admin-key").write_text(ADMIN_KEY + "\n", encoding="utf-8")
    monkeypatch.setattr(console_server.service, "SECRETS", str(secrets))
    assert console_server.load_credentials({}) == {"password": PASSWORD_HASH,
                                                   "admin_key": ADMIN_KEY}
    assert console_server.load_credentials(
        {"CREDENTIALS_DIRECTORY": str(tmp_path / "missing")}) == {"password": None,
                                                                  "admin_key": None}


def test_secrets_never_logged(tmp_path, caplog, capsys):
    import logging

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Capture()
    logging.getLogger("exitnode").addHandler(handler)
    client = FakeClient()
    try:
        with caplog.at_level("ERROR"), Running(make(tmp_path, client=client)) as server:
            data, cookie = login(server)
            cookie_value = cookie.split("=", 1)[1]
            client.error = RuntimeError(
                "TEST-PASSWORD " + ADMIN_KEY + " " + PASSWORD_HASH)
            status, _, _ = call(server, "/api/directory",
                                headers={"X-Console-CSRF": data["csrf"]}, cookie=cookie)
            assert status == 500
    finally:
        logging.getLogger("exitnode").removeHandler(handler)
    captured = capsys.readouterr()
    text = caplog.text + captured.out + captured.err + "\n".join(records)
    assert "管理网页请求处理失败" in text
    assert PASSWORD not in text
    assert ADMIN_KEY not in text
    assert PASSWORD_HASH not in text
    assert data["csrf"] not in text
    assert cookie_value not in text


def test_rejected_post_waits_for_body_then_answers(tmp_path):
    # 会被拒的 POST 也要先等请求体:请求体没到齐之前服务端一个字都不许回,
    # 到了之后才按原规则给出 401 / 403 / 422 / 429。
    payload = b'{"days":1,"max_uses":1,"note":""}'
    with Running(make(tmp_path, client=FakeClient())) as server:
        data, cookie = login(server)
        host = f"127.0.0.1:{server.server_address[1]}"
        csrf = data["csrf"]
        password_payload = json.dumps({"password": PASSWORD}).encode("utf-8")

        def exchange(request_head, request_body):
            sock = socket.create_connection(server.server_address, timeout=5)
            try:
                # 先只发请求头;请求体没到,服务端此刻必须一个字节都不回。
                sock.sendall(request_head)
                sock.settimeout(0.3)
                with pytest.raises(TimeoutError):
                    sock.recv(4096)
                # 再把请求体补上,读到连接关闭为止。
                sock.sendall(request_body)
                sock.settimeout(5)
                raw = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                return raw
            finally:
                sock.close()

        cases = [
            # 没带 Cookie:401,要先等请求体到齐。
            ("/api/invites", {"Content-Type": "application/json"}, payload,
             401, {"detail": "请先登录", "code": "login_required"}),
            # 带 Cookie、不带防伪头:403。
            ("/api/logout", {"Cookie": cookie, "Content-Type": "application/json"}, b"{}",
             403, {"detail": console_server.CSRF_DETAIL, "code": "csrf"}),
            # 来源页不对:403。
            ("/api/invites", {"Cookie": cookie, "X-Console-CSRF": csrf,
                              "Origin": "http://evil.example",
                              "Content-Type": "application/json"}, payload,
             403, {"detail": console_server.CSRF_DETAIL, "code": "csrf"}),
            # 登录也要先等请求体,来源页不对照样 403。
            ("/api/login", {"Origin": "http://evil.example",
                            "Content-Type": "application/json"}, password_payload,
             403, {"detail": console_server.CSRF_DETAIL, "code": "csrf"}),
            # 内容类型不对:422。
            ("/api/invites", {"Cookie": cookie, "X-Console-CSRF": csrf,
                              "Content-Type": "text/plain"}, payload,
             422, {"detail": "请求格式不对", "code": "bad_request"}),
        ]
        for path, extra, body, status, expected in cases:
            head = (f"POST {path} HTTP/1.0\r\nHost: {host}\r\n"
                    + "".join(f"{key}: {value}\r\n" for key, value in extra.items())
                    + f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
            raw = exchange(head, body)
            assert raw.startswith(b"HTTP/1.0 " + str(status).encode("ascii"))
            assert json.loads(raw.split(b"\r\n\r\n", 1)[1]) == expected

        # 最后一种:先用常规请求错 5 次,再把正确密码的 POST 拆开发,应得 429。
        for _ in range(5):
            status, _, _ = call(server, "/api/login", "POST",
                                json_body={"password": WRONG_PASSWORD})
            assert status == 401
        head = (f"POST /api/login HTTP/1.0\r\nHost: {host}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(password_payload)}\r\n\r\n").encode("ascii")
        raw = exchange(head, password_payload)
        assert raw.startswith(b"HTTP/1.0 429")
        assert json.loads(raw.split(b"\r\n\r\n", 1)[1])["code"] == "throttled"


def test_stalled_body_closes_without_reply(tmp_path, caplog, monkeypatch):
    # 请求体没到齐、等到套接字超时:这条连接一个字都不回,直接断开,也不记错误日志。
    import logging

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Capture()
    logging.getLogger("exitnode").addHandler(handler)
    try:
        with caplog.at_level("ERROR"), Running(make(tmp_path)) as server:
            port = server.server_address[1]
            with monkeypatch.context() as patch:
                # 每条新连接建立时读这个类属性,所以块里建的这条连接只等 0.5 秒。
                patch.setattr(console_server.ConsoleHandler, "timeout", 0.5)
                head = (f"POST /api/invites HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: 10\r\n\r\n").encode("ascii")
                sock = socket.create_connection(server.server_address, timeout=5)
                try:
                    # 请求头和三个字节一起发,声明的长度是 10,剩下的七个字节永远不来。
                    sock.sendall(head + b'{"d')
                    received = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        received += chunk
                finally:
                    sock.close()
            assert received == b""
            # 超时已回到原值,再发一条普通请求:服务还在。
            assert call(server, "/api/session")[0] == 200
    finally:
        logging.getLogger("exitnode").removeHandler(handler)
    text = caplog.text + "\n".join(records)
    assert "管理网页请求处理失败" not in text
