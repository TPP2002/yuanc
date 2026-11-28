import contextlib
import http.client
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from exitnode.admin.server import PackageHandler, PackageServer, check, create_server


@pytest.fixture
def hosted(tmp_path):
    root = tmp_path / "winclient" / "releases"
    root.mkdir(parents=True)
    (root / "latest.json").write_bytes(b'{"version":"1.2.3"}')
    (root / "YuanC-Client-1.2.3.exe").write_bytes(b"0123456789")
    server = create_server("127.0.0.1", 0, root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, root
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def request(hosted, path, method="GET", headers=None):
    connection = http.client.HTTPConnection(*hosted[0].server_address, timeout=3)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_files_head_and_headers(hosted):
    status, headers, body = request(hosted, "/winclient/latest.json")
    assert status == 200 and body == b'{"version":"1.2.3"}'
    assert headers["Content-Type"] == "application/json"
    assert headers["Content-Length"] == str(len(body))
    assert headers["Cache-Control"] == "no-store"
    assert headers["Accept-Ranges"] == "bytes"
    status, headers, body = request(hosted, "/winclient/YuanC-Client-1.2.3.exe", "HEAD")
    assert status == 200 and not body
    assert headers["Content-Length"] == "10"
    assert headers["Content-Type"] == "application/octet-stream"


def test_resume_and_out_of_range(hosted):
    path = "/winclient/YuanC-Client-1.2.3.exe"
    status, headers, body = request(hosted, path, headers={"Range": "bytes=4-"})
    assert status == 206 and body == b"456789"
    assert headers["Content-Range"] == "bytes 4-9/10"
    assert headers["Content-Length"] == "6"
    status, headers, _ = request(hosted, path, headers={"Range": "bytes=10-"})
    assert status == 416 and headers["Content-Range"] == "bytes */10"


@pytest.mark.parametrize("path", ["/", "/winclient/", "/winclient/../latest.json",
                                  "/winclient/%2e%2e/latest.json", "/winclient/evil.exe",
                                  "/winclient/a%5cb", "/winclient/latest.json?x=1"])
def test_only_exact_allowlisted_paths(hosted, path):
    assert request(hosted, path)[0] == 404


def test_post_refused_and_no_access_log(hosted, capsys):
    assert request(hosted, "/winclient/latest.json", "POST")[0] in {404, 405}
    assert not capsys.readouterr().err


def test_symlink_refused(hosted, tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    link = hosted[1] / "YuanC-Client-2.0.0.exe"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("当前测试用户无创建符号链接权限，Linux 真机仍须验证")
    assert request(hosted, "/winclient/" + link.name)[0] == 404


def test_check_accepts_200_and_404_but_not_unreachable(hosted):
    config = SimpleNamespace(admin=SimpleNamespace(bind="127.0.0.1",
                                                   port=hosted[0].server_address[1]))
    assert check(config)["result"] == "通过"
    # The first response may still be sending on Windows; exercise an empty
    # hosting root instead of racing deletion against its open file handle.
    hosted[0].root = hosted[1] / "empty"
    assert check(config)["result"] == "通过"
    hosted[0].shutdown()
    hosted[0].server_close()
    assert check(config)["result"] == "失败"


BIG = 32 * 1024 * 1024
LATEST = b'{"version":"1.2.3"}'


@contextlib.contextmanager
def running(tmp_path, **options):
    root = tmp_path / "winclient" / "releases"
    root.mkdir(parents=True)
    (root / "latest.json").write_bytes(LATEST)
    with open(root / "YuanC-Client-9.9.9.exe", "wb") as stream:
        stream.truncate(BIG)
    server = create_server("127.0.0.1", 0, root, **options)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def raw_connect(server):
    sock = socket.create_connection(server.server_address, timeout=3)
    return sock


def latest_status(server):
    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
    try:
        connection.request("GET", "/winclient/latest.json")
        return connection.getresponse().status
    finally:
        connection.close()


def config_for(server):
    return SimpleNamespace(admin=SimpleNamespace(bind="127.0.0.1", port=server.server_address[1]))


def closed_without_bytes(sock, within):
    """对端在 within 秒内关了连接,而且一个字节都没写。被对端重置也算关了。"""
    sock.settimeout(within)
    try:
        return sock.recv(1024) == b""
    except ConnectionError:
        return True
    except TimeoutError:
        return False


def stalled_download(server):
    """发完整请求、收到响应开头后不再读:服务端写满缓冲就卡住,这条连接一直占着一个并发名额。"""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(3)
    sock.connect(server.server_address)
    sock.sendall(b"GET /winclient/YuanC-Client-9.9.9.exe HTTP/1.1\r\nHost: x\r\n\r\n")
    assert sock.recv(12).startswith(b"HTTP/1.0 200")
    return sock


def status_when_available(server, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return latest_status(server)
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
    return None


def test_slow_client_is_disconnected_without_blocking_others(tmp_path):
    with running(tmp_path, timeout=0.5) as server:
        slow = raw_connect(server)
        try:
            # 另一条正常连接不受慢客户端影响。
            assert latest_status(server) in {200, 404}
            slow.settimeout(3)
            started = time.monotonic()
            assert slow.recv(1024) == b""
            assert time.monotonic() - started < 2
        finally:
            slow.close()


def test_timeout_is_per_server_not_global(tmp_path):
    before = PackageHandler.timeout
    with running(tmp_path, timeout=0.5):
        assert PackageHandler.timeout == before == 15


def test_idle_connections_do_not_take_slots(tmp_path):
    with running(tmp_path, max_connections=2) as server:
        idle = [raw_connect(server) for _ in range(10)]
        try:
            assert latest_status(server) == 200
            assert check(config_for(server))["result"] == "通过"
        finally:
            for sock in idle:
                sock.close()


def test_partial_header_does_not_take_slot(tmp_path):
    with running(tmp_path, max_connections=1, timeout=0.5) as server:
        slow = raw_connect(server)
        try:
            slow.sendall(b"GET /winclient/latest.json HTTP/1.1\r\nHost: x\r\n")
            assert latest_status(server) == 200
            started = time.monotonic()
            assert closed_without_bytes(slow, 3)
            assert time.monotonic() - started < 2
        finally:
            slow.close()


def test_header_split_across_packets_is_served(tmp_path):
    with running(tmp_path) as server:
        sock = raw_connect(server)
        try:
            sock.sendall(b"GET /winclient/latest.json HT")
            time.sleep(0.2)
            sock.sendall(b"TP/1.1\r\nHost: x\r\n\r\n")
            data = b""
            while True:
                block = sock.recv(4096)
                if not block:
                    break
                data += block
            assert data.startswith(b"HTTP/1.0 200")
            assert data.endswith(b"\r\n\r\n" + LATEST)
        finally:
            sock.close()


def test_header_timeout_closes_idle_connection_early(tmp_path):
    with running(tmp_path, header_timeout=0.3) as server:
        idle = raw_connect(server)
        try:
            started = time.monotonic()
            assert closed_without_bytes(idle, 3)
            assert time.monotonic() - started < 2
            assert latest_status(server) == 200
        finally:
            idle.close()


def test_oversized_header_is_closed_without_response(tmp_path):
    with running(tmp_path) as server:
        sock = raw_connect(server)
        try:
            sock.sendall(b"GET /winclient/latest.json HTTP/1.1\r\nX-Pad: " + b"a" * 9000)
            started = time.monotonic()
            assert closed_without_bytes(sock, 3)
            assert time.monotonic() - started < 2
        finally:
            sock.close()


def test_waiting_room_evicts_oldest_connection(tmp_path):
    with running(tmp_path, max_waiting=4) as server:
        socks = [raw_connect(server) for _ in range(6)]
        try:
            for sock in socks[:2]:
                assert closed_without_bytes(sock, 2)
            for sock in socks[2:]:
                assert not closed_without_bytes(sock, 0.3)
            assert latest_status(server) == 200
        finally:
            for sock in socks:
                sock.close()


def test_flood_of_idle_connections_keeps_service_available(tmp_path):
    with running(tmp_path, max_connections=4, max_waiting=32) as server:
        slow = stalled_download(server)
        idle = []
        try:
            for _ in range(200):
                idle.append(raw_connect(server))
            assert check(config_for(server))["result"] == "通过"
            connection = http.client.HTTPConnection(*server.server_address, timeout=3)
            try:
                connection.request("GET", "/winclient/latest.json")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == LATEST
            finally:
                connection.close()
        finally:
            for sock in [slow, *idle]:
                sock.close()


def test_shutdown_closes_waiting_connections(tmp_path):
    with running(tmp_path) as server:
        idle = raw_connect(server)
        assert latest_status(server) == 200
    try:
        assert closed_without_bytes(idle, 3)
    finally:
        idle.close()


def test_connection_limit_closes_extra_request_and_recovers(tmp_path):
    with running(tmp_path, max_connections=2) as server:
        first, second = stalled_download(server), stalled_download(server)
        third = raw_connect(server)
        try:
            third.sendall(b"GET /winclient/latest.json HTTP/1.1\r\nHost: x\r\n\r\n")
            started = time.monotonic()
            assert closed_without_bytes(third, 2)
            assert time.monotonic() - started < 1
            first.close()
            assert status_when_available(server, 5) == 200
        finally:
            for sock in (first, second, third):
                sock.close()


def test_rejected_request_does_not_start_thread(tmp_path, monkeypatch):
    started = []
    original = PackageServer.process_request_thread

    def counting(self, request, client_address):
        started.append(1)
        return original(self, request, client_address)

    monkeypatch.setattr(PackageServer, "process_request_thread", counting)
    with running(tmp_path, max_connections=2) as server:
        first, second = stalled_download(server), stalled_download(server)
        third = raw_connect(server)
        try:
            third.sendall(b"GET /winclient/latest.json HTTP/1.1\r\nHost: x\r\n\r\n")
            assert closed_without_bytes(third, 2)
            assert len(started) == 2
        finally:
            for sock in (first, second, third):
                sock.close()
