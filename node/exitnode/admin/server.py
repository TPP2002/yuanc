"""无目录浏览、无访问日志的只读 HTTP 服务。"""

import collections
import http.client
import io
import logging
import os
import re
import selectors
import signal
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from ..log import redact
from .publish import FILENAME, releases

# 请求头最多收这么多字节;超过还没收完的连接直接关掉。
MAX_HEADER_BYTES = 8192
HEADER_END = (b"\r\n\r\n", b"\n\n")


class PackageServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, max_connections=32, header_timeout=5, max_waiting=256, **kwargs):
        # 必须先建好这些:父类构造会开始监听,但不会处理连接。
        self._slots = threading.BoundedSemaphore(max_connections)
        self._header_timeout = header_timeout
        self._max_waiting = max_waiting
        self._heads = {}
        self._stop = threading.Event()
        self._stopped = threading.Event()
        super().__init__(*args, **kwargs)

    def serve_forever(self, poll_interval=0.5):
        """一条线程管监听口和等候区:连接发完请求头之前不占并发名额、不开线程。"""
        self._stopped.clear()
        # 连接 -> [到期时刻, 已收到的字节, 来源地址],按接入先后排,最前面的等得最久。
        waiting = collections.OrderedDict()
        try:
            with selectors.DefaultSelector() as selector:
                self.socket.setblocking(False)
                selector.register(self.socket, selectors.EVENT_READ)
                try:
                    while not self._stop.is_set():
                        wait = poll_interval
                        if waiting:
                            oldest = next(iter(waiting.values()))[0]
                            wait = max(0, min(wait, oldest - time.monotonic()))
                        for key, _ in selector.select(wait):
                            if key.fileobj is self.socket:
                                self._admit(selector, waiting)
                            else:
                                self._read_head(selector, waiting, key.fileobj)
                        now = time.monotonic()
                        while waiting and next(iter(waiting.values()))[0] <= now:
                            self._drop(selector, waiting, next(iter(waiting)))
                finally:
                    for sock in list(waiting):
                        self._drop(selector, waiting, sock)
        finally:
            self._stop.clear()
            self._stopped.set()

    def shutdown(self):
        self._stop.set()
        self._stopped.wait()

    def _admit(self, selector, waiting):
        try:
            sock, address = self.get_request()
        except OSError:
            return
        if len(waiting) >= self._max_waiting:
            # 等候区满了:关掉等得最久的那一条,给新来的让位。
            self._drop(selector, waiting, next(iter(waiting)))
        sock.setblocking(False)
        waiting[sock] = [time.monotonic() + self._header_timeout, bytearray(), address]
        selector.register(sock, selectors.EVENT_READ)

    def _drop(self, selector, waiting, sock):
        del waiting[sock]
        selector.unregister(sock)
        self.shutdown_request(sock)

    def _read_head(self, selector, waiting, sock):
        entry = waiting.get(sock)
        if entry is None:
            # 同一轮里先被挤掉或已到期的连接。
            return
        try:
            data = sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            self._drop(selector, waiting, sock)
            return
        entry[1] += data
        if not any(mark in entry[1] for mark in HEADER_END):
            if len(entry[1]) > MAX_HEADER_BYTES:
                self._drop(selector, waiting, sock)
            return
        del waiting[sock]
        selector.unregister(sock)
        if not self._slots.acquire(blocking=False):
            # 并发名额用完:直接关闭,不开线程、不写任何响应字节。
            self.shutdown_request(sock)
            return
        self._heads[sock] = bytes(entry[1])
        try:
            self.process_request(sock, entry[2])
        except Exception:
            # 线程没能启动时名额不会被 process_request_thread 归还。
            self._heads.pop(sock, None)
            self._slots.release()
            self.shutdown_request(sock)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._heads.pop(request, None)
            self._slots.release()

    def handle_error(self, request, client_address):
        logging.getLogger("exitnode").error(redact("客户端包请求处理失败"))


class PackageHandler(BaseHTTPRequestHandler):
    # 每连接套接字超时(秒):读请求头或写响应卡住超过它就断开该连接。
    timeout = 15

    def setup(self):
        super().setup()
        # 请求头已经由服务线程收齐,这里不再从连接上读。
        self.rfile.close()
        self.rfile = io.BytesIO(self.server._heads.pop(self.connection, b""))

    def log_message(self, format, *args):
        pass

    def _headers(self, code, size=0, content_type="application/octet-stream", content_range=None):
        self.send_response(code)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Accept-Ranges", "bytes")
        if content_range:
            self.send_header("Content-Range", content_range)
        self.end_headers()

    def send_error(self, code, message=None, explain=None):
        # Never include request text, server paths or exception details in a response.
        self._headers(405 if code == 501 else code)

    def do_HEAD(self):
        self._serve(head=True)

    def do_GET(self):
        self._serve(head=False)

    def _serve(self, head):
        path = unquote(self.path)
        if ".." in path or "\\" in path or not path.startswith("/winclient/"):
            self._headers(404)
            return
        name = path[len("/winclient/"):]
        if name != "latest.json" and not FILENAME.fullmatch(name):
            self._headers(404)
            return
        target = self.server.root / name
        sent = False
        try:
            if any(p.is_symlink() for p in (target, *target.parents)):
                self._headers(404)
                return
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_BINARY", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise OSError
                size, start = info.st_size, 0
                range_header = self.headers.get("Range")
                if range_header:
                    match = re.fullmatch(r"bytes=([0-9]+)-", range_header)
                    if not match or len(match[1]) > 20 or int(match[1]) >= size:
                        self._headers(416, content_range=f"bytes */{size}")
                        return
                    start = int(match[1])
                self._headers(206 if range_header else 200, size - start,
                              "application/json" if name.endswith(".json") else "application/octet-stream",
                              f"bytes {start}-{size - 1}/{size}" if range_header else None)
                sent = True
                if head:
                    return
                stream.seek(start)
                remaining = size - start
                while remaining:
                    block = stream.read(min(65536, remaining))
                    if not block:
                        break
                    self.wfile.write(block)
                    remaining -= len(block)
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            self._headers(404)
        except OSError:
            # A broken client connection has no actionable access log.
            if not sent:
                self._headers(404)
            self.close_connection = True


def create_server(bind, port, root, *, max_connections=32, timeout=15, header_timeout=5, max_waiting=256):
    # 派生子类承载本实例的超时,不改全局 PackageHandler.timeout。
    handler = type("PackageHandler", (PackageHandler,), {"timeout": timeout})
    # 等请求头的时限不超过套接字超时。
    server = PackageServer((bind, port), handler, max_connections=max_connections,
                           header_timeout=min(header_timeout, timeout), max_waiting=max_waiting)
    server.root = Path(root).absolute()
    return server


def serve(config):
    logger = logging.getLogger("exitnode")
    with create_server(config.admin.bind, config.admin.port, releases(config)) as server:
        previous = signal.getsignal(signal.SIGTERM)
        def stop(signum, frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        logger.info(redact("客户端包托管服务已启动"))
        try:
            server.serve_forever()
        finally:
            signal.signal(signal.SIGTERM, previous)


def check(config):
    connection = http.client.HTTPConnection(config.admin.bind, config.admin.port, timeout=3)
    try:
        connection.request("GET", "/winclient/latest.json")
        ok = connection.getresponse().status in {200, 404}
    except (OSError, http.client.HTTPException):
        ok = False
    finally:
        connection.close()
    return {"layer": "winclient", "name": "客户端托管服务", "result": "通过" if ok else "失败",
            "reason": "客户端托管服务可用" if ok else "无法连接客户端托管服务"}
