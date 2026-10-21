"""无目录浏览、无访问日志的只读 HTTP 服务。"""

import http.client
import logging
import os
import re
import signal
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from ..log import redact
from .publish import FILENAME, releases


class PackageServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        logging.getLogger("exitnode").error(redact("客户端包请求处理失败"))


class PackageHandler(BaseHTTPRequestHandler):
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


def create_server(bind, port, root):
    server = PackageServer((bind, port), PackageHandler)
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
