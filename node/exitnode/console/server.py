"""管理网页的 HTTP 服务：标准库实现，只读文件并经鉴权服务管理。"""

import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .. import service
from ..log import redact
from . import auth, authclient, snapshot
from .auth import LoginThrottle, Sessions

# 与鉴权服务逐字节相同的通用 404 网页（复制字符串，不导入对方包）。
NOT_FOUND_PAGE = (
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
    "<body><h1>Not Found</h1></body></html>"
)
PASSWORD_NAME = "console-password"
ADMIN_KEY_NAME = "authserver-admin-key"
COOKIE = "yc_console"
LAN_SOURCES = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
               "169.254.0.0/16")
LOCAL_SOURCES = ("127.0.0.0/8",)

SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     "connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; "
     "frame-ancestors 'none'"),
)

CSRF_DETAIL = "页面已过期,请刷新后再试"
BAD_REQUEST = {"detail": "请求格式不对", "code": "bad_request"}
LOGIN_REQUIRED = {"detail": "请先登录", "code": "login_required"}
COOKIE_ATTRIBUTES = "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
CLEAR_COOKIE = COOKIE + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
# Cookie 头最长 4096 个字符；会话令牌只收这套字符表。
COOKIE_HEADER_LIMIT = 4096
COOKIE_VALUE_FORMAT = re.compile(r"[A-Za-z0-9_-]{1,128}")

STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/console.js": ("console.js", "text/javascript; charset=utf-8"),
    "/console.css": ("console.css", "text/css; charset=utf-8"),
}
GET_ROUTES = {"/api/session": "session", "/api/status": "status",
              "/api/directory": "directory"}
POST_ROUTES = {"/api/login": "login", "/api/logout": "logout", "/api/invites": "invites"}
ACCOUNT_ROUTE = re.compile(r"^/api/accounts/([A-Za-z0-9_-]{1,64})/(extend|disable|enable)$")
DEVICE_ROUTE = re.compile(r"^/api/devices/([A-Za-z0-9_-]{1,64})/revoke$")


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, max_connections=32, **kwargs):
        # 先建好槽位再监听：父类构造会开始监听，但不会处理连接。
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            # 超过并发上限：直接关连接，不写任何字节。
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        logging.getLogger("exitnode").error(redact("管理网页请求处理失败"))


class ConsoleHandler(BaseHTTPRequestHandler):
    # 每连接套接字超时（秒）：读头或写响应卡住超过它就断开。
    timeout = 15

    def log_message(self, format, *args):
        pass

    def send_response(self, code, message=None):
        # 不发 Server 头，只发状态行与日期。
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None, explain=None):
        self._decoy()

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._decoy()

    do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = do_PUT

    def _handle(self, method):
        path = urlsplit(self.path).path
        try:
            if not self._allowed_source() or not self._allowed_host():
                return self._decoy()
            route = self._route(method, path)
            if route is None:
                return self._decoy()
            kind, name, extra = route
            if kind == "static":
                return self._static(name)
            return self._api(method, name, extra)
        except Exception:
            logging.getLogger("exitnode").error(redact("管理网页请求处理失败"))
            if path.startswith("/api/"):
                self._json(500, {"detail": "管理网页出错了,请稍后再试", "code": "internal"})
            else:
                self._decoy()

    def _route(self, method, path):
        if method == "GET" and path in STATIC_ROUTES:
            return ("static", STATIC_ROUTES[path], ())
        if method == "GET" and path in GET_ROUTES:
            return ("api", GET_ROUTES[path], ())
        if method == "POST":
            if path in POST_ROUTES:
                return ("api", POST_ROUTES[path], ())
            match = ACCOUNT_ROUTE.fullmatch(path)
            if match:
                return ("api", "account", (match[1], match[2]))
            match = DEVICE_ROUTE.fullmatch(path)
            if match:
                return ("api", "device", (match[1],))
        return None

    def _allowed_source(self):
        try:
            address = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return any(address in network for network in self.server.sources)

    def _allowed_host(self):
        value = self.headers.get("Host")
        if not value:
            return False
        host, separator, port = value.partition(":")
        if separator and (not port.isdigit() or len(port) > 5
                          or not 1 <= int(port) <= 65535):
            return False
        if host.lower() == "localhost":
            return True
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return True

    def _token(self):
        header = self.headers.get("Cookie")
        if not header or len(header) > COOKIE_HEADER_LIMIT:
            # 没带、或者长得离谱，一律当没带。
            return None
        for segment in header.split(";"):
            item = segment.strip()
            if not item.startswith(COOKIE + "="):
                continue
            value = item[len(COOKIE) + 1:]
            # 值只认令牌那套字符，别的写法一律当没带；取第一段就停。
            return value if COOKIE_VALUE_FORMAT.fullmatch(value) else None
        return None

    def _send(self, status, body, content_type, cookie=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", content_type)
        for key, value in SECURITY_HEADERS:
            self.send_header(key, value)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, value, cookie=None):
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", cookie)

    def _decoy(self):
        body = NOT_FOUND_PAGE.encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        # 通用 404 回完就断开，不再搭理这条连接上的后续请求。
        self.close_connection = True
        self._drain_input()

    def _drain_input(self):
        # 断开前把对方已经到了的请求字节读掉：连接里留着没读的字节，
        # 系统会直接给对端回 RST，把刚写好的 404 一起冲掉。
        try:
            self.wfile.flush()
            self.connection.settimeout(0.2)
            while self.rfile.read1(65536):
                pass
        except OSError:
            pass

    def _static(self, target):
        name, content_type = target
        try:
            data = (self.server.static_dir / name).read_bytes()
        except OSError:
            return self._decoy()
        self._send(200, data, content_type)

    def _api(self, method, name, extra):
        # POST 第一件事就是把请求体读完，排在登录、来源页、防伪头、限流各道检查之前：
        # 被拒的请求也得等对端把请求体发完，否则先回话再关连接会把应答冲掉。
        if method == "POST" and not self._take_body():
            # 请求体没读完（超时或对方重置）：这条连接不回任何应答，直接结束。
            return
        token = self._token()
        csrf = None if token is None else self.server.sessions.get(token)
        if name not in {"session", "login"} and csrf is None:
            return self._json(401, LOGIN_REQUIRED)
        if method == "POST":
            origin = self.headers.get("Origin")
            if origin is not None and origin != "http://" + self.headers.get("Host", ""):
                return self._json(403, {"detail": CSRF_DETAIL, "code": "csrf"})
            if name != "login":
                sent = self.headers.get("X-Console-CSRF")
                if not sent or not hmac.compare_digest(sent.encode("utf-8"),
                                                       csrf.encode("utf-8")):
                    return self._json(403, {"detail": CSRF_DETAIL, "code": "csrf"})
        if name == "session":
            if csrf is None:
                return self._json(200, {"logged_in": False})
            return self._json(200, self._logged_in(csrf))
        if name == "login":
            return self._login()
        if name == "logout":
            return self._logout(token)
        if name == "status":
            return self._json(200, snapshot.load(self.server.snapshot_path,
                                                 self.server.clock()))
        if name == "directory":
            return self._manage(lambda client: {"invites": client.invites(),
                                                "accounts": client.accounts(),
                                                "devices": client.devices()})
        if name == "invites":
            return self._create_invite()
        if name == "account":
            return self._account(extra)
        return self._revoke(extra[0])

    def _logged_in(self, csrf):
        return {"logged_in": True, "csrf": csrf,
                "node_name": self.server.config.node.name,
                "invite_mode": bool(self.server.config.authsync.enabled)}

    def _login(self):
        ip = self.client_address[0]
        # 第 1 步：先占名额再看别的；这次尝试一律先按失败记。
        if not self.server.throttle.attempt(ip):
            return self._json(429, {"detail": "登录失败次数太多,请 15 分钟后再试",
                                    "code": "throttled"})
        body = self._read_body({"password"})
        if body is None:
            return
        stored = (self.server.credentials or {}).get("password")
        if not stored:
            return self._json(409, {
                "detail": "还没设管理密码,请在节点上运行 exitnode console password",
                "code": "password_missing"})
        password = body.get("password")
        if not isinstance(password, str):
            return self._json(422, BAD_REQUEST)
        # 验密码一次最多两个：每次 scrypt 要吃 16 MiB 内存，32 个并发会把单元撑爆。
        if not self.server.password_slots.acquire(blocking=False):
            return self._json(429, {"detail": "登录失败次数太多,请 15 分钟后再试",
                                    "code": "throttled"})
        try:
            passed = auth.verify_password(password, stored)
        finally:
            self.server.password_slots.release()
        if not passed:
            # 失败已在上面 attempt 时记下了，这里不再记一次。
            return self._json(401, {"detail": "密码不对", "code": "wrong_password"})
        self.server.throttle.succeed(ip)
        token, csrf = self.server.sessions.create()
        return self._json(200, self._logged_in(csrf),
                          COOKIE + "=" + token + COOKIE_ATTRIBUTES)

    def _logout(self, token):
        body = self._read_body(())
        if body is None:
            return
        if token is not None:
            self.server.sessions.drop(token)
        return self._json(200, {"logged_in": False}, CLEAR_COOKIE)

    def _take_body(self):
        # 走到接口层的 POST 先把请求体读完再做判断：先回话再关连接的话，
        # 对端还没写完的请求体会落到已关的连接上，系统回 RST，把刚写的应答一起冲掉；
        # 所以这里宁可多等一会儿请求体，也不靠「回完再等一小会儿」碰运气。
        self.body = b""
        self.body_length = 0
        value = self.headers.get("Content-Length")
        if value is None:
            return True
        try:
            length = int(value)
        except ValueError:
            # 声明长度读不了：不读套接字，后面按现有规则回 422 并断开。
            self.body_length = None
            return True
        if length < 0 or length > 16384:
            self.body_length = None
            return True
        if length == 0:
            return True
        self.body_length = length
        try:
            # 连接提前结束时读到多少算多少，后面按格式不对处理。
            self.body = self.rfile.read(length)
        except OSError:
            # 套接字超时（含 TimeoutError）或对方重置：这条连接不回任何应答，
            # 直接断开；不记错误日志，当成对端自己放弃了这条连接。
            self.close_connection = True
            return False
        return True

    def _read_body(self, allowed):
        # 只判断并解析 _take_body 存下的内容，不再碰套接字。
        if self.body_length is None:
            self.close_connection = True
            self._json(422, BAD_REQUEST)
            return None
        if self.body_length == 0:
            return {}
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            self._json(422, BAD_REQUEST)
            return None
        try:
            body = json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._json(422, BAD_REQUEST)
            return None
        if not isinstance(body, dict) or set(body) - set(allowed):
            self._json(422, BAD_REQUEST)
            return None
        return body

    def _manage(self, action):
        client = self.server.client
        if client is None:
            if not self.server.config.authsync.enabled:
                return self._json(409, {"detail": authclient.INVITE_MODE_OFF,
                                        "code": "invite_mode_off"})
            return self._json(409, {"detail": authclient.ADMIN_KEY_MISSING,
                                    "code": "admin_key_missing"})
        try:
            value = action(client)
        except authclient.AuthError as error:
            return self._json(error.status, {"detail": error.detail, "code": error.code})
        return self._json(200, value)

    def _create_invite(self):
        body = self._read_body({"days", "max_uses", "note"})
        if body is None:
            return
        days = body.get("days")
        if type(days) is not int or not 1 <= days <= 3650:
            return self._json(422, {"detail": "天数要填 1 到 3650 的整数",
                                    "code": "bad_request"})
        max_uses = body.get("max_uses")
        if type(max_uses) is not int or not 1 <= max_uses <= 100:
            return self._json(422, {"detail": "人数要填 1 到 100 的整数",
                                    "code": "bad_request"})
        note = body.get("note", "")
        if (not isinstance(note, str)
                or any(unicodedata.category(item) == "Cc" for item in note)
                or len(note.strip()) > 200):
            return self._json(422, {"detail": "备注最多 200 个字,不能换行",
                                    "code": "bad_request"})
        note = note.strip()
        return self._manage(lambda client: {
            "invite": client.create_invite(days, max_uses, note)})

    def _account(self, extra):
        account_id, action = extra
        if action == "extend":
            body = self._read_body({"days"})
            if body is None:
                return
            days = body.get("days")
            if type(days) is not int or not 1 <= days <= 3650:
                return self._json(422, {"detail": "天数要填 1 到 3650 的整数",
                                        "code": "bad_request"})
            return self._manage(lambda client: {
                "account": client.account_action(account_id, action, days)})
        body = self._read_body(())
        if body is None:
            return
        return self._manage(lambda client: {
            "account": client.account_action(account_id, action)})

    def _revoke(self, device_id):
        body = self._read_body(())
        if body is None:
            return
        return self._manage(lambda client: client.revoke(device_id))


def create_server(config, *, credentials, static_dir=None, snapshot_path=None, client=None,
                  clock=time.time, sources=None, bind=None, port=None):
    if static_dir is None:
        static_dir = Path(__file__).parent / "static"
    if snapshot_path is None:
        snapshot_path = snapshot.path(config)
    if client is None and config.authsync.enabled:
        admin_key = (credentials or {}).get("admin_key")
        if admin_key:
            client = authclient.AuthClient(config.authsync.url,
                                           config.authsync.spki_sha256, admin_key)
    if sources is None:
        sources = LAN_SOURCES if config.console.lan else LOCAL_SOURCES
    if bind is None:
        bind = "0.0.0.0" if config.console.lan else "127.0.0.1"
    server = ConsoleServer((bind, config.console.port if port is None else port),
                           ConsoleHandler)
    server.config = config
    server.credentials = credentials or {}
    server.static_dir = Path(static_dir)
    server.snapshot_path = str(snapshot_path)
    server.client = client
    server.clock = clock
    server.sources = tuple(ipaddress.ip_network(item) for item in sources)
    server.sessions = Sessions(clock)
    server.throttle = LoginThrottle(clock)
    # 同时最多两个请求在验密码：scrypt 一次要 16 MiB，多了会把单元撑爆。
    server.password_slots = threading.BoundedSemaphore(2)
    return server


def load_credentials(environ=None):
    environ = os.environ if environ is None else environ
    directory = environ.get("CREDENTIALS_DIRECTORY") or service.SECRETS

    def read(name):
        try:
            return Path(directory, name).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None

    password = read(PASSWORD_NAME)
    if password is not None:
        password = password.strip()
        if not password.startswith("scrypt$"):
            password = None
    admin_key = read(ADMIN_KEY_NAME)
    if admin_key is not None:
        admin_key = admin_key.strip()
        if (not admin_key or len(admin_key) > 512
                or any(unicodedata.category(item) == "Cc" for item in admin_key)):
            admin_key = None
    return {"password": password, "admin_key": admin_key}


def serve(config):
    logger = logging.getLogger("exitnode")
    with create_server(config, credentials=load_credentials()) as server:
        previous = signal.getsignal(signal.SIGTERM)

        def stop(signum, frame):
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        logger.info(redact("管理网页已启动"))
        try:
            server.serve_forever()
        finally:
            signal.signal(signal.SIGTERM, previous)


def check(config):
    connection = http.client.HTTPConnection("127.0.0.1", config.console.port, timeout=3)
    try:
        connection.request("GET", "/api/session",
                           headers={"Host": "127.0.0.1:" + str(config.console.port)})
        response = connection.getresponse()
        value = json.loads(response.read(65536).decode("utf-8"))
        ok = response.status == 200 and isinstance(value, dict) and "logged_in" in value
    except (OSError, http.client.HTTPException, ValueError, UnicodeDecodeError):
        ok = False
    finally:
        connection.close()
    return {"layer": "console", "name": "管理网页", "result": "通过" if ok else "失败",
            "reason": "管理网页可以打开" if ok else "管理网页打不开"}
