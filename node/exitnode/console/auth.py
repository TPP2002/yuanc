"""管理网页专用的密码、会话与登录限速，只在本进程内存里。"""

import base64
import hashlib
import hmac
import secrets
import threading

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_password():
    """生成 20 个字符、四组五位的密码，只显示一次。"""
    characters = [secrets.choice(ALPHABET) for _ in range(20)]
    groups = ["".join(characters[index:index + 5]) for index in range(0, 20, 5)]
    return "-".join(groups)


def normalize(raw):
    return "".join(raw.split()).replace("-", "").upper()


def hash_password(raw, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(normalize(raw).encode("utf-8"), salt=salt,
                            n=16384, r=8, p=1, dklen=32)
    encoded_salt = base64.b64encode(salt).decode("ascii")
    encoded_digest = base64.b64encode(digest).decode("ascii")
    return f"scrypt$16384$8$1${encoded_salt}${encoded_digest}"


def verify_password(raw, stored):
    try:
        if not isinstance(raw, str) or len(raw) > 200 or not isinstance(stored, str):
            return False
        parts = stored.split("$")
        if len(parts) != 6 or parts[:4] != ["scrypt", "16384", "8", "1"]:
            return False
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
        digest = hashlib.scrypt(normalize(raw).encode("utf-8"), salt=salt,
                                n=16384, r=8, p=1, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


class Sessions:
    """会话只存令牌哈希；闲置与绝对期限都到期就删。"""

    def __init__(self, clock, idle=7200, absolute=43200, limit=20):
        self.clock = clock
        self.idle = idle
        self.absolute = absolute
        self.limit = limit
        self.lock = threading.Lock()
        # 字典保持插入顺序，超限时删最早建立的那个。
        self.items = {}

    def create(self):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = self.clock()
        with self.lock:
            self.items[_hash(token)] = {"csrf": csrf, "created": now, "seen": now}
            while len(self.items) > self.limit:
                del self.items[next(iter(self.items))]
        return token, csrf

    def get(self, token):
        if not isinstance(token, str):
            return None
        key = _hash(token)
        with self.lock:
            item = self.items.get(key)
            if item is None:
                return None
            now = self.clock()
            if now - item["seen"] > self.idle or now - item["created"] > self.absolute:
                del self.items[key]
                return None
            item["seen"] = now
            return item["csrf"]

    def drop(self, token):
        if not isinstance(token, str):
            return
        with self.lock:
            self.items.pop(_hash(token), None)


class LoginThrottle:
    """按来源 IP 与全体两个口径数失败次数。"""

    def __init__(self, clock, per_ip=5, global_limit=30, window=900):
        self.clock = clock
        self.per_ip = per_ip
        self.global_limit = global_limit
        self.window = window
        self.lock = threading.Lock()
        self.failures = {}
        self.total = []

    def _clean(self, now):
        cutoff = now - self.window
        for address in list(self.failures):
            kept = [at for at in self.failures[address] if at > cutoff]
            if kept:
                self.failures[address] = kept
            else:
                del self.failures[address]
        self.total = [at for at in self.total if at > cutoff]

    def blocked(self, ip):
        with self.lock:
            now = self.clock()
            self._clean(now)
            return (len(self.failures.get(ip, [])) >= self.per_ip
                    or len(self.total) >= self.global_limit)

    def fail(self, ip):
        with self.lock:
            now = self.clock()
            self._clean(now)
            self.failures.setdefault(ip, []).append(now)
            self.total.append(now)

    def succeed(self, ip):
        with self.lock:
            self._clean(self.clock())
            self.failures.pop(ip, None)


def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
