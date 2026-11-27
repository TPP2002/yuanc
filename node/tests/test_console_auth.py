import hashlib
import re
import threading

from exitnode.console import auth
from exitnode.console.auth import (
    ALPHABET,
    LoginThrottle,
    Sessions,
    generate_password,
    hash_password,
    normalize,
    verify_password,
)

# 格式正确的固定测试密码：20 位、只用 generate_password 那套字母表。
VALID_PASSWORD = "ABCDE-FGHJK-LMNPQ-RSTUV"


class Clock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def tick(self, seconds):
        self.value += seconds


def test_generated_password_shape():
    first, second = generate_password(), generate_password()
    assert re.fullmatch(r"[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}", first)
    assert re.fullmatch(r"[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}", second)
    assert first != second
    assert set(first.replace("-", "")) <= set(ALPHABET)
    # 去掉分隔符后正好 20 个字符、4 组。
    assert len(first.replace("-", "")) == 20
    assert first.count("-") == 3


def test_hash_and_verify_with_normalization():
    stored = hash_password("k7mq2-abcde-fghjk-lmnpq")
    assert stored.startswith("scrypt$16384$8$1$")
    assert len(stored.split("$")) == 6
    # 去横线、加空格、小写都能验过。
    assert normalize(" K7MQ2 ABCDE FGHJK LMNPQ ") == "K7MQ2ABCDEFGHJKLMNPQ"
    assert verify_password("K7MQ2 ABCDE FGHJK LMNPQ", stored)
    assert verify_password("k7mq2abcde fghjk-lmnpq", stored)
    assert not verify_password("K7MQ2-ABCDE-FGHJK-LMNPX", stored)


def test_verify_rejects_malformed_stored_value():
    good = hash_password(VALID_PASSWORD)
    for value in ("", "scrypt$1$2$3", "scrypt$16384$8$1$bad$bad",
                  "scrypt$16384$8$2$c2FsdA==$aGFzaA==", None, 123, b"bytes"):
        assert verify_password(VALID_PASSWORD, value) is False
    assert verify_password(None, good) is False
    assert verify_password(123, good) is False
    assert verify_password("A" * 201, good) is False
    assert verify_password("A" * 200, good) is False


def test_sessions_expire_idle_and_absolute():
    clock = Clock()
    sessions = Sessions(clock, idle=100, absolute=250)
    token, csrf = sessions.create()
    assert sessions.get(token) == csrf
    clock.tick(60)
    assert sessions.get(token) == csrf
    clock.tick(101)
    assert sessions.get(token) is None
    # 绝对期限：即使每次都在刷新闲置计时，建立超过 250 秒也会失效。
    token, csrf = sessions.create()
    for _ in range(4):
        clock.tick(60)
        assert sessions.get(token) == csrf
    clock.tick(11)
    assert sessions.get(token) is None
    assert sessions.get("never-created") is None


def test_sessions_limit_evicts_oldest():
    clock = Clock()
    sessions = Sessions(clock, limit=2)
    first, _ = sessions.create()
    second, second_csrf = sessions.create()
    third, third_csrf = sessions.create()
    assert sessions.get(first) is None
    assert sessions.get(second) == second_csrf
    assert sessions.get(third) == third_csrf
    sessions.drop(second)
    assert sessions.get(second) is None


def test_sessions_store_only_hashes():
    clock = Clock()
    sessions = Sessions(clock)
    token, _ = sessions.create()
    assert token not in repr(vars(sessions))
    assert token not in repr(sessions.__dict__)
    hash_of_token = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert hash_of_token in repr(sessions.__dict__)


def test_throttle_per_ip_and_global():
    clock = Clock()
    throttle = LoginThrottle(clock, per_ip=2, global_limit=4, window=100)
    assert throttle.attempt("a") is True
    assert throttle.attempt("a") is True
    assert throttle.blocked("a") is True
    assert throttle.blocked("b") is False
    # succeed 只清该 IP，不清全体计数。
    throttle.succeed("a")
    assert throttle.blocked("a") is False
    for ip in ("b", "c", "d", "e"):
        throttle.attempt(ip)
    assert throttle.blocked("other") is True
    clock.tick(101)
    assert throttle.blocked("other") is False


def test_throttle_attempt_counts_before_verify_and_is_atomic():
    clock = Clock()
    throttle = LoginThrottle(clock)
    # 同一个 IP 连占 5 个名额，第 6 次就不让了；succeed 之后又放行。
    assert all(throttle.attempt("192.168.1.7") for _ in range(5))
    assert throttle.attempt("192.168.1.7") is False
    throttle.succeed("192.168.1.7")
    assert throttle.attempt("192.168.1.7") is True

    # 50 个线程同时抢同一个新 IP，正好 5 个成功：判断和登记在同一把锁里。
    crowd = LoginThrottle(clock)
    results = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(50)

    def hit():
        barrier.wait()
        allowed = crowd.attempt("10.1.2.3")
        with results_lock:
            results.append(allowed)

    threads = [threading.Thread(target=hit) for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert len(results) == 50
    assert sum(1 for allowed in results if allowed) == 5


def test_throttle_loopback_exempt_from_global_limit():
    clock = Clock()
    throttle = LoginThrottle(clock)
    for index in range(1, 31):
        assert throttle.attempt(f"192.168.1.{index}") is True
    # 全体上限只数非回环来源：第 31 个局域网地址被挡，回环照旧放行。
    assert throttle.attempt("192.168.1.31") is False
    assert throttle.blocked("192.168.1.31") is True
    assert throttle.blocked("127.0.0.1") is False
    for _ in range(5):
        assert throttle.attempt("127.0.0.1") is True
    # 回环自己也有 5 次的上限。
    assert throttle.attempt("127.0.0.1") is False
    assert throttle.blocked("127.0.0.1") is True
    # 窗口过去后全部恢复。
    clock.tick(901)
    assert throttle.blocked("192.168.1.31") is False
    assert throttle.blocked("127.0.0.1") is False
    assert throttle.attempt("192.168.1.31") is True
    assert throttle.attempt("127.0.0.1") is True


def test_verify_password_rejects_bad_format_without_scrypt(monkeypatch):
    stored = hash_password(VALID_PASSWORD)
    calls = []

    def boom(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("格式不对时不该调用 scrypt")

    monkeypatch.setattr(auth.hashlib, "scrypt", boom)
    # 太短、21 位、含字母 O、含数字 1：都在进 scrypt 之前就被挡掉。
    for bad in ("short", "A" * 21, "ABCDE-FGHJK-LMNPQ-RSTUO", "ABCDE-FGHJK-LMNPQ-RSTU1"):
        assert auth.verify_password(bad, stored) is False
    assert calls == []

    # 格式对但密码错：确实会走 scrypt，算出来不一样就是 False。
    monkeypatch.undo()
    assert auth.verify_password("ABCDE-FGHJK-LMNPQ-RSTUW", stored) is False
