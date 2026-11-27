import hashlib
import re

from exitnode.console.auth import (
    ALPHABET,
    LoginThrottle,
    Sessions,
    generate_password,
    hash_password,
    normalize,
    verify_password,
)


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
    good = hash_password("ABCDE-FGHJK")
    for value in ("", "scrypt$1$2$3", "scrypt$16384$8$1$bad$bad",
                  "scrypt$16384$8$2$c2FsdA==$aGFzaA==", None, 123, b"bytes"):
        assert verify_password("ABCDE-FGHJK", value) is False
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
    throttle.fail("a")
    throttle.fail("a")
    assert throttle.blocked("a") is True
    assert throttle.blocked("b") is False
    # succeed 只清该 IP，不清全体计数。
    throttle.succeed("a")
    assert throttle.blocked("a") is False
    for ip in ("b", "c", "d", "e"):
        throttle.fail(ip)
    assert throttle.blocked("other") is True
    clock.tick(101)
    assert throttle.blocked("other") is False
