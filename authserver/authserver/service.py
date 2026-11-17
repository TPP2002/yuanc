"""HTTP 与离线管理共用业务事务。"""

from datetime import datetime, timedelta
from uuid import uuid4

from .db import audit
from .security import hash_token, hy2_password, iso, new_invite_code, new_token, now


class Problem(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def required(row, detail):
    if row is None:
        raise Problem(404, detail)
    return row


def add_days(value, days):
    try:
        return iso(datetime.fromisoformat(value) + timedelta(days=days))
    except OverflowError:
        raise Problem(422, "期限超出支持的日期范围") from None


def extend_from(value, at, days):
    """从旧到期日与当前时间中较晚的一个起算,叠加天数。"""
    return add_days(value if value > at else at, days)


class Service:
    def __init__(self, db, settings, clock=now):
        self.db = db
        self.settings = settings
        self.clock = clock
        self.salt = settings.security.token_salt.get_secret_value()

    def time(self):
        return iso(self.clock())

    def create_invite(self, days, max_uses=1, note="", ip="local"):
        if days < 1 or max_uses < 1:
            raise Problem(422, "天数和次数必须为正整数")
        at = self.time()
        add_days(at, days)
        code = new_invite_code()
        with self.db.transaction(write=True) as conn:
            conn.execute(
                "INSERT INTO invites VALUES (?, ?, ?, 0, ?, 'admin', ?)",
                (code, days, max_uses, note, at),
            )
            audit(conn, "admin", "invite.create", at, ip)
        return {"code": code, "days": days, "max_uses": max_uses, "used": 0, "note": note}

    def accounts(self, account_id=None):
        with self.db.transaction() as conn:
            if account_id is not None:
                row = required(conn.execute(
                    "SELECT * FROM accounts WHERE id = ?", (account_id,)
                ).fetchone(), "账号不存在")
                result = dict(row)
                result["devices"] = self._devices(conn, account_id)
                return result
            return [dict(row) for row in conn.execute("SELECT * FROM accounts ORDER BY id")]

    @staticmethod
    def _devices(conn, account_id=None):
        sql = """SELECT id, account_id, platform, name, last_seen, revoked_at FROM devices"""
        params = ()
        if account_id is not None:
            sql += " WHERE account_id = ?"
            params = (account_id,)
        return [dict(row) for row in conn.execute(sql + " ORDER BY id", params)]

    def devices(self):
        with self.db.transaction() as conn:
            return self._devices(conn)

    def audits(self, limit=2000):
        with self.db.transaction() as conn:
            rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(row) for row in reversed(rows)]

    def change_account(self, account_id, action, ip="local", days=None):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            account = required(conn.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone(), "账号不存在")
            if action == "extend":
                if days is None or days < 1:
                    raise Problem(422, "天数必须为正整数")
                conn.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
                             (extend_from(account["expires_at"], at, days), account_id))
            elif action in ("disable", "enable"):
                conn.execute("UPDATE accounts SET status = ? WHERE id = ?",
                             ("disabled" if action == "disable" else "active", account_id))
                if action == "disable":
                    conn.execute("""DELETE FROM sessions WHERE device_id IN
                                    (SELECT id FROM devices WHERE account_id = ?)""", (account_id,))
            else:
                raise ValueError("未知管理操作")
            audit(conn, "admin", f"account.{action}:{account_id}", at, ip)
            return dict(conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())

    def revoke(self, device_id, ip="local"):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            required(conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone(),
                     "设备不存在")
            conn.execute("UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?",
                         (at, device_id))
            conn.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
            audit(conn, "admin", f"device.revoke:{device_id}", at, ip)
        return {"device_id": device_id, "revoked": True}

    def _by_refresh(self, conn, raw):
        row = conn.execute("SELECT * FROM devices WHERE refresh_token_hash = ?",
                           (hash_token(raw, self.salt),)).fetchone()
        if row is None:
            raise Problem(401, "令牌无效，请重新登录")
        return row

    def _check(self, conn, device, at, *, renewal=False):
        account = conn.execute("SELECT * FROM accounts WHERE id = ?",
                               (device["account_id"],)).fetchone()
        if account["status"] != "active":
            raise Problem(403, "账号已停用，请联系管理员")
        if device["revoked_at"] is not None:
            raise Problem(423, "设备已吊销，请联系管理员")
        if not renewal and account["expires_at"] <= at:
            raise Problem(410, "账号已到期，请兑换邀请码续期")
        count = conn.execute("""SELECT COUNT(*) FROM devices
                                WHERE account_id = ? AND revoked_at IS NULL""",
                             (account["id"],)).fetchone()[0]
        if count > account["device_limit"]:
            raise Problem(409, "设备数量超过上限，请联系管理员")
        return account

    def redeem(self, code, device_info, refresh_token=None, ip="local"):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            invite = required(conn.execute("SELECT * FROM invites WHERE code = ?",
                                           (code,)).fetchone(), "邀请码不存在")
            device = None
            account = None
            if refresh_token is not None:
                source = self._by_refresh(conn, refresh_token)
                account = self._check(conn, source, at, renewal=True)
                device = conn.execute("""SELECT * FROM devices
                    WHERE account_id = ? AND fingerprint = ?""",
                    (account["id"], device_info.fingerprint)).fetchone()
            else:
                # A retry of initial redemption is identified by its code + fingerprint.
                device = conn.execute("""SELECT d.* FROM devices d JOIN accounts a
                    ON a.id = d.account_id WHERE a.invite_code = ? AND d.fingerprint = ?""",
                    (code, device_info.fingerprint)).fetchone()
                if device is not None:
                    account = self._check(conn, device, at)
            if device is not None and device["revoked_at"] is not None:
                raise Problem(423, "设备已吊销，请联系管理员")
            receipt = None if device is None else conn.execute(
                "SELECT id FROM audit WHERE who = ? AND what = ?",
                ("device:" + device["id"], "invite.redeem:" + code),
            ).fetchone()
            if receipt is None:
                if invite["used"] >= invite["max_uses"]:
                    raise Problem(409, "邀请码使用次数已用完")
                if account is None:
                    account_id = str(uuid4())
                    expires = add_days(at, invite["days"])
                    conn.execute("INSERT INTO accounts VALUES (?, ?, 'active', ?, ?, ?)",
                                 (account_id, code, expires,
                                  self.settings.limits.default_device_limit, at))
                    account = conn.execute("SELECT * FROM accounts WHERE id = ?",
                                           (account_id,)).fetchone()
                else:
                    expires = extend_from(account["expires_at"], at, invite["days"])
                    conn.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
                                 (expires, account["id"]))
                conn.execute("UPDATE invites SET used = used + 1 WHERE code = ?", (code,))
            else:
                expires = account["expires_at"]
            if device is None:
                count = conn.execute("""SELECT COUNT(*) FROM devices
                    WHERE account_id = ? AND revoked_at IS NULL""", (account["id"],)).fetchone()[0]
                if count >= account["device_limit"]:
                    raise Problem(409, "设备数量已达上限，请联系管理员")
                device_id = str(uuid4())
                raw = new_token()
                conn.execute("""INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                             (device_id, account["id"], str(uuid4()), device_info.platform,
                              device_info.name, device_info.fingerprint,
                              hash_token(raw, self.salt), at))
            else:
                device_id = device["id"]
                same_token = refresh_token and hash_token(refresh_token, self.salt) == (
                    device["refresh_token_hash"])
                raw = refresh_token if same_token else new_token()
                conn.execute("""UPDATE devices SET refresh_token_hash = ?, last_seen = ?,
                    platform = ?, name = ? WHERE id = ?""",
                    (hash_token(raw, self.salt), at, device_info.platform, device_info.name, device_id))
                if not same_token:
                    conn.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
            audit(conn, "device:" + device_id,
                  ("invite.redeem:" if receipt is None else "invite.retry:") + code, at, ip)
            return {"account_id": account["id"], "expires_at": expires,
                    "refresh_token": raw, "device_id": device_id}

    def session(self, refresh_token, ip="local"):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            device = self._by_refresh(conn, refresh_token)
            account = self._check(conn, device, at)
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (at,))
            raw = new_token()
            expires = iso(datetime.fromisoformat(at) + timedelta(
                hours=self.settings.limits.session_hours))
            conn.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                         (hash_token(raw, self.salt), device["id"], expires))
            conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (at, device["id"]))
            audit(conn, "device:" + device["id"], "session.create", at, ip)
            node = self.settings.node.model_dump()
            # Node excludes the local certificate path and exports the loaded PEM lines.
            node.update(uuid=device["uuid"], hy2_password=hy2_password(device["uuid"], self.salt))
            return {"session_token": raw, "session_expires_at": expires,
                    "account_expires_at": account["expires_at"], "node": node}

    def authenticate_session(self, raw):
        at = self.time()
        with self.db.transaction() as conn:
            return dict(self._session_device(conn, raw, at))

    def _session_device(self, conn, raw, at):
        session = conn.execute("SELECT * FROM sessions WHERE token_hash = ?",
                               (hash_token(raw, self.salt),)).fetchone()
        if session is None or session["expires_at"] <= at:
            raise Problem(401, "会话无效或已过期，请重新登录")
        device = conn.execute("SELECT * FROM devices WHERE id = ?",
                              (session["device_id"],)).fetchone()
        self._check(conn, device, at)
        return device

    def logout(self, raw, *, session=False, ip="local"):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            device = (self._session_device(conn, raw, at) if session
                      else self._by_refresh(conn, raw))
            conn.execute("UPDATE devices SET refresh_token_hash = NULL WHERE id = ?",
                         (device["id"],))
            conn.execute("DELETE FROM sessions WHERE device_id = ?", (device["id"],))
            audit(conn, "device:" + device["id"], "client.logout", at, ip)
        return {"logged_out": True}

    def allowed(self):
        at = self.time()
        with self.db.transaction() as conn:
            rows = conn.execute("""SELECT d.uuid, d.account_id, d.id AS device_id
                FROM devices d JOIN accounts a ON d.account_id = a.id
                WHERE a.status = 'active' AND a.expires_at > ? AND d.revoked_at IS NULL
                  AND d.refresh_token_hash IS NOT NULL
                ORDER BY d.id""", (at,)).fetchall()
        allowed = [{**dict(row), "hy2_password": hy2_password(row["uuid"], self.salt)} for row in rows]
        # Version tracks effective content, including expiry without a database write.
        import hashlib
        import json

        version = hashlib.sha256(json.dumps(allowed, sort_keys=True).encode()).hexdigest()
        return {"version": version, "allowed": allowed}

    def heartbeat(self, ip="local"):
        at = self.time()
        with self.db.transaction(write=True) as conn:
            previous = conn.execute("SELECT ip FROM node_heartbeat WHERE id = 1").fetchone()
            conn.execute("""INSERT INTO node_heartbeat VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET at = excluded.at, ip = excluded.ip""", (at, ip))
            if previous is None or previous["ip"] != ip:
                audit(conn, "node", "node.heartbeat", at, ip)
        return {"at": at}
