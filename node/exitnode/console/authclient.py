"""经鉴权服务现有的 /admin/* 接口发码、管账号与设备，不直接碰数据库。"""

import base64
import hashlib
import hmac
import http.client
import json
import ssl
from urllib.parse import quote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

MAX_BODY = 4194304

INVITE_KEYS = ("code", "days", "max_uses", "used", "note", "created_at")
NEW_INVITE_KEYS = ("code", "days", "max_uses", "used", "note")
ACCOUNT_KEYS = ("id", "invite_code", "status", "expires_at", "device_limit", "created_at")
DEVICE_KEYS = ("id", "account_id", "platform", "name", "last_seen", "revoked_at")

INVITE_MODE_OFF = "这台节点没开邀请码模式"
ADMIN_KEY_MISSING = "还没填鉴权服务的管理密钥,请在节点上运行 exitnode console admin-key"
UNREACHABLE = "连不上鉴权服务"
PIN_MISMATCH = "鉴权服务的证书指纹对不上,请核对节点配置里的 authsync.spki_sha256"
KEY_REJECTED = "鉴权服务不认这把管理密钥,请在节点上用 exitnode console admin-key 重新填写"
BAD_RESPONSE = "鉴权服务回的内容不对"


class AuthError(Exception):
    """只带状态、代码与中文说明；绝不带管理密钥、请求体或对方原文。"""

    def __init__(self, status, code, detail):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


class AuthClient:
    def __init__(self, url, spki_sha256, admin_key, transport=None, timeout=10):
        self.url = url
        self.spki_sha256 = spki_sha256
        self.admin_key = admin_key
        self.timeout = timeout
        self.transport = transport or self._default_transport

    def invites(self):
        return _rows(self._call("GET", "/admin/invites"), INVITE_KEYS)

    def create_invite(self, days, max_uses, note):
        body = {"days": days, "max_uses": max_uses, "note": note}
        return _item(self._call("POST", "/admin/invites", body), NEW_INVITE_KEYS)

    def accounts(self):
        return _rows(self._call("GET", "/admin/accounts"), ACCOUNT_KEYS)

    def devices(self):
        return _rows(self._call("GET", "/admin/devices"), DEVICE_KEYS)

    def account_action(self, account_id, action, days=None):
        target = quote(str(account_id), safe="")
        if action == "extend":
            value = self._call("POST", "/admin/accounts/" + target + "/extend",
                               {"days": days})
        elif action in ("disable", "enable"):
            value = self._call("POST", "/admin/accounts/" + target + "/" + action)
        else:
            raise ValueError("未知管理操作")
        return _item(value, ACCOUNT_KEYS)

    def revoke(self, device_id):
        target = quote(str(device_id), safe="")
        value = self._call("POST", "/admin/devices/" + target + "/revoke")
        if not isinstance(value, dict):
            raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)
        return {"device_id": value.get("device_id"), "revoked": value.get("revoked")}

    def _call(self, method, path, payload=None):
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"X-Admin-Key": self.admin_key, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            status, content_type, data = self.transport(method, path, body, headers)
        except AuthError:
            raise
        except (OSError, http.client.HTTPException):
            raise AuthError(502, "authserver_unreachable", UNREACHABLE) from None
        if not isinstance(data, bytes | bytearray) or len(data) > MAX_BODY:
            raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)
        if status == 200:
            try:
                return json.loads(bytes(data).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise AuthError(502, "authserver_bad_response", BAD_RESPONSE) from None
        if status == 404 and (content_type or "").lower().startswith("text/html"):
            raise AuthError(502, "admin_key_rejected", KEY_REJECTED)
        if 400 <= status <= 499:
            try:
                answer = json.loads(bytes(data).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                answer = None
            if isinstance(answer, dict) and isinstance(answer.get("detail"), str):
                raise AuthError(status, "authserver_error", answer["detail"])
        raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)

    def _default_transport(self, method, path, body, headers):
        parts = urlsplit(self.url)
        host = parts.hostname
        port = parts.port
        if parts.scheme == "https":
            port = port or 443
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(host, port, timeout=self.timeout,
                                                     context=context)
            try:
                connection.connect()
                if not _pinned(connection.sock.getpeercert(binary_form=True),
                               self.spki_sha256):
                    # 指纹不符：立刻关闭，此前没有发出任何请求字节。
                    raise AuthError(502, "authserver_pin_mismatch", PIN_MISMATCH)
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                return (response.status, response.getheader("Content-Type", ""),
                        response.read(MAX_BODY + 1))
            finally:
                connection.close()
        connection = http.client.HTTPConnection(host, port or 80, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return (response.status, response.getheader("Content-Type", ""),
                    response.read(MAX_BODY + 1))
        finally:
            connection.close()


def _pinned(der, expected):
    if not der:
        return False
    try:
        certificate = x509.load_der_x509_certificate(der)
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError):
        return False
    actual = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return hmac.compare_digest(actual.encode("utf-8"), str(expected).encode("utf-8"))


def _rows(value, keys):
    if not isinstance(value, list):
        raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)
    rows = []
    for item in value:
        if not isinstance(item, dict):
            raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)
        rows.append({key: item.get(key) for key in keys})
    return rows


def _item(value, keys):
    if not isinstance(value, dict):
        raise AuthError(502, "authserver_bad_response", BAD_RESPONSE)
    return {key: value.get(key) for key in keys}
