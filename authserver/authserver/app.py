"""应用工厂：uvicorn authserver.app:create_app --factory --app-dir authserver。"""

import os
from collections import deque
from threading import Lock

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from .config import load_config
from .db import Database
from .security import hash_token, now
from .service import Problem, Service


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class InviteInput(Input):
    days: int = Field(gt=0, strict=True)
    max_uses: int = Field(default=1, gt=0, strict=True)
    note: str = Field(default="", max_length=2000)


class ExtendInput(Input):
    days: int = Field(gt=0, strict=True)


class DeviceInput(Input):
    platform: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(min_length=1, max_length=512)


class RedeemInput(Input):
    code: str = Field(min_length=1, max_length=64)
    device: DeviceInput
    refresh_token: SecretStr | None = None


class SessionInput(Input):
    refresh_token: SecretStr


class LogoutInput(Input):
    refresh_token: SecretStr | None = None
    session_token: SecretStr | None = None

    @model_validator(mode="after")
    def one_token(self):
        if (self.refresh_token is None) == (self.session_token is None):
            raise ValueError("请提供一种令牌")
        return self


class RateLimiter:
    def __init__(self, limit, clock):
        self.limit = limit
        self.clock = clock
        self.buckets = {}
        self.lock = Lock()

    def check(self, ip, kind):
        stamp = self.clock().timestamp()
        with self.lock:
            for key in list(self.buckets):
                queue = self.buckets[key]
                while queue and queue[0] <= stamp - 3600:
                    queue.popleft()
                if not queue:
                    del self.buckets[key]
            queue = self.buckets.setdefault((ip, kind), deque())
            if len(queue) >= self.limit:
                raise Problem(429, "请求过于频繁，请一小时后重试")
            queue.append(stamp)


def create_app(settings=None, db_path=None, clock=now):
    if settings is None:
        path = os.environ.get("AUTHSERVER_CONFIG")
        if not path:
            raise ValueError("缺少 AUTHSERVER_CONFIG，必须指定安全配置文件")
        settings = load_config(path)
    db = Database(db_path or os.environ.get("AUTHSERVER_DB", "authserver.sqlite3"))
    db.initialize()
    service = Service(db, settings, clock)
    app = FastAPI(title="邀请码鉴权服务", debug=False)
    app.state.service = service
    limiter = RateLimiter(settings.limits.redeem_per_ip_per_hour, clock)
    salt = settings.security.token_salt.get_secret_value()

    def ip(request):
        # Forwarded headers are accepted only by the explicitly configured ASGI server proxy trust.
        return request.client.host if request.client else "unknown"

    def verify(raw, expected):
        import hmac

        if raw is None or not hmac.compare_digest(hash_token(raw, salt), hash_token(expected, salt)):
            raise Problem(401, "认证密钥无效或缺失")

    def admin(key: str | None = Header(default=None, alias="X-Admin-Key")):
        verify(key, settings.security.admin_key.get_secret_value())

    def node(key: str | None = Header(default=None, alias="X-Node-Key")):
        verify(key, settings.security.node_key.get_secret_value())

    def redeem_limit(request: Request):
        limiter.check(ip(request), "redeem")

    def session_limit(request: Request):
        limiter.check(ip(request), "session")

    @app.exception_handler(Problem)
    async def problem_handler(request, error):
        headers = {"Retry-After": "3600"} if error.status == 429 else None
        return JSONResponse({"detail": error.detail}, status_code=error.status, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, error):
        # Never echo pydantic's input field: it may contain a raw refresh/session token.
        return JSONResponse({"detail": "请求参数无效，请检查字段、类型和取值"}, status_code=422)

    @app.middleware("http")
    async def no_cache(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/admin/invites", dependencies=[Depends(admin)])
    def invite(body: InviteInput, request: Request):
        return service.create_invite(body.days, body.max_uses, body.note, ip(request))

    @app.get("/admin/accounts", dependencies=[Depends(admin)])
    def accounts():
        return service.accounts()

    @app.get("/admin/accounts/{account_id}", dependencies=[Depends(admin)])
    def account(account_id: str):
        return service.accounts(account_id)

    @app.post("/admin/accounts/{account_id}/extend", dependencies=[Depends(admin)])
    def extend(account_id: str, body: ExtendInput, request: Request):
        return service.change_account(account_id, "extend", ip(request), body.days)

    @app.post("/admin/accounts/{account_id}/disable", dependencies=[Depends(admin)])
    def disable(account_id: str, request: Request):
        return service.change_account(account_id, "disable", ip(request))

    @app.post("/admin/accounts/{account_id}/enable", dependencies=[Depends(admin)])
    def enable(account_id: str, request: Request):
        return service.change_account(account_id, "enable", ip(request))

    @app.get("/admin/devices", dependencies=[Depends(admin)])
    def devices():
        return service.devices()

    @app.post("/admin/devices/{device_id}/revoke", dependencies=[Depends(admin)])
    def revoke(device_id: str, request: Request):
        return service.revoke(device_id, ip(request))

    @app.get("/admin/audit", dependencies=[Depends(admin)])
    def audits():
        return service.audits()

    @app.post("/client/redeem", dependencies=[Depends(redeem_limit)])
    def redeem(body: RedeemInput, request: Request):
        token = body.refresh_token.get_secret_value() if body.refresh_token is not None else None
        return service.redeem(body.code, body.device, token, ip(request))

    @app.post("/client/session", dependencies=[Depends(session_limit)])
    def session(body: SessionInput, request: Request):
        result = service.session(body.refresh_token.get_secret_value(), ip(request))
        return result

    @app.post("/client/logout")
    def logout(body: LogoutInput, request: Request):
        token = body.session_token if body.session_token is not None else body.refresh_token
        return service.logout(token.get_secret_value(), session=body.session_token is not None,
                              ip=ip(request))

    @app.get("/node/allowed", dependencies=[Depends(node)])
    def allowed():
        return service.allowed()

    @app.post("/node/heartbeat", dependencies=[Depends(node)])
    def heartbeat(request: Request):
        return service.heartbeat(ip(request))

    return app
