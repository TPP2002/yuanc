"""直接访问本地数据库的管理员命令；不启动 HTTP 服务或子进程。"""

import argparse
import json
import os

from .config import load_config
from .db import Database
from .service import Problem, Service


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("必须为正整数")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="邀请码和账号离线管理")
    parser.add_argument("--config", default=os.environ.get("AUTHSERVER_CONFIG"))
    parser.add_argument("--db", default=os.environ.get("AUTHSERVER_DB", "authserver.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    invite = commands.add_parser("invite", help="生成邀请码")
    invite.add_argument("--days", type=positive, required=True)
    invite.add_argument("--uses", type=positive, default=1)
    invite.add_argument("--note", default="")
    commands.add_parser("accounts", help="查看账号")
    commands.add_parser("devices", help="查看设备")
    revoke = commands.add_parser("revoke", help="吊销设备")
    revoke.add_argument("device_id")
    extend = commands.add_parser("extend", help="延期账号")
    extend.add_argument("account_id")
    extend.add_argument("--days", type=positive, required=True)
    args = parser.parse_args(argv)
    if not args.config:
        parser.error("必须提供 --config 或 AUTHSERVER_CONFIG")
    try:
        settings = load_config(args.config)
        db = Database(args.db)
        db.initialize()
        service = Service(db, settings)
        if args.command == "invite":
            result = service.create_invite(args.days, args.uses, args.note)
        elif args.command == "accounts":
            result = service.accounts()
        elif args.command == "devices":
            result = service.devices()
        elif args.command == "revoke":
            result = service.revoke(args.device_id)
        else:
            result = service.change_account(args.account_id, "extend", days=args.days)
    except (ValueError, OSError, Problem) as error:
        parser.exit(1, f"操作失败：{error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
