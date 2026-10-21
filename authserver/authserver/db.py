"""短连接、显式事务；写事务先占写锁以串行化额度与设备上限检查。"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .models import SCHEMA


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)

    @contextmanager
    def transaction(self, *, write=False):
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        with self.transaction(write=True) as connection:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)


def audit(connection, who, what, at, ip):
    connection.execute(
        "INSERT INTO audit(who, what, at, ip) VALUES (?, ?, ?, ?)",
        (who, what, at, ip),
    )
