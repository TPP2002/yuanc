"""日志和诊断共用脱敏，文件写入仍经过 Runner。"""

import logging
import re

FIELD = re.compile(
    r'''(?i)((?:[\w-]*(?:token|uuid|key|password|secret)[\w-]*)["']?\s*[:=]\s*["']?)([^\s,"';}]+)'''
)
UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def redact(text):
    text = FIELD.sub(lambda m: m[1] + m[2][:4] + "***", str(text))
    return UUID.sub(lambda m: m[0][:4] + "***", text)


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))


class RunnerLogHandler(logging.Handler):
    def __init__(self, runner, directory, max_bytes=262144):
        super().__init__()
        self.runner = runner
        self.path = directory.rstrip("/") + "/exitnode.log"
        self.max_bytes = max_bytes
        runner.mkdir(directory)

    def emit(self, record):
        text = self.format(record) + "\n"
        old = self.runner.read_file(self.path) if self.runner.exists(self.path) else ""
        if len((old + text).encode("utf-8")) > self.max_bytes:
            self.runner.write_file(self.path + ".1", old, 0o600)
            old = ""
        self.runner.write_file(self.path, old + text, 0o600)


def configure(runner, directory=None, level="INFO"):
    logger = logging.getLogger("exitnode")
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(level)
    handler = RunnerLogHandler(runner, directory) if directory else logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger
