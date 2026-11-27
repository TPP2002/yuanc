"""确认包里的静态页面能被默认配置服务出来。"""

import http.client
import threading
from pathlib import Path

from exitnode.config import load
from exitnode.console import server as console_server
from exitnode.runner import FakeRunner
from test_cli import TEXT


def test_package_static_files_are_served():
    config = load("/config", FakeRunner(files={"/config": TEXT}))
    # 示例配置默认开启管理网页，页面按这份配置由包里的 static 目录服务。
    assert config.console.enabled is True
    server = console_server.create_server(config, credentials={}, bind="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        static = Path(console_server.__file__).parent / "static"
        for path, name, content_type in (("/", "index.html", "text/html"),
                                         ("/console.js", "console.js", "text/javascript"),
                                         ("/console.css", "console.css", "text/css")):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1],
                                                    timeout=5)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                body = response.read()
                assert response.status == 200
                assert body == (static / name).read_bytes()
                assert response.getheader("Content-Type").startswith(content_type)
            finally:
                connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
