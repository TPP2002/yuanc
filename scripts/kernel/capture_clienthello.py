"""仅在本机回环地址采集连接内核与 Chrome 首包，供人工核对。"""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

NOWIN = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
GREASE = {0x0a0a + 0x1010 * index for index in range(16)}


def u16(data, index):
    return int.from_bytes(data[index:index + 2], "big")


def read_hello(connection):
    connection.settimeout(10)
    buffer = b""
    body = b""
    while True:
        while len(buffer) < 5:
            chunk = connection.recv(65536)
            if not chunk:
                raise ValueError("连接在首包完整到达前关闭")
            buffer += chunk
        length = u16(buffer, 3)
        while len(buffer) < 5 + length:
            chunk = connection.recv(65536)
            if not chunk:
                raise ValueError("连接在首包完整到达前关闭")
            buffer += chunk
        body += buffer[5:5 + length]
        buffer = buffer[5 + length:]
        if len(body) >= 4 and len(body) >= 4 + int.from_bytes(body[1:4], "big"):
            return body


def parse(hello):
    if hello[0] != 1:
        raise ValueError("收到的不是客户端握手首包")
    position = 4 + 2 + 32
    position += 1 + hello[position]
    length = u16(hello, position)
    ciphers = [u16(hello, position + 2 + index) for index in range(0, length, 2)]
    position += 2 + length
    position += 1 + hello[position]
    end = position + 2 + u16(hello, position)
    position += 2
    extensions, alpn, groups, shares, signatures, versions = [], [], [], [], [], []
    sni = None
    while position < end:
        kind, length = u16(hello, position), u16(hello, position + 2)
        data = hello[position + 4:position + 4 + length]
        position += 4 + length
        extensions.append(kind)
        if kind == 0:
            sni = data[5:].decode()
        elif kind == 16:
            offset = 2
            while offset < len(data):
                alpn.append(data[offset + 1:offset + 1 + data[offset]].decode())
                offset += 1 + data[offset]
        elif kind == 10:
            groups = [u16(data, 2 + index) for index in range(0, u16(data, 0), 2)]
        elif kind == 51:
            offset = 2
            while offset < len(data):
                shares.append((u16(data, offset), u16(data, offset + 2)))
                offset += 4 + u16(data, offset + 2)
        elif kind == 13:
            signatures = [u16(data, 2 + index) for index in range(0, u16(data, 0), 2)]
        elif kind == 43:
            versions = [u16(data, 1 + index) for index in range(0, data[0], 2)]
    return dict(ciphers=ciphers, exts=extensions, sni=sni, alpn=alpn, groups=groups,
                key_share=shares, sigs=signatures, versions=versions, length=len(hello),
                has_mlkem=0x11ec in groups or any(group == 0x11ec for group, _ in shares),
                has_ech=0xfe0d in extensions)


def without_grease(values):
    return [value for value in values if value not in GREASE]


def short_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()[:12] if value else "000000000000"


def ja4(hello):
    ciphers, extensions = without_grease(hello["ciphers"]), without_grease(hello["exts"])
    version = max(without_grease(hello["versions"]) or [0x0303])
    version_name = {0x0304: "13", 0x0303: "12"}.get(version, "00")
    alpn = hello["alpn"][0] if hello["alpn"] else ""
    protocol = alpn[0] + alpn[-1] if alpn else "00"
    prefix = f"t{version_name}{'d' if hello['sni'] else 'i'}{len(ciphers):02d}{len(extensions):02d}{protocol}"
    cipher_hash = short_hash(",".join(f"{value:04x}" for value in sorted(ciphers)))
    extension_text = ",".join(f"{value:04x}" for value in sorted(
        value for value in extensions if value not in (0, 16)))
    signature_text = ",".join(f"{value:04x}" for value in without_grease(hello["sigs"]))
    extension_hash = short_hash(extension_text + ("_" + signature_text if signature_text else ""))
    return f"{prefix}_{cipher_hash}_{extension_hash}"


def listen():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    return server


def grab(server, output, key):
    server.settimeout(40)
    try:
        connection, _ = server.accept()
        with connection:
            hello = parse(read_hello(connection))
        hello["ja4"] = ja4(hello)
        output[key] = hello
    except (OSError, ValueError, IndexError) as error:
        output[key] = {"error": str(error)}


def capture(sing_box, chrome, work):
    version = subprocess.run([str(sing_box), "version"], capture_output=True, text=True,
                             check=True, creationflags=NOWIN, timeout=30)
    output = {"singbox_version": version.stdout.splitlines()[0]}
    keys = subprocess.run([str(sing_box), "generate", "reality-keypair"],
                          capture_output=True, text=True, check=True,
                          creationflags=NOWIN, timeout=30)
    public = next(line.split(":", 1)[1].strip() for line in keys.stdout.splitlines()
                  if line.lower().startswith("publickey"))
    with listen() as mixed:
        mixed_port = mixed.getsockname()[1]
    with listen() as server:
        config = {
            "log": {"disabled": True},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": mixed_port}],
            "outbounds": [{"type": "vless", "tag": "main", "server": "127.0.0.1",
                           "server_port": server.getsockname()[1],
                           "uuid": "00000000-0000-4000-8000-000000000001",
                           "flow": "xtls-rprx-vision",
                           "tls": {"enabled": True, "server_name": "www.microsoft.com",
                                   "utls": {"enabled": True, "fingerprint": "chrome"},
                                   "reality": {"enabled": True, "public_key": public,
                                               "short_id": "0123456789abcdef"}}}],
        }
        config_path = work / "client.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        worker = threading.Thread(target=grab, args=(server, output, "singbox"))
        with subprocess.Popen([str(sing_box), "run", "-c", str(config_path)],
                              creationflags=NOWIN, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as process:
            worker.start()
            try:
                time.sleep(2)
                with socket.create_connection(("127.0.0.1", mixed_port), timeout=10) as connection:
                    connection.sendall(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
                    time.sleep(1)
                    connection.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            except OSError as error:
                output["singbox_trigger_error"] = str(error)
            finally:
                worker.join()
                process.kill()
    with listen() as server:
        worker = threading.Thread(target=grab, args=(server, output, "chrome_local"))
        with subprocess.Popen([
            str(chrome), "--headless=new", f"--user-data-dir={work / 'profile'}", "--no-first-run",
            "--disable-background-networking", "--disable-component-update",
            "--host-resolver-rules=MAP www.microsoft.com 127.0.0.1",
            f"https://www.microsoft.com:{server.getsockname()[1]}/",
        ], creationflags=NOWIN, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            worker.start()
            try:
                worker.join()
                time.sleep(1)
            finally:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, check=False, creationflags=NOWIN, timeout=30)
                else:
                    process.kill()
    for key in ("singbox", "chrome_local"):
        hello = output.get(key, {})
        for field in ("ciphers", "exts", "groups", "sigs", "versions"):
            if field in hello:
                hello[field] = [f"0x{value:04x}" for value in hello[field]]
        if "key_share" in hello:
            hello["key_share"] = [[f"0x{group:04x}", length]
                                  for group, length in hello["key_share"]]
    output["chrome_version"] = sorted(path.name for path in chrome.parent.iterdir()
                                      if path.name[:1].isdigit())
    return output


def main():
    parser = argparse.ArgumentParser(description="仅在本机回环地址核对两种客户端的握手首包")
    parser.add_argument("--sing-box", type=Path, required=True, help="连接内核可执行文件路径")
    parser.add_argument("--chrome", type=Path, required=True, help="本机浏览器可执行文件路径")
    parser.add_argument("--out", type=Path, required=True, help="核对结果 JSON 保存路径")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="utls-") as directory:
        output = capture(args.sing_box.resolve(), args.chrome.resolve(), Path(directory))
    args.out.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("核对结果已保存")


if __name__ == "__main__":
    main()
