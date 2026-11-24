"""Loopback-only JumpServer catalog and SSH emulator for the job benchmark.

The emulator parses the bridge's framing and returns canned records. It never
runs an SSH command or spawns a shell.
"""
from collections import Counter
from contextlib import contextmanager
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import secrets
import socket
import threading
import time

from mcp_baseline import encode


class LoopbackJobs:
    def __init__(self, root, case):
        from paramiko import RSAKey

        self.case = case
        self.assets = {row["id"]: row for row in case["targets"]}
        self.key = RSAKey.generate(2048)
        self.password = secrets.token_urlsafe()
        self.token = secrets.token_urlsafe()
        self.jobs = {}
        self.counts = Counter()
        self.errors = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.transports = []
        self.threads = []
        self.ssh = socket.socket()
        self.ssh.bind(("127.0.0.1", 0))
        self.ssh.listen()
        self.ssh.settimeout(.2)
        ssh_port = self.ssh.getsockname()[1]
        self.catalog = ThreadingHTTPServer(("127.0.0.1", 0), self.catalog_handler())
        known_hosts = root / "known_hosts"
        known_hosts.write_text(
            f"[127.0.0.1]:{ssh_port} {self.key.get_name()} {self.key.get_base64()}\n"
        )
        self.config = root / "config.toml"
        self.config.write_text(
            f'[bastion]\nurl = "http://127.0.0.1:{self.catalog.server_port}"\n'
            f'ssh_port = {ssh_port}\nlogin_user = "fixture"\n'
            f'ssh_password = "{self.password}"\nsession_token = "{self.token}"\n'
            f'[bridge]\nknown_hosts = "{known_hosts}"\nssh_host = "127.0.0.1"\n'
        )
        self.config.chmod(0o600)

    def catalog_handler(self):
        fixture = self

        class Catalog(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if fixture.token not in self.headers.get("Authorization", "").split():
                    self.send_error(401)
                    return
                base = "/api/v1/perms/users/my/assets"
                path = self.path.split("?", 1)[0].rstrip("/")
                if path == base:
                    rows = [{"id": aid, "name": row["name"]}
                            for aid, row in fixture.assets.items()]
                    result = {"count": len(rows), "next": None, "results": rows}
                    fixture.count("catalog_list")
                elif path.startswith(base + "/") and path[len(base) + 1:] in fixture.assets:
                    aid = path[len(base) + 1:]
                    name = fixture.assets[aid]["name"]
                    result = {"id": aid, "name": name, "address": name,
                              "is_active": True,
                              "permed_accounts": [{"username": "fixture", "has_secret": True}],
                              "permed_protocols": [{"name": "ssh"}]}
                    fixture.count("catalog_asset")
                else:
                    self.send_error(404)
                    return
                body = encode(result)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Catalog

    def count(self, kind):
        with self.lock:
            self.counts[kind] += 1

    def ssh_accept(self):
        while not self.stop.is_set():
            try:
                sock, _ = self.ssh.accept()
            except socket.timeout:
                continue
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.thread(self.ssh_connection, sock)

    def thread(self, fn, *args):
        t = threading.Thread(target=fn, args=args, daemon=True)
        self.threads.append(t)
        t.start()

    def ssh_connection(self, sock):
        import paramiko

        fixture = self

        class Server(paramiko.ServerInterface):
            asset = None

            def check_auth_password(self, user, password):
                fields = set(user.split("#"))
                self.asset = next((aid for aid, row in fixture.assets.items()
                                   if aid in fields or row["name"] in fields), None)
                if self.asset is not None and password == fixture.password:
                    return paramiko.AUTH_SUCCESSFUL
                self.asset = None
                return paramiko.AUTH_FAILED

            def check_channel_request(self, kind, _):
                return (paramiko.OPEN_SUCCEEDED if kind == "session" and self.asset
                        else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

            def check_channel_exec_request(self, channel, _command):
                fixture.thread(fixture.ssh_command, channel, self.asset)
                return True

        with paramiko.Transport(sock) as transport:
            self.transports.append(transport)
            transport.add_server_key(self.key)
            transport.start_server(server=Server())
            keep = []
            while transport.is_active() and not self.stop.is_set():
                channel = transport.accept(.1)
                if channel is not None:
                    keep.append(channel)
                keep = [c for c in keep if not c.closed]

    def ssh_command(self, channel, asset):
        try:
            channel.settimeout(5)
            ready = bytearray()
            while not ready.endswith(b"\n"):
                chunk = channel.recv(1024)
                if not chunk or len(ready) + len(chunk) > 1024:
                    raise ValueError("invalid fixture READY packet")
                ready.extend(chunk)
            nonce = re.search(rb"READY([0-9a-f]{32})", ready).group(1)
            self.marker(channel, b"\x1eREADY" + nonce + b"\x1f")
            packet = bytearray()
            while chunk := channel.recv(65536):
                packet.extend(chunk)
                if len(packet) > 32768:
                    raise ValueError("oversize fixture operation")
            nonce = re.search(rb"START([0-9a-f]{32})", packet).group(1)
            self.marker(channel, b"\x1eSTART" + nonce + b"\x1f")
            output = self.canned_reply(asset, packet)
            channel.sendall(output)
            self.marker(channel, b"\x1eEND" + nonce + b":0\x1f")
            channel.send_exit_status(0)
            channel.shutdown_write()
        except Exception as error:
            with self.lock:
                self.errors.append(str(error))
        finally:
            channel.close()

    @staticmethod
    def marker(channel, marker):
        channel.sendall(marker)
        channel.sendall_stderr(marker)

    def canned_reply(self, asset, packet):
        # These are bridge-generated script shapes, interpreted only as tags.
        ids = set(re.findall(rb"jobs/([0-9a-f]{8})(?![0-9a-f])", packet))
        if len(ids) != 1:
            raise ValueError(f"expected exactly one synthetic job ID, got {ids!r}")
        job = asset, next(iter(ids))
        row = self.assets[asset]
        log = row["log"].encode()
        with self.lock:
            if b"JMS_RUNNER_EOF" in packet and self.case["command"].encode() in packet:
                self.counts["ssh_launch"] += 1
                if job in self.jobs:
                    raise ValueError("duplicate launch of fixture job")
                self.jobs[job] = None
                return b"LAUNCHER=setsid\n"
            if job not in self.jobs:
                raise ValueError("probe did not refer to a launched fixture job")
            if b"echo \"status=" in packet:
                self.counts["ssh_status"] += 1
                if self.jobs[job] is None:
                    self.jobs[job] = time.monotonic() + row["pending_seconds"]
                if time.monotonic() < self.jobs[job]:
                    return f"status=running\nalive=yes\nexit_code=\nlog_bytes={len(log)}\n".encode()
                exit_code = row["exit_code"]
                state = "failed" if exit_code else "done"
                return f"status={state}\nalive=no\nexit_code={exit_code}\nlog_bytes={len(log)}\n".encode()
            if b"base64 -w0" in packet and b"offset=0" in packet:
                self.counts["ssh_logs"] += 1
                return f"size={len(log)}\noffset=0\n".encode() + base64.b64encode(log)
            raise ValueError("unrecognized fixture operation")

    @contextmanager
    def serving(self):
        self.thread(self.ssh_accept)
        self.thread(self.catalog.serve_forever)
        try:
            yield self
        finally:
            self.stop.set()
            for transport in self.transports:
                transport.close()
            self.catalog.shutdown()
            self.catalog.server_close()
            for thread in self.threads:
                thread.join(timeout=1)
            self.ssh.close()
