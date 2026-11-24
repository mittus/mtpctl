#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test double for telemt: the subset of the Control API that mtpctl uses.

  fake_telemt.py run /etc/telemt/<id>.toml     — same command line as telemt (container tests)
  FakeTelemt(port, token).start()               — in-process (selftest)

Extra test-only endpoint: POST /test/traffic {"username", "add_octets", "connections", "ips"}.
Users live in memory. In `run` mode the proxy port is emulated only for "not Telegram" traffic:
it reads the incoming PROXY v1 header and relays the connection to the mask host with a new
PROXY v1 header — what telemt does for the cover site.
"""
import binascii
import json
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _link(domain, key, sni):
    return "tg://proxy?server=%s&port=443&secret=ee%s%s" % (domain, key, binascii.hexlify(sni.encode()).decode())


class FakeTelemt:
    def __init__(self, port, token, domain="example.org", host="127.0.0.1"):
        self.port, self.token, self.domain, self.host = port, token, domain, host
        self.users = {}
        self.policy = {"user_max_unique_ips_global_each": 0}
        self.lock = threading.Lock()
        self.started = time.time()
        self.calls = []
        self.srv = None

    # ---------------------------------------------------------------- model
    def info(self, u):
        own = u.get("max_unique_ips")
        glob = self.policy.get("user_max_unique_ips_global_each") or 0
        eff = own or (glob or None)
        return {
            "username": u["username"], "enabled": u.get("enabled", True),
            "expiration_rfc3339": u.get("expiration_rfc3339"), "data_quota_bytes": u.get("data_quota_bytes"),
            "quota_period": u.get("quota_period"), "max_unique_ips": eff,
            "limits": {"desired": {"max_unique_ips": {"value": eff, "configured_override": own,
                                                       "global_value": glob,
                                                       "origin": "user" if own else ("global" if glob else
                                                                                     "unlimited")}}},
            "current_connections": u.get("conns", 0), "active_unique_ips_list": u.get("ips", []),
            "total_octets": u.get("octets", 0),
            "links": {"classic": [], "secure": [], "tls": [_link(self.domain, u["secret"], self.domain)]},
        }

    def handle(self, method, path, body):
        self.calls.append((method, path))
        if path == "/v1/health":
            return 200, {"status": "ok"}
        if path == "/v1/system/info":
            return 200, {"version": "fake"}
        if path == "/v1/stats/summary":
            return 200, {"uptime_seconds": int(time.time() - self.started), "connections_total": 0,
                         "connections_bad_total": 0}
        if path == "/v1/access/policy":
            if method == "PATCH":
                v = body.get("user_max_unique_ips_global_each")
                self.policy["user_max_unique_ips_global_each"] = v or 0
            return 200, {"desired": dict(self.policy), "effective": dict(self.policy)}
        if path == "/test/traffic":
            u = self.users[body["username"]]
            u["octets"] = u.get("octets", 0) + int(body.get("add_octets", 0))
            u["conns"] = int(body.get("connections", 0))
            u["ips"] = body.get("ips", [])
            return 200, {}
        if path == "/v1/users":
            if method == "GET":
                return 200, [self.info(u) for u in self.users.values()]
            if method == "POST":
                name = body["username"]
                if name in self.users:
                    return 409, ("user_exists", "exists")
                if not re.match(r"^[0-9a-f]{32}$", body.get("secret", "")):
                    return 400, ("bad_request", "secret")
                u = {"username": name, "enabled": True}
                u.update({k: v for k, v in body.items() if k != "username"})
                self.users[name] = u
                return 200, self.info(u)
        m = re.match(r"^/v1/users/([^/]+)(/[a-z-]+)?$", path)
        if m:
            name, act = m.group(1), m.group(2)
            u = self.users.get(name)
            if not u:
                return 404, ("not_found", "no user")
            if act is None and method == "GET":
                return 200, self.info(u)
            if act is None and method == "DELETE":
                del self.users[name]
                return 200, {}
            if act is None and method == "PATCH":
                for k, v in body.items():
                    u[k] = v
                return 200, self.info(u)
            if act in ("/enable", "/disable") and method == "POST":
                u["enabled"] = act == "/enable"
                return 200, self.info(u)
            if act == "/reset-quota" and method == "POST":
                u["octets"] = 0
                return 200, self.info(u)
        return 404, ("not_found", "no route")

    # ---------------------------------------------------------------- http
    def start(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                if self.headers.get("Authorization") != "Bearer " + fake.token:
                    return self._out(401, ("unauthorized", "bad token"))
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n).decode()) if n else {}
                with fake.lock:
                    code, data = fake.handle(method, self.path.split("?")[0], body)
                self._out(code, data)

            def _out(self, code, data):
                if code >= 300:
                    payload = {"ok": False, "error": {"code": data[0], "message": data[1]}}
                else:
                    payload = {"ok": True, "data": data}
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_PATCH(self):
                self._do("PATCH")

            def do_DELETE(self):
                self._do("DELETE")

        ThreadingHTTPServer.allow_reuse_address = True
        self.srv = ThreadingHTTPServer((self.host, self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
            self.srv = None


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for x in (a, b):
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def mask_listener(port, mask_host, mask_port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(64)

    def serve(c):
        try:
            head = b""
            while b"\r\n" not in head and len(head) < 120:
                ch = c.recv(1)
                if not ch:
                    return c.close()
                head += ch
            m = re.match(rb"PROXY TCP4 (\S+) \S+ (\d+) \d+\r\n", head)
            src, sport = (m.group(1).decode(), m.group(2).decode()) if m else ("127.0.0.1", "1")
            up = socket.create_connection((mask_host, mask_port), timeout=5)
            up.sendall(("PROXY TCP4 %s 127.0.0.1 %s %d\r\n" % (src, sport, mask_port)).encode())
            threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
            _pipe(c, up)
        except OSError:
            c.close()

    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def main(argv):
    if len(argv) < 3 or argv[1] != "run":
        if len(argv) > 1 and argv[1] in ("--version", "-V"):
            print("telemt 0.0.0-fake")
            return 0
        print("usage: fake_telemt.py run <config.toml>", file=sys.stderr)
        return 2
    text = open(argv[2], encoding="utf-8").read()
    listen = re.search(r'(?m)^listen\s*=\s*"([\d.]+):(\d+)"', text)
    token = re.search(r'(?m)^auth_header\s*=\s*"Bearer ([^"]+)"', text)
    domain = re.search(r'(?m)^tls_domain\s*=\s*"([^"]+)"', text)
    f = FakeTelemt(int(listen.group(2)), token.group(1), domain.group(1) if domain else "example.org",
                   listen.group(1)).start()
    port = re.search(r"(?m)^\[server\][^\[]*?^port\s*=\s*(\d+)", text)
    mh = re.search(r'(?m)^mask_host\s*=\s*"([^"]+)"', text)
    mp = re.search(r"(?m)^mask_port\s*=\s*(\d+)", text)
    if port and mh and mp:
        mask_listener(int(port.group(1)), mh.group(1), int(mp.group(1)))
    print("fake telemt on %s:%d" % (f.host, f.port), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
