# -*- coding: utf-8 -*-
"""mtpctl web: backend of the panel (served on every server domain). Runs on 127.0.0.1 behind nginx.

Everything except POST /api/login answers 404 without a valid session, so an anonymous
visitor (or a DPI probe) only ever sees the static login page served by nginx.
The panel UI itself (app.html) is handed out only after login via GET /api/app.
"""
import hashlib
import hmac
import html
import http.server
import json
import os
import random
import re
import secrets
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
from core import MtpError  # noqa: E402

APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "app.html")
INSTALL_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install.sh")
PBKDF2_ITER = 240000
SESSION_HOURS = 12
REMEMBER_DAYS = 30
FAIL_WINDOW = 15 * 60
FAIL_PER_IP = 5
FAIL_GLOBAL = 30
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "XMLHttpRequest"
MAX_BODY = 64 * 1024


# ---------------------------------------------------------------- admin credentials

def hash_password(password, salt=None, iterations=PBKDF2_ITER):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        algo, it, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, AttributeError):
        return False


def load_auth():
    m = core.Manager()
    try:
        return m.auth()
    finally:
        m.close()


def set_admin(user, password):
    if not core.NAME_RE.match(user or ""):
        raise MtpError("логин: латиница, цифры, . _ -")
    if len(password) < 10:
        raise MtpError("пароль не короче 10 символов")
    m = core.Manager()
    try:
        m.set_auth(user, hash_password(password))
    finally:
        m.close()


# dummy hash so a wrong login costs the same time as a wrong password
_DUMMY_HASH = hash_password(secrets.token_hex(8))


# ---------------------------------------------------------------- sessions / throttling

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}      # sid -> {"user", "exp", "epoch"}
        self.fails = {}         # ip -> [ts...]
        self.fails_global = []  # [ts...]

    def prune(self, now):
        for ip in list(self.fails):
            self.fails[ip] = [t for t in self.fails[ip] if now - t < FAIL_WINDOW]
            if not self.fails[ip]:
                del self.fails[ip]
        self.fails_global = [t for t in self.fails_global if now - t < FAIL_WINDOW]
        for sid in list(self.sessions):
            if self.sessions[sid]["exp"] < now:
                del self.sessions[sid]


STATE = State()
LOGIN_SLOTS = threading.BoundedSemaphore(4)


def _fail_delay():
    time.sleep(0.7 + random.random() * 0.6)


# ---------------------------------------------------------------- HTTP handler

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # quieter, no query strings / bodies in logs
    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_ip(), fmt % args))

    def client_ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    # --- responses
    def _send(self, status, body=b"", ctype="application/json; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, headers=None):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), headers=headers)

    def _not_found(self):
        self._send(404, b"<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1>"
                        b"</center><hr><center>nginx</center></body></html>\n", "text/html")

    # --- request parsing
    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise MtpError("неверный Content-Length")
        if n < 0:
            raise MtpError("неверный Content-Length")
        if n > MAX_BODY:
            raise MtpError("слишком большой запрос", status=413)
        if n == 0:
            return {}
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise MtpError("нужен JSON", status=415)
        try:
            data = json.loads(self.rfile.read(n).decode())
        except ValueError:
            raise MtpError("неверный JSON")
        if not isinstance(data, dict):
            raise MtpError("неверный JSON")
        return data

    def _cookie_sid(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return None

    def _session(self):
        sid = self._cookie_sid()
        if not sid:
            return None
        now = time.time()
        auth = load_auth()
        with STATE.lock:
            s = STATE.sessions.get(sid)
            if not s or s["exp"] < now or s["epoch"] != auth.get("epoch") or s["user"] != auth.get("user"):
                STATE.sessions.pop(sid, None)
                return None
            return dict(s, sid=sid)

    # --- dispatch
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if not path.startswith("/api/") or self.headers.get(CSRF_HEADER) != CSRF_VALUE:
                return self._not_found()
            if path == "/api/login" and method == "POST":
                return self.h_login()
            sess = self._session()
            if not sess:
                return self._not_found()
            self.sess = sess
            parts = [urllib.parse.unquote(p) for p in path[len("/api/"):].split("/") if p]
            return self.route(method, parts)
        except MtpError as e:
            self._json(e.status if e.status < 600 else 400, {"ok": False, "error": e.message, "code": e.code})
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("internal error: %r\n" % (e,))
            self._json(500, {"ok": False, "error": "внутренняя ошибка"})

    def route(self, method, p):
        m = core.Manager()
        try:
            return self._route(m, method, p)
        finally:
            m.close()

    def _query(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        return {k: v[0] for k, v in q.items()}

    def _clients_payload(self, m, clients):
        servers = [{"id": s["id"], "title": s["title"], "enabled": s["enabled"],
                    "default": s["id"] == m.default_server_id()} for s in m.servers()]
        return {"ok": True, "clients": clients, "servers": servers, "errors": m.errors}

    def _route(self, m, method, p):
        if p == ["session"] and method == "GET":
            return self._json(200, {"ok": True, "user": self.sess["user"]})
        if p == ["logout"] and method == "POST":
            with STATE.lock:
                STATE.sessions.pop(self.sess["sid"], None)
            return self._json(200, {"ok": True}, {"Set-Cookie": _cookie("", 0, _cookie_path(self))})
        if p == ["app"] and method == "GET":
            with open(APP_PATH, "rb") as f:
                page = f.read()
            with open(os.path.join(os.path.dirname(APP_PATH), "qrcode.js"), "rb") as f:
                page = page.replace(b"/*QRCODE*/", f.read(), 1)
            page = page.replace(b"{{BRAND}}", html.escape(m.brand()).encode())
            return self._send(200, page, "text/html; charset=utf-8")
        if p == ["password"] and method == "POST":
            b = self._body()
            auth = m.auth()
            if not verify_password(b.get("current", ""), auth.get("hash") or ""):
                _fail_delay()
                raise MtpError("текущий пароль неверен", status=403)
            set_admin(b.get("user") or auth["user"], b.get("new", ""))
            return self._json(200, {"ok": True}, {"Set-Cookie": _cookie("", 0, _cookie_path(self))})
        if p == ["traffic"] and method == "GET":
            q = self._query()
            return self._json(200, {"ok": True, "traffic": m.traffic_report(
                q.get("name") or None, q.get("range") or "24h", q.get("server") or None)})
        if p == ["settings"]:
            if method == "PATCH":
                b = self._body()
                if "master_addr" in b:
                    addr = str(b["master_addr"] or "").strip()
                    if addr:
                        try:
                            addr = core.check_ip(addr)
                        except MtpError:
                            addr = core.check_domain(addr)
                    m.db.set_meta("master_addr", addr or None)
                if "panel_domain" in b:
                    m.set_panel_domain(str(b["panel_domain"] or ""))
                if b.get("regenerate_path"):
                    m.set_base_path()
                elif b.get("base_path"):
                    m.set_base_path(str(b["base_path"]))
            return self._json(200, {"ok": True, "settings": {
                "master_addr": m.master_addr(), "default_server": m.default_server_id(),
                "panel_domain": m.panel_domain(), "base_path": m.base_path(), "panel_urls": m.panel_urls(),
                "panel_checks": m.panel_checks()}})
        if p == ["backup"] and method == "GET":
            return self._backup(m)
        if p == ["install.sh"] and method == "GET":
            with open(INSTALL_SH, "rb") as f:
                body = f.read()
            return self._send(200, body, "application/x-sh",
                              {"Content-Disposition": 'attachment; filename="install.sh"'})
        # ---- servers
        if p == ["servers"]:
            if method == "GET":
                return self._json(200, {"ok": True, "servers": m.servers_info(),
                                        "master_addr": m.master_addr()})
            if method == "POST":
                b = self._body()
                s = m.server_add(b.get("title"), b.get("domain"), b.get("entry_ip"), b.get("extra_sni"),
                                 b.get("default_devices"), b.get("note", ""))
                if b.get("default"):
                    m.server_update(s["id"], make_default=True)
                return self._json(201, {"ok": True, "server": core.public_server(s),
                                        "slave_cmd": m.slave_command(s)})
        if len(p) >= 2 and p[0] == "servers":
            sid = m.server(p[1])["id"]
            if len(p) == 2 and method == "PATCH":
                b = self._body()
                kw = {k: b[k] for k in ("title", "domain", "entry_ip", "extra_sni", "default_devices", "note",
                                        "enabled") if k in b}
                s = m.server_update(sid, make_default=bool(b.get("default")), **kw)
                return self._json(200, {"ok": True, "server": core.public_server(s), "errors": m.errors})
            if len(p) == 2 and method == "DELETE":
                m.server_delete(sid)
                return self._json(200, {"ok": True})
            if p[2:] == ["check"] and method == "POST":
                if not core.request_apply("check " + sid):
                    raise MtpError("не удалось передать задание агенту", status=500)
                return self._json(200, {"ok": True})
        # ---- clients
        if p == ["clients"]:
            if method == "GET":
                return self._json(200, self._clients_payload(m, m.list()))
            if method == "POST":
                b = self._body()
                c = m.add(b.get("name", ""), servers=b.get("servers") or None, expires=b.get("expires"),
                          note=b.get("note", ""), quota=b.get("quota"), period=b.get("period"),
                          devices=b.get("devices"))
                return self._json(201, {"ok": True, "client": c, "errors": m.errors})
        if len(p) >= 2 and p[0] == "clients":
            name = p[1]
            if len(p) == 2:
                if method == "GET":
                    return self._json(200, {"ok": True, "client": m.get(name)})
                if method == "DELETE":
                    m.delete(name)
                    return self._json(200, {"ok": True})
                if method == "PATCH":
                    b = self._body()
                    kw = {}
                    for k in ("servers", "note", "quota", "period", "devices"):
                        if k in b:
                            kw[k] = b[k]
                    if "expires" in b:
                        kw["expires"] = b["expires"] or "never"
                    c = m.update(name, **kw)
                    return self._json(200, {"ok": True, "client": c, "errors": m.errors})
            if len(p) == 3 and method == "POST":
                act = p[2]
                if act in ("enable", "disable"):
                    return self._json(200, {"ok": True, "client": m.enable(name, act == "enable")})
                if act == "rotate":
                    return self._json(200, {"ok": True, "client": m.rotate(name)})
                if act == "reset-quota":
                    return self._json(200, {"ok": True, "client": m.reset_quota(name)})
        return self._not_found()

    def _backup(self, m):
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix=".backup-", dir=os.path.dirname(core.DB_PATH))
        os.close(fd)
        try:
            m.db.backup_to(tmp)
            with open(tmp, "rb") as f:
                body = f.read()
        finally:
            os.unlink(tmp)
        fname = "mtpctl-%s.db" % time.strftime("%Y%m%d-%H%M")
        return self._send(200, body, "application/vnd.sqlite3",
                          {"Content-Disposition": 'attachment; filename="%s"' % fname})

    def h_login(self):
        ip = self.client_ip()
        now = time.time()
        try:
            b = self._body()
        except MtpError:
            b = {}
        user, pw, remember = str(b.get("user", "")), str(b.get("password", "")), bool(b.get("remember"))
        # попытку засчитываем ДО проверки пароля: параллельные запросы не обойдут лимит
        with STATE.lock:
            STATE.prune(now)
            blocked = len(STATE.fails.get(ip, [])) >= FAIL_PER_IP
            crowded = len(STATE.fails_global) >= FAIL_GLOBAL
            STATE.fails.setdefault(ip, []).append(now)
            STATE.fails_global.append(now)
        ok = False
        if not blocked and LOGIN_SLOTS.acquire(timeout=10):      # PBKDF2 не больше чем в 4 потоках
            try:
                auth = load_auth()
                if auth.get("hash"):
                    user_ok = hmac.compare_digest(user.encode(), str(auth.get("user", "")).encode())
                    pw_ok = verify_password(pw, auth["hash"] if user_ok else _DUMMY_HASH)
                    ok = user_ok and pw_ok
            finally:
                LOGIN_SLOTS.release()
        if not ok:
            sys.stderr.write("login failed from %s%s\n" % (ip, " (blocked)" if blocked else ""))
            _fail_delay()
            if crowded:
                time.sleep(3)
            return self._json(403, {"ok": False, "error": "Неверный логин или пароль"})
        sid = secrets.token_urlsafe(32)
        ttl = REMEMBER_DAYS * 86400 if remember else SESSION_HOURS * 3600
        with STATE.lock:
            STATE.fails.pop(ip, None)
            if now in STATE.fails_global:
                STATE.fails_global.remove(now)
            STATE.sessions[sid] = {"user": auth["user"], "exp": now + ttl, "epoch": auth.get("epoch")}
        sys.stderr.write("login ok from %s\n" % ip)
        return self._json(200, {"ok": True, "user": auth["user"]},
                          {"Set-Cookie": _cookie(sid, ttl if remember else None, _cookie_path(self))})


def _cookie_path(handler):
    """Cookie only for the panel path (nginx passes it; the decoy page at / never gets one)."""
    p = handler.headers.get("X-Base-Path") or "/"
    return p if re.match(r"^/[A-Za-z0-9_-]{4,64}/$", p) else "/"


def _cookie(value, max_age, path="/"):
    c = "sid=%s; Path=%s; HttpOnly; Secure; SameSite=Strict" % (value, path)
    if max_age is not None:
        c += "; Max-Age=%d" % max_age
    return c


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def collector(interval=60):
    """Замер трафика и «в сети» раз в минуту, даже когда кабинет никто не открывает."""
    last_err = None
    while True:
        try:
            m = core.Manager()
            try:
                m.collect()
                errs = "; ".join("%s: %s" % kv for kv in sorted(m.errors.items()))
            finally:
                m.close()
            if errs and errs != last_err:
                sys.stderr.write("sync: %s\n" % errs)
            last_err = errs or None
        except Exception as e:  # noqa: BLE001
            msg = getattr(e, "message", None) or repr(e)
            if msg != last_err:
                sys.stderr.write("traffic collect failed: %s\n" % msg)
                last_err = msg
        time.sleep(interval)


def main():
    host = os.environ.get("MTPCTL_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("MTPCTL_WEB_PORT", "8090"))
    os.umask(0o007)
    core.Manager().close()  # fail fast without a database
    threading.Thread(target=collector, name="collector", daemon=True).start()
    srv = Server((host, port), Handler)
    sys.stderr.write("mtpctl web on %s:%d\n" % (host, port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
