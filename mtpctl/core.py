# -*- coding: utf-8 -*-
"""mtpctl core: SQLite store, servers (entry points), clients, telemt sync, traffic.

Python 3.7+, standard library only. Used by the CLI (cli.py), the web panel (web.py)
and the root agent (agent.py).

Model
  * master host (has access to Telegram) runs one telemt instance per server: telemt@<server id>;
  * a server = an entry point: a slave host (entry_ip) + domain (+ optional extra SNI masks);
    the slave only forwards 443 -> master:<port> (PROXY protocol) and 80 -> master:80;
  * a client has one key and access to a set of servers; links are built per server.
The database is the source of truth. telemt is brought to it by sync_server() through its
Control API (web panel: on every change and once a minute; agent: after (re)start).
"""
import binascii
import contextlib
import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

HOME = os.environ.get("MTPCTL_HOME", "/opt/mtpctl")            # домашний каталог пользователя mtpctl
DB_PATH = os.environ.get("MTPCTL_DB", os.path.join(HOME, "data", "mtpctl.db"))
BACKUP_PATH = os.path.join(HOME, "backup", "mtpctl.db")         # одна рабочая копия, обновляется раз в сутки
LIB_DIR = os.environ.get("MTPCTL_LIB", os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(LIB_DIR, "templates")
BASE_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
RESERVED_BASE = {"api", "login", "index.html", ".well-known"}
SCHEMA_VERSION = 1

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
KEY_RE = re.compile(r"^[0-9a-f]{32}$")
SERVER_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")

PORT_FIRST, API_PORT_FIRST = 8443, 9091
RESERVED_PORTS = {8445, 8446, 8090}       # nginx: маскировка SNI, сайт-заглушка; mtpctl-web

KEEP = object()                           # «не менять» в update()


class MtpError(Exception):
    """Error with a human-readable Russian message and an optional machine code."""

    def __init__(self, message, code="error", status=400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS servers(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL UNIQUE COLLATE NOCASE,
  domain TEXT NOT NULL UNIQUE,
  entry_ip TEXT NOT NULL,
  extra_sni TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL UNIQUE,
  api_port INTEGER NOT NULL UNIQUE,
  api_token TEXT NOT NULL,
  reserve_key TEXT NOT NULL,
  default_devices INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS server_state(
  server TEXT PRIMARY KEY,
  applied TEXT,
  checked REAL,
  checks TEXT,
  cert_try REAL);
CREATE TABLE IF NOT EXISTS clients(
  name TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  expires TEXT,
  quota_bytes INTEGER,
  quota_period TEXT,
  max_devices INTEGER);
CREATE TABLE IF NOT EXISTS access(
  client TEXT NOT NULL REFERENCES clients(name) ON DELETE CASCADE,
  server TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  PRIMARY KEY(client, server));
CREATE TABLE IF NOT EXISTS tr_state(
  client TEXT NOT NULL,
  server TEXT NOT NULL,
  prev INTEGER,
  total INTEGER NOT NULL DEFAULT 0,
  first_seen REAL,
  last_seen REAL,
  online_since REAL,
  PRIMARY KEY(client, server));
CREATE TABLE IF NOT EXISTS tr_slot(
  client TEXT NOT NULL,
  server TEXT NOT NULL,
  slot INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY(client, server, slot));
CREATE TABLE IF NOT EXISTS tr_day(
  client TEXT NOT NULL,
  server TEXT NOT NULL,
  day TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY(client, server, day));
"""


class Store:
    """Thin wrapper around one sqlite3 connection (one per request / thread)."""

    def __init__(self, path=None, create=False):
        self.path = path or DB_PATH
        if not create and not os.path.exists(self.path):
            raise MtpError("нет базы %s — установите мастер (install.sh master) или выполните mtpctl init"
                           % self.path, "no_db", 500)
        self.conn = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=15000")
        if create:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            if self.meta("schema") is None:
                self.set_meta("schema", str(SCHEMA_VERSION))
        else:
            v = self.meta("schema")
            if v is None:
                raise MtpError("%s — не база mtpctl" % self.path, "bad_db", 500)
            if int(v) > SCHEMA_VERSION:
                raise MtpError("база новее этой версии mtpctl (схема %s) — обновите mtpctl" % v, "bad_db", 500)

    def close(self):
        with contextlib.suppress(Exception):
            self.conn.close()

    @contextlib.contextmanager
    def tx(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()

    def x(self, sql, args=()):
        return self.conn.execute(sql, args)

    def meta(self, k, default=None):
        try:
            r = self.q1("SELECT v FROM meta WHERE k=?", (k,))
        except sqlite3.OperationalError:
            return default
        return r["v"] if r else default

    def set_meta(self, k, v):
        if v is None:
            self.x("DELETE FROM meta WHERE k=?", (k,))
        else:
            self.x("INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def backup_to(self, dest):
        """Consistent copy of the live database (works while web/agent are writing)."""
        out = sqlite3.connect(dest)
        try:
            self.conn.backup(out)
            out.execute("PRAGMA journal_mode=DELETE")   # копия — один самодостаточный файл, без -wal/-shm
        finally:
            out.close()


def init_db(path=None, master_addr=None):
    """Create (or upgrade) the database. Returns the Store."""
    st = Store(path, create=True)
    if master_addr and not st.meta("master_addr"):
        st.set_meta("master_addr", master_addr)
    return st


def check_db_file(path):
    """Validate a database file before restoring it. Returns a short summary."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(os.path.abspath(path)), uri=True)
    except sqlite3.Error as e:
        raise MtpError("не открывается как SQLite: %s" % e)
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise MtpError("файл повреждён: %s" % ok)
        v = conn.execute("SELECT v FROM meta WHERE k='schema'").fetchone()
        if not v:
            raise MtpError("это не база mtpctl")
        if int(v[0]) > SCHEMA_VERSION:
            raise MtpError("база новее этой версии mtpctl")
        rows = conn.execute("SELECT * FROM servers").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM servers LIMIT 0").description]
        for r in rows:
            validate_server(_server_from_row(dict(zip(cols, r))))
        bp = conn.execute("SELECT v FROM meta WHERE k='web_base_path'").fetchone()
        if bp and bp[0]:
            check_base_path(bp[0])
        n_s = len(rows)
        n_c = conn.execute("SELECT count(*) FROM clients").fetchone()[0]
    except sqlite3.Error as e:
        raise MtpError("это не база mtpctl (%s)" % e)
    finally:
        conn.close()
    return {"servers": n_s, "clients": n_c, "schema": int(v[0])}


# ---------------------------------------------------------------- telemt API

class TelemtAPI:
    def __init__(self, url, auth, timeout=10):
        self.url = url.rstrip("/")
        self.auth = auth
        self.timeout = timeout

    def call(self, method, path, body=None, _retry=True):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        if self.auth:
            req.add_header("Authorization", self.auth)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read().decode() or "{}")
            except ValueError:
                payload = {}
            err = payload.get("error") or {}
            code = err.get("code") or "http_%d" % e.code
            if _retry and code in ("revision_conflict", "reload_in_progress"):
                time.sleep(1.5)
                return self.call(method, path, body, _retry=False)
            raise MtpError(_api_message(code, err.get("message") or str(e)), code, e.code if e.code < 500 else 502)
        except (urllib.error.URLError, OSError) as e:
            raise MtpError("telemt не отвечает (%s)" % getattr(e, "reason", e), "api_down", 502)
        if not payload.get("ok", False):
            err = payload.get("error") or {}
            raise MtpError(_api_message(err.get("code"), err.get("message", "ошибка API")),
                           err.get("code") or "api_error", 502)
        return payload.get("data")


_API_MESSAGES = {
    "user_exists": "клиент с таким именем уже есть",
    "not_found": "клиент не найден",
    "last_user_forbidden": "нельзя удалить последнего клиента",
    "unauthorized": "telemt отклонил токен API",
    "forbidden": "telemt не пускает этот адрес к API",
    "revision_conflict": "конфигурация изменилась одновременно, повторите",
    "reload_in_progress": "telemt перечитывает конфигурацию, повторите через пару секунд",
}


def _api_message(code, fallback):
    return _API_MESSAGES.get(code or "", fallback)


# ---------------------------------------------------------------- helpers

def random_string(n):
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # без похожих 0/O, 1/l/I
    return "".join(secrets.choice(alphabet) for _ in range(n))


def check_base_path(p):
    p = (p or "").strip().strip("/")
    if not BASE_PATH_RE.match(p) or p.lower() in RESERVED_BASE:
        raise MtpError("путь кабинета: 4–64 символа, латиница, цифры, - и _", "bad_path")
    return p


def check_name(name):
    if not NAME_RE.match(name or ""):
        raise MtpError("имя: латиница, цифры, точка, дефис, подчёркивание; до 64 символов", "bad_name")
    return name


def check_domain(d):
    d = (d or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d):
        raise MtpError("домен: например example.org (латиница, без http:// и пути)", "bad_domain")
    return d


def check_ip(ip):
    try:
        a = ipaddress.IPv4Address((ip or "").strip())
    except ValueError:
        raise MtpError("IP входного хоста: IPv4, например 203.0.113.10", "bad_ip")
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        raise MtpError("этот IP не подходит для входного хоста", "bad_ip")
    return str(a)


def check_title(t):
    t = re.sub(r"\s+", " ", (t or "").strip())
    if not 1 <= len(t) <= 40 or any(ord(ch) < 32 for ch in t):
        raise MtpError("название сервера: от 1 до 40 символов", "bad_title")
    return t


def parse_sni_list(v):
    if v is None:
        return []
    items = v if isinstance(v, (list, tuple)) else re.split(r"[\s,;]+", str(v))
    out = []
    for x in items:
        x = (x or "").strip()
        if x:
            x = check_domain(x)
            if x not in out:
                out.append(x)
    return out


def parse_size(text):
    """'20G', '500M', '1.5T', '123456' -> bytes; '' / '0' / None -> None."""
    if text in (None, "", 0, "0"):
        return None
    if isinstance(text, int):
        return text
    m = re.match(r"^\s*([0-9]+(?:[.,][0-9]+)?)\s*([KMGT]?)i?B?\s*$", str(text), re.I)
    if not m:
        raise MtpError("размер: число с K/M/G/T, например 20G", "bad_size")
    num = float(m.group(1).replace(",", "."))
    mult = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2).upper()]
    return int(num * mult) or None


def human_size(n):
    if n is None:
        return "—"
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return ("%.0f %s" if unit == "Б" else "%.1f %s") % (n, unit)
        n /= 1024


def utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_expiry(value, base=None):
    """None/'' -> no change (None); 'never' -> '' (remove);
    '+30' / '30' -> now(or base)+30 days; 'YYYY-MM-DD' -> end of that day UTC; RFC3339 passthrough."""
    if value is None or value == "":
        return None
    v = str(value).strip().lower()
    if v in ("never", "none", "бессрочно", "-", "0"):
        return ""
    if re.match(r"^\+?\d+$", v):
        start = base or utcnow()
        if start < utcnow():
            start = utcnow()
        return iso(start + _dt.timedelta(days=int(v.lstrip("+"))))
    if re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        if not parse_rfc3339(v + "T23:59:59Z"):
            raise MtpError("неверная дата", "bad_expiry")
        return v + "T23:59:59Z"
    dt = parse_rfc3339(str(value))
    if dt:
        return iso(dt.astimezone(_dt.timezone.utc))
    raise MtpError("срок: число дней, дата ГГГГ-ММ-ДД или «бессрочно»", "bad_expiry")


def parse_rfc3339(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    s = re.sub(r"\.\d+", "", s)
    if re.search(r"[+-]\d{2}:\d{2}$", s):
        s = s[:-3] + s[-2:]
    try:
        return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def key_from_link(link):
    m = re.search(r"secret=ee([0-9a-f]{32})", link or "")
    return m.group(1) if m else None


def make_secret(key, sni):
    return "ee" + key + binascii.hexlify(sni.encode("ascii")).decode()


def make_links(key, endpoints):
    out = []
    for ep in endpoints:
        secret = make_secret(key, ep["sni"])
        q = urllib.parse.urlencode({"server": ep["server"], "port": ep["port"], "secret": secret})
        out.append(dict(ep, secret=secret, tg="tg://proxy?" + q, https="https://t.me/proxy?" + q))
    return out


def _check_period(p):
    p = (p or "").strip().lower()
    mapping = {"day": "daily", "daily": "daily", "день": "daily",
               "week": "weekly", "weekly": "weekly", "неделя": "weekly",
               "month": "monthly", "monthly": "monthly", "месяц": "monthly"}
    if p not in mapping:
        raise MtpError("период: day, week или month", "bad_period")
    return mapping[p]


def _pos_int(v, what):
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise MtpError("число %s должно быть целым" % what, "bad_int")
    if n < 1:
        raise MtpError("число %s должно быть больше нуля" % what, "bad_int")
    return n


def _opt_int(v, what):
    return None if v in (None, "", 0, "0") else _pos_int(v, what)


def _hidden(name):
    return name.startswith("_")       # служебные пользователи telemt (у экземпляра должен быть хоть один)


def request_apply(reason="change"):
    """Wake the root agent (mtpctl-agent.path watches this file)."""
    path = os.path.join(os.path.dirname(DB_PATH), "apply.req")
    try:
        with open(path, "w") as f:
            f.write("%d %s\n" % (time.time(), reason))
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- servers

def server_endpoints(s):
    eps = [{"id": "main", "title": "Основная", "server": s["domain"], "port": 443, "sni": s["domain"]},
           {"id": "ip", "title": "По IP", "server": s["entry_ip"], "port": 443, "sni": s["domain"]}]
    for x in s["extra_sni"]:
        eps.append({"id": "sni:" + x, "title": "Маскировка под " + x, "server": s["entry_ip"], "port": 443, "sni": x})
    return eps


def _server_from_row(r):
    d = dict(r)
    d["extra_sni"] = [x for x in (d.get("extra_sni") or "").split(",") if x]
    d["enabled"] = bool(d["enabled"])
    return d


def validate_server(s):
    """Re-check a row from the database before root uses it (paths, nginx/TOML/ufw arguments)."""
    if not SERVER_ID_RE.match(s.get("id") or ""):
        raise MtpError("неверный id сервера: %r" % s.get("id"), "bad_server")
    if check_domain(s["domain"]) != s["domain"] or check_ip(s["entry_ip"]) != s["entry_ip"]:
        raise MtpError("сервер %s: неверный домен или IP в базе" % s["id"], "bad_server")
    if parse_sni_list(s["extra_sni"]) != list(s["extra_sni"]):
        raise MtpError("сервер %s: неверный список SNI в базе" % s["id"], "bad_server")
    for k in ("port", "api_port"):
        if not isinstance(s[k], int) or not 1024 <= s[k] <= 65535:
            raise MtpError("сервер %s: неверный %s в базе" % (s["id"], k), "bad_server")
    if not re.match(r"^[0-9a-f]{32,64}$", s["api_token"]) or not KEY_RE.match(s["reserve_key"]):
        raise MtpError("сервер %s: неверный токен в базе" % s["id"], "bad_server")
    return s


def public_server(s):
    return {k: v for k, v in s.items() if k not in ("api_token", "reserve_key")}


def render_telemt_conf(s, tmpl=None):
    """telemt config for one server (users are added later through the API)."""
    if tmpl is None:
        with open(os.path.join(TEMPLATES, "telemt.toml.tmpl"), encoding="utf-8") as f:
            tmpl = f.read()
    extra = s["extra_sni"]
    subst = {
        "ID": s["id"], "DOMAIN": s["domain"], "PORT": str(s["port"]),
        "API_PORT": str(s["api_port"]), "TOKEN": s["api_token"], "ENTRY_IP": s["entry_ip"],
        "RESERVE_KEY": s["reserve_key"],
        "TLS_DOMAINS": ("tls_domains = [%s]" % ", ".join('"%s"' % x for x in extra)) if extra else "",
        "EXCLUSIVE_MASK": ("[censorship.exclusive_mask]\n" + "\n".join(
            '"%s" = "127.0.0.1:8445"' % x for x in extra)) if extra else "",
    }
    for k, v in subst.items():
        tmpl = tmpl.replace("{{%s}}" % k, v)
    return tmpl


def conf_hash(s, tmpl=None):
    return hashlib.sha256((render_telemt_conf(s, tmpl) + ("|on" if s["enabled"] else "|off")).encode()).hexdigest()[:16]


def _port_free(port, host):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sk.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sk.close()


# ---------------------------------------------------------------- traffic

SLOT = 300
KEEP_SLOTS = 49 * 3600
KEEP_DAYS = 400
PERIODS = [("1h", "Последний час", 1, "h"), ("7h", "7 часов", 7, "h"), ("12h", "12 часов", 12, "h"),
           ("day", "Сегодня", 1, "d"), ("week", "7 дней", 7, "d"), ("month", "30 дней", 30, "d"),
           ("year", "365 дней", 365, "d"), ("all", "Всё время", None, None)]


def collect_traffic(db, server_id, users, known, now=None):
    """Store increments of telemt's cumulative total_octets (per client and server).

    users: {name: UserInfo}; known: set of client names in the database.
    5-minute slots for 49 h, calendar days (local time) for 400 days, running total.
    A counter that went down (telemt restarted, user re-created) counts from zero."""
    now = time.time() if now is None else now
    slot = int(now) // SLOT
    day = _dt.date.fromtimestamp(now).isoformat()
    with db.tx():
        for name, u in users.items():
            if name not in known:
                continue
            cur = int(u.get("total_octets") or 0)
            online = int(u.get("current_connections") or 0) > 0
            r = db.q1("SELECT prev, total, online_since FROM tr_state WHERE client=? AND server=?", (name, server_id))
            if r is None:
                db.x("INSERT INTO tr_state(client, server, prev, total, first_seen, last_seen, online_since) "
                     "VALUES(?,?,?,?,?,?,?)", (name, server_id, cur, cur, now, now if online else None,
                                               now if online else None))
                continue
            prev = r["prev"]
            delta = 0 if prev is None else (cur - prev if cur >= prev else cur)
            total = (r["total"] or 0) + delta if prev is not None else max(r["total"] or 0, cur)
            db.x("UPDATE tr_state SET prev=?, total=?, last_seen=CASE WHEN ? THEN ? ELSE last_seen END, "
                 "online_since=CASE WHEN ? THEN COALESCE(online_since, ?) ELSE NULL END WHERE client=? AND server=?",
                 (cur, total, online, now, online, now, name, server_id))
            if delta > 0:
                db.x("INSERT INTO tr_slot(client, server, slot, bytes) VALUES(?,?,?,?) "
                     "ON CONFLICT(client, server, slot) DO UPDATE SET bytes=bytes+excluded.bytes",
                     (name, server_id, slot, delta))
                db.x("INSERT INTO tr_day(client, server, day, bytes) VALUES(?,?,?,?) "
                     "ON CONFLICT(client, server, day) DO UPDATE SET bytes=bytes+excluded.bytes",
                     (name, server_id, day, delta))
        db.x("DELETE FROM tr_slot WHERE slot < ?", (int(now - KEEP_SLOTS) // SLOT,))
        db.x("DELETE FROM tr_day WHERE day < ?", (_dt.date.fromtimestamp(now - KEEP_DAYS * 86400).isoformat(),))


def _tr_filter(name, server):
    w, a = [], []
    if name:
        w.append("client=?")
        a.append(name)
    if server:
        w.append("server=?")
        a.append(server)
    return (" AND " + " AND ".join(w)) if w else "", a


def traffic_periods(db, name=None, server=None, now=None):
    now = time.time() if now is None else now
    today = _dt.date.fromtimestamp(now)
    f, a = _tr_filter(name, server)
    rows = []
    for key, title, length, unit in PERIODS:
        if length is None:
            v = db.q1("SELECT COALESCE(SUM(total),0) s FROM tr_state WHERE 1=1" + f, a)["s"]
        elif unit == "h":
            v = db.q1("SELECT COALESCE(SUM(bytes),0) s FROM tr_slot WHERE slot>=?" + f,
                      [int(now - length * 3600) // SLOT] + a)["s"]
        else:
            v = db.q1("SELECT COALESCE(SUM(bytes),0) s FROM tr_day WHERE day>=?" + f,
                      [(today - _dt.timedelta(days=length - 1)).isoformat()] + a)["s"]
        rows.append({"period": key, "title": title, "bytes": int(v)})
    return rows


def traffic_series(db, rng, name=None, server=None, now=None):
    """Bars for a chart: [{"t": start_ts, "label", "bytes"}], oldest first."""
    now = time.time() if now is None else now
    f, a = _tr_filter(name, server)
    out = []
    if rng == "24h":
        hour0 = int(now) // 3600 * 3600
        first = hour0 - 23 * 3600
        by_slot = {r["slot"]: r["b"] for r in db.q(
            "SELECT slot, SUM(bytes) b FROM tr_slot WHERE slot>=?" + f + " GROUP BY slot", [first // SLOT] + a)}
        for i in range(23, -1, -1):
            start = hour0 - i * 3600
            total = sum(v for k, v in by_slot.items() if start // SLOT <= k < (start + 3600) // SLOT)
            out.append({"t": start, "label": _dt.datetime.fromtimestamp(start).strftime("%H:00"), "bytes": total})
    elif rng in ("7d", "30d"):
        n = 7 if rng == "7d" else 30
        today = _dt.date.fromtimestamp(now)
        since = (today - _dt.timedelta(days=n - 1)).isoformat()
        by_day = {r["day"]: r["b"] for r in db.q(
            "SELECT day, SUM(bytes) b FROM tr_day WHERE day>=?" + f + " GROUP BY day", [since] + a)}
        for i in range(n - 1, -1, -1):
            d = today - _dt.timedelta(days=i)
            out.append({"t": int(_dt.datetime(d.year, d.month, d.day).timestamp()),
                        "label": d.strftime("%d.%m"), "bytes": by_day.get(d.isoformat(), 0)})
    elif rng == "12m":
        today = _dt.date.fromtimestamp(now)
        y, m = today.year, today.month
        months = []
        for _ in range(12):
            months.append((y, m))
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        by_m = {r["m"]: r["b"] for r in db.q(
            "SELECT substr(day,1,7) m, SUM(bytes) b FROM tr_day WHERE day>=?" + f + " GROUP BY m",
            ["%04d-%02d-01" % months[-1]] + a)}
        for y, m in reversed(months):
            out.append({"t": int(_dt.datetime(y, m, 1).timestamp()), "label": "%02d.%d" % (m, y % 100),
                        "bytes": by_m.get("%04d-%02d" % (y, m), 0)})
    else:
        raise MtpError("диапазон: 24h, 7d, 30d или 12m", "bad_range")
    return out


# ---------------------------------------------------------------- manager

def _same_time(a, b):
    return parse_rfc3339(a) == parse_rfc3339(b)


def _user_key(u):
    for l in (u.get("links") or {}).get("tls") or []:
        k = key_from_link(l)
        if k:
            return k
    return None


def _own_devices(u):
    eff = ((u.get("limits") or {}).get("desired") or {}).get("max_unique_ips")
    if isinstance(eff, dict):
        return eff.get("configured_override") or None
    return u.get("max_unique_ips") or None


def _create_body(c):
    body = {"username": c["name"], "secret": c["key"]}
    if c["expires"]:
        body["expiration_rfc3339"] = c["expires"]
    if c["quota_bytes"]:
        body["data_quota_bytes"] = c["quota_bytes"]
        if c["quota_period"]:
            body["quota_period"] = c["quota_period"]
    if c["max_devices"]:
        body["max_unique_ips"] = c["max_devices"]
    return body


def _diff(c, u):
    d = {}
    if _user_key(u) != c["key"]:
        d["secret"] = c["key"]
    if not _same_time(u.get("expiration_rfc3339"), c["expires"]):
        d["expiration_rfc3339"] = c["expires"] or None
    if (u.get("data_quota_bytes") or None) != (c["quota_bytes"] or None):
        d["data_quota_bytes"] = c["quota_bytes"] or None
    want_p = c["quota_period"] if c["quota_bytes"] else None
    if (u.get("quota_period") or None) != want_p:
        d["quota_period"] = want_p
    if _own_devices(u) != (c["max_devices"] or None):
        d["max_unique_ips"] = c["max_devices"] or None
    return d


def _upath(name, suffix=""):
    return "/v1/users/" + urllib.parse.quote(name) + suffix


class Manager:
    def __init__(self, db=None):
        self.db = db or Store()
        self.errors = {}          # server id -> message (telemt unreachable, sync failed)

    def close(self):
        self.db.close()

    # ------------------------------------------------------------ servers
    def servers(self, enabled_only=False):
        rows = self.db.q("SELECT * FROM servers ORDER BY sort, created, id")
        out = [_server_from_row(r) for r in rows]
        return [s for s in out if s["enabled"]] if enabled_only else out

    def server(self, ref):
        ref = (ref or "").strip()
        r = self.db.q1("SELECT * FROM servers WHERE id=?", (ref,))
        if r:
            return _server_from_row(r)
        for s in self.servers():              # COLLATE NOCASE в SQLite не знает кириллицу
            if s["title"].casefold() == ref.casefold():
                return s
        raise MtpError("нет такого сервера: %s" % ref, "bad_server", 404)

    def default_server_id(self):
        v = self.db.meta("default_server")
        ids = [s["id"] for s in self.servers()]
        if v in ids:
            return v
        en = [s["id"] for s in self.servers(enabled_only=True)]
        return (en or ids or [None])[0]

    def api(self, s, timeout=10):
        return TelemtAPI("http://127.0.0.1:%d" % s["api_port"], "Bearer " + s["api_token"], timeout)

    def master_addr(self):
        return self.db.meta("master_addr") or ""

    def slave_command(self, s):
        return "bash install.sh slave --master %s --port %d" % (self.master_addr() or "<IP-мастера>", s["port"])

    def _resolve_servers(self, refs):
        out = []
        for r in refs:
            sid = self.server(r)["id"]
            if sid not in out:
                out.append(sid)
        return out

    def _alloc_port(self, col, first, host):
        used = {r[0] for r in self.db.q("SELECT %s FROM servers" % col)} | RESERVED_PORTS
        p = first
        while p in used or not _port_free(p, host):
            p += 1
            if p > first + 500:
                raise MtpError("не нашлось свободного порта", "no_port")
        return p

    def _check_unique(self, sid, title=None, domain=None, entry_ip=None):
        if domain is not None and domain == self.db.meta("panel_domain"):
            raise MtpError("этот домен занят кабинетом", "exists")
        if title is not None and any(s["title"].casefold() == title.casefold() and s["id"] != sid
                                     for s in self.servers()):
            raise MtpError("сервер с таким названием уже есть", "exists")
        for col, val, msg in (
                              ("domain", domain, "этот домен уже занят другим сервером"),
                              ("entry_ip", entry_ip, "этот IP уже занят другим сервером: входной хост пересылает "
                                                      "443 только на один сервер")):
            if val is None:
                continue
            r = self.db.q1("SELECT id FROM servers WHERE %s=? AND id<>?" % col, (val, sid or ""))
            if r:
                raise MtpError(msg, "exists")

    def server_add(self, title, domain, entry_ip, extra_sni=None, default_devices=None, note="", sid=None,
                   port=None, api_port=None, enabled=True):
        title, domain, entry_ip = check_title(title), check_domain(domain), check_ip(entry_ip)
        extra = [x for x in parse_sni_list(extra_sni) if x != domain]
        dev = _opt_int(default_devices, "устройств")
        if sid:
            if not SERVER_ID_RE.match(sid):
                raise MtpError("id сервера: латиница в нижнем регистре, цифры, дефис", "bad_server")
            if self.db.q1("SELECT 1 FROM servers WHERE id=?", (sid,)):
                raise MtpError("сервер %s уже есть" % sid, "exists")
        else:
            n = 1
            while self.db.q1("SELECT 1 FROM servers WHERE id=?", ("s%d" % n,)):
                n += 1
            sid = "s%d" % n
        self._check_unique(sid, title, domain, entry_ip)
        port = port or self._alloc_port("port", PORT_FIRST, "0.0.0.0")
        api_port = api_port or self._alloc_port("api_port", API_PORT_FIRST, "127.0.0.1")
        with self.db.tx():
            sort = (self.db.q1("SELECT COALESCE(MAX(sort),0)+1 m FROM servers")["m"])
            self.db.x("INSERT INTO servers(id, title, domain, entry_ip, extra_sni, port, api_port, api_token, "
                      "reserve_key, default_devices, enabled, note, created, sort) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (sid, title, domain, entry_ip, ",".join(extra), int(port), int(api_port),
                       secrets.token_hex(24), secrets.token_hex(16), dev, 1 if enabled else 0,
                       (note or "").strip(), iso(utcnow()), sort))
            if not self.db.meta("default_server"):
                self.db.set_meta("default_server", sid)
        request_apply("server add " + sid)
        return self.server(sid)

    def server_update(self, ref, title=KEEP, domain=KEEP, entry_ip=KEEP, extra_sni=KEEP, default_devices=KEEP,
                      note=KEEP, enabled=KEEP, make_default=False):
        s = self.server(ref)
        f = {}
        if title is not KEEP:
            f["title"] = check_title(title)
        if domain is not KEEP:
            f["domain"] = check_domain(domain)
        if entry_ip is not KEEP:
            f["entry_ip"] = check_ip(entry_ip)
        if extra_sni is not KEEP:
            dom = f.get("domain", s["domain"])
            f["extra_sni"] = ",".join(x for x in parse_sni_list(extra_sni) if x != dom)
        if default_devices is not KEEP:
            f["default_devices"] = _opt_int(default_devices, "устройств")
        if note is not KEEP:
            f["note"] = (note or "").strip()
        if enabled is not KEEP:
            f["enabled"] = 1 if enabled else 0
        self._check_unique(s["id"], f.get("title"), f.get("domain"), f.get("entry_ip"))
        with self.db.tx():
            if f:
                self.db.x("UPDATE servers SET %s WHERE id=?" % ", ".join("%s=?" % k for k in f),
                          list(f.values()) + [s["id"]])
            if make_default:
                self.db.set_meta("default_server", s["id"])
        new = self.server(s["id"])
        if conf_hash(new) != conf_hash(s):
            request_apply("server edit " + s["id"])
        elif "default_devices" in f and new["enabled"]:
            self.sync([s["id"]])
        return new

    def server_delete(self, ref):
        s = self.server(ref)
        with self.db.tx():
            self.db.x("DELETE FROM servers WHERE id=?", (s["id"],))
            self.db.x("DELETE FROM server_state WHERE server=?", (s["id"],))
            if self.db.meta("default_server") == s["id"]:
                self.db.set_meta("default_server", None)
        request_apply("server delete " + s["id"])

    def server_state(self, sid):
        r = self.db.q1("SELECT * FROM server_state WHERE server=?", (sid,))
        if not r:
            return {"applied": None, "checked": None, "checks": [], "cert_try": None}
        d = dict(r)
        try:
            d["checks"] = json.loads(d.get("checks") or "[]")
        except ValueError:
            d["checks"] = []
        return d

    def set_server_state(self, sid, **fields):
        if "checks" in fields:
            fields["checks"] = json.dumps(fields["checks"], ensure_ascii=False)
        with self.db.tx():
            self.db.x("INSERT INTO server_state(server) VALUES(?) ON CONFLICT(server) DO NOTHING", (sid,))
            self.db.x("UPDATE server_state SET %s WHERE server=?" % ", ".join("%s=?" % k for k in fields),
                      list(fields.values()) + [sid])

    def servers_info(self):
        default = self.default_server_id()
        counts = {}
        for r in self.db.q("SELECT server, client FROM access"):
            counts.setdefault(r["server"], set()).add(r["client"])
        out = []
        try:
            with open(os.path.join(TEMPLATES, "telemt.toml.tmpl"), encoding="utf-8") as f:
                tmpl = f.read()
        except OSError:
            tmpl = None
        for s in self.servers():
            row = public_server(s)
            st = self.server_state(s["id"])
            row.update({"default": s["id"] == default, "endpoints": server_endpoints(s),
                        "clients": len(counts.get(s["id"], ())), "online": 0,
                        "checks": st["checks"], "checked": st["checked"],
                        "pending": (tmpl is not None and st["applied"] != conf_hash(s, tmpl)),
                        "slave_cmd": self.slave_command(s)})
            if s["enabled"]:
                api = self.api(s, timeout=5)
                for key, path in (("health", "/v1/health"), ("info", "/v1/system/info"),
                                  ("summary", "/v1/stats/summary")):
                    try:
                        row[key] = api.call("GET", path)
                    except MtpError as e:
                        row[key] = {"error": e.message}
                try:
                    users = api.call("GET", "/v1/users") or []
                    row["online"] = sum(1 for u in users if not _hidden(u["username"])
                                        and int(u.get("current_connections") or 0) > 0)
                except MtpError:
                    pass
            out.append(row)
        return out

    # ------------------------------------------------------------ telemt sync
    def _fetch(self, s):
        return {u["username"]: u for u in (self.api(s).call("GET", "/v1/users") or []) if not _hidden(u["username"])}

    def _live(self, servers):
        """{server_id: {name: UserInfo}} for reachable enabled servers; others go to self.errors."""
        out = {}
        for s in servers:
            if not s["enabled"]:
                continue
            try:
                out[s["id"]] = self._fetch(s)
                self.errors.pop(s["id"], None)
            except MtpError as e:
                self.errors[s["id"]] = e.message
        return out

    def _clients_of(self, sid):
        return {r["name"]: dict(r) for r in self.db.q(
            "SELECT c.* FROM clients c JOIN access a ON a.client=c.name WHERE a.server=?", (sid,))}

    def sync_server(self, s, users=None):
        """Bring one telemt instance to the database. Returns the number of changes."""
        api = self.api(s)
        if users is None:
            users = self._fetch(s)
        desired = self._clients_of(s["id"])
        changes, errs = 0, []
        for name, c in desired.items():
            u = users.get(name)
            try:
                if u is None:
                    api.call("POST", "/v1/users", _create_body(c))
                    if not c["enabled"]:
                        api.call("POST", _upath(name, "/disable"))
                    changes += 1
                    continue
                d = _diff(c, u)
                if d:
                    api.call("PATCH", _upath(name), d)
                    changes += 1
                if bool(u.get("enabled", True)) != bool(c["enabled"]):
                    api.call("POST", _upath(name, "/enable" if c["enabled"] else "/disable"))
                    changes += 1
            except MtpError as e:
                errs.append("%s: %s" % (name, e.message))
        for name in users:
            if name not in desired:
                try:
                    api.call("DELETE", _upath(name))
                    changes += 1
                except MtpError as e:
                    if e.code != "not_found":
                        errs.append("%s: %s" % (name, e.message))
        try:
            pol = (api.call("GET", "/v1/access/policy") or {}).get("desired") or {}
            want = s["default_devices"] or 0
            if int(pol.get("user_max_unique_ips_global_each") or 0) != want:
                api.call("PATCH", "/v1/access/policy", {"user_max_unique_ips_global_each": want or None})
                changes += 1
        except MtpError as e:
            errs.append("лимит устройств: " + e.message)
        if errs:
            raise MtpError("не всё применилось: " + "; ".join(errs[:3]), "sync_partial", 502)
        return changes

    def sync(self, server_ids=None):
        """Sync the given (or all enabled) servers; failures are kept in self.errors (retried every minute)."""
        for s in self.servers(enabled_only=True):
            if server_ids is not None and s["id"] not in server_ids:
                continue
            try:
                self.sync_server(s)
                self.errors.pop(s["id"], None)
            except MtpError as e:
                self.errors[s["id"]] = e.message

    def _known(self):
        return {r["name"] for r in self.db.q("SELECT name FROM clients")}

    def collect(self):
        """Once a minute (mtpctl-web): sync every enabled server and record traffic."""
        known = self._known()
        for s in self.servers(enabled_only=True):
            try:
                users = self._fetch(s)
            except MtpError as e:
                self.errors[s["id"]] = e.message
                continue
            try:
                collect_traffic(self.db, s["id"], users, known)
            except sqlite3.Error as e:
                self.errors[s["id"]] = "трафик: %s" % e
            try:
                self.sync_server(s, users)
                self.errors.pop(s["id"], None)
            except MtpError as e:
                self.errors[s["id"]] = e.message

    # ------------------------------------------------------------ clients: views
    def _client_row(self, name):
        check_name(name)
        r = self.db.q1("SELECT * FROM clients WHERE name=?", (name,))
        if not r:
            raise MtpError("клиент не найден", "not_found", 404)
        return dict(r)

    def _access(self):
        order = {s["id"]: i for i, s in enumerate(self.servers())}
        acc = {}
        for r in self.db.q("SELECT client, server FROM access"):
            acc.setdefault(r["client"], []).append(r["server"])
        for v in acc.values():
            v.sort(key=lambda x: order.get(x, 999))
        return acc

    def _view(self, c, sids, live, tr, by_id):
        name = c["name"]
        rows = {sid: live[sid][name] for sid in sids if sid in live and name in live[sid]}
        exp = parse_rfc3339(c["expires"])
        now = utcnow()
        state = "disabled" if not c["enabled"] else ("expired" if exp and exp <= now else "active")
        conns = sum(int(u.get("current_connections") or 0) for u in rows.values())
        ips = sorted({ip for u in rows.values() for ip in (u.get("active_unique_ips_list") or [])})
        mine = tr.get(name, {})
        since = [t["online_since"] for t in mine.values() if t["online_since"]]
        seen = [t["last_seen"] for t in mine.values() if t["last_seen"]]
        total = 0
        for sid in set(mine) | set(rows):
            total += max(int((mine.get(sid) or {}).get("total") or 0),
                         int((rows.get(sid) or {}).get("total_octets") or 0))
        defaults = {by_id[sid]["default_devices"] for sid in sids if sid in by_id}
        links = []
        for sid in sids:
            s = by_id.get(sid)
            if s:
                for l in make_links(c["key"], server_endpoints(s)):
                    l["server_id"], l["server_title"] = sid, s["title"]
                    links.append(l)
        return {
            "name": name,
            "note": c["note"],
            "created": c["created"],
            "servers": sids,
            "enabled": bool(c["enabled"]),
            "state": state,
            "expires": c["expires"],
            "days_left": (None if not exp else max(0, (exp - now).days)),
            "quota_bytes": c["quota_bytes"],
            "quota_period": c["quota_period"],
            "max_devices": c["max_devices"],
            "devices_limit": c["max_devices"] or (defaults.pop() if len(defaults) == 1 else None),
            "connections": conns,
            "active_ips": ips,
            "online": conns > 0,
            "online_since": min(since) if since else None,
            "last_seen": max(seen) if seen else None,
            "total_bytes": total,
            "pending": [sid for sid in sids if sid in live and name not in live[sid]],
            "links": links,
        }

    def _views(self, clients, collect=True):
        servers = self.servers()
        by_id = {s["id"]: s for s in servers}
        acc = self._access()
        need = {sid for c in clients for sid in acc.get(c["name"], [])}
        live = self._live([s for s in servers if s["id"] in need])
        if collect:
            known = self._known()
            for sid, users in live.items():
                with contextlib.suppress(sqlite3.Error):
                    collect_traffic(self.db, sid, users, known)
        tr = {}
        for r in self.db.q("SELECT * FROM tr_state"):
            tr.setdefault(r["client"], {})[r["server"]] = dict(r)
        return [self._view(c, acc.get(c["name"], []), live, tr, by_id) for c in clients]

    def list(self):
        return self._views([dict(r) for r in self.db.q("SELECT * FROM clients ORDER BY name")])

    def get(self, name):
        return self._views([self._client_row(name)])[0]

    def traffic_report(self, name=None, rng="24h", server=None):
        if name:
            self._client_row(name)
        if server:
            server = self.server(server)["id"]
        live = self._live(self.servers(enabled_only=True))
        known = self._known()
        for sid, users in live.items():
            with contextlib.suppress(sqlite3.Error):
                collect_traffic(self.db, sid, users, known)
        return {"name": name, "server": server, "range": rng,
                "periods": traffic_periods(self.db, name, server),
                "series": traffic_series(self.db, rng, name, server)}

    # ------------------------------------------------------------ clients: changes
    def add(self, name, servers=None, expires=None, note="", quota=None, period=None, devices=None, key=None,
            enabled=True):
        check_name(name)
        if _hidden(name):
            raise MtpError("имя не может начинаться с «_»", "bad_name")
        if self.db.q1("SELECT 1 FROM clients WHERE name=?", (name,)):
            raise MtpError("клиент с таким именем уже есть", "user_exists")
        if servers:
            sids = self._resolve_servers(servers)
        else:
            d = self.default_server_id()
            if not d:
                raise MtpError("сначала добавьте сервер", "no_server")
            sids = [d]
        if key:
            key = key.strip().lower()
            if not KEY_RE.match(key):
                raise MtpError("ключ: ровно 32 hex-символа", "bad_key")
        else:
            key = secrets.token_hex(16)
        exp = parse_expiry(expires) or None
        q = parse_size(quota)
        per = _check_period(period) if (q and period) else None
        dev = _opt_int(devices, "устройств")
        with self.db.tx():
            self.db.x("INSERT INTO clients(name, key, note, created, enabled, expires, quota_bytes, quota_period, "
                      "max_devices) VALUES(?,?,?,?,?,?,?,?,?)",
                      (name, key, (note or "").strip(), iso(utcnow()), 1 if enabled else 0, exp, q, per, dev))
            for sid in sids:
                self.db.x("INSERT INTO access(client, server) VALUES(?,?)", (name, sid))
        self.sync(sids)
        return self.get(name)

    def update(self, name, servers=KEEP, note=KEEP, expires=KEEP, quota=KEEP, period=KEEP, devices=KEEP,
               enabled=KEEP, key=KEEP):
        c = self._client_row(name)
        f = {}
        if note is not KEEP:
            f["note"] = (note or "").strip()
        if expires is not KEEP:
            base = parse_rfc3339(c["expires"]) if str(expires or "").startswith("+") else None
            exp = parse_expiry(expires or "never", base=base)
            f["expires"] = exp or None
        if quota is not KEEP:
            f["quota_bytes"] = parse_size(quota)
            if f["quota_bytes"] is None:
                f["quota_period"] = None
        if period is not KEEP:
            has_quota = f["quota_bytes"] if "quota_bytes" in f else c["quota_bytes"]
            f["quota_period"] = _check_period(period) if (period and has_quota) else None
        if devices is not KEEP:
            f["max_devices"] = _opt_int(devices, "устройств")
        if enabled is not KEEP:
            f["enabled"] = 1 if enabled else 0
        if key is not KEEP:
            key = (key or "").strip().lower()
            if not KEY_RE.match(key):
                raise MtpError("ключ: ровно 32 hex-символа", "bad_key")
            f["key"] = key
        old = [r["server"] for r in self.db.q("SELECT server FROM access WHERE client=?", (name,))]
        new = old
        if servers is not KEEP:
            new = self._resolve_servers(servers or [])
            if not new:
                raise MtpError("выберите хотя бы один сервер", "bad_server")
        with self.db.tx():
            if f:
                self.db.x("UPDATE clients SET %s WHERE name=?" % ", ".join("%s=?" % k for k in f),
                          list(f.values()) + [name])
            for sid in set(old) - set(new):
                self.db.x("DELETE FROM access WHERE client=? AND server=?", (name, sid))
            for sid in set(new) - set(old):
                self.db.x("INSERT INTO access(client, server) VALUES(?,?)", (name, sid))
        self.sync(set(old) | set(new))
        return self.get(name)

    def set_expiry(self, name, expires):
        if expires in (None, ""):
            raise MtpError("укажите срок", "bad_expiry")
        return self.update(name, expires=expires)

    def set_limits(self, name, quota="keep", period="keep", devices="keep"):
        kw = {}
        if quota != "keep":
            kw["quota"] = quota
        if period != "keep":
            kw["period"] = period
        if devices != "keep":
            kw["devices"] = devices
        return self.update(name, **kw)

    def set_note(self, name, note):
        return self.update(name, note=note)

    def set_servers(self, name, servers):
        return self.update(name, servers=servers)

    def enable(self, name, on=True):
        return self.update(name, enabled=on)

    def rotate(self, name):
        return self.update(name, key=secrets.token_hex(16))

    def reset_quota(self, name):
        self._client_row(name)
        by_id = {s["id"]: s for s in self.servers(enabled_only=True)}
        for r in self.db.q("SELECT server FROM access WHERE client=?", (name,)):
            s = by_id.get(r["server"])
            if s:
                try:
                    self.api(s).call("POST", _upath(name, "/reset-quota"))
                except MtpError as e:
                    if e.code != "not_found":
                        self.errors[s["id"]] = e.message
        return self.get(name)

    def delete(self, name):
        self._client_row(name)
        sids = [r["server"] for r in self.db.q("SELECT server FROM access WHERE client=?", (name,))]
        with self.db.tx():
            self.db.x("DELETE FROM clients WHERE name=?", (name,))
            for t in ("tr_state", "tr_slot", "tr_day"):
                self.db.x("DELETE FROM %s WHERE client=?" % t, (name,))
        self.sync(sids)

    # ------------------------------------------------------------ admin credentials (panel)
    def auth(self):
        return {"user": self.db.meta("admin_user"), "hash": self.db.meta("admin_hash"),
                "epoch": int(self.db.meta("admin_epoch", "0"))}

    def base_path(self):
        return self.db.meta("web_base_path") or ""

    def panel_domain(self):
        return self.db.meta("panel_domain") or ""

    def panel_urls(self):
        b = self.base_path()
        if not b:
            return []
        if self.panel_domain():
            return ["https://%s/%s/" % (self.panel_domain(), b)]
        return ["https://%s/%s/" % (s["domain"], b) for s in self.servers(enabled_only=True)]

    def set_panel_domain(self, domain):
        """Отдельный домен кабинета (A-запись на мастер); пусто — кабинет на доменах серверов."""
        domain = check_domain(domain) if (domain or "").strip() else None
        if domain and self.db.q1("SELECT 1 FROM servers WHERE domain=?", (domain,)):
            raise MtpError("этот домен уже занят сервером: для кабинета нужен отдельный", "exists")
        self.db.set_meta("panel_domain", domain)
        request_apply("panel domain")
        return domain or ""

    def set_base_path(self, path=None):
        path = check_base_path(path) if path else random_string(18)
        self.db.set_meta("web_base_path", path)
        request_apply("base path")
        return path

    def panel_checks(self):
        try:
            return json.loads(self.db.meta("panel_checks") or "[]")
        except ValueError:
            return []

    def set_auth(self, user, pw_hash):
        with self.db.tx():
            self.db.set_meta("admin_user", user)
            self.db.set_meta("admin_hash", pw_hash)
            self.db.set_meta("admin_epoch", int(self.db.meta("admin_epoch", "0")) + 1)
