# -*- coding: utf-8 -*-
"""mtpctl agent (root): bring the master host to the database.

Runs as `mtpctl apply` from mtpctl-agent.service: on every change made in the panel
(mtpctl-agent.path watches /opt/mtpctl/data/apply.req) and every 10 minutes (timer).
The panel itself never runs anything as root; it only writes the desired state to the
database. This module validates values again before using them.

What it manages (and nothing else):
  * /etc/telemt/<id>.toml + telemt@<id>   — one telemt instance per server;
  * ufw rules commented "mtpctl:<id>"      — telemt port and 80 only from the server's entry IP;
  * /etc/nginx/conf.d/mtp-<domain>.conf    — cover site (login page + panel) per domain;
  * /etc/nginx/stream.d/mtp-mask.conf      — extra SNI masks (e.g. ya.ru) -> the real site;
  * Let's Encrypt certificates for server domains (webroot, through the entry host's port 80);
  * server_state in the database: applied config hash and health checks shown in the panel.
"""
import contextlib
import glob
import hashlib
import html
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
from core import MtpError  # noqa: E402

TELEMT_DIR = "/etc/telemt"
TELEMT_DATA = "/var/lib/telemt"
NGINX_SITES = "/etc/nginx/conf.d"
NGINX_STREAM = "/etc/nginx/stream.d"
MASK_CONF = os.path.join(NGINX_STREAM, "mtp-mask.conf")
SNIPPET = "/etc/nginx/snippets/mtpanel.conf"
PANEL_SNIPPET = "/etc/nginx/snippets/mtpanel-direct.conf"
PANEL_CONF = os.path.join(NGINX_SITES, "mtp-panel.conf")
WEBROOT = "/var/www/mtpctl"
FALLBACK_CERT = "/etc/nginx/mtpctl-fallback.crt"
FALLBACK_KEY = "/etc/nginx/mtpctl-fallback.key"
REMOVED_DIR = os.path.join(core.HOME, "backup", "removed")
CERT_RETRY = 30 * 60
MARKER = "# mtpctl: server "


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def run(cmd, check=True, timeout=120):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                       timeout=timeout)
    if check and p.returncode != 0:
        raise MtpError("%s: %s" % (" ".join(cmd[:3]), (p.stdout or "").strip()[-400:]))
    return p


def _write(path, text, mode=0o644, owner=None):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, ".%s.tmp" % os.path.basename(path))
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    if owner:
        shutil.chown(tmp, owner, owner)
    os.replace(tmp, path)


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (FileNotFoundError, UnicodeDecodeError):
        return None


def _stash(path, copy=False):
    """Move (or copy) a file we are about to replace/remove into backup/removed/."""
    os.makedirs(REMOVED_DIR, mode=0o700, exist_ok=True)
    dest = os.path.join(REMOVED_DIR, "%s.%s" % (os.path.basename(path), time.strftime("%Y%m%d%H%M%S")))
    (shutil.copy2 if copy else shutil.move)(path, dest)
    return dest


def _unit_active(unit):
    return run(["systemctl", "is-active", unit], check=False).stdout.strip() == "active"


# ---------------------------------------------------------------- telemt

def _wait_api(m, s, timeout=45):
    api = m.api(s, timeout=3)
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            api.call("GET", "/v1/health")
            return True
        except MtpError:
            time.sleep(1)
    return False


def _sync_after_start(m, s):
    for i in range(5):
        try:
            n = m.sync_server(s)
            log("  %s: клиенты синхронизированы (%d изм.)" % (s["id"], n))
            return
        except MtpError as e:
            last = e.message
            time.sleep(2)
    log("  %s: синхронизация не удалась: %s" % (s["id"], last))


def apply_telemt(m, s, tmpl):
    unit = "telemt@%s" % s["id"]
    conf = os.path.join(TELEMT_DIR, s["id"] + ".toml")
    h = core.conf_hash(s, tmpl)
    st = m.server_state(s["id"])
    if not s["enabled"]:
        if _unit_active(unit) or run(["systemctl", "is-enabled", unit], check=False).stdout.strip() == "enabled":
            run(["systemctl", "disable", "--now", unit], check=False)
            log("  %s: отключён, %s остановлен" % (s["id"], unit))
        m.set_server_state(s["id"], applied=h)
        return
    if st["applied"] != h or not os.path.exists(conf):
        os.makedirs(TELEMT_DIR, exist_ok=True)
        data = os.path.join(TELEMT_DATA, s["id"])
        os.makedirs(data, exist_ok=True)
        shutil.chown(data, "telemt", "telemt")
        if os.path.exists(conf) and st["applied"] is None:
            log("  %s: прежний конфиг сохранён в %s" % (s["id"], _stash(conf, copy=True)))
        _write(conf, core.render_telemt_conf(s, tmpl), 0o600, "telemt")
        run(["systemctl", "enable", unit], check=False)
        run(["systemctl", "restart", unit])
        log("  %s: конфиг записан, %s перезапущен" % (s["id"], unit))
        if not _wait_api(m, s):
            raise MtpError("%s не поднял API за 45 с — journalctl -u %s" % (unit, unit))
        _sync_after_start(m, s)
        m.set_server_state(s["id"], applied=h)
    elif not _unit_active(unit):
        run(["systemctl", "enable", "--now", unit])
        log("  %s: %s был остановлен — запущен" % (s["id"], unit))
        if _wait_api(m, s):
            _sync_after_start(m, s)


def remove_orphans(servers):
    ids = {s["id"] for s in servers}
    for conf in glob.glob(os.path.join(TELEMT_DIR, "*.toml")):
        sid = os.path.basename(conf)[:-5]
        if sid in ids or not core.SERVER_ID_RE.match(sid):
            continue
        head = (_read(conf) or "")[:200]
        if MARKER not in head:
            continue                      # не наш файл
        run(["systemctl", "disable", "--now", "telemt@%s" % sid], check=False)
        log("  %s: сервер удалён — telemt@%s остановлен, конфиг -> %s" % (sid, sid, _stash(conf)))


# ---------------------------------------------------------------- firewall

RULE_RE = re.compile(r"^(\d+)/tcp\s+ALLOW(?: IN)?\s+(\d+\.\d+\.\d+\.\d+)\s+#\s*(mtpctl:\S+)", re.M)


def apply_firewall(servers):
    if not shutil.which("ufw"):
        return "none"
    out = run(["ufw", "status"], check=False).stdout
    if "Status: active" not in out:
        return "inactive"
    verbose = run(["ufw", "status", "verbose"], check=False).stdout
    policy = "allow" if re.search(r"Default:\s*allow \(incoming\)", verbose) else "deny"
    want = set()
    for s in servers:
        if s["enabled"]:
            want.add((s["port"], s["entry_ip"], "mtpctl:" + s["id"]))
            want.add((80, s["entry_ip"], "mtpctl:%s:http" % s["id"]))
    have = {(int(p), ip, c) for p, ip, c in RULE_RE.findall(out)}
    for port, ip, c in sorted(want - have):
        run(["ufw", "allow", "proto", "tcp", "from", ip, "to", "any", "port", str(port), "comment", c])
        log("  ufw: %s/tcp от %s (%s)" % (port, ip, c))
    for port, ip, c in sorted(have - want):
        if (port, ip) in {(p, i) for p, i, _ in want}:
            continue
        run(["ufw", "delete", "allow", "proto", "tcp", "from", ip, "to", "any", "port", str(port)], check=False)
        log("  ufw: убрано %s/tcp от %s (%s)" % (port, ip, c))
    return "active" if policy == "deny" else "allow-default"


# ---------------------------------------------------------------- nginx + certificates

def _le(domain):
    live = "/etc/letsencrypt/live/%s" % domain
    if os.path.exists(live + "/fullchain.pem") and os.path.exists(live + "/privkey.pem"):
        return live + "/fullchain.pem", live + "/privkey.pem"
    return None


def ensure_fallback_cert():
    if os.path.exists(FALLBACK_CERT) and os.path.exists(FALLBACK_KEY):
        return
    run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "3650", "-subj", "/CN=localhost",
         "-keyout", FALLBACK_KEY, "-out", FALLBACK_CERT])
    os.chmod(FALLBACK_KEY, 0o600)


def _resolvers():
    out = []
    for line in (_read("/etc/resolv.conf") or "").splitlines():
        m = re.match(r"^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
        if m and not m.group(1).startswith("127."):
            out.append(m.group(1))
    return out or ["8.8.8.8", "1.1.1.1"]


_NGINX_VER = []


def nginx_version():
    if not _NGINX_VER:
        try:
            out = subprocess.run(["nginx", "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 universal_newlines=True).stdout
            m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out)
            _NGINX_VER.append(tuple(int(x) for x in m.groups()) if m else (0, 0, 0))
        except OSError:
            _NGINX_VER.append((0, 0, 0))
    return _NGINX_VER[0]


def _listen(addr, extra=""):
    if nginx_version() >= (1, 25, 1):          # «listen … http2» устарел
        return "listen %s ssl%s;\n    http2 on;" % (addr, extra)
    return "listen %s ssl http2%s;" % (addr, extra)


def render_site(domain, panel=False):
    """Домен сервера (за telemt, PROXY v1 на 127.0.0.1:8446) или домен кабинета (прямо на 443)."""
    if panel:
        t = _tmpl("panel-site.conf.tmpl").replace("{{LISTEN}}", _listen("443"))
    else:
        t = _tmpl("mtp-site.conf.tmpl").replace("{{LISTEN}}", _listen("127.0.0.1:8446", " proxy_protocol"))
    cert, key = _le(domain) or (FALLBACK_CERT, FALLBACK_KEY)
    return t.replace("{{DOMAIN}}", domain).replace("{{CERT}}", cert).replace("{{KEY}}", key)


def _tmpl(name):
    with open(os.path.join(core.TEMPLATES, name), encoding="utf-8") as f:
        return f.read()


def render_snippet(m, direct=False):
    """direct=False — домены серверов (через telemt); direct=True — домен кабинета."""
    t = _tmpl("mtpanel.conf.tmpl")
    base = m.base_path()
    if direct:
        t = re.sub(r"(?s)# ---- realip.*?(?=# ---- общее)", "", t)
    if base and (direct or not m.panel_domain()):
        t = t.replace("{{BASE}}", core.check_base_path(base))
    else:                                     # кабинет не здесь — только заставка
        t = re.sub(r"(?s)# ---- кабинет.*?(?=# ---- заставка)", "", t)
    if direct:                                # домен кабинета: кроме пути кабинета — «сайта нет»
        t = re.sub(r"(?s)# ---- заставка.*", "# ---- всё остальное: стандартный 404 nginx\nlocation / { return 404; }\n", t)
    return t.replace("{{GENERATED}}", "Сгенерировано mtpctl agent из mtpanel.conf.tmpl; не править.")


def render_index(m):
    brand = re.sub(r"[^A-Za-z0-9 ._-]", "", m.brand())[:24] or "console"
    return (_tmpl("index.html.tmpl").replace("{{BRAND}}", brand).replace("{{YEAR}}", time.strftime("%Y"))
            .replace("{{GENERATED}}", "generated by mtpctl"))


# ---------------------------------------------------------------- cover sites (заставки)

BG_DIR = os.path.join(WEBROOT, "bg")
BG_LIST = os.path.join(BG_DIR, "list.json")
BG_POOL = 40                 # фото в общем наборе
BG_PER_DAY = 8               # сколько новых докачивать за раз
BG_PER_SITE = 12             # подборка одного домена
BG_REFRESH = 20 * 3600
BG_UA = "mtpctl-cover/1.0 (+https://github.com/mittus/mtpctl; wallpaper cache) python-urllib"
COMMONS_API = "https://commons.wikimedia.org/w/api.php"


def _web_dir(path):
    """Каталог под веб-корнем, читаемый nginx (агент работает с umask 007)."""
    os.makedirs(path, exist_ok=True)
    p = path
    while p.startswith(WEBROOT):
        os.chmod(p, 0o755)
        p = os.path.dirname(p)
    return path


def _bg_list():
    try:
        with open(BG_LIST, encoding="utf-8") as f:
            data = json.load(f)
        return [p for p in data if isinstance(p, dict) and re.match(r"^[0-9a-f]{16}\.jpg$", p.get("f", ""))
                and os.path.exists(os.path.join(BG_DIR, p["f"]))]
    except (OSError, ValueError):
        return []


def _http_get(url, limit, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": BG_UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise OSError("слишком большой ответ")
    return data


def _strip_html(v):
    v = re.sub(r"<[^>]+>", "", v or "")
    return re.sub(r"\s+", " ", html.unescape(v)).strip()[:80]


def _potd(day):
    """Picture of the day on Wikimedia Commons for a date: landscape JPEG, 1920 px wide, or None."""
    q = urllib.parse.urlencode({
        "action": "query", "format": "json", "generator": "images", "titles": "Template:Potd/" + day,
        "prop": "imageinfo", "iiprop": "url|size|mime|extmetadata", "iiurlwidth": "1920",
        "iiextmetadatafilter": "Artist|LicenseShortName"})
    data = json.loads(_http_get(COMMONS_API + "?" + q, 2 * 1024 * 1024).decode())
    for page in ((data.get("query") or {}).get("pages") or {}).values():
        for ii in page.get("imageinfo") or []:
            w, h = ii.get("width") or 0, ii.get("height") or 1
            if ii.get("mime") != "image/jpeg" or w < 1920 or w < 1.3 * h or w > 3.2 * h:
                continue
            thumb = (ii.get("thumburl") or "").split("?")[0]
            if not thumb.startswith("https://") or "wikimedia.org/" not in thumb:
                continue
            md = ii.get("extmetadata") or {}
            return {"url": thumb, "a": _strip_html((md.get("Artist") or {}).get("value")) or "Wikimedia Commons",
                    "l": _strip_html((md.get("LicenseShortName") or {}).get("value")),
                    "s": ii.get("descriptionurl") or "https://commons.wikimedia.org/"}
    return None


def refresh_backgrounds(force=False):
    """Докачать фото дня с Wikimedia Commons в общий набор (раз в сутки, без сети — молча пропускаем)."""
    import datetime as _dt
    import random as _rnd
    _web_dir(BG_DIR)
    pool = _bg_list()
    try:
        age = time.time() - os.path.getmtime(BG_LIST)
    except OSError:
        age = 1e9
    if not force and age < BG_REFRESH and len(pool) >= 8:
        return
    have = {p["f"] for p in pool}
    added, tries = 0, 0
    first = _dt.date(2012, 1, 1)
    span = (_dt.date.today() - first).days
    while added < BG_PER_DAY and tries < BG_PER_DAY * 3:
        tries += 1
        day = (first + _dt.timedelta(days=_rnd.randrange(span))).isoformat()
        try:
            info = _potd(day)
            if not info:
                continue
            img = _http_get(info["url"], 3 * 1024 * 1024, timeout=40)
        except (OSError, ValueError) as e:
            log("  заставки: Wikimedia недоступна (%s)" % (getattr(e, "code", None) or e.__class__.__name__))
            break
        if not img.startswith(b"\xff\xd8\xff"):
            continue
        name = hashlib.sha256(img).hexdigest()[:16] + ".jpg"
        if name in have:
            continue
        tmp = os.path.join(BG_DIR, "." + name)
        with open(tmp, "wb") as f:
            f.write(img)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(BG_DIR, name))
        pool.append({"f": name, "a": info["a"], "l": info["l"], "s": info["s"], "t": int(time.time())})
        have.add(name)
        added += 1
        time.sleep(2)                          # бережно к Wikimedia: без пачек запросов
    pool.sort(key=lambda p: p.get("t", 0))
    for p in pool[:-BG_POOL] if len(pool) > BG_POOL else []:
        with contextlib.suppress(OSError):
            os.unlink(os.path.join(BG_DIR, p["f"]))
    pool = pool[-BG_POOL:]
    _write(BG_LIST, json.dumps(pool, ensure_ascii=False))
    keep = {p["f"] for p in pool} | {"list.json"}
    for f in os.listdir(BG_DIR):
        if f not in keep and not f.startswith("."):
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(BG_DIR, f))
    if added:
        log("  заставки: +%d фото (в наборе %d)" % (added, len(pool)))


def _seed(domain, salt=""):
    return int(hashlib.sha256((salt + domain).encode()).hexdigest(), 16)


ACCENTS = ["#e8590c", "#2f9e44", "#1c7ed6", "#ae3ec9", "#f08c00", "#0c8599", "#e03131", "#5f3dc4"]
POSITIONS = ["left:6vw;bottom:9vh", "left:50%;top:42%;transform:translate(-50%,-50%);text-align:center",
             "left:6vw;top:16vh", "right:6vw;bottom:9vh;text-align:right"]


def render_cover(domain, pool):
    """Файлы заставки одного домена: своя подборка фото, раскладка, цвет, favicon."""
    sd = _seed(domain)
    name = domain.split(".")[0]
    accent = ACCENTS[sd % len(ACCENTS)]
    photos = sorted(pool, key=lambda p: _seed(domain, p["f"]))[:BG_PER_SITE]
    hue = sd % 360
    fallback = "linear-gradient(135deg,hsl(%d,45%%,28%%),hsl(%d,55%%,12%%))" % (hue, (hue + 40) % 360)
    weight = ["200", "300", "500"][(sd >> 8) % 3]
    pjson = json.dumps([{k: p.get(k, "") for k in ("f", "a", "l", "s")} for p in photos], ensure_ascii=False)
    pjson = pjson.replace("<", "\\u003c")
    sub = {"NAME": html.escape(name), "ACCENT": accent, "FALLBACK": fallback, "WEIGHT": weight,
           "POS": POSITIONS[(sd >> 4) % len(POSITIONS)], "PHOTOS": pjson,
           "BG": ('url("/bg/%s"),' % photos[0]["f"] if photos else "") + fallback}
    out = {}
    for fn, t in (("index.html", "cover.html.tmpl"), ("404.html", "404.html.tmpl")):
        text = _tmpl(t)
        for k, v in sub.items():
            text = text.replace("{{%s}}" % k, v)
        out[fn] = text
    out["robots.txt"] = "User-agent: *\nAllow: /\n"
    out["favicon.svg"] = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" '
                          'fill="%s"/><circle cx="16" cy="16" r="6" fill="#fff" opacity=".85"/></svg>\n' % accent)
    out["favicon.ico"] = _ico(accent)
    return out


def _ico(color):
    """16×16 ICO (32 bpp): цветной круг — без внешних библиотек."""
    import struct
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    px = bytearray()
    for y in range(15, -1, -1):                       # BMP хранится снизу вверх
        for x in range(16):
            d = ((x - 7.5) ** 2 + (y - 7.5) ** 2) ** .5
            if d <= 2.6:
                px += bytes((255, 255, 255, 230))     # белая точка в центре
            elif d <= 7.2:
                px += bytes((b, g, r, 255))
            else:
                px += bytes(4)                        # прозрачно
    bmp = struct.pack("<IiiHHIIiiII", 40, 16, 32, 1, 32, 0, len(px) + 64, 0, 0, 0, 0) + bytes(px) + bytes(64)
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(bmp), 22) + bmp


def write_sites(m, servers):
    """Заставки всех доменов + страница входа в кабинет (без перезагрузки nginx)."""
    try:
        refresh_backgrounds()
    except Exception as e:  # noqa: BLE001 — заставки не должны ломать применение
        log("  заставки: %s" % e)
    pool = _bg_list()
    site_root = os.path.join(WEBROOT, "site")
    want = set()
    domains = [s["domain"] for s in servers]          # у домена кабинета заставки нет
    for dom in domains:
        d = os.path.join(site_root, dom)
        want.add(dom)
        for fn, content in render_cover(dom, pool).items():
            path = os.path.join(d, fn)
            if isinstance(content, bytes):
                old = None
                with contextlib.suppress(OSError):
                    with open(path, "rb") as f:
                        old = f.read()
                if old != content:
                    _web_dir(d)
                    with open(path + ".tmp", "wb") as f:
                        f.write(content)
                    os.chmod(path + ".tmp", 0o644)
                    os.replace(path + ".tmp", path)
            elif _read(path) != content:
                _web_dir(d)
                _write(path, content)
    if os.path.isdir(site_root):
        for dom in os.listdir(site_root):
            if dom not in want:
                shutil.rmtree(os.path.join(site_root, dom), ignore_errors=True)
    panel = os.path.join(WEBROOT, "panel", "index.html")
    text = render_index(m)
    if _read(panel) != text:
        _web_dir(os.path.dirname(panel))
        _write(panel, text)


def render_mask(servers):
    extra = sorted({x for s in servers for x in s["extra_sni"]})
    lines = ["# Сгенерировано mtpctl agent; не править. Маскировка дополнительных SNI серверов:",
             "# telemt (exclusive_mask) шлёт сюда с PROXY v1, nginx снимает его и соединяет с настоящим сайтом.",
             "map $ssl_preread_server_name $mtp_mask_upstream {"]
    lines += ["    %s %s:443;" % (x, x) for x in extra]
    lines += ["    default 127.0.0.1:1;", "}", "",
              "server {",
              "    listen 127.0.0.1:8445 proxy_protocol;",
              "    ssl_preread on;",
              "    resolver %s valid=300s ipv6=off;" % " ".join(_resolvers()),
              "    resolver_timeout 3s;",
              "    proxy_pass $mtp_mask_upstream;",
              "    proxy_connect_timeout 5s;",
              "    proxy_timeout 10m;",
              "}", ""]
    return "\n".join(lines)


def _nginx_reload(backups):
    p = run(["nginx", "-t"], check=False)
    if p.returncode != 0:
        for path, old in backups.items():          # откат: вернуть прежние файлы
            if old is None:
                with_suppress_unlink(path)
            else:
                _write(path, old)
        raise MtpError("nginx -t не прошёл, изменения отменены: " + p.stdout.strip()[-400:])
    run(["systemctl", "reload", "nginx"])


def with_suppress_unlink(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def apply_nginx(m, servers):
    ensure_fallback_cert()
    _web_dir(os.path.join(WEBROOT, ".well-known", "acme-challenge"))
    want = {os.path.join(NGINX_SITES, "mtp-%s.conf" % s["domain"]): render_site(s["domain"]) for s in servers}
    want[MASK_CONF] = render_mask(servers)
    want[SNIPPET] = render_snippet(m)
    pd = _panel_domain(m)
    if pd:
        want[PANEL_SNIPPET] = render_snippet(m, direct=True)
        want[PANEL_CONF] = render_site(pd, panel=True)
    backups, changed = {}, []
    for path, text in want.items():
        old = _read(path)
        if old != text:
            backups[path] = old
            _write(path, text)
            changed.append(os.path.basename(path))
    for path in glob.glob(os.path.join(NGINX_SITES, "mtp-*.conf")) + [PANEL_SNIPPET]:
        if path not in want and os.path.exists(path):
            backups[path] = _read(path)
            changed.append("-" + os.path.basename(path))
            _stash(path)
    if changed:
        _nginx_reload(backups)
        log("  nginx: " + ", ".join(changed))
    write_sites(m, servers)


def _panel_domain(m):
    d = m.panel_domain()
    if not d:
        return None
    try:
        return core.check_domain(d)
    except MtpError:
        log("  кабинет: неверный домен в базе — пропущен")
        return None


def host_ips(m):
    """Адреса этого хоста: публичный (адрес мастера) и локальные."""
    ips = set(run(["hostname", "-I"], check=False).stdout.split())
    addr = m.master_addr()
    if addr:
        ips |= set(dns_ips(addr)) if not re.match(r"^[0-9.]+$", addr) else {addr}
    return ips


def panel_cert(m, force=False):
    d = _panel_domain(m)
    if not d or _le(d) or not set(dns_ips(d)) & host_ips(m):
        return
    last = float(m.db.meta("panel_cert_try") or 0)
    if not force and time.time() - last < CERT_RETRY:
        return
    m.db.set_meta("panel_cert_try", int(time.time()))
    log("  кабинет: выпуск сертификата Let's Encrypt для %s" % d)
    p = run(["certbot", "certonly", "--webroot", "-w", WEBROOT, "-d", d, "--non-interactive", "--agree-tos",
             "--register-unsafely-without-email", "--keep-until-expiring",
             "--deploy-hook", "systemctl reload nginx"], check=False, timeout=180)
    if p.returncode == 0 and _le(d):
        old = _read(PANEL_CONF)
        _write(PANEL_CONF, render_site(d, panel=True))
        _nginx_reload({PANEL_CONF: old})
        log("  кабинет: сертификат выпущен")
    else:
        log("  кабинет: certbot не смог: %s" % (p.stdout or "").strip()[-300:])


def panel_checks(m):
    d = _panel_domain(m)
    if not d:
        return []
    out = []
    ips, mine = dns_ips(d), host_ips(m)
    if set(ips) & mine:
        out.append({"key": "dns", "status": "ok", "text": "%s указывает на этот хост" % d})
    else:
        out.append({"key": "dns", "status": "fail", "text": "%s указывает на %s, а нужно на %s" % (
            d, ", ".join(ips) or "ничего", m.master_addr() or "этот хост")})
    le = _le(d)
    if le:
        until = _cert_until(le[0])
        out.append({"key": "cert", "status": "ok", "text": "Let's Encrypt%s" % (
            " до " + time.strftime("%d.%m.%Y", time.localtime(until)) if until else "")})
    else:
        out.append({"key": "cert", "status": "warn", "text": "временный самоподписанный — Let's Encrypt выпустится "
                                                             "сам, когда домен будет указывать на этот хост"})
    listening = run(["ss", "-ltnH", "sport = :443"], check=False).stdout.strip()
    out.append({"key": "port", "status": "ok" if listening else "fail",
                "text": "порт 443 слушается (снаружи он должен быть открыт)" if listening else "порт 443 не слушается"})
    return out


def dns_ips(domain):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        return []


def issue_certs(m, servers, force=False):
    now = time.time()
    for s in servers:
        d = s["domain"]
        if _le(d):
            continue
        if s["entry_ip"] not in dns_ips(d):
            continue
        st = m.server_state(s["id"])
        if not force and st.get("cert_try") and now - st["cert_try"] < CERT_RETRY:
            continue
        m.set_server_state(s["id"], cert_try=now)
        log("  %s: выпуск сертификата Let's Encrypt для %s" % (s["id"], d))
        p = run(["certbot", "certonly", "--webroot", "-w", WEBROOT, "-d", d, "--non-interactive", "--agree-tos",
                 "--register-unsafely-without-email", "--keep-until-expiring",
                 "--deploy-hook", "systemctl reload nginx"], check=False, timeout=180)
        if p.returncode == 0 and _le(d):
            path = os.path.join(NGINX_SITES, "mtp-%s.conf" % d)
            old = _read(path)
            _write(path, render_site(d))
            _nginx_reload({path: old})
            log("  %s: сертификат выпущен" % d)
        else:
            log("  %s: certbot не смог: %s" % (d, (p.stdout or "").strip()[-300:]))


# ---------------------------------------------------------------- health checks

def _tls_get(ip, sni, verify, timeout=6):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    with socket.create_connection((ip, 443), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            tls.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtpctl-check\r\nConnection: close\r\n\r\n"
                         % sni).encode())
            head = tls.recv(64).decode("latin-1")
    m = re.match(r"HTTP/\d\.\d (\d{3})", head)
    return int(m.group(1)) if m else 0


def _cert_until(path):
    try:
        info = ssl._ssl._test_decode_cert(path)
        return time.mktime(time.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z"))
    except Exception:  # noqa: BLE001
        return None


def checks(m, s, fw):
    out = []

    def add(key, status, text):
        out.append({"key": key, "status": status, "text": text})

    unit = "telemt@%s" % s["id"]
    if not s["enabled"]:
        add("telemt", "off", "сервер отключён, %s остановлен" % unit)
        return out
    try:
        m.api(s, timeout=3).call("GET", "/v1/health")
        add("telemt", "ok", "%s работает" % unit)
    except MtpError as e:
        add("telemt", "fail", "%s: %s" % (unit, e.message))
    if fw == "active":
        add("firewall", "ok", "порт %d открыт только для %s" % (s["port"], s["entry_ip"]))
    else:
        why = {"none": "ufw не установлен", "inactive": "ufw выключен",
               "allow-default": "в ufw входящие по умолчанию разрешены", "error": "ufw: ошибка"}.get(fw, fw)
        add("firewall", "warn", "%s — порт %d не закрыт для остальных" % (why, s["port"]))
    ips = dns_ips(s["domain"])
    if s["entry_ip"] in ips:
        add("dns", "ok", "%s указывает на %s" % (s["domain"], s["entry_ip"]))
    elif ips:
        add("dns", "fail", "%s указывает на %s, а нужно на %s" % (s["domain"], ", ".join(ips), s["entry_ip"]))
    else:
        add("dns", "fail", "у %s нет A-записи — укажите %s" % (s["domain"], s["entry_ip"]))
    le = _le(s["domain"])
    if le:
        until = _cert_until(le[0])
        days = int((until - time.time()) // 86400) if until else None
        add("cert", "ok" if days is None or days > 7 else "warn",
            "Let's Encrypt%s" % (" до " + time.strftime("%d.%m.%Y", time.localtime(until)) if until else ""))
    else:
        add("cert", "warn", "временный самоподписанный — Let's Encrypt выпустится сам, когда домен будет "
                            "указывать на вход и вход заработает")
    try:
        code = _tls_get(s["entry_ip"], s["domain"], verify=bool(le))
        add("entry", "ok" if 200 <= code < 400 else "fail",
            "вход %s:443 отвечает (сайт-заглушка, HTTP %d)" % (s["entry_ip"], code))
    except ssl.SSLCertVerificationError:
        add("entry", "fail", "вход %s:443 отдаёт чужой сертификат — на нём точно install.sh slave?" % s["entry_ip"])
    except (OSError, ssl.SSLError) as e:
        add("entry", "fail", "нет связи с %s:443 (%s) — на входе выполнен install.sh slave --port %d?"
            % (s["entry_ip"], getattr(e, "strerror", None) or e.__class__.__name__, s["port"]))
    for x in s["extra_sni"]:
        try:
            code = _tls_get(s["entry_ip"], x, verify=True)
            add("sni:" + x, "ok", "маскировка под %s работает (HTTP %d)" % (x, code))
        except (OSError, ssl.SSLError) as e:
            add("sni:" + x, "fail", "маскировка под %s не отвечает (%s)" % (x, e.__class__.__name__))
    return out


# ---------------------------------------------------------------- entry point

@contextlib.contextmanager
def agent_lock():
    """One agent at a time (timer, path unit, CLI, installer, restore)."""
    import fcntl
    with open(os.path.join(os.path.dirname(core.DB_PATH), "agent.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def apply(do_checks=True, force_cert=False, only=None):
    if os.geteuid() != 0:
        raise MtpError("mtpctl apply выполняется от root")
    with agent_lock():
        return _apply(do_checks, force_cert, only)


def _apply(do_checks, force_cert, only):
    m = core.Manager()
    try:
        all_servers = m.servers()
        tmpl = _tmpl("telemt.toml.tmpl")
        errors, servers = {}, []
        for s in all_servers:                  # значения из базы проверяем ещё раз: дальше они идут в пути и конфиги
            try:
                servers.append(core.validate_server(s))
            except MtpError as e:
                errors[s["id"]] = e.message
                log("  %s: ПРОПУЩЕН — %s" % (s["id"], e.message))
        for s in servers:
            if only and s["id"] != only:
                continue
            try:
                apply_telemt(m, s, tmpl)
            except (MtpError, OSError, subprocess.SubprocessError) as e:
                errors[s["id"]] = getattr(e, "message", None) or str(e)
                log("  %s: ОШИБКА %s" % (s["id"], errors[s["id"]]))
        remove_orphans(all_servers)
        try:
            fw = apply_firewall(servers)
        except (MtpError, OSError, subprocess.SubprocessError) as e:
            fw = "error"
            log("  ufw: ОШИБКА %s" % (getattr(e, "message", None) or e))
        try:
            apply_nginx(m, servers)
            issue_certs(m, servers, force=force_cert)
            panel_cert(m, force=force_cert)
        except (MtpError, OSError, subprocess.SubprocessError) as e:
            errors["nginx"] = getattr(e, "message", None) or str(e)
            log("  nginx: ОШИБКА " + errors["nginx"])
        if do_checks:
            pc = panel_checks(m)
            if "nginx" in errors:
                pc.insert(0, {"key": "nginx", "status": "fail", "text": errors["nginx"]})
            m.db.set_meta("panel_checks", json.dumps(pc, ensure_ascii=False) if pc else None)
            for s in all_servers:
                if only and s["id"] != only:
                    continue
                res = checks(m, s, fw) if s in servers else []
                if s["id"] in errors:
                    res.insert(0, {"key": "apply", "status": "fail", "text": errors[s["id"]]})
                if "nginx" in errors:
                    res.insert(0, {"key": "nginx", "status": "fail", "text": errors["nginx"]})
                m.set_server_state(s["id"], checks=res, checked=time.time())
        return errors
    finally:
        m.close()
