#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mtpctl self-test: database, servers, clients, telemt sync, traffic, panel API, migration.

  python3 tests/selftest.py            (no root, no network; telemt is replaced by tests/fake_telemt.py)
"""
import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix="mtpctl-test-")
os.environ["MTPCTL_HOME"] = TMP
os.environ["MTPCTL_DB"] = os.path.join(TMP, "mtpctl.db")
sys.path.insert(0, os.path.join(ROOT, "mtpctl"))
sys.path.insert(0, HERE)

import core  # noqa: E402
import web  # noqa: E402
import agent  # noqa: E402
from core import MtpError  # noqa: E402
from fake_telemt import FakeTelemt  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Env:
    """One database + fake telemt per server."""

    def __init__(self):
        for suf in ("", "-wal", "-shm"):
            if os.path.exists(core.DB_PATH + suf):
                os.unlink(core.DB_PATH + suf)
        core.init_db(master_addr="203.0.113.1").close()
        self.m = core.Manager()
        self.fakes = {}

    def add_server(self, title, domain, ip, **kw):
        s = self.m.server_add(title, domain, ip, api_port=free_port(), port=free_port(), **kw)
        s = self.m.server(s["id"])
        self.fakes[s["id"]] = FakeTelemt(s["api_port"], s["api_token"], domain).start()
        return s

    def close(self):
        for f in self.fakes.values():
            f.stop()
        self.m.close()


class T(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.m = self.e.m

    def tearDown(self):
        self.e.close()

    # ---------------------------------------------------------------- servers
    def test_server_validation(self):
        s = self.e.add_server("Мои", "one.example.org", "203.0.113.10", extra_sni="ya.ru, one.example.org")
        self.assertEqual(s["extra_sni"], ["ya.ru"])
        with self.assertRaises(MtpError):
            self.m.server_add("мои", "other.ru", "1.2.3.4")          # название без учёта регистра
        with self.assertRaises(MtpError):
            self.m.server_add("X", "one.example.org", "1.2.3.4")                 # домен занят
        with self.assertRaises(MtpError):
            self.m.server_add("X", "x.ru", "203.0.113.10")            # IP занят
        with self.assertRaises(MtpError):
            self.m.server_add("X", "http://x.ru/", "1.2.3.4")
        with self.assertRaises(MtpError):
            self.m.server_add("X", "x.ru", "127.0.0.1")
        self.assertEqual(self.m.default_server_id(), s["id"])
        self.assertEqual(self.m.server("МОИ")["id"], s["id"])
        conf = core.render_telemt_conf(s)
        self.assertIn('tls_domains = ["ya.ru"]', conf)
        self.assertIn('"ya.ru" = "127.0.0.1:8445"', conf)
        self.assertIn('proxy_protocol_trusted_cidrs = ["203.0.113.10/32"]', conf)
        self.assertNotIn("{{", conf)
        h = core.conf_hash(s)
        self.m.server_update(s["id"], title="Мои")                      # название не трогает telemt
        self.assertEqual(core.conf_hash(self.m.server(s["id"])), h)
        self.m.server_update(s["id"], extra_sni="")
        self.assertNotEqual(core.conf_hash(self.m.server(s["id"])), h)
        self.assertNotIn("{{", core.render_telemt_conf(self.m.server(s["id"])))
        self.assertIn("--master 203.0.113.1 --port %d" % s["port"], self.m.slave_command(s))

    def test_base_path_and_templates(self):
        self.assertEqual(len(core.random_string(18)), 18)
        for bad in ("api", "a/b", "abc", "x" * 65, "../etc"):
            with self.assertRaises(MtpError):
                core.check_base_path(bad)
        self.assertEqual(core.check_base_path("/Ab_c-12/"), "Ab_c-12")
        snip = agent.render_snippet(self.m)                    # путь не задан — только заглушка
        self.assertNotIn("{{", snip)
        self.assertNotIn("proxy_pass", snip)
        self.m.db.set_meta("web_base_path", "Secret123path")
        snip = agent.render_snippet(self.m)
        self.assertIn("location /Secret123path/api/ {", snip)
        self.assertIn("proxy_set_header X-Base-Path /Secret123path/;", snip)
        self.assertIn("location /bg/", snip)
        self.assertNotIn("api/login", snip)                    # на корне больше нет формы входа
        self.m.db.set_meta("brand", "acme<script>")
        page = agent.render_index(self.m)
        self.assertIn("acmescript console", page)
        self.assertNotIn("{{", page)
        self.e.add_server("A", "a.example.org", "198.51.100.7")
        self.assertEqual(self.m.panel_urls(), ["https://a.example.org/Secret123path/"])

    def test_panel_domain(self):
        self.e.add_server("A", "a.example.org", "198.51.100.7")
        self.m.set_base_path("Secret123path")
        self.assertIn("location /Secret123path/api/", agent.render_snippet(self.m))        # без домена — на серверах
        with self.assertRaises(MtpError):
            self.m.set_panel_domain("a.example.org")                                     # занят сервером
        self.m.set_panel_domain("panel.example.org")
        with self.assertRaises(MtpError):
            self.m.server_add("B", "panel.example.org", "198.51.100.8")                  # занят кабинетом
        entry, direct = agent.render_snippet(self.m), agent.render_snippet(self.m, direct=True)
        self.assertNotIn("Secret123path", entry)                                         # на серверах только заставка
        self.assertIn("location /Secret123path/api/", direct)
        self.assertNotIn("real_ip_header proxy_protocol", direct)
        self.assertIn("location / { return 404; }", direct)                             # без заставки
        self.assertNotIn("/404.html", direct)
        self.assertNotIn("location /bg/", direct)
        self.assertIn("real_ip_header proxy_protocol", entry)
        site = agent.render_site("panel.example.org", panel=True)
        self.assertIn("server_name panel.example.org;", site)
        self.assertIn("include snippets/mtpanel-direct.conf;", site)
        self.assertNotIn("proxy_protocol", site)
        self.assertEqual(self.m.panel_urls(), ["https://panel.example.org/Secret123path/"])
        old = self.m.base_path()
        self.assertNotEqual(self.m.set_base_path(), old)
        self.m.set_panel_domain("")
        self.assertEqual(self.m.panel_urls(), ["https://a.example.org/%s/" % self.m.base_path()])

    def test_covers(self):
        pool = [{"f": "%016x.jpg" % i, "a": "Автор <b>%d</b>" % i, "l": "CC0", "s": "https://commons.wikimedia.org/"}
                for i in range(30)]
        a, b = agent.render_cover("one.example.org", pool), agent.render_cover("two.example.org", pool)
        self.assertEqual(set(a), {"index.html", "404.html", "robots.txt", "favicon.svg", "favicon.ico"})
        self.assertNotEqual(a["index.html"], b["index.html"])          # у каждого домена своя страница
        for f in ("index.html", "404.html"):
            self.assertNotIn("{{", a[f])
        self.assertNotIn("api/login", a["index.html"])
        self.assertNotIn("<b>", a["index.html"].split("var P=")[1].split(";")[0])   # подписи — данные, не HTML
        self.assertTrue(a["favicon.ico"].startswith(b"\x00\x00\x01\x00\x01\x00\x10\x10"))
        self.assertEqual(len(a["favicon.ico"]), 6 + 16 + 40 + 16 * 16 * 4 + 64)
        empty = agent.render_cover("one.example.org", [])                # без сети — градиент
        self.assertIn("var P=[]", empty["index.html"])

    def test_mask_and_site_render(self):
        s = self.e.add_server("A", "a.example.org", "198.51.100.7", extra_sni="ya.ru")
        txt = agent.render_mask([s])
        self.assertIn("ya.ru ya.ru:443;", txt)
        self.assertIn("ssl_preread on;", txt)
        site = agent.render_site("a.example.org")
        self.assertIn("server_name a.example.org;", site)
        self.assertIn(agent.FALLBACK_CERT, site)                         # LE ещё нет
        self.assertNotIn("{{", site)

    # ---------------------------------------------------------------- clients + sync
    def test_client_lifecycle(self):
        a = self.e.add_server("Мои", "one.example.org", "203.0.113.10", extra_sni="ya.ru")
        b = self.e.add_server("Друзья", "two.example.org", "203.0.113.20")
        fa, fb = self.e.fakes[a["id"]], self.e.fakes[b["id"]]
        c = self.m.add("ivan", note="тест", devices=2, expires="30")
        self.assertEqual(c["servers"], [a["id"]])                        # по умолчанию — первый сервер
        self.assertIn("ivan", fa.users)
        self.assertNotIn("ivan", fb.users)
        self.assertEqual(fa.users["ivan"]["secret"], c["links"][0]["secret"][2:34])
        self.assertEqual(len(c["links"]), 3)                             # домен, IP, ya.ru
        self.assertEqual(c["max_devices"], 2)
        self.assertEqual(fa.users["ivan"]["max_unique_ips"], 2)

        c = self.m.set_servers("ivan", [a["id"], "Друзья"])
        self.assertIn("ivan", fb.users)
        self.assertEqual(fb.users["ivan"]["secret"], fa.users["ivan"]["secret"])
        self.assertEqual(len(c["links"]), 5)
        self.assertEqual(fb.users["ivan"]["expiration_rfc3339"], c["expires"])

        self.m.server_update(b["id"], default_devices=3)
        self.assertEqual(fb.policy["user_max_unique_ips_global_each"], 3)
        c = self.m.set_limits("ivan", devices=0)
        self.assertIsNone(c["max_devices"])
        self.assertIsNone(fb.users["ivan"].get("max_unique_ips"))

        c = self.m.enable("ivan", False)
        self.assertEqual(c["state"], "disabled")
        self.assertFalse(fa.users["ivan"]["enabled"])
        self.assertFalse(fb.users["ivan"]["enabled"])
        self.m.enable("ivan", True)
        self.assertTrue(fb.users["ivan"]["enabled"])

        old = fa.users["ivan"]["secret"]
        c = self.m.rotate("ivan")
        self.assertNotEqual(fa.users["ivan"]["secret"], old)
        self.assertEqual(fa.users["ivan"]["secret"], fb.users["ivan"]["secret"])

        c = self.m.set_limits("ivan", quota="20G", period="month")
        self.assertEqual(fa.users["ivan"]["data_quota_bytes"], 20 * 1024 ** 3)
        self.assertEqual(fa.users["ivan"]["quota_period"], "monthly")
        c = self.m.set_limits("ivan", quota="0")
        self.assertIsNone(c["quota_period"])
        self.assertIsNone(fa.users["ivan"]["data_quota_bytes"])

        c = self.m.set_expiry("ivan", "never")
        self.assertIsNone(c["expires"])
        self.assertIsNone(fa.users["ivan"]["expiration_rfc3339"])
        c = self.m.set_expiry("ivan", "2030-01-31")
        self.assertEqual(c["expires"], "2030-01-31T23:59:59Z")
        c = self.m.set_expiry("ivan", "+10")
        self.assertEqual(c["expires"], "2030-02-10T23:59:59Z")

        self.m.set_servers("ivan", [b["id"]])
        self.assertNotIn("ivan", fa.users)
        with self.assertRaises(MtpError):
            self.m.set_servers("ivan", [])
        self.m.delete("ivan")
        self.assertNotIn("ivan", fb.users)
        with self.assertRaises(MtpError):
            self.m.get("ivan")

    def test_no_patch_loop(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7", default_devices=2)
        self.m.add("x", devices=3, expires="2031-05-01", quota="1G", period="week")
        self.m.add("y")
        self.m.enable("y", False)
        f = self.e.fakes[a["id"]]
        self.assertEqual(self.m.sync_server(self.m.server(a["id"])), 0)
        f.calls.clear()
        self.m.collect()
        self.assertFalse([c for c in f.calls if c[0] != "GET"], f.calls)

    def test_self_heal_and_offline_server(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        b = self.e.add_server("B", "b.example.org", "198.51.100.8")
        fa, fb = self.e.fakes[a["id"]], self.e.fakes[b["id"]]
        self.m.add("p", servers=[a["id"]])
        del fa.users["p"]                                   # кто-то удалил руками / telemt потерял конфиг
        fa.users["stranger"] = {"username": "stranger", "secret": "0" * 32}
        self.m.collect()
        self.assertIn("p", fa.users)
        self.assertNotIn("stranger", fa.users)
        fb.stop()                                           # сервер B недоступен
        c = self.m.add("q", servers=[b["id"]])              # клиент всё равно создаётся
        self.assertIn(b["id"], self.m.errors)
        self.assertEqual(c["servers"], [b["id"]])
        fb.start()
        self.m.collect()
        self.assertIn("q", fb.users)
        self.assertNotIn(b["id"], self.m.errors)
        self.assertEqual(self.m.get("q")["pending"], [])

    def test_disabled_and_deleted_server(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        self.m.add("p")
        self.m.server_update(a["id"], enabled=False)
        c = self.m.get("p")
        self.assertEqual(c["servers"], [a["id"]])
        self.m.server_delete(a["id"])
        c = self.m.get("p")
        self.assertEqual(c["servers"], [])
        self.assertEqual(c["links"], [])
        with self.assertRaises(MtpError):
            self.m.add("z")                                  # серверов нет

    def test_traffic(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        b = self.e.add_server("B", "b.example.org", "198.51.100.8")
        fa, fb = self.e.fakes[a["id"]], self.e.fakes[b["id"]]
        self.m.add("t", servers=[a["id"], b["id"]])
        fa.users["t"]["octets"] = 1000                       # первый замер был при создании (0)
        self.m.collect()
        fa.users["t"]["octets"] = 5000
        fa.users["t"]["conns"] = 1
        fa.users["t"]["ips"] = ["10.0.0.1"]
        fb.users["t"]["octets"] = 700
        self.m.collect()
        r = self.m.traffic_report("t", "24h")
        per = {p["period"]: p["bytes"] for p in r["periods"]}
        self.assertEqual(per["1h"], 5000 + 700)
        self.assertEqual(per["all"], 5000 + 700)
        self.assertEqual(sum(x["bytes"] for x in r["series"]), 5700)
        self.assertEqual(len(r["series"]), 24)
        r = self.m.traffic_report(None, "7d", b["id"])
        self.assertEqual({p["period"]: p["bytes"] for p in r["periods"]}["day"], 700)
        for rng, n in (("7d", 7), ("30d", 30), ("12m", 12)):
            self.assertEqual(len(self.m.traffic_report("t", rng)["series"]), n)
        c = self.m.get("t")
        self.assertTrue(c["online"])
        self.assertEqual(c["active_ips"], ["10.0.0.1"])
        self.assertEqual(c["total_bytes"], 5700)
        fa.users["t"]["octets"] = 100                        # telemt перезапустился
        fa.users["t"]["conns"] = 0
        self.m.collect()
        c = self.m.get("t")
        self.assertEqual(c["total_bytes"], 5800)
        self.assertFalse(c["online"])
        self.assertIsNotNone(c["last_seen"])
        self.m.delete("t")
        self.assertEqual(self.m.db.q1("SELECT count(*) n FROM tr_slot")["n"], 0)

    def test_traffic_first_sight(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        f = self.e.fakes[a["id"]]
        with self.m.db.tx():                                  # клиент из базы, которого ещё не видели
            self.m.db.x("INSERT INTO clients(name, key, created) VALUES('old', ?, '2026-01-01T00:00:00Z')",
                        ("ab" * 16,))
            self.m.db.x("INSERT INTO access VALUES('old', ?)", (a["id"],))
        f.users["old"] = {"username": "old", "secret": "ab" * 16, "octets": 9000}
        self.m.collect()
        per = {p["period"]: p["bytes"] for p in self.m.traffic_report("old")["periods"]}
        self.assertEqual((per["1h"], per["all"]), (0, 9000))   # история до первого замера — только «всё время»

    def test_crafted_rows_rejected(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        core.validate_server(self.m.server(a["id"]))             # нормальная строка проходит
        for col, val in (("domain", "x.org;\n include /etc/passwd"), ("domain", "../../etc/cron.d/x"),
                         ("entry_ip", "1.2.3.4\nport 22"), ("extra_sni", "ya.ru,evil;x"), ("port", 22)):
            with self.m.db.tx():
                self.m.db.x("UPDATE servers SET %s=? WHERE id=?" % col, (val, a["id"]))
            with self.assertRaises(MtpError, msg=col):
                core.validate_server(self.m.server(a["id"]))
            dest = os.path.join(TMP, "crafted.db")
            if os.path.exists(dest):
                os.unlink(dest)
            self.m.db.backup_to(dest)
            with self.assertRaises(MtpError, msg=col):
                core.check_db_file(dest)                     # такую копию restore не примет
            with self.m.db.tx():
                self.m.db.x("UPDATE servers SET domain=?, entry_ip=?, extra_sni='', port=? WHERE id=?",
                            (a["domain"], a["entry_ip"], a["port"], a["id"]))

    def test_backup_restore_file(self):
        self.e.add_server("A", "a.example.org", "198.51.100.7")
        self.m.add("k")
        dest = os.path.join(TMP, "copy.db")
        if os.path.exists(dest):
            os.unlink(dest)
        self.m.db.backup_to(dest)
        info = core.check_db_file(dest)
        self.assertEqual((info["servers"], info["clients"]), (1, 1))
        self.assertFalse(os.path.exists(dest + "-wal") or os.path.exists(dest + "-shm"))   # один файл
        bad = os.path.join(TMP, "bad.db")
        with open(bad, "wb") as f:
            f.write(b"not a database" * 100)
        with self.assertRaises(MtpError):
            core.check_db_file(bad)

    # ---------------------------------------------------------------- panel API
    def test_web(self):
        a = self.e.add_server("A", "a.example.org", "198.51.100.7")
        web.set_password("secret-password-1")
        port = free_port()
        srv = web.Server(("127.0.0.1", port), web.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def req(method, path, body=None, cookie=None, csrf=True):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                h = {}
                if csrf:
                    h["X-Requested-With"] = "XMLHttpRequest"
                h["X-Base-Path"] = "/panelpath123/"
                if cookie:
                    h["Cookie"] = cookie
                data = None
                if body is not None:
                    data = json.dumps(body)
                    h["Content-Type"] = "application/json"
                c.request(method, path, data, h)
                r = c.getresponse()
                raw = r.read()
                c.close()
                return r.status, r.getheader("Set-Cookie"), r.getheader("Content-Type"), raw

            st, _, ct, _ = req("GET", "/api/clients")
            self.assertEqual((st, ct), (404, "text/html"))
            st, _, _, _ = req("POST", "/api/login", {"password": "wrong"})
            self.assertEqual(st, 403)
            st, ck, _, _ = req("POST", "/api/login", {"password": "secret-password-1"}, csrf=False)
            self.assertEqual(st, 404)                        # без CSRF-заголовка — как будто ничего нет
            st, ck, _, _ = req("POST", "/api/login", {"password": "secret-password-1"})
            self.assertEqual(st, 200)
            self.assertIn("Path=/panelpath123/;", ck)
            cookie = ck.split(";")[0]
            st, _, _, raw = req("POST", "/api/clients", {"name": "w1", "devices": 2}, cookie)
            self.assertEqual(st, 201, raw)
            st, _, _, raw = req("GET", "/api/clients", cookie=cookie)
            j = json.loads(raw)
            self.assertEqual([c["name"] for c in j["clients"]], ["w1"])
            self.assertEqual(j["servers"][0]["id"], a["id"])
            st, _, _, raw = req("POST", "/api/servers", {"title": "B", "domain": "b.example.org",
                                                         "entry_ip": "198.51.100.9", "extra_sni": "ya.ru"}, cookie)
            self.assertEqual(st, 201, raw)
            sid = json.loads(raw)["server"]["id"]
            self.assertIn("install.sh slave --master 203.0.113.1", json.loads(raw)["slave_cmd"])
            self.assertTrue(os.path.exists(os.path.join(TMP, "apply.req")))
            st, _, _, raw = req("PATCH", "/api/servers/" + sid, {"title": "Бэ", "default": True}, cookie)
            self.assertEqual(st, 200, raw)
            self.assertEqual(self.m.default_server_id(), sid)
            st, _, _, raw = req("GET", "/api/servers", cookie=cookie)
            j = json.loads(raw)
            self.assertEqual([s["title"] for s in j["servers"]], ["A", "Бэ"])
            self.assertTrue(j["servers"][1]["pending"])
            self.assertNotIn("api_token", raw.decode())
            st, _, _, raw = req("PATCH", "/api/clients/w1", {"servers": [a["id"], sid], "note": "n"}, cookie)
            self.assertEqual(st, 200, raw)
            self.assertEqual(json.loads(raw)["client"]["servers"], [a["id"], sid])
            st, _, _, raw = req("GET", "/api/traffic?range=7d&server=" + sid, cookie=cookie)
            self.assertEqual(st, 200, raw)
            st, _, ct, raw = req("GET", "/api/backup", cookie=cookie)
            self.assertEqual((st, ct), (200, "application/vnd.sqlite3"))
            p = os.path.join(TMP, "dl.db")
            with open(p, "wb") as f:
                f.write(raw)
            self.assertEqual(core.check_db_file(p)["clients"], 1)
            st, _, _, raw = req("PATCH", "/api/settings", {"master_addr": "m.example.org"}, cookie)
            self.assertEqual(json.loads(raw)["settings"]["master_addr"], "m.example.org")
            st, _, _, raw = req("DELETE", "/api/servers/" + sid, cookie=cookie)
            self.assertEqual(st, 200)
            st, _, _, raw = req("POST", "/api/password", {"current": "secret-password-1",
                                                          "new": "another-password"}, cookie)
            self.assertEqual(st, 200)
            st, _, _, _ = req("GET", "/api/clients", cookie=cookie)
            self.assertEqual(st, 404)                        # смена пароля сбрасывает сессии
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
