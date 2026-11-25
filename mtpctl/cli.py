# -*- coding: utf-8 -*-
"""mtpctl — управление MTProto-прокси (telemt): серверы-входы и клиенты.

  mtpctl client add <name> [--server S[,S]] [--days N | --until ГГГГ-ММ-ДД] [--note TEXT]
                           [--quota 20G [--period month]] [--devices N] [--key HEX32] [--qr]
  mtpctl client list | show <name> [--qr]
  mtpctl client renew <name> (--days N | --until ГГГГ-ММ-ДД | --never)
  mtpctl client limits <name> [--quota 20G|0] [--period day|week|month|none] [--devices N|0]
  mtpctl client note <name> TEXT
  mtpctl client servers <name> S[,S]           # на каких серверах работает (ключ тот же)
  mtpctl client enable|disable|rotate|reset-quota|delete <name> [-y]
  mtpctl server list | show <S>
  mtpctl server add --title T --domain D --ip IP [--sni ya.ru] [--devices N] [--note T] [--default]
  mtpctl server edit <S> [--title T] [--domain D] [--ip IP] [--sni LIST] [--devices N|0] [--note T]
                         [--enable | --disable] [--default]
  mtpctl server rm <S> [-y]
  mtpctl server check [<S>]                    # применить и проверить сейчас (root)
  mtpctl online
  mtpctl traffic [<name>] [--server S] [--range 24h|7d|30d|12m]
  mtpctl settings [--master-addr IP|DNS] [--panel-domain DNS]
  mtpctl web access | reset [--random] | passwd | path [PATH|--random]
  mtpctl backup [FILE]                         # без FILE — рабочая копия /opt/mtpctl/backup/mtpctl.db
  mtpctl restore FILE [--access-from-backup]   # заменить базу копией без переустановки (root)
  mtpctl status | restart | log | update | uninstall
  mtpctl                                       # меню (в терминале)
  mtpctl setup | apply                         # служебные: установщик и агент (root)
S — id или название сервера.
"""
import argparse
import contextlib
import getpass
import os
import shutil
import sqlite3
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
from core import MtpError, human_size  # noqa: E402

STATE_RU = {"active": "активен", "disabled": "отключён", "expired": "истёк"}


def _manager():
    return core.Manager()


def _fmt_exp(c):
    if not c["expires"]:
        return "бессрочно"
    return "%s (%d дн.)" % (c["expires"][:10], c["days_left"] or 0)


def _fmt_quota(c):
    if not c["quota_bytes"]:
        return "—"
    per = {"daily": "/день", "weekly": "/нед", "monthly": "/мес"}.get(c["quota_period"] or "", "")
    return human_size(c["quota_bytes"]) + per


def _table(rows, headers):
    w = [len(h) for h in headers]
    for r in rows:
        for i, v in enumerate(r):
            w[i] = max(w[i], len(str(v)))
    line = "  ".join(h.ljust(w[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * x for x in w))
    for r in rows:
        print("  ".join(str(v).ljust(w[i]) for i, v in enumerate(r)))


def _ago(ts):
    import time
    if not ts:
        return "не подключался"
    s = int(time.time() - ts)
    if s < 120:
        return "только что"
    if s < 3600:
        return "%d мин назад" % (s // 60)
    if s < 86400:
        return "%d ч назад" % (s // 3600)
    return "%d дн. назад" % (s // 86400)


def _fmt_online(c):
    if c["online"]:
        return "в сети (%d устр.)" % max(1, len(c["active_ips"]))
    if c["last_seen"]:
        return "был " + _ago(c["last_seen"])
    return "подключался раньше" if c["total_bytes"] else "не подключался"


def cmd_list(m, a):
    rows = []
    for c in m.list():
        rows.append([c["name"], ",".join(c["servers"]) or "—", STATE_RU[c["state"]], _fmt_online(c), _fmt_exp(c),
                     human_size(c["total_bytes"]), _fmt_quota(c), _fmt_dev(c), c["note"]])
    for sid, err in m.errors.items():
        print("! сервер %s: %s" % (sid, err), file=sys.stderr)
    if not rows:
        print("клиентов нет")
        return
    _table(rows, ["имя", "серверы", "статус", "в сети", "срок", "трафик", "квота", "устр.", "заметка"])
    print("\n«был …» считается с момента установки сбора (раз в минуту). Трафик по периодам: mtpctl traffic <имя>")


def _fmt_dev(c):
    if c["max_devices"]:
        return str(c["max_devices"])
    return "%s (сервер)" % c["devices_limit"] if c.get("devices_limit") else "—"


def cmd_servers(m, a):
    c = m.set_servers(a.name, _split(a.servers))
    print("%s: серверы %s" % (c["name"], ", ".join(_stitle(m, s) for s in c["servers"])))


def _split(v):
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _stitle(m, sid):
    try:
        return m.server(sid)["title"]
    except MtpError:
        return sid


CHECK_MARK = {"ok": "✓", "warn": "!", "fail": "✗", "off": "–"}


def cmd_server_list(m, a):
    rows = []
    for s in m.servers_info():
        h = s.get("health") or {}
        tel = "отключён" if not s["enabled"] else (
            "работает" if h.get("status") == "ok" else (h.get("error") or h.get("status") or "?"))
        bad = [c for c in s["checks"] if c["status"] in ("fail", "warn")]
        rows.append([s["id"] + (" *" if s["default"] else ""), s["title"], s["domain"], s["entry_ip"],
                     s["port"], tel, "%d (онлайн %d)" % (s["clients"], s["online"]),
                     "ждёт применения" if s["pending"] else ("ok" if not bad else "%d замеч." % len(bad))])
    if not rows:
        print("серверов нет — mtpctl server add --title … --domain … --ip …")
        return
    _table(rows, ["id", "название", "домен", "IP входа", "порт", "telemt", "клиентов", "проверки"])
    print("\n* — сервер по умолчанию для новых клиентов. Подробности: mtpctl server show <id>")


def _print_server(m, s):
    info = next((x for x in m.servers_info() if x["id"] == s["id"]), None) or s
    print("%s (%s)%s%s" % (info["title"], info["id"], "" if info["enabled"] else " — отключён",
                           " — по умолчанию для новых клиентов" if info.get("default") else ""))
    print("  домен %s, IP входа %s, порт на мастере %d, API 127.0.0.1:%d"
          % (info["domain"], info["entry_ip"], info["port"], info["api_port"]))
    if info["extra_sni"]:
        print("  дополнительные SNI: " + ", ".join(info["extra_sni"]))
    print("  устройств по умолчанию: %s" % (info["default_devices"] or "без ограничений"))
    if info.get("note"):
        print("  заметка: " + info["note"])
    if info.get("pending"):
        print("  ! изменения ещё не применены агентом (mtpctl server check)")
    if info.get("checks"):
        import time as _t
        print("  проверки (%s):" % (_t.strftime("%d.%m %H:%M", _t.localtime(info["checked"]))
                                    if info.get("checked") else "?"))
        for c in info["checks"]:
            print("    %s %s" % (CHECK_MARK.get(c["status"], "?"), c["text"]))
    print("\n  на входном хосте (root):\n    " + m.slave_command(info))


def cmd_server_show(m, a):
    _print_server(m, m.server(a.server))


def cmd_server_add(m, a):
    s = m.server_add(a.title, a.domain, a.ip, a.sni, a.devices, a.note or "", sid=a.id, port=a.port)
    if a.default:
        m.server_update(s["id"], make_default=True)
    print("сервер %s добавлен: порт на мастере %d.\n" % (s["id"], s["port"]))
    print("Дальше:\n  1. A-запись %s -> %s\n  2. на входном хосте %s (root):\n       %s\n"
          "  3. проверка: mtpctl server show %s (агент проверяет сам каждые 10 минут)"
          % (s["domain"], s["entry_ip"], s["entry_ip"], m.slave_command(s), s["id"]))
    _run_apply_if_root(s["id"])


def cmd_server_edit(m, a):
    kw = {}
    for k, attr in (("title", "title"), ("domain", "domain"), ("entry_ip", "ip"), ("extra_sni", "sni"),
                    ("default_devices", "devices"), ("note", "note")):
        v = getattr(a, attr)
        if v is not None:
            kw[k] = v
    if a.enable:
        kw["enabled"] = True
    if a.disable:
        kw["enabled"] = False
    s = m.server_update(a.server, make_default=a.default, **kw)
    print("сохранено")
    _run_apply_if_root(s["id"])
    _print_server(m, s)


def cmd_server_rm(m, a):
    s = m.server(a.server)
    n = m.db.q1("SELECT count(*) n FROM access WHERE server=?", (s["id"],))["n"]
    _confirm(a, "Удалить сервер «%s»? Его ссылки у %d клиент(ов) перестанут работать." % (s["title"], n))
    m.server_delete(s["id"])
    print("удалён; входной хост %s можно освободить (install.sh slave --uninstall)" % s["entry_ip"])
    _run_apply_if_root(None)


def cmd_server_check(m, a):
    sid = m.server(a.server)["id"] if a.server else None
    if os.geteuid() != 0:
        core.request_apply("check")
        print("задание передано агенту; результат: mtpctl server show <id> через минуту")
        return
    import agent
    agent.apply(only=sid, force_cert=True)
    for s in m.servers():
        if not sid or s["id"] == sid:
            print()
            _print_server(m, s)


def _run_apply_if_root(sid):
    if os.geteuid() == 0:
        import agent
        print("\nприменяю (агент):")
        agent.apply(only=sid)


def cmd_traffic(m, a):
    r = m.traffic_report(a.name, a.range, a.server)
    who = "клиента %s" % a.name if a.name else ("сервера %s" % a.server if a.server else "всех клиентов")
    print("Трафик %s\n" % who)
    _table([[p["title"], human_size(p["bytes"])] for p in r["periods"]], ["период", "трафик"])
    ser = r["series"]
    peak = max([s["bytes"] for s in ser] + [1])
    title = {"24h": "по часам, 24 часа", "7d": "по дням, 7 дней", "30d": "по дням, 30 дней", "12m": "по месяцам, 12 месяцев"}
    print("\n%s:" % title[a.range])
    for s in ser:
        bar = "█" * int(round(30 * s["bytes"] / peak)) if s["bytes"] else ""
        print("  %-6s %10s  %s" % (s["label"], human_size(s["bytes"]) if s["bytes"] else "—", bar))


def _print_client(c, qr=False):
    print("%s — %s, серверы: %s, срок: %s, трафик: %s, квота: %s, устройств: %s" % (
        c["name"], STATE_RU[c["state"]], ", ".join(l for l in dict.fromkeys(x["server_title"] for x in c["links"])) or "нет", _fmt_exp(c), human_size(c["total_bytes"]),
        _fmt_quota(c), _fmt_dev(c) if _fmt_dev(c) != "—" else "без ограничений"))
    if c["note"]:
        print("заметка: " + c["note"])
    if c["active_ips"]:
        print("онлайн: %d соед., IP: %s" % (c["connections"], ", ".join(c["active_ips"])))
    if not c["links"]:
        print("ссылок нет (ключ неизвестен)")
        return
    for l in c["links"]:
        print("\n[%s · %s] %s:%s, SNI %s" % (l.get("server_title", ""), l["title"], l["server"], l["port"], l["sni"]))
        print("  " + l["tg"])
        print("  " + l["https"])
        if qr:
            if shutil.which("qrencode"):
                subprocess.run(["qrencode", "-t", "ansiutf8", "-m", "1", l["tg"]])
            else:
                print("  (для QR поставьте qrencode: apt install qrencode)")


def cmd_add(m, a):
    exp = a.until or (str(a.days) if a.days else None)
    c = m.add(a.name, servers=_split(a.server) or None, expires=exp, note=a.note or "", quota=a.quota,
              period=a.period, devices=a.devices, key=a.key)
    for sid, err in m.errors.items():
        print("! сервер %s пока не принял клиента (%s) — повторится автоматически" % (sid, err), file=sys.stderr)
    print("клиент создан\n")
    _print_client(c, a.qr)


def cmd_show(m, a):
    _print_client(m.get(a.name), a.qr)


def cmd_renew(m, a):
    if a.never:
        exp = "never"
    elif a.until:
        exp = a.until
    elif a.days:
        exp = "+%d" % a.days
    else:
        raise MtpError("укажите --days, --until или --never")
    c = m.set_expiry(a.name, exp)
    print("%s: срок %s" % (c["name"], _fmt_exp(c)))


def cmd_limits(m, a):
    c = m.set_limits(a.name,
                     quota=a.quota if a.quota is not None else "keep",
                     period=("" if a.period == "none" else a.period) if a.period is not None else "keep",
                     devices=a.devices if a.devices is not None else "keep")
    print("%s: квота %s, устройств %s" % (c["name"], _fmt_quota(c), c["max_devices"] or "без ограничений"))


def cmd_note(m, a):
    m.set_note(a.name, " ".join(a.text))
    print("заметка сохранена")


def _confirm(a, text):
    if getattr(a, "yes", False):
        return
    if input(text + " [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
        raise SystemExit("отменено")


def cmd_simple(m, a):
    if a.action == "enable":
        c = m.enable(a.name, True)
    elif a.action == "disable":
        c = m.enable(a.name, False)
    elif a.action == "rotate":
        _confirm(a, "Старые ссылки %s перестанут работать. Продолжить?" % a.name)
        c = m.rotate(a.name)
        _print_client(c)
        return
    elif a.action == "reset-quota":
        c = m.reset_quota(a.name)
    elif a.action == "delete":
        _confirm(a, "Удалить клиента %s?" % a.name)
        m.delete(a.name)
        print("удалён")
        return
    print("%s: %s" % (c["name"], STATE_RU[c["state"]]))


def cmd_online(m, a):
    rows = [[c["name"], c["connections"], ", ".join(c["active_ips"])] for c in m.list() if c["connections"]]
    if not rows:
        print("сейчас никого")
        return
    _table(rows, ["имя", "соед.", "IP"])


def _addr(v):
    v = (v or "").strip()
    if not v:
        return None
    try:
        return core.check_ip(v)
    except MtpError:
        return core.check_domain(v)


def cmd_settings(m, a):
    if a.master_addr is not None:
        m.db.set_meta("master_addr", _addr(a.master_addr))
    if a.panel_domain is not None:
        m.set_panel_domain(a.panel_domain)
        _run_apply_if_root(None)
    print("адрес мастера для входов: %s" % (m.master_addr() or "не задан"))
    print("домен кабинета: %s" % (m.panel_domain() or "не задан — кабинет на доменах серверов"))
    print("сервер по умолчанию для новых клиентов: %s" % (m.default_server_id() or "—"))


# ---------------------------------------------------------------- backup / restore

def cmd_backup(m, a):
    """Без аргумента — обновить единственную рабочую копию (BACKUP_PATH)."""
    dest = a.file or core.BACKUP_PATH
    if a.file and os.path.exists(dest):
        raise MtpError("%s уже существует" % dest)
    d = os.path.dirname(os.path.abspath(dest))
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = os.path.join(d, ".%s.tmp" % os.path.basename(dest))
    old = os.umask(0o077)
    try:
        if os.path.exists(tmp):
            os.unlink(tmp)
        m.db.backup_to(tmp)
    finally:
        os.umask(old)
    try:
        info = core.check_db_file(tmp)       # прежнюю копию заменяем только целой
    except MtpError:
        os.unlink(tmp)
        raise
    os.replace(tmp, dest)
    for suf in ("-wal", "-shm"):                  # хвосты прежних версий
        with contextlib.suppress(OSError):
            os.unlink(tmp + suf)
    print("%s: серверов %d, клиентов %d" % (dest, info["servers"], info["clients"]))


ACCESS_KEYS = ("admin_user", "admin_hash", "admin_epoch", "web_base_path", "panel_domain", "master_addr")


def restore_db(src, keep_access=True):
    """Заменить базу копией (root): web остановлен на время замены, агент тоже ждёт.

    keep_access — оставить текущие пароль, путь и домен кабинета и адрес мастера (иначе — из копии)."""
    import time as _t
    import agent
    info = core.check_db_file(src)
    db = core.DB_PATH
    access = {}
    if keep_access and os.path.exists(db):
        cur = core.Store(db)
        try:
            access = {k: cur.meta(k) for k in ACCESS_KEYS}
        finally:
            cur.close()
    subprocess.run(["systemctl", "stop", "mtpctl-web"], check=False)
    try:
        with agent.agent_lock():               # таймер агента не должен читать базу посреди замены
            if os.path.exists(db):
                keep = "%s.before-restore-%s" % (core.BACKUP_PATH, _t.strftime("%Y%m%d-%H%M%S"))
                os.makedirs(os.path.dirname(keep), mode=0o700, exist_ok=True)
                cur = core.Store(db)
                try:
                    cur.backup_to(keep)
                finally:
                    cur.close()
                print("прежняя база: " + keep)
            for suf in ("", "-wal", "-shm"):
                if os.path.exists(db + suf):
                    os.unlink(db + suf)
            shutil.copyfile(src, db)
            shutil.chown(db, "mtpctl", "mtpctl")
            os.chmod(db, 0o660)
            st = core.Store(db, create=True)      # догоняет схему, если копия старее
            try:
                st.x("UPDATE server_state SET applied=NULL, cert_try=NULL")   # конфиги пересоздать на этом хосте
                with st.tx():
                    for k, v in access.items():
                        st.set_meta(k, v)
            finally:
                st.close()
    finally:
        subprocess.run(["systemctl", "start", "mtpctl-web"], check=False)
    print("база восстановлена: серверов %d, клиентов %d%s" % (
        info["servers"], info["clients"], "; доступ к кабинету оставлен прежним" if access else
        "; пароль, путь и домен кабинета — из копии"))
    agent.apply()


def cmd_restore(m, a):
    if os.geteuid() != 0:
        raise MtpError("restore выполняется от root")
    info = core.check_db_file(a.file)
    _confirm(a, "Заменить текущую базу копией %s (серверов %d, клиентов %d)? Текущая будет сохранена рядом."
             % (a.file, info["servers"], info["clients"]))
    restore_db(a.file, keep_access=not a.access_from_backup)


def pending_restore():
    """Копия, загруженная через кабинет: data/restore.upload + data/restore.req (выполняет агент от root)."""
    d = os.path.dirname(core.DB_PATH)
    req, up = os.path.join(d, "restore.req"), os.path.join(d, "restore.upload")
    if not os.path.exists(req):
        return
    import json as _json
    try:
        with open(req, encoding="utf-8") as f:
            opts = _json.load(f)
    except (OSError, ValueError):
        opts = {}
    os.unlink(req)
    if not os.path.exists(up):
        return
    try:
        print("восстановление из копии, загруженной через кабинет")
        restore_db(up, keep_access=bool(opts.get("keep_access", True)))
    finally:
        with contextlib.suppress(OSError):
            os.unlink(up)


# ---------------------------------------------------------------- setup (installer), access, credentials

def _ask(prompt, default=""):
    if not sys.stdin.isatty():
        return default
    v = input(prompt).strip()
    return v or default


def _yes(prompt):
    return sys.stdin.isatty() and input(prompt + " [y/N]: ").strip().lower() in ("y", "yes", "д", "да")


def _set_password(password=None):
    import web
    password = password or core.random_string(16)
    web.set_password(password)
    return password


def _set_base_path(m, path=None):
    return m.set_base_path(path)


def _access_block(m, password=None, title="Доступ к кабинету"):
    line = "═" * 64
    urls = m.panel_urls()
    print(line)
    print("  " + title)
    print(line)
    print("  Пароль:         %s" % (password or "(не менялся; новый: mtpctl → 2)"))
    print("  Путь кабинета:  /%s/" % m.base_path())
    if m.panel_domain():
        print("  Домен кабинета: %s  (A-запись на этот хост)" % m.panel_domain())
    print("  Адрес мастера:  %s  (для команды установки входов)" % (m.master_addr() or "не задан"))
    if urls:
        for i, u in enumerate(urls):
            print("  %s %s" % ("Кабинет:       " if i == 0 else "               ", u))
    else:
        print("  Кабинет:        откроется на https://<домен сервера>/%s/ после добавления первого сервера\n"
              "                  (или задайте свой домен: mtpctl settings --panel-domain tg.example.org)" % m.base_path())
    print(line)
    if password:
        print("  ⚠ Сохраните пароль: в базе хранится только его хэш.")
        print(line)


def cmd_setup(m, a):
    """Установщик: база, пароль и путь кабинета."""
    if os.geteuid() != 0:
        raise MtpError("setup выполняется от root")
    new = not os.path.exists(core.DB_PATH)
    core.init_db().close()
    if new:
        shutil.chown(core.DB_PATH, "mtpctl", "mtpctl")
        os.chmod(core.DB_PATH, 0o660)
    m = core.Manager()
    try:
        if a.addr:
            m.db.set_meta("master_addr", _addr(a.addr))
        pd = a.panel_domain or os.environ.get("MTPCTL_PANEL_DOMAIN")
        if pd:
            m.set_panel_domain(pd)
        password = None
        env_pw = os.environ.get("MTPCTL_PASSWORD")
        env_path = os.environ.get("MTPCTL_WEB_BASE_PATH")
        if not m.auth().get("hash") or env_pw:
            if not env_pw and _yes("Задать пароль кабинета вручную? (иначе случайный)"):
                env_pw = _ask("Пароль, от 10 символов [случайный]: ")
            password = _set_password(env_pw)
        if not m.base_path() or env_path:
            if not env_path and _yes("Задать путь кабинета вручную? (иначе случайный, 18 символов)"):
                env_path = _ask("Путь [случайный]: ")
            _set_base_path(m, env_path)
        _access_block(m, password, "Мастер mtpctl установлен" if new else "Мастер mtpctl обновлён")
    finally:
        m.close()


def cmd_access(m, a):
    _access_block(m)


def cmd_web_reset(m, a):
    password = _set_password(None if a.random else _ask("Пароль, от 10 символов [случайный]: "))
    _access_block(m, password, "Новый пароль (все сессии кабинета закрыты)")


def cmd_web_passwd(m, a):
    import web
    p1 = getpass.getpass("новый пароль: ")
    p2 = getpass.getpass("ещё раз: ")
    if p1 != p2:
        raise MtpError("пароли не совпадают")
    web.set_password(p1)
    print("сохранено; все сессии кабинета сброшены")


def cmd_web_path(m, a):
    path = _set_base_path(m, None if a.random else (a.path or _ask("Новый путь [случайный]: ")))
    if os.geteuid() == 0:
        import agent
        agent.apply(do_checks=False)
    print("Путь кабинета: /%s/" % path)
    for u in m.panel_urls():
        print("  " + u)


# ---------------------------------------------------------------- services

UNITS = ["mtpctl-web", "mtpctl-agent.path", "mtpctl-agent.timer", "mtpctl-backup.timer", "nginx"]


def _telemt_units(m):
    return ["telemt@%s" % s["id"] for s in m.servers(enabled_only=True)]


def cmd_status(m, a):
    for u in UNITS + _telemt_units(m):
        st = subprocess.run(["systemctl", "is-active", u], stdout=subprocess.PIPE, universal_newlines=True).stdout
        print("  %-24s %s" % (u, st.strip()))
    if os.path.exists(core.BACKUP_PATH):
        import time as _t
        print("  резервная копия: %s (%s)" % (core.BACKUP_PATH, _t.strftime(
            "%d.%m.%Y %H:%M", _t.localtime(os.path.getmtime(core.BACKUP_PATH)))))


def cmd_restart(m, a):
    if os.geteuid() != 0:
        raise MtpError("нужен root")
    for u in ["mtpctl-web"] + _telemt_units(m):
        subprocess.run(["systemctl", "restart", u])
        print("перезапущен " + u)


def cmd_log(m, a):
    units = ["-u", "mtpctl-web", "-u", "mtpctl-agent"] + [x for u in _telemt_units(m) for x in ("-u", u)]
    subprocess.run(["journalctl", "--no-pager", "-n", str(a.lines)] + units)


def _installer(*args):
    if os.geteuid() != 0:
        raise MtpError("нужен root")
    path = os.path.join(core.LIB_DIR, "install.sh")
    os.execvp("bash", ["bash", path] + list(args))


def cmd_update(m, a):
    cur = core.installed_version()
    latest, _ = core.latest_version(m.db, force=True)
    print("установлена %s, в репозитории %s (%s)" % (cur, latest or "?", core.source_repo()[0]))
    if a.check:
        return
    if latest and core.version_tuple(latest) <= core.version_tuple(cur) and not a.force:
        print("обновлять нечего (принудительно: mtpctl update --force)")
        return
    _installer("update")


def cmd_uninstall(m, a):
    _installer("uninstall")


def cmd_apply(m, a):
    import agent
    import time as _t
    pending_restore()                          # до открытия базы: восстановление её заменяет
    m = core.Manager()
    try:
        sid = m.server(a.server)["id"] if a.server else None
    finally:
        m.close()
    if getattr(a, "covers", False):
        agent.refresh_backgrounds(force=True)
    req = os.path.join(os.path.dirname(core.DB_PATH), "apply.req")
    for _ in range(5):
        t0 = _t.time()
        errs = agent.apply(do_checks=not a.no_checks, force_cert=a.force_cert, only=sid)
        try:
            again = os.path.getmtime(req) > t0          # в кабинете что-то поменяли, пока агент работал
        except OSError:
            again = False
        if not again:
            break
    if errs:
        raise MtpError("с ошибками: " + "; ".join("%s: %s" % kv for kv in errs.items()))


# ---------------------------------------------------------------- menu

MENU = [
    ("Доступ к кабинету (адрес, путь)", cmd_access),
    ("Новый пароль кабинета", cmd_web_reset),
    ("Сменить путь кабинета", cmd_web_path),
    ("Серверы", cmd_server_list),
    ("Клиенты", cmd_list),
    ("Кто сейчас в сети", cmd_online),
    ("Состояние служб", cmd_status),
    ("Применить и проверить сейчас", None),
    ("Перезапустить службы", cmd_restart),
    ("Журнал (последние 100 строк)", cmd_log),
    ("Обновить резервную копию", cmd_backup),
    ("Восстановить базу из копии", "restore"),
    ("Обновить mtpctl", cmd_update),
    ("Удалить mtpctl", cmd_uninstall),
]


def _version():
    try:
        with open(os.path.join(core.LIB_DIR, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "?"


def cmd_menu(m, a):
    ns = argparse.Namespace(random=False, path=None, file=None, lines=100, server=None, no_checks=False,
                            force_cert=True, yes=False, check=False, force=False, covers=False)
    while True:
        print("\n  mtpctl %s — MTProto-прокси (telemt)\n  %s" % (_version(), "─" * 40))
        for i, (title, _) in enumerate(MENU, 1):
            print("  %2d. %s" % (i, title))
        print("   0. Выход")
        try:
            ch = input("\n  Выберите [0-%d]: " % len(MENU)).strip()
        except EOFError:
            return
        if ch in ("0", "q", ""):
            return
        if not ch.isdigit() or not 1 <= int(ch) <= len(MENU):
            continue
        title, fn = MENU[int(ch) - 1]
        print()
        try:
            if fn is None:
                cmd_apply(m, ns)
                for s in m.servers():
                    print()
                    _print_server(m, s)
            elif fn == "restore":
                path = _ask("Путь к файлу копии (.db): ")
                if path and _yes("Заменить базу копией %s? Пароль, путь и домен кабинета останутся текущими" % path):
                    restore_db(path, keep_access=True)
            elif fn is cmd_web_reset:
                if _yes("Сменить пароль кабинета?"):
                    fn(m, ns)
            elif fn is cmd_web_path:
                if _yes("Сменить путь кабинета? Старая ссылка перестанет работать"):
                    fn(m, ns)
            else:
                fn(m, ns)
        except MtpError as e:
            print("ошибка: " + e.message)


def main(argv=None):
    os.umask(0o007)            # файлы базы (-wal/-shm), созданные root, должны оставаться доступны mtpctl-web
    p = argparse.ArgumentParser(prog="mtpctl", description="управление MTProto-прокси (telemt)")
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("client", help="клиенты")
    cs = pc.add_subparsers(dest="sub")

    x = cs.add_parser("add")
    x.add_argument("name")
    x.add_argument("--days", type=int)
    x.add_argument("--until")
    x.add_argument("--note")
    x.add_argument("--quota")
    x.add_argument("--period")
    x.add_argument("--devices", type=int)
    x.add_argument("--key")
    x.add_argument("--server", help="сервер(ы) через запятую; по умолчанию — сервер по умолчанию")
    x.add_argument("--qr", action="store_true")
    x.set_defaults(fn=cmd_add)

    cs.add_parser("list").set_defaults(fn=cmd_list)

    x = cs.add_parser("show")
    x.add_argument("name")
    x.add_argument("--qr", action="store_true")
    x.set_defaults(fn=cmd_show)

    x = cs.add_parser("renew")
    x.add_argument("name")
    x.add_argument("--days", type=int)
    x.add_argument("--until")
    x.add_argument("--never", action="store_true")
    x.set_defaults(fn=cmd_renew)

    x = cs.add_parser("limits")
    x.add_argument("name")
    x.add_argument("--quota")
    x.add_argument("--period")
    x.add_argument("--devices")
    x.set_defaults(fn=cmd_limits)

    x = cs.add_parser("servers")
    x.add_argument("name")
    x.add_argument("servers")
    x.set_defaults(fn=cmd_servers)

    x = cs.add_parser("note")
    x.add_argument("name")
    x.add_argument("text", nargs="*")
    x.set_defaults(fn=cmd_note)

    for act in ("enable", "disable", "rotate", "reset-quota", "delete"):
        x = cs.add_parser(act)
        x.add_argument("name")
        x.add_argument("-y", "--yes", action="store_true")
        x.set_defaults(fn=cmd_simple, action=act)

    ps = sub.add_parser("server", help="серверы (входы)")
    ss = ps.add_subparsers(dest="sub")
    ss.add_parser("list").set_defaults(fn=cmd_server_list)
    x = ss.add_parser("show")
    x.add_argument("server")
    x.set_defaults(fn=cmd_server_show)
    x = ss.add_parser("add")
    x.add_argument("--title", required=True)
    x.add_argument("--domain", required=True)
    x.add_argument("--ip", required=True, help="IP входного хоста")
    x.add_argument("--sni", help="дополнительные SNI-маскировки через запятую, например ya.ru")
    x.add_argument("--devices", help="устройств по умолчанию для клиентов сервера")
    x.add_argument("--note")
    x.add_argument("--default", action="store_true", help="сервер по умолчанию для новых клиентов")
    x.add_argument("--id", help="id (по умолчанию s1, s2, …)")
    x.add_argument("--port", type=int, help="порт telemt на мастере (по умолчанию первый свободный с 8443)")
    x.set_defaults(fn=cmd_server_add)
    x = ss.add_parser("edit")
    x.add_argument("server")
    x.add_argument("--title")
    x.add_argument("--domain")
    x.add_argument("--ip")
    x.add_argument("--sni")
    x.add_argument("--devices")
    x.add_argument("--note")
    x.add_argument("--enable", action="store_true")
    x.add_argument("--disable", action="store_true")
    x.add_argument("--default", action="store_true")
    x.set_defaults(fn=cmd_server_edit)
    x = ss.add_parser("rm")
    x.add_argument("server")
    x.add_argument("-y", "--yes", action="store_true")
    x.set_defaults(fn=cmd_server_rm)
    x = ss.add_parser("check")
    x.add_argument("server", nargs="?")
    x.set_defaults(fn=cmd_server_check)

    sub.add_parser("online").set_defaults(fn=cmd_online)

    x = sub.add_parser("traffic", help="трафик по периодам")
    x.add_argument("name", nargs="?")
    x.add_argument("--range", default="24h", choices=["24h", "7d", "30d", "12m"])
    x.add_argument("--server")
    x.set_defaults(fn=cmd_traffic)

    x = sub.add_parser("settings", help="адрес мастера, домен кабинета")
    x.add_argument("--master-addr")
    x.add_argument("--panel-domain", help="отдельный домен кабинета (A-запись на мастер); пусто — на доменах серверов")
    x.set_defaults(fn=cmd_settings)

    pw = sub.add_parser("web", help="кабинет: доступ, пароль, путь")
    ws = pw.add_subparsers(dest="sub")
    ws.add_parser("access", help="адрес и путь кабинета").set_defaults(fn=cmd_access)
    x = ws.add_parser("passwd", help="сменить пароль (ввести свой)")
    x.set_defaults(fn=cmd_web_passwd)
    x = ws.add_parser("reset", help="новый пароль (случайный или свой)")
    x.add_argument("--random", action="store_true", help="случайные, без вопросов")
    x.set_defaults(fn=cmd_web_reset)
    x = ws.add_parser("path", help="сменить путь кабинета (/<путь>/)")
    x.add_argument("path", nargs="?")
    x.add_argument("--random", action="store_true")
    x.set_defaults(fn=cmd_web_path)

    x = sub.add_parser("backup", help="резервная копия базы (без аргумента — рабочая копия %s)" % core.BACKUP_PATH)
    x.add_argument("file", nargs="?")
    x.set_defaults(fn=cmd_backup)
    x = sub.add_parser("restore", help="заменить базу копией без переустановки (root)")
    x.add_argument("file")
    x.add_argument("-y", "--yes", action="store_true")
    x.add_argument("--access-from-backup", action="store_true",
                   help="взять пароль, путь и домен кабинета из копии (по умолчанию остаются текущие)")
    x.set_defaults(fn=cmd_restore, raw=True)

    sub.add_parser("status", help="состояние служб").set_defaults(fn=cmd_status)
    sub.add_parser("restart", help="перезапустить кабинет и telemt").set_defaults(fn=cmd_restart)
    x = sub.add_parser("log", help="журнал кабинета, агента и telemt")
    x.add_argument("-n", "--lines", type=int, default=100)
    x.set_defaults(fn=cmd_log)
    x = sub.add_parser("update", help="обновить мастер из репозитория (код, telemt, конфиги)")
    x.add_argument("--check", action="store_true", help="только показать версии")
    x.add_argument("--force", action="store_true", help="переустановить, даже если версия та же")
    x.set_defaults(fn=cmd_update)
    sub.add_parser("uninstall", help="удалить mtpctl с этого хоста").set_defaults(fn=cmd_uninstall, raw=True)
    sub.add_parser("menu", help="меню").set_defaults(fn=cmd_menu)

    x = sub.add_parser("setup", help="установщик: база, пароль и путь кабинета (root)")
    x.add_argument("--addr", help="адрес мастера для входов")
    x.add_argument("--panel-domain", help="отдельный домен кабинета")
    x.set_defaults(fn=cmd_setup, raw=True)
    x = sub.add_parser("apply", help="агент: привести хост к базе (root)")
    x.add_argument("--no-checks", action="store_true")
    x.add_argument("--force-cert", action="store_true")
    x.add_argument("--covers", action="store_true", help="докачать фото для заставок сейчас")
    x.add_argument("--server")
    x.set_defaults(fn=cmd_apply, raw=True)

    a = p.parse_args(argv)
    if not hasattr(a, "fn"):
        if a.cmd is None and sys.stdin.isatty() and sys.stdout.isatty():
            a.fn = cmd_menu
        elif a.cmd is None:
            p.print_help()
            return 0
        else:
            p.parse_args([a.cmd, "-h"])
            return 1
    m = None
    try:
        m = None if getattr(a, "raw", False) else _manager()
        a.fn(m, a)
    except MtpError as e:
        print("ошибка: " + e.message, file=sys.stderr)
        return 1
    except sqlite3.OperationalError as e:
        print("ошибка базы: %s%s" % (e, " — запустите от root" if os.geteuid() else ""), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if m is not None:
            m.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
