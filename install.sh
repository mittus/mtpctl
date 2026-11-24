#!/usr/bin/env bash
#
# mtpctl — MTProto-прокси для Telegram (telemt) по схеме «мастер + входы», с веб-кабинетом.
#
#   Мастер (хост с доступом к Telegram: кабинет, база SQLite, telemt на каждый сервер), одной строкой:
#       bash <(wget -qO- https://raw.githubusercontent.com/mittus/mtpctl/master/install.sh)
#     или из каталога проекта:  bash install.sh [master] [--addr IP|DNS] [--panel-domain DNS] [--restore mtpctl.db]
#     Повторный запуск обновляет код и ничего не теряет; --restore переносит мастер с копии базы.
#       bash install.sh update          — скачать свежую версию с GitHub и обновиться (mtpctl update)
#       bash install.sh uninstall       — удалить мастер (копия базы остаётся в /root)
#
#   Вход (хост, к которому подключаются клиенты; данных и ключей на нём нет):
#       bash install.sh slave --master IP|DNS --port PORT
#       bash install.sh slave --uninstall
#     Порт и готовую команду показывает кабинет («Серверы» → «Подключение входа»).
#
#   Переменные: MTPCTL_PASSWORD, MTPCTL_WEB_BASE_PATH, MTPCTL_PANEL_DOMAIN — пароль, путь и домен кабинета
#   (иначе случайные); MTPCTL_REPO_URL, MTPCTL_BRANCH — откуда скачивать исходники.
#
# Поддержка: Debian 10–13, Ubuntu 20.04+ (amd64/arm64).
#
set -euo pipefail

TELEMT_VERSION="3.5.17"
TELEMT_SHA256_x86_64="f1591635849e0aad31f147692b21726da2f49499aae3ece79f8760c92925133a"
TELEMT_SHA256_aarch64="c80b0159b41cf410b2a87cf62676d67a16a537bd7207602b60dd9ce56e14d1f6"
TELEMT_URL="https://github.com/telemt/telemt/releases/download"

DEFAULT_REPO_URL="https://github.com/mittus/mtpctl"

HOME_DIR=/opt/mtpctl                         # домашний каталог пользователя mtpctl
APP=$HOME_DIR/app                            # код (root, только чтение)
DATA=$HOME_DIR/data                          # база SQLite (mtpctl)
BACKUP=$HOME_DIR/backup                      # рабочая копия базы (root)
DB=$DATA/mtpctl.db
BIN=/usr/local/bin/mtpctl
WEBROOT=/var/www/mtpctl
SLAVE_CONF=/etc/nginx/stream.d/mtproxy.conf
SELF="${BASH_SOURCE[0]}"
# откуда ставили — туда же ходит update (форк остаётся форком)
REPO_URL="${MTPCTL_REPO_URL:-$(sed -n 's/^REPO_URL=//p' "$APP/SOURCE" 2>/dev/null || true)}"
REPO_URL="${REPO_URL:-$DEFAULT_REPO_URL}"
REPO_BRANCH="${MTPCTL_BRANCH:-$(sed -n 's/^BRANCH=//p' "$APP/SOURCE" 2>/dev/null || true)}"   # пусто — master, затем main
SRC=""
SRC_BRANCH=""
TMP_DIR=""
trap '[ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"' EXIT

C_OK=$'\033[1;32m'; C_ERR=$'\033[1;31m'; C_WARN=$'\033[1;33m'; C_INFO=$'\033[1;36m'; C_OFF=$'\033[0m'
[ -t 1 ] || { C_OK=; C_ERR=; C_WARN=; C_INFO=; C_OFF=; }
info() { printf '%s[mtpctl]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
ok()   { printf '%s[mtpctl]%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s[mtpctl]%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '%s[mtpctl] ОШИБКА:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

usage() { printf '%s\n' \
    "mtpctl installer" \
    "  bash install.sh [master] [--addr IP|DNS] [--panel-domain DNS] [--restore mtpctl.db]   мастер" \
    "  bash install.sh update | uninstall                               обновить / удалить мастер" \
    "  bash install.sh slave --master IP|DNS --port PORT                вход" \
    "  bash install.sh slave --uninstall"; exit "${1:-1}"; }

# --------------------------------------------------------------------------- общее

need_root() { [ "$(id -u)" -eq 0 ] || die "нужны права root (sudo bash install.sh …)"; }

detect_os() {
    [ -r /etc/os-release ] || die "нет /etc/os-release — система не поддерживается"
    # shellcheck disable=SC1091
    . /etc/os-release
    local major="${VERSION_ID%%.*}"
    case "${ID:-}" in
        debian) [ "${major:-0}" -ge 10 ] 2>/dev/null || die "нужен Debian 10+";;
        ubuntu) [ "${major:-0}" -ge 20 ] 2>/dev/null || die "нужен Ubuntu 20.04+";;
        *) case " ${ID_LIKE:-} " in *debian*) warn "${PRETTY_NAME:-$ID}: не проверялось, но совместимо с Debian";;
                                       *) die "поддерживаются Debian и Ubuntu";; esac;;
    esac
    command -v apt-get >/dev/null || die "нет apt-get"
}

APT_UPDATED=
apt_install() {
    local missing=() p
    for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
    [ "${#missing[@]}" -eq 0 ] && return 0
    [ -n "${MTP_SKIP_APT:-}" ] && die "не хватает пакетов: ${missing[*]}"
    info "пакеты: ${missing[*]}"
    if [ -z "$APT_UPDATED" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || die "apt-get update не прошёл (Debian 10: нужен archive.debian.org)"
        APT_UPDATED=1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null \
        || die "не удалось поставить: ${missing[*]}"
}

valid_addr() {   # IPv4 или DNS-имя
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0
    [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$ ]]
}

is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

public_ip() {
    curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null \
        || ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p'
}

# nginx со stream-модулем и блоком stream { include /etc/nginx/stream.d/*.conf; }
ensure_nginx_stream() {
    apt_install nginx
    # в подоболочке: die внутри apt_install не должен обрывать установку (nginx.org: stream уже встроен)
    dpkg -s libnginx-mod-stream >/dev/null 2>&1 || ( apt_install libnginx-mod-stream ) 2>/dev/null \
        || warn "пакета libnginx-mod-stream нет — проверю, встроен ли stream в nginx"
    mkdir -p /etc/nginx/stream.d
    local conf=/etc/nginx/nginx.conf
    if ! grep -qE '^[[:space:]]*stream[[:space:]]*\{' "$conf"; then
        printf '\n# mtpctl\nstream { include /etc/nginx/stream.d/*.conf; }\n' >> "$conf"
        info "nginx.conf: добавлен блок stream"
    elif ! grep -q 'stream.d/\*\.conf' "$conf"; then
        die "в $conf уже есть свой блок stream — добавьте в него: include /etc/nginx/stream.d/*.conf;"
    fi
    local test_out
    test_out=$(nginx -t 2>&1 || true)
    if printf '%s' "$test_out" | grep -q 'unknown directive "stream"'; then
        local so
        so=$(ls /usr/share/nginx/modules/ngx_stream_module.so /usr/lib/nginx/modules/ngx_stream_module.so 2>/dev/null | head -1)
        [ -n "$so" ] || die "у nginx нет модуля stream"
        sed -i "1i load_module $so;" "$conf"
        info "nginx.conf: подключён модуль $so"
    fi
}

nginx_apply() {
    nginx -t 2>/tmp/mtpctl-nginx-t.log || { cat /tmp/mtpctl-nginx-t.log >&2; die "nginx -t не прошёл"; }
    systemctl enable nginx >/dev/null 2>&1 || true
    if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl restart nginx; fi
}

# --------------------------------------------------------------------------- вход (slave)

slave() {
    local master="" port="" force="" uninstall=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --master) master="${2:-}"; shift 2;;
            --port) port="${2:-}"; shift 2;;
            --force) force=1; shift;;
            --uninstall) uninstall=1; shift;;
            -h|--help) usage 0;;
            *) die "неизвестный параметр: $1";;
        esac
    done
    need_root; detect_os
    if [ -n "$uninstall" ]; then
        [ -f "$SLAVE_CONF" ] || { ok "вход не установлен"; return; }
        mv "$SLAVE_CONF" "/root/mtproxy.conf.removed-$(date +%Y%m%d%H%M%S)"
        nginx_apply
        ok "вход удалён (nginx остался; конфиг сохранён в /root)"
        return
    fi
    master="${master,,}"
    [ -n "$master" ] && valid_addr "$master" || die "укажите --master IP или DNS-имя мастера"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "укажите --port (порт сервера на мастере)"

    ensure_nginx_stream
    apt_install iproute2
    # 80 и 443 должны быть свободны (или заняты этим же nginx)
    local busy
    busy=$(ss -ltnpH 2>/dev/null | awk '$4 ~ /:(80|443)$/' | grep -v '"nginx"' || true)
    [ -z "$busy" ] || die "порты 80/443 заняты не nginx:
$busy"
    if [ -L /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
        info "отключён стандартный сайт nginx (sites-enabled/default): порт 80 нужен входу"
    fi
    local clash
    clash=$(grep -lE '^[[:space:]]*listen[[:space:]]+([^;]*:)?(80|443)([[:space:]]|;)' \
        /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null || true)
    if [ -n "$clash" ] && [ -z "$force" ]; then
        die "сайты nginx на 80/443 помешают входу: $(echo $clash) — уберите их или --force"
    fi

    local target80 target443 head=""
    if is_ip "$master"; then
        target443="$master:$port"; target80="$master:80"
    else
        # DNS-имя мастера перечитывается каждые 5 минут: переезд мастера = смена A-записи
        local ns
        ns=$(awk '$1=="nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ {print $2}' /etc/resolv.conf | head -2 | xargs)
        head="map \$remote_addr \$mtp_master_tls  { default $master:$port; }
map \$remote_addr \$mtp_master_http { default $master:80; }
"
        target443='$mtp_master_tls'; target80='$mtp_master_http'
        RESOLVER="    resolver ${ns:-1.1.1.1 8.8.8.8} valid=300s ipv6=off;"
    fi
    cat > "$SLAVE_CONF.new" <<EOF
# Вход mtpctl: всё с 443 без расшифровки -> мастер $master:$port (telemt) с PROXY protocol,
# HTTP (сайт-заглушка и выпуск сертификата) -> мастер :80. Создано install.sh slave $(date +%Y-%m-%d).
$head
server {
    listen 443;
${RESOLVER:-}
    proxy_pass $target443;
    proxy_protocol on;
    proxy_connect_timeout 5s;
    proxy_timeout 10m;
}

server {
    listen 80;
${RESOLVER:-}
    proxy_pass $target80;
    proxy_connect_timeout 5s;
}
EOF
    [ -f "$SLAVE_CONF" ] && cp "$SLAVE_CONF" "/root/mtproxy.conf.bak-$(date +%Y%m%d%H%M%S)"
    mv "$SLAVE_CONF.new" "$SLAVE_CONF"
    nginx_apply
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 443/tcp >/dev/null; ufw allow 80/tcp >/dev/null
        info "ufw: открыты 80 и 443"
    fi
    ok "вход настроен: 443 -> $master:$port, 80 -> $master:80"
    if timeout 6 bash -c "exec 3<>/dev/tcp/$master/$port" 2>/dev/null; then
        ok "мастер принимает соединения с этого хоста"
    else
        warn "мастер $master:$port не отвечает этому хосту. Проверьте, что в кабинете у сервера"
        warn "указан IP этого хоста ($(public_ip || echo '?')) — мастер открывает порт только для него."
    fi
    info "дальше: A-запись домена сервера -> IP этого хоста, затем «Проверить» в кабинете."
}

# --------------------------------------------------------------------------- мастер

fetch_sources() {     # $1=force — всегда скачивать (update)
    local here
    here="$(cd "$(dirname "$SELF")" 2>/dev/null && pwd || true)"
    if [ "${1:-}" != force ] && [ -n "$here" ] && [ -f "$here/mtpctl/core.py" ]; then
        SRC="$here"; info "исходники: $SRC"; return
    fi
    command -v curl >/dev/null || apt_install curl ca-certificates
    TMP_DIR="$(mktemp -d)"
    local br got=""
    for br in ${REPO_BRANCH:-master main}; do
        info "скачиваю $REPO_URL ($br)"
        if curl -fsSL --retry 3 --max-time 120 "$REPO_URL/archive/refs/heads/$br.tar.gz" -o "$TMP_DIR/src.tgz"; then
            got=1; SRC_BRANCH=$br; break
        fi
    done
    [ -n "$got" ] || die "не удалось скачать исходники с $REPO_URL"
    tar xzf "$TMP_DIR/src.tgz" -C "$TMP_DIR" || die "архив исходников повреждён"
    SRC="$(dirname "$(find "$TMP_DIR" -maxdepth 3 -path '*/mtpctl/core.py' -print -quit)")"
    SRC="${SRC%/mtpctl}"
    [ -f "$SRC/mtpctl/core.py" ] || die "в архиве нет mtpctl/"
}

install_telemt() {
    if [ -n "${MTP_TELEMT_BIN:-}" ]; then           # тесты: подменный telemt
        install -m 755 "$MTP_TELEMT_BIN" /usr/local/bin/telemt
        return
    fi
    if /usr/local/bin/telemt --version 2>/dev/null | grep -qx "telemt $TELEMT_VERSION"; then
        ok "telemt $TELEMT_VERSION уже установлен"
        return
    fi
    local arch sha tmp b upgrade=""
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64; sha=$TELEMT_SHA256_x86_64;;
        aarch64|arm64) arch=aarch64; sha=$TELEMT_SHA256_aarch64;;
        *) die "архитектура $(uname -m) не поддерживается";;
    esac
    tmp=$(mktemp -d)
    info "скачиваю telemt $TELEMT_VERSION ($arch)"
    curl -fsSL --retry 3 --max-time 180 -o "$tmp/t.tgz" "$TELEMT_URL/$TELEMT_VERSION/telemt-$arch-linux-musl.tar.gz" \
        || { rm -rf "$tmp"; die "не скачался telemt"; }
    echo "$sha  $tmp/t.tgz" | sha256sum -c --quiet - || { rm -rf "$tmp"; die "контрольная сумма telemt не совпала"; }
    mkdir "$tmp/x" && tar xzf "$tmp/t.tgz" -C "$tmp/x"
    b=$(find "$tmp/x" -type f -name telemt | head -1)
    [ -n "$b" ] || { rm -rf "$tmp"; die "в архиве нет telemt"; }
    [ -x /usr/local/bin/telemt ] && upgrade=1
    install -m 755 "$b" /usr/local/bin/telemt
    rm -rf "$tmp"
    ok "telemt $TELEMT_VERSION установлен"
    if [ -n "$upgrade" ]; then
        local u
        for u in $(systemctl list-units 'telemt@*' --all --no-legend --plain 2>/dev/null | awk '{print $1}'); do
            if systemctl is-active --quiet "$u"; then systemctl restart "$u" && info "перезапущен $u" || true; fi
        done
    else
        TELEMT_FRESH=1                             # uninstall удалит telemt, только если ставили его мы
    fi
    return 0
}

install_files() {
    install -d -o root -g mtpctl -m 750 "$HOME_DIR"
    install -d -o mtpctl -g mtpctl -m 2770 "$DATA"
    install -d -o root -g root -m 700 "$BACKUP"
    rm -rf "$APP.new"
    cp -r "$SRC/mtpctl" "$APP.new"
    install -m 644 "$SRC/install.sh" "$APP.new/install.sh"
    install -m 644 "$SRC/VERSION" "$APP.new/VERSION" 2>/dev/null || echo dev > "$APP.new/VERSION"
    printf 'REPO_URL=%s\nBRANCH=%s\n' "$REPO_URL" "${SRC_BRANCH:-$REPO_BRANCH}" > "$APP.new/SOURCE"
    find "$APP.new" -name __pycache__ -prune -exec rm -rf {} +
    chown -R root:root "$APP.new"; chmod -R u=rwX,go=rX "$APP.new"
    rm -rf "$APP.old"; [ -d "$APP" ] && mv "$APP" "$APP.old"
    mv "$APP.new" "$APP"; rm -rf "$APP.old"
    printf '#!/bin/sh\nexec /usr/bin/python3 -I %s/cli.py "$@"\n' "$APP" > "$BIN"
    chmod 755 "$BIN"
    install -d -m 755 "$WEBROOT" "$WEBROOT/.well-known/acme-challenge"
    local u
    for u in "$APP"/systemd/*; do install -m 644 "$u" /etc/systemd/system/; done
    systemctl daemon-reload
}

master() {
    local addr="" restore="" force="" pdomain=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --addr) addr="${2:-}"; shift 2;;
            --panel-domain) pdomain="${2:-}"; shift 2;;
            --restore) restore="${2:-}"; shift 2;;
            --update) force=1; shift;;
            -h|--help) usage 0;;
            *) die "неизвестный параметр: $1";;
        esac
    done
    need_root; detect_os
    [ -z "$restore" ] || [ -f "$restore" ] || die "нет файла $restore"
    [ -z "$restore" ] || restore="$(cd "$(dirname "$restore")" && pwd)/$(basename "$restore")"
    if [ -n "$addr" ]; then addr="${addr,,}"; valid_addr "$addr" || die "--addr: IPv4 или DNS-имя"; fi

    apt_install python3 openssl ca-certificates curl tar certbot iproute2
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 7))' || die "нужен Python 3.7+"
    fetch_sources ${force:+force}
    ensure_nginx_stream
    install_telemt

    id telemt >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/telemt --shell /usr/sbin/nologin telemt
    id mtpctl >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$HOME_DIR" --shell /usr/sbin/nologin mtpctl
    install -d -o telemt -g telemt -m 750 /etc/telemt /var/lib/telemt

    systemctl stop mtpctl-web 2>/dev/null || true
    install_files
    [ -z "${TELEMT_FRESH:-}" ] || touch "$HOME_DIR/.telemt-installed"
    [ -f "$DB" ] && "$BIN" backup >/dev/null 2>&1 || true          # рабочая копия до изменений

    if [ -n "$restore" ]; then
        if [ -f "$DB" ]; then
            "$BIN" restore "$restore" -y
        else
            python3 -I -c "import sys; sys.path.insert(0, '$APP'); import core; core.check_db_file(sys.argv[1])" "$restore" \
                || die "$restore — не база mtpctl"
            install -o mtpctl -g mtpctl -m 660 "$restore" "$DB"
            python3 -I -c "import sys; sys.path.insert(0, '$APP'); import core; s = core.Store(create=True); s.x('UPDATE server_state SET applied=NULL, cert_try=NULL'); s.close()"
            ok "база восстановлена из $restore"
        fi
        if [ -z "$addr" ]; then                     # переезд: прежний IP мастера заменяем текущим (DNS-имя оставляем)
            local cur pub
            cur=$("$BIN" settings 2>/dev/null | sed -n 's/^адрес мастера для входов: //p' || true)
            pub=$(public_ip || true)
            if { [ -z "$cur" ] || [ "$cur" = "не задан" ] || is_ip "$cur"; } && [ -n "$pub" ] && [ "$cur" != "$pub" ]; then
                addr=$pub
                warn "адрес мастера: $cur -> $pub — входы нужно перенастроить на новый адрес"
            fi
        fi
    fi
    [ -f "$DB" ] || [ -n "$addr" ] || addr=$(public_ip || true)

    systemctl enable --now mtpctl-agent.path mtpctl-agent.timer mtpctl-backup.timer >/dev/null 2>&1
    systemctl enable mtpctl-web >/dev/null 2>&1
    "$BIN" setup ${addr:+--addr "$addr"} ${pdomain:+--panel-domain "$pdomain"}   # пароль и путь кабинета — как в 3x-ui
    systemctl restart mtpctl-web
    info "применяю конфигурацию (telemt, ufw, nginx, сертификаты)…"
    "$BIN" apply || warn "применилось не всё — подробности выше и в mtpctl server list"
    echo
    "$BIN" server list || true
    echo
    if ! "$BIN" server list 2>/dev/null | grep -q '^[a-z]' && [ -z "$("$BIN" settings | sed -n 's/^домен кабинета: \([a-z0-9.-]*\)$/\1/p')" ]; then
        cat <<EOF
Дальше:
  1. Добавьте первый сервер (вход):  mtpctl server add --title Знакомые --domain example.org --ip <IP входа>
  2. На входном хосте выполните команду, которую покажет mtpctl, и сделайте A-запись домена на его IP.
  3. Кабинет откроется на https://<домен сервера>/<путь кабинета>/ — путь и пароль выше.
EOF
    elif [ -n "$restore" ]; then
        echo "Если адрес мастера поменялся, на каждом входе повторите команду из «Подключение входа»."
    fi
    echo "Меню управления: mtpctl"
}

uninstall_master() {
    need_root
    [ -d "$HOME_DIR" ] || [ -f "$BIN" ] || { ok "mtpctl не установлен"; return; }
    if [ -t 0 ]; then
        read -r -p "Удалить мастер mtpctl (кабинет, telemt всех серверов, правила nginx и ufw)? [y/N]: " ans
        case "$ans" in y|Y|yes|д|да) ;; *) echo "отменено"; return;; esac
    fi
    local keep="" u n domains="" own_telemt=""
    [ -f "$HOME_DIR/.telemt-installed" ] && own_telemt=1
    if [ -f "$DB" ]; then
        domains=$(python3 -I -c "import sqlite3; c = sqlite3.connect('file:$DB?mode=ro', uri=True); print(' '.join([r[0] for r in c.execute('select domain from servers')] + [r[0] for r in c.execute(\"select v from meta where k='panel_domain'\")]))" 2>/dev/null || true)
        keep="/root/mtpctl-uninstall-$(date +%Y%m%d%H%M%S).db"
        python3 -I -c "import sqlite3,sys; s=sqlite3.connect('file:$DB?mode=ro',uri=True); d=sqlite3.connect(sys.argv[1]); s.backup(d)" "$keep"
        chmod 600 "$keep"
    fi
    for u in mtpctl-web mtpctl-agent.path mtpctl-agent.timer mtpctl-agent mtpctl-backup.timer; do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
    done
    for u in $(systemctl list-units 'telemt@*' --all --no-legend --plain 2>/dev/null | awk '{print $1}'); do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
    done
    grep -l '^# mtpctl: server ' /etc/telemt/*.toml 2>/dev/null | xargs -r rm -f
    rm -f /etc/nginx/conf.d/mtp-*.conf /etc/nginx/stream.d/mtp-mask.conf /etc/nginx/snippets/mtpanel.conf \
          /etc/nginx/snippets/mtpanel-direct.conf \
          /etc/nginx/mtpctl-fallback.crt /etc/nginx/mtpctl-fallback.key
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || warn "проверьте nginx -t"
    if command -v ufw >/dev/null; then
        for n in $(ufw status numbered 2>/dev/null | grep '# mtpctl:' | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn); do
            ufw --force delete "$n" >/dev/null
        done
    fi
    for n in $domains; do                       # продление через удалённый webroot иначе будет падать
        [ -f "/etc/letsencrypt/renewal/$n.conf" ] && certbot delete --cert-name "$n" --non-interactive >/dev/null 2>&1 \
            && info "сертификат $n удалён"
    done
    rm -f /etc/systemd/system/mtpctl-* /etc/systemd/system/telemt@.service "$BIN"
    [ -n "$own_telemt" ] && rm -f /usr/local/bin/telemt
    systemctl daemon-reload
    rm -rf "$HOME_DIR" "$WEBROOT"
    rmdir /etc/telemt /var/lib/telemt/* /var/lib/telemt 2>/dev/null || true
    userdel mtpctl 2>/dev/null || true
    [ -n "$own_telemt" ] && { userdel telemt 2>/dev/null || true; }
    ok "mtpctl удалён${keep:+; копия базы: $keep}. Блок stream {} в nginx.conf оставлен."
}

# --------------------------------------------------------------------------- main

case "${1:-master}" in
    master) [ $# -gt 0 ] && shift; master "$@";;
    --*)    master "$@";;
    update) shift; master --update "$@";;
    uninstall) shift; uninstall_master "$@";;
    slave)  shift; slave "$@";;
    -h|--help|help) usage 0;;
    *) die "неизвестная команда: $1 (bash install.sh --help)";;
esac
