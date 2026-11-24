#!/usr/bin/env bash
# Сквозная проверка установщика в контейнерах с systemd (telemt подменён tests/fake_telemt.py):
#   m1 — мастер одной строкой (bash <(…), исходники с «GitHub»), e1 — вход (install.sh slave),
#   m2 — новый мастер из копии базы (--restore, ufw), затем uninstall.
#
#   bash tests/docker-e2e.sh [образ]          по умолчанию debian:13
#   KEEP=1 bash tests/docker-e2e.sh           не удалять контейнеры после прогона
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(dirname "$HERE")"
BASE="${1:-debian:13}"
TAG="mtpctl-e2e:$(echo "$BASE" | tr ':/' '--')"
NET=mtpctl-e2e
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  [ok]   $1"; }
bad() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }
chk() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
x()   { local c="$1"; shift; docker exec "$c" bash -c "$*"; }

docker build -q -t "$TAG" - >/dev/null <<EOF || { echo "сборка образа не удалась"; exit 2; }
FROM $BASE
ENV DEBIAN_FRONTEND=noninteractive
RUN (apt-get update -qq || { sed -i -e 's|deb.debian.org|archive.debian.org|g' -e 's|security.debian.org|archive.debian.org|g' -e '/-updates/d' /etc/apt/sources.list && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive && apt-get update -qq; }) && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus \
    nginx libnginx-mod-stream python3 certbot curl openssl iproute2 ca-certificates procps tar ufw iptables \
    >/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN systemctl mask getty@tty1.service console-getty.service >/dev/null 2>&1; true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

cleanup() {
    [ -n "${KEEP:-}" ] && { echo "контейнеры оставлены: m1 e1 m2 (docker rm -f m1 e1 m2; docker network rm $NET)"; return; }
    docker rm -f m1 e1 m2 >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
docker rm -f m1 e1 m2 >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >/dev/null
for c in m1 e1 m2; do
    docker run -d --name "$c" --hostname "$c" --network "$NET" --privileged --tmpfs /run --tmpfs /run/lock \
        -v "$SRC":/src:ro "$TAG" >/dev/null
done
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
M1=$(ip_of m1); E1=$(ip_of e1); M2=$(ip_of m2)
for c in m1 e1 m2; do x "$c" 'for i in $(seq 60); do systemctl is-system-running 2>/dev/null | grep -qE "running|degraded" && exit 0; sleep 1; done; exit 1' || echo "systemd в $c не поднялся"; done
echo "=== $BASE: m1=$M1 e1=$E1 m2=$M2 ==="
D=t.example.test

echo "--- мастер m1: установка одной строкой (bash <(wget …)), «GitHub» — локальный http.server"
x m1 'mkdir -p /root/gh/archive/refs/heads && cd /root && rm -rf mtpctl-master && cp -r /src mtpctl-master \
      && rm -rf mtpctl-master/local mtpctl-master/.git && tar czf gh/archive/refs/heads/master.tar.gz mtpctl-master \
      && (cd /root/gh && nohup python3 -m http.server 8000 >/dev/null 2>&1 &) && sleep 1'
x m1 "cd /tmp && MTPCTL_REPO_URL=http://127.0.0.1:8000 MTP_TELEMT_BIN=/src/tests/fake_telemt.py bash <(cat /src/install.sh) --addr $M1" \
    > /tmp/mtpctl-e2e-m1.log 2>&1 && ok "установка одной строкой" || { bad "установка одной строкой"; tail -30 /tmp/mtpctl-e2e-m1.log; }
chk "исходники скачаны с «GitHub»" grep -q "скачиваю http://127.0.0.1:8000 (master)" /tmp/mtpctl-e2e-m1.log
USER_=$(sed -n 's/^  Логин: *//p' /tmp/mtpctl-e2e-m1.log | head -1)
PW=$(sed -n 's/^  Пароль: *//p' /tmp/mtpctl-e2e-m1.log | head -1)
BASE=$(sed -n 's#^  Путь кабинета: */\([^/]*\)/#\1#p' /tmp/mtpctl-e2e-m1.log | head -1)
chk "логин, пароль и путь сгенерированы (10/16/18)" test "${#USER_}" = 10 -a "${#PW}" = 16 -a "${#BASE}" = 18
chk "mtpctl-web работает" x m1 'systemctl is-active mtpctl-web'
chk "агент: path и timer включены" x m1 'systemctl is-active mtpctl-agent.path mtpctl-agent.timer mtpctl-backup.timer'
chk "всё в /opt/mtpctl, база mtpctl:mtpctl 660" x m1 '[ "$(stat -c %U:%G:%a /opt/mtpctl/data/mtpctl.db)" = mtpctl:mtpctl:660 ] && [ -f /opt/mtpctl/app/core.py ]'
chk "домашний каталог mtpctl = /opt/mtpctl" x m1 '[ "$(getent passwd mtpctl | cut -d: -f6)" = /opt/mtpctl ]'
x m1 "mtpctl server add --title Тест --domain $D --ip $E1 --sni ya.ru" > /tmp/mtpctl-e2e-add.log 2>&1 \
    && ok "server add (CLI, сразу применяется)" || { bad "server add"; tail -20 /tmp/mtpctl-e2e-add.log; }
chk "telemt@s1 запущен" x m1 'systemctl is-active telemt@s1'
chk "конфиг telemt: доверяет только входу" x m1 "grep -q 'proxy_protocol_trusted_cidrs = \[\"$E1/32\"\]' /etc/telemt/s1.toml"
chk "nginx: сайт $D с временным сертификатом" x m1 "grep -q mtpctl-fallback.crt /etc/nginx/conf.d/mtp-$D.conf"
chk "nginx: маскировка ya.ru" x m1 "grep -q 'ya.ru ya.ru:443' /etc/nginx/stream.d/mtp-mask.conf"
chk "nginx: кабинет на /$BASE/" x m1 "grep -q 'location /$BASE/api/' /etc/nginx/snippets/mtpanel.conf"
chk "команда для входа показана" grep -q "install.sh slave --master $M1 --port 8443" /tmp/mtpctl-e2e-add.log
x m1 'mtpctl backup' >/dev/null 2>&1 && x m1 '[ "$(stat -c %a /opt/mtpctl/backup/mtpctl.db)" = 600 ]' \
    && ok "рабочая копия /opt/mtpctl/backup/mtpctl.db (600)" || bad "рабочая копия"
chk "копия одна" x m1 '[ "$(ls /opt/mtpctl/backup | wc -l)" = 1 ]'

echo "--- вход e1"
x e1 "bash /src/install.sh slave --master $M1 --port 8443" > /tmp/mtpctl-e2e-e1.log 2>&1 \
    && ok "install.sh slave" || { bad "install.sh slave"; tail -20 /tmp/mtpctl-e2e-e1.log; }
chk "вход видит мастер" grep -q "мастер принимает соединения" /tmp/mtpctl-e2e-e1.log
chk "повторный slave безопасен" x e1 "bash /src/install.sh slave --master $M1 --port 8443"
x m1 'mtpctl server check s1' > /tmp/mtpctl-e2e-check.log 2>&1
chk "проверка мастера: вход отвечает" grep -q "✓ вход $E1:443 отвечает" /tmp/mtpctl-e2e-check.log
chk "проверка мастера: DNS не настроен (ожидаемо)" grep -q "✗ у $D нет A-записи" /tmp/mtpctl-e2e-check.log

echo "--- кабинет через вход (как снаружи)"
cat > /tmp/mtpctl-e2e-client.sh <<'EOS'
set -e
D=$1; IP=$2; U=$3; PW=$4; B=$5
R="--resolve $D:443:$IP"
C="curl -sk $R -H X-Requested-With:XMLHttpRequest -H Content-Type:application/json -c /tmp/j -b /tmp/j"
curl -sk $R https://$D/ | grep -q 'id="t"' && ! curl -sk $R https://$D/ | grep -q api/login && echo COVER
[ "$(curl -sk -o /dev/null -w '%{http_code}' $R https://$D/robots.txt)" = 200 ] && echo ROBOTS
[ "$(curl -sk -o /dev/null -w '%{http_code} %{content_type}' $R https://$D/favicon.ico)" = "200 image/x-icon" ] && echo FAVICON
[ "$(curl -sk -o /tmp/404 -w '%{http_code}' $R https://$D/wp-login.php)" = 404 ] && grep -q "Такой страницы нет" /tmp/404 && echo PAGE404
[ "$(curl -sk -o /dev/null -w '%{http_code}' $R -H X-Requested-With:XMLHttpRequest -d "{\"user\":\"$U\",\"password\":\"$PW\"}" https://$D/api/login)" = 404 ] && echo NO_ROOT_API
curl -sk $R https://$D/$B/ | grep -q api/login && echo PAGE
[ "$(curl -sk -o /dev/null -w '%{http_code}' $R -H X-Requested-With:XMLHttpRequest https://$D/$B/api/clients)" = 404 ] && echo HIDDEN
$C -d "{\"user\":\"$U\",\"password\":\"$PW\"}" -D /tmp/h https://$D/$B/api/login | grep -q '"ok": true' && echo LOGIN
grep -qi "set-cookie: sid=.*Path=/$B/;" /tmp/h && echo COOKIE_PATH
$C -d '{"name":"e2e","devices":2}' https://$D/$B/api/clients | grep -q '"name": "e2e"' && echo CLIENT
$C https://$D/$B/api/clients | grep -q "server=$IP" && echo LINKS
$C -d '{"title":"Второй","domain":"two.example.test","entry_ip":"192.0.2.55"}' https://$D/$B/api/servers | grep -q slave_cmd && echo SERVER
EOS
docker cp /tmp/mtpctl-e2e-client.sh e1:/root/c.sh >/dev/null
R=$(x e1 "bash /root/c.sh $D $E1 '$USER_' '$PW' '$BASE'" 2>&1)
for k in COVER ROBOTS FAVICON PAGE404 NO_ROOT_API PAGE HIDDEN LOGIN COOKIE_PATH CLIENT LINKS SERVER; do
    case " $(echo $R) " in *" $k "*) ok "кабинет: $k";; *) bad "кабинет: $k ($R)";; esac
done
chk "реальный IP клиента дошёл до кабинета (PROXY)" x m1 "journalctl -u mtpctl-web --no-pager | grep -q 'login ok from $E1'"
chk "клиент e2e попал в telemt@s1" x m1 'mtpctl client show e2e | grep -q "tg://proxy"'
x m1 'for i in $(seq 40); do systemctl is-active -q telemt@s2 && exit 0; sleep 1; done; exit 1' \
    && ok "сервер из кабинета: агент поднял telemt@s2 сам" || bad "telemt@s2 не поднялся"
x m1 'mtpctl server rm s2 -y' >/dev/null 2>&1
chk "удаление сервера: telemt@s2 остановлен" x m1 '! systemctl is-active -q telemt@s2 && [ ! -f /etc/telemt/s2.toml ]'
x m1 'mtpctl web path --random' > /tmp/mtpctl-e2e-path.log 2>&1
NB=$(sed -n 's#^Путь кабинета: /\([^/]*\)/#\1#p' /tmp/mtpctl-e2e-path.log)
code_of() { x e1 "for i in \$(seq 10); do c=\$(curl -sk -o /dev/null -w '%{http_code}' --resolve $D:443:$E1 https://$D$1); [ \$c = $2 ] && break; sleep 0.5; done; echo \$c"; }
chk "смена пути: старый путь больше не работает" test "$(code_of /$BASE/ 404)" = 404
chk "смена пути: новый работает" test "$(code_of /$NB/ 200)" = 200
BASE=$NB
x m1 'mtpctl settings --panel-domain panel.example.test' > /tmp/mtpctl-e2e-pd.log 2>&1 && ok "домен кабинета задан" || { bad "домен кабинета"; tail /tmp/mtpctl-e2e-pd.log; }
chk "кабинет на своём домене (прямо на 443 мастера)" test "$(x e1 "curl -sk --resolve panel.example.test:443:$M1 https://panel.example.test/$BASE/ | grep -c api/login")" -ge 1
chk "на домене сервера кабинета больше нет" test "$(code_of /$BASE/ 404)" = 404
chk "заставка и на домене кабинета" test "$(x e1 "curl -sk --resolve panel.example.test:443:$M1 https://panel.example.test/ | grep -c 'id=\"t\"'")" -ge 1
x m1 "mtpctl settings --panel-domain ''" >/dev/null 2>&1
chk "домен кабинета снят — кабинет снова на доменах серверов" test "$(code_of /$BASE/ 200)" = 200
x m1 'mtpctl backup /root/b.db' >/dev/null && ok "backup в файл" || bad "backup в файл"

echo "--- переезд мастера на m2 (с ufw)"
docker cp m1:/root/b.db /tmp/mtpctl-e2e-b.db >/dev/null && docker cp /tmp/mtpctl-e2e-b.db m2:/root/b.db >/dev/null
x m2 'ufw allow 22/tcp >/dev/null && ufw --force enable >/dev/null' && ok "ufw включён на m2" || bad "ufw на m2"
x m2 "MTP_TELEMT_BIN=/src/tests/fake_telemt.py bash /src/install.sh master --restore /root/b.db --addr $M2" > /tmp/mtpctl-e2e-m2.log 2>&1 \
    && ok "install.sh master --restore" || { bad "install.sh master --restore"; tail -30 /tmp/mtpctl-e2e-m2.log; }
chk "после restore логин не сброшен" grep -q "Пароль: *(не менялся" /tmp/mtpctl-e2e-m2.log
chk "клиент e2e на новом мастере" x m2 'mtpctl client show e2e | grep -q "tg://proxy"'
chk "ufw: порт 8443 только для входа" x m2 "ufw status | grep -qE '^8443/tcp +ALLOW +$E1 +# mtpctl:s1'"
x e1 "bash /src/install.sh slave --master $M2 --port 8443" >/dev/null 2>&1 && ok "вход перенаправлен на m2" || bad "вход на m2"
R=$(x e1 "bash /root/c.sh $D $E1 '$USER_' '$PW' '$BASE' 2>&1")
case " $(echo $R) " in *" LOGIN "*) ok "кабинет на m2: тот же логин, пароль и путь";; *) bad "кабинет на m2 ($R)";; esac
x m2 'mtpctl server check s1' > /tmp/mtpctl-e2e-check2.log 2>&1
chk "m2: вход отвечает" grep -q "✓ вход $E1:443 отвечает" /tmp/mtpctl-e2e-check2.log
chk "повторный install.sh master безопасен" x m2 "MTP_TELEMT_BIN=/src/tests/fake_telemt.py bash /src/install.sh"

echo "--- удаление мастера m2"
x m2 'bash /opt/mtpctl/app/install.sh uninstall </dev/null' > /tmp/mtpctl-e2e-un.log 2>&1 && ok "uninstall" || { bad "uninstall"; tail /tmp/mtpctl-e2e-un.log; }
chk "uninstall: ничего не осталось" x m2 '[ ! -e /opt/mtpctl ] && [ ! -e /usr/local/bin/mtpctl ] && ! ls /etc/nginx/conf.d/mtp-* 2>/dev/null && ! systemctl is-active -q telemt@s1'
chk "uninstall: правила ufw убраны" x m2 '! ufw status | grep -q mtpctl:'
chk "uninstall: копия базы в /root" x m2 'ls /root/mtpctl-uninstall-*.db'

echo "=== итог: $PASS ok, $FAIL FAIL ==="
[ "$FAIL" -eq 0 ]
