#!/bin/bash
# AntiBot — установка и удаление.
#
#   sudo ./install.sh                         поставить в режиме наблюдения
#   sudo ./install.sh --vhost ФАЙЛ            ещё и подключить страницу бана к сайту (строка include в server { };
#                                             бэкап файла рядом, nginx -t, при ошибке — откат)
#   sudo ./install.sh --agent-user ИМЯ        учётка для агента (Claude Code и др.): по sudo — только antibot
#   sudo ./install.sh --report-only           без nginx: только наблюдение и письма
#   sudo ./install.sh --remove                удалить (настройки и база остаются)
#   sudo ./install.sh --remove --purge        удалить всё
#
# Повторный запуск обновляет сторожа и правила, настройки не трогает.
set -euo pipefail

PREFIX=/opt/antibot
BIN=/usr/local/sbin/antibot
ETC=/etc/antibot
STATE=/var/lib/antibot
CRON=/etc/cron.d/antibot
LOGROTATE=/etc/logrotate.d/antibot
SUDOERS=/etc/sudoers.d/antibot-agent
SRC=$(cd "$(dirname "$0")" && pwd)

VHOST="" AGENT="" REPORT_ONLY=0 REMOVE=0 PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --vhost) VHOST="$2"; shift 2 ;;
        --agent-user) AGENT="$2"; shift 2 ;;
        --report-only) REPORT_ONLY=1; shift ;;
        --remove) REMOVE=1; shift ;;
        --purge) PURGE=1; shift ;;
        *) echo "непонятный параметр: $1"; exit 2 ;;
    esac
done

say() { echo "== $*"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "нужен root (sudo ./install.sh)"
STAMP=$(date +%Y%m%d-%H%M%S)

nginx_ok() { command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; }
nginx_reload() { nginx -s reload 2>/dev/null || systemctl reload nginx; }

# ---------------------------------------------------------------- удаление
if [ "$REMOVE" = 1 ]; then
    rm -f "$CRON" "$LOGROTATE" "$SUDOERS" "$BIN"
    say "cron, logrotate и команда antibot убраны"
    if command -v nginx >/dev/null 2>&1; then
        FILES=$(grep -rl 'antibot-site.conf' /etc/nginx 2>/dev/null | grep -v '/snippets/antibot-site.conf$' || true)
        for f in $FILES; do
            cp -p "$f" "$f.antibot-bak-$STAMP"
            sed -i '/include .*antibot-site\.conf;/d' "$f"
            say "убрана строка include из $f (бэкап $f.antibot-bak-$STAMP)"
        done
        rm -f /etc/nginx/conf.d/antibot.conf /etc/nginx/snippets/antibot-site.conf
        if nginx_ok; then
            nginx_reload
            say "nginx перечитан — баны сняты"
        else
            for f in $FILES; do cp -p "$f.antibot-bak-$STAMP" "$f"; done
            die "nginx -t не прошёл после удаления — файлы сайта возвращены; посмотрите nginx -t"
        fi
    fi
    rm -rf "$PREFIX"
    if [ "$PURGE" = 1 ]; then
        rm -rf "$ETC" "$STATE" /etc/nginx/antibot /var/log/antibot.log*
        say "настройки, база и списки удалены"
    else
        say "настройки ($ETC) и база ($STATE) оставлены; удалить всё — --remove --purge"
    fi
    exit 0
fi

# ---------------------------------------------------------------- установка
command -v python3 >/dev/null 2>&1 || die "нет python3"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 6))' || die "нужен Python 3.6 или новее: $(python3 -V 2>&1)"
[ -f "$SRC/antibot.py" ] && [ -f "$SRC/rules.txt" ] || die "запускайте из папки AntiBot"

install -d -m 755 "$PREFIX" "$ETC"
install -d -m 750 "$STATE"
install -m 755 "$SRC/antibot.py" "$PREFIX/antibot.py"
install -m 644 "$SRC/rules.txt" "$PREFIX/rules.txt"
install -m 644 "$SRC/antibot.example.ini" "$PREFIX/antibot.example.ini"
if [ -d "$SRC/workspace" ]; then
    rm -rf "$PREFIX/workspace"
    cp -r "$SRC/workspace" "$PREFIX/workspace"
fi
ln -sf "$PREFIX/antibot.py" "$BIN"
say "сторож — $PREFIX, команда — $BIN ($(python3 -V 2>&1))"

if [ ! -f "$ETC/antibot.ini" ]; then
    install -m 600 "$SRC/antibot.example.ini" "$ETC/antibot.ini"
    IPS=$(hostname -I 2>/dev/null | xargs || true)
    [ -n "$IPS" ] && sed -i "s|^server_ips =.*|server_ips = $IPS|" "$ETC/antibot.ini"
    for L in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
        if [ -f "$L" ]; then
            sed -i "s|^log = .*|log = $L|; s|^log_archives = .*|log_archives = $L.*|" "$ETC/antibot.ini"
            break
        fi
    done
    [ "$REPORT_ONLY" = 1 ] && sed -i 's|^mode = .*|mode = report|' "$ETC/antibot.ini"
    say "настройки — $ETC/antibot.ini: впишите домен, почту и контакт (адреса сервера и журнал подставлены)"
else
    say "настройки $ETC/antibot.ini уже есть — не трогаю"
fi

cat > "$CRON" <<EOF
# AntiBot: проход раз в минуту, сводка за неделю — по воскресеньям в 20:00. Убрать — sudo ./install.sh --remove
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root $BIN --tick >>/var/log/antibot.log 2>&1
0 20 * * 0 root $BIN --weekly >>/var/log/antibot.log 2>&1
EOF
chmod 644 "$CRON"
cat > "$LOGROTATE" <<EOF
/var/log/antibot.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
EOF
say "cron и logrotate поставлены"

if [ "$REPORT_ONLY" = 0 ] && command -v nginx >/dev/null 2>&1; then
    "$BIN" --nginx-files || die "файлы nginx не записаны (см. выше); сторож работает без банов"
    if [ -n "$VHOST" ]; then
        [ -f "$VHOST" ] || die "нет файла сайта: $VHOST"
        if grep -q 'antibot-site.conf' "$VHOST"; then
            say "в $VHOST строка include уже есть"
        else
            cp -p "$VHOST" "$VHOST.antibot-bak-$STAMP"
            # после каждой строки server_name — внутри каждого server { } сайта
            sed -i '/^[[:space:]]*server_name[[:space:]]/a\    include /etc/nginx/snippets/antibot-site.conf;' "$VHOST"
            if nginx_ok; then
                nginx_reload
                say "страница бана подключена к $VHOST (бэкап $VHOST.antibot-bak-$STAMP)"
            else
                cp -p "$VHOST.antibot-bak-$STAMP" "$VHOST"
                nginx -t || true
                die "nginx -t не прошёл — $VHOST возвращён как был"
            fi
        fi
    else
        say "чтобы баны работали, впишите в server { } сайта: include /etc/nginx/snippets/antibot-site.conf;"
        say "  (или запустите ещё раз с --vhost ФАЙЛ_САЙТА). Если сайт создан в панели — в её место для своих настроек."
    fi
elif [ "$REPORT_ONLY" = 0 ]; then
    say "nginx не найден — сторож будет только наблюдать и писать (режим report)"
    sed -i 's|^mode = .*|mode = report|' "$ETC/antibot.ini"
fi

if [ -n "$AGENT" ]; then
    id "$AGENT" >/dev/null 2>&1 || useradd -m -s /bin/bash "$AGENT"
    echo "$AGENT ALL=(root) NOPASSWD: $BIN" > "$SUDOERS.tmp"
    chmod 440 "$SUDOERS.tmp"
    if visudo -cf "$SUDOERS.tmp" >/dev/null; then
        mv "$SUDOERS.tmp" "$SUDOERS"
        say "учётка $AGENT: по sudo может только $BIN; ключ SSH положите в ~$AGENT/.ssh/authorized_keys"
    else
        rm -f "$SUDOERS.tmp"
        die "строка sudoers не прошла проверку visudo"
    fi
fi

say "проверка настроек:"
"$BIN" --check-config || true
cat <<EOF

Дальше:
  1. Отредактируйте $ETC/antibot.ini (домен, почта, контакт) и проверьте: sudo antibot --check-config
  2. Пробное письмо: sudo antibot --test-mail
  3. Первая неделя — наблюдение: сканеров сторож закрывает сам, остальных записывает. Сводка: sudo antibot --daily
  4. Ежедневный разбор с агентом — папка $PREFIX/workspace (скопируйте к себе на компьютер).
EOF
