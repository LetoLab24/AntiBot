#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AntiBot — сторож от вредных ботов для сайта за nginx.

Раз в минуту читает журнал запросов сайта и раскладывает посетителей по поведению. Сканеров уязвимостей
закрывает сразу. Остальных вредных (парсеры каталога, слишком частые, поддельные поисковики) по умолчанию
только записывает — «закрыл бы»: решение за человеком (сводка --daily, разбор адреса --who, бан --ban).
Поисковики проверяются по DNS и не закрываются. Закрывает nginx: адрес получает страницу с объяснением.

  antibot --tick                          раз в минуту из cron
  antibot --daily [ЧАСОВ]                 сводка: что сделал сторож и кого стоит закрыть (по умолчанию 24 ч)
  antibot --who АДРЕС [ЧАСОВ]             что делал адрес
  antibot --ban АДРЕС ЧАСОВ [причина]     закрыть адрес (вручную)
  antibot --unban АДРЕС                   снять бан
  antibot --allow АДРЕС [кто это]         снять бан и внести в белый список
  antibot --block-ua "ИМЯ" [--force]      закрыть точное имя браузера (User-Agent) в nginx
  antibot --unblock-ua "ИМЯ"
  antibot --mode observe|enforce|report   сменить режим
  antibot --report                        состояние сейчас
  antibot --weekly                        сводка за неделю письмом (cron, воскресенье)
  antibot --replay ФАЙЛ... --state ПАПКА  прогнать старые журналы в отдельную базу (проверка правил)
  antibot --check-config                  проверить настройки и разбор журнала
  antibot --nginx-files                   записать файлы nginx (уровень http и страница бана)
  antibot --test-mail | --version

Настройки — /etc/antibot/antibot.ini (или --config ФАЙЛ). Правила — rules.txt рядом со скриптом.
Режимы: observe — «закрыл бы» в базу, по-настоящему закрывает только правила из enforce_always (сканеры);
enforce — закрывает всех; report — никого не закрывает и nginx не трогает. MAIL_DRY=1 — письма в консоль.
"""
VERSION = '0.1.1'

import calendar, collections, configparser, glob, gzip, html, ipaddress, json, os, pickle, re
import shlex, smtplib, socket, sqlite3, subprocess, sys, threading, time, traceback, urllib.parse, urllib.request
from email.message import EmailMessage
from email.utils import formatdate

try:
    import fcntl
except ImportError:                      # не Linux — только для тестов
    fcntl = None

HERE = os.path.dirname(os.path.realpath(__file__))
DEFAULT_CONFIG = os.environ.get('ANTIBOT_CONFIG', '/etc/antibot/antibot.ini')
DRY_MAIL = bool(os.environ.get('MAIL_DRY'))
PIPE = subprocess.PIPE
MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}
COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"')
# готовые форматы журнала (log_format в настройках). BitrixVM: код ответа до запроса, в скобках с датой — время ответа
LOG_FORMATS = {
    'bitrixvm': r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})[^\]]*\] (?P<status>\d{3}) '
                r'"(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" (?P<size>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?',
}
MAX_READ = 64 << 20                      # за один проход — не больше 64 МБ журнала
PROBE_KEY = '_probe'                     # в review.uas: имена браузеров, под которыми адрес делал пробы
PLAIN_PAGE = re.compile(r'^/(?:[^.?]*|[^?]*\.html?)$', re.I)
BASE_ALLOW = ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7', 'fe80::/10']

# поля минутной корзины адреса
REQ, ST, D, P, JS, TY, PR, CT, SR, DP, HD, LG, SC, RF, BAN = range(15)
NF = 15

RULE_NAMES = {'scan': 'сканер уязвимостей', 'rate': 'слишком часто', 'refusals': 'долбит отказы (403/429)',
              'parser': 'парсер каталога', 'headless': 'безголовый браузер', 'pagination': 'глубокая пагинация',
              'head': 'HEAD по страницам', 'login': 'подбор пароля', 'fake_se': 'поддельный поисковик',
              'fake_ai': 'поддельный ИИ-бот', 'manual': 'вручную'}
SOFT = {'parser', 'headless', 'pagination', 'head', 'refusals'}
RV_NAMES = {'good-bot': 'хороший бот', 'human': 'похоже, человек', 'shared': 'общий адрес: и бот, и люди',
            'bot': 'бот — подтвердилось', 'quiet': 'ушёл после бана', 'manual': 'снят вручную',
            'typing': 'похоже, человек: страница работала как в браузере'}
PROPOSAL = {
    'good-bot': 'адрес уже в белом списке. Стоит поправить правило: поисковик не узнан по имени.',
    'human': 'снять бан (сторож снимает сам один раз в неделю на адрес; если уже снят — ничего не делать).',
    'shared': 'за адресом и бот, и люди (офис, NAT, мобильный оператор). Варианты: 1) снять бан и внести в белый '
              'список с пометкой; 2) оставить бан — люди увидят страницу с контактом и напишут.',
    'typing': 'после бана адрес сам набирал текст или страница выполняла свои скрипты и грузила картинки — так '
              'ходит человек в браузере (или люди за общим адресом). Снять бан; если это скрипт в браузере — оставить.',
}
HOSTING_RDNS = re.compile(r'(?:^|[.-])(?:vps|vds|server|srv|hosting|cloud|dedic|colo|compute|amazonaws|'
                          r'googleusercontent|digitalocean|linode|vultr|hetzner|contabo|ovh|scaleway|leaseweb|choopa|'
                          r'm247|datacamp|aeza|selectel|timeweb|beget|firstvds|ruvds|aruba|azure|oraclecloud)(?:[.-]|\d|$)', re.I)
HOME_RDNS = re.compile(r'(?:^|[.-])(?:mobile|mob|gprs|lte|ppp|pppoe|dyn|dynamic|dynamicip|dsl|adsl|broadband|cable|'
                       r'pool|dhcp|client|home|user|subs|abo|cust)(?:[.-]|\d|$)', re.I)


# ---------------------------------------------------------------- мелочи
def log(*a):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), *a, flush=True)


def fmt(n):
    return '{:,}'.format(int(n)).replace(',', ' ')


class Clock:
    """Часы сторожа: настоящие, а при --replay — время журнала."""
    fixed = None

    def now(self):
        return self.fixed if self.fixed is not None else time.time()


CLOCK = Clock()


def now():
    return int(CLOCK.now())


def day_key(ts=None):
    return time.strftime('%Y-%m-%d', time.localtime(now() if ts is None else ts))


def hm(ts):
    return time.strftime('%d.%m %H:%M', time.localtime(ts))


def run(cmd, data=None, timeout=60):
    """Команда из настроек (строка) -> (код, вывод). Пустая строка — не запускать."""
    if not cmd:
        return 0, ''
    try:
        r = subprocess.run(shlex.split(cmd), input=data, stdout=PIPE, stderr=PIPE, timeout=timeout)
    except Exception as e:
        return 127, str(e)
    out = (r.stdout or b'') + (r.stderr or b'')
    return r.returncode, out.decode('utf-8', 'replace')


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class NetSet:
    def __init__(self, nets=()):
        self.nets = []
        self.cache = {}
        for n in nets:
            self.add(n)

    def add(self, n):
        try:
            self.nets.append(ipaddress.ip_network(n.strip(), strict=False))
            self.cache = {}
            return True
        except ValueError:
            return False

    def __contains__(self, ip):
        v = self.cache.get(ip)
        if v is None:
            try:
                a = ipaddress.ip_address(ip)
                v = any(a.version == n.version and a in n for n in self.nets)
            except ValueError:
                v = False
            if len(self.cache) > 100000:
                self.cache = {}
            self.cache[ip] = v
        return v


# ---------------------------------------------------------------- настройки и правила
def _ini(path, required=False):
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    if path and os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            cp.read_file(f)
    elif required:
        raise SystemExit('нет файла: %s' % path)
    return cp


def _lines(text):
    return [l.strip() for l in (text or '').splitlines() if l.strip() and not l.strip().startswith('#')]


class Settings:
    def __init__(self, path, state_override=None):
        self.path = path
        self.site = _ini(path)
        g = self.get
        self.rules_path = g('paths', 'rules') or os.path.join(HERE, 'rules.txt')
        self.rules = _ini(self.rules_path, required=True)
        self.domain = g('site', 'domain', 'localhost')
        self.log = g('site', 'log', '/var/log/nginx/access.log')
        self.log_archives = g('site', 'log_archives', self.log + '[.-]*')
        if self.log_archives == self.log + '.*':
            self.log_archives = self.log + '[.-]*'      # прежнее значение по умолчанию не видит архивы с датой
        self.log_format = g('site', 'log_format', 'combined')
        self.log_regex = g('site', 'log_regex')
        self.time_format = g('site', 'time_format', 'clf')
        self.engine = g('site', 'engine', 'custom')
        self.contact = g('site', 'contact')
        self.server_ips = g('site', 'server_ips').split()
        self.replay = bool(state_override)
        cfg_dir = os.path.dirname(os.path.abspath(path)) if path else '/etc/antibot'
        self.state_dir = state_override or g('paths', 'state_dir', '/var/lib/antibot')
        self.etc_dir = state_override or g('paths', 'etc_dir', cfg_dir)
        self.nginx_dir = '' if state_override else g('paths', 'nginx_dir', '/etc/nginx/antibot')
        self.nginx_http_conf = g('paths', 'nginx_http_conf', '/etc/nginx/conf.d/antibot.conf')
        self.nginx_site_conf = g('paths', 'nginx_site_conf', '/etc/nginx/snippets/antibot-site.conf')
        # команды nginx: пустое значение в настройках — не запускать
        self.nginx_test = self.raw('paths', 'nginx_test', 'nginx -t')
        self.nginx_reload = self.raw('paths', 'nginx_reload', 'nginx -s reload')
        self.nginx_dump = self.raw('paths', 'nginx_dump', 'nginx -T')
        self.mail = {k: g('mail', k) for k in ('to', 'copy_to', 'from', 'method', 'smtp_host', 'smtp_port',
                                               'smtp_security', 'smtp_login', 'smtp_password', 'sendmail')}
        self.ai_lists = self.flag('features', 'ai_lists', True) and not state_override
        self.auto_unban = self.flag('features', 'auto_unban_humans', True)
        self.never_ban_cdn = self.flag('features', 'never_ban_cdn', True)

    def get(self, sec, key, default=''):
        v = self.site.get(sec, key, fallback=None)
        return default if v is None or not v.strip() else v.strip()

    def raw(self, sec, key, default=''):
        v = self.site.get(sec, key, fallback=None)
        return default if v is None else v.strip()

    def flag(self, sec, key, default):
        v = self.get(sec, key, '').lower()
        return default if not v else v in ('1', 'yes', 'on', 'true', 'да')

    def th(self, name):
        v = self.get('thresholds', name) or self.rules.get('thresholds', name, fallback='0')
        return float(v) if '.' in v else int(v)

    def ban_hours(self, rule):
        v = self.get('ban_hours', rule) or self.rules.get('ban_hours', rule, fallback='24')
        return [float(x) for x in v.split()]

    def policy(self, key):
        v = self.site.get('site', key, fallback=None)
        if v is None:
            v = self.rules.get('policy', key, fallback='')
        return set(v.replace(',', ' ').split())

    def pattern(self, name):
        """Шаблон движка: из [patterns] настроек (перекрывает), иначе из [engine:…] правил; плюс name_extra."""
        if self.site.has_option('patterns', name):
            text = self.site.get('patterns', name)
        else:
            text = self.rules.get('engine:' + self.engine, name, fallback='')
            if not text and not self.rules.has_section('engine:' + self.engine):
                text = self.rules.get('engine:custom', name, fallback='')
        extra = self.site.get('patterns', name + '_extra', fallback='')
        return '\n'.join(_lines(text) + _lines(extra))

    def mode(self):
        try:
            with open(os.path.join(self.etc_dir, 'mode'), encoding='utf-8') as f:
                m = f.read().strip()
        except OSError:
            m = ''
        m = m or self.get('site', 'mode', 'observe')
        return m if m in ('observe', 'enforce', 'report') else 'observe'


def _rx(lines, flags=re.I):
    lines = [l for l in lines if l]
    if not lines:
        return None
    return re.compile('|'.join('(?:%s)' % l for l in lines), flags)


class Rules:
    """Скомпилированные правила: rules.txt + переопределения из настроек."""

    def __init__(self, s):
        R = s.rules
        stem = re.escape(s.domain.split('.')[0]) if s.domain and s.domain != 'localhost' else 'site'

        def lines(sec, key):
            return [l.replace('{stem}', stem) for l in _lines(R.get(sec, key, fallback=''))]

        # probe_extra в настройках — свои пробы, которые у этого сайта не бывают у людей (например, \.php$ на сайте без PHP)
        self.probe = _rx(lines('probe', 'paths') + _lines(s.get('patterns', 'probe_extra')))
        self.probe_cms = _rx(lines('probe', 'cms'))
        self.probe_q = _rx(lines('probe', 'query'))
        self.traversal = _rx(lines('probe', 'traversal'))
        self.sqli = _rx(lines('probe', 'sqli'))
        self.leak = _rx(lines('probe', 'leak'))
        self.leak_exclude = _rx(_lines(s.get('patterns', 'leak_exclude')))
        self.static = _rx(lines('static', 'ext') + _lines(s.pattern('static')))
        self.own = _rx(_lines(s.pattern('own')))
        self.product = _rx(_lines(s.pattern('product')))
        self.catalog = _rx(_lines(s.pattern('catalog')))
        self.search = _rx(_lines(s.pattern('search')))
        self.page_no = _rx(_lines(s.pattern('page')))
        self.js = _rx(_lines(s.pattern('js')))
        self.typing = _rx(_lines(s.pattern('typing')))
        self.login = _rx(_lines(s.pattern('login')))
        pages = _lines(s.pattern('pages')) or lines('pages', 'generic')
        self.pages = _rx(pages)
        self.bot_ua = _rx(lines('ua', 'bot'))
        self.browser_ua = _rx(lines('ua', 'browser'), 0)
        self.se_ref = _rx(lines('referer', 'search'))
        self.se_ua = [(re.compile(v, re.I), fam) for fam, v in R.items('search_engines')
                      if fam not in R.defaults()]
        self.se_domains = {fam: tuple(v.split()) for fam, v in R.items('se_domains') if fam not in R.defaults()}
        # сети поисковиков, чьи роботы ходят без имени в DNS: адрес из сети — настоящий робот
        self.se_nets = {fam: NetSet(v.split()) for fam, v in R.items('se_nets')
                        if fam not in R.defaults()} if R.has_section('se_nets') else {}
        self.ai_ua = [tuple(l.split()[:2]) for l in lines('ai_bots', 'list') if len(l.split()) >= 2]
        self.ai_rdns = {fam: tuple(v.split()) for fam, v in R.items('ai_rdns')} if R.has_section('ai_rdns') else {}
        self.ai_lists = {fam: v.split() for fam, v in R.items('ai_lists')} if R.has_section('ai_lists') else {}
        self.shared = NetSet(lines('nets', 'shared'))
        self.cdn = NetSet(lines('nets', 'cdn'))
        self.version = R.get('meta', 'version', fallback='?')
        self._ua = {}

    def is_static(self, path):
        return bool(self.static and self.static.search(path))

    def is_sqli(self, url):
        q = url.partition('?')[2]
        if len(q) < 8 or not self.sqli:
            return False
        try:
            q = urllib.parse.unquote_plus(q)
        except Exception:
            pass
        return bool(self.sqli.search(q))

    def probe_hit(self, path, url):
        """Проба по шаблонам (без SQL-инъекций и кода 444). Пробы чужих движков на своих путях не считаются."""
        if (self.probe and self.probe.search(path)) or (self.traversal and self.traversal.search(url)):
            return True
        if self.own and self.own.search(url):
            return False
        return bool((self.probe_cms and self.probe_cms.search(path)) or (self.probe_q and self.probe_q.search(url)))

    def is_product(self, path, url):
        """Карточка товара; если шаблона нет — любая обычная страница (не статика, не служебный путь)."""
        if self.product:
            return bool(self.product.search(url))
        return bool(PLAIN_PAGE.match(path)) and not (self.own and self.own.search(path))

    def is_page(self, path, url, is_static):
        if is_static:
            return True
        for rx in (self.pages, self.product, self.catalog, self.search):
            if rx and rx.search(path if rx is self.pages else url):
                return True
        return False

    def page_number(self, url):
        if not self.page_no:
            return 0
        m = self.page_no.search(url)
        if not m:
            return 0
        for g in m.groups():
            if g and g.isdigit():
                return int(g)
        return 0

    def ua_class(self, ua):
        """-> (класс, семья): se — поисковик, ai — ИИ-бот, bot — программа, empty — без имени, br — браузер."""
        v = self._ua.get(ua)
        if v:
            return v
        if not ua or ua == '-':
            v = ('empty', '')
        else:
            v = None
            for rx, fam in self.se_ua:
                if rx.search(ua):
                    v = ('se', fam)
                    break
            if v is None:
                low = ua.lower()
                for sub, fam in self.ai_ua:
                    if sub in low:
                        v = ('ai', fam)
                        break
            if v is None:
                # программа — по слову в имени или если в имени нет ни одного признака браузера
                prog = (self.bot_ua and self.bot_ua.search(ua)) or (self.browser_ua and not self.browser_ua.search(ua))
                v = ('bot', '') if prog else ('br', '')
        if len(self._ua) > 50000:
            self._ua = {}
        self._ua[ua] = v
        return v


# ---------------------------------------------------------------- журнал
class LogParser:
    def __init__(self, s):
        self.custom = None
        self.ip_first = s.log_format in ('combined', 'bitrixvm')   # строка начинается с адреса
        self.tf = s.time_format
        if s.log_format in LOG_FORMATS:
            self.custom = re.compile(LOG_FORMATS[s.log_format])
            self.tf = 'clf'
        elif s.log_format == 'custom':
            if not s.log_regex:
                raise SystemExit('log_format = custom, но log_regex не задан')
            self.custom = re.compile(s.log_regex)
        self._t = {}

    def minute(self, ts):
        """Время запроса -> минута от эпохи (UTC)."""
        if self.tf == 'epoch':
            return int(float(ts)) // 60
        k = ts[:17] if self.tf == 'clf' else ts[:16] + ts[19:]
        v = self._t.get(k)
        if v is None:
            if self.tf == 'clf':                       # 10/Oct/2026:14:39:01 +0300
                d, mon, rest = ts[:2], ts[3:6], ts[7:]
                y, hh, mm = int(rest[:4]), int(rest[5:7]), int(rest[8:10])
                y, mo, d = y, MONTHS[mon], int(d)
                off = ts[-5:]
            else:                                      # 2026-10-10T14:39:01+03:00
                y, mo, d, hh, mm = int(ts[:4]), int(ts[5:7]), int(ts[8:10]), int(ts[11:13]), int(ts[14:16])
                off = ts[19:].lstrip('.0123456789') or 'Z'
                off = '+0000' if off in ('Z', 'z') else off.replace(':', '')
            sign = -1 if off[0] == '-' else 1
            off_s = sign * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)
            v = (calendar.timegm((y, mo, d, hh, mm, 0)) - off_s) // 60
            if len(self._t) > 5000:
                self._t = {}
            self._t[k] = v
        return v

    def parse(self, line):
        """-> (адрес, минута, метод, адрес запроса, код, размер, Referer, UA) или None."""
        if self.custom:
            m = self.custom.match(line)
            if not m:
                return None
            g = m.groupdict()
            try:
                return (g['ip'], self.minute(g['time']), g.get('method') or 'GET', g.get('url') or '/',
                        int(g.get('status') or 0), g.get('size') or '-', g.get('referer') or '-', g.get('ua') or '-')
            except (KeyError, ValueError, IndexError):
                return None
        m = COMBINED.match(line)
        if not m:
            return None
        ip, ts, meth, url, status, size, ref, ua = m.groups()
        try:
            return ip, self.minute(ts), meth, url, int(status), size, ref, ua
        except (KeyError, ValueError, IndexError):
            return None


def open_log(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, encoding='utf-8', errors='replace')


def log_files(s, since_ts):
    """Журнал и архивы, в которые писали после since_ts."""
    seen, out = set(), []
    for f in [s.log] + sorted(glob.glob(s.log_archives)):
        try:
            rp = os.path.realpath(f)
            if rp in seen or os.path.getmtime(f) < since_ts:
                continue
        except OSError:
            continue
        seen.add(rp)
        out.append(f)
    return out


def scan_logs(s, parser, since_ts, ip=None):
    """Разобранные строки журналов за период (порядок — по файлам)."""
    since_min = since_ts // 60
    prefix = ip + ' ' if ip and parser.ip_first else None
    for f in log_files(s, since_ts):
        try:
            with open_log(f) as fh:
                for line in fh:
                    if prefix and not line.startswith(prefix):
                        continue
                    p = parser.parse(line)
                    if p and p[1] >= since_min and (ip is None or p[0] == ip):
                        yield p
        except (OSError, EOFError) as e:
            log('журнал не прочитан:', f, e)


# ---------------------------------------------------------------- база
class Store:
    SCHEMA = '''
    CREATE TABLE IF NOT EXISTS bans(ip TEXT PRIMARY KEY, rule TEXT, kind INT, since INT, until INT, hits INT DEFAULT 0, note TEXT);
    CREATE TABLE IF NOT EXISTS ban_log(id INTEGER PRIMARY KEY, ip TEXT, rule TEXT, ts INT, until INT, enforced INT, detail TEXT, hits INT DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ban_log_ts ON ban_log(ts);
    CREATE INDEX IF NOT EXISTS ban_log_ip ON ban_log(ip);
    CREATE TABLE IF NOT EXISTS dns(ip TEXT PRIMARY KEY, fam TEXT, ok INT, host TEXT, checked INT);
    CREATE TABLE IF NOT EXISTS daily(day TEXT, key TEXT, val INT, PRIMARY KEY(day, key));
    CREATE TABLE IF NOT EXISTS traffic(t5 INT PRIMARY KEY, req INT, dyn INT);
    CREATE TABLE IF NOT EXISTS ticks(h INT PRIMARY KEY, n INT);
    CREATE TABLE IF NOT EXISTS alerts(key TEXT PRIMARY KEY, last INT);
    CREATE TABLE IF NOT EXISTS alert_log(id INTEGER PRIMARY KEY, ts INT, subject TEXT, sent INT);
    CREATE TABLE IF NOT EXISTS mail_queue(id INTEGER PRIMARY KEY, ts INT, subject TEXT, body TEXT, rcpt TEXT, last_try INT);
    CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, val TEXT);
    CREATE TABLE IF NOT EXISTS review(ip TEXT PRIMARY KEY, rule TEXT, since INT, hits INT DEFAULT 0, pages INT DEFAULT 0,
        uas TEXT DEFAULT '{}', bot_ua TEXT, se_ref INT DEFAULT 0, favicon INT DEFAULT 0, st INT DEFAULT 0, sg INT DEFAULT 0,
        post INT DEFAULT 0, js INT DEFAULT 0, human_before INT DEFAULT 0, rdns TEXT, rdns_ok INT, verdict TEXT);
    CREATE TABLE IF NOT EXISTS review_log(id INTEGER PRIMARY KEY, ts INT, ip TEXT, rule TEXT, verdict TEXT, action TEXT, evidence TEXT);
    CREATE TABLE IF NOT EXISTS ua_bans(ua TEXT PRIMARY KEY, ts INT, note TEXT);
    CREATE TABLE IF NOT EXISTS ua_seen(ua TEXT PRIMARY KEY, first_day TEXT, last_day TEXT);
    '''

    def __init__(self, state_dir):
        os.makedirs(state_dir, exist_ok=True)
        self.db = sqlite3.connect(os.path.join(state_dir, 'antibot.sqlite3'), timeout=30)
        self.db.executescript(self.SCHEMA)

    def q(self, sql, args=()):
        return self.db.execute(sql, args)

    def meta(self, key, default=None):
        r = self.q('SELECT val FROM meta WHERE key=?', (key,)).fetchone()
        return r[0] if r else default

    def set_meta(self, key, val):
        self.q('INSERT OR REPLACE INTO meta VALUES(?,?)', (key, str(val)))

    def _add(self, table, keys, vals):
        """Прибавить к счётчикам строки (без UPSERT: старый SQLite его не знает)."""
        where = ' AND '.join('%s=?' % k for k in keys)
        sets = ', '.join('%s=%s+?' % (c, c) for c in vals)
        args = list(vals.values()) + [keys[k] for k in keys]
        if self.q('UPDATE %s SET %s WHERE %s' % (table, sets, where), args).rowcount == 0:
            cols = list(keys) + list(vals)
            self.q('INSERT INTO %s(%s) VALUES(%s)' % (table, ','.join(cols), ','.join('?' * len(cols))),
                   list(keys.values()) + list(vals.values()))

    def add_daily(self, day, key, val):
        if val:
            self._add('daily', {'day': day, 'key': key}, {'val': int(val)})

    def commit(self):
        self.db.commit()


# ---------------------------------------------------------------- белый список
def load_allow(s):
    nets = NetSet(BASE_ALLOW + s.server_ips)
    for line in _lines(s.get('allow', 'addresses')):
        nets.add(line.split('#', 1)[0])
    try:
        with open(os.path.join(s.etc_dir, 'allow.txt'), encoding='utf-8') as f:
            for line in f:
                part = line.split('#', 1)[0].strip()
                if part:
                    nets.add(part)
    except OSError:
        pass
    return nets


def allow_add(s, ip, note):
    os.makedirs(s.etc_dir, exist_ok=True)
    with open(os.path.join(s.etc_dir, 'allow.txt'), 'a', encoding='utf-8') as f:
        f.write('%s  # %s\n' % (ip, note))


# ---------------------------------------------------------------- проверка поисковиков и ИИ-ботов
def _rdns_check(ip, suffixes, out):
    # Подделка — только по точному ответу DNS. Сбой DNS (SERVFAIL, таймаут) — «не проверен», повтор позже:
    # иначе настоящий поисковик в минуту сбоя попадёт в подделки на неделю.
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
    except socket.herror as e:
        if e.args and e.args[0] == 1:                   # у адреса нет имени
            out[ip] = (0, '')
        return
    except Exception:
        return
    if not suffixes or not host.endswith(suffixes):
        out[ip] = (0, host)
        return
    try:
        ok = ip in socket.gethostbyname_ex(host)[2]
    except socket.gaierror as e:
        if not e.args or e.args[0] not in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', -5)):
            return
        ok = False
    except Exception:
        return
    out[ip] = (1 if ok else 0, host)


def rdns_many(ips, wait=4.0):
    """{адрес: имя по DNS} — для писем и сводок."""
    out, threads = {}, []
    for ip in ips:
        t = threading.Thread(target=_rdns_check, args=(ip, (), out), daemon=True)
        t.start()
        threads.append(t)
    deadline = time.time() + wait
    for t in threads:
        t.join(max(0, deadline - time.time()))
    return {ip: v[1] for ip, v in list(out.items())}


def dns_verdict(r, fam, ok, host):
    """Нет имени в DNS у поисковика, чьи роботы так и ходят (Mail.ru), — не подделка, а «проверить нечем» (-1)."""
    if ok == 0 and not host and fam in r.se_nets:
        return -1
    return ok


class Verifier:
    """Обратный + прямой DNS для поисковиков; сети поисковиков без имени в DNS; опубликованные списки адресов
    для OpenAI и Perplexity."""

    def __init__(self, s, r, store):
        self.s, self.r, self.st = s, r, store
        self.cache = {row[0]: (row[1], dns_verdict(r, row[1], row[2], row[3]))
                      for row in store.q('SELECT ip, fam, ok, host FROM dns WHERE checked > ?', (now() - 7 * 86400,))}
        self.lists = self._load_lists()

    def _load_lists(self):
        path = os.path.join(self.s.state_dir, 'ai-lists.json')
        data = {}
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            pass
        if self.s.ai_lists and time.time() - data.get('_ts', 0) > 86400:
            fresh = {'_ts': time.time()}
            for fam, urls in self.r.ai_lists.items():
                nets = []
                for u in urls:
                    try:
                        with urllib.request.urlopen(u, timeout=10) as resp:
                            j = json.loads(resp.read().decode('utf-8'))
                        for p in j.get('prefixes', []):
                            n = p.get('ipv4Prefix') or p.get('ipv6Prefix')
                            if n:
                                nets.append(n)
                    except Exception as e:
                        log('список адресов', u, 'не скачан:', e)
                if nets:
                    fresh[fam] = nets
                elif fam in data:
                    fresh[fam] = data[fam]                 # старый список лучше, чем никакого
            data = fresh
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f)
            except OSError:
                pass
        return {fam: NetSet(nets) for fam, nets in data.items() if fam != '_ts'}

    def in_lists(self, ip, ua=''):
        """Адрес из опубликованного списка ИИ-компании или из сети поисковика, чьим именем назвался."""
        if any(ip in n for n in self.lists.values()):
            return True
        cls, fam = self.r.ua_class(ua) if ua else ('', '')
        return cls == 'se' and fam in self.r.se_nets and ip in self.r.se_nets[fam]

    def status(self, ip, cls, fam):
        """1 — подтверждён, 0 — подделка, -1 — проверить нечем (у адреса нет имени в DNS, а этот поисковик
        так и ходит, но адрес не из его сетей), None — ещё не проверен."""
        if cls == 'ai' and fam in self.lists:
            return 1 if ip in self.lists[fam] else 0
        if cls == 'se' and fam in self.r.se_nets and ip in self.r.se_nets[fam]:
            return 1
        v = self.cache.get(ip)
        if v and v[0] == fam:
            return v[1]
        return None

    def checked(self, ip, fam):
        v = self.cache.get(ip)
        return bool(v and v[0] == fam)

    def suffixes(self, fam):
        return self.r.se_domains.get(fam) or self.r.ai_rdns.get(fam)

    def check(self, items, limit=40, wait=4.0):
        """items: [(адрес, семья)] — проверка DNS в фоновых потоках, не дольше wait секунд."""
        out, threads = {}, []
        for ip, fam in items[:limit]:
            suf = self.suffixes(fam)
            if not suf:
                continue
            t = threading.Thread(target=_rdns_check, args=(ip, suf, out), daemon=True)
            t.start()
            threads.append((t, ip, fam))
        deadline = time.time() + wait
        for t, ip, fam in threads:
            t.join(max(0, deadline - time.time()))
        for t, ip, fam in threads:
            if ip in out:
                ok, host = out[ip]
                ok = dns_verdict(self.r, fam, ok, host)
                self.cache[ip] = (fam, ok)
                self.st.q('INSERT OR REPLACE INTO dns VALUES(?,?,?,?,?)', (ip, fam, ok, host, now()))


# ---------------------------------------------------------------- почта
class Mailer:
    def __init__(self, s, store):
        self.s, self.st = s, store
        self.replay_log = []

    def recipients(self, summary):
        m = self.s.mail
        out = [a.strip() for a in m['to'].replace(';', ',').split(',') if a.strip()]
        if summary:
            out += [a.strip() for a in m['copy_to'].replace(';', ',').split(',') if a.strip()]
        return out

    def send(self, subject, body, key=None, repeat_h=None, summary=False):
        """Тревога или сводка. key — повтор не чаще repeat_h часов; summary — с копией (copy_to)."""
        s, st = self.s, self.st
        t = now()
        subject = 'AntiBot: %s — %s' % (subject, s.domain)
        if key:
            r = st.q('SELECT last FROM alerts WHERE key=?', (key,)).fetchone()
            if r and t - r[0] < (repeat_h or s.th('alert_repeat_h')) * 3600:
                return False
            today = int(time.mktime(time.localtime(t)[:3] + (0, 0, 0, 0, 0, -1)))
            n = st.q('SELECT COUNT(*) FROM alert_log WHERE ts>=? AND sent=1', (today,)).fetchone()[0]
            if n >= s.th('alerts_per_day'):
                st.q('INSERT INTO alert_log(ts, subject, sent) VALUES(?,?,0)', (t, subject))
                return False
            st.q('INSERT OR REPLACE INTO alerts VALUES(?,?)', (key, t))
        rcpt = self.recipients(summary)
        if s.replay:
            self.replay_log.append((t, subject))
            ok = True
        else:
            ok = self.deliver(subject, body, rcpt)
        st.q('INSERT INTO alert_log(ts, subject, sent) VALUES(?,?,?)', (t, subject, 1 if ok else 0))
        if not ok and rcpt:                               # не потерять: повторит retry()
            st.q('INSERT INTO mail_queue(ts, subject, body, rcpt, last_try) VALUES(?,?,?,?,?)',
                 (t, subject, body, ','.join(rcpt), t))
        st.commit()
        return ok

    def deliver(self, subject, body, rcpt):
        m = self.s.mail
        if DRY_MAIL:
            print('=' * 70, '\nКому:', ', '.join(rcpt) or '—', '\nТема:', subject, '\n\n' + body, '\n' + '=' * 70)
            return True
        if not rcpt:
            log('письмо не отправлено — в настройках нет адреса [mail] to:', subject)
            return False
        msg = EmailMessage()
        msg['From'] = m['from'] or m['smtp_login'] or 'antibot@' + self.s.domain
        msg['To'] = ', '.join(rcpt)
        msg['Subject'] = subject
        msg['Date'] = formatdate(localtime=True)
        msg.set_content(body)
        try:
            method = m['method'] or ('smtp' if m['smtp_host'] else 'sendmail')
            if method == 'sendmail':
                code, out = run((m['sendmail'] or '/usr/sbin/sendmail') + ' -t -oi', msg.as_bytes())
                if code:
                    raise RuntimeError(out.strip()[:300])
                return True
            port = int(m['smtp_port'] or 465)
            sec = m['smtp_security'] or ('ssl' if port == 465 else 'starttls')
            cls = smtplib.SMTP_SSL if sec == 'ssl' else smtplib.SMTP
            with cls(m['smtp_host'], port, timeout=30) as conn:
                if sec == 'starttls':
                    conn.starttls()
                if m['smtp_login']:
                    conn.login(m['smtp_login'], m['smtp_password'])
                conn.send_message(msg)
            return True
        except Exception as e:
            log('письмо не ушло:', e)
            return False

    def retry(self):
        """Письма, которые не ушли: повтор раз в mail_retry_min минут, но не дольше mail_keep_h часов."""
        s, st = self.s, self.st
        t = now()
        rows = st.q('SELECT id, ts, subject, body, rcpt FROM mail_queue WHERE last_try < ? ORDER BY id LIMIT 10',
                    (t - s.th('mail_retry_min') * 60,)).fetchall()
        for qid, ts, subject, body, rcpt in rows:
            if t - ts > s.th('mail_keep_h') * 3600:
                st.q('DELETE FROM mail_queue WHERE id=?', (qid,))
                log('письмо не ушло за %s ч, больше не пробую:' % s.th('mail_keep_h'), subject)
                continue
            note = '\n\n(Письмо задержалось: должно было уйти %s, почтовый сервер был недоступен.)' % hm(ts)
            if not self.deliver(subject, body + note, [a for a in (rcpt or '').split(',') if a]):
                st.q('UPDATE mail_queue SET last_try=? WHERE id>=?', (t, qid))
                break                                       # почта ещё лежит — остальные не пробуем
            st.q('DELETE FROM mail_queue WHERE id=?', (qid,))
            st.q('INSERT INTO alert_log(ts, subject, sent) VALUES(?,?,1)', (t, subject))
        st.commit()


# ---------------------------------------------------------------- nginx
def nginx_quote(ua):
    """Точное имя браузера -> регулярка для map nginx (в двойных кавычках)."""
    if any(c in ua for c in '\r\n\t') or not ua.strip():
        raise ValueError('в имени браузера переводы строк или оно пустое')
    body = re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', ua)
    body = body.replace('\\', '\\\\').replace('"', '\\"')
    return '"~^%s$"' % body


def render_nginx(s, store, mailer, force=False):
    """Пишет banned.conf и ua-banned.conf и перечитывает nginx, если что-то изменилось.

    banned.conf: в режиме enforce — все баны, в observe — ручные и правила из enforce_always (сканеры).
    """
    if not s.nginx_dir or s.mode() == 'report' or not os.path.isdir(s.nginx_dir):
        return
    t = now()
    enforce = s.mode() == 'enforce'
    always = s.policy('enforce_always')
    rows = store.q('SELECT ip, kind, rule, until FROM bans WHERE until > ? ORDER BY ip', (t,)).fetchall()
    banned = ''.join('%s %d; # %s до %s\n' % (ip, kind, rule, time.strftime('%d.%m.%Y %H:%M', time.localtime(u)))
                     for ip, kind, rule, u in rows if kind and (enforce or rule == 'manual' or rule in always))
    uas = ''
    for ua, ts, note in store.q('SELECT ua, ts, note FROM ua_bans ORDER BY ts'):
        try:
            uas += '%s 1;\n' % nginx_quote(ua)
        except ValueError:
            continue
    changed = []
    for name, body in (('banned.conf', banned), ('ua-banned.conf', uas)):
        path = os.path.join(s.nginx_dir, name)
        try:
            with open(path, encoding='utf-8') as f:
                old = f.read()
        except OSError:
            old = None
        if old != body:
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(body)
            os.replace(tmp, path)
            changed.append((path, old))
    if not changed and not force:
        return
    code, out = run(s.nginx_test)
    if code != 0:
        for path, old in changed:                         # откат — nginx не должен остаться с битым списком
            if old is None:
                os.remove(path)
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(old)
        mailer.send('nginx не принял список банов',
                    'Коротко: сторож не смог обновить список закрытых адресов — проверка nginx (%s) не прошла. Сайт '
                    'работает как раньше, новые баны не применены. Нужно посмотреть, что с настройкой nginx.\n\n%s'
                    % (s.nginx_test, out[-2000:]), key='nginx-t')
        return
    run(s.nginx_reload)
    store.set_meta('reload_ts', t)
    store.commit()


NGINX_HTTP = '''# AntiBot — уровень http. Списки пишет antibot, руками не править.
# 1 — страница «доступ ограничен» с контактом, 2 — обрыв соединения.
geo $antibot_ban {
    default 0;
    include %(dir)s/banned.conf;
}
# закрытые имена браузеров (antibot --block-ua)
map $http_user_agent $antibot_ua_ban {
    default 0;
    include %(dir)s/ua-banned.conf;
}
'''

NGINX_SITE = '''# AntiBot — внутрь server { } сайта: include %(path)s;
# Отказ отдаёт nginx — до сайта и базы запрос не доходит. В журнале — код 403 (или 444).
if ($antibot_ban = 2) {
    return 444;
}
if ($antibot_ban = 1) {
    rewrite ^ /__antibot-banned last;
}
if ($antibot_ua_ban) {
    rewrite ^ /__antibot-banned last;
}
location = /__antibot-banned {
    internal;
    default_type text/html;
    add_header Cache-Control "no-store" always;
    add_header X-Robots-Tag "noindex" always;
    return 403 '%(page)s';
}
'''

BAN_PAGE = ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            'initial-scale=1"><meta name="robots" content="noindex"><title>Доступ временно ограничен — %(domain)s</title>'
            '</head><body style="margin:0;background:#f5f6f8;color:#222;font:16px/1.55 Arial,Helvetica,sans-serif">'
            '<div style="max-width:560px;margin:48px auto;padding:28px 24px;background:#fff;border-radius:10px;'
            'box-shadow:0 1px 4px rgba(0,0,0,.08)"><h1 style="margin:0 0 14px;font-size:22px">Доступ временно ограничен'
            '</h1><p>С вашего адреса <b>$remote_addr</b> на сайт приходило очень много автоматических запросов, поэтому '
            'доступ к %(domain)s с него на время закрыт.</p><p>Если вы видите эту страницу по ошибке, %(contact)s '
            'и укажите ваш адрес: <b>$remote_addr</b>.</p></div></body></html>')


def nginx_files(s, store, mailer):
    """Файлы nginx: уровень http, страница бана, пустые списки. Проверка nginx -t, при ошибке — откат."""
    if s.mode() == 'report':
        raise SystemExit('режим report: nginx не используется')
    for v in (s.contact, s.domain):
        if '$' in v or "'" in v or '\\' in v:
            raise SystemExit('в contact и domain нельзя символы $ \' \\')
    contact = html.escape(s.contact) if s.contact else ''
    if contact and ('@' in s.contact and '/' not in s.contact):
        contact = 'напишите на <a href="mailto:%s">%s</a>' % (contact, contact)
    elif contact and s.contact.startswith(('http://', 'https://')):
        contact = 'напишите нам: <a href="%s">%s</a>' % (contact, contact)
    elif contact:
        contact = 'напишите нам: ' + contact
    else:
        contact = 'напишите владельцу сайта'
    page = BAN_PAGE % {'domain': html.escape(s.domain), 'contact': contact}
    written = []
    os.makedirs(s.nginx_dir, exist_ok=True)
    for name in ('banned.conf', 'ua-banned.conf'):
        p = os.path.join(s.nginx_dir, name)
        if not os.path.exists(p):
            open(p, 'w', encoding='utf-8').close()
            written.append((p, None))
    for path, body in ((s.nginx_http_conf, NGINX_HTTP % {'dir': s.nginx_dir}),
                       (s.nginx_site_conf, NGINX_SITE % {'path': s.nginx_site_conf, 'page': page})):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, encoding='utf-8') as f:
                old = f.read()
        except OSError:
            old = None
        with open(path, 'w', encoding='utf-8') as f:
            f.write(body)
        written.append((path, old))
    code, out = run(s.nginx_test)
    if code != 0:
        for path, old in written:
            if old is None:
                os.remove(path)
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(old)
        raise SystemExit('nginx -t не прошёл, файлы возвращены как были:\n' + out[-1500:])
    run(s.nginx_reload)
    print('записано: %s, %s; списки — %s' % (s.nginx_http_conf, s.nginx_site_conf, s.nginx_dir))
    print('Дальше: строка «include %s;» внутрь server { } сайта, затем nginx -t и reload.' % s.nginx_site_conf)


# ---------------------------------------------------------------- окна и правила
def load_windows(s):
    try:
        with open(os.path.join(s.state_dir, 'windows.pkl'), 'rb') as f:
            st = pickle.load(f)
        if st.get('v') == 1:
            return st
    except Exception:
        pass
    return {'v': 1, 'W': {}, 'UA': {}, 'HD': {}, 'PU': {}, 'UAS': {}, 'G': [collections.OrderedDict(), [0]],
            'sweep': 0}


def save_windows(s, state):
    tmp = os.path.join(s.state_dir, 'windows.pkl.tmp')
    with open(tmp, 'wb') as f:
        pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, os.path.join(s.state_dir, 'windows.pkl'))


class Guard:
    """Окна по минутам на адрес, правила, баны, тревоги, работа над ошибками."""

    def __init__(self, s, r, store, mailer):
        self.s, self.r, self.st, self.mail = s, r, store, mailer
        self.state = load_windows(s)
        self.allow = load_allow(s)
        self.win = s.th('window_min')
        self.ver = None
        self.reset_tick()

    def reset_tick(self):
        self.active = collections.Counter()
        self.rv = {}
        self.dly = collections.Counter()
        self.t5 = collections.defaultdict(lambda: [0, 0])
        self.ban_hits = collections.Counter()
        self.leaks = []
        self.max_min = None
        self.enforced_mode = self.s.mode() == 'enforce'
        self.banned_now = {r[0]: r[1] for r in self.st.q('SELECT ip, kind FROM bans WHERE until > ?', (now(),))}

    # --- окна
    def _bucket(self, ip, minute):
        e = self.state['W'].get(ip)
        if e is None:
            e = self.state['W'][ip] = [collections.OrderedDict(), [0] * NF]
        bk = e[0]
        if bk:
            last = next(reversed(bk))
            if minute < last:
                minute = last                                 # строка из прошлого — в последнюю минуту
        b = bk.get(minute)
        if b is None:
            b = bk[minute] = [0] * NF
        return b, e[1]

    def _expire(self, ip, now_min):
        e = self.state['W'].get(ip)
        if not e:
            return
        bk, hs = e
        cut = now_min - self.win + 1
        while bk:
            m = next(iter(bk))
            if m >= cut:
                break
            v = bk.pop(m)
            for i in range(NF):
                hs[i] -= v[i]

    def _sum5(self, ip, now_min):
        out = [0] * NF
        e = self.state['W'].get(ip)
        if not e:
            return out
        for m in reversed(e[0]):
            if m < now_min - 4:
                break
            v = e[0][m]
            for i in range(NF):
                out[i] += v[i]
        return out

    def _g_add(self, minute, n):
        bk, tot = self.state['G']
        if bk:
            last = next(reversed(bk))
            minute = max(minute, last)
        bk[minute] = bk.get(minute, 0) + n
        tot[0] += n

    def _g_expire(self, now_min):
        bk, tot = self.state['G']
        cut = now_min - self.win + 1
        while bk:
            m = next(iter(bk))
            if m >= cut:
                break
            tot[0] -= bk.pop(m)

    # --- строки журнала
    def add(self, p):
        ip, minute, meth, url, st, size, ref, ua = p
        if ip in self.allow:
            return
        r = self.r
        S = self.state
        if self.max_min is None or minute > self.max_min:
            self.max_min = minute
        path = url.split('?', 1)[0]
        is_static = r.is_static(path)
        sqli = not is_static and r.is_sqli(url)
        hit = r.probe_hit(path, url)
        # проба: сканеры подделывают Referer поисковика и меняют имя браузера на каждой пробе — ни «пришёл из
        # поиска», ни «другие браузеры за адресом» по ней не считаем
        probe = st == 444 or sqli or hit
        page = not probe and r.is_page(path, url, is_static)
        se_page = page and bool(r.se_ref and r.se_ref.match(ref))
        if probe:
            S['PU'].setdefault(ip, {})[ua[:150]] = minute
        b, h = self._bucket(ip, minute)
        b[REQ] += 1
        h[REQ] += 1
        self.dly['req'] += 1
        t = self.t5[minute // 5 * 5]
        t[0] += 1
        if ip in self.banned_now and (st in (403, 444) or not self.enforced_mode or not self.banned_now[ip]):
            b[BAN] += 1                                       # в наблюдении — «были бы отбиты»
            h[BAN] += 1
            self.ban_hits[ip] += 1
            self.dly['banned_hits'] += 1
            v = self.rv.setdefault(ip, {'hits': 0, 'pages': 0, 'uas': collections.Counter(), 'se_ref': 0,
                                        'favicon': 0, 'st': 0, 'sg': 0, 'post': 0, 'js': 0})
            v['hits'] += 1
            if r.ua_class(ua)[0] == 'br' and page:
                v['uas'][ua[:150]] += 1
            if se_page:
                v['se_ref'] += 1                              # пришёл из поиска — так ходят люди
            if path == '/favicon.ico' or path.startswith('/apple-touch-icon'):
                v['favicon'] += 1                             # браузер показал страницу и просит значок
            elif is_static:
                v['st'] += 1
            elif r.typing and r.typing.search(url):
                v['sg'] += 1
            elif meth == 'POST':
                v['post'] += 1
            elif r.js and r.js.search(url):
                v['js'] += 1
            elif r.is_product(path, url) or (r.catalog and r.catalog.search(url)) or (r.search and r.search.search(url)):
                v['pages'] += 1
            return
        cls, fam = r.ua_class(ua)
        S['UA'][ip] = (ua[:300], cls, fam, minute)
        if cls == 'br':
            self._g_add(minute, 1)
            if page:
                u = S['UAS'].setdefault(ip, {})
                if len(u) < 40 or ua[:150] in u:
                    u[ua[:150]] = minute
            if se_page and not is_static:
                S['HD'][ip] = minute
        if is_static:
            b[ST] += 1
            h[ST] += 1
        else:
            b[D] += 1
            h[D] += 1
            self.dly['dyn'] += 1
            t[1] += 1
            f = None
            if r.typing and r.typing.search(url):
                f = TY
            elif meth == 'POST':
                f = P
                if r.login and r.login.search(url):
                    b[LG] += 1
                    h[LG] += 1
            elif r.js and r.js.search(url):
                f = JS
            elif meth == 'HEAD':
                f = HD if page else None
            elif not probe:
                if r.is_product(path, url):
                    f = PR
                elif r.catalog and r.catalog.search(url):
                    f = CT
                elif r.search and r.search.search(url):
                    f = SR
                if f is not None and r.page_number(url) >= self.s.th('pagination_min_page'):
                    b[DP] += 1
                    h[DP] += 1
            if f is not None:
                b[f] += 1
                h[f] += 1
            if st in (403, 429):
                b[RF] += 1
                h[RF] += 1
        if cls in ('se', 'ai'):
            self.dly['%s:%s' % (cls, fam)] += 1
        if sqli:
            b[SC] += self.s.th('scan_hits')                   # SQL-инъекция — уверенная проба: бан с первой попытки
            h[SC] += self.s.th('scan_hits')
        elif hit:
            b[SC] += 1
            h[SC] += 1
        if st == 200 and size not in ('-', '0') and r.leak and r.leak.search(path) \
                and not (r.leak_exclude and r.leak_exclude.search(path)):
            self.leaks.append((ip, url, size, ua))
        self.active[ip] += 1

    # --- проход
    def evaluate(self):
        s, st, r = self.s, self.st, self.r
        S = self.state
        tnow = now()
        day = day_key(tnow)
        for k, v in self.dly.items():
            st.add_daily(day, k, v)
        for k, (req, dyn) in self.t5.items():
            st._add('traffic', {'t5': k * 60}, {'req': req, 'dyn': dyn})
        st._add('ticks', {'h': tnow // 3600}, {'n': 1})
        for ip, n in self.ban_hits.items():
            st.q('UPDATE bans SET hits=hits+? WHERE ip=?', (n, ip))
            st.q('UPDATE ban_log SET hits=hits+? WHERE id=(SELECT MAX(id) FROM ban_log WHERE ip=?)', (n, ip))
        for ip, v in self.rv.items():
            row = st.q('SELECT uas FROM review WHERE ip=? AND verdict IS NULL', (ip,)).fetchone()
            if not row:
                continue
            saved = json.loads(row[0] or '{}') or {}
            pu = set(saved.pop(PROBE_KEY, [])) | set(S['PU'].get(ip, ()))
            uas = collections.Counter(saved)
            uas.update(v['uas'])
            uas = dict(uas.most_common(20))
            if pu:
                uas[PROBE_KEY] = sorted(pu)[:20]
            st.q('UPDATE review SET hits=hits+?, pages=pages+?, uas=?, se_ref=se_ref+?, favicon=favicon+?, st=st+?, '
                 'sg=sg+?, post=post+?, js=js+? WHERE ip=?',
                 (v['hits'], v['pages'], json.dumps(uas, ensure_ascii=False), v['se_ref'], v['favicon'], v['st'],
                  v['sg'], v['post'], v['js'], ip))

        now_min = self.max_min if self.max_min is not None else tnow // 60
        for ip in self.active:
            self._expire(ip, now_min)
        self._g_expire(now_min)

        if self.ver is None or (s.replay and tnow - getattr(self, '_ver_ts', 0) > 3600):
            self.ver = Verifier(s, r, st)
            self._ver_ts = tnow
        ver = self.ver
        UA = S['UA']
        todo = [(ip, UA[ip][2]) for ip in self.active if ip in UA and UA[ip][1] in ('se', 'ai')
                and ver.status(ip, UA[ip][1], UA[ip][2]) is None and not ver.checked(ip, UA[ip][2])
                and ver.suffixes(UA[ip][2])]
        if todo:
            ver.check(todo)
        for ip in self.active:
            if ip in UA and UA[ip][1] in ('se', 'ai'):
                vs = ver.status(ip, UA[ip][1], UA[ip][2])
                st.add_daily(day, '%s:%s:%s' % (UA[ip][1], UA[ip][2], 'ok' if vs == 1 else 'fake' if vs == 0 else 'na'),
                             self.active[ip])

        started = int(st.meta('started', 0) or 0)
        if not started:
            started = tnow
            st.set_meta('started', started)
        warm = tnow - started >= s.th('warmup_min') * 60
        grace = {x[0] for x in st.q("SELECT ip FROM review_log WHERE action='снят сам' AND ts > ?",
                                    (tnow - s.th('grace_h') * 3600,))}
        paused = int(st.meta('pause_until', 0) or 0) > tnow
        g_total = S['G'][1][0]
        new_bans = []
        th = s.th
        for ip in self.active:
            if ip in self.banned_now or ip not in UA:
                continue
            ua, cls, fam, _ = UA[ip]
            h = S['W'][ip][1]
            f5 = self._sum5(ip, now_min)
            pages, pages5 = h[PR] + h[CT] + h[SR], f5[PR] + f5[CT] + f5[SR]
            detail = {'ua': ua[:150], 'pages_60': pages, 'products_60': h[PR], 'dyn_60': h[D], 'static_60': h[ST],
                      'js_60': h[JS], 'typing_60': h[TY], 'post_60': h[P], 'head_60': h[HD], 'deep_60': h[DP],
                      'refusals_60': h[RF], 'login_60': h[LG], 'probes_60': h[SC], 'pages_5': pages5, 'dyn_5': f5[D],
                      'cls': cls, 'fam': fam,
                      'human_before': 1 if S['HD'].get(ip, -10 ** 9) >= now_min - 1440 else 0}
            soft_ok = ip not in grace
            shared = ip in r.shared
            rule = None
            if cls == 'se':
                vs = ver.status(ip, cls, fam)
                if vs == 1:
                    continue
                if vs == 0 and h[D] >= th('fake_se_dyn') and h[ST] == 0:
                    rule = 'fake_se'
                elif vs is None and f5[D] < th('rate_dyn_5'):
                    continue                                  # ждём проверки DNS
                # vs == -1 (проверить нечем): не подделка, но правила для всех — парсер, частота, пробы — действуют
            elif cls == 'ai':
                vs = ver.status(ip, cls, fam)
                k = th('ai_factor')
                if vs == 1:
                    continue
                if vs == 0 and h[D] >= th('fake_ai_dyn'):
                    rule = 'fake_ai'
                elif pages5 >= th('rate_pages_5') * k or f5[D] >= th('rate_dyn_5') * k:
                    rule = 'rate'
                elif h[SC] < th('scan_hits') or shared:
                    continue
                # иначе — к правилу «сканер»: сканеры называются и ИИ-ботами
            if rule is None:
                no_static = h[ST] == 0
                if h[SC] >= th('scan_hits') and not shared:
                    rule = 'scan'
                elif pages5 >= th('rate_pages_5') or f5[D] >= th('rate_dyn_5'):
                    rule = 'rate'
                elif h[LG] >= th('login_posts'):
                    rule = 'login'
                elif h[RF] >= th('refusals_hour'):
                    rule = 'refusals'
                elif soft_ok and warm and no_static and h[TY] == 0 and h[PR] >= th('headless_products'):
                    rule = 'headless'
                elif soft_ok and warm and no_static and h[TY] == 0 and h[JS] == 0 and h[P] == 0 \
                        and h[PR] >= th('parser_products'):
                    rule = 'parser'
                elif soft_ok and warm and no_static and h[TY] == 0 and h[DP] >= th('pagination_pages'):
                    rule = 'pagination'
                # HEAD шлют и браузеры некоторых телефонов (перед каждой страницей) — только вместе с «без картинок»
                elif soft_ok and no_static and h[TY] == 0 and h[HD] >= th('head_hits'):
                    rule = 'head'
            if not rule:
                continue
            if s.never_ban_cdn and ip in r.cdn:
                self._once('cdn:' + ip, 'адрес CDN похож на бота — не закрыт',
                           'Коротко: адрес %s принадлежит CDN (Cloudflare) и попал под правило «%s». Такие адреса '
                           'сторож не закрывает: если сайт стоит за Cloudflare без настройки real_ip, через них идут все '
                           'посетители. Проверьте, что nginx видит настоящие адреса (real_ip_header CF-Connecting-IP).'
                           % (ip, RULE_NAMES.get(rule, rule)))
                continue
            if g_total >= th('proxy_min_req') and h[REQ] >= th('proxy_share') * g_total \
                    and len(S['UAS'].get(ip, ())) >= th('proxy_uas'):
                self._once('proxy:' + ip, 'похоже, сайт за прокси — адрес не закрыт',
                           'Коротко: через адрес %s за час прошло %s из %s запросов браузеров, за ним %d разных браузеров. '
                           'Так выглядит прокси или балансировщик, а не бот: если его закрыть, закроется весь сайт. '
                           'Сторож его не закрыл (правило «%s»). Проверьте, что nginx видит настоящие адреса посетителей '
                           '(set_real_ip_from / real_ip_header).' % (ip, fmt(h[REQ]), fmt(g_total),
                                                                    len(S['UAS'].get(ip, ())), RULE_NAMES.get(rule, rule)))
                continue
            self.ban(ip, rule, detail, paused=paused)
            if S['PU'].get(ip):
                st.q('UPDATE review SET uas=? WHERE ip=? AND verdict IS NULL',
                     (json.dumps({PROBE_KEY: sorted(S['PU'][ip])[:20]}, ensure_ascii=False), ip))
            new_bans.append((ip, rule, detail))

        self.alerts(new_bans, now_min)
        self.review_pass()
        self.check_flood()
        self.breaker()
        if not s.replay:
            self.self_check()
            self.mail.retry()
        if now_min - S.get('sweep', 0) >= 15:
            self.sweep(now_min)
        st.q('DELETE FROM traffic WHERE t5 < ?', (tnow - 15 * 86400,))
        st.q('DELETE FROM ticks WHERE h < ?', (tnow // 3600 - 24 * 15,))
        st.q('DELETE FROM bans WHERE until < ?', (tnow - 86400,))
        st.commit()
        self.reset_tick()

    def _once(self, key, subject, body):
        log(subject, key)
        self.mail.send(subject, body, key=key, repeat_h=24)

    def sweep(self, now_min):
        S = self.state
        S['sweep'] = now_min
        for ip in list(S['W']):
            self._expire(ip, now_min)
            if not S['W'][ip][0]:
                del S['W'][ip]
                S['UA'].pop(ip, None)
        for ip in [i for i, m in S['HD'].items() if m < now_min - 1440]:
            del S['HD'][ip]
        for key, keep in (('PU', 1440), ('UAS', self.win)):
            for ip in list(S[key]):
                S[key][ip] = {u: m for u, m in S[key][ip].items() if m >= now_min - keep}
                if not S[key][ip]:
                    del S[key][ip]

    def ban(self, ip, rule, detail, hours=None, paused=False):
        return do_ban(self.s, self.st, ip, rule, detail, hours, paused=paused, enforced_mode=self.enforced_mode)

    def alerts(self, new_bans, now_min):
        s, st, th = self.s, self.st, self.s.th
        always = s.policy('enforce_always')
        enforced = self.enforced_mode
        for ip, rule, d in new_bans:
            real = enforced or rule in always
            if d['pages_60'] >= th('heavy_pages') or d['dyn_60'] >= th('heavy_dyn'):
                self.mail.send('тяжёлый бот %s %s' % (ip, 'закрыт' if real else '(наблюдение)'),
                               'Коротко: с адреса %s за последний час пришло %s запросов, из них %s страниц каталога. '
                               'Адрес %s. Делать ничего не нужно, если это не ваш партнёр.\n\nПравило: %s\n'
                               'Подробности: %s' % (ip, fmt(d['dyn_60']), fmt(d['pages_60']),
                                                    'закрыт' if real else 'был бы закрыт (сторож в режиме наблюдения)',
                                                    RULE_NAMES.get(rule, rule),
                                                    json.dumps(d, ensure_ascii=False, indent=1)),
                               key='heavy:' + ip)
            if rule == 'fake_se' and d['dyn_60'] >= th('fake_se_alert'):
                self.mail.send('адрес %s выдаёт себя за поисковик' % ip,
                               'Коротко: адрес %s представляется роботом %s, но по DNS им не является, и сделал %s '
                               'запросов за час. Это программа под чужим именем, адрес %s. Делать ничего не нужно.\n\n%s'
                               % (ip, d['fam'], fmt(d['dyn_60']), 'закрыт' if enforced else 'был бы закрыт',
                                  json.dumps(d, ensure_ascii=False, indent=1)), key='fake:' + ip)
        for ip in self.ban_hits:
            e = self.state['W'].get(ip)
            n = e[1][BAN] if e else 0
            if n >= th('banned_flood'):
                self.mail.send('закрытый адрес %s продолжает' % ip,
                               'Коротко: адрес %s закрыт, но за час прислал ещё %s запросов. nginx отвечает им дёшево, '
                               'сайт не страдает. Если так продолжится сутки — адрес можно закрыть в файрволе.'
                               % (ip, fmt(n)), key='banflood:' + ip)
        t = now()
        wave = st.q("SELECT COUNT(*), GROUP_CONCAT(ip) FROM ban_log WHERE ts > ? AND rule IN "
                    "('parser','headless','pagination','head')", (t - 3600,)).fetchone()
        if wave[0] >= th('wave_bans'):
            nets = collections.Counter(net_of(i) for i in (wave[1] or '').split(','))
            self.mail.send('распределённый парсер: %d адресов за час' % wave[0],
                           'Коротко: за последний час сторож %s %d адресов одного почерка — парсер меняет адреса '
                           '(обычно мобильные или домашние прокси). Каждый закрывается после порога своего правила.\n\n'
                           'Сети: %s' % ('закрыл' if enforced else 'закрыл бы', wave[0],
                                         ', '.join('%s — %d' % kv for kv in nets.most_common(10))), key='wave')
        for ip, url, size, ua in self.leaks[:5]:
            self.mail.send('ВНИМАНИЕ, сайт отдал служебный файл',
                           'Коротко: на запрос %s с адреса %s сайт ответил кодом 200 и отдал %s байт. Такие файлы '
                           '(резервные копии, .env, дампы базы) не должны открываться снаружи. Нужно проверить сегодня: '
                           'что это за файл и нет ли в нём паролей.\n\nUA: %s' % (url, ip, size, ua),
                           key='leak:' + url, repeat_h=24)

    def breaker(self):
        """Предохранитель: слишком много настоящих автобанов за час — похоже на ошибку настройки, автобаны на паузу."""
        s, st = self.s, self.st
        t = now()
        if int(st.meta('pause_until', 0) or 0) > t:
            return
        n = st.q("SELECT COUNT(*) FROM ban_log WHERE ts > ? AND enforced=1 AND rule != 'manual'", (t - 3600,)).fetchone()[0]
        if n >= s.th('max_bans_hour'):
            st.set_meta('pause_until', t + 3600)
            self.mail.send('автобаны остановлены на час',
                           'Коротко: за последний час сторож по-настоящему закрыл %d адресов — больше предела %d. Так '
                           'бывает при ошибке настройки (журнал в другом формате, сайт за прокси без real_ip) или при '
                           'большой атаке. На час новые автобаны записываются только как «закрыл бы». Посмотрите '
                           '«antibot --daily 1».' % (n, s.th('max_bans_hour')), key='breaker', repeat_h=6)

    def review_pass(self):
        review_pass(self.s, self.st, self.ver, self.allow, self.mail, self.enforced_mode)

    def check_flood(self):
        s, st = self.s, self.st
        t5 = (now() // 300 - 1) * 300
        r = st.q('SELECT dyn FROM traffic WHERE t5=?', (t5,)).fetchone()
        if not r:
            return
        base = sorted(x[0] for x in st.q('SELECT dyn FROM traffic WHERE t5 IN (%s)' %
                                         ','.join(str(t5 - d * 86400) for d in range(1, 8))))
        med = base[len(base) // 2] if len(base) >= 3 else 0
        if r[0] >= max(s.th('flood_floor'), s.th('flood_factor') * med):
            self.mail.send('всплеск запросов к сайту',
                           'Коротко: за 5 минут до %s пришло %s динамических запросов, обычно в это время — %s. Это может '
                           'быть атака или большой парсер. Сторож закрывает отдельные адреса сам; если сайт тормозит — '
                           '«antibot --daily 1» на сервере.' % (time.strftime('%H:%M', time.localtime(t5 + 300)),
                                                               fmt(r[0]), fmt(med)), key='flood', repeat_h=1)

    def self_check(self):
        s, st = self.s, self.st
        t = now()
        last = int(st.meta('last_data', t))
        if t - last > s.th('stale_min') * 60:
            self.mail.send('журнал сайта не пополняется',
                           'Коротко: в журнал запросов сайта (%s) %d минут не пришло ни строки. Либо сайт не принимает '
                           'посетителей, либо журнал переехал. Проверьте, открывается ли сайт, и путь log в настройках.'
                           % (s.log, (t - last) // 60), key='stale', repeat_h=6)
        if s.mode() == 'enforce' and s.nginx_dir and t - int(st.meta('nginx_check', 0)) > 3600:
            st.set_meta('nginx_check', t)
            code, out = run(s.nginx_dump)
            if code == 0 and ('$antibot_ban' not in out or '/__antibot-banned' not in out):
                self.mail.send('баны не подключены к сайту',
                               'Коротко: сторож закрывает адреса, но nginx их не применяет — в его настройке нет файлов '
                               'AntiBot (%s и строки include %s внутри server). Так бывает после пересборки настроек '
                               'панелью. Сайт работает, но без защиты.' % (s.nginx_http_conf, s.nginx_site_conf),
                               key='include', repeat_h=12)


def net_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 4:
        return str(ipaddress.ip_network(ip + '/24', strict=False))
    return str(ipaddress.ip_network(ip + '/48', strict=False))


def do_ban(s, store, ip, rule, detail, hours=None, paused=False, enforced_mode=None):
    """Бан: лестница повторов, долгий бан повторному сканеру; в наблюдении — «закрыл бы» (kind 0)."""
    t = now()
    if enforced_mode is None:
        enforced_mode = s.mode() == 'enforce'
    always = s.policy('enforce_always')
    if hours is None:
        since = t - s.th('repeat_days') * 86400
        freed = store.q("SELECT MAX(ts) FROM review_log WHERE ip=? AND action IN ('снят сам', 'снят вручную')",
                        (ip,)).fetchone()[0] or 0
        prev = store.q("SELECT COUNT(*) FROM ban_log WHERE ip=? AND ts>? AND rule!='manual'",
                       (ip, max(since, freed))).fetchone()[0]
        shared = store.q("SELECT 1 FROM review_log WHERE ip=? AND ts>? AND verdict IN ('shared', 'typing') LIMIT 1",
                         (ip, since)).fetchone()
        hours = s.ban_hours(rule)[0]
        if prev:
            steps = s.ban_hours('repeat')
            step = steps[0] if shared else steps[min(prev, len(steps)) - 1]
            hours = max(hours, step)
        if rule == 'scan':
            people = store.q("SELECT 1 FROM review_log WHERE ip=? AND verdict IN ('shared', 'typing', 'human') LIMIT 1",
                             (ip,)).fetchone()
            again = store.q('SELECT 1 FROM ban_log WHERE ip=? AND rule=? AND ts>? LIMIT 1', (ip, rule, freed)).fetchone()
            if again and not people:
                hours = s.ban_hours('scan_repeat')[0]
    enforced = s.mode() != 'report' and (enforced_mode or rule in always or rule == 'manual') and not paused
    until = t + int(hours * 3600)
    store.q('INSERT INTO ban_log(ip, rule, ts, until, enforced, detail) VALUES(?,?,?,?,?,?)',
            (ip, rule, t, until, 1 if enforced else 0, json.dumps(detail, ensure_ascii=False)))
    # kind 0 — «закрыл бы»: правила адрес до конца срока не пересчитывают, в nginx он не попадает
    kind = (2 if rule in s.policy('silent') else 1) if enforced else 0
    store.q('INSERT OR REPLACE INTO bans(ip, rule, kind, since, until, hits, note) VALUES(?,?,?,?,?,0,?)',
            (ip, rule, kind, t, until, detail.get('ua', '')[:200]))
    if rule != 'manual':                       # работа над ошибками: следующие сутки смотрим, кто за адресом
        store.q('INSERT OR REPLACE INTO review(ip, rule, since, human_before, bot_ua) VALUES(?,?,?,?,?)',
                (ip, rule, t, 1 if detail.get('human_before') else 0, detail.get('ua', '')[:150]))
    log('БАН' if enforced else 'закрыл бы', ip, rule, '%g ч' % hours, json.dumps(detail, ensure_ascii=False)[:300])
    return until


def review_pass(s, store, ver, allow, mailer, enforced_mode):
    """Работа над ошибками: кого из закрытых за сутки, похоже, закрыли зря.

    Явные ошибки сторож исправляет сам: поисковик по DNS или адрес из списка ИИ-компании — снять и в белый список;
    человек (пришёл из поиска, выдачу почти не листает) — снять, не чаще раза в неделю на адрес. Общий адрес и
    «страница работала как в браузере» — только предложение на почту. Выключить автоснятие: auto_unban_humans = no.
    """
    t = now()
    th = s.th
    always = s.policy('enforce_always')
    todo = [r[0] for r in store.q('SELECT ip FROM review WHERE verdict IS NULL AND rdns_ok IS NULL LIMIT 20')]
    if todo:                                   # не поисковик ли это под браузерным именем
        suf = tuple(x for d in (ver.r.se_domains, ver.r.ai_rdns) for v in d.values() for x in v)
        out, threads = {}, []
        for ip in todo:
            th_ = threading.Thread(target=_rdns_check, args=(ip, suf, out), daemon=True)
            th_.start()
            threads.append(th_)
        deadline = time.time() + 4
        for th_ in threads:
            th_.join(max(0, deadline - time.time()))
        for ip, (ok, host) in list(out.items()):
            store.q('UPDATE review SET rdns=?, rdns_ok=? WHERE ip=?', (host, ok, ip))
    found = []
    rows = store.q('SELECT ip, rule, since, hits, pages, uas, bot_ua, se_ref, favicon, st, sg, post, js, human_before, '
                   'rdns, rdns_ok FROM review WHERE verdict IS NULL').fetchall()
    for ip, rule, since, hits, pages, uas, bot_ua, se_ref, fav, st_, sg, post, js, hb, rdns, rdns_ok in rows:
        uas = json.loads(uas or '{}') or {}
        probe_uas = set(uas.pop(PROBE_KEY, []))
        # другие браузеры за адресом: не тот UA, под которым шёл бот, и запросов мало — так выглядят люди за NAT.
        # Имя, под которым адрес делал пробы, — сам сканер.
        others = [u for u, n in uas.items() if u != (bot_ua or '')[:150] and u not in probe_uas and n <= 20]
        in_list = ver.in_lists(ip, bot_ua)
        ev = []
        if hits:
            ev.append('после бана %d запросов, из них страниц каталога %d' % (hits, pages))
        if se_ref:
            ev.append('%d раз пришли на адрес из поиска' % se_ref)
        if others:
            ev.append('другие браузеры за адресом, по нескольку запросов — %d' % len(others))
        if hb:
            ev.append('за сутки до бана на этот адрес приходили из поиска')
        if sg or post or st_ or fav or js:
            ev.append('после бана: подсказки %d, скрипты %d, POST %d, картинки %d, значок %d' % (sg, js, post, st_, fav))
        if rdns:
            ev.append('имя адреса по DNS: ' + rdns)
        verdict = None
        if rdns_ok == 1 or in_list or ip in allow:
            verdict = 'good-bot'
        elif se_ref and pages <= th('human_max_pages'):
            verdict = 'human'
        elif se_ref or len(others) >= th('shared_uas') - 1 or hb:
            verdict = 'shared'
        elif t - since > th('review_hours') * 3600:
            tj = sg + js
            if tj and (post or st_) and tj >= th('typing_share') * max(pages, 1):
                verdict = 'typing'
                ev.append('страница работала как в браузере на %d %% страниц' % min(100, 100 * tj // max(pages, 1)))
            else:
                verdict = 'bot' if hits >= 20 else 'quiet'
        if not verdict:
            continue
        action = ''
        if verdict == 'good-bot':
            action = 'снят сам'
            if (rdns_ok == 1 or in_list) and ip not in allow:
                note = 'хороший бот по DNS: %s' % rdns if rdns_ok == 1 else 'адрес из опубликованной сети компании'
                allow_add(s, ip, '%s, добавил сторож %s' % (note, time.strftime('%d.%m.%Y', time.localtime(t))))
        elif verdict == 'human':
            prev = store.q("SELECT COUNT(*) FROM review_log WHERE ip=? AND action='снят сам' AND ts > ?",
                           (ip, t - 7 * 86400)).fetchone()[0]
            action = 'снят сам' if s.auto_unban and not prev else 'предложение'
        elif verdict in ('shared', 'typing'):
            action = 'предложение'
        if action == 'снят сам':
            store.q('DELETE FROM bans WHERE ip=?', (ip,))
            log('СНЯЛ' if enforced_mode or rule in always else 'снял бы', ip, verdict, '; '.join(ev))
        store.q('UPDATE review SET verdict=? WHERE ip=?', (verdict, ip))
        store.q('INSERT INTO review_log(ts, ip, rule, verdict, action, evidence) VALUES(?,?,?,?,?,?)',
                (t, ip, rule, verdict, action, '; '.join(ev)))
        if verdict in PROPOSAL:
            found.append((ip, rule, verdict, action, ev, uas, pages))
    store.q('DELETE FROM review WHERE since < ?', (t - 8 * 86400,))
    store.commit()
    if not found:
        return
    real_all = enforced_mode or all(f[1] in always for f in found)
    verb, unb = ('закрыл', 'снял') if real_all else ('закрыл бы', 'снял бы')
    n_auto = sum(1 for f in found if f[3] == 'снят сам')
    n_prop = len(found) - n_auto
    short = 'Коротко: сторож проверил свои баны и, похоже, зря %s %d адрес(а).' % (verb, len(found))
    if n_auto:
        short += ' %d — явная ошибка (поисковик или человек, пришедший из поиска), сторож %s бан сам — делать ничего ' \
                 'не нужно.' % (n_auto, unb)
    if n_prop:
        short += ' По %d нужно ваше решение — предложения ниже.' % n_prop
    if not enforced_mode:
        short += ' Сторож в режиме наблюдения: по-настоящему он закрывает только сканеров уязвимостей, остальное — ' \
                 'проверка правил.'
    body = [short, '']
    for ip, rule, verdict, action, ev, uas, pages in found:
        body.append('%s — %s. Правило: «%s». %s' % (ip, RV_NAMES[verdict], RULE_NAMES.get(rule, rule),
                                                     'Бан снят сам.' if action == 'снят сам' else 'Ждёт решения.'))
        body += ['  • ' + e for e in ev]
        if uas:
            body.append('  • браузеры: ' + ' | '.join('%s (%s)' % (u[:60], n) for u, n in list(uas.items())[:3]))
        body.append('  Предложение: ' + PROPOSAL[verdict])
        body.append('  Команды: antibot --who %s · antibot --unban %s · antibot --allow %s "кто это"' % (ip, ip, ip))
        body.append('')
    body += review_rule_hints(store)
    mailer.send('работа над ошибками — %d адрес(а) %s зря?' % (len(found), verb), '\n'.join(body), key='review:%d' % t)


def review_rule_hints(store, days=7):
    """Какие правила за неделю ошибаются чаще 10 % — предложение поправить порог."""
    t0 = now() - days * 86400
    bans = collections.Counter(r[0] for r in store.q('SELECT rule FROM ban_log WHERE ts > ?', (t0,)))
    bad = collections.Counter(r[0] for r in store.q(
        "SELECT rule FROM review_log WHERE ts > ? AND verdict IN ('good-bot','human','shared','typing')", (t0,)))
    out = []
    for rule, n in bad.most_common():
        total = max(bans.get(rule, 0), n)
        if n >= 2 and n / total >= 0.10:
            out.append('Правило «%s»: за %d дней %d из %d банов похожи на ошибку (%d %%) — стоит поднять его порог '
                       '(antibot.ini, [thresholds]).' % (RULE_NAMES.get(rule, rule), days, n, total, 100 * n // total))
    return (['Что поправить в правилах:'] + ['  ' + o for o in out]) if out else []


# ---------------------------------------------------------------- проход по новым строкам
def read_new(s, store, parser):
    """Новые строки журнала с прошлого прохода (с хвостом файла .1 после ротации). Первый запуск — с конца."""
    try:
        stt = os.stat(s.log)
    except OSError as e:
        return None, str(e)
    pos = json.loads(store.meta('pos', '{}') or '{}')
    if not pos:
        store.set_meta('pos', json.dumps({'ino': stt.st_ino, 'off': stt.st_size}))
        return [], 'первый запуск: начинаю с конца журнала'
    lines = []
    off = pos.get('off', 0)
    if pos.get('ino') != stt.st_ino:
        # журнал повернули: дочитать хвост прежнего файла, потом новый с начала. Прежний файл ищем по inode:
        # access.log.1 или с датой (logrotate dateext: access.log-20261028), без сжатия
        olds = [s.log + '.1'] + [f for f in sorted(glob.glob(s.log_archives), reverse=True) if not f.endswith('.gz')]
        for old in olds:
            try:
                if os.path.realpath(old) == os.path.realpath(s.log) or os.stat(old).st_ino != pos.get('ino'):
                    continue
                with open(old, 'rb') as f:
                    f.seek(off)
                    chunk = f.read(MAX_READ)
                lines += chunk.decode('utf-8', 'replace').splitlines()
                break
            except OSError:
                pass
        off = 0
    if stt.st_size < off:                                    # файл обрезан
        off = 0
    with open(s.log, 'rb') as f:
        f.seek(off)
        chunk = f.read(MAX_READ)
    cut = chunk.rfind(b'\n') + 1                             # неполную последнюю строку — в следующий проход
    store.set_meta('pos', json.dumps({'ino': stt.st_ino, 'off': off + cut}))
    if cut or lines:
        store.set_meta('last_data', now())
    lines += chunk[:cut].decode('utf-8', 'replace').splitlines()
    return lines, ''


def cmd_tick(s):
    r = Rules(s)
    store = Store(s.state_dir)
    mailer = Mailer(s, store)
    parser = LogParser(s)
    lines, note = read_new(s, store, parser)
    if lines is None:
        mailer.send('не читается журнал сайта',
                    'Коротко: сторож не может прочитать журнал запросов сайта, поэтому сейчас никого не видит и не '
                    'закрывает. Сайт работает. Проверьте путь log в настройках и права.\n\n%s' % note, key='log-missing')
        return
    if note:
        log(note)
    g = Guard(s, r, store, mailer)
    for line in lines:
        p = parser.parse(line)
        if p:
            g.add(p)
    g.evaluate()
    save_windows(s, g.state)
    store.set_meta('last_tick', now())
    store.commit()
    render_nginx(s, store, mailer)


def cmd_replay(s, files):
    """Старые журналы — в отдельную базу (--state), минута за минутой, со временем журнала."""
    r = Rules(s)
    store = Store(s.state_dir)
    mailer = Mailer(s, store)
    parser = LogParser(s)

    def first_minute(f):
        try:
            with open_log(f) as fh:
                for line in fh:
                    p = parser.parse(line)
                    if p:
                        return p[1]
        except OSError:
            pass
        return 0

    files = sorted(files, key=first_minute)
    g = None
    cur = None
    n = 0
    for f in files:
        log('читаю', f)
        with open_log(f) as fh:
            for line in fh:
                p = parser.parse(line)
                if not p:
                    continue
                if cur is None:
                    cur = p[1]
                    CLOCK.fixed = cur * 60 + 59
                    store.set_meta('started', CLOCK.fixed)
                    g = Guard(s, r, store, mailer)
                if p[1] > cur:
                    CLOCK.fixed = cur * 60 + 59
                    g.evaluate()
                    cur = p[1]
                g.add(p)
                n += 1
    if g:
        CLOCK.fixed = cur * 60 + 59
        g.evaluate()
        save_windows(s, g.state)
    store.commit()
    print('строк: %s' % fmt(n))
    print('баны по правилам (по-настоящему / «закрыл бы»):')
    for rule, enf, cnt in store.q('SELECT rule, enforced, COUNT(*) FROM ban_log GROUP BY rule, enforced ORDER BY rule'):
        print('  %-24s %-10s %d' % (RULE_NAMES.get(rule, rule), 'закрыл' if enf else 'закрыл бы', cnt))
    print('работа над ошибками:')
    for v, a, cnt in store.q('SELECT verdict, action, COUNT(*) FROM review_log GROUP BY verdict, action'):
        print('  %-40s %-12s %d' % (RV_NAMES.get(v, v), a or '—', cnt))
    print('писем было бы: %d' % len(mailer.replay_log))
    for t, subj in mailer.replay_log[:30]:
        print('  ', hm(t), subj)


# ---------------------------------------------------------------- сводка за сутки и разбор адреса
def _agg():
    # uas — все имена браузеров; puas — только с обычных страниц: сканер меняет имя на каждой пробе, это не люди
    return {'req': 0, 'pages': 0, 'prod': 0, 'st': 0, 'js': 0, 'ty': 0, 'post': 0, 'head': 0, 'probe': 0, 'sqli': 0,
            'rf': 0, 'codes': collections.Counter(), 'uas': collections.Counter(), 'puas': collections.Counter(),
            'se': 0, 'hours': set(), 'q': set(), 'refs': collections.Counter(), 'paths': collections.Counter(),
            'after_codes': collections.Counter(), 'cls': '', 'fam': ''}


def aggregate(s, r, parser, since, ip=None, after=None):
    """Журнал за период -> {адрес: счётчики}. after — {адрес: время бана}: коды ответов после бана — в after_codes."""
    A = {}
    after = after or {}
    for p in scan_logs(s, parser, since, ip):
        a_ip, minute, meth, url, st, size, ref, ua = p
        a = A.get(a_ip)
        if a is None:
            a = A[a_ip] = _agg()
        if a_ip in after and minute * 60 >= after[a_ip]:
            a['after_codes'][st] += 1
        path = url.split('?', 1)[0]
        is_static = r.is_static(path)
        sqli = not is_static and r.is_sqli(url)
        hit = r.probe_hit(path, url)
        probe = st == 444 or sqli or hit
        page = not probe and r.is_page(path, url, is_static)
        a['req'] += 1
        a['codes'][st] += 1
        a['hours'].add(minute // 60)
        a['uas'][ua[:200]] += 1
        if page and r.ua_class(ua)[0] == 'br':
            a['puas'][ua[:200]] += 1
        if hit or sqli:
            a['probe'] += 1
            a['sqli'] += 1 if sqli else 0
        if page and r.se_ref and r.se_ref.match(ref):
            a['se'] += 1
        if ref not in ('-', ''):
            host = urllib.parse.urlsplit(ref).netloc.lower()
            if host and host != s.domain and not host.endswith('.' + s.domain):
                a['refs'][host] += 1
        if is_static:
            a['st'] += 1
            continue
        if ip:
            a['paths'][url[:120]] += 1
        if r.typing and r.typing.search(url):
            a['ty'] += 1
        elif meth == 'POST':
            a['post'] += 1
        elif r.js and r.js.search(url):
            a['js'] += 1
        elif meth == 'HEAD':
            a['head'] += 1
        elif not probe:
            is_prod = r.is_product(path, url)
            if is_prod or (r.catalog and r.catalog.search(url)) or (r.search and r.search.search(url)):
                a['pages'] += 1
                a['prod'] += 1 if is_prod else 0
                if r.search and r.search.search(url) and len(a['q']) < 200:
                    a['q'].add(url)
        if st in (403, 429):
            a['rf'] += 1
    for a in A.values():                       # класс адреса — по самому частому имени
        if a['uas']:
            a['cls'], a['fam'] = r.ua_class(a['uas'].most_common(1)[0][0])
    return A


def se_state(r, dns, ip, fam):
    """Проверка поисковика для сводок: 1, 0, -1 или None (см. Verifier.status). dns — {адрес: (семья, ok, имя)}."""
    if fam in r.se_nets and ip in r.se_nets[fam]:
        return 1
    v = dns.get(ip)
    if v and v[0] == fam:
        return dns_verdict(r, fam, v[1], v[2])
    return None


def signs(a, rdns='', se=None):
    """-> (за бота, за человека: сильные, слабые). se — проверка поисковика (se_state)."""
    bot, strong, weak = [], [], []
    browsers = [u for u, n in a['puas'].items() if n <= 20]
    if a['cls'] == 'se' and se != 1:
        bot.append('назвался поисковиком (%s), %s' % (a['fam'], {
            0: 'DNS это не подтвердил',
            -1: 'у адреса нет имени в DNS и он не из сетей поисковика — проверить нечем'}.get(se, 'DNS ещё не проверен')))
    elif a['cls'] == 'ai':
        weak.append('ИИ-бот %s' % a['fam'])
    if a['pages'] >= 10 and a['st'] == 0:
        bot.append('%d страниц, картинок и стилей 0' % a['pages'])
    if a['pages'] >= 10 and a['js'] == 0 and a['ty'] == 0 and a['post'] == 0:
        bot.append('скрипты страницы не работали (ни AJAX, ни POST)')
    if a['head']:
        bot.append('HEAD-запросов %d' % a['head'])
    if a['probe']:
        bot.append('проб уязвимостей %d%s' % (a['probe'], ', из них SQL-инъекций %d' % a['sqli'] if a['sqli'] else ''))
    if a['cls'] in ('bot', 'empty'):
        bot.append('имя программы' if a['cls'] == 'bot' else 'без имени браузера')
    if a['rf'] >= 10:
        bot.append('отказов 403/429 от сайта: %d' % a['rf'])
    if len(a['hours']) >= 12:
        bot.append('активен %d часов из суток' % len(a['hours']))
    if rdns and HOSTING_RDNS.search(rdns):
        bot.append('адрес хостинга (%s)' % rdns)
    if a['se']:
        strong.append('пришёл из поиска %d раз' % a['se'])
    if len(browsers) >= 3:
        strong.append('разных браузеров с малым числом запросов: %d' % len(browsers))
    if a['ty']:
        strong.append('набирал текст (подсказки: %d)' % a['ty'])
    if a['js']:
        weak.append('скрипты страницы работали (%d)' % a['js'])
    if a['st']:
        weak.append('грузил картинки и стили (%d)' % a['st'])
    if a['post']:
        weak.append('POST %d' % a['post'])
    if rdns and HOME_RDNS.search(rdns):
        weak.append('домашний или мобильный адрес (%s) — навсегда не закрывать' % rdns)
    return bot, strong, weak


def hint(a, bot, strong, se=None):
    if a['cls'] == 'se' and se == 1:
        return 'настоящий поисковик — не трогать'
    if a['probe'] >= 3 or a['sqli']:
        return 'сканер — закрыть'
    if a['cls'] == 'se' and se == -1:
        return 'неясно: поисковик без имени в DNS — сверить сеть по whois, прежде чем закрывать'
    if strong:
        return 'похоже, человек — не трогать' if len(bot) < 3 else 'неясно: есть признаки человека — смотреть --who'
    if len(bot) >= 2:
        return 'похоже, бот — кандидат в бан'
    return 'неясно — смотреть --who'


def cmd_daily(s, hours):
    r = Rules(s)
    store = Store(s.state_dir)
    parser = LogParser(s)
    t = now()
    since = t - hours * 3600
    allow = load_allow(s)
    out = []
    w = out.append
    mode = s.mode()
    # 1. жив ли сторож
    last_tick = int(store.meta('last_tick', 0) or 0)
    ticks = store.q('SELECT SUM(n) FROM ticks WHERE h >= ?', (since // 3600,)).fetchone()[0] or 0
    errors = store.q("SELECT COUNT(*) FROM alert_log WHERE ts >= ? AND subject LIKE '%ошибка в сторож%'", (since,)).fetchone()[0]
    queue = store.q('SELECT COUNT(*) FROM mail_queue').fetchone()[0]
    alive = last_tick and t - last_tick < 300
    # 2. письма
    letters = store.q('SELECT ts, subject, sent FROM alert_log WHERE ts >= ? ORDER BY ts', (since,)).fetchall()
    # 3. баны
    bl = store.q('SELECT ip, rule, ts, until, enforced, detail, hits FROM ban_log WHERE ts >= ? ORDER BY ts', (since,)).fetchall()
    by_rule = collections.Counter((b[1], b[4]) for b in bl)
    active_bans = {row[0]: row for row in store.q('SELECT ip, rule, kind, since, until, hits, note FROM bans WHERE until > ?', (t,))}
    rl = store.q('SELECT ts, ip, rule, verdict, action, evidence FROM review_log WHERE ts >= ? ORDER BY ts', (since,)).fetchall()
    # 4. журнал
    real_bans = {ip: row[3] for ip, row in active_bans.items() if row[2] > 0}
    A = aggregate(s, r, parser, since, after=real_bans)
    dns = {row[0]: (row[1], row[2], row[3]) for row in store.q('SELECT ip, fam, ok, host FROM dns')}
    dns_ok = {ip for ip, v in dns.items() if v[1] == 1}
    # вернулись к бану — запросы после начала бана; обычный ответ (200/304) после бана — бан не дошёл до nginx
    returned = [(ip, a) for ip, a in A.items() if ip in real_bans and a['after_codes']]
    leaking = [(ip, a) for ip, a in returned if a['after_codes'].get(200, 0) + a['after_codes'].get(304, 0) > 0]
    pool = []
    for ip, a in A.items():
        if ip in allow or ip in dns_ok or ip in real_bans or (a['cls'] == 'se' and se_state(r, dns, ip, a['fam']) == 1):
            continue
        if a['pages'] >= 20 or a['probe'] or a['head'] >= 5 or a['rf'] >= 10 or a['req'] >= 500:
            pool.append((ip, a))
    pool.sort(key=lambda x: -(x[1]['pages'] * 3 + x[1]['req'] + x[1]['probe'] * 50))
    pool = pool[:40]
    rd = rdns_many([ip for ip, _ in pool], wait=4.0) if pool else {}
    cands, people = [], []
    for ip, a in pool:
        se = se_state(r, dns, ip, a['fam'])
        bot, strong, weak = signs(a, rd.get(ip, ''), se)
        (people if hint(a, bot, strong, se).startswith('похоже, человек') else cands).append((ip, a))
    cands, people = cands[:15], people[:10]
    bots = collections.Counter()
    bot_ips = collections.defaultdict(set)
    for ip, a in A.items():
        if a['cls'] in ('bot', 'empty'):
            for u, n in a['uas'].items():
                c = r.ua_class(u)[0]
                if c in ('bot', 'empty'):
                    bots[u] += n
                    bot_ips[u].add(ip)
    today = day_key(t)
    new_names = []
    first_run = store.q('SELECT COUNT(*) FROM ua_seen').fetchone()[0] == 0   # в первый раз «новое» не помечаем
    for u, n in bots.most_common(30):
        row = store.q('SELECT first_day FROM ua_seen WHERE ua=?', (u,)).fetchone()
        if row:
            store.q('UPDATE ua_seen SET last_day=? WHERE ua=?', (today, u))
        else:
            store.q('INSERT INTO ua_seen VALUES(?,?,?)', (u, today, today))
        if not first_run and (not row or row[0] == today):
            new_names.append(u)
    store.commit()
    # поисковики: за период по журналу (подтверждённые DNS адреса), в пересчёте на сутки — против средних суток прошлой недели
    se_now = collections.Counter()
    se_prev = collections.Counter()
    days_prev = [day_key(t - i * 86400) for i in range(1, 8)]
    for ip, a in A.items():
        if a['cls'] == 'se' and ip in dns_ok:
            se_now[a['fam']] += a['req'] * 24.0 / hours
    for k, v in store.q('SELECT key, SUM(val) FROM daily WHERE day IN (%s) GROUP BY key' % ','.join('?' * 7), days_prev):
        if k.startswith('se:') and k.endswith(':ok'):
            se_prev[k.split(':')[1]] += v / 7.0

    # --- Коротко
    scan_n = sum(n for (rule, enf), n in by_rule.items() if rule == 'scan')
    real_n = sum(n for (rule, enf), n in by_rule.items() if enf)
    would = [b for b in bl if not b[4]]
    likely = []
    for ip, a in cands:
        se = se_state(r, dns, ip, a['fam'])
        if hint(a, *signs(a, rd.get(ip, ''), se)[:2], se=se).startswith(('похоже, бот', 'сканер')):
            likely.append((ip, a))
    short = []
    if not last_tick:
        short.append('Сторож ещё ни разу не работал (нет проходов) — проверить cron.')
    elif not alive:
        short.append('ВНИМАНИЕ: последний проход сторожа %s — %d мин назад; проверить cron.' % (hm(last_tick), (t - last_tick) // 60))
    else:
        short.append('Сторож работает (режим %s, последний проход %s%s).' % (mode, hm(last_tick),
                                                                            ', ошибок %d' % errors if errors else ''))
    short.append('За %d ч закрыто по-настоящему: %d (сканеров %d); «закрыл бы»: %d.' % (hours, real_n, scan_n, len(would)))
    if likely:
        short.append('Похожих на ботов без бана: %d — список ниже, решение за вами.' % len(likely))
    else:
        short.append('Явных ботов без бана в журнале не видно.')
    if leaking:
        short.append('ВНИМАНИЕ: закрытые адреса получают обычные ответы (%d) — баны не доходят до nginx.' % len(leaking))
    for f, avg in se_prev.items():
        if avg >= 50 and se_now[f] < avg * 0.3 and hours >= 24:
            short.append('ВНИМАНИЕ: робот %s за период — ~%d в сутки, обычно ~%d — проверить, не режем ли его.'
                         % (f, se_now[f], avg))
    w('AntiBot %s · %s · сводка за %d ч (с %s)' % (VERSION, s.domain, hours, hm(since)))
    w('')
    w('Коротко: ' + ' '.join(short))
    w('')
    w('1. Сторож: режим %s; проходов за период %s (норма — раз в минуту); последний %s; очередь писем %d; правила %s.'
      % (mode, fmt(ticks), hm(last_tick) if last_tick else '—', queue, r.version))
    w('')
    w('2. Письма (%d):' % len(letters))
    for ts, subj, sent in letters:
        w('   %s  %s%s' % (hm(ts), subj, '' if sent else '  (не отправлено)'))
    w('')
    w('3. Баны за период: ' + (', '.join('%s %s — %d' % (RULE_NAMES.get(rule, rule), 'закрыл' if enf else 'закрыл бы', n)
                                      for (rule, enf), n in sorted(by_rule.items())) or 'нет'))
    for ip, rule, ts, until, enf, det, hits in bl:
        d = json.loads(det or '{}')
        if rule == 'scan':
            w('   %s  %-15s сканер, до %s, отказов после %d · %s' % (hm(ts), ip, hm(until), hits, d.get('ua', '')[:60]))
        else:
            w('   %s  %-15s %s%s: страниц %s, картинок %s, скриптов %s, POST %s, HEAD %s · %s'
              % (hm(ts), ip, RULE_NAMES.get(rule, rule), '' if enf else ' (закрыл бы)', d.get('pages_60', '?'),
                 d.get('static_60', '?'), d.get('js_60', '?'), d.get('post_60', '?'), d.get('head_60', '?'),
                 d.get('ua', '')[:60]))
    w('   Действует банов: %d (из них «закрыл бы» — %d).' % (len(active_bans), sum(1 for v in active_bans.values() if not v[2])))
    if returned:
        w('   Вернулись к бану (запросов после бана, коды): ' + ', '.join(
            '%s (%d, %s)' % (ip, sum(a['after_codes'].values()), dict(a['after_codes'].most_common(3)))
            for ip, a in sorted(returned, key=lambda x: -sum(x[1]['after_codes'].values()))[:10]))
    for ip, a in leaking[:10]:
        w('   ВНИМАНИЕ: %s закрыт, но получил после бана обычные ответы: %s' % (ip, dict(a['after_codes'].most_common(4))))
    w('')
    w('4. Кандидаты в бан — из журнала, без бана (сильные признаки человека: пришёл из поиска, несколько браузеров, '
      'набирал текст; картинки и скрипты — слабые, боты в браузере делают и это):')
    if not cands:
        w('   нет')
    for i, (ip, a) in enumerate(cands, 1):
        rdns = rd.get(ip, '')
        se = se_state(r, dns, ip, a['fam'])
        bot, strong, weak = signs(a, rdns, se)
        ua = a['uas'].most_common(1)[0][0] if a['uas'] else ''
        w('   %d) %s%s — запросов %s, страниц %s (товаров %s), часов %d · %s'
          % (i, ip, ' (' + rdns + ')' if rdns else '', fmt(a['req']), fmt(a['pages']), fmt(a['prod']), len(a['hours']),
             ua[:70]))
        if bot:
            w('      за бота: ' + '; '.join(bot))
        if strong or weak:
            w('      за человека: ' + '; '.join(strong + weak))
        w('      вывод: %s. Разбор: antibot --who %s' % (hint(a, bot, strong, se), ip))
    if people:
        w('   Активные, похожие на людей — не трогать (для сведения):')
        for ip, a in people:
            bot, strong, weak = signs(a, rd.get(ip, ''), se_state(r, dns, ip, a['fam']))
            w('     %-16s страниц %s, запросов %s · %s' % (ip, fmt(a['pages']), fmt(a['req']), '; '.join(strong)))
    w('')
    w('5. Работа над ошибками (%d):' % len(rl))
    for ts, ip, rule, verdict, action, ev in rl:
        w('   %s  %-15s %-18s %-36s %s · %s' % (hm(ts), ip, RULE_NAMES.get(rule, rule or '—')[:18],
                                             RV_NAMES.get(verdict, verdict), action or '—', (ev or '')[:120]))
    w('')
    ref_all = collections.Counter()
    for ip, a in A.items():
        if a['rf']:
            ref_all[ip] = a['rf']
    w('6. Отказы сайта 403/429 по адресам (не наши баны): ' + (', '.join('%s — %d' % kv for kv in ref_all.most_common(10)
                                                                       if kv[0] not in active_bans) or 'нет'))
    w('')
    w('7. Программы и роботы без имени поисковика (запросов / адресов):')
    for u, n in bots.most_common(12):
        w('   %6s / %-4d %s%s' % (fmt(n), len(bot_ips[u]), u[:90] or '(пусто)', '  ← новое' if u in new_names else ''))
    if not bots:
        w('   нет')
    w('')
    w('8. Поисковики, подтверждённые по DNS, запросов в сутки — за период / в среднем за прошлую неделю: ' +
      (', '.join('%s %d / %d' % (f, se_now[f], se_prev[f]) for f in sorted(set(se_now) | set(se_prev))) or 'данных пока нет'))
    w('')
    w('Команды: antibot --who АДРЕС · --ban АДРЕС ЧАСОВ "причина" · --unban АДРЕС · --allow АДРЕС "кто это" · '
      '--block-ua "точное имя"')
    print('\n'.join(out))


def cmd_who(s, ip, hours):
    if not valid_ip(ip):
        raise SystemExit('не адрес: ' + ip)
    r = Rules(s)
    store = Store(s.state_dir)
    parser = LogParser(s)
    t = now()
    since = t - hours * 3600
    hourly = collections.OrderedDict()
    for p in scan_logs(s, parser, since, ip):
        hh = p[1] // 60
        if hh not in hourly:
            hourly[hh] = []
        hourly[hh].append(p)
    A = aggregate(s, r, parser, since, ip)
    a = A.get(ip)
    rd = rdns_many([ip], wait=4.0).get(ip, '')
    print('Адрес %s%s — за %d ч' % (ip, ' (' + rd + ')' if rd else ' (имени в DNS нет)', hours))
    allow = load_allow(s)
    if ip in allow:
        print('В белом списке.')
    if ip in r.cdn:
        print('Адрес CDN Cloudflare.')
    b = store.q('SELECT rule, kind, since, until, hits, note FROM bans WHERE ip=? AND until > ?', (ip, t)).fetchone()
    if b:
        print('Бан сейчас: %s, %s, с %s до %s, отказов %d' % (RULE_NAMES.get(b[0], b[0]), 'действует' if b[1] else '«закрыл бы»',
                                                           hm(b[2]), hm(b[3]), b[4]))
    for row in store.q('SELECT ts, rule, until, enforced FROM ban_log WHERE ip=? ORDER BY ts DESC LIMIT 10', (ip,)):
        print('  бан %s %s до %s%s' % (hm(row[0]), RULE_NAMES.get(row[1], row[1]), hm(row[2]), '' if row[3] else ' (закрыл бы)'))
    for row in store.q('SELECT ts, verdict, action, evidence FROM review_log WHERE ip=? ORDER BY ts DESC LIMIT 5', (ip,)):
        print('  проверка %s: %s, %s · %s' % (hm(row[0]), RV_NAMES.get(row[1], row[1]), row[2] or '—', (row[3] or '')[:150]))
    if not a:
        print('В журнале за период запросов нет.')
        return
    se = None
    if a['cls'] == 'se':
        dns = {row[0]: (row[1], row[2], row[3]) for row in store.q('SELECT ip, fam, ok, host FROM dns WHERE ip=?', (ip,))}
        se = se_state(r, dns, ip, a['fam'])
        if se is None and r.se_domains.get(a['fam']):
            out = {}
            _rdns_check(ip, r.se_domains[a['fam']], out)
            if ip in out:
                se = dns_verdict(r, a['fam'], out[ip][0], out[ip][1])
        if se == 1:
            print('Настоящий поисковик %s: %s.' % (a['fam'], 'адрес из его сети' if a['fam'] in r.se_nets
                                                  and ip in r.se_nets[a['fam']] else 'DNS подтвердил'))
    bot, strong, weak = signs(a, rd, se)
    print('Всего: запросов %s, страниц %s (товаров %s), картинок/стилей %d, скриптов %d, подсказок %d, POST %d, HEAD %d, '
          'проб %d, отказов 403/429 %d, из поиска %d' % (fmt(a['req']), fmt(a['pages']), fmt(a['prod']), a['st'], a['js'],
                                                        a['ty'], a['post'], a['head'], a['probe'], a['rf'], a['se']))
    print('Коды: ' + ', '.join('%s — %d' % kv for kv in a['codes'].most_common()))
    print('За бота: ' + ('; '.join(bot) or '—'))
    print('За человека: ' + ('; '.join(strong + weak) or '—'))
    print('Вывод: ' + hint(a, bot, strong, se))
    print('Браузеры (UA):')
    for u, n in a['uas'].most_common(8):
        print('  %6d  %s' % (n, u[:150]))
    if a['refs']:
        print('Откуда приходил: ' + ', '.join('%s — %d' % kv for kv in a['refs'].most_common(8)))
    print('Что запрашивал чаще всего:')
    for u, n in a['paths'].most_common(12):
        print('  %6d  %s' % (n, u))
    print('По часам: запросов / страниц / картинок / скриптов / POST / HEAD / проб / отказов · коды')
    for hh, rows in hourly.items():
        c = collections.Counter(x[4] for x in rows)
        pg = st_ = js = po = he = pr = rf = 0
        for x in rows:
            path = x[3].split('?', 1)[0]
            if r.is_static(path):
                st_ += 1
                continue
            if r.probe_hit(path, x[3]) or r.is_sqli(x[3]):
                pr += 1
            if x[2] == 'POST':
                po += 1
            elif r.js and r.js.search(x[3]):
                js += 1
            elif x[2] == 'HEAD':
                he += 1
            elif r.is_page(path, x[3], False):
                pg += 1
            if x[4] in (403, 429):
                rf += 1
        print('  %s  %5d / %4d / %4d / %4d / %3d / %3d / %3d / %3d · %s'
              % (time.strftime('%d.%m %H:00', time.localtime(hh * 3600)), len(rows), pg, st_, js, po, he, pr, rf,
                 dict(c.most_common(4))))


def cmd_block_ua(s, ua, force):
    """Бан по точному имени браузера: сначала — кто под этим именем за сутки и нет ли среди них людей."""
    r = Rules(s)
    store = Store(s.state_dir)
    parser = LogParser(s)
    nginx_quote(ua)
    t = now()
    ips = collections.Counter()
    human = set()
    for p in scan_logs(s, parser, t - 86400):
        if p[7] != ua:
            continue
        ips[p[0]] += 1
        path = p[3].split('?', 1)[0]
        if r.typing and r.typing.search(p[3]):
            human.add(p[0])
        if r.se_ref and r.se_ref.match(p[6]) and r.is_page(path, p[3], r.is_static(path)):
            human.add(p[0])
    print('Имя «%s»: за сутки %d адресов, %s запросов.' % (ua, len(ips), fmt(sum(ips.values()))))
    if human:
        print('Признаки человека (набирал текст или пришёл из поиска) у %d адресов: %s'
              % (len(human), ', '.join(sorted(human)[:10])))
        if not force:
            raise SystemExit('Не закрыто: под этим именем, похоже, ходят люди. Разберите адреса (--who); закрыть '
                             'всё равно — добавьте --force.')
    store.q('INSERT OR REPLACE INTO ua_bans VALUES(?,?,?)', (ua, t, 'вручную'))
    store.commit()
    render_nginx(s, store, Mailer(s, store), force=True)
    print('закрыто имя браузера' + ('' if s.nginx_dir and os.path.isdir(s.nginx_dir) else ' (nginx ещё не подключён: '
                                                                                         'antibot --nginx-files)'))


def cmd_unblock_ua(s, ua):
    store = Store(s.state_dir)
    n = store.q('DELETE FROM ua_bans WHERE ua=?', (ua,)).rowcount
    store.commit()
    render_nginx(s, store, Mailer(s, store), force=True)
    print('снято' if n else 'такого имени в списке нет')


# ---------------------------------------------------------------- ручные команды
def cmd_manual(s, args):
    store = Store(s.state_dir)
    cmd, ip = args[0], args[1]
    if not valid_ip(ip):
        raise SystemExit('не адрес: %s (баны — только по одному адресу)' % ip)
    t = now()
    if cmd in ('--unban', '--allow'):
        store.q('DELETE FROM bans WHERE ip=?', (ip,))
        store.q("UPDATE review SET verdict='manual' WHERE ip=? AND verdict IS NULL", (ip,))
        store.q('INSERT INTO review_log(ts, ip, rule, verdict, action, evidence) VALUES(?,?,?,?,?,?)',
                (t, ip, '', 'manual', 'снят вручную', ' '.join(args[2:])))
        if cmd == '--allow':
            allow_add(s, ip, ' '.join(args[2:]) or time.strftime('добавлен %d.%m.%Y'))
        print('снято' + (' и добавлено в белый список' if cmd == '--allow' else ''))
    else:
        if len(args) < 3:
            raise SystemExit('--ban АДРЕС ЧАСОВ [причина]')
        if ip in load_allow(s):
            raise SystemExit('адрес в белом списке (свой сервер, частная сеть или allow) — не закрываю')
        hours = float(args[2])
        until = do_ban(s, store, ip, 'manual', {'ua': ' '.join(args[3:]) or 'вручную'}, hours)
        print('закрыт до %s' % time.strftime('%d.%m.%Y %H:%M', time.localtime(until)))
    store.commit()
    render_nginx(s, store, Mailer(s, store), force=True)


def cmd_mode(s, m):
    if m not in ('observe', 'enforce', 'report'):
        raise SystemExit('режим: observe, enforce или report')
    os.makedirs(s.etc_dir, exist_ok=True)
    with open(os.path.join(s.etc_dir, 'mode'), 'w', encoding='utf-8') as f:
        f.write(m + '\n')
    store = Store(s.state_dir)
    if m == 'enforce':                                       # «закрыл бы» становятся настоящими банами
        store.q('UPDATE bans SET kind=1 WHERE kind=0 AND until > ?', (now(),))
        store.commit()
    render_nginx(s, store, Mailer(s, store), force=True)
    print('режим: ' + m)


def cmd_report(s):
    store = Store(s.state_dir)
    t = now()
    print('AntiBot %s · %s · режим %s' % (VERSION, s.domain, s.mode()))
    rows = store.q('SELECT rule, kind, COUNT(*) FROM bans WHERE until > ? GROUP BY rule, kind', (t,)).fetchall()
    print('Действующие баны:', ', '.join('%s %s %d' % (RULE_NAMES.get(r, r), 'закрыт' if k else 'закрыл бы', n)
                                         for r, k, n in rows) or 'нет')
    for ip, rule, until, hits, note in store.q(
            'SELECT ip, rule, until, hits, note FROM bans WHERE until > ? ORDER BY hits DESC LIMIT 20', (t,)):
        print('  %-16s %-10s до %s отказов %6d %s' % (ip, rule, hm(until), hits, (note or '')[:50]))
    print('Закрытые имена браузеров:', ', '.join(r[0][:60] for r in store.q('SELECT ua FROM ua_bans')) or 'нет')
    print('Последний проход:', hm(int(store.meta('last_tick', 0) or 0)) if store.meta('last_tick') else '—')


def cmd_weekly(s):
    store = Store(s.state_dir)
    mailer = Mailer(s, store)
    t = now()
    t0 = t - 7 * 86400
    d0, d1 = time.strftime('%d.%m', time.localtime(t0)), time.strftime('%d.%m', time.localtime(t))
    days = [day_key(t - i * 86400) for i in range(7)]
    prev_days = [day_key(t - i * 86400) for i in range(7, 14)]
    daily = collections.Counter()
    prev = collections.Counter()
    for k, v in store.q('SELECT key, SUM(val) FROM daily WHERE day IN (%s) GROUP BY key' % ','.join('?' * 7), days):
        daily[k] = v
    for k, v in store.q('SELECT key, SUM(val) FROM daily WHERE day IN (%s) GROUP BY key' % ','.join('?' * 7), prev_days):
        prev[k] = v
    bl = store.q('SELECT ip, rule, enforced, detail, hits FROM ban_log WHERE ts > ?', (t0,)).fetchall()
    mode = s.mode()
    real = collections.Counter(b[1] for b in bl if b[2])
    would = collections.Counter(b[1] for b in bl if not b[2])
    top = sorted(bl, key=lambda b: -(json.loads(b[3] or '{}').get('dyn_60', 0) + b[4]))[:10]
    nets = collections.Counter(net_of(b[0]) for b in bl if b[1] in ('parser', 'headless', 'pagination', 'head'))
    al = store.q("SELECT subject, sent FROM alert_log WHERE ts > ? AND subject NOT LIKE '%сводка за неделю%'", (t0,)).fetchall()
    rl = store.q('SELECT verdict, action, COUNT(*) FROM review_log WHERE ts > ? GROUP BY verdict, action', (t0,)).fetchall()
    rv_bad = sum(n for v, a, n in rl if v in ('good-bot', 'human', 'shared', 'typing'))
    parts = ['Коротко: за неделю %s–%s сторож закрыл %d адресов' % (d0, d1, sum(real.values()))]
    if real:
        parts[0] += ' (' + ', '.join('%s — %d' % (RULE_NAMES.get(r, r), n) for r, n in real.most_common()) + ')'
    parts[0] += '.'
    if would:
        parts.append('«Закрыл бы» (наблюдение, решение за вами): %d — %s.' % (
            sum(would.values()), ', '.join('%s — %d' % (RULE_NAMES.get(r, r), n) for r, n in would.most_common())))
    parts.append('Работа над ошибками: %s.' % ('%d адресов, похоже, закрыты зря — письма были' % rv_bad if rv_bad
                                              else 'адресов, закрытых зря, не найдено'))
    for f in ('yandex', 'google'):
        a, b = daily['se:%s:ok' % f], prev['se:%s:ok' % f]
        if b and a < b * 0.7:
            parts.append('ВНИМАНИЕ: робот %s за неделю пришёл %s раз против %s неделей раньше — проверить, не режем ли его.'
                         % (f, fmt(a), fmt(b)))
    parts.append('Тревог за неделю: %d.' % len(al) if al else 'Тревог не было.')
    body = [' '.join(parts), '', 'Режим: %s. Запросов за неделю: %s, динамических: %s.' % (mode, fmt(daily['req']), fmt(daily['dyn'])), '']
    if top:
        body.append('Самые тяжёлые (запросов за час до бана / отбито после):')
        for ip, rule, enf, det, hits in top:
            d = json.loads(det or '{}')
            body.append('  %-16s %-24s %6s / %7s  %s' % (ip, RULE_NAMES.get(rule, rule), fmt(d.get('dyn_60', 0)), fmt(hits),
                                                        d.get('ua', '')[:50]))
        body.append('')
    if nets:
        body.append('Сети парсеров (адресов): ' + ', '.join('%s — %d' % kv for kv in nets.most_common(12)))
        body.append('')
    body.append('Поисковики, подтверждённые DNS (эта неделя / прошлая): ' + ', '.join(
        '%s %s / %s' % (f, fmt(daily['se:%s:ok' % f]), fmt(prev['se:%s:ok' % f])) for f in ('yandex', 'google', 'bing')))
    body.append('')
    if rl:
        body.append('Работа над ошибками за неделю:')
        body += ['  %-40s %-12s %d' % (RV_NAMES.get(v, v), a or '—', n) for v, a, n in sorted(rl, key=lambda x: -x[2])]
        body += ['  ' + h for h in review_rule_hints(store)]
        body.append('')
    if al:
        body.append('Тревоги:')
        body += ['  %s%s' % (subj, '' if ok else ' (не отправлена)') for subj, ok in al]
        body.append('')
    body.append('Подробно за сутки — «antibot --daily» на сервере. Снять бан: antibot --unban АДРЕС; в белый список: '
                'antibot --allow АДРЕС "кто это".')
    mailer.send('сводка за неделю %s–%s' % (d0, d1), '\n'.join(body), summary=True)


def cmd_check_config(s):
    r = Rules(s)
    parser = LogParser(s)
    print('Настройки: %s\nПравила: %s (версия %s)\nСайт: %s, движок: %s, режим: %s' % (
        s.path, s.rules_path, r.version, s.domain, s.engine, s.mode()))
    print('Журнал: %s (%s)' % (s.log, s.log_format))
    print('База: %s; nginx: %s' % (s.state_dir, s.nginx_dir or '—'))
    if s.nginx_dir and s.nginx_dump:
        code, out = run(s.nginx_dump)
        if code == 0:
            print('nginx: %s — %s; страница бана в сайте — %s' % (
                s.nginx_http_conf, 'подключён' if '# configuration file %s:' % s.nginx_http_conf in out else
                'НЕ подключён: nginx не читает этот файл, укажите в [paths] nginx_http_conf папку, которую он подключает',
                'подключена' if '/__antibot-banned' in out else 'не подключена'))
    print('Почта: %s → %s%s' % (s.mail['method'] or ('smtp' if s.mail['smtp_host'] else 'sendmail'), s.mail['to'] or '(нет адреса!)',
                                 ', копия сводки: ' + s.mail['copy_to'] if s.mail['copy_to'] else ''))
    try:
        size = os.path.getsize(s.log)
        with open(s.log, 'rb') as f:
            f.seek(max(0, size - (2 << 20)))
            tail = f.read().decode('utf-8', 'replace').splitlines()[1:][-5000:]
    except OSError as e:
        print('журнал не читается:', e)
        return
    ok = 0
    k = collections.Counter()
    for line in tail:
        p = parser.parse(line)
        if not p:
            continue
        ok += 1
        ip, minute, meth, url, st, size_, ref, ua = p
        path = url.split('?', 1)[0]
        if r.is_static(path):
            k['статика'] += 1
        elif r.probe_hit(path, url) or r.is_sqli(url):
            k['пробы'] += 1
        elif r.js and r.js.search(url):
            k['скрипты страницы'] += 1
        elif r.product and r.product.search(url):
            k['товар'] += 1
        elif r.catalog and r.catalog.search(url):
            k['раздел'] += 1
        elif r.search and r.search.search(url):
            k['поиск'] += 1
        elif r.is_page(path, url, False):
            k['обычные страницы'] += 1
        else:
            k['прочее'] += 1
        k['класс ' + r.ua_class(ua)[0]] += 1
    print('Последние %d строк журнала: разобрано %d (%d %%).' % (len(tail), ok, 100 * ok // max(len(tail), 1)))
    for name, n in k.most_common():
        print('  %-22s %6d  %3d %%' % (name, n, 100 * n // max(ok, 1)))
    if ok and not k['статика']:
        print('Статики в журнале нет: если картинки отдаёт CDN или другой домен, правила «без картинок» будут ловить '
              'людей — поднимите parser_products или задайте признак скриптов (patterns js).')


# ---------------------------------------------------------------- вход
def main():
    # cron часто запускает с LANG=C: на Python 3.6 вывод по-русски тогда падает — пишем в UTF-8 явно
    if (getattr(sys.stdout, 'encoding', '') or '').lower().replace('-', '') != 'utf8' and hasattr(sys.stdout, 'buffer'):
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        return
    if args[0] == '--version':
        print('AntiBot', VERSION)
        return
    conf = DEFAULT_CONFIG
    state = None
    rest = []
    i = 0
    while i < len(args):
        if args[i] == '--config' and i + 1 < len(args):
            conf = args[i + 1]
            i += 2
        elif args[i] == '--state' and i + 1 < len(args):
            state = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1
    args = rest
    cmd = args[0] if args else ''
    # Через sudo (учётка агента) — только боевые настройки: свой файл настроек задаёт команды nginx, а они
    # выполняются от root. Проверка правил по старым журналам — без sudo, от своей учётки.
    if os.environ.get('SUDO_USER') and hasattr(os, 'geteuid') and os.geteuid() == 0 and \
            (conf != DEFAULT_CONFIG or state or cmd in ('--replay', '--nginx-files')):
        raise SystemExit('через sudo нельзя --config, --state, --replay и --nginx-files — запустите от root')
    if cmd == '--replay' and not state:
        raise SystemExit('--replay только с --state ПАПКА — чтобы не смешать с боевой базой')
    s = Settings(conf if os.path.exists(conf) or cmd != '--replay' else None, state)
    if cmd != '--replay' and not os.path.exists(conf):
        raise SystemExit('нет файла настроек %s (пример — antibot.example.ini)' % conf)
    os.makedirs(s.state_dir, exist_ok=True)
    lock = open(os.path.join(s.state_dir, 'lock'), 'w')
    # только читающие команды не ждут прохода и не задерживают его
    if fcntl and cmd not in ('--daily', '--who', '--report', '--check-config'):
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if cmd == '--tick' else 0))
        except (BlockingIOError, OSError):
            return                                          # прошлый проход ещё идёт
    try:
        if cmd == '--tick':
            cmd_tick(s)
        elif cmd == '--daily':
            cmd_daily(s, int(args[1]) if len(args) > 1 else 24)
        elif cmd == '--who' and len(args) > 1:
            cmd_who(s, args[1], int(args[2]) if len(args) > 2 else 24)
        elif cmd in ('--ban', '--unban', '--allow') and len(args) > 1:
            cmd_manual(s, args)
        elif cmd == '--block-ua' and len(args) > 1:
            cmd_block_ua(s, args[1], '--force' in args[2:])
        elif cmd == '--unblock-ua' and len(args) > 1:
            cmd_unblock_ua(s, args[1])
        elif cmd == '--mode' and len(args) > 1:
            cmd_mode(s, args[1])
        elif cmd == '--report':
            cmd_report(s)
        elif cmd == '--weekly':
            cmd_weekly(s)
        elif cmd == '--replay':
            cmd_replay(s, args[1:])
        elif cmd == '--check-config':
            cmd_check_config(s)
        elif cmd == '--nginx-files':
            store = Store(s.state_dir)
            nginx_files(s, store, Mailer(s, store))
        elif cmd == '--test-mail':
            store = Store(s.state_dir)
            ok = Mailer(s, store).send('пробное письмо', 'Коротко: это проверка почты сторожа AntiBot. Делать ничего не нужно.')
            print('отправлено' if ok else 'не отправлено — см. сообщение выше')
        else:
            print(__doc__)
            sys.exit(2)
    except SystemExit:
        raise
    except Exception:
        tb = traceback.format_exc()
        log(tb)
        if cmd == '--tick':
            try:
                store = Store(s.state_dir)
                Mailer(s, store).send('ошибка в стороже',
                                      'Коротко: сторож упал с ошибкой. Сайт работает, уже закрытые адреса остаются '
                                      'закрытыми, новые не закрываются, пока ошибку не исправят.\n\n' + tb,
                                      key='crash', repeat_h=6)
            except Exception:
                pass
        sys.exit(1)


if __name__ == '__main__':
    main()
