"""Проверки AntiBot на синтетике. Запуск: python -m unittest discover -s tests -v"""
import calendar
import contextlib
import io
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import antibot as ab  # noqa: E402
import make_log  # noqa: E402

# DNS без сети: настоящий Googlebot подтверждается, у остальных имени нет
FAKE_DNS = {'192.0.2.66': 'crawl-192-0-2-66.googlebot.com'}


def fake_rdns(ip, suffixes, out):
    host = FAKE_DNS.get(ip, '')
    out[ip] = (1 if host and suffixes and host.endswith(tuple(suffixes)) else 0, host)


ab._rdns_check = fake_rdns


def write_conf(d, engine='custom', extra=''):
    p = lambda *x: os.path.join(d, *x)
    text = '''[site]
domain = shop.example
log = {log}
log_archives = {log}.*
engine = {engine}
mode = observe
contact = support@shop.example
[mail]
to =
[features]
ai_lists = no
[paths]
state_dir = {state}
nginx_dir = {nginx}
nginx_http_conf = {http}
nginx_site_conf = {site}
nginx_test =
nginx_reload =
nginx_dump =
[thresholds]
warmup_min = 0
'''.format(log=p('access.log'), engine=engine, state=p('state'), nginx=p('nginx'), http=p('conf.d', 'antibot.conf'),
           site=p('snippets', 'antibot-site.conf')) + extra
    path = p('antibot.ini')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    return path


def quiet(fn, *a):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*a)
    return buf.getvalue()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='antibot-test-')
        ab.CLOCK.fixed = None

    def tearDown(self):
        ab.CLOCK.fixed = None
        shutil.rmtree(self.d, ignore_errors=True)


class Patterns(Tmp):
    def rules(self, engine):
        return ab.Rules(ab.Settings(write_conf(self.d, engine)))

    def test_probes_custom(self):
        r = self.rules('custom')
        for u in ('/.env', '/.git/config', '/backup.zip', '/shop.sql.gz', '/phpinfo.php', '/wp-login.php',
                  '/blog/xmlrpc.php', '/wp-json/wp/v2/users', '/x/.aws/credentials', '/wordpress/',
                  '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/shop.zip', '/a/../../etc/passwd'):
            self.assertTrue(r.probe_hit(u.split('?')[0], u), u)
        for u in ('/', '/catalog/phones/', '/product/item-1', '/.well-known/acme-challenge/x', '/img/a.png',
                  '/search?q=iphone', '/blog/', '/wp-content/uploads/2020/a.jpg'):
            self.assertFalse(r.probe_hit(u.split('?')[0], u), u)
        self.assertTrue(r.probe_hit('/', '/?rest_route=/wp/v2/users'))

    def test_sqli(self):
        r = self.rules('custom')
        for u in ("/s/?q=ipad%27%20UNION%20SELECT%20NULL--%20-", "/p?id=1%20AND%20SLEEP(5)",
                  "/c?sort=1 ORDER BY 1000-- -", "/c?q=x') AND ('x'='x", "/c?q=1 AND EXTRACTVALUE(1,CONCAT(0x7e))",
                  "/c?q=1;DROP TABLE users"):
            self.assertTrue(r.is_sqli(u), u)
        for u in ('/s/?q=union jack select', '/s/?q=iphone 11 select', '/c?q=order by price',
                  "/s/?q=it's and others", '/c?q=from where to buy', '/c?page=2'):
            self.assertFalse(r.is_sqli(u), u)

    def test_woocommerce_own_paths(self):
        r = self.rules('woocommerce')
        for u in ('/wp-admin/admin-ajax.php', '/wp-json/wc/store/v1/cart', '/wp-login.php', '/xmlrpc.php',
                  '/?rest_route=/wc/store/v1/cart', '/wp-content/plugins/woo/a.js'):
            self.assertFalse(r.probe_hit(u.split('?')[0], u), u)
        self.assertTrue(r.probe_hit('/.env', '/.env'))
        self.assertTrue(r.probe_hit('/backup.sql', '/backup.sql'))
        self.assertTrue(r.is_product('/product/blue-case/', '/product/blue-case/'))
        self.assertEqual(r.page_number('/product-category/cases/page/9/'), 9)
        self.assertTrue(r.login.search('/wp-login.php'))
        # 0.2.2: признак браузера — корзина и оформление Store API, каталог Store API — нет (его выкачивают программы)
        for u in ('/wp-json/wc/store/v1/cart', '/wp-json/wc/store/v1/cart/add-item', '/wp-json/wc/store/checkout',
                  '/wp-json/wc/store/v1/batch', '/?wc-ajax=get_refreshed_fragments'):
            self.assertTrue(r.js.search(u), u)
        for u in ('/wp-json/wc/store/v1/products?per_page=100', '/wp-json/wc/store/products',
                  '/wp-json/wc/store/v1/products/categories'):
            self.assertFalse(r.js.search(u), u)
        for u in ('/product-category/cases/', '/shop/', '/shop/page/2/', '/catalog/iphone/displei/'):
            self.assertTrue(r.catalog.search(u), u)

    def test_check_config_catalog_hint(self):
        # 0.2.2: адреса каталога не совпали с шаблоном движка — проверка настроек подсказывает папку
        conf = write_conf(self.d, 'woocommerce')
        t0 = int(time.time()) - 3600
        with open(os.path.join(self.d, 'access.log'), 'w', encoding='utf-8') as f:
            for i in range(600):
                url = '/katalog/razdel-%d/' % (i % 40) if i % 3 else '/stati/%d/' % (i % 7)
                f.write(make_log.line('198.51.100.%d' % (i % 50 + 1), t0 + i, 'GET', url)[1] + '\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ab.cmd_check_config(ab.Settings(conf))
        self.assertIn('Каталога почти не видно', out.getvalue())
        self.assertIn('/katalog/', out.getvalue())

    def test_bitrix(self):
        r = self.rules('bitrix')
        for u in ('/local/templates/.default/style.css', '/bitrix/admin/', '/bitrix/components/x/.default/a.css',
                  '/upload/iblock/1/a.jpg'):
            self.assertFalse(r.probe_hit(u, u), u)
        self.assertTrue(r.probe_hit('/.git/HEAD', '/.git/HEAD'))
        self.assertTrue(r.probe_hit('/wp-login.php', '/wp-login.php'))
        self.assertEqual(r.page_number('/catalog/cases/?PAGEN_1=12'), 12)
        self.assertTrue(r.js.search('/catalog/?bxajaxid=abc'))

    def test_leak(self):
        r = self.rules('custom')
        for u in ('/.env', '/.env.local', '/.env.production', '/app/.env', '/.git/config', '/.git/HEAD', '/.htpasswd',
                  '/.aws/credentials', '/phpinfo.php', '/backup.zip', '/shop.sql.gz', '/config.php.bak'):
            self.assertTrue(r.leak.search(u), u)
        for u in ('/auth/.env/', '/.env/', '/.envrc', '/phpinfo.php/x', '/.git/config/', '/catalog/', '/info.php'):
            self.assertFalse(r.leak.search(u), u)
        self.assertIsNone(r.leak_exclude)
        # Битрикс отвечает 200 страницей входа на /bitrix/admin/* и на всё внутри /auth/
        b = self.rules('bitrix')
        for u in ('/bitrix/admin/phpinfo.php', '/auth/.env'):
            self.assertTrue(b.leak.search(u) and b.leak_exclude.search(u), u)
        self.assertFalse(b.leak_exclude.search('/.env'))
        # свои исключения: _extra добавляет к набору движка, ключ без _extra — заменяет набор
        add = ab.Rules(ab.Settings(write_conf(self.d, 'bitrix', '[patterns]\nleak_exclude_extra = ^/login/\n')))
        for u in ('/login/.env', '/auth/.env', '/bitrix/admin/phpinfo.php'):
            self.assertTrue(add.leak_exclude.search(u), u)
        own = ab.Rules(ab.Settings(write_conf(self.d, 'bitrix', '[patterns]\nleak_exclude = ^/login/\n')))
        self.assertTrue(own.leak_exclude.search('/login/.env'))
        self.assertFalse(own.leak_exclude.search('/auth/.env'))

    def test_nextjs(self):
        r = self.rules('nextjs')
        self.assertTrue(r.is_static('/_next/image'))
        self.assertTrue(r.is_static('/_next/static/chunks/a.js'))
        self.assertTrue(r.js.search('/catalog?_rsc=1abc'))
        self.assertFalse(self.rules('custom').is_static('/_next/image'))

    def test_ua_class(self):
        r = self.rules('custom')
        self.assertEqual(r.ua_class(make_log.GOOGLEBOT), ('se', 'google'))
        self.assertEqual(r.ua_class('Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'), ('se', 'yandex'))
        app = ('Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36 '
               'YaApp_Android/23.1 YaSearchBrowser/23.1')
        self.assertEqual(r.ua_class(app)[0], 'br')               # приложение Яндекса — человек
        self.assertEqual(r.ua_class('curl/8.5.0')[0], 'bot')
        self.assertEqual(r.ua_class('Mozilla/5.0 Claude-User/1.0'), ('ai', 'anthropic'))
        self.assertEqual(r.ua_class('-')[0], 'empty')

    def test_parse_formats(self):
        s = ab.Settings(write_conf(self.d))
        p = ab.LogParser(s)
        t = calendar.timegm((2026, 10, 10, 11, 39, 0))
        line = '203.0.113.1 - - [10/Oct/2026:14:39:01 +0300] "GET /a?b=1 HTTP/2.0" 200 512 "-" "curl/8.0"'
        self.assertEqual(p.parse(line), ('203.0.113.1', t // 60, 'GET', '/a?b=1', 200, '512', '-', 'curl/8.0'))
        docker = ('203.0.113.2 - - [26/Oct/2026:10:16:18 +0000] "GET / HTTP/1.1" 200 2221 "https://www.google.com/" '
                  '"Mozilla/5.0" "203.0.113.2" rt=0.025')
        self.assertEqual(p.parse(docker)[:5], ('203.0.113.2', calendar.timegm((2026, 10, 26, 10, 16, 0)) // 60, 'GET',
                                               '/', 200))
        c = ab.Settings(write_conf(self.d, extra='[x]\n'))
        c.log_format, c.time_format = 'custom', 'iso8601'
        c.log_regex = r'^(?P<time>\S+) (?P<ip>\S+) (?P<method>\S+) (?P<url>\S+) (?P<status>\d+) "(?P<ua>[^"]*)"'
        p2 = ab.LogParser(c)
        r2 = p2.parse('2026-10-10T14:39:01+03:00 2001:db8::5 GET /x 404 "Mozilla/5.0"')
        self.assertEqual(r2[0], '2001:db8::5')
        self.assertEqual(r2[1], t // 60)
        # BitrixVM: код ответа до запроса, в скобках с датой — время ответа (бывает «-» и список через запятую)
        b = ab.Settings(write_conf(self.d, extra='[x]\n'))
        b.log_format = 'bitrixvm'
        p3 = ab.LogParser(b)
        for urt in ('0.123', '-', '0.050, 0.120'):
            ln = ('203.0.113.1 - - [10/Oct/2026:14:39:01 +0300 - %s] 200 "GET /a?b=1 HTTP/1.1" 512 '
                  '"https://shop.example/" "curl/8.0" "-"' % urt)
            self.assertEqual(p3.parse(ln), ('203.0.113.1', t // 60, 'GET', '/a?b=1', 200, '512', 'https://shop.example/',
                                            'curl/8.0'), urt)
        self.assertTrue(p3.ip_first)
        self.assertIsNone(p3.parse(line))                 # строка combined в формате BitrixVM не разбирается

    def test_archives_default(self):
        s = ab.Settings(write_conf(self.d))               # в настройках прежнее значение: access.log.*
        self.assertEqual(s.log_archives, s.log + '[.-]*')
        for name in ('access.log', 'access.log.1', 'access.log.2.gz', 'access.log-20261028', 'access.log-20261027.gz'):
            open(os.path.join(self.d, name), 'w').close()
        found = {os.path.basename(f) for f in ab.log_files(s, 0)}
        self.assertEqual(found, {'access.log', 'access.log-20261028', 'access.log-20261027.gz', 'access.log.1',
                                 'access.log.2.gz'})

    def test_mailru_nets(self):
        r = self.rules('custom')
        st = ab.Store(os.path.join(self.d, 'st'))
        ver = ab.Verifier(ab.Settings(write_conf(self.d)), r, st)
        self.assertEqual(r.ua_class(make_log.MAILRU), ('se', 'mailru'))
        self.assertEqual(ver.status('95.163.33.18', 'se', 'mailru'), 1)        # сеть VK
        self.assertEqual(ver.status('217.174.191.100', 'se', 'mailru'), 1)
        ver.check([('198.51.100.30', 'mailru'), ('198.51.100.20', 'google')])
        self.assertEqual(ver.status('198.51.100.30', 'se', 'mailru'), -1)      # имени нет — проверить нечем
        self.assertTrue(ver.checked('198.51.100.30', 'mailru'))
        self.assertEqual(ver.status('198.51.100.20', 'se', 'google'), 0)       # Googlebot без имени — подделка
        self.assertEqual(ver.status('95.163.33.18', 'se', 'google'), None)     # сеть VK — только для Mail.ru
        self.assertTrue(ver.in_lists('95.163.33.18', make_log.MAILRU))
        self.assertFalse(ver.in_lists('95.163.33.18', make_log.CHROME))

    def test_fake_ua(self):
        r = self.rules('custom')
        for ua in ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 '
                   'Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/138.0.0.0 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                   'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 '
                   'Safari/537.36'):
            self.assertTrue(r.is_fake(ua), ua)
        for ua in (make_log.CHROME, make_log.IPHONE, make_log.GOOGLEBOT, 'Mozilla/5.0', 'curl/8.5.0', '-', '',
                   'Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile '
                   'Safari/537.36 YaBrowser/24.12.1.112.00 SA/3',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
                   'Version/17.4 Safari/605.1.15'):
            self.assertFalse(r.is_fake(ua), ua)

    def test_bitrix_login_narrow(self):
        """Битрикс: подбор пароля — только форма входа, сохранения в админке — нет."""
        r = self.rules('bitrix')
        for u in ('/bitrix/admin/', '/bitrix/admin/index.php?login=yes', '/bitrix/admin/?login=yes',
                  '/auth/?login=yes', '/personal/?login=yes&backurl=%2F'):
            self.assertTrue(r.login.search(u), u)
        for u in ('/bitrix/admin/iblock_element_edit.php?IBLOCK_ID=2&type=catalog&ID=15',
                  '/bitrix/admin/fileman_admin.php?lang=ru', '/catalog/?login=yesterday'):
            self.assertFalse(r.login.search(u), u)

    def test_nginx_quote(self):
        for ua in ('Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'a.b+c*d? "q" \\back $x {y} [z] ^|'):
            q = ab.nginx_quote(ua)
            self.assertTrue(q.startswith('"~^') and q.endswith('$"'))
            # как nginx раскрывает строку в кавычках: \\ -> \, \" -> ", остальное как есть
            body = re.sub(r'\\([\\"])', r'\1', q[3:-2])
            self.assertTrue(re.fullmatch(body, ua), ua)
            self.assertFalse(re.fullmatch(body, ua + ' Chrome'))
        self.assertRaises(ValueError, ab.nginx_quote, 'a\nb')


class Replay(Tmp):
    def run_replay(self, engine):
        start = calendar.timegm((2026, 10, 20, 8, 0, 0))
        log = os.path.join(self.d, 'access.log')
        with open(log, 'w', encoding='utf-8') as f:
            f.write('\n'.join(make_log.build(start)) + '\n')
        s = ab.Settings(write_conf(self.d, engine), os.path.join(self.d, 'replay'))
        quiet(ab.cmd_replay, s, [log])
        db = sqlite3.connect(os.path.join(self.d, 'replay', 'antibot.sqlite3'))
        rules = {}
        for ip, rule in db.execute('SELECT ip, rule FROM ban_log ORDER BY id'):
            rules.setdefault(ip, set()).add(rule)
        alerts = [r[0] for r in db.execute('SELECT subject FROM alert_log')]
        enforced = {r[0]: r[1] for r in db.execute('SELECT ip, MAX(enforced) FROM ban_log GROUP BY ip')}
        return rules, alerts, enforced

    def check(self, engine, expect):
        rules, alerts, enforced = self.run_replay(engine)
        for ip, rule in expect.items():
            if rule is None:
                self.assertNotIn(ip, rules, '%s: не должен быть закрыт (%s)' % (ip, engine))
            else:
                self.assertIn(rule, rules.get(ip, set()), '%s: ждём %s, есть %s (%s)' % (ip, rule, rules.get(ip), engine))
        for ip in rules:
            self.assertIn(ip, expect, 'лишний бан %s %s (%s)' % (ip, rules[ip], engine))
        self.assertTrue(any('служебный файл' in a for a in alerts), alerts)
        self.assertTrue(any('CDN' in a for a in alerts), alerts)
        # в наблюдении по-настоящему закрыты только сканеры и пул без скриптов
        for ip, rs in rules.items():
            self.assertEqual(bool(enforced[ip]), bool(rs & {'scan', 'nojs'}), (ip, rs))

    def test_custom(self):
        self.check('custom', make_log.EXPECT_CUSTOM)

    def test_woocommerce(self):
        self.check('woocommerce', make_log.EXPECT_WOO)


class Review(Tmp):
    UAS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 '
           'Safari/537.36',
           'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
           'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 '
           'Safari/537.36',
           'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0',
           'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile '
           'Safari/537.36']

    def test_rotation_shared_and_soft_scan(self):
        """Сканер со сменой имени браузера — не «общий адрес»; люди за NAT с картинками — общий; «закрыл бы» по
        мягкому правилу не прикрывает сканера от настоящего бана."""
        start = calendar.timegm((2026, 10, 20, 8, 0, 0))
        L, U = make_log.line, self.UAS
        lines = []
        # сканер: три пробы — бан scan; потом сутки с лишним заходит на главную, вход и регистрацию под пятью именами
        for j, u in enumerate(('/.env', '/wp-login.php', '/.git/config')):
            lines.append(L('198.51.100.41', start + j * 20, 'GET', u, status=404, ua='curl/8.0'))
        for k in range(20):
            t, ua = start + 600 + k * 80 * 60, U[k % 5]
            lines.append(L('198.51.100.41', t, 'GET', '/', status=403, ua=ua))
            lines.append(L('198.51.100.41', t + 5, 'GET', '/login', status=403, ua=ua))
            lines.append(L('198.51.100.41', t + 9, 'POST', '/register', status=403, ua=ua))
        # NAT: парсер под одним именем, после «закрыл бы» — трое людей с картинками и значком
        for i in range(70):
            lines.append(L('198.51.100.42', start + i * 25, 'GET', '/catalog/item-%d' % i, ua='python-requests/2.31'))
        for k, ua in enumerate(U[:3]):
            t = start + 2400 + k * 300
            lines.append(L('198.51.100.42', t, 'GET', '/catalog/phones/', ua=ua))
            lines.append(L('198.51.100.42', t + 1, 'GET', '/img/a.png', ua=ua))
            lines.append(L('198.51.100.42', t + 2, 'GET', '/favicon.ico', ua=ua))
            lines.append(L('198.51.100.42', t + 40, 'GET', '/catalog/phones/item-%d' % k, ua=ua))
        # сканер за своей проверкой сайта: 403 — «долбит отказы» («закрыл бы»), потом пробы под новыми именами
        for i in range(35):
            lines.append(L('198.51.100.40', start + i * 60, 'GET', '/catalog/a-%d' % i, status=403, ua=U[0]))
        for j, u in enumerate(('/.env', '/wp-login.php', '/.git/config')):
            lines.append(L('198.51.100.40', start + 2400 + j * 30, 'GET', u, status=404, ua=U[j + 1]))
        lines.append(L('203.0.113.200', start + 27 * 3600, 'GET', '/', ua=U[0]))     # журнал идёт дальше суток
        log = os.path.join(self.d, 'access.log')
        with open(log, 'w', encoding='utf-8') as f:
            f.write('\n'.join(l for _, l in sorted(lines)) + '\n')
        s = ab.Settings(write_conf(self.d), os.path.join(self.d, 'replay'))
        quiet(ab.cmd_replay, s, [log])
        db = sqlite3.connect(os.path.join(self.d, 'replay', 'antibot.sqlite3'))
        verdict = {ip: (rule, v) for ip, rule, v in db.execute('SELECT ip, rule, verdict FROM review_log ORDER BY id')}
        self.assertEqual(verdict['198.51.100.41'], ('scan', 'bot'))
        ev = db.execute("SELECT evidence FROM review_log WHERE ip='198.51.100.41'").fetchone()[0]
        self.assertIn('имён браузера без единой картинки и скрипта — 5', ev)
        self.assertEqual(verdict['198.51.100.42'], ('parser', 'shared'))
        bans = list(db.execute("SELECT rule, enforced FROM ban_log WHERE ip='198.51.100.40' ORDER BY id"))
        self.assertEqual(bans, [('refusals', 0), ('scan', 1)])

    def replay(self, lines, extra=''):
        log = os.path.join(self.d, 'access.log')
        with open(log, 'w', encoding='utf-8') as f:
            f.write('\n'.join(l for _, l in sorted(lines)) + '\n')
        state = tempfile.mkdtemp(prefix='replay-', dir=self.d)  # своя база на каждый прогон (Windows не даст удалить открытую)
        quiet(ab.cmd_replay, ab.Settings(write_conf(self.d, extra=extra), state), [log])
        return sqlite3.connect(os.path.join(state, 'antibot.sqlite3'))

    def test_confirmed(self):
        """«Закрыл бы» по мягкому правилу, а за сутки — 20+ запросов без единого признака человека: настоящий бан на
        7 суток. Значок после бана — признак браузера: такого не подтверждаем."""
        start = calendar.timegm((2026, 10, 20, 8, 0, 0))
        L = make_log.line
        lines = []
        for ip, favicon in (('198.51.100.50', False), ('198.51.100.51', True)):
            for i in range(70):
                lines.append(L(ip, start + i * 30, 'GET', '/catalog/item-%d' % i, ua='python-requests/2.31'))
            for k in range(27):                                  # дальше под «закрыл бы» по три страницы в час
                lines.append(L(ip, start + 3600 + k * 1200, 'GET', '/catalog/next-%d' % k, ua='python-requests/2.31'))
            if favicon:
                lines.append(L(ip, start + 5000, 'GET', '/favicon.ico', ua=make_log.CHROME))
        lines.append(L('203.0.113.200', start + 26 * 3600, 'GET', '/', ua=make_log.CHROME))
        db = self.replay(lines)
        bans = list(db.execute("SELECT rule, enforced, until - ts FROM ban_log WHERE ip='198.51.100.50' ORDER BY id"))
        self.assertEqual(bans, [('parser', 0, 12 * 3600), ('confirmed', 1, 168 * 3600)])
        act = db.execute("SELECT action FROM review_log WHERE ip='198.51.100.50'").fetchone()[0]
        self.assertIn('подтверждён', act)
        self.assertEqual([r[0] for r in db.execute("SELECT rule FROM ban_log WHERE ip='198.51.100.51'")], ['parser'])

    def test_nojs(self):
        """Без скриптов: под именем браузера 20+ страниц без картинок — бан на 3 ч. Не трогаем, если адрес грузил
        картинки за сутки или пришёл из поиска, и если картинок сайта в журнале нет вовсе (CDN)."""
        start = calendar.timegm((2026, 10, 20, 8, 0, 0))
        L, CH = make_log.line, make_log.CHROME
        people, bots = [], []
        for k in range(120):                                       # люди: страница, стили, картинка
            t = start + k * 60
            people.append(L('192.0.2.%d' % (k % 120 + 1), t, 'GET', '/catalog/p-%d' % k, ua=make_log.IPHONE))
            people.append(L('192.0.2.%d' % (k % 120 + 1), t + 1, 'GET', '/css/site.css', ua=make_log.IPHONE))
            people.append(L('192.0.2.%d' % (k % 120 + 1), t + 2, 'GET', '/img/p-%d.jpg' % k, ua=make_log.IPHONE))
        bots.append(L('198.51.100.61', start + 300, 'GET', '/img/a.png', ua=CH))       # грузил картинки час назад
        bots.append(L('198.51.100.62', start + 600, 'GET', '/', ref='https://yandex.ru/search/?text=x', ua=CH))
        for i in range(25):
            for ip in ('198.51.100.60', '198.51.100.61', '198.51.100.62'):
                bots.append(L(ip, start + 4200 + i * 60, 'GET', '/catalog/item-%d' % i, ua=CH))
        db = self.replay(people + bots)
        bans = {ip: (rule, enf, until - ts) for ip, rule, enf, until, ts in
                db.execute('SELECT ip, rule, enforced, until, ts FROM ban_log')}
        self.assertEqual(bans.get('198.51.100.60'), ('nojs', 1, 3 * 3600))
        self.assertNotIn('198.51.100.61', bans)
        self.assertNotIn('198.51.100.62', bans)
        # картинки отдаёт CDN — в журнале их нет ни у кого: правило молчит
        no_static = [x for x in people + bots if '/img/' not in x[1] and '/css/' not in x[1]]
        db = self.replay(no_static)
        self.assertEqual(list(db.execute("SELECT rule FROM ban_log WHERE rule='nojs'")), [])
        # и письма «пул разовых адресов» про людей по одной странице нет: без картинок в журнале пулы не считаются
        self.assertEqual([r[0] for r in db.execute("SELECT subject FROM alert_log WHERE subject LIKE '%пул%'")], [])

    def test_pool_letter(self):
        """Пул разовых адресов: 70 адресов по 2 страницы под одним (подделанным) именем — письмо. Люди с тем же
        популярным именем, которые грузят картинки, — нет."""
        start = calendar.timegm((2026, 10, 20, 8, 0, 0))
        L = make_log.line
        fake = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 '
                'Safari/537.36')
        lines = []
        for k in range(70):
            ip = '2001:db8::%x' % (k + 1)
            lines.append(L(ip, start + k * 20, 'GET', '/catalog/a-%d' % k, ua=fake))
            lines.append(L(ip, start + k * 20 + 3, 'GET', '/catalog/b-%d' % k, ua=fake))
        for k in range(90):
            ip = '192.0.2.%d' % (k + 1)
            lines.append(L(ip, start + k * 20, 'GET', '/catalog/p-%d' % k))
            lines.append(L(ip, start + k * 20 + 1, 'GET', '/img/p-%d.jpg' % k))
        lines.append(L('203.0.113.200', start + 3000, 'GET', '/'))
        db = self.replay(lines)
        subj = [r[0] for r in db.execute('SELECT subject FROM alert_log')]
        pool = [x for x in subj if 'пул разовых адресов' in x]
        self.assertEqual(len(pool), 1, subj)
        self.assertIn('70', pool[0])


class Rotation(Tmp):
    def test_dateext_tail(self):
        """После ротации с датой (logrotate dateext) хвост прежнего файла дочитывается."""
        s = ab.Settings(write_conf(self.d))
        st = ab.Store(s.state_dir)
        parser = ab.LogParser(s)
        with open(s.log, 'w', encoding='utf-8') as f:
            f.write('old-1\n')
        self.assertEqual(ab.read_new(s, st, parser)[0], [])           # первый запуск — с конца
        with open(s.log, 'a', encoding='utf-8') as f:
            f.write('old-2\nold-3\n')
        os.rename(s.log, s.log + '-20261028')
        with open(s.log, 'w', encoding='utf-8') as f:
            f.write('new-1\n')
        self.assertEqual(ab.read_new(s, st, parser)[0], ['old-2', 'old-3', 'new-1'])
        with open(s.log, 'a', encoding='utf-8') as f:
            f.write('new-2\n')
        self.assertEqual(ab.read_new(s, st, parser)[0], ['new-2'])

    def test_long_tail(self):
        """Хвост прежнего файла больше MAX_READ: дочитываем его за несколько проходов, потом — новый файл."""
        s = ab.Settings(write_conf(self.d))
        st = ab.Store(s.state_dir)
        parser = ab.LogParser(s)
        open(s.log, 'w').close()
        ab.read_new(s, st, parser)
        with open(s.log, 'ab') as f:
            f.write(b''.join(b'old-%02d\n' % i for i in range(10)))     # 10 строк по 7 байт
        os.rename(s.log, s.log + '.1')
        with open(s.log, 'w', encoding='utf-8') as f:
            f.write('new-1\n')
        saved = ab.MAX_READ
        ab.MAX_READ = 30
        try:
            got = []
            for _ in range(5):
                got.append(ab.read_new(s, st, parser)[0])
        finally:
            ab.MAX_READ = saved
        self.assertEqual(got[0], ['old-00', 'old-01', 'old-02', 'old-03'])
        self.assertEqual(sum(got, []), ['old-%02d' % i for i in range(10)] + ['new-1'])
        self.assertEqual(got[-1], [])


class Bans(Tmp):
    def test_ladder_and_scan_repeat(self):
        s = ab.Settings(write_conf(self.d))
        st = ab.Store(s.state_dir)
        t = calendar.timegm((2026, 10, 20, 8, 0, 0))
        ab.CLOCK.fixed = t
        u = ab.do_ban(s, st, '203.0.113.9', 'parser', {})
        self.assertEqual(u - t, 12 * 3600)
        ab.CLOCK.fixed = t + 13 * 3600
        u = ab.do_ban(s, st, '203.0.113.9', 'parser', {})
        self.assertEqual(u - ab.CLOCK.fixed, 168 * 3600)
        ab.CLOCK.fixed = t + 9 * 86400
        u = ab.do_ban(s, st, '203.0.113.9', 'parser', {})
        self.assertEqual(u - ab.CLOCK.fixed, 720 * 3600)
        ab.CLOCK.fixed = t
        u = ab.do_ban(s, st, '203.0.113.10', 'scan', {})
        self.assertEqual(u - t, 720 * 3600)
        ab.CLOCK.fixed = t + 31 * 86400
        u = ab.do_ban(s, st, '203.0.113.10', 'scan', {})
        self.assertEqual(u - ab.CLOCK.fixed, 87600 * 3600)          # повторный сканер — 10 лет
        st.q("INSERT INTO review_log(ts, ip, rule, verdict, action) VALUES(?,?,?,?,?)",
             (t, '203.0.113.11', 'scan', 'shared', 'предложение'))
        ab.do_ban(s, st, '203.0.113.11', 'scan', {})
        ab.CLOCK.fixed = t + 62 * 86400
        u = ab.do_ban(s, st, '203.0.113.11', 'scan', {})
        self.assertEqual(u - ab.CLOCK.fixed, 720 * 3600)           # за адресом были люди — не 10 лет

    def test_nginx_lists(self):
        s = ab.Settings(write_conf(self.d))
        os.makedirs(s.nginx_dir)
        st = ab.Store(s.state_dir)
        ab.do_ban(s, st, '203.0.113.20', 'parser', {})              # наблюдение — в nginx не идёт
        ab.do_ban(s, st, '203.0.113.21', 'scan', {})                # сканер — идёт и в наблюдении
        st.commit()
        quiet(ab.cmd_manual, s, ['--ban', '2001:db8::21', '24', 'проверка'])
        banned = open(os.path.join(s.nginx_dir, 'banned.conf')).read()
        self.assertIn('203.0.113.21 1;', banned)
        self.assertIn('2001:db8::21 1;', banned)
        self.assertNotIn('203.0.113.20', banned)
        with open(s.log, 'w') as f:
            f.write('')
        quiet(ab.cmd_block_ua, s, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', False)
        self.assertIn('Win64; x64\\\\)$" 1;', open(os.path.join(s.nginx_dir, 'ua-banned.conf')).read())
        quiet(ab.cmd_manual, s, ['--unban', '203.0.113.21'])
        self.assertNotIn('203.0.113.21', open(os.path.join(s.nginx_dir, 'banned.conf')).read())
        self.assertRaises(SystemExit, ab.cmd_manual, s, ['--ban', '127.0.0.1', '1'])
        quiet(ab.cmd_mode, s, 'enforce')
        self.assertIn('203.0.113.20 1;', open(os.path.join(s.nginx_dir, 'banned.conf')).read())

    def test_nginx_files(self):
        s = ab.Settings(write_conf(self.d, extra='[allow]\naddresses =\n    198.51.100.10  # офис\n'))
        st = ab.Store(s.state_dir)
        quiet(ab.nginx_files, s, st, ab.Mailer(s, st))
        http = open(s.nginx_http_conf, encoding='utf-8').read()
        site = open(s.nginx_site_conf, encoding='utf-8').read()
        self.assertIn('geo $antibot_ban', http)
        self.assertIn('map $http_user_agent $antibot_ua_ban', http)
        self.assertIn('geo $antibot_allow', http)
        self.assertIn('"~^[^|]*HeadlessChrome" 1;', http)
        self.assertIn('"~*^[^|]*\\|.*(?:googlebot', http)                 # в файле nginx — \| (поисковики мимо)
        self.assertIn('if ($antibot_name_ban)', site)
        self.assertNotIn('$antibot_ua_ban)', site)
        allow = open(os.path.join(s.nginx_dir, 'allow.conf'), encoding='utf-8').read()
        self.assertIn('198.51.100.10/32 1;', allow)
        self.assertIn('127.0.0.0/8 1;', allow)
        self.assertIn('mailto:support@shop.example', site)
        self.assertIn('$remote_addr', site)
        self.assertNotIn("'", site.split("return 403 '", 1)[1].rstrip().rstrip("';\n}").rstrip("'"))
        off = ab.Settings(write_conf(self.d, extra='[features]\nblock_headless = no\n'))
        quiet(ab.nginx_files, off, st, ab.Mailer(off, st))
        self.assertIn('"~^[^|]*HeadlessChrome" 0;', open(off.nginx_http_conf, encoding='utf-8').read())

    def test_ban_net(self):
        """Сеть целиком: не закрывает, если в ней были люди (или с --force); пересечения с CDN и белым списком —
        отказ; адреса из закрытой сети сторож не разбирает — отказ им даёт nginx."""
        s = ab.Settings(write_conf(self.d))
        os.makedirs(s.nginx_dir)
        t = int(time.time()) - 3600
        L = make_log.line
        lines = [L('203.0.113.77', t, 'GET', '/', ref='https://yandex.ru/search/?text=x'),
                 L('203.0.113.77', t + 1, 'GET', '/img/a.png')]
        lines += [L('203.0.113.78', t + 60 + i, 'GET', '/catalog/item-%d' % i, ua='python-requests/2.31') for i in range(30)]
        with open(s.log, 'w', encoding='utf-8') as f:
            f.write('\n'.join(l for _, l in lines) + '\n')
        self.assertRaises(SystemExit, quiet, ab.cmd_ban_net, s, ['--ban-net', '203.0.113.0/24', '720', 'облако'])
        self.assertRaises(SystemExit, quiet, ab.cmd_ban_net, s, ['--ban-net', '104.16.0.0/16', '720'])   # CDN
        self.assertRaises(SystemExit, quiet, ab.cmd_ban_net, s, ['--ban-net', '10.1.0.0/16', '720'])      # частная сеть
        self.assertRaises(SystemExit, quiet, ab.cmd_ban_net, s, ['--ban-net', '20.0.0.0/8', '720'])      # слишком большая
        out = quiet(ab.cmd_ban_net, s, ['--ban-net', '203.0.113.5/24', '720', 'облако', '--force'])
        self.assertIn('203.0.113.77', out)
        banned = open(os.path.join(s.nginx_dir, 'banned.conf')).read()
        self.assertIn('203.0.113.0/24 1;', banned)
        st = ab.Store(s.state_dir)
        g = ab.Guard(s, ab.Rules(s), st, ab.Mailer(s, st))
        p = ab.LogParser(s)
        for i in range(40):
            g.add(p.parse(L('203.0.113.99', t + 600 + i, 'GET', '/catalog/a-%d' % i, status=403)[1]))
        quiet(g.evaluate)
        self.assertIsNone(st.q("SELECT 1 FROM ban_log WHERE ip='203.0.113.99'").fetchone())
        who = quiet(ab.cmd_who, s, '203.0.113.99', 24)
        self.assertIn('Входит в закрытую сеть 203.0.113.0/24', who)
        quiet(ab.cmd_manual, s, ['--unban', '203.0.113.0/24'])
        self.assertNotIn('203.0.113.0/24', open(os.path.join(s.nginx_dir, 'banned.conf')).read())


class Mail(Tmp):
    def test_caps_split(self):
        """Предел писем в сутки: «работа над ошибками» — свой, остальные тревоги — свой."""
        s = ab.Settings(write_conf(self.d))
        st = ab.Store(s.state_dir)
        m = ab.Mailer(s, st)
        saved = ab.DRY_MAIL
        ab.DRY_MAIL = True
        try:
            sent = [quiet(lambda i=i: m.send('работа над ошибками — %d' % i, 'x', key='review:%d' % i)) for i in range(14)]
            self.assertEqual(len(sent), 14)
            n_rev = st.q("SELECT SUM(sent) FROM alert_log WHERE subject LIKE '%работа над ошибками%'").fetchone()[0]
            self.assertEqual(n_rev, 12)
            quiet(m.send, 'тяжёлый бот 203.0.113.1', 'x', 'heavy:203.0.113.1')
            self.assertEqual(st.q("SELECT sent FROM alert_log WHERE subject LIKE '%тяжёлый%'").fetchone()[0], 1)
        finally:
            ab.DRY_MAIL = saved


class Load(Tmp):
    def test_load_watch(self):
        """Нагрузка выше порога 10 минут — одно письмо на эпизод; резервная копия — без письма."""
        s = ab.Settings(write_conf(self.d, extra='load_max = 3\n'))
        st = ab.Store(s.state_dir)
        g = ab.Guard(s, ab.Rules(s), st, ab.Mailer(s, st))
        saved = ab.read_loadavg, ab.proc_top
        la = [(5.0, 5.0)]
        procs = [[(80.0, 'www-data', 'php-fpm: pool www')]]
        ab.read_loadavg = lambda: la[0]
        ab.proc_top = lambda wait=2.0: procs[0]
        t0 = calendar.timegm((2026, 10, 20, 8, 0, 0))
        try:
            def at(minutes):
                ab.CLOCK.fixed = t0 + minutes * 60
                quiet(g.load_watch, (t0 // 60) + minutes)
            for mnt in (0, 5, 11, 12):
                at(mnt)
            la[0] = (1.0, 1.0)
            at(20)
            la[0], procs[0] = (6.0, 6.0), [(90.0, 'root', '/usr/bin/mysqldump --all-databases')]
            for mnt in (90, 101, 102):
                at(mnt)
            la[0] = (0.5, 0.5)
            at(110)
        finally:
            ab.read_loadavg, ab.proc_top = saved
        subj = [r[0] for r in st.q("SELECT subject FROM alert_log WHERE subject LIKE '%нагрузка%'")]
        self.assertEqual(len(subj), 1, subj)
        eps = list(st.q('SELECT alerted, why FROM load_ep ORDER BY start'))
        self.assertEqual([e[0] for e in eps], [1, 0])
        self.assertIn('php-fpm', eps[0][1])
        self.assertTrue(eps[1][1].startswith('Штатно: резервная копия'), eps[1][1])


class Daily(Tmp):
    def test_daily_and_who(self):
        start = int(time.time()) - 3 * 3600 - 60
        conf = write_conf(self.d)
        s = ab.Settings(conf)
        with open(s.log, 'w', encoding='utf-8') as f:
            f.write('\n'.join(make_log.build(start)) + '\n')
        quiet(ab.cmd_replay, ab.Settings(conf, s.state_dir), [s.log])
        ab.CLOCK.fixed = None
        out = quiet(ab.cmd_daily, ab.Settings(conf), 24)
        self.assertIn('Коротко:', out)
        bots = out.split('4. Кандидаты в бан', 1)[1].split('Активные, похожие на людей', 1)[0]
        people = out.split('Активные, похожие на людей', 1)[1].split('5. Работа', 1)[0]
        self.assertIn('198.51.100.8', bots)                 # парсер («закрыл бы» в наблюдении) — кандидат
        self.assertIn('похоже, бот', bots.split('198.51.100.8', 1)[1].split('Разбор:', 1)[0])
        self.assertNotIn('198.51.100.7 ', bots)             # пул без скриптов уже закрыт по-настоящему
        self.assertIn('192.0.2.10', people)                 # человек из поиска — отдельно, не в кандидатах
        self.assertNotIn('192.0.2.10 ', bots)
        self.assertNotIn('203.0.113.5 ', bots)              # сканер уже закрыт
        self.assertNotIn('← новое', out)                    # первый запуск — без пометок «новое»
        self.assertIn('9. Пулы разовых адресов', out)
        self.assertIn('10. Нагрузка сервера', out)
        who = quiet(ab.cmd_who, ab.Settings(conf), '198.51.100.7', 24)
        self.assertIn('За бота', who)
        self.assertIn('картинок и стилей 0', who)
        # Mail.ru из сети VK — не кандидат, «настоящий поисковик»; без имени в DNS не из сети — «сверить сеть»
        self.assertNotIn('95.163.33.18', out)
        who = quiet(ab.cmd_who, ab.Settings(conf), '95.163.33.18', 24)
        self.assertIn('Настоящий поисковик mailru: адрес из его сети', who)
        self.assertIn('Вывод: настоящий поисковик — не трогать', who)
        self.assertNotIn('DNS это не подтвердил', who)
        quiet_one = bots.split('198.51.100.30', 1)[1].split('Разбор:', 1)[0]
        self.assertIn('проверить нечем', quiet_one)
        self.assertIn('сверить сеть', quiet_one)


class Syntax(unittest.TestCase):
    def test_python36_compatible(self):
        """Без возможностей новее 3.6: синтаксис (на 3.8–3.12) и известные функции стандартной библиотеки."""
        src = open(os.path.join(os.path.dirname(HERE), 'antibot.py'), encoding='utf-8').read()
        import ast
        if (3, 8) <= sys.version_info < (3, 13):
            ast.parse(src, feature_version=(3, 6))
        for bad in ('capture_output=', 'text=True', 'fromisoformat', ':=', 'removeprefix', 'functools.cache',
                    'ON CONFLICT', 'isascii(', 'math.dist'):
            self.assertNotIn(bad, src, bad)


if __name__ == '__main__':
    unittest.main()
