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
        # в наблюдении по-настоящему закрыты только сканеры
        for ip, rs in rules.items():
            self.assertEqual(bool(enforced[ip]), rs == {'scan'}, (ip, rs))

    def test_custom(self):
        self.check('custom', make_log.EXPECT_CUSTOM)

    def test_woocommerce(self):
        self.check('woocommerce', make_log.EXPECT_WOO)


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
        s = ab.Settings(write_conf(self.d))
        st = ab.Store(s.state_dir)
        quiet(ab.nginx_files, s, st, ab.Mailer(s, st))
        http = open(s.nginx_http_conf, encoding='utf-8').read()
        site = open(s.nginx_site_conf, encoding='utf-8').read()
        self.assertIn('geo $antibot_ban', http)
        self.assertIn('map $http_user_agent $antibot_ua_ban', http)
        self.assertIn('mailto:support@shop.example', site)
        self.assertIn('$remote_addr', site)
        self.assertNotIn("'", site.split("return 403 '", 1)[1].rstrip().rstrip("';\n}").rstrip("'"))


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
        self.assertIn('198.51.100.7', bots)                 # парсер («закрыл бы» в наблюдении) — кандидат
        self.assertIn('похоже, бот', bots.split('198.51.100.7', 1)[1].split('Разбор:', 1)[0])
        self.assertIn('192.0.2.10', people)                 # человек из поиска — отдельно, не в кандидатах
        self.assertNotIn('192.0.2.10 ', bots)
        self.assertNotIn('203.0.113.5 ', bots)              # сканер уже закрыт
        self.assertNotIn('← новое', out)                    # первый запуск — без пометок «новое»
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
