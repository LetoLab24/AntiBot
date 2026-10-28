#!/usr/bin/env python3
"""Синтетический журнал nginx (combined) для проверки AntiBot. Только документационные адреса
(192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::), плюс по одному адресу Cloudflare WARP и CDN.

  python make_log.py > access.log          # три часа, начиная за три часа до сейчас
"""
import sys
import time

CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1'
GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

# кто есть в журнале и чего от сторожа ждём (правило или None)
EXPECT_CUSTOM = {
    '203.0.113.5': 'scan',        # пробы секретов
    '203.0.113.6': 'scan',        # одна SQL-инъекция
    '198.51.100.7': 'parser',     # 80 карточек за 40 минут без картинок и скриптов
    '192.0.2.10': None,           # человек: пришёл из поиска, картинки, скрипты
    '198.51.100.20': 'fake_se',   # «Googlebot», DNS не подтверждает
    '192.0.2.66': None,           # настоящий Googlebot
    '203.0.113.30': 'head',       # HEAD по товарам
    '203.0.113.40': 'rate',       # 400 страниц за 4 минуты
    '192.0.2.40': 'scan',         # пути WordPress — на «своём» движке это пробы
    '104.28.1.1': None,           # Cloudflare WARP — общий адрес людей, за пробы не закрываем
    '162.158.1.1': None,          # адрес CDN Cloudflare — не закрываем никогда
    '203.0.113.60': 'scan',       # /.env отдан с кодом 200 — утечка
    '2001:db8::7': 'parser',      # IPv6-парсер
    '203.0.113.50': 'scan',       # POST на wp-login.php — на «своём» движке это пробы
    '192.0.2.77': None,           # телефон, браузер шлёт HEAD перед каждой страницей, но грузит картинки
}
EXPECT_WOO = dict(EXPECT_CUSTOM, **{'192.0.2.40': None,    # на WooCommerce это свои пути
                                    '203.0.113.50': 'login'})  # подбор пароля


MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def line(ip, ts, method, url, status=200, size=5120, ref='-', ua=CHROME):
    g = time.gmtime(ts)
    t = '%02d/%s/%04d:%02d:%02d:%02d +0000' % (g.tm_mday, MONTHS[g.tm_mon - 1], g.tm_year, g.tm_hour, g.tm_min, g.tm_sec)
    return ts, '%s - - [%s] "%s %s HTTP/1.1" %d %s "%s" "%s"' % (ip, t, method, url, status, size, ref, ua)


def build(start):
    out = []

    def a(item):
        out.append(item)
    # человек: из поиска, 50 карточек за полтора часа, картинки и скрипты страницы
    for i in range(50):
        ts = start + 600 + i * 100
        a(line('192.0.2.10', ts, 'GET', '/product/item-%d' % i, ref='https://www.google.com/' if i == 0 else
               'https://shop.example/catalog', ua=IPHONE))
        a(line('192.0.2.10', ts + 1, 'GET', '/img/item-%d.jpg' % i, ua=IPHONE))
        a(line('192.0.2.10', ts + 1, 'GET', '/css/site.css', ua=IPHONE))
        a(line('192.0.2.10', ts + 2, 'GET', '/ajax/cart?ajax=1', ua=IPHONE))
    # парсер: 80 карточек за 40 минут, ни картинок, ни скриптов
    for i in range(80):
        a(line('198.51.100.7', start + 3600 + i * 30, 'GET', '/product/item-%d' % i))
        a(line('2001:db8::7', start + 3600 + i * 30, 'GET', '/product/item-%d' % i))
    # сканер: пробы секретов в одну минуту
    for j, u in enumerate(('/.env', '/.git/config', '/backup.zip', '/phpinfo.php', '/wp-login.php')):
        a(line('203.0.113.5', start + 1200 + j, 'GET', u, status=404, size=150, ua='Mozilla/5.0 zgrab/0.x'))
    # SQL-инъекция — одна
    a(line('203.0.113.6', start + 1300, 'GET', "/catalog/?q=ipad%27%20UNION%20SELECT%20NULL--%20-"))
    # поддельный и настоящий Googlebot
    for i in range(30):
        a(line('198.51.100.20', start + 2000 + i * 20, 'GET', '/product/item-%d' % i, ua=GOOGLEBOT))
    for i in range(200):
        a(line('192.0.2.66', start + 2000 + i * 10, 'GET', '/product/item-%d' % i, ua=GOOGLEBOT))
    # HEAD по товарам
    for i in range(25):
        a(line('203.0.113.30', start + 4000 + i * 10, 'HEAD', '/product/item-%d' % i, size=0))
    # телефон: HEAD перед каждой страницей, потом сама страница, картинки и скрипты
    for i in range(30):
        ts = start + 4200 + i * 60
        a(line('192.0.2.77', ts, 'HEAD', '/product/item-%d' % i, size=0, ua=IPHONE))
        a(line('192.0.2.77', ts + 1, 'GET', '/product/item-%d' % i, ua=IPHONE))
        a(line('192.0.2.77', ts + 2, 'GET', '/img/item-%d.jpg' % i, ua=IPHONE))
        a(line('192.0.2.77', ts + 2, 'POST', '/ajax/cart', ua=IPHONE))
    # слишком часто: 400 страниц за 4 минуты (с картинками — правило частоты статику не смотрит)
    for i in range(400):
        a(line('203.0.113.40', start + 5000 + i * 0.6, 'GET', '/product/item-%d' % (i % 90)))
        if i % 10 == 0:
            a(line('203.0.113.40', start + 5000 + i * 0.6, 'GET', '/img/a.png'))
    # пути WordPress: на WooCommerce это сам магазин
    for j, u in enumerate(('/wp-admin/admin-ajax.php', '/wp-json/wc/store/v1/cart', '/wp-login.php',
                           '/wp-includes/js/jquery.js', '/xmlrpc.php')):
        a(line('192.0.2.40', start + 6000 + j * 5, 'GET', u))
    # подбор пароля к WooCommerce
    for i in range(25):
        a(line('203.0.113.50', start + 6500 + i * 30, 'POST', '/wp-login.php', status=200, size=4000))
    # WARP: пробы, но адрес общий
    for j, u in enumerate(('/.env', '/.git/config', '/backup.sql', '/phpinfo.php')):
        a(line('104.28.1.1', start + 7000 + j, 'GET', u, status=404, size=150))
    # адрес CDN ведёт себя как парсер
    for i in range(90):
        a(line('162.158.1.1', start + 7200 + i * 20, 'GET', '/product/item-%d' % i))
    # утечка: /.env отдан с кодом 200
    a(line('203.0.113.60', start + 8000, 'GET', '/.env', status=200, size=512, ua='python-requests/2.31'))
    a(line('203.0.113.60', start + 8001, 'GET', '/.git/config', status=404, size=150, ua='python-requests/2.31'))
    a(line('203.0.113.60', start + 8002, 'GET', '/.aws/credentials', status=404, size=150, ua='python-requests/2.31'))
    # фон: обычные люди по паре страниц
    for k in range(60):
        ip = '192.0.2.%d' % (100 + k)
        a(line(ip, start + k * 170, 'GET', '/', ref='https://yandex.ru/search/?text=x', ua=IPHONE))
        a(line(ip, start + k * 170 + 1, 'GET', '/css/site.css', ua=IPHONE))
        a(line(ip, start + k * 170 + 5, 'GET', '/product/item-%d' % k, ua=IPHONE))
    # ровно в последнюю минуту — точка отсчёта, чтобы прогон дошёл до конца журнала
    a(line('192.0.2.250', start + 3 * 3600, 'GET', '/', ua=IPHONE))
    out.sort(key=lambda x: x[0])
    return [text for ts, text in out]


if __name__ == '__main__':
    start = int(time.time()) - 3 * 3600
    sys.stdout.write('\n'.join(build(start)) + '\n')
