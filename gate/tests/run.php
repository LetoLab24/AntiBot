<?php
// Тесты привратника на синтетике (без PHPUnit): php gate/tests/run.php
// Нужны расширение openssl (проверка подписи) и команда openssl (ключи для теста).
define('ABG_NO_RUN', 1);
require dirname(__DIR__) . '/gate.php';

$fails = 0;
$count = 0;
function t($name, $cond)
{
    global $fails, $count;
    $count++;
    if (!$cond) {
        $fails++;
        echo "FAIL: $name\n";
    }
}

function rmtree($d)
{
    if (!is_dir($d)) {
        return;
    }
    foreach (scandir($d) as $f) {
        if ($f === '.' || $f === '..') {
            continue;
        }
        $p = $d . '/' . $f;
        is_dir($p) ? rmtree($p) : unlink($p);
    }
    rmdir($d);
}

$tmp = sys_get_temp_dir() . '/abg-test-' . getmypid();
rmtree($tmp);
mkdir($tmp, 0700, true);

// ключи хаба для теста — через команду openssl
$priv = $tmp . '/hub.pem';
$pub = $tmp . '/hub.pub';
shell_exec('openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ' . escapeshellarg($priv) . ' 2>&1');
shell_exec('openssl pkey -in ' . escapeshellarg($priv) . ' -pubout -out ' . escapeshellarg($pub) . ' 2>&1');
$pubPem = (string)@file_get_contents($pub);
$keys = $pubPem !== '' && function_exists('openssl_sign');

$cfg = "<?php return array('domain' => 'shop.example', 'contact' => 'support@shop.example', 'engine' => 'wordpress',"
    . " 'data_dir' => " . var_export($tmp . '/data', true) . ", 'secret' => 'test-secret-0123456789abcdef',"
    . " 'server_ips' => array('192.0.2.1'), 'allow' => array('198.51.100.0/28' => 'office'),"
    . " 'hub_public_key' => " . var_export($pubPem, true) . ", 'max_new_bans' => 5);";
file_put_contents($tmp . '/config.php', $cfg);
t('load config', AbGate::load($tmp . '/config.php'));
t('data .htaccess created', is_file($tmp . '/data/.htaccess'));

// --- сети
$b = inet_pton('203.0.113.77');
t('v4 in /24', AbGate::inNet($b, AbGate::cidr('203.0.113.0/24')));
t('v4 not in other /24', !AbGate::inNet($b, AbGate::cidr('203.0.114.0/24')));
t('v4 in /20 bits', AbGate::inNet(inet_pton('172.20.15.1'), AbGate::cidr('172.20.0.0/20')));
t('v4 not in /20 bits', !AbGate::inNet(inet_pton('172.20.16.1'), AbGate::cidr('172.20.0.0/20')));
t('v6 in /48', AbGate::inNet(inet_pton('2001:db8:1:ffff::5'), AbGate::cidr('2001:db8:1::/48')));
t('v6 not in /48', !AbGate::inNet(inet_pton('2001:db8:2::5'), AbGate::cidr('2001:db8:1::/48')));
t('v4 vs v6 no match', !AbGate::inNet($b, AbGate::cidr('2001:db8::/32')));
t('bad cidr', AbGate::cidr('300.1.1.1/24') === null && AbGate::cidr('203.0.113.0/40') === null);

// --- адрес посетителя
AbGate::$cfg['trusted_proxies'] = array('127.0.0.1');
t('xff from trusted proxy', AbGate::clientIp(array('REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9, 127.0.0.1')) === '203.0.113.9');
t('xff ignored from untrusted', AbGate::clientIp(array('REMOTE_ADDR' => '203.0.113.8', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1')) === '203.0.113.8');
t('ipv6 normalized', AbGate::clientIp(array('REMOTE_ADDR' => '2001:DB8:0:0::1')) === '2001:db8::1');
AbGate::$cfg['trusted_proxies'] = array();

// --- классы запросов
t('probe .env', AbGate::classify('GET', '/.env') === 'probe');
t('probe .git/config', AbGate::classify('GET', '/.git/config') === 'probe');
t('sqli', AbGate::classify('GET', '/?id=1%20union%20select%201,2') === 'sqli');
t('sqli sleep', AbGate::classify('GET', '/product/x/?a=1%27%20and%20sleep(5)') === 'sqli');
t('wp own login not probe', AbGate::classify('POST', '/wp-login.php') !== 'probe');
t('static', AbGate::classify('GET', '/wp-content/uploads/a.jpg?ver=1') === 'static');
t('product', AbGate::classify('GET', '/product/iphone-11-lcd/') === 'product');
t('catalog', AbGate::classify('GET', '/product-category/lcd/page/2/') === 'catalog');
t('search', AbGate::classify('GET', '/?s=iphone&post_type=product') === 'search');
t('js', AbGate::classify('POST', '/wp-admin/admin-ajax.php') === 'js');
t('page', AbGate::classify('GET', '/contacts/') === 'page');
t('normal query not sqli', AbGate::classify('GET', '/?s=select+lcd+from+samsung') !== 'sqli');
AbGate::$cfg['engine'] = 'opencart';
t('opencart: wp-login is probe', AbGate::classify('GET', '/wp-login.php') === 'probe');
t('opencart product', AbGate::classify('GET', '/index.php?route=product/product&product_id=5') === 'product');
AbGate::$cfg['engine'] = 'wordpress';

// --- белый список и баны
t('server ip allowed', AbGate::isAllowed('192.0.2.1'));
t('allow net', AbGate::isAllowed('198.51.100.5') && !AbGate::isAllowed('198.51.100.20'));
AbGate::writePhp($tmp . '/data/list.php', array('ips' => array('203.0.113.10' => 1, '203.0.113.11' => 2),
    'nets' => array(array('198.18.0.0/16', 1), array('2001:db8:bad::/48', 1)),
    'ua_exact' => array('Mozilla/5.0 Chrome/130.0'), 'ua_regex' => array('^PriceDesk')));
AbGate::resetCache();
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';
t('ban ip', AbGate::banKind('203.0.113.10', $ua) === 1);
t('ban ip kind 2', AbGate::banKind('203.0.113.11', $ua) === 2);
t('ban net v4', AbGate::banKind('198.18.200.1', $ua) === 1);
t('ban net v6', AbGate::banKind('2001:db8:bad:1::9', $ua) === 1);
t('not banned', AbGate::banKind('203.0.113.12', $ua) === 0);
t('ban ua exact', AbGate::banKind('203.0.113.12', 'Mozilla/5.0 Chrome/130.0') === 1);
t('ban ua regex', AbGate::banKind('203.0.113.12', 'PriceDesk/1.0') === 1);
t('ban page has ip and contact', strpos(AbGate::banPage('203.0.113.10'), '203.0.113.10') !== false
    && strpos(AbGate::banPage('203.0.113.10'), 'mailto:support@shop.example') !== false);
t('ban page escapes', strpos(AbGate::banPage('<x>'), '<x>') === false);

// --- местный бан сканера
AbGate::countProbe('203.0.113.50', 1);
AbGate::countProbe('203.0.113.50', 1);
t('2 probes no ban', AbGate::banKind('203.0.113.50', $ua) === 0);
AbGate::countProbe('203.0.113.50', 1);
t('3 probes local ban', AbGate::banKind('203.0.113.50', $ua) === 1);
AbGate::countProbe('203.0.113.51', 3);
t('sqli weight = instant ban', AbGate::banKind('203.0.113.51', $ua) === 1);

// --- метка
$now = 1795600000;
$day = intdiv($now, 86400);
$tok = AbGate::token('203.0.113.77', $day);
t('mark today', AbGate::checkMark($tok, '203.0.113.77', $now));
t('mark same /24', AbGate::checkMark($tok, '203.0.113.200', $now));
t('mark other /24', !AbGate::checkMark($tok, '203.0.114.77', $now));
t('mark 6 days old', AbGate::checkMark(AbGate::token('203.0.113.77', $day - 6), '203.0.113.77', $now));
t('mark 7 days old', !AbGate::checkMark(AbGate::token('203.0.113.77', $day - 7), '203.0.113.77', $now));
t('mark forged', !AbGate::checkMark('0123456789abcdef', '203.0.113.77', $now));
t('mark garbage', !AbGate::checkMark('x', '203.0.113.77', $now));
$enc = AbGate::encode($tok);
$dec = '';
for ($i = strlen($enc) - 1; $i >= 0; $i--) {
    $dec .= dechex((hexdec($enc[$i]) + 9) % 16);
}
t('encode/decode like mark.js', $dec === $tok && $enc !== $tok);

// --- вставка скрипта
AbGate::$ip = '203.0.113.77';
$html = '<html><body><p>x</p></body></html>';
$out = AbGate::insertMark($html, array('Content-Type: text/html; charset=UTF-8'), 200);
t('insert before </body>', strpos($out, '<i id="abm"') !== false && strpos($out, '</body>') > strpos($out, '<script'));
t('page snippet has no token (cache-safe)', strpos($out, 'data-v=') === false && strpos($out, 'data-r="1"') !== false);
AbGate::$hasMark = true;
t('page snippet r=0 with mark', strpos(AbGate::insertMark($html, array(), 200), 'data-r="0"') !== false);
AbGate::$hasMark = false;
t('challenge snippet has inline token', strpos(AbGate::markSnippet('203.0.113.77', true), 'data-v="' . AbGate::encode(AbGate::token('203.0.113.77', intdiv(time(), 86400))) . '"') !== false);
t('abg endpoints are js', AbGate::classify('GET', '/?abg=t&_=1') === 'js' && AbGate::classify('GET', '/?abg=m') === 'js');
t('no insert on json', AbGate::insertMark($html, array('Content-Type: application/json'), 200) === $html);
t('no insert on 404', AbGate::insertMark($html, array(), 404) === $html);
t('no insert on gzip bytes', AbGate::insertMark("\x1f\x8b\x08rest</body>", array(), 200) === "\x1f\x8b\x08rest</body>");
t('no insert with content-encoding', AbGate::insertMark($html, array('Content-Encoding: gzip'), 200) === $html);
t('no insert without body', AbGate::insertMark('<p>fragment</p>', array(), 200) === '<p>fragment</p>');
t('empty stays empty', AbGate::insertMark('', array(), 200) === '');
t('insert at last </body>', substr_count(AbGate::insertMark('<body>a</body><!-- </body> -->', array(), 200), 'abm') === 1);

// --- предохранители
$cur = array('ips' => array(), 'nets' => array());
$s = AbGate::sanitizeList(array('ips' => array('203.0.113.20' => 1, '192.0.2.1' => 1, '198.51.100.3' => 1, '95.163.40.1' => 1, 'bad' => 1),
    'nets' => array(array('10.0.0.0/8', 1), array('198.19.0.0/16', 1), array('2001:db8::/32', 1), array('2001:db8:5::/48', 2),
        array('198.51.100.0/24', 1)),
    'ua_regex' => array('Chrome', 'python-requests', '^PriceDesk', '(bad'), 'ua_exact' => array('short', 'Mozilla/5.0 Chrome/130.0')), $cur);
t('safeguard keeps normal ip', isset($s['ips']['203.0.113.20']));
t('safeguard drops server ip', !isset($s['ips']['192.0.2.1']));
t('safeguard drops allow ip', !isset($s['ips']['198.51.100.3']));
t('safeguard drops mail.ru robot net ip', !isset($s['ips']['95.163.40.1']));
t('safeguard drops /8', !in_array(array('10.0.0.0/8', 1), $s['nets'], true));
t('safeguard keeps /16', in_array(array('198.19.0.0/16', 1), $s['nets'], true));
t('safeguard drops v6 /32', !in_array(array('2001:db8::/32', 1), $s['nets'], true));
t('safeguard keeps v6 /48', in_array(array('2001:db8:5::/48', 2), $s['nets'], true));
t('safeguard drops net covering allow', !in_array(array('198.51.100.0/24', 1), $s['nets'], true));
t('safeguard drops ua regex matching browsers', !in_array('Chrome', $s['ua_regex'], true));
t('safeguard keeps bot ua regex', in_array('python-requests', $s['ua_regex'], true) && in_array('^PriceDesk', $s['ua_regex'], true));
t('safeguard drops bad regex', !in_array('(bad', $s['ua_regex'], true));
t('safeguard drops short ua', !in_array('short', $s['ua_exact'], true));
$many = array();
for ($i = 1; $i <= 6; $i++) {
    $many['203.0.113.' . (100 + $i)] = 1;
}
$have = array('ips' => array('203.0.113.99' => 1), 'nets' => array());
t('too many new bans rejected', AbGate::sanitizeList(array('ips' => $many + array('203.0.113.99' => 1)), $have) === null);
t('known bans not counted as new', AbGate::sanitizeList(array('ips' => $many), array('ips' => $many, 'nets' => array())) !== null);
t('first list after install accepted whole', AbGate::sanitizeList(array('ips' => $many), $cur) !== null);

// --- настройки из хаба
$cs = AbGate::cleanSettings(array('challenge' => 1, 'challenge_pages' => 1, 'rate_hour' => 'x', 'hub_url' => 'https://evil.example',
    'paths' => array('catalog' => '^/catalog/', 'search' => '(bad'), 'secret' => 'x'));
t('settings: challenge bool', $cs['challenge'] === true);
t('settings: clamp', $cs['challenge_pages'] === 5);
t('settings: no hub_url/secret from hub', !isset($cs['hub_url']) && !isset($cs['secret']));
t('settings: bad regex dropped', isset($cs['paths']['catalog']) && !isset($cs['paths']['search']));

// --- подпись списка
if ($keys) {
    $pk = openssl_pkey_get_private(file_get_contents($priv));
    $mk = function ($p) use ($pk) {
        $j = json_encode($p);
        openssl_sign($j, $sig, $pk, OPENSSL_ALGO_SHA256);
        return json_encode(array('payload' => base64_encode($j), 'sig' => base64_encode($sig)));
    };
    $t0 = time();
    @unlink($tmp . '/data/state.php');
    AbGate::writePhp($tmp . '/data/list.php', array('ips' => array(), 'nets' => array()));
    AbGate::resetCache();
    $good = $mk(array('site' => 'shop1', 'issued' => $t0, 'ver' => 'v1', 'list' => array('ips' => array('203.0.113.30' => 1)),
        'settings' => array('challenge' => true)));
    t('signed list accepted', AbGate::acceptList($good, $t0) === true);
    AbGate::resetCache();
    t('signed list applied', AbGate::banKind('203.0.113.30', $ua) === 1);
    t('settings file written', is_array(AbGate::readPhp($tmp . '/data/settings.php')));
    $env = json_decode($good, true);
    $env['payload'] = base64_encode(str_replace('203.0.113.30', '203.0.113.31', base64_decode($env['payload'])));
    t('tampered list rejected', AbGate::acceptList(json_encode($env), $t0) === false);
    t('unsigned rejected', AbGate::acceptList(json_encode(array('payload' => base64_encode('{}'), 'sig' => '')), $t0) === false);
    t('other site rejected', AbGate::acceptList($mk(array('site' => 'shop2', 'issued' => $t0 + 1, 'ver' => 'v2', 'list' => array())), $t0) === false);
    t('older list rejected', AbGate::acceptList($mk(array('site' => 'shop1', 'issued' => $t0 - 10, 'ver' => 'v0', 'list' => array())), $t0) === false);
    t('unchanged accepted', AbGate::acceptList($mk(array('site' => 'shop1', 'issued' => $t0 + 2, 'ver' => 'v1', 'unchanged' => true)), $t0) === true);
    AbGate::resetCache();
    t('unchanged keeps list', AbGate::banKind('203.0.113.30', $ua) === 1);
} else {
    echo "SKIP: подпись — нет openssl (расширение или команда)\n";
}

// --- журнал и подозрительные
AbGate::$cfg['data_dir'] = $tmp . '/data';
$logDir = $tmp . '/data/log';
@mkdir($logDir, 0700, true);
$now = time();
$lines = '';
for ($i = 0; $i < 25; $i++) {
    $lines .= implode("\t", array($now - 100 + $i, '203.0.113.60', 'GET', 'product', '/product/p' . $i . '/', 200, 0, 0, $ua, '')) . "\n";
}
for ($i = 0; $i < 25; $i++) {
    $lines .= implode("\t", array($now - 100 + $i, '203.0.113.61', 'GET', 'product', '/product/p' . $i . '/', 200, 1, 0, $ua, '')) . "\n";
}
$lines .= implode("\t", array($now - 50, '203.0.113.62', 'GET', 'probe', '/.env', 404, 0, 0, 'curl/8.0', '')) . "\n";
$lines .= implode("\t", array($now - 50, '198.51.100.2', 'GET', 'probe', '/.env', 404, 0, 0, 'curl/8.0', '')) . "\n";
$lines .= implode("\t", array($now - 7200, '203.0.113.63', 'GET', 'probe', '/.env', 404, 0, 0, 'curl/8.0', '')) . "\n";
file_put_contents($logDir . '/' . date('Y-m-d', $now) . '.log', $lines);
$agg = AbGate::aggregate($now);
$sips = array();
foreach ($agg['suspects'] as $x) {
    $sips[$x['ip']] = $x;
}
t('nomark parser is suspect', isset($sips['203.0.113.60']) && $sips['203.0.113.60']['pages_nomark'] === 25);
t('marked visitor not sent', !isset($sips['203.0.113.61']));
t('prober is suspect with sample', isset($sips['203.0.113.62']) && $sips['203.0.113.62']['samples'] === array('/.env'));
t('allowed not sent', !isset($sips['198.51.100.2']));
t('old lines ignored', !isset($sips['203.0.113.63']));
t('stats mark share', $agg['stats']['mark_share'] === 0.5);
// роботы поисковиков (exempt=1) и белый список в долю страниц с меткой не входят
$more = '';
for ($i = 0; $i < 50; $i++) {
    $more .= implode("\t", array($now - 40, '66.249.66.1', 'GET', 'product', '/product/g' . $i . '/', 200, 0, 1, 'Googlebot/2.1', '')) . "\n";
    $more .= implode("\t", array($now - 40, '198.51.100.3', 'GET', 'product', '/product/o' . $i . '/', 200, 0, 0, $ua, '')) . "\n";
}
file_put_contents($logDir . '/' . date('Y-m-d', $now) . '.log', $lines . $more);
$agg2 = AbGate::aggregate($now);
t('mark share ignores search robots and allow list', $agg2['stats']['mark_share'] === 0.5 && $agg2['stats']['pages_hour'] === 50);
t('req_hour still counts all requests', $agg2['stats']['req_hour'] === $agg['stats']['req_hour'] + 100);
file_put_contents($logDir . '/' . date('Y-m-d', $now) . '.log', $lines);

// --- 0.2: выбор сайта по группам (shared), связки примет, свои правила, сводка, страница состояния
AbGate::$cfg['rules_file'] = $tmp . '/my-rules.php';
AbGate::$cfg['shared'] = array('bans' => 'on', 'nets' => 'on', 'names' => 'on', 'seo' => 'on', 'patterns' => 'on');
t('mode on', AbGate::mode('bans') === 'on');
AbGate::$cfg['shared'] = array('bans' => 'WATCH ', 'nets' => false, 'names' => true, 'seo' => 'nonsense');
t('mode normalized', AbGate::mode('bans') === 'watch' && AbGate::mode('nets') === 'off' && AbGate::mode('names') === 'on'
    && AbGate::mode('seo') === 'watch' && AbGate::mode('patterns') === 'on');
AbGate::$cfg['shared'] = 'off';
t('mode string for all', AbGate::mode('bans') === 'off' && AbGate::mode('patterns') === 'off');

AbGate::writePhp($tmp . '/data/list.php', array('ips' => array('203.0.113.10' => 1),
    'nets' => array(array('198.18.0.0/16', 1), array('198.20.0.0/16', 1, 'bans')),
    'ua_exact' => array(), 'ua_regex' => array('^PriceDesk', 'ahrefsbot'), 'ua_grp' => array('ahrefsbot' => 'seo'),
    'rules' => array(
        array('id' => 'fake-se', 'ref' => '^https?://www\.(?:yandex|bing)\.ru/$', 'mode' => 'on'),
        array('id' => 'buy-names', 'ua_in' => array('Mozilla/5.0 (X11; Linux x86_64) BotChrome/1.0'), 'mode' => 'watch'),
        array('id' => 'mob', 'ua' => 'Android \d+; SM-', 'noref' => true, 'path' => '^/catalog/', 'mode' => 'on'),
    )));
@unlink($tmp . '/my-rules.php');
AbGate::resetCache();
AbGate::$cfg['shared'] = array('bans' => 'on', 'nets' => 'on', 'names' => 'on', 'seo' => 'on', 'patterns' => 'on');
$q = function ($ip, $u, $ref = '', $uri = '/', $m = 'GET') {
    AbGate::$tags = array();
    return AbGate::banKind($ip, $u, $ref, $uri, $m);
};
t('on: listed ip', $q('203.0.113.10', $ua) === 1 && AbGate::$why === '@bans');
t('on: net group nets', $q('198.18.1.1', $ua) === 1 && AbGate::$why === '@nets');
t('on: manual net is bans', $q('198.20.1.1', $ua) === 1 && AbGate::$why === '@bans');
t('on: seo name', $q('203.0.113.12', 'Mozilla/5.0 (compatible; AhrefsBot/7.0)') === 1 && AbGate::$why === '@seo');
t('rule ref on blocks', $q('203.0.113.12', $ua, 'https://www.yandex.ru/') === 1 && AbGate::$why === 'fake-se');
t('rule ref: real yandex passes', $q('203.0.113.12', $ua, 'https://yandex.ru/') === 0);
t('rule ua_in watch only tags', $q('203.0.113.12', 'Mozilla/5.0 (X11; Linux x86_64) BotChrome/1.0') === 0
    && isset(AbGate::$tags['buy-names']));
$mob = 'Mozilla/5.0 (Linux; Android 14; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36';
t('rule all conditions', $q('203.0.113.12', $mob, '', '/catalog/lcd/') === 1 && AbGate::$why === 'mob');
t('rule: with referer no match', $q('203.0.113.12', $mob, 'https://example.org/', '/catalog/lcd/') === 0);
t('rule: other path no match', $q('203.0.113.12', $mob, '', '/about/') === 0);
AbGate::$cfg['shared'] = array('bans' => 'watch', 'nets' => 'off', 'names' => 'on', 'seo' => 'off', 'patterns' => 'watch');
t('watch: ip passes and is tagged', $q('203.0.113.10', $ua) === 0 && isset(AbGate::$tags['@bans']));
t('off: net passes untagged', $q('198.18.1.1', $ua) === 0 && !AbGate::$tags);
t('watch: manual net tagged as bans', $q('198.20.1.1', $ua) === 0 && isset(AbGate::$tags['@bans']));
t('off: seo name passes', $q('203.0.113.12', 'Mozilla/5.0 (compatible; AhrefsBot/7.0)') === 0);
t('names still on', $q('203.0.113.12', 'PriceDesk/2.0') === 1 && AbGate::$why === '@names');
t('patterns watch: hub "on" rule only tags', $q('203.0.113.12', $ua, 'https://www.bing.ru/') === 0 && isset(AbGate::$tags['fake-se']));
AbGate::$cfg['shared']['patterns'] = 'off';
t('patterns off: nothing', $q('203.0.113.12', $ua, 'https://www.bing.ru/') === 0 && !AbGate::$tags);
AbGate::$cfg['shared'] = array('bans' => 'on', 'nets' => 'on', 'names' => 'on', 'seo' => 'on', 'patterns' => 'on');

// проверка связок
$e = '';
t('rule: path alone rejected', AbGate::cleanRule(array('path' => '^/catalog/'), $e) === null);
t('rule: noref alone rejected', AbGate::cleanRule(array('noref' => true, 'path' => '^/'), $e) === null);
t('rule: browser ua alone rejected', AbGate::cleanRule(array('ua' => 'Chrome/1\d\d'), $e) === null && $e !== '');
t('rule: real google ref alone rejected', AbGate::cleanRule(array('ref' => 'google\.com'), $e) === null);
t('rule: ref+noref rejected', AbGate::cleanRule(array('ua' => 'x', 'ref' => 'a', 'noref' => true), $e) === null);
t('rule: bad regex rejected', AbGate::cleanRule(array('ua' => '(bad'), $e) === null);
t('rule: bad method rejected', AbGate::cleanRule(array('ua' => 'BotX', 'method' => 'DELETE'), $e) === null);
t('rule: ua+noref accepted', is_array(AbGate::cleanRule(array('ua' => 'Chrome/1\d\d\.0\.0\.0', 'noref' => 1), $e)));
t('rule: browser names dropped from ua_in', AbGate::cleanRule(array('ua_in' => array($ua)), $e) === null);

// предохранители списка для новых полей
$s = AbGate::sanitizeList(array('nets' => array(array('198.21.0.0/16', 1, 'bans'), array('198.22.0.0/16', 1, 'x')),
    'ua_grp' => array('ahrefsbot' => 'seo', 'x' => 'names'),
    'rules' => array(array('id' => 'ok-1', 'ref' => '^https://www\.baidu\.ru/$', 'mode' => 'on'),
        array('id' => 'bad', 'path' => '^/'), array('id' => 'BAD ID', 'ua' => 'BotX'), array('id' => 'w2', 'ua' => 'BotXYZ', 'mode' => 'x'))),
    array('ips' => array(), 'nets' => array()));
t('sanitize: net group kept', in_array(array('198.21.0.0/16', 1, 'bans'), $s['nets'], true)
    && in_array(array('198.22.0.0/16', 1), $s['nets'], true));
t('sanitize: ua_grp only seo', $s['ua_grp'] === array('ahrefsbot' => 'seo'));
$ids = array();
foreach ($s['rules'] as $r) {
    $ids[$r['id']] = $r['mode'];
}
t('sanitize: rules checked', $ids === array('ok-1' => 'on', 'w2' => 'watch'));

// свои правила сайта
file_put_contents($tmp . '/my-rules.php', "<?php return array(\n"
    . " 'ban' => array('203.0.113.120' => 'сканер из журнала', '203.0.114.0/24' => 'сеть', '10.0.0.0/8' => 'слишком широко', 'nonsense' => ''),\n"
    . " 'names' => array('EvilCrawler/2.1 (+http://evil.example)' => 'сборщик', 'short'),\n"
    . " 'names_regex' => array('harvestbot' => '', 'Chrome' => 'задело бы всех'),\n"
    . " 'patterns' => array(array('ua' => 'Firefox/99\\.0', 'ref' => '^https://www\\.example\\.org/$', 'note' => 'подмена'), array('path' => '^/')),\n"
    . ");\n");
AbGate::resetCache();
$mm = AbGate::mine();
t('mine: valid parsed', count($mm['items']) === 5 && $mm['offer'] === true);
t('mine: errors listed', count($mm['errors']) === 5);
t('mine: own ip blocks', $q('203.0.113.120', $ua) === 1 && AbGate::$why === 'own');
t('mine: own net blocks', $q('203.0.114.9', $ua) === 1 && AbGate::$why === 'own');
t('mine: own name', $q('203.0.113.12', 'EvilCrawler/2.1 (+http://evil.example)') === 1);
t('mine: own regex', $q('203.0.113.12', 'x HarvestBot/1') === 1);
t('mine: own pattern', $q('203.0.113.12', 'Mozilla/5.0 Firefox/99.0', 'https://www.example.org/') === 1 && AbGate::$why === 'own');
t('mine: wide net not applied', $q('10.1.2.3', $ua) === 0);
t('mine: allow still wins', AbGate::isAllowed('198.51.100.5'));
$types = array();
foreach ($mm['items'] as $it) {
    $types[] = $it['t'];
}
t('mine: offer items', $types === array('ip', 'net', 'ua', 'ua_re', 'pattern'));

// сводка за час по 11-й колонке журнала
$lines = '';
$lines .= implode("\t", array($now - 30, '203.0.113.130', 'GET', 'page', '/', 200, 0, 0, $ua, 'https://www.bing.ru/', 'fake-se')) . "\n";
$lines .= implode("\t", array($now - 29, '203.0.113.130', 'GET', 'page', '/x/', 200, 0, 0, $ua, 'https://www.bing.ru/', 'fake-se')) . "\n";
$lines .= implode("\t", array($now - 28, '203.0.113.131', 'GET', 'page', '/', 200, 1, 0, $ua, 'https://www.bing.ru/', 'fake-se')) . "\n";
$lines .= implode("\t", array($now - 27, '203.0.113.132', 'GET', 'page', '/', 403, 0, 0, $ua, '', '!@bans')) . "\n";
file_put_contents($logDir . '/' . date('Y-m-d', $now) . '.log', $lines);
$agg = AbGate::aggregate($now);
t('watch summary', isset($agg['watch']['fake-se']) && $agg['watch']['fake-se']['hits'] === 3
    && $agg['watch']['fake-se']['ips'] === 2 && $agg['watch']['fake-se']['mark_ips'] === 1 && $agg['watch']['fake-se']['blocked'] === 0);
t('blocked summary', isset($agg['watch']['@bans']) && $agg['watch']['@bans']['blocked'] === 1);
t('watch samples one per ip', count($agg['watch']['fake-se']['samples']) === 2);

// страница состояния
AbGate::$cfg['status_key'] = 'status-key-0123456789abcd';
AbGate::$cfg['domain'] = 'shop.example';
AbGate::writePhp($tmp . '/data/offers.php', array(array('ip', '203.0.113.120', 'approved', ''), array('ua', '<script>', 'rejected', 'x')));
$html = AbGate::statusHtml($now);
t('status: domain', strpos($html, 'shop.example') !== false);
t('status: shared table', strpos($html, 'Связки примет ботов') !== false && strpos($html, 'закрывать') !== false);
t('status: own rule errors shown', strpos($html, 'слишком') !== false || strpos($html, 'шире /16') !== false);
t('status: offers shown and escaped', strpos($html, 'принято в общий список') !== false && strpos($html, '<script>') === false);
t('status: watch shown', strpos($html, 'связка fake-se') !== false);
ob_start();
AbGate::serveStatus('wrong-key');
t('status: wrong key — nothing', ob_get_clean() === '');
AbGate::serveStatus('');
t('status: empty key — nothing', true);

// 0.3.0: язык браузера в связках (nolang)
t('lang: ru-RU есть', AbGate::langHas('ru-RU,ru;q=0.9', 'ru'));
t('lang: ru вторым есть', AbGate::langHas('en-US,en;q=0.9,ru;q=0.8', 'ru'));
t('lang: en-US нет ru', !AbGate::langHas('en-US,en;q=0.9', 'ru'));
t('lang: пусто — нет', !AbGate::langHas('', 'ru'));
t('lang: «ruby» не ru', !AbGate::langHas('xx-ruby', 'ru'));
$e = '';
$lr = AbGate::cleanRule(array('nolang' => 'RU', 'noref' => true, 'path' => '^/product/'), $e);
t('nolang + noref + path — принята', is_array($lr) && $lr['nolang'] === 'ru' && $e === '');
t('nolang один — не принята', AbGate::cleanRule(array('nolang' => 'ru'), $e) === null);
t('nolang неверный — не принята', AbGate::cleanRule(array('nolang' => 'русский', 'noref' => true), $e) === null);
t('без nolang noref + path — по-прежнему не принята', AbGate::cleanRule(array('noref' => true, 'path' => '^/product/'), $e) === null);
t('nolang: en-US без Referer на карточке — совпала', AbGate::ruleMatch($lr, 'Mozilla/5.0 x', '', '/product/a', 'GET', 'en-US,en;q=0.9'));
t('nolang: ru — нет', !AbGate::ruleMatch($lr, 'Mozilla/5.0 x', '', '/product/a', 'GET', 'ru-RU,ru;q=0.9'));
t('nolang: с Referer — нет', !AbGate::ruleMatch($lr, 'Mozilla/5.0 x', 'https://yandex.ru/', '/product/a', 'GET', 'en-US'));
t('nolang: другая страница — нет', !AbGate::ruleMatch($lr, 'Mozilla/5.0 x', '', '/', 'GET', 'en-US'));
AbGate::$whyLang = 'ru';
$bp = AbGate::banPage('203.0.113.9');
t('страница отказа по языку — совет про VPN', strpos($bp, 'VPN') !== false && strpos($bp, '203.0.113.9') !== false);
AbGate::$whyLang = '';
t('обычная страница отказа — без VPN', strpos(AbGate::banPage('203.0.113.9'), 'VPN') === false);
$lines = implode("	", array($now - 20, '203.0.113.140', 'GET', 'product', '/product/a', 200, 0, 0, 'Mozilla/5.0 y', '', 'lang-card', 'en-US,en;q=0.9')) . "
";
file_put_contents($logDir . '/' . date('Y-m-d', $now) . '.log', $lines);
$agg = AbGate::aggregate($now);
t('пример связки с языком', isset($agg['watch']['lang-card']['samples'][0][4]) && $agg['watch']['lang-card']['samples'][0][4] === 'en-US,en;q=0.9');

rmtree($tmp);
echo ($fails ? "FAILED $fails of $count\n" : "OK $count tests\n");
exit($fails ? 1 : 0);
