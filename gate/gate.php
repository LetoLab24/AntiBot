<?php
// AntiBot gate — привратник для сайтов на обычном хостинге (PHP 7.0+, без зависимостей).
// Выполняется перед сайтом: auto_prepend_file, mu-plugin WordPress или строкой require. Описание — README-gate.md.
// Из хаба приходят только данные (списки банов, связки примет и настройки), код сторож не получает и не выполняет.
// Что брать из общего списка, решает сайт сам ('shared' в config.php): хаб это переопределить не может.
// Свои правила сайта (my-rules.php) действуют здесь сразу; в общий список они уходят только предложением.

if (!class_exists('AbGate', false)) {

final class AbGate
{
    const VERSION = '0.3.0';
    const GROUPS = array('bans', 'nets', 'names', 'seo', 'patterns');

    public static $cfg = array();
    public static $ip = '';
    public static $ua = '';
    public static $ref = '';
    public static $al = '';         // Accept-Language (с 0.3.0)
    public static $whyLang = '';    // запрос закрыла связка по языку — на странице отказа совет про VPN
    public static $why = '';
    public static $tags = array();
    public static $uri = '/';
    public static $method = 'GET';
    public static $kind = 'other';
    public static $hasMark = false;
    public static $exempt = false;
    public static $started = 0.0;
    public static $logged = false;
    private static $done = false;
    private static $list = null;
    private static $mine = null;
    private static $postError = '';
    private static $obDone = false;

    public static function defaults()
    {
        return array(
            'domain' => '',
            'contact' => '',
            'engine' => 'wordpress',
            'data_dir' => __DIR__ . '/data',
            'secret' => '',
            'hub_url' => '',
            'site_token' => '',
            'hub_public_key' => '',
            'sync_interval' => 60,
            'hub_timeout' => 3,
            'trusted_proxies' => array(),
            'server_ips' => array(),
            'allow' => array(),
            'mark' => true,
            'mark_url' => '/?abg=m',
            'challenge' => false,
            'challenge_pages' => 30,
            'suspect_pages' => 20,
            'rate_hour' => 600,
            'head_hits' => 20,
            'scan_hits' => 3,
            'local_scan_ban' => true,
            'local_scan_hours' => 720,
            'max_new_bans' => 10000,
            'log_days' => 14,
            'paths' => array(),
            // что брать из общего списка: on — закрывать, watch — только отмечать, off — не брать
            'shared' => array('bans' => 'on', 'nets' => 'on', 'names' => 'on', 'seo' => 'on', 'patterns' => 'on'),
            'rules_file' => '',
            'status_key' => '',
        );
    }

    // ------------------------------------------------------------------ запуск

    public static function load($cfgFile)
    {
        $cfg = is_file($cfgFile) ? include $cfgFile : null;
        if (!is_array($cfg)) {
            return false;
        }
        self::$cfg = array_merge(self::defaults(), $cfg);
        if (self::$cfg['secret'] === '' || strlen(self::$cfg['secret']) < 16) {
            return false;
        }
        $dir = self::$cfg['data_dir'];
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            return false;
        }
        if (!is_file($dir . '/.htaccess') && is_file(__DIR__ . '/data.htaccess')) {
            @copy(__DIR__ . '/data.htaccess', $dir . '/.htaccess');
        }
        $over = self::readPhp($dir . '/settings.php');
        if (is_array($over)) {
            self::$cfg = array_merge(self::$cfg, self::cleanSettings($over));
        }
        return true;
    }

    public static function run($cfgFile)
    {
        if (self::$done) {
            return;
        }
        self::$done = true;
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return;
        }
        if (!self::load($cfgFile)) {
            return;
        }
        self::$started = microtime(true);
        self::$uri = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '/';
        self::$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string)$_SERVER['REQUEST_METHOD']) : 'GET';
        self::$ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
        self::$ref = isset($_SERVER['HTTP_REFERER']) ? (string)$_SERVER['HTTP_REFERER'] : '';
        self::$al = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? substr((string)$_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 200) : '';
        $path = self::path(self::$uri);
        if ($path === '/wp-cron.php') {
            return;
        }
        self::$ip = self::clientIp($_SERVER);
        if ($path === '/' && isset($_GET['abg']) && $_GET['abg'] === 'm') {
            self::serveMarkJs();
        }
        if ($path === '/' && isset($_GET['abg']) && $_GET['abg'] === 's') {
            self::serveStatus(isset($_GET['k']) ? (string)$_GET['k'] : '');
        }
        self::$hasMark = self::checkMark(isset($_COOKIE['abm']) ? (string)$_COOKIE['abm'] : '', self::$ip, time());
        self::$kind = self::classify(self::$method, self::$uri);
        register_shutdown_function(array('AbGate', 'shutdown'));

        self::$exempt = self::isAllowed(self::$ip) || self::isSearchEngine(self::$ip, self::$ua);
        if (!self::$exempt) {
            $ban = self::banKind(self::$ip, self::$ua);
            if ($ban) {
                self::deny($ban);
            }
            if (self::$kind === 'probe' || self::$kind === 'sqli') {
                self::countProbe(self::$ip, self::$kind === 'sqli' ? (int)self::$cfg['scan_hits'] : 1);
            }
        }
        if ($path === '/' && isset($_GET['abg']) && $_GET['abg'] === 't') {
            self::serveToken();
        }
        if (!self::$exempt) {
            if (self::$cfg['challenge'] && !self::$hasMark && self::$method === 'GET'
                && in_array(self::$kind, array('page', 'catalog', 'product', 'search'), true) && !self::isAjax()) {
                $n = self::bumpHour('ch', self::$ip);
                if ($n > (int)self::$cfg['challenge_pages']) {
                    self::serveChallenge();
                }
            }
        }
        if (self::$cfg['mark'] && self::$method === 'GET' && !self::isAjax()
            && !in_array(self::$kind, array('static', 'js', 'probe', 'sqli'), true)) {
            ob_start(array('AbGate', 'obInsert'));
        }
    }

    // ------------------------------------------------------------------ адрес и классы запроса

    public static function clientIp(array $srv)
    {
        $ip = self::rawClientIp($srv);
        $bin = @inet_pton($ip);
        return $bin === false ? $ip : inet_ntop($bin);
    }

    private static function rawClientIp(array $srv)
    {
        $remote = isset($srv['REMOTE_ADDR']) ? trim((string)$srv['REMOTE_ADDR']) : '';
        if ($remote !== '' && self::$cfg['trusted_proxies'] && self::inList($remote, self::$cfg['trusted_proxies'])) {
            foreach (array('HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR') as $h) {
                if (!empty($srv[$h])) {
                    $parts = array_map('trim', explode(',', (string)$srv[$h]));
                    for ($i = count($parts) - 1; $i >= 0; $i--) {
                        $p = $parts[$i];
                        if (filter_var($p, FILTER_VALIDATE_IP) && !self::inList($p, self::$cfg['trusted_proxies'])) {
                            return $p;
                        }
                    }
                }
            }
        }
        return $remote;
    }

    public static function path($uri)
    {
        $p = strtok($uri, '?');
        return ($p === false || $p === '') ? '/' : $p;
    }

    public static function patterns()
    {
        $engines = array(
            'wordpress' => array(
                'product' => '^/product/[^/?]+/?$',
                'catalog' => '^/product-(?:category|tag)/|^/shop/?$|^/category/',
                'search' => '[?&]s=',
                'js' => '[?&]wc-ajax=|^/wp-admin/admin-ajax\.php|^/wp-json/',
                'own' => '^/wp-(?:admin|content|includes|json)/|^/wp-(?:login|cron)\.php|[?&]rest_route=',
            ),
            'opencart' => array(
                'product' => '[?&]route=product/product\b',
                'catalog' => '[?&]route=product/(?:category|manufacturer)\b',
                'search' => '[?&]route=product/search\b',
                'js' => '[?&]route=(?:common/cart/info|checkout/cart/add|extension/)',
                'own' => '^/(?:admin|image|catalog/view)/',
            ),
            'bitrix' => array(
                'product' => '',
                'catalog' => '^/catalog/',
                'search' => '^/(?:search|catalog)/?(?:index\.php)?\?(?:.*&)?q=',
                'js' => '[?&](?:bxajaxid|ajax_call|ajax_mode)=|^/bitrix/(?:services|tools|components)/',
                'own' => '^/(?:bitrix|local|upload)/',
            ),
            'custom' => array(
                'product' => '', 'catalog' => '', 'search' => '[?&](?:q|s|search)=',
                'js' => '[?&](?:ajax)=|/ajax(?:/|\.php)', 'own' => '',
            ),
        );
        $e = isset($engines[self::$cfg['engine']]) ? $engines[self::$cfg['engine']] : $engines['custom'];
        if (is_array(self::$cfg['paths'])) {
            foreach (self::$cfg['paths'] as $k => $v) {
                if (isset($e[$k]) && is_string($v)) {
                    $e[$k] = $v;
                }
            }
        }
        return $e;
    }

    public static function rx($re, $s)
    {
        return $re !== '' && @preg_match('~' . str_replace('~', '\~', $re) . '~i', $s) === 1;
    }

    public static function classify($method, $uri)
    {
        $path = self::path($uri);
        $q = strpos($uri, '?') !== false ? substr($uri, strpos($uri, '?') + 1) : '';
        $dq = strtolower(rawurldecode(str_replace('+', ' ', $q)));
        if (self::rx('\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|otf|eot|ico|mp4|webm)$', $path)) {
            return 'static';
        }
        if ($dq !== '' && self::isSqli($dq)) {
            return 'sqli';
        }
        if ($path === '/' && preg_match('~(?:^|&)abg=[mts](?:&|$)~', $q)) {
            return 'js';
        }
        $e = self::patterns();
        $own = self::rx($e['own'], $uri);
        if (self::isProbe($path, $uri, $own)) {
            return 'probe';
        }
        if (self::rx($e['js'], $uri)) {
            return 'js';
        }
        if (self::rx($e['search'], $uri)) {
            return 'search';
        }
        if (self::rx($e['product'], $uri)) {
            return 'product';
        }
        if (self::rx($e['catalog'], $uri)) {
            return 'catalog';
        }
        if ($own) {
            return 'other';
        }
        if (preg_match('~^/$|^/[^.?]*$|\.html?$|\.php$~', $path)) {
            return 'page';
        }
        return 'other';
    }

    public static function isProbe($path, $uri, $own)
    {
        $paths = array(
            '/\.(?:env|git|svn|hg|aws|ssh|ds_store|htpasswd)',
            '(?:^|/)(?:backup|backups|dump|db|database|site|www|public_html)\.(?:zip|tar|tgz|tar\.gz|rar|7z|sql|sql\.gz)$',
            '\.(?:sql|sql\.gz|bak|old|swp|save)$',
            '/vendor/phpunit', 'eval-stdin', 'phpinfo\.php', '^/(?:cgi-bin/|actuator|server-status)',
            '(?:^|/)(?:aws[_-]?(?:credentials|config)|azure(?:ad)?\.json|boto\.cfg|gcloud/|(?:service[_-]?account|credentials)\.json|secrets?\.(?:json|ya?ml))',
            '\.\./|%2e%2e|/etc/passwd',
        );
        foreach ($paths as $re) {
            if (self::rx($re, $uri)) {
                return true;
            }
        }
        if ($own) {
            return false;
        }
        $cms = array(
            '^/(?:wp-login\.php|xmlrpc\.php|wp-admin/|wp-content/(?:plugins|themes)/|wp-includes/|phpmyadmin|pma/|adminer)',
            '^/(?:[^/]+/)*(?:xmlrpc\.php|wp-login\.php|wp-config\.php)',
            '^/(?:[^/]+/)*\.(?!well-known/)[\w-]',
        );
        foreach ($cms as $re) {
            if (self::rx($re, $path)) {
                return true;
            }
        }
        return false;
    }

    public static function isSqli($dq)
    {
        $re = array(
            '\bunion\b[\s(/*+]+(?:all[\s(/*+]+|distinct[\s(/*+]+)?select\b',
            '\b(?:extractvalue|updatexml)\s*\(', '\b(?:sleep|pg_sleep)\s*\(\s*\d', '\bbenchmark\s*\(\s*\d',
            '\bwaitfor\s+delay\b', '\border\s+by\s+\d+\s*(?:--|#|/\*)',
            '[\'"]\s*\)*\s*(?:and|or)\s+\(*\s*[\'"]?\w+[\'"]?\s*(?:=|<|>|like\b)',
            '\binformation_schema\b', '\bconcat(?:_ws)?\s*\(\s*0x', '@@version\b',
            '\bselect\b[^&]{0,60}\bfrom\b[^&]{0,60}\b(?:where|dual|limit)\b',
            ';\s*(?:drop|truncate|alter)\s+table\b', '\bload_file\s*\(', '\binto\s+(?:out|dump)file\b',
        );
        foreach ($re as $r) {
            if (self::rx($r, $dq)) {
                return true;
            }
        }
        return false;
    }

    public static function isAjax()
    {
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
            return true;
        }
        $acc = isset($_SERVER['HTTP_ACCEPT']) ? (string)$_SERVER['HTTP_ACCEPT'] : '';
        return $acc !== '' && stripos($acc, 'text/html') === false && stripos($acc, '*/*') === false;
    }

    // ------------------------------------------------------------------ сети

    public static function cidr($net)
    {
        $net = trim((string)$net);
        if (strpos($net, '/') === false) {
            $bin = @inet_pton($net);
            return $bin === false ? null : array($bin, strlen($bin) * 8);
        }
        list($a, $len) = explode('/', $net, 2);
        $bin = @inet_pton(trim($a));
        if ($bin === false || !ctype_digit(trim($len))) {
            return null;
        }
        $len = (int)$len;
        if ($len > strlen($bin) * 8) {
            return null;
        }
        return array($bin, $len);
    }

    public static function inNet($ipBin, $net)
    {
        if ($net === null || strlen($ipBin) !== strlen($net[0])) {
            return false;
        }
        $bytes = intdiv($net[1], 8);
        $bits = $net[1] % 8;
        if ($bytes && substr($ipBin, 0, $bytes) !== substr($net[0], 0, $bytes)) {
            return false;
        }
        if ($bits) {
            $mask = (0xFF << (8 - $bits)) & 0xFF;
            return (ord($ipBin[$bytes]) & $mask) === (ord($net[0][$bytes]) & $mask);
        }
        return true;
    }

    public static function inList($ip, array $nets)
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach ($nets as $k => $v) {
            $n = is_string($k) ? $k : $v;
            if (self::inNet($bin, self::cidr($n))) {
                return true;
            }
        }
        return false;
    }

    public static function isAllowed($ip)
    {
        return $ip === '' || self::inList($ip, (array)self::$cfg['server_ips']) || self::inList($ip, (array)self::$cfg['allow']);
    }

    public static function seNets()
    {
        return array('95.163.32.0/19', '90.156.232.0/21', '217.174.190.0/23');
    }

    public static function isSearchEngine($ip, $ua)
    {
        $se = array(
            'google' => array('googlebot|google-inspectiontool|googleother|adsbot-google|storebot-google|mediapartners-google|google-read-aloud|apis-google|feedfetcher-google', array('.googlebot.com', '.google.com')),
            'yandex' => array('compatible; ?ya|yandex\.com/bots|yandex\w*bot', array('.yandex.ru', '.yandex.net', '.yandex.com')),
            'bing' => array('bingbot|msnbot|bingpreview|adidxbot', array('.search.msn.com')),
            'mailru' => array('mail\.ru_bot', array()),
        );
        foreach ($se as $name => $d) {
            if (!self::rx($d[0], $ua)) {
                continue;
            }
            if ($name === 'mailru') {
                return self::inList($ip, self::seNets());
            }
            return self::rdnsOk($ip, $d[1]);
        }
        return false;
    }

    public static function rdnsOk($ip, array $suffixes)
    {
        $f = self::$cfg['data_dir'] . '/dns/' . sha1($ip . '|' . implode(',', $suffixes)) . '.txt';
        $c = @file_get_contents($f);
        if ($c !== false) {
            list($st, $ts) = array_pad(explode('|', $c, 2), 2, '0');
            $ttl = $st === 'err' ? 3600 : 7 * 86400;
            if (time() - (int)$ts < $ttl) {
                return $st === 'ok';
            }
        }
        $host = @gethostbyaddr($ip);
        $st = 'err';
        if ($host !== false && $host !== $ip) {
            $st = 'no';
            foreach ($suffixes as $s) {
                if (substr(strtolower($host), -strlen($s)) === $s) {
                    $back = strpos($ip, ':') !== false ? self::aaaa($host) : (array)@gethostbynamel($host);
                    $st = in_array($ip, $back, true) ? 'ok' : 'no';
                    break;
                }
            }
        }
        @mkdir(dirname($f), 0750, true);
        @file_put_contents($f, $st . '|' . time(), LOCK_EX);
        return $st === 'ok';
    }

    private static function aaaa($host)
    {
        $out = array();
        $r = @dns_get_record($host, DNS_AAAA);
        if (is_array($r)) {
            foreach ($r as $x) {
                if (isset($x['ipv6'])) {
                    $out[] = inet_ntop(inet_pton($x['ipv6']));
                }
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------ баны

    public static function readPhp($file)
    {
        if (!is_file($file)) {
            return null;
        }
        $v = @include $file;
        return is_array($v) ? $v : null;
    }

    public static function lists()
    {
        if (self::$list === null) {
            $l = self::readPhp(self::$cfg['data_dir'] . '/list.php');
            $loc = self::readPhp(self::$cfg['data_dir'] . '/local.php');
            self::$list = array(
                'ips' => isset($l['ips']) ? (array)$l['ips'] : array(),
                'nets' => isset($l['nets']) ? (array)$l['nets'] : array(),
                'ua_exact' => isset($l['ua_exact']) ? (array)$l['ua_exact'] : array(),
                'ua_regex' => isset($l['ua_regex']) ? (array)$l['ua_regex'] : array(),
                'ua_grp' => isset($l['ua_grp']) ? (array)$l['ua_grp'] : array(),
                'rules' => self::prepRules(isset($l['rules']) ? (array)$l['rules'] : array()),
                'local' => is_array($loc) ? $loc : array(),
            );
        }
        return self::$list;
    }

    public static function prepRules(array $rules)
    {
        foreach ($rules as $i => $r) {
            if (!empty($r['ua_in']) && is_array($r['ua_in'])) {
                $rules[$i]['ua_set'] = array_fill_keys($r['ua_in'], 1);
            }
        }
        return $rules;
    }

    public static function resetCache()
    {
        self::$list = null;
        self::$mine = null;
    }

    // Выбор сайта для группы общего списка: on, watch (только отметить в журнале и сводке) или off.
    public static function mode($group)
    {
        $s = self::$cfg['shared'];
        if (!is_array($s)) {
            $s = array_fill_keys(self::GROUPS, $s);
        }
        if (!array_key_exists($group, $s)) {
            return 'on';
        }
        $v = $s[$group];
        if ($v === true || $v === 1) {
            return 'on';
        }
        if ($v === false || $v === 0 || $v === null) {
            return 'off';
        }
        $v = strtolower(trim((string)$v));
        return in_array($v, array('on', 'watch', 'off'), true) ? $v : 'watch';
    }

    public static function sharedModes()
    {
        $out = array();
        foreach (self::GROUPS as $g) {
            $out[$g] = self::mode($g);
        }
        return $out;
    }

    private static function verdict($tag, $mode, $kind)
    {
        if ($mode === 'on') {
            self::$why = $tag;
            return $kind;
        }
        if ($mode === 'watch') {
            self::$tags[$tag] = 1;
        }
        return 0;
    }

    // Связка примет: все указанные условия сразу. ua, ref, path — регулярные выражения без учёта регистра,
    // ua_in — имена целиком, noref — без Referer, method — GET/POST/HEAD, nolang — среди языков браузера нет такого
    // (например ru: у покупателей из России он есть почти всегда, у сборщиков с зарубежных адресов — en-US).
    public static function ruleMatch(array $r, $ua, $ref, $uri, $method, $al = null)
    {
        if (!empty($r['nolang']) && self::langHas($al === null ? self::$al : (string)$al, $r['nolang'])) {
            return false;
        }
        if (!empty($r['method']) && $method !== $r['method']) {
            return false;
        }
        if (!empty($r['noref']) && $ref !== '') {
            return false;
        }
        if (isset($r['ref']) && $r['ref'] !== '' && ($ref === '' || !self::rx($r['ref'], $ref))) {
            return false;
        }
        if (isset($r['ua_set']) && !isset($r['ua_set'][$ua])) {
            return false;
        }
        if (isset($r['ua']) && $r['ua'] !== '' && !self::rx($r['ua'], $ua)) {
            return false;
        }
        if (isset($r['path']) && $r['path'] !== '' && !self::rx($r['path'], $uri)) {
            return false;
        }
        return true;
    }

    // Есть ли язык среди языков браузера: «ru-RU,ru;q=0.9» и «en-US,en;q=0.9,ru;q=0.8» — да, «en-US,en;q=0.9» и пусто — нет.
    public static function langHas($al, $lang)
    {
        return (bool)preg_match('~(?:^|[^a-z])' . preg_quote((string)$lang, '~') . '(?:[^a-z]|$)~i', (string)$al);
    }

    // Порядок: свои правила сайта, сканер на месте, затем общий список по выбору сайта (shared).
    // Белый список и поисковики сюда не доходят (exempt раньше).
    public static function banKind($ip, $ua, $ref = null, $uri = null, $method = null)
    {
        $ref = $ref === null ? self::$ref : (string)$ref;
        $uri = $uri === null ? self::$uri : (string)$uri;
        $method = $method === null ? self::$method : strtoupper((string)$method);
        self::$why = '';
        $l = self::lists();
        if (self::matchMine(self::mine(), $ip, $ua, $ref, $uri, $method)) {
            self::$why = 'own';
            return 1;
        }
        if (isset($l['local'][$ip]) && (int)$l['local'][$ip] > time()) {
            self::$why = 'local';
            return 1;
        }
        if (isset($l['ips'][$ip])) {
            $r = self::verdict('@bans', self::mode('bans'), (int)$l['ips'][$ip] === 2 ? 2 : 1);
            if ($r) {
                return $r;
            }
        }
        $bin = @inet_pton($ip);
        if ($bin !== false) {
            foreach ($l['nets'] as $n) {
                if (!self::inNet($bin, self::cidr(is_array($n) ? $n[0] : $n))) {
                    continue;
                }
                $g = (is_array($n) && isset($n[2]) && $n[2] === 'bans') ? 'bans' : 'nets';
                $r = self::verdict('@' . $g, self::mode($g), (is_array($n) && isset($n[1]) && (int)$n[1] === 2) ? 2 : 1);
                if ($r) {
                    return $r;
                }
            }
        }
        if ($ua !== '') {
            if (in_array($ua, $l['ua_exact'], true)) {
                $g = (isset($l['ua_grp'][$ua]) && $l['ua_grp'][$ua] === 'seo') ? 'seo' : 'names';
                $r = self::verdict('@' . $g, self::mode($g), 1);
                if ($r) {
                    return $r;
                }
            }
            foreach ($l['ua_regex'] as $re) {
                if (self::rx($re, $ua)) {
                    $g = (isset($l['ua_grp'][$re]) && $l['ua_grp'][$re] === 'seo') ? 'seo' : 'names';
                    $r = self::verdict('@' . $g, self::mode($g), 1);
                    if ($r) {
                        return $r;
                    }
                }
            }
        }
        $pm = self::mode('patterns');
        if ($pm !== 'off') {
            foreach ($l['rules'] as $rule) {
                if (self::ruleMatch($rule, $ua, $ref, $uri, $method)) {
                    $r = self::verdict((string)$rule['id'], ($pm === 'on' && $rule['mode'] === 'on') ? 'on' : 'watch', 1);
                    if ($r) {
                        self::$whyLang = !empty($rule['nolang']) ? (string)$rule['nolang'] : '';
                        return $r;
                    }
                }
            }
        }
        return 0;
    }

    // ------------------------------------------------------------------ свои правила сайта (my-rules.php)

    public static function realRefs()
    {
        return array('https://www.google.com/', 'https://yandex.ru/', 'https://ya.ru/', 'https://yandex.com/',
            'https://www.bing.com/', 'https://duckduckgo.com/', 'https://go.mail.ru/');
    }

    // Проверка связки (своей или из хаба): одно условие по адресу страницы или «без Referer» задело бы людей.
    public static function cleanRule($r, &$err)
    {
        $err = '';
        if (!is_array($r)) {
            $err = 'связка — не массив';
            return null;
        }
        $out = array();
        foreach (array('ua', 'ref', 'path') as $k) {
            if (!isset($r[$k]) || $r[$k] === '') {
                continue;
            }
            if (!is_string($r[$k]) || strlen($r[$k]) > 1000
                || @preg_match('~' . str_replace('~', '\~', $r[$k]) . '~i', '') === false) {
                $err = $k . ': неверное регулярное выражение';
                return null;
            }
            $out[$k] = $r[$k];
        }
        if (!empty($r['ua_in']) && is_array($r['ua_in'])) {
            $samples = self::browserSamples();
            $names = array();
            foreach ($r['ua_in'] as $u) {
                if (is_string($u) && strlen($u) >= 8 && strlen($u) <= 512 && !in_array($u, $samples, true)) {
                    $names[$u] = 1;
                }
            }
            if ($names) {
                $out['ua_in'] = array_keys($names);
            }
        }
        if (!empty($r['noref'])) {
            $out['noref'] = true;
        }
        if (isset($r['nolang']) && $r['nolang'] !== '' && $r['nolang'] !== false) {
            $l = strtolower((string)$r['nolang']);
            if (!preg_match('~^[a-z]{2,3}$~', $l)) {
                $err = 'nolang: код языка из 2–3 латинских букв, например ru';
                return null;
            }
            $out['nolang'] = $l;
        }
        if (!empty($r['method'])) {
            $m = strtoupper((string)$r['method']);
            if (!in_array($m, array('GET', 'POST', 'HEAD'), true)) {
                $err = 'method: GET, POST или HEAD';
                return null;
            }
            $out['method'] = $m;
        }
        // язык браузера вместе с «без Referer» или адресом страницы — достаточно: у людей нужный язык есть почти всегда
        if (empty($out['ua']) && empty($out['ua_in']) && empty($out['ref'])
            && !(!empty($out['nolang']) && (!empty($out['noref']) || !empty($out['path'])))) {
            $err = 'нужно ua, ua_in, ref или nolang вместе с noref или path: по одному адресу страницы или «без Referer» ходят и люди';
            return null;
        }
        if (!empty($out['ref']) && !empty($out['noref'])) {
            $err = 'ref и noref вместе никогда не сработают';
            return null;
        }
        if (!empty($out['ua']) && empty($out['ref']) && empty($out['noref']) && empty($out['path']) && empty($out['ua_in'])) {
            foreach (self::browserSamples() as $s) {
                if (self::rx($out['ua'], $s)) {
                    $err = 'ua задевает обычные браузеры';
                    return null;
                }
            }
        }
        if (!empty($out['ref']) && empty($out['ua']) && empty($out['ua_in'])) {
            foreach (self::realRefs() as $s) {
                if (self::rx($out['ref'], $s)) {
                    $err = 'ref задевает обычные переходы из поиска';
                    return null;
                }
            }
        }
        return $out;
    }

    public static function rulesFile()
    {
        $f = (string)self::$cfg['rules_file'];
        return $f !== '' ? $f : __DIR__ . '/my-rules.php';
    }

    // Свои правила: действуют на сайте сразу и всегда (кроме белого списка); с 'offer' => true — ещё и предложением в хаб.
    public static function mine()
    {
        if (self::$mine !== null) {
            return self::$mine;
        }
        $m = array('ips' => array(), 'nets' => array(), 'names' => array(), 'regex' => array(), 'rules' => array(),
            'offer' => false, 'errors' => array(), 'items' => array());
        $raw = self::readPhp(self::rulesFile());
        if (!is_array($raw)) {
            return self::$mine = $m;
        }
        $m['offer'] = !isset($raw['offer']) || (bool)$raw['offer'];
        $pairs = function ($v) {
            $out = array();
            foreach (is_array($v) ? $v : array() as $k => $x) {
                $out[] = is_string($k) ? array(trim($k), (string)$x) : array(trim((string)$x), '');
            }
            return $out;
        };
        $samples = self::browserSamples();
        foreach ($pairs(isset($raw['ban']) ? $raw['ban'] : null) as $p) {
            $c = self::cidr($p[0]);
            if ($c === null) {
                $m['errors'][] = 'ban: «' . $p[0] . '» — не адрес и не сеть';
                continue;
            }
            $isNet = strpos($p[0], '/') !== false && $c[1] < strlen($c[0]) * 8;
            if ($isNet && $c[1] < (strlen($c[0]) === 4 ? 16 : 48)) {
                $m['errors'][] = 'ban: «' . $p[0] . '» — сеть шире /16 (IPv6 /48)';
                continue;
            }
            if ($isNet) {
                $m['nets'][] = $c;
                $m['items'][] = array('t' => 'net', 'v' => $p[0], 'note' => substr($p[1], 0, 200));
            } else {
                $ip = inet_ntop($c[0]);
                $m['ips'][$ip] = 1;
                $m['items'][] = array('t' => 'ip', 'v' => $ip, 'note' => substr($p[1], 0, 200));
            }
        }
        foreach ($pairs(isset($raw['names']) ? $raw['names'] : null) as $p) {
            if (strlen($p[0]) < 8 || in_array($p[0], $samples, true)) {
                $m['errors'][] = 'names: «' . substr($p[0], 0, 80) . '» — короче 8 знаков или обычный браузер';
                continue;
            }
            $m['names'][$p[0]] = 1;
            $m['items'][] = array('t' => 'ua', 'v' => $p[0], 'note' => substr($p[1], 0, 200));
        }
        foreach ($pairs(isset($raw['names_regex']) ? $raw['names_regex'] : null) as $p) {
            $bad = strlen($p[0]) < 4 || @preg_match('~' . str_replace('~', '\~', $p[0]) . '~i', '') === false;
            foreach ($bad ? array() : $samples as $s) {
                if (self::rx($p[0], $s)) {
                    $bad = true;
                    break;
                }
            }
            if ($bad) {
                $m['errors'][] = 'names_regex: «' . substr($p[0], 0, 80) . '» — неверное, короче 4 знаков или задевает обычные браузеры';
                continue;
            }
            $m['regex'][] = $p[0];
            $m['items'][] = array('t' => 'ua_re', 'v' => $p[0], 'note' => substr($p[1], 0, 200));
        }
        foreach (isset($raw['patterns']) && is_array($raw['patterns']) ? $raw['patterns'] : array() as $i => $r) {
            $err = '';
            $c = self::cleanRule($r, $err);
            if ($c === null) {
                $m['errors'][] = 'patterns[' . $i . ']: ' . $err;
                continue;
            }
            $m['items'][] = array('t' => 'pattern', 'v' => $c,
                'note' => is_array($r) && isset($r['note']) ? substr((string)$r['note'], 0, 200) : '');
            $m['rules'][] = $c;
        }
        $m['rules'] = self::prepRules($m['rules']);
        return self::$mine = $m;
    }

    public static function matchMine(array $m, $ip, $ua, $ref, $uri, $method)
    {
        if (isset($m['ips'][$ip])) {
            return true;
        }
        if ($m['nets']) {
            $bin = @inet_pton($ip);
            if ($bin !== false) {
                foreach ($m['nets'] as $c) {
                    if (self::inNet($bin, $c)) {
                        return true;
                    }
                }
            }
        }
        if ($ua !== '') {
            if (isset($m['names'][$ua])) {
                return true;
            }
            foreach ($m['regex'] as $re) {
                if (self::rx($re, $ua)) {
                    return true;
                }
            }
        }
        foreach ($m['rules'] as $r) {
            if (self::ruleMatch($r, $ua, $ref, $uri, $method)) {
                self::$whyLang = !empty($r['nolang']) ? (string)$r['nolang'] : '';
                return true;
            }
        }
        return false;
    }

    public static function banPage($ip)
    {
        $c = (string)self::$cfg['contact'];
        $h = htmlspecialchars($c, ENT_QUOTES, 'UTF-8');
        if ($c === '') {
            $how = 'напишите владельцу сайта';
        } elseif (strpos($c, '@') !== false && strpos($c, '/') === false) {
            $how = 'напишите на <a href="mailto:' . $h . '">' . $h . '</a>';
        } elseif (preg_match('~^https?://~', $c)) {
            $how = 'напишите нам: <a href="' . $h . '">' . $h . '</a>';
        } else {
            $how = 'напишите нам: ' . $h;
        }
        $ipH = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        $dom = htmlspecialchars((string)self::$cfg['domain'], ENT_QUOTES, 'UTF-8');
        if (self::$whyLang !== '') {
            return '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
                . 'initial-scale=1"><meta name="robots" content="noindex"><title>Страница не открылась' . ($dom ? ' — ' . $dom : '')
                . '</title></head><body style="margin:0;background:#f5f6f8;color:#222;font:16px/1.55 Arial,Helvetica,sans-serif">'
                . '<div style="max-width:560px;margin:48px auto;padding:28px 24px;background:#fff;border-radius:10px;'
                . 'box-shadow:0 1px 4px rgba(0,0,0,.08)"><h1 style="margin:0 0 14px;font-size:22px">Страница не открылась</h1>'
                . '<p>Похоже, вы заходите через VPN или браузер настроен не на русский язык — так к сайту часто приходят '
                . 'программы-сборщики. Отключите VPN или добавьте русский язык в настройках браузера и откройте страницу заново.</p>'
                . '<p>Если не помогло, ' . $how . ' и укажите ваш адрес: <b>' . $ipH . '</b>.</p></div></body></html>';
        }
        return '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            . 'initial-scale=1"><meta name="robots" content="noindex"><title>Доступ временно ограничен' . ($dom ? ' — ' . $dom : '')
            . '</title></head><body style="margin:0;background:#f5f6f8;color:#222;font:16px/1.55 Arial,Helvetica,sans-serif">'
            . '<div style="max-width:560px;margin:48px auto;padding:28px 24px;background:#fff;border-radius:10px;'
            . 'box-shadow:0 1px 4px rgba(0,0,0,.08)"><h1 style="margin:0 0 14px;font-size:22px">Доступ временно ограничен</h1>'
            . '<p>С вашего адреса <b>' . $ipH . '</b> на сайт приходило очень много автоматических запросов, поэтому доступ '
            . 'к сайту с него на время закрыт.</p><p>Если вы видите эту страницу по ошибке, ' . $how
            . ' и укажите ваш адрес: <b>' . $ipH . '</b>.</p></div></body></html>';
    }

    public static function deny($kind)
    {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex');
        }
        if ($kind !== 2) {
            echo self::banPage(self::$ip);
        }
        exit;
    }

    // ------------------------------------------------------------------ счётчики

    public static function bumpHour($what, $ip)
    {
        $dir = self::$cfg['data_dir'] . '/cnt/' . date('YmdH');
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $f = $dir . '/' . $what . '-' . sha1($ip) . '.txt';
        $h = @fopen($f, 'c+');
        if (!$h) {
            return 0;
        }
        flock($h, LOCK_EX);
        $n = (int)stream_get_contents($h) + 1;
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, (string)$n);
        flock($h, LOCK_UN);
        fclose($h);
        return $n;
    }

    public static function countProbe($ip, $weight)
    {
        $n = 0;
        for ($i = 0; $i < $weight; $i++) {
            $n = self::bumpHour('pr', $ip);
        }
        if (self::$cfg['local_scan_ban'] && $n >= (int)self::$cfg['scan_hits']) {
            self::localBan($ip, time() + 3600 * (int)self::$cfg['local_scan_hours']);
        }
        return $n;
    }

    public static function localBan($ip, $until)
    {
        $f = self::$cfg['data_dir'] . '/local.php';
        $h = @fopen($f . '.lock', 'c');
        if (!$h) {
            return;
        }
        flock($h, LOCK_EX);
        $cur = self::readPhp($f);
        $cur = is_array($cur) ? $cur : array();
        $now = time();
        foreach ($cur as $k => $u) {
            if ((int)$u <= $now) {
                unset($cur[$k]);
            }
        }
        $cur[$ip] = $until;
        self::writePhp($f, $cur);
        flock($h, LOCK_UN);
        fclose($h);
        self::$list = null;
    }

    public static function writePhp($file, array $data)
    {
        $tmp = $file . '.tmp' . getmypid();
        if (@file_put_contents($tmp, '<?php return ' . var_export($data, true) . ";\n", LOCK_EX) === false) {
            return false;
        }
        $ok = @rename($tmp, $file);
        if (!$ok) {
            @unlink($file);
            $ok = @rename($tmp, $file);
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
        return $ok;
    }

    // ------------------------------------------------------------------ метка JS

    public static function netKey($ip)
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return $ip;
        }
        return strlen($bin) === 4 ? bin2hex(substr($bin, 0, 3)) : bin2hex(substr($bin, 0, 6));
    }

    public static function token($ip, $day)
    {
        return substr(hash_hmac('sha256', self::netKey($ip) . '|' . $day, (string)self::$cfg['secret']), 0, 16);
    }

    public static function encode($tok)
    {
        $out = '';
        for ($i = strlen($tok) - 1; $i >= 0; $i--) {
            $out .= dechex((hexdec($tok[$i]) + 7) % 16);
        }
        return $out;
    }

    public static function checkMark($cookie, $ip, $now)
    {
        if (!preg_match('~^[0-9a-f]{16}$~', $cookie)) {
            return false;
        }
        $day = intdiv($now, 86400);
        for ($k = 0; $k < 7; $k++) {
            if (hash_equals(self::token($ip, $day - $k), $cookie)) {
                return true;
            }
        }
        return false;
    }

    // В страницы сайта — одинаковая для всех строка (её можно кэшировать): метку скрипт берёт отдельным запросом
    // /?abg=t (без кэша). data-r="1" — у этого запроса метки не было, взять заново. На странице проверки браузера
    // (она не кэшируется) метка вписана сразу: data-v.
    public static function markSnippet($ip, $inline)
    {
        $src = htmlspecialchars((string)self::$cfg['mark_url'], ENT_QUOTES, 'UTF-8');
        if ($inline) {
            $v = self::encode(self::token($ip, intdiv(time(), 86400)));
            return '<i id="abm" data-v="' . $v . '" hidden></i><script src="' . $src . '"></script>';
        }
        return '<i id="abm" data-r="' . (self::$hasMark ? '0' : '1') . '" hidden></i><script src="' . $src . '" async></script>';
    }

    public static function serveToken()
    {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        header('X-Robots-Tag: noindex');
        echo '{"v":"' . self::encode(self::token(self::$ip, intdiv(time(), 86400))) . '"}';
        exit;
    }

    public static function insertMark($html, array $headers, $code)
    {
        if ($html === '' || $code !== 200) {
            return $html;
        }
        if (substr($html, 0, 2) === "\x1f\x8b") {
            return $html;
        }
        foreach ($headers as $hd) {
            $l = strtolower($hd);
            if (strpos($l, 'content-type:') === 0 && strpos($l, 'text/html') === false) {
                return $html;
            }
            if (strpos($l, 'content-encoding:') === 0) {
                return $html;
            }
        }
        $pos = strripos($html, '</body>');
        if ($pos === false) {
            return $html;
        }
        return substr($html, 0, $pos) . self::markSnippet(self::$ip, false) . substr($html, $pos);
    }

    // Вывод может уходить кусками (flush() темы, implicit_flush): скрипт вставляется один раз — в тот кусок,
    // где первым встретился </body>. Сжатый вывод (gzip внутри PHP) не трогаем.
    public static function obInsert($buf, $phase)
    {
        if (self::$obDone || $buf === '') {
            return $buf;
        }
        if (substr($buf, 0, 2) === "\x1f\x8b") {
            self::$obDone = true;
            return $buf;
        }
        $code = http_response_code();
        $out = self::insertMark($buf, headers_list(), $code === false ? 200 : (int)$code);
        if ($out !== $buf) {
            self::$obDone = true;
        }
        return $out;
    }

    public static function serveMarkJs()
    {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        header('Content-Type: application/javascript; charset=utf-8');
        header('Cache-Control: public, max-age=86400');
        $f = __DIR__ . '/mark.js';
        echo is_file($f) ? file_get_contents($f) : '';
        exit;
    }

    public static function serveChallenge()
    {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code(429);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex');
            header('Retry-After: 1');
        }
        echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            . 'initial-scale=1"><meta name="robots" content="noindex"><title>Проверка браузера</title></head>'
            . '<body style="margin:0;background:#f5f6f8;color:#222;font:16px/1.55 Arial,Helvetica,sans-serif">'
            . '<div style="max-width:560px;margin:48px auto;padding:28px 24px;background:#fff;border-radius:10px">'
            . '<p>Проверяем браузер, страница сейчас откроется…</p>'
            . '<noscript><p>Включите JavaScript, чтобы открыть сайт.</p></noscript></div>'
            . self::markSnippet(self::$ip, true)
            . '<script>(function(){try{var n=+(sessionStorage.getItem("abr")||0);if(n>2)return;sessionStorage.setItem("abr",n+1);}'
            . 'catch(e){}if(document.cookie.indexOf("abm=")>=0){location.reload();}})();</script></body></html>';
        exit;
    }

    // ------------------------------------------------------------------ журнал и синхронизация

    public static function shutdown()
    {
        self::writeLog();
        self::maybeSync(false);
    }

    public static function clean($s, $max)
    {
        return substr(str_replace(array("\t", "\r", "\n"), ' ', (string)$s), 0, $max);
    }

    public static function writeLog()
    {
        if (self::$logged) {
            return;
        }
        self::$logged = true;
        $code = http_response_code();
        $uri = self::$kind === 'static' ? self::path(self::$uri) : self::$uri;
        if (strpos($uri, 'abg=s') !== false) {
            $uri = preg_replace('~([?&]k=)[^&]*~', '$1*', $uri);
        }
        $ref = isset($_SERVER['HTTP_REFERER']) ? (string)$_SERVER['HTTP_REFERER'] : '';
        // 11-я колонка: что сработало — «!причина» закрыло запрос, без «!» — только отметка (watch); 12-я — язык браузера (с 0.3.0)
        $tags = array_keys(self::$tags);
        if (self::$why !== '') {
            $tags[] = '!' . self::$why;
        }
        $line = implode("\t", array(
            time(), self::$ip, self::$method, self::$kind, self::clean($uri, 400), $code === false ? 200 : (int)$code,
            self::$hasMark ? 1 : 0, self::$exempt ? 1 : 0, self::clean(self::$ua, 300), self::clean($ref, 200),
            self::clean(implode(',', $tags), 300), self::clean(self::$al, 80),
        )) . "\n";
        $dir = self::$cfg['data_dir'] . '/log';
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        @file_put_contents($dir . '/' . date('Y-m-d') . '.log', $line, FILE_APPEND | LOCK_EX);
    }

    public static function maybeSync($force)
    {
        $dir = self::$cfg['data_dir'];
        $h = @fopen($dir . '/sync.lock', 'c+');
        if (!$h) {
            return false;
        }
        if (!flock($h, LOCK_EX | LOCK_NB)) {
            fclose($h);
            return false;
        }
        $last = (int)stream_get_contents($h);
        $now = time();
        if (!$force && $now - $last < (int)self::$cfg['sync_interval']) {
            flock($h, LOCK_UN);
            fclose($h);
            return false;
        }
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, (string)$now);
        fflush($h);
        if (!$force && function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } elseif (!$force && function_exists('litespeed_finish_request')) {
            @litespeed_finish_request();
        }
        $res = false;
        try {
            self::cleanup($now);
            if (self::$cfg['hub_url'] !== '') {
                $res = self::sync($now);
            }
        } catch (\Throwable $e) {
            self::state(array('error' => 'sync: ' . $e->getMessage()));
        }
        flock($h, LOCK_UN);
        fclose($h);
        return $res;
    }

    public static function cleanup($now)
    {
        $f = self::$cfg['data_dir'] . '/cleanup.txt';
        if ((int)@file_get_contents($f) > $now - 3600) {
            return;
        }
        @file_put_contents($f, (string)$now);
        $keep = (int)self::$cfg['log_days'] * 86400;
        foreach ((array)glob(self::$cfg['data_dir'] . '/log/*.log') as $p) {
            if (@filemtime($p) < $now - $keep) {
                @unlink($p);
            }
        }
        $cur = date('YmdH', $now);
        $prev = date('YmdH', $now - 3600);
        foreach ((array)glob(self::$cfg['data_dir'] . '/cnt/*', GLOB_ONLYDIR) as $d) {
            $b = basename($d);
            if ($b !== $cur && $b !== $prev) {
                foreach ((array)glob($d . '/*') as $x) {
                    @unlink($x);
                }
                @rmdir($d);
            }
        }
    }

    public static function readRecent($now, $window)
    {
        $out = array();
        $files = array(date('Y-m-d', $now - $window), date('Y-m-d', $now));
        $files = array_unique($files);
        foreach ($files as $d) {
            $p = self::$cfg['data_dir'] . '/log/' . $d . '.log';
            if (!is_file($p)) {
                continue;
            }
            $size = filesize($p);
            $fh = @fopen($p, 'rb');
            if (!$fh) {
                continue;
            }
            $start = max(0, $size - 8 * 1048576);
            fseek($fh, $start);
            if ($start > 0) {
                fgets($fh);
            }
            while (($l = fgets($fh)) !== false) {
                $c = explode("\t", rtrim($l, "\n"));
                if (count($c) < 10 || (int)$c[0] < $now - $window) {
                    continue;
                }
                $out[] = $c;
            }
            fclose($fh);
        }
        return $out;
    }

    public static function aggregate($now)
    {
        $rows = self::readRecent($now, 3600);
        $ips = array();
        $w = array();
        $total = 0;
        $pages = 0;
        $pagesMark = 0;
        foreach ($rows as $c) {
            list($ts, $ip, $meth, $kind, $uri, $code, $mark, $exempt, $ua, $ref) = $c;
            $total++;
            $isPage = in_array($kind, array('page', 'catalog', 'product', 'search'), true);
            // доля страниц с меткой — только по обычным посетителям: роботы поисковиков и белый список скрипт
            // не выполняют, на маленьком сайте они занижали бы долю почти до нуля (с 0.2.1)
            if ((int)$exempt || self::isAllowed($ip)) {
                continue;
            }
            if ($isPage) {
                $pages++;
                $pagesMark += (int)$mark;
            }
            if (!isset($ips[$ip])) {
                $ips[$ip] = array('ip' => $ip, 'first' => (int)$ts, 'last' => (int)$ts, 'req' => 0, 'pages' => 0,
                    'pages_nomark' => 0, 'catalog' => 0, 'product' => 0, 'search' => 0, 'static' => 0, 'js' => 0,
                    'probe' => 0, 'sqli' => 0, 'head' => 0, 'post' => 0, 'refused' => 0, 'mark' => 0,
                    'se_ref' => 0, 'uas' => array(), 'samples' => array());
            }
            $a =& $ips[$ip];
            $a['last'] = (int)$ts;
            $a['req']++;
            if (isset($a[$kind]) && is_int($a[$kind])) {
                $a[$kind]++;
            }
            if ($isPage) {
                $a['pages']++;
                if (!(int)$mark) {
                    $a['pages_nomark']++;
                }
            }
            if ((int)$mark) {
                $a['mark'] = 1;
            }
            if ($meth === 'HEAD') {
                $a['head']++;
            } elseif ($meth === 'POST') {
                $a['post']++;
            }
            if (in_array((int)$code, array(403, 429), true)) {
                $a['refused']++;
            }
            if ($ref !== '' && self::rx('^https?://(?:www\.)?(?:yandex\.[a-z.]+|ya\.ru|google\.[a-z.]+|bing\.com|go\.mail\.ru|duckduckgo\.com)(?:/|$)', $ref)) {
                $a['se_ref'] = 1;
            }
            if (count($a['uas']) < 3 && !in_array($ua, $a['uas'], true)) {
                $a['uas'][] = $ua;
            }
            if (($kind === 'probe' || $kind === 'sqli') && count($a['samples']) < 5) {
                $a['samples'][] = substr($uri, 0, 200);
            }
            unset($a);
            if (isset($c[10]) && $c[10] !== '') {
                foreach (explode(',', $c[10]) as $t) {
                    if ($t === '') {
                        continue;
                    }
                    $blocked = $t[0] === '!';
                    $id = $blocked ? substr($t, 1) : $t;
                    if (!isset($w[$id])) {
                        if (count($w) >= 100) {
                            continue;
                        }
                        $w[$id] = array('hits' => 0, 'blocked' => 0, 'ips' => array(), 'samples' => array());
                    }
                    $w[$id]['hits']++;
                    if ($blocked) {
                        $w[$id]['blocked']++;
                    }
                    if (!isset($w[$id]['ips'][$ip]) && count($w[$id]['samples']) < 5) {
                        $w[$id]['samples'][] = array($ip, substr($ua, 0, 160), substr($ref, 0, 120), substr($uri, 0, 120),
                            isset($c[11]) ? substr((string)$c[11], 0, 60) : '');
                    }
                    $w[$id]['ips'][$ip] = 1;
                }
            }
        }
        $sus = array();
        foreach ($ips as $a) {
            if ($a['probe'] + $a['sqli'] > 0 || $a['pages_nomark'] >= (int)self::$cfg['suspect_pages']
                || $a['req'] >= (int)self::$cfg['rate_hour'] || $a['head'] >= (int)self::$cfg['head_hits']) {
                $sus[] = $a;
            }
        }
        // по каждой связке и группе: у скольких адресов есть метка (скрипт выполнился) и картинки — признаки человека
        $watch = array();
        foreach ($w as $id => $x) {
            $mk = 0;
            $st = 0;
            foreach ($x['ips'] as $wip => $_) {
                if (!empty($ips[$wip]['mark'])) {
                    $mk++;
                }
                if (!empty($ips[$wip]['static'])) {
                    $st++;
                }
            }
            $watch[$id] = array('hits' => $x['hits'], 'blocked' => $x['blocked'], 'ips' => count($x['ips']),
                'mark_ips' => $mk, 'static_ips' => $st, 'samples' => $x['samples']);
        }
        return array('suspects' => $sus, 'watch' => $watch, 'stats' => array('req_hour' => $total, 'ips_hour' => count($ips),
            'pages_hour' => $pages, 'mark_share' => $pages ? round($pagesMark / $pages, 3) : null));
    }

    public static function state(array $set = array())
    {
        $f = self::$cfg['data_dir'] . '/state.php';
        $s = self::readPhp($f);
        $s = is_array($s) ? $s : array();
        if ($set) {
            $s = array_merge($s, $set);
            self::writePhp($f, $s);
        }
        return $s;
    }

    public static function post($url, $body)
    {
        $t = max(1, (int)self::$cfg['hub_timeout']);
        $hdr = array('Content-Type: application/json', 'Authorization: Bearer ' . self::$cfg['site_token']);
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $hdr,
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $t, CURLOPT_CONNECTTIMEOUT => $t));
            $out = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($out === false || $code !== 200) {
                self::$postError = $out === false ? 'curl: ' . $err : 'HTTP ' . $code;
                return null;
            }
            return $out;
        }
        $ctx = stream_context_create(array('http' => array('method' => 'POST', 'header' => implode("\r\n", $hdr),
            'content' => $body, 'timeout' => $t, 'ignore_errors' => true)));
        $out = @file_get_contents($url, false, $ctx);
        if ($out === false || !isset($http_response_header[0]) || strpos($http_response_header[0], ' 200') === false) {
            $e = error_get_last();
            self::$postError = isset($http_response_header[0]) ? $http_response_header[0]
                : ('нет ответа' . ($e && isset($e['message']) ? ': ' . $e['message'] : ''));
            return null;
        }
        return $out;
    }

    public static function sync($now)
    {
        $agg = self::aggregate($now);
        $st = self::state();
        $m = self::mine();
        $body = json_encode(array(
            'gate' => self::VERSION, 'php' => PHP_VERSION, 'engine' => self::$cfg['engine'],
            'list_ver' => isset($st['ver']) ? $st['ver'] : '', 'list_issued' => isset($st['issued']) ? $st['issued'] : 0,
            'stats' => $agg['stats'], 'suspects' => $agg['suspects'], 'watch' => (object)$agg['watch'],
            'shared' => self::sharedModes(), 'mine' => array('rules' => count($m['items']), 'errors' => count($m['errors'])),
            'offers' => $m['offer'] ? array_slice($m['items'], 0, 500) : array(),
            'server_ips' => array_values((array)self::$cfg['server_ips']),
            'error' => isset($st['error']) ? $st['error'] : '', 'time' => $now,
        ));
        $out = self::post(rtrim(self::$cfg['hub_url'], '/') . '/v1/checkin', $body);
        if ($out === null) {
            self::state(array('hub_fail' => $now, 'error' => 'hub: ' . substr(self::$postError, 0, 200)));
            return false;
        }
        $r = self::acceptList($out, $now);
        return $r;
    }

    public static function verify($payload, $sigB64)
    {
        if (!function_exists('openssl_verify') || self::$cfg['hub_public_key'] === '') {
            return false;
        }
        $sig = base64_decode((string)$sigB64, true);
        if ($sig === false) {
            return false;
        }
        return openssl_verify($payload, $sig, self::$cfg['hub_public_key'], OPENSSL_ALGO_SHA256) === 1;
    }

    public static function acceptList($raw, $now)
    {
        $env = json_decode($raw, true);
        if (!is_array($env) || !isset($env['payload'], $env['sig'])) {
            self::state(array('error' => 'hub: bad envelope'));
            return false;
        }
        $payload = base64_decode((string)$env['payload'], true);
        if ($payload === false || !self::verify($payload, $env['sig'])) {
            self::state(array('error' => 'hub: bad signature'));
            return false;
        }
        $p = json_decode($payload, true);
        $st = self::state();
        if (!is_array($p) || !isset($p['site'], $p['issued'], $p['ver'])) {
            self::state(array('error' => 'hub: bad payload'));
            return false;
        }
        if (isset($st['site']) && $st['site'] !== '' && $st['site'] !== $p['site']) {
            self::state(array('error' => 'hub: list for another site'));
            return false;
        }
        if ((int)$p['issued'] < (isset($st['issued']) ? (int)$st['issued'] : 0) || (int)$p['issued'] < $now - 86400) {
            self::state(array('error' => 'hub: stale list'));
            return false;
        }
        if (!empty($p['unchanged'])) {
            self::state(array('site' => $p['site'], 'issued' => (int)$p['issued'], 'hub_ok' => $now, 'error' => ''));
            return true;
        }
        $list = isset($p['list']) && is_array($p['list']) ? $p['list'] : array();
        $clean = self::sanitizeList($list, self::lists());
        if ($clean === null) {
            self::state(array('error' => 'hub: too many new bans, list rejected'));
            return false;
        }
        self::writePhp(self::$cfg['data_dir'] . '/list.php', $clean);
        if (isset($p['settings']) && is_array($p['settings'])) {
            self::writePhp(self::$cfg['data_dir'] . '/settings.php', self::cleanSettings($p['settings']));
        }
        if (isset($p['offers']) && is_array($p['offers'])) {
            $offs = array();
            foreach ($p['offers'] as $o) {
                if (is_array($o) && count($o) >= 3) {
                    $offs[] = array(substr((string)$o[0], 0, 10), substr((string)$o[1], 0, 600), substr((string)$o[2], 0, 12),
                        isset($o[3]) ? substr((string)$o[3], 0, 200) : '');
                }
                if (count($offs) >= 300) {
                    break;
                }
            }
            self::writePhp(self::$cfg['data_dir'] . '/offers.php', $offs);
        }
        self::$list = null;
        self::state(array('site' => $p['site'], 'issued' => (int)$p['issued'], 'ver' => (string)$p['ver'],
            'hub_ok' => $now, 'error' => '', 'bans' => count($clean['ips']) + count($clean['nets']),
            'rules' => count($clean['rules'])));
        return true;
    }

    public static function browserSamples()
    {
        return array(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 YaBrowser/25.10.0.0 Safari/537.36',
        );
    }

    // Предохранители: сеть не шире /16 (IPv6 /48), никогда — свой сервер, белый список, поисковики;
    // имя браузера, под которое попадает обычный браузер, — отбрасывается; слишком много новых банов — весь список отклоняется.
    public static function sanitizeList(array $list, array $cur)
    {
        $protect = array();
        foreach (array((array)self::$cfg['server_ips'], (array)self::$cfg['allow'], self::seNets()) as $grp) {
            foreach ($grp as $k => $v) {
                $protect[] = is_string($k) ? $k : (string)$v;
            }
        }
        $ips = array();
        foreach ((isset($list['ips']) && is_array($list['ips'])) ? $list['ips'] : array() as $ip => $kind) {
            $ip = (string)$ip;
            if (!filter_var($ip, FILTER_VALIDATE_IP) || self::inList($ip, $protect)) {
                continue;
            }
            $ips[inet_ntop(inet_pton($ip))] = (int)$kind === 2 ? 2 : 1;
        }
        $nets = array();
        foreach ((isset($list['nets']) && is_array($list['nets'])) ? $list['nets'] : array() as $n) {
            $cidr = is_array($n) ? (string)$n[0] : (string)$n;
            $kind = (is_array($n) && isset($n[1]) && (int)$n[1] === 2) ? 2 : 1;
            $c = self::cidr($cidr);
            if ($c === null || $c[1] < (strlen($c[0]) === 4 ? 16 : 48)) {
                continue;
            }
            $hit = false;
            foreach ($protect as $pr) {
                $pc = self::cidr($pr);
                if ($pc !== null && strlen($pc[0]) === strlen($c[0])
                    && (self::inNet($pc[0], $c) || self::inNet($c[0], $pc))) {
                    $hit = true;
                    break;
                }
            }
            if (!$hit) {
                $nets[] = (is_array($n) && isset($n[2]) && $n[2] === 'bans') ? array($cidr, $kind, 'bans') : array($cidr, $kind);
            }
        }
        $uaEx = array();
        $uaRe = array();
        $samples = self::browserSamples();
        foreach ((isset($list['ua_exact']) && is_array($list['ua_exact'])) ? $list['ua_exact'] : array() as $u) {
            if (is_string($u) && strlen($u) >= 8 && !in_array($u, $samples, true)) {
                $uaEx[] = $u;
            }
        }
        foreach ((isset($list['ua_regex']) && is_array($list['ua_regex'])) ? $list['ua_regex'] : array() as $re) {
            if (!is_string($re) || strlen($re) < 6 || @preg_match('~' . str_replace('~', '\~', $re) . '~i', '') === false) {
                continue;
            }
            $bad = false;
            foreach ($samples as $s) {
                if (self::rx($re, $s)) {
                    $bad = true;
                    break;
                }
            }
            if (!$bad) {
                $uaRe[] = $re;
            }
        }
        $new = 0;
        foreach ($ips as $ip => $k) {
            if (!isset($cur['ips'][$ip])) {
                $new++;
            }
        }
        $curNets = array();
        foreach ($cur['nets'] as $n) {
            $curNets[is_array($n) ? $n[0] : $n] = 1;
        }
        foreach ($nets as $n) {
            if (!isset($curNets[$n[0]])) {
                $new++;
            }
        }
        // стоп-кран — на прибавку к уже принятому списку; первый список после установки принимается целиком
        if ($new > (int)self::$cfg['max_new_bans'] && count($cur['ips']) + count($cur['nets']) > 0) {
            return null;
        }
        $grp = array();
        foreach ((isset($list['ua_grp']) && is_array($list['ua_grp'])) ? $list['ua_grp'] : array() as $k => $g) {
            if ($g === 'seo') {
                $grp[(string)$k] = 'seo';
            }
        }
        // связки: та же проверка, что у своих правил; режим из хаба — не строже, чем выбрал сайт (shared → patterns)
        $rules = array();
        foreach ((isset($list['rules']) && is_array($list['rules'])) ? $list['rules'] : array() as $r) {
            if (!is_array($r) || !isset($r['id']) || !preg_match('~^[a-z0-9][a-z0-9_.-]{1,40}$~', (string)$r['id'])) {
                continue;
            }
            $err = '';
            $c = self::cleanRule($r, $err);
            if ($c === null) {
                continue;
            }
            $c['id'] = (string)$r['id'];
            $c['mode'] = (isset($r['mode']) && $r['mode'] === 'on') ? 'on' : 'watch';
            $rules[] = $c;
            if (count($rules) >= 200) {
                break;
            }
        }
        return array('ips' => $ips, 'nets' => $nets, 'ua_exact' => $uaEx, 'ua_regex' => $uaRe, 'ua_grp' => $grp,
            'rules' => $rules);
    }

    public static function cleanSettings(array $s)
    {
        $out = array();
        foreach (array('challenge', 'mark') as $k) {
            if (isset($s[$k])) {
                $out[$k] = (bool)$s[$k];
            }
        }
        foreach (array('challenge_pages' => array(5, 10000), 'suspect_pages' => array(5, 100000),
                     'rate_hour' => array(50, 1000000), 'head_hits' => array(5, 100000)) as $k => $r) {
            if (isset($s[$k]) && is_numeric($s[$k])) {
                $out[$k] = max($r[0], min($r[1], (int)$s[$k]));
            }
        }
        if (isset($s['paths']) && is_array($s['paths'])) {
            $p = array();
            foreach (array('product', 'catalog', 'search', 'js', 'own') as $k) {
                if (isset($s['paths'][$k]) && is_string($s['paths'][$k]) && strlen($s['paths'][$k]) < 500
                    && @preg_match('~' . str_replace('~', '\~', $s['paths'][$k]) . '~i', '') !== false) {
                    $p[$k] = $s['paths'][$k];
                }
            }
            if ($p) {
                $out['paths'] = $p;
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------ страница состояния: /?abg=s&k=КЛЮЧ

    public static function serveStatus($key)
    {
        $want = (string)self::$cfg['status_key'];
        if (strlen($want) < 16 || !hash_equals($want, (string)$key)) {
            return;
        }
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store, private');
            header('X-Robots-Tag: noindex');
            header('X-Frame-Options: DENY');
            header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
            header('Referrer-Policy: no-referrer');
        }
        echo self::statusHtml(time());
        exit;
    }

    public static function statusHtml($now)
    {
        $h = function ($s) {
            return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
        };
        $when = function ($ts) {
            return $ts ? date('d.m.Y H:i', (int)$ts) : 'ни разу';
        };
        $st = self::state();
        $l = self::lists();
        $m = self::mine();
        $agg = self::aggregate($now);
        $modeRu = array('on' => 'закрывать', 'watch' => 'только отмечать', 'off' => 'не брать');
        $grpRu = array('bans' => 'Адреса сканеров и ботов', 'nets' => 'Сети хостингов без людей',
            'names' => 'Имена браузеров сборщиков', 'seo' => 'SEO-роботы (Ahrefs, Semrush и т. п.)',
            'patterns' => 'Связки примет ботов');
        $tagRu = array('@bans' => 'адреса из общего списка', '@nets' => 'сети из общего списка', '@names' => 'имена из общего списка',
            '@seo' => 'SEO-роботы', 'own' => 'ваши правила', 'local' => 'сканер (закрыт на месте)');
        $cnt = array('bans' => count($l['ips']), 'nets' => 0, 'names' => 0, 'seo' => 0, 'patterns' => count($l['rules']));
        foreach ($l['nets'] as $n) {
            $cnt[(is_array($n) && isset($n[2]) && $n[2] === 'bans') ? 'bans' : 'nets']++;
        }
        foreach (array_merge($l['ua_exact'], $l['ua_regex']) as $u) {
            $cnt[(isset($l['ua_grp'][$u]) && $l['ua_grp'][$u] === 'seo') ? 'seo' : 'names']++;
        }
        $td = 'style="padding:4px 10px;border-bottom:1px solid #e3e5e8;vertical-align:top"';
        $table = function (array $head, array $rows) use ($h, $td) {
            $o = '<table style="border-collapse:collapse;margin:6px 0 4px;font-size:14px"><tr>';
            foreach ($head as $x) {
                $o .= '<th ' . $td . ' align="left">' . $h($x) . '</th>';
            }
            $o .= '</tr>';
            foreach ($rows as $r) {
                $o .= '<tr>';
                foreach ($r as $x) {
                    $o .= '<td ' . $td . '>' . $h($x) . '</td>';
                }
                $o .= '</tr>';
            }
            return $o . '</table>';
        };
        $o = '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            . 'initial-scale=1"><meta name="robots" content="noindex"><title>Защита от ботов — состояние</title></head>'
            . '<body style="margin:0;background:#f5f6f8;color:#222;font:15px/1.5 Arial,Helvetica,sans-serif">'
            . '<div style="max-width:880px;margin:24px auto;padding:20px 24px;background:#fff;border-radius:10px">'
            . '<h1 style="font-size:21px;margin:0 0 4px">Защита от ботов — ' . $h(self::$cfg['domain']) . '</h1>'
            . '<p style="color:#666;margin:0 0 12px">Привратник ' . $h(self::VERSION) . ', ' . $h(date('d.m.Y H:i', $now))
            . '. Страница открывается только по ключу — не пересылайте ссылку.</p>';
        $o .= '<h2 style="font-size:17px">Связь с сервером защиты</h2><p>Последний обмен: ' . $h($when(isset($st['hub_ok']) ? $st['hub_ok'] : 0))
            . '. Список от: ' . $h($when(isset($st['issued']) ? $st['issued'] : 0)) . '.'
            . (!empty($st['error']) ? ' <b style="color:#b00">Ошибка: ' . $h($st['error']) . '</b>' : ' Ошибок нет.') . '</p>';
        $rows = array();
        foreach (self::GROUPS as $g) {
            $rows[] = array($grpRu[$g], $modeRu[self::mode($g)], $cnt[$g]);
        }
        $o .= '<h2 style="font-size:17px">Что вы берёте из общего списка</h2>'
            . $table(array('Группа', 'Ваш выбор', 'Записей'), $rows)
            . '<p style="color:#666;font-size:13px">Меняется в config.php, строка \'shared\': on — закрывать, watch — только отмечать '
            . '(видно ниже, сайт работает как раньше), off — не брать. Белый список (\'allow\') сильнее всего.</p>';
        if ($l['rules']) {
            $pm = self::mode('patterns');
            $rows = array();
            foreach ($l['rules'] as $r) {
                $eff = $pm === 'off' ? 'выключено' : (($pm === 'on' && $r['mode'] === 'on') ? 'закрывает' : 'только отмечает');
                $rows[] = array($r['id'], $eff);
            }
            $o .= '<h2 style="font-size:17px">Связки примет</h2>' . $table(array('Связка', 'У вас'), $rows);
        }
        $s = $agg['stats'];
        $o .= '<h2 style="font-size:17px">Последний час</h2><p>Запросов: ' . $h($s['req_hour']) . ', адресов: ' . $h($s['ips_hour'])
            . ', доля страниц с меткой браузера: ' . $h($s['mark_share'] === null ? '—' : $s['mark_share']) . '.</p>';
        if ($agg['watch']) {
            $rows = array();
            foreach ($agg['watch'] as $id => $x) {
                $rows[] = array(isset($tagRu[$id]) ? $tagRu[$id] : 'связка ' . $id, $x['hits'], $x['blocked'], $x['ips'], $x['mark_ips']);
            }
            $o .= $table(array('Что сработало', 'Запросов', 'Из них закрыто', 'Адресов', 'С меткой браузера'), $rows)
                . '<p style="color:#666;font-size:13px">«С меткой браузера» — у адреса выполнился скрипт страницы: похоже на человека. '
                . 'Если таких много у того, что вы «только отмечаете», включать закрытие нельзя.</p>';
        } else {
            $o .= '<p>Ничего не сработало.</p>';
        }
        $kinds = array('ip' => 0, 'net' => 0, 'ua' => 0, 'ua_re' => 0, 'pattern' => 0);
        foreach ($m['items'] as $it) {
            $kinds[$it['t']]++;
        }
        $o .= '<h2 style="font-size:17px">Ваши правила (my-rules.php)</h2><p>Адресов: ' . ($kinds['ip'] + 0) . ', сетей: ' . $kinds['net']
            . ', имён: ' . $kinds['ua'] . ', частей имени: ' . $kinds['ua_re'] . ', связок: ' . $kinds['pattern']
            . '. Действуют на вашем сайте сразу. Предлагаются в общий список: ' . ($m['offer'] ? 'да' : 'нет') . '.</p>';
        if ($m['errors']) {
            $o .= '<p style="color:#b00">Не приняты (поправьте в my-rules.php):</p><ul>';
            foreach (array_slice($m['errors'], 0, 50) as $e) {
                $o .= '<li>' . $h($e) . '</li>';
            }
            $o .= '</ul>';
        }
        $offs = self::readPhp(self::$cfg['data_dir'] . '/offers.php');
        if (is_array($offs) && $offs) {
            $stRu = array('new' => 'ждёт решения', 'approved' => 'принято в общий список', 'rejected' => 'отклонено');
            $kRu = array('ip' => 'адрес', 'net' => 'сеть', 'ua' => 'имя', 'ua_re' => 'часть имени', 'pattern' => 'связка');
            $rows = array();
            foreach ($offs as $x) {
                $rows[] = array(isset($kRu[$x[0]]) ? $kRu[$x[0]] : $x[0], substr($x[1], 0, 160),
                    isset($stRu[$x[2]]) ? $stRu[$x[2]] : $x[2], $x[3]);
            }
            $o .= '<h2 style="font-size:17px">Ваши предложения в общий список</h2>'
                . $table(array('Что', '', 'Статус', 'Пометка'), $rows);
        }
        return $o . '</div></body></html>';
    }
}

}

if (!defined('ABG_NO_RUN')) {
    AbGate::run(__DIR__ . '/config.php');
}
