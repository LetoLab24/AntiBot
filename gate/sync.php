<?php
// Синхронизация с хабом из cron (если хостинг даёт cron): php /путь/antibot-gate/sync.php
// Без cron привратник синхронизируется сам после ответа посетителю.
if (PHP_SAPI !== 'cli') {
    exit;
}
define('ABG_NO_RUN', 1);
require __DIR__ . '/gate.php';
if (!AbGate::load(__DIR__ . '/config.php')) {
    fwrite(STDERR, "config.php не найден или нет secret\n");
    exit(1);
}
$r = AbGate::maybeSync(true);
$s = AbGate::state();
echo ($r ? 'ok' : 'нет ответа хаба или список не принят') . (empty($s['error']) ? '' : ': ' . $s['error']) . "\n";
exit($r ? 0 : 2);
