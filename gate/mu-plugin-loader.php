<?php
/*
Plugin Name: AntiBot gate
Description: Привратник AntiBot — проверка посетителя перед страницей. Удалить файл — привратник выключен.
*/
// Скопировать в wp-content/mu-plugins/antibot-gate.php. Папка привратника по умолчанию — antibot-gate
// рядом с корнем сайта (на уровень выше папки WordPress, вне доступа из браузера). Другой путь — константа ABG_DIR в wp-config.php.
// Если привратник уже подключён через auto_prepend_file, второй раз он не сработает.
$abg_dir = defined('ABG_DIR') ? ABG_DIR : dirname(dirname(dirname(__DIR__))) . '/antibot-gate';
if (is_file($abg_dir . '/gate.php')) {
    require_once $abg_dir . '/gate.php';
}
unset($abg_dir);
