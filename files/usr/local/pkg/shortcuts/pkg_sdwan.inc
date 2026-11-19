<?php

global $shortcuts;

/* An exact native System Logs privilege may allow the base page only. */
$sdwan_log_page = 'status_logs.php';
$sdwan_filtered_log = $sdwan_log_page . '?logfile=system&filterlogentries_submit=1&filterlogentries_process=sdwan';

$shortcuts['sdwan'] = [
	'service' => 'sdwan',
	'main' => isAllowedPage('/sdwan/members.php') ? 'sdwan/members.php' : '',
	'status' => isAllowedPage('/sdwan/status.php') ? 'sdwan/status.php' : '',
	'log' => isAllowedPage($sdwan_filtered_log) ? htmlspecialchars($sdwan_filtered_log, ENT_QUOTES, 'UTF-8') :
	    (isAllowedPage($sdwan_log_page) ? $sdwan_log_page : ''),
];

unset($sdwan_log_page, $sdwan_filtered_log);
