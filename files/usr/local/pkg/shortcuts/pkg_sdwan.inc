<?php

global $shortcuts;

$sdwan_page = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$sdwan_settings = '/sdwan/members.php';
$sdwan_status = '/sdwan/status.php';
$sdwan_log_page = '/status_logs.php';
$sdwan_filtered_log = $sdwan_log_page . '?logfile=system&filterlogentries_submit=1&filterlogentries_process=sdwan';
$sdwan_log = '';

/* Status and Diagnostics already offer the filtered System Logs form. */
if ($sdwan_page !== $sdwan_status && $sdwan_page !== '/sdwan/diagnostics.php') {
	/* The native header also authorizes the URL as stored here. */
	$sdwan_log_html = htmlspecialchars($sdwan_filtered_log, ENT_QUOTES, 'UTF-8');
	if (isAllowedPage($sdwan_filtered_log) && isAllowedPage($sdwan_log_html)) {
		$sdwan_log = $sdwan_log_html;
	} elseif (isAllowedPage($sdwan_log_page)) {
		$sdwan_log = $sdwan_log_page;
	}
	unset($sdwan_log_html);
}

$shortcuts['sdwan'] = [
	'service' => 'sdwan',
	'main' => $sdwan_page !== $sdwan_settings && isAllowedPage($sdwan_settings) ? $sdwan_settings : '',
	'status' => $sdwan_page !== $sdwan_status && isAllowedPage($sdwan_status) ? $sdwan_status : '',
	'log' => $sdwan_log,
];

unset($sdwan_page, $sdwan_settings, $sdwan_status, $sdwan_log_page, $sdwan_filtered_log, $sdwan_log);
