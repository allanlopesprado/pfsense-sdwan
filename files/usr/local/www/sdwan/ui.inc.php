<?php
// Shared page routines. The caller must have passed the pfSense WebGUI gate.
if (!defined('SDWAN_GUI')) {
	http_response_code(404);
	exit;
}

require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');

function sdwan_ui_escape($text): string {
	return htmlspecialchars((string)$text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function sdwan_ui_tabs(string $current): void {
	$labels = [
		'status' => gettext('Status'),
		'members' => gettext('Members'),
		'slas' => gettext('Performance SLAs'),
		'policies' => gettext('Policies'),
		'diagnostics' => gettext('Diagnostics'),
	];
	$tabs = [];
	foreach ($labels as $page => $label) {
		$tabs[] = [$label, $page === $current, '/sdwan/' . $page . '.php'];
	}
	display_top_tabs($tabs, true);
}

function sdwan_ui_scalar(array $source, string $key): string {
	return isset($source[$key]) && is_string($source[$key]) ? trim($source[$key]) : '';
}

function sdwan_ui_snapshot(array $config): ?array {
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config)) {
		return null;
	}
	return $snapshot;
}

function sdwan_ui_empty(string $message, int $columns): void {
	echo '<tr><td colspan="' . $columns . '">' . sdwan_ui_escape($message) . '</td></tr>';
}

function sdwan_ui_metric($number, string $unit): string {
	return is_numeric($number) ? sdwan_ui_escape(number_format((float)$number, 2) . $unit) : '—';
}

try {
	$sdwan = sdwan_get_config();
} catch (UnexpectedValueException $error) {
	$pgtitle = [gettext('Services'), gettext('SD-WAN')];
	include('head.inc');
	print_input_errors([gettext('The stored SD-WAN configuration cannot be read by this version.'), $error->getMessage()]);
	include('foot.inc');
	exit;
}
