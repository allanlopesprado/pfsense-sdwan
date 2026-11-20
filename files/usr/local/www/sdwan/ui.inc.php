<?php
// Shared page routines. The caller must have passed the pfSense WebGUI gate.
if (!defined('SDWAN_GUI')) {
	http_response_code(404);
	exit;
}

require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');

$shortcut_section = 'sdwan';

function sdwan_ui_escape($text): string {
	return htmlspecialchars((string)$text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function sdwan_ui_tabs(string $current): void {
	$labels = [
		'status' => gettext('Status'),
		'members' => gettext('Members'),
		'slas' => gettext('Performance SLAs'),
		'policies' => gettext('Policies'),
		'forwarding' => gettext('Forwarding'),
		'diagnostics' => gettext('Diagnostics'),
		'updates' => gettext('Updates'),
	];
	$tabs = [];
	foreach ($labels as $page => $label) {
		if ($page === 'forwarding' && !sdwan_can_view_forwarding()) {
			continue;
		}
		$tabs[] = [$label, $page === $current, '/sdwan/' . $page . '.php'];
	}
	display_top_tabs($tabs);
}

function sdwan_ui_scalar(array $source, string $key): string {
	return isset($source[$key]) && is_string($source[$key]) ? trim($source[$key]) : '';
}

/* Native Form_Select compares values loosely. Keep "1" and "01" distinct. */
function sdwan_ui_choice(string $value): string {
	return $value === '' ? '' : ':' . $value;
}

function sdwan_ui_choice_value(string $value): string {
	return str_starts_with($value, ':') ? substr($value, 1) : $value;
}

function sdwan_ui_service_state(): string {
	static $state;
	if ($state === null) {
		require_once('service-utils.inc');
		$service = find_service_by_name('sdwan');
		$state = !$service ? 'unregistered' : (get_service_status($service) ? 'running' : 'stopped');
	}
	return $state;
}

function sdwan_ui_snapshot(array $config): ?array {
	if (sdwan_ui_service_state() !== 'running') {
		return null;
	}
	return sdwan_current_snapshot($config, sdwan_gateways());
}

function sdwan_ui_empty(string $message, int $columns): void {
	echo '<tr><td colspan="' . $columns . '" class="text-center">' . sdwan_ui_escape($message) . '</td></tr>';
}

function sdwan_ui_metric($number, string $unit): string {
	return is_numeric($number) ? sdwan_ui_escape(number_format((float)$number, 2) . $unit) : '—';
}

/* Follow Status > Gateways: semantic cell classes plus visible state text. */
function sdwan_ui_gateway_state(?string $state): array {
	return match ($state) {
		'online' => ['bg-success', gettext('Online')],
		'degraded' => ['bg-warning', gettext('Warning')],
		'down' => ['bg-danger', gettext('Offline')],
		default => ['bg-info', gettext('Unknown')],
	};
}

/* Read-only filters use native inputs and the current pfSense theme. */
function sdwan_ui_filter(string $url, array $fields, string $action, bool $enabled = true): void {
	?>
	<style>
	.sdwan-filter { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 8px 12px; padding: 12px 15px; }
	.sdwan-filter .form-group { flex: 1 1 13rem; min-width: 0; max-width: 25rem; margin: 0; padding: 0; border: 0; }
	.sdwan-filter .form-control { width: 100%; }
	@media (max-width: 575px) {
		.sdwan-filter .form-group { flex-basis: 100%; max-width: none; }
	}
	</style>
	<div class="panel panel-default">
		<form method="get" action="<?=sdwan_ui_escape($url)?>" class="sdwan-filter" aria-label="<?=sdwan_ui_escape($action)?>">
			<?php foreach ($fields as $name => [$label, $selected, $choices]): ?>
			<div class="form-group">
				<label for="<?=sdwan_ui_escape($name)?>"><?=sdwan_ui_escape($label)?></label>
				<select class="form-control" id="<?=sdwan_ui_escape($name)?>" name="<?=sdwan_ui_escape($name)?>" required>
					<?php foreach ($choices as $value => $text): ?>
					<option value="<?=sdwan_ui_escape($value)?>"<?=$value === $selected ? ' selected' : ''?>><?=sdwan_ui_escape($text)?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<?php endforeach; ?>
			<button type="submit" class="btn btn-primary"<?=$enabled ? '' : ' disabled'?>>
				<i class="fa-solid fa-magnifying-glass fa-fw" aria-hidden="true"></i> <?=sdwan_ui_escape($action)?>
			</button>
		</form>
	</div>
	<?php
}

/* Follow the action toolbar below native Gateway Groups and Firewall Aliases. */
function sdwan_ui_actions(array $links, bool $events = false): void {
	$buttons = [];
	$can_view_events = $events && isAllowedPage('/status_logs.php');
	if ($can_view_events) {
		$buttons[] = '<button type="submit" form="sdwan-system-logs" class="btn btn-default btn-sm">' .
		    '<i class="fa-solid fa-list fa-fw" aria-hidden="true"></i> ' .
		    sdwan_ui_escape(gettext('System Logs')) . '</button>';
	}
	foreach ($links as $url => [$label, $icon]) {
		if (isAllowedPage($url)) {
			$buttons[] = '<a class="btn btn-default btn-sm" role="button" href="' . sdwan_ui_escape($url) . '">' .
			    '<i class="fa-solid ' . sdwan_ui_escape($icon) . ' fa-fw" aria-hidden="true"></i> ' .
			    sdwan_ui_escape($label) . '</a>';
		}
	}
	if ($buttons) {
		echo '<nav class="action-buttons" aria-label="' . sdwan_ui_escape(gettext('Related pages')) . '">' .
		    implode(' ', $buttons) . '</nav>';
	}
	if ($can_view_events) {
		// System Logs has an exact native page privilege. Filtering via its
		// regular POST form keeps the URL authorized and uses the native CSRF token.
		echo '<form method="post" action="/status_logs.php" id="sdwan-system-logs" hidden>' .
		    '<input type="hidden" name="logfile" value="system">' .
		    '<input type="hidden" name="filterlogentries_submit" value="1">' .
		    '<input type="hidden" name="filterlogentries_process" value="sdwan">' .
		    '</form>';
		?>
		<script>
		events.push(function () {
			// pfSense runs these callbacks after focusing the first visible input.
			const button = document.querySelector('button[form="sdwan-system-logs"]');
			if (button && document.activeElement === button) {
				button.blur();
			}
		});
		</script>
		<?php
	}
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
