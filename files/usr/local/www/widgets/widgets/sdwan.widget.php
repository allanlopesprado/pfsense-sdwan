<?php
require_once('guiconfig.inc');

/* index.php supplies the key on rendering. A refresh is a separate request. */
$sdwanDirectRequest = !isset($widgetkey);
if (!isAllowedPage('/sdwan/status.php')) {
	if ($sdwanDirectRequest) {
		http_response_code(403);
	}
	echo gettext('SD-WAN status permission is required.');
	return;
}
if ($sdwanDirectRequest) {
	$sdwanKey = $_POST['widgetkey'] ?? '';
	if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || ($_POST['ajax'] ?? '') !== 'ajax' ||
	    !is_string($sdwanKey) || !preg_match('/\Asdwan-[0-9]+\z/', $sdwanKey) ||
	    !is_valid_widgetkey($sdwanKey, $user_settings, __FILE__)) {
		http_response_code(400);
		return;
	}
}

require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');

$sdwanRender = static function (): void {
	$escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	$notice = static function (string $message) use ($escape): void {
		echo '<p class="text-center sdwan-widget-note">' . $escape($message) . '</p>';
	};
	try {
		$config = sdwan_get_config();
	} catch (UnexpectedValueException $error) {
		$notice(gettext('The stored SD-WAN configuration cannot be read.'));
		return;
	}

	$inventory = sdwan_gateways();
	$members = array_column($config['members'], 'gateway', 'name');
	$gateways = $members ? array_values($members) : array_keys($inventory);
	if (!$gateways) {
		$notice(gettext('No available gateways.'));
		return;
	}
	$snapshot = sdwan_current_snapshot($config, $inventory);
	if ($members) {
		$samples = [];
		foreach ($members as $member => $gateway) {
			$samples[$gateway] = $snapshot['members'][$member] ?? [];
		}
	} else {
		$samples = $snapshot['gateways'] ?? [];
	}

	$unavailable = [];
	foreach ($config['policies'] as $policy) {
		$name = $policy['name'];
		$result = $snapshot['policies'][$name] ?? null;
		if ($result === null || $result['selected'] !== null) {
			continue;
		}
		$candidates = $result['candidates'] ?? [];
		if (count($candidates) !== count($policy['members']) ||
		    array_diff($policy['members'], array_keys($candidates))) {
			continue;
		}
		$unavailable[] = $name;
	}
	$defaults = [
		'inet' => config_get_path('gateways/defaultgw4', ''),
		'inet6' => config_get_path('gateways/defaultgw6', ''),
	];
	$canSeeDetails = isAllowedPage('/sdwan/diagnostics.php');
	$policyLinks = static function (array $policies) use ($escape, $canSeeDetails): string {
		$labels = [];
		foreach ($policies as $policy) {
			$label = $escape($policy);
			$labels[] = $canSeeDetails ?
			    '<a href="/sdwan/diagnostics.php?policy=' . rawurlencode($policy) . '">' . $label . '</a>' : $label;
		}
		return implode(', ', $labels);
	};
	$metric = static function (?float $number, int $precision, string $unit): string {
		return $number === null ? '—' : number_format($number, $precision, '.', '') . $unit;
	};
	?>
	<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<caption class="sr-only"><?=gettext('SD-WAN link monitoring')?></caption>
		<thead><tr>
			<th scope="col" class="sdwan-widget-icon" aria-hidden="true"></th>
			<th scope="col"><?=gettext('Name')?></th>
			<th scope="col" class="sdwan-widget-latency" title="<?=gettext('Round-trip time')?>">RTT</th>
			<th scope="col" class="sdwan-widget-latency" title="<?=gettext('RTT standard deviation')?>">RTTsd</th>
			<th scope="col" class="sdwan-widget-loss"><?=gettext('Loss')?></th>
			<th scope="col" class="sdwan-widget-state"><?=gettext('Status')?></th>
		</tr></thead>
		<tbody>
		<?php foreach ($gateways as $gateway):
			$entry = $inventory[$gateway] ?? null;
			$sample = $samples[$gateway] ?? [];
			$address = $entry['address'] ?? null;
			if ($address === 'dynamic') {
				require_once('gwlb.inc');
				$address = $entry['family'] === 'inet6' ? get_interface_gateway_v6($entry['interface']) :
				    get_interface_gateway($entry['interface']);
			}
			$display_address = is_string($address) && filter_var(explode('%', $address, 2)[0], FILTER_VALIDATE_IP);
			$is_default = ($defaults[$entry['family'] ?? ''] ?? '') === $gateway;
			$status = $sample['status'] ?? 'unknown';
			if ($entry === null || $entry['force_down']) {
				$status = 'down';
				$sample = [];
			} elseif ($entry['monitor_disabled']) {
				$status = 'unmonitored';
				$sample = [];
			} elseif ($status === 'unknown') {
				$sample = [];
			}
			$loss = $sample['loss_pct'] ?? null;
			$rtt = $loss >= 100 ? null : ($sample['rtt_ms'] ?? null);
			$rttsd = $loss >= 100 ? null : ($sample['rttsd_ms'] ?? null);
			[$icon, $state_class, $label] = match ($status) {
				'online' => ['fa-regular fa-circle-check', 'bg-success', gettext('Online')],
				'degraded' => ['fa-solid fa-triangle-exclamation', 'bg-warning', gettext('Warning')],
				'down' => ['fa-regular fa-circle-xmark', 'bg-danger', gettext('Down')],
				'unmonitored' => ['fa-solid fa-ban', 'bg-info', gettext('Monitor off')],
				default => ['fa-regular fa-circle-question', 'bg-info', gettext('No data')],
			};
		?>
			<tr>
				<td class="sdwan-widget-icon" aria-hidden="true"><i class="<?=$icon?> fa-fw"></i></td>
				<th scope="row" class="sdwan-widget-name">
					<span class="sdwan-widget-label"><?=$escape($gateway)?></span>
					<?php if ($is_default): ?>
						<i class="fa-solid fa-globe" role="img" aria-label="<?=$escape(gettext('Configured default gateway'))?>"
						    title="<?=$escape(gettext('Configured default gateway'))?>"></i>
					<?php endif; ?>
					<?php if ($display_address): ?>
						<strong class="sdwan-widget-address"><?=$escape($address)?></strong>
					<?php endif; ?>
				</th>
				<td class="sdwan-widget-rtt"><?=$metric($rtt, 3, 'ms')?></td>
				<td class="sdwan-widget-rttsd"><?=$metric($rttsd, 3, 'ms')?></td>
				<td class="sdwan-widget-loss"><?=$metric($loss, 1, '%')?></td>
				<td class="sdwan-widget-status <?=$state_class?>"><?=$escape($label)?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php if ($unavailable): ?>
		<p class="sdwan-widget-note bg-warning small">
			<i class="fa-solid fa-triangle-exclamation fa-fw" aria-hidden="true"></i>
			<?=sprintf($escape(gettext('No eligible path: %s')), $policyLinks($unavailable))?>
		</p>
	<?php endif;
};

// Mark valid fragments so a login or error page cannot replace the widget.
$sdwanFragment = static function () use ($sdwanRender): void {
	echo '<div class="sdwan-widget-content">';
	$sdwanRender();
	echo '</div>';
};

if ($sdwanDirectRequest) {
	$sdwanFragment();
	return;
}
$sdwanBodyId = 'sdwan-status-' . $widgetkey;
?>
<style>
.sdwan-status-widget { container-type: inline-size; }
.sdwan-status-widget .table { table-layout: fixed; margin-bottom: 0; }
.sdwan-status-widget .table-responsive .table th,
.sdwan-status-widget .table-responsive .table td { white-space: normal; overflow-wrap: anywhere; }
.sdwan-status-widget .table-responsive { margin-bottom: 0; }
.sdwan-status-widget a { color: inherit; text-decoration: underline; }
.sdwan-status-widget .sdwan-widget-icon { width: 8%; text-align: center; }
.sdwan-status-widget .sdwan-widget-icon i { font-size: 1.13em; }
.sdwan-status-widget .sdwan-widget-name { font-weight: normal; }
.sdwan-status-widget .sdwan-widget-latency { width: 19%; text-align: right; }
.sdwan-status-widget .sdwan-widget-loss { width: 11%; text-align: right; }
.sdwan-status-widget .sdwan-widget-state { width: 14%; }
.sdwan-status-widget .sdwan-widget-rtt,
.sdwan-status-widget .sdwan-widget-rttsd,
.sdwan-status-widget .sdwan-widget-loss { font-variant-numeric: tabular-nums; text-align: right; }
.sdwan-status-widget .sdwan-widget-address { display: block; }
@container (max-width: 439px) {
	.sdwan-status-widget .table { font-size: 12px; }
	.sdwan-status-widget .table > thead > tr > th,
	.sdwan-status-widget .table > tbody > tr > th,
	.sdwan-status-widget .table > tbody > tr > td { padding-right: 2px; padding-left: 2px; }
	.sdwan-status-widget .sdwan-widget-icon { width: 20px; }
	.sdwan-status-widget .sdwan-widget-address { font-size: .9em; }
	.sdwan-status-widget .sdwan-widget-latency { width: 18.5%; }
	.sdwan-status-widget .sdwan-widget-loss { width: 14.5%; }
	.sdwan-status-widget .sdwan-widget-state { width: 16.5%; }
}
.sdwan-status-widget .sdwan-widget-note { padding: .4em .5em; margin: 0; overflow-wrap: anywhere; }
</style>
<div class="sdwan-status-widget" tabindex="-1" role="region" aria-label="<?=gettext('SD-WAN link monitoring')?>" id="<?=htmlspecialchars($sdwanBodyId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<?php $sdwanFragment(); ?>
	<p class="sdwan-widget-note text-center" role="status" hidden><?=gettext('Gateway status unavailable.')?></p>
</div>
<script>
events.push(function () {
	const body = document.getElementById(<?=json_encode($sdwanBodyId, JSON_HEX_TAG)?>);
	if (!body) return;
	const notice = body.querySelector('[role="status"]');
	let content = body.querySelector('.sdwan-widget-content');
	let refreshTimeout;

	function waitForRefresh() {
		notice.hidden = true;
		clearTimeout(refreshTimeout);
		refreshTimeout = setTimeout(function () {
			if (content.contains(document.activeElement)) body.focus({preventScroll: true});
			content.hidden = true;
			notice.hidden = false;
		}, <?=SDWAN_MAX_SNAPSHOT_AGE * 1000?>);
	}

	waitForRefresh();
	register_ajax({
		name: "SD-WAN",
		url: "/widgets/widgets/sdwan.widget.php",
		parms: {ajax: "ajax", widgetkey: <?=json_encode($widgetkey, JSON_HEX_TAG)?>},
		freq: 10,
		callback: function (html) {
			if (!body.isConnected) return;
			const fragment = document.createElement('template');
			fragment.innerHTML = html;
			const next = fragment.content.firstElementChild;
			if (!next || next.nextElementSibling || !next.classList.contains('sdwan-widget-content')) return;
			const focused = content.contains(document.activeElement) ? document.activeElement.getAttribute('href') : null;
			content.replaceWith(next);
			content = next;
			waitForRefresh();
			if (focused !== null) {
				const link = Array.from(content.querySelectorAll('a[href]')).find(function (item) {
					return item.getAttribute('href') === focused;
				});
				(link || body).focus({preventScroll: true});
			}
		}
	});
});
</script>
