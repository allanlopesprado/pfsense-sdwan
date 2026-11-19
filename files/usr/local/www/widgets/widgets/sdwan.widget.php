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
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config)) {
		$snapshot = null;
	}
	if ($members) {
		$samples = [];
		foreach ($members as $member => $gateway) {
			$samples[$gateway] = $snapshot['members'][$member] ?? [];
		}
	} else {
		$samples = ($snapshot['gateway_inventory_revision'] ?? null) === sdwan_config_revision($inventory) ?
		    $snapshot['gateways'] ?? [] : [];
	}

	$preferred = [];
	$unavailable = [];
	foreach ($config['policies'] as $policy) {
		$name = $policy['name'];
		$result = $snapshot['policies'][$name] ?? null;
		$candidates = $result['candidates'] ?? [];
		if (count($candidates) !== count($policy['members']) ||
		    array_diff($policy['members'], array_keys($candidates))) {
			continue;
		}
		$selected = $result['selected'];
		if (isset($members[$selected]) && isset($inventory[$members[$selected]]) &&
		    !$inventory[$members[$selected]]['monitor_disabled'] &&
		    !$inventory[$members[$selected]]['force_down']) {
			$preferred[$members[$selected]][] = $name;
		} elseif ($selected === null) {
			$unavailable[] = $name;
		}
	}
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
	$metric = static function ($number, string $suffix): string {
		return $number === null ? '—' : rtrim(rtrim(number_format($number, 2, '.', ''), '0'), '.') . $suffix;
	};
	?>
	<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<caption class="sr-only"><?=gettext('SD-WAN link monitoring')?></caption>
		<thead><tr>
			<th scope="col"><?=gettext('Gateway')?></th>
			<th scope="col" class="text-right sdwan-widget-latency"><span class="text-nowrap"><?=gettext('RTT (ms)')?></span></th>
			<th scope="col" class="text-right sdwan-widget-metric"><?=gettext('Loss')?></th>
			<th scope="col" class="sdwan-widget-state"><?=gettext('Status')?></th>
		</tr></thead>
		<tbody>
		<?php foreach ($gateways as $gateway):
			$entry = $inventory[$gateway] ?? null;
			$sample = $samples[$gateway] ?? [];
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
			[$icon, $label] = match ($status) {
				'online' => ['fa-regular fa-circle-check text-success', gettext('Online')],
				'degraded' => ['fa-solid fa-triangle-exclamation text-warning', gettext('Warning')],
				'down' => ['fa-regular fa-circle-xmark text-danger', gettext('Down')],
				'unmonitored' => ['fa-solid fa-ban text-muted', gettext('Unmonitored')],
				default => ['fa-regular fa-circle-question text-muted', gettext('No data')],
			};
		?>
			<tr>
				<th scope="row">
					<?=$escape($gateway)?>
					<?php if (isset($preferred[$gateway])): ?>
						<small class="sdwan-widget-detail">
							<?=sprintf($escape(gettext('Preferred: %s')), $policyLinks($preferred[$gateway]))?>
						</small>
					<?php endif; ?>
				</th>
				<td class="text-right sdwan-widget-rtt"><?=$metric($rtt, '')?></td>
				<td class="text-right"><?=$metric($loss, '%')?></td>
				<td><span class="sdwan-widget-status"><i class="<?=$icon?> fa-fw" aria-hidden="true"></i><span><?=$escape($label)?></span></span></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php if ($unavailable): ?>
		<p class="sdwan-widget-note small"><i class="fa-solid fa-triangle-exclamation text-warning fa-fw" aria-hidden="true"></i>
			<?=sprintf($escape(gettext('No eligible path: %s')), $policyLinks($unavailable))?></p>
	<?php endif;
};

if ($sdwanDirectRequest) {
	$sdwanRender();
	return;
}
$sdwanBodyId = 'sdwan-status-' . $widgetkey;
?>
<style>
.sdwan-status-widget .table { table-layout: fixed; margin-bottom: 0; }
.sdwan-status-widget .table-responsive .table th,
.sdwan-status-widget .table-responsive .table td { white-space: normal; overflow-wrap: anywhere; }
.sdwan-status-widget .table-responsive { margin-bottom: 0; }
.sdwan-status-widget a { color: inherit; text-decoration: underline; }
.sdwan-status-widget .sdwan-widget-latency { width: 72px; }
.sdwan-status-widget .sdwan-widget-metric { width: 52px; }
.sdwan-status-widget .sdwan-widget-state { width: 108px; }
.sdwan-status-widget .sdwan-widget-status { display: inline-flex; align-items: baseline; gap: .3em; }
.sdwan-status-widget .sdwan-widget-status i { flex: none; }
.sdwan-status-widget .sdwan-widget-detail { display: block; font-weight: normal; }
.sdwan-status-widget .sdwan-widget-note { padding: .4em .5em; margin: 0; overflow-wrap: anywhere; }
</style>
<div class="sdwan-status-widget" tabindex="-1" role="region" aria-label="<?=gettext('SD-WAN link monitoring')?>" id="<?=htmlspecialchars($sdwanBodyId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>"><?php $sdwanRender(); ?></div>
<script>
events.push(function () {
	register_ajax({
		name: "SD-WAN",
		url: "/widgets/widgets/sdwan.widget.php",
		parms: {ajax: "ajax", widgetkey: <?=json_encode($widgetkey, JSON_HEX_TAG)?>},
		freq: 10,
		callback: function (html) {
			var body = document.getElementById(<?=json_encode($sdwanBodyId, JSON_HEX_TAG)?>);
			if (!body) return;
			var focused = body.contains(document.activeElement) ? document.activeElement.getAttribute('href') : null;
			$(body).html(html);
			if (focused !== null) {
				var link = Array.from(body.querySelectorAll('a[href]')).find(function (item) {
					return item.getAttribute('href') === focused;
				});
				(link || body).focus({preventScroll: true});
			}
		}
	});
});
</script>
