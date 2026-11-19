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
	$notice = static function (string $icon, string $message) use ($escape): void {
		echo '<p class="text-center sdwan-widget-note"><i class="fa-solid fa-fw ' . $icon .
		    '" aria-hidden="true"></i> ' . $escape($message) . '</p>';
	};
	try {
		$config = sdwan_get_config();
	} catch (UnexpectedValueException $error) {
		$notice('fa-triangle-exclamation text-warning', gettext('The stored SD-WAN configuration cannot be read.'));
		return;
	}
	if (!$config['policies']) {
		$notice('fa-circle-info text-info', gettext('No SD-WAN policies configured.'));
		return;
	}
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config)) {
		$notice('fa-clock text-muted', gettext('Waiting for current gateway measurements.'));
		return;
	}
	$requests = [];
	$bindingError = false;
	if (sdwan_can_view_forwarding()) {
		require_once('/usr/local/pkg/sdwan_steering.inc');
		try {
			foreach (sdwan_steering_bindings() as $binding) {
				$group = $binding['group'];
				$state = $snapshot['steering'][$group] ?? null;
				$target = gettext('Awaiting request');
				if (is_array($state) && ($state['revision'] ?? null) === sdwan_config_revision($binding) &&
				    array_key_exists('gateway', $state)) {
					if ($state['gateway'] === null) {
						$target = gettext('No gateway requested');
					} elseif (in_array($state['gateway'], $binding['gateways'], true)) {
						$target = $state['gateway'];
					}
				}
				$requests[$binding['policy']][$group] = $target;
			}
		} catch (UnexpectedValueException $error) {
			$bindingError = true;
		}
	}
	$details = isAllowedPage('/sdwan/diagnostics.php');
	?>
	<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<caption class="sr-only"><?=gettext('SD-WAN policy status')?></caption>
		<thead><tr>
			<th scope="col" class="sdwan-widget-state"><span class="sr-only"><?=gettext('Status')?></span></th>
			<th scope="col"><?=gettext('Policy')?></th>
			<th scope="col" title="<?=$escape(gettext('Recommended member'))?>"><?=gettext('Member')?></th>
			<th scope="col" class="text-right sdwan-widget-paths" title="<?=$escape(gettext('Eligible paths'))?>"><?=gettext('Paths')?></th>
		</tr></thead>
		<tbody>
		<?php foreach ($config['policies'] as $policy):
			$name = $policy['name'];
			$result = $snapshot['policies'][$name] ?? [];
			$selected = $result['selected'] ?? null;
			$candidates = $result['candidates'] ?? [];
			$total = count($policy['members']);
			$current = count($candidates) === $total && !array_diff($policy['members'], array_keys($candidates));
			$eligible = count(array_keys($candidates, 'Eligible', true));
			[$icon, $state] = match (true) {
				!$current => ['fa-regular fa-clock', gettext('Awaiting evaluation')],
				$eligible === 0 => ['fa-regular fa-circle-xmark text-danger', gettext('No eligible path')],
				$eligible < $total => ['fa-solid fa-triangle-exclamation text-warning', gettext('Limited redundancy')],
				default => ['fa-regular fa-circle-check text-success', gettext('Available')],
			};
			$paths = $current ? sprintf(gettext('%1$d of %2$d eligible'), $eligible, $total) : $state;
		?>
			<tr>
				<td class="text-center" title="<?=$escape($state)?>">
					<i class="<?=$icon?>" aria-hidden="true"></i><span class="sr-only"><?=$escape($state)?></span>
				</td>
				<th scope="row">
					<?php if ($details): ?><a href="/sdwan/diagnostics.php?policy=<?=rawurlencode($name)?>"><?=$escape($name)?></a><?php else: ?><?=$escape($name)?><?php endif; ?>
				</th>
				<td>
					<?php if ($current && $selected !== null): ?>
						<?=$escape($selected)?>
					<?php else: ?>
						<span aria-hidden="true">—</span><span class="sr-only"><?=gettext('No recommendation')?></span>
					<?php endif; ?>
					<?php foreach ($requests[$name] ?? [] as $group => $target): ?>
						<small class="sdwan-widget-detail" title="<?=$escape(sprintf(gettext('Requested gateway · %s'), $group))?>">
							<?=$escape(sprintf(gettext('%1$s: %2$s'), $group, $target))?>
						</small>
					<?php endforeach; ?>
				</td>
				<td class="text-right" title="<?=$escape($paths)?>">
					<span aria-hidden="true"><?=$current ? $escape(sprintf('%d/%d', $eligible, $total)) : '—'?></span>
					<span class="sr-only"><?=$escape($paths)?></span>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php if ($bindingError) {
		$notice('fa-triangle-exclamation text-warning', gettext('Forwarding requests unavailable.'));
	} ?>
	<p class="sdwan-widget-note small"><i class="fa-regular fa-clock" aria-hidden="true"></i>
		<?=gettext('Last sample')?> <time datetime="<?=$escape(date(DATE_ATOM, $snapshot['generated_at']))?>"><?=$escape(date('H:i:s T', $snapshot['generated_at']))?></time></p>
	<?php
};

if ($sdwanDirectRequest) {
	$sdwanRender();
	return;
}
$sdwanBodyId = 'sdwan-status-' . $widgetkey;
?>
<style>
.sdwan-status-widget .table { table-layout: fixed; margin-bottom: 0; }
.sdwan-status-widget .table th, .sdwan-status-widget .table td { white-space: normal; overflow-wrap: anywhere; }
.sdwan-status-widget .table-responsive { margin-bottom: 0; }
.sdwan-status-widget .sdwan-widget-state { width: 2em; }
.sdwan-status-widget .sdwan-widget-paths { width: 4.5em; }
.sdwan-status-widget .sdwan-widget-detail { display: block; }
.sdwan-status-widget .sdwan-widget-note { padding: .4em .5em; margin: 0; }
</style>
<div class="sdwan-status-widget" tabindex="-1" role="region" aria-label="<?=gettext('SD-WAN policy status')?>" id="<?=htmlspecialchars($sdwanBodyId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>"><?php $sdwanRender(); ?></div>
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
