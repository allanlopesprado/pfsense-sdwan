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
		echo '<p class="sdwan-widget-note"><i class="fa-solid fa-fw ' . $icon .
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
	if (isAllowedPage('/sdwan/forwarding.php')) {
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
	<table class="table table-striped table-hover table-condensed">
		<caption class="sr-only"><?=gettext('SD-WAN policy status')?></caption>
		<thead><tr><th scope="col"><?=gettext('Policy')?></th>
			<th scope="col"><?=$requests ? gettext('Path selection') : gettext('Recommended member')?></th></tr></thead>
		<tbody>
		<?php foreach ($config['policies'] as $policy):
			$name = $policy['name'];
			$result = $snapshot['policies'][$name] ?? [];
			$selected = $result['selected'] ?? null;
			$candidates = $result['candidates'] ?? [];
			$total = count($policy['members']);
			$current = count($candidates) === $total && !array_diff($policy['members'], array_keys($candidates));
			$eligible = count(array_keys($candidates, 'Eligible', true));
			$icon = match (true) {
				!$current => 'fa-clock text-muted',
				$eligible === 0 => 'fa-circle-xmark text-danger',
				$eligible < $total => 'fa-triangle-exclamation text-warning',
				default => 'fa-circle-check text-success',
			};
		?>
			<tr>
				<th scope="row">
					<?php if ($details): ?><a href="/sdwan/diagnostics.php?policy=<?=rawurlencode($name)?>"><?=$escape($name)?></a><?php else: ?><?=$escape($name)?><?php endif; ?>
					<small class="sdwan-widget-detail"><i class="fa-solid <?=$icon?>" aria-hidden="true"></i>
						<?=$current ? $escape(sprintf(gettext('%1$d of %2$d eligible'), $eligible, $total)) : gettext('Awaiting evaluation')?></small>
				</th>
				<td><?php if ($requests): ?><small class="sdwan-widget-detail"><?=gettext('Recommended member')?></small><?php endif; ?>
					<?=$escape($current && $selected !== null ? $selected : gettext('No recommendation'))?>
					<?php foreach ($requests[$name] ?? [] as $group => $target): ?>
						<div class="sdwan-widget-request">
							<small class="sdwan-widget-detail"><?=$escape(sprintf(gettext('Requested gateway · %s'), $group))?></small>
							<?=$escape($target)?>
						</div>
					<?php endforeach; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
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
.sdwan-status-widget .table { width: 100%; table-layout: fixed; margin-bottom: 0; }
.sdwan-status-widget th, .sdwan-status-widget td { white-space: normal; overflow-wrap: anywhere; }
.sdwan-status-widget thead th:first-child { width: 42%; }
.sdwan-status-widget .sdwan-widget-detail { display: block; font-weight: normal; }
.sdwan-status-widget .sdwan-widget-request { margin-top: .25em; }
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
