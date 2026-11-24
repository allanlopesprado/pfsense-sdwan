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
	try {
		$config = sdwan_get_config();
	} catch (UnexpectedValueException $error) {
		echo '<p class="sdwan-widget-note">' . $escape(gettext('The stored SD-WAN configuration cannot be read.')) . '</p>';
		return;
	}
	$can_view_forwarding = sdwan_can_view_forwarding();
	$bindings_by_policy = [];
	$bindings_error = false;
	if ($can_view_forwarding) {
		require_once('/usr/local/pkg/sdwan_steering.inc');
		$policies = array_fill_keys(array_column($config['policies'], 'name'), true);
		$orphaned = false;
		try {
			foreach (sdwan_steering_bindings() as $binding) {
				if (isset($policies[$binding['policy']])) {
					$bindings_by_policy[$binding['policy']][] = $binding;
				} else {
					$orphaned = true;
				}
			}
		} catch (UnexpectedValueException $error) {
			$bindings_error = true;
		}
		if ($orphaned) {
			echo '<p class="sdwan-widget-note">' .
			    $escape(gettext('A forwarding binding refers to a policy that no longer exists.')) .
			    ' <a href="/sdwan/forwarding.php">' . $escape(gettext('Review Forwarding')) . '</a></p>';
		}
	}
	if (!$config['policies']) {
		echo '<p class="sdwan-widget-note">' . $escape(gettext('No SD-WAN policies configured.'));
		if (isAllowedPage('/sdwan/policies.php')) {
			echo ' <a href="/sdwan/policies.php">' . $escape(gettext('Configure policies')) . '</a>';
		}
		echo '</p>';
		return;
	}

	$inventory = sdwan_gateways();
	$snapshot = sdwan_service_state() === 'running' ? sdwan_current_snapshot($config, $inventory) : null;
	$members = array_column($config['members'], 'gateway', 'name');
	$can_inspect = isAllowedPage('/sdwan/diagnostics.php');
	$native = null;
	$pf_rules = null;
	if ($snapshot !== null && $bindings_by_policy && sdwan_steering_supported()) {
		$pf_rules = sdwan_steering_pf_rules();
		$native = sdwan_steering_native($inventory);
	}
	?>
	<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed">
		<caption class="sr-only"><?=gettext('SD-WAN policy forwarding')?></caption>
		<thead><tr>
			<th scope="col" class="sdwan-widget-policy"><?=gettext('Policy')?></th>
			<th scope="col" class="sdwan-widget-egress" title="<?=gettext('Egress for new connections')?>"><?=gettext('Egress')?></th>
			<th scope="col"><?=gettext('Status')?></th>
		</tr></thead>
		<tbody>
		<?php foreach ($config['policies'] as $policy):
			$name = $policy['name'];
			$result = $snapshot['policies'][$name] ?? [];
			$candidates = $result['candidates'] ?? [];
			$evaluated = count($candidates) === count($policy['members']) &&
			    !array_diff($policy['members'], array_keys($candidates));
			$eligible = [];
			if ($evaluated) {
				foreach (array_keys($candidates, 'Eligible', true) as $member) {
					$eligible[] = $members[$member];
				}
			}
			$bindings = $bindings_by_policy[$name] ?? [null];
			foreach ($bindings as $binding):
				$group = $binding['group'] ?? null;
				$url = $can_inspect ? '/sdwan/diagnostics.php?policy=' . rawurlencode($name) : null;
				$egress = [];
				$backup = '';
				$detail = '';
				if ($binding !== null) {
					$url = '/sdwan/forwarding.php?' . http_build_query(['policy' => $name, 'group' => $group], '', '&', PHP_QUERY_RFC3986);
					$state = $snapshot['steering'][$group] ?? [];
					$verified = 'unavailable';
					if ($native !== null) {
						$approval = sdwan_steering_preflight($config, $name, $group, $native);
						$valid = sdwan_steering_preflight_matches($binding, $approval) &&
						    $binding['policy_revision'] === sdwan_steering_policy_revision($config, $name);
						$verified = $valid ? sdwan_steering_pf_status($binding, is_array($state) ? $state : [],
						    $inventory, $pf_rules, $approval['rule_pairs']) : 'binding_changed';
					}
					[$color, $status] = match (true) {
						$snapshot === null => ['bg-info', gettext('No current data')],
						$verified === 'applied' => ['bg-success', gettext('Applied')],
						$verified === 'blocked' => ['bg-danger', gettext('Blocked')],
						$verified === 'pending' => ['bg-warning', gettext('Rules pending')],
						$verified === 'binding_changed' => ['bg-warning', gettext('Binding changed')],
						default => ['bg-warning', gettext('Rules unverified')],
					};
					if ($verified === 'applied') {
						$egress = $state['pool'] ?? [$state['gateway']];
						if ($evaluated) {
							$alternatives = array_diff(array_intersect($eligible, $binding['gateways']), $egress);
							if (array_diff($egress, $eligible)) {
								$color = 'bg-warning';
								$detail = gettext('Outside SLA');
							}
							if ($alternatives && (!empty($result['shared_interface']) || !empty($result['shared_underlay']))) {
								$backup = gettext('Shared link');
							} elseif ($alternatives && ($result['shared_interface'] ?? null) === false &&
							    ($result['shared_underlay'] ?? null) === false) {
								$backup = sprintf(gettext('Backup: %s'), implode(', ', $alternatives));
							} elseif (!$alternatives && count($egress) === 1) {
								$backup = gettext('No SLA backup');
							}
						}
					} elseif ($verified === 'blocked' && $evaluated && !$eligible) {
						$detail = gettext('No eligible link');
					}
				} elseif ($bindings_error) {
					[$color, $status] = ['bg-warning', gettext('Bindings unreadable')];
				} elseif ($can_view_forwarding) {
					[$color, $status] = [$evaluated && !$eligible ? 'bg-warning' : '', gettext('Monitor only')];
					$detail = match (true) {
						!$evaluated => gettext('No current data'),
						!$eligible => gettext('No eligible link'),
						default => '',
					};
				} else {
					[$color, $status] = match (true) {
						!$evaluated => ['bg-info', gettext('No current data')],
						!$eligible => ['bg-warning', gettext('No eligible link')],
						default => ['', gettext('Within SLA')],
					};
				}
		?>
			<tr>
				<th scope="row" class="sdwan-widget-name">
					<?php if ($url !== null): ?><a href="<?=$escape($url)?>"><?=$escape($name)?></a><?php else: ?><?=$escape($name)?><?php endif; ?>
					<?php if (count($bindings) > 1): ?><small><?=$escape($group)?></small><?php endif; ?>
				</th>
				<td class="sdwan-widget-route">
					<?=$egress ? $escape(implode(', ', $egress)) : '—'?>
					<?php if ($backup !== ''): ?><small><?=$escape($backup)?></small><?php endif; ?>
				</td>
				<td class="sdwan-widget-status <?=$color?>">
					<?=$escape($status)?>
					<?php if ($detail !== ''): ?><small><?=$escape($detail)?></small><?php endif; ?>
				</td>
			</tr>
		<?php endforeach; endforeach; ?>
		</tbody>
	</table>
	</div>
	<?php
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
.sdwan-status-widget .table { table-layout: fixed; margin-bottom: 0; }
.sdwan-status-widget .table-responsive .table th,
.sdwan-status-widget .table-responsive .table td { white-space: normal; overflow-wrap: anywhere; }
.sdwan-status-widget .table-responsive { margin-bottom: 0; }
.sdwan-status-widget .sdwan-widget-policy { width: 27%; }
.sdwan-status-widget .sdwan-widget-egress { width: 42%; }
.sdwan-status-widget .sdwan-widget-name a { color: inherit; text-decoration: underline; }
.sdwan-status-widget .sdwan-widget-route { font-weight: bold; }
.sdwan-status-widget small { display: block; font-weight: normal; }
.sdwan-status-widget .sdwan-widget-note { padding: .5em; margin: 0; overflow-wrap: anywhere; }
</style>
<div class="sdwan-status-widget" tabindex="-1" role="region" aria-label="<?=gettext('SD-WAN policy forwarding')?>" id="<?=htmlspecialchars($sdwanBodyId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<?php $sdwanFragment(); ?>
	<p class="sdwan-widget-note text-center" role="status" hidden><?=gettext('SD-WAN status unavailable.')?></p>
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
