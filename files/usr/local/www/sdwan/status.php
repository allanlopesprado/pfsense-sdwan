<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$snapshot = sdwan_ui_snapshot($sdwan);
$path_labels = [
	'single' => gettext('Single path'),
	'no_eligible' => gettext('No eligible path'),
	'degraded' => gettext('One eligible path remains'),
	'alternatives' => gettext('Multiple eligible paths'),
];
$can_inspect = isAllowedPage('/sdwan/diagnostics.php');
$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Status')];
include('head.inc');
sdwan_ui_tabs('status');
if (!$sdwan['members']) {
	print_info_box(gettext('Configure a member and a performance SLA to start monitoring a path.'), 'info', false);
} elseif ($snapshot === null) {
	print_info_box(gettext('Waiting for current gateway measurements. Check the observer service and Diagnostics.'), 'warning', false);
} elseif ($sdwan['policies']) {
	$unavailable = $reduced = $pending = 0;
	foreach ($sdwan['policies'] as $policy) {
		$state = $snapshot['policies'][$policy['name']]['path_status'] ?? null;
		$unavailable += (int)($state === 'no_eligible');
		$reduced += (int)($state === 'degraded');
		$pending += (int)($state === null);
	}
	$summary = [];
	if ($unavailable) {
		$summary[] = sprintf(gettext('Policies without an eligible path: %d.'), $unavailable);
	}
	if ($reduced) {
		$summary[] = sprintf(gettext('Policies down to one eligible path: %d.'), $reduced);
	}
	if ($pending) {
		$summary[] = sprintf(gettext('Policies awaiting evaluation: %d.'), $pending);
	}
	print_info_box($summary ? implode(' ', $summary) : gettext('Every policy has an eligible path within its SLA.'),
	    $unavailable ? 'danger' : ($reduced || $pending ? 'warning' : 'success'), false);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Policy recommendations')?></h2></div>
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
		<thead><tr><th><?=gettext('Policy')?></th><th><?=gettext('Eligible paths')?></th><th><?=gettext('Recommended member')?></th><th><?=gettext('Reason')?></th></tr></thead>
		<tbody>
		<?php foreach ($sdwan['policies'] as $policy):
			$result = $snapshot['policies'][$policy['name']] ?? [];
		?>
			<tr><td><?php if ($can_inspect): ?><a href="/sdwan/diagnostics.php?policy=<?=rawurlencode($policy['name'])?>"><?=sdwan_ui_escape($policy['name'])?></a><?php else: ?><?=sdwan_ui_escape($policy['name'])?><?php endif; ?></td>
				<td><?php if (isset($path_labels[$result['path_status'] ?? ''], $result['eligible_count'])): ?>
					<?=sdwan_ui_escape(sprintf(gettext('%1$d of %2$d · %3$s'), $result['eligible_count'], count($policy['members']), $path_labels[$result['path_status']]))?>
					<?php if (!empty($result['shared_interface'])): ?>
						<div class="text-warning"><?=gettext('Members share a gateway interface.')?></div>
					<?php elseif (!empty($result['shared_underlay'])): ?>
						<div class="text-warning"><?=gettext('Members share a transport interface.')?></div>
					<?php endif; ?>
				<?php else: ?>—<?php endif; ?></td>
				<td><?=sdwan_ui_escape($result['selected'] ?? '—')?></td>
				<td><?=sdwan_ui_escape($result['reason'] ?? gettext('Awaiting evaluation'))?></td></tr>
		<?php endforeach;
		if (!$sdwan['policies']) {
			sdwan_ui_empty(gettext('No policies configured.'), 4);
		}
		?>
		</tbody>
	</table></div>
	<?php if ($snapshot !== null): ?>
	<div class="panel-footer"><?=sdwan_ui_escape(sprintf(gettext('Last sample: %s'), date('Y-m-d H:i:s T', $snapshot['generated_at'])))?></div>
	<?php endif; ?>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Gateway measurements')?></h2></div>
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
		<thead><tr><th><?=gettext('Member')?></th><th><?=gettext('Gateway')?></th><th><?=gettext('State')?></th>
			<th><?=gettext('RTT')?></th><th><?=gettext('RTT standard deviation')?></th><th><?=gettext('Loss')?></th></tr></thead>
		<tbody>
		<?php foreach ($sdwan['members'] as $member):
			$reading = $snapshot['members'][$member['name']] ?? [];
			[$cell_class, $state_text] = sdwan_ui_gateway_state($reading['status'] ?? null);
		?>
			<tr><td><?=sdwan_ui_escape($member['name'])?></td><td><?=sdwan_ui_escape($member['gateway'])?></td>
				<td class="<?=$cell_class?>"><strong><?=sdwan_ui_escape($state_text)?></strong></td>
				<td><?=sdwan_ui_metric($reading['rtt_ms'] ?? null, ' ms')?></td>
				<td><?=sdwan_ui_metric($reading['rttsd_ms'] ?? null, ' ms')?></td>
				<td><?=sdwan_ui_metric($reading['loss_pct'] ?? null, '%')?></td></tr>
		<?php endforeach;
		if (!$sdwan['members']) {
			sdwan_ui_empty(gettext('Add a member to observe an existing gateway.'), 6);
		}
		?>
		</tbody>
	</table></div>
	<?php sdwan_ui_links(['/status_gateways.php' => gettext('Gateway status'),
	    SDWAN_UI_EVENT_LOG => gettext('SD-WAN events'),
	    '/status_services.php' => gettext('Services')]); ?>
</div>
<?php include('foot.inc'); ?>
