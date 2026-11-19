<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$snapshot = sdwan_ui_snapshot($sdwan);
$path_states = [
	'single' => ['bg-success', gettext('Single path')],
	'no_eligible' => ['bg-danger', gettext('No eligible path')],
	'degraded' => ['bg-warning', gettext('One eligible path remains')],
	'alternatives' => ['bg-success', gettext('Multiple eligible paths')],
];
$can_inspect = isAllowedPage('/sdwan/diagnostics.php');
$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Status')];
include('head.inc');
sdwan_ui_tabs('status');
if (!$sdwan['members']) {
	print_info_box(gettext('Configure a member and a performance SLA to start monitoring a path.'), 'info', false);
} elseif ($snapshot === null) {
	print_info_box(gettext('Waiting for current gateway measurements. Check the observer service and Diagnostics.'), 'warning', false);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Policy Status')?></h2></div>
	<div class="panel-body">
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
		<thead><tr><th scope="col"><?=gettext('Policy')?></th><th scope="col"><?=gettext('Recommended Member')?></th>
			<th scope="col"><?=gettext('Eligible Paths')?></th><th scope="col"><?=gettext('Status')?></th></tr></thead>
		<tbody>
		<?php foreach ($sdwan['policies'] as $policy):
			$result = $snapshot['policies'][$policy['name']] ?? [];
			[$path_class, $path_text] = $path_states[$result['path_status'] ?? ''] ?? ['bg-info', gettext('Awaiting evaluation')];
		?>
			<tr><th scope="row"><?php if ($can_inspect): ?><a href="/sdwan/diagnostics.php?policy=<?=rawurlencode($policy['name'])?>" title="<?=gettext('View policy diagnostics')?>"><?=sdwan_ui_escape($policy['name'])?></a><?php else: ?><?=sdwan_ui_escape($policy['name'])?><?php endif; ?></th>
				<td><?=sdwan_ui_escape($result['selected'] ?? '—')?></td>
				<td><?=isset($result['eligible_count']) ? sdwan_ui_escape(sprintf(gettext('%1$d of %2$d'), $result['eligible_count'], count($policy['members']))) : '—'?></td>
				<td class="<?=$path_class?>"><strong><?=sdwan_ui_escape($path_text)?></strong>
					<?php if (!empty($result['shared_interface'])): ?>
						<br><small><?=gettext('Members share a gateway interface.')?></small>
					<?php elseif (!empty($result['shared_underlay'])): ?>
						<br><small><?=gettext('Members share a transport interface.')?></small>
					<?php endif; ?>
				</td></tr>
		<?php endforeach;
		if (!$sdwan['policies']) {
			sdwan_ui_empty(gettext('No policies configured.'), 4);
		}
		?>
		</tbody>
	</table></div>
	<?php if ($snapshot !== null): ?>
	<p><small><?=gettext('Last sample')?>:
		<time datetime="<?=date(DATE_ATOM, $snapshot['generated_at'])?>"><?=sdwan_ui_escape(date('Y-m-d H:i:s T', $snapshot['generated_at']))?></time></small></p>
	<?php endif; ?>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Gateway Status')?></h2></div>
	<div class="panel-body">
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
		<thead><tr><th scope="col"><?=gettext('Member')?></th><th scope="col"><?=gettext('Gateway')?></th>
			<th scope="col"><?=gettext('RTT')?></th><th scope="col" title="<?=gettext('RTT standard deviation')?>"><?=gettext('RTTsd')?></th>
			<th scope="col"><?=gettext('Loss')?></th><th scope="col"><?=gettext('Status')?></th></tr></thead>
		<tbody>
		<?php foreach ($sdwan['members'] as $member):
			$reading = $snapshot['members'][$member['name']] ?? [];
			[$cell_class, $state_text] = sdwan_ui_gateway_state($reading['status'] ?? null);
		?>
			<tr><th scope="row"><?=sdwan_ui_escape($member['name'])?></th><td><?=sdwan_ui_escape($member['gateway'])?></td>
				<td><?=sdwan_ui_metric($reading['rtt_ms'] ?? null, ' ms')?></td>
				<td><?=sdwan_ui_metric($reading['rttsd_ms'] ?? null, ' ms')?></td>
				<td><?=sdwan_ui_metric($reading['loss_pct'] ?? null, '%')?></td>
				<td class="<?=$cell_class?>"><strong><?=sdwan_ui_escape($state_text)?></strong></td></tr>
		<?php endforeach;
		if (!$sdwan['members']) {
			sdwan_ui_empty(gettext('Add a member to observe an existing gateway.'), 6);
		}
		?>
		</tbody>
	</table></div>
	</div>
</div>
<?php
sdwan_ui_actions([
	'/status_gateways.php' => [gettext('Gateways'), 'fa-network-wired'],
	'/status_services.php' => [gettext('Services'), 'fa-gears'],
], true);
include('foot.inc');
