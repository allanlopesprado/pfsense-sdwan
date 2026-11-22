<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$snapshot = sdwan_ui_snapshot($sdwan);
$policies = array_column($sdwan['policies'], null, 'name');
$requested = sdwan_ui_choice_value(sdwan_ui_scalar($_GET, 'policy'));
$current = $requested !== '' ? $requested : ($sdwan['policies'][0]['name'] ?? '');
$policy = $policies[$current] ?? null;
$result = $snapshot['policies'][$current] ?? null;
$slas = array_column($sdwan['slas'], null, 'name');
$members = array_column($sdwan['members'], null, 'name');
$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Diagnostics')];
include('head.inc');
sdwan_ui_tabs('diagnostics');
if ($requested !== '' && $policy === null) {
	print_input_errors([gettext('This policy is no longer configured. Select an available policy.')]);
}
if (!$policies) {
	print_info_box(gettext('Create a policy to inspect its candidate members.'), 'info', false);
} else {
	$options = $policy === null ? ['' => gettext('Select a policy')] : [];
	foreach ($sdwan['policies'] as $entry) {
		$options[sdwan_ui_choice($entry['name'])] = $entry['name'];
	}
	sdwan_ui_filter('/sdwan/diagnostics.php', [
		'policy' => [gettext('Policy'), $policy === null ? '' : sdwan_ui_choice($current), $options],
	], gettext('Inspect'));
}
if ($policy !== null):
	$sla = $slas[$policy['sla']];
	$use_pool = $policy['strategy'] === 'balance';
	$selected = $use_pool ? null : ($result['selected'] ?? null);
	$use_cost = $policy['strategy'] === 'cost';
	$show_checks = (bool)array_column(array_intersect_key($members, array_fill_keys($policy['members'], true)), 'probe_primary');
	$metrics = [
		'rtt_ms' => [' ms', (float)$sla['latency_ms']],
		'rttsd_ms' => [' ms', isset($sla['rttsd_ms']) ? (float)$sla['rttsd_ms'] : null],
		'loss_pct' => ['%', (float)$sla['loss_pct']],
	];
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Results')?></h2></div>
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-5">
				<p><strong><?=$use_pool ? gettext('Selection strategy') : gettext('Recommended member')?></strong><br>
				<?php if ($selected !== null): ?>
					<?=sdwan_ui_escape($selected)?><br><small><?=sdwan_ui_escape($result['reason'])?></small>
				<?php else: ?>
					<?php if ($use_pool && !empty($result['eligible_count'])): ?>
						<?=sdwan_ui_escape(gettext($result['reason']))?>
					<?php else: ?>
						<?=$result === null ? gettext('Awaiting evaluation') : gettext('No eligible member')?>
					<?php endif; ?>
				<?php endif; ?></p>
			</div>
			<div class="col-sm-5">
				<p><strong><?=gettext('Performance SLA')?></strong><br>
				<?=sdwan_ui_escape($sla['name'])?><br>
				<small><?=sdwan_ui_escape(sprintf(gettext('Maximum RTT: %1$s ms · Maximum loss: %2$s%%'), $sla['latency_ms'], $sla['loss_pct']))?><?php if (isset($sla['rttsd_ms'])): ?><br><?=sdwan_ui_escape(sprintf(gettext('Maximum RTTsd: %s ms'), $sla['rttsd_ms']))?><?php endif; ?></small></p>
			</div>
			<?php if ($result !== null): ?>
			<div class="col-sm-2">
				<p><strong><?=gettext('Eligible members')?></strong><br>
				<?=sdwan_ui_escape(sprintf(gettext('%1$d of %2$d'), count(array_keys($result['candidates'], 'Eligible', true)), count($policy['members'])))?></p>
			</div>
			<?php endif; ?>
		</div>
		<?php if ($result === null) {
			$notice = match (sdwan_service_state()) {
				'stopped' => gettext('The SD-WAN service is stopped.'),
				'unregistered' => gettext('The SD-WAN service is not registered in Status > Services.'),
				default => gettext('No current sample for this policy. Check gateway monitoring.'),
			};
			print_info_box($notice, 'warning', false);
		} ?>
	</div>
	<?php if ($result !== null): ?>
	<div class="table-responsive" tabindex="0" role="region" aria-label="<?=gettext('Member evaluation')?>">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead><tr>
				<th scope="col"><?=gettext('Member / Gateway')?></th>
				<th scope="col"><?=gettext('Decision')?></th>
				<th scope="col"><?=gettext('Gateway status')?></th>
				<th scope="col" class="text-right"><?=gettext('RTT')?></th>
				<th scope="col" class="text-right" title="<?=gettext('RTT standard deviation')?>"><?=gettext('RTTsd')?></th>
				<th scope="col" class="text-right"><?=gettext('Loss')?></th>
				<?php if ($show_checks): ?><th scope="col"><?=gettext('Service checks')?></th><?php endif; ?>
				<?php if ($use_cost): ?><th scope="col" class="text-right"><?=gettext('Cost')?></th><?php endif; ?>
			</tr></thead>
			<tbody>
			<?php foreach ($policy['members'] as $member):
				$gateway = $members[$member]['gateway'] ?? null;
				$reading = $snapshot['members'][$member] ?? [];
				$status = $reading['status'] ?? null;
				[$cell_class, $state_text] = sdwan_ui_gateway_state($status);
				$candidate = $result['candidates'][$member] ?? null;
				$recommended = $selected === $member;
			?>
				<tr>
					<th scope="row"><?=sdwan_ui_escape($member)?>
						<?php if ($gateway !== null && $gateway !== $member): ?><br><small><?=sdwan_ui_escape($gateway)?></small><?php endif; ?>
					</th>
					<td<?=$recommended ? ' class="bg-success"' : ''?>>
						<?php if ($recommended): ?>
							<strong><i class="fa-solid fa-check" aria-hidden="true"></i> <?=gettext('Recommended')?></strong>
						<?php elseif ($candidate === 'Eligible'): ?>
							<?=gettext('Eligible')?>
						<?php elseif ($candidate !== null): ?>
							<strong><?=gettext('Not eligible')?></strong><br><small><?=sdwan_ui_escape($candidate)?></small>
						<?php else: ?>
							<?=gettext('Awaiting evaluation')?>
						<?php endif; ?>
					</td>
					<td class="<?=$cell_class?>"><?=sdwan_ui_escape($state_text)?></td>
					<?php foreach ($metrics as $key => [$unit, $limit]):
						$value = $reading[$key] ?? null;
						$over_limit = $limit !== null && $value !== null && $value > $limit &&
						    in_array($status, ['online', 'degraded'], true);
					?>
					<td class="text-right text-nowrap<?=$over_limit ? ' bg-warning' : ''?>" data-value="<?=sdwan_ui_escape($value)?>">
						<?php if ($over_limit): ?>
							<i class="fa-solid fa-triangle-exclamation" title="<?=sdwan_ui_escape(gettext('Above the SLA limit'))?>" aria-hidden="true"></i>
							<span class="sr-only"><?=gettext('Above the SLA limit')?></span>
						<?php endif; ?>
						<?=sdwan_ui_metric($value, $unit)?>
					</td>
					<?php endforeach; ?>
					<?php if ($show_checks): ?>
					<td><?php foreach (['probe_primary' => gettext('Primary'), 'probe_secondary' => gettext('Secondary')] as $field => $label): ?>
						<?php if (isset($members[$member][$field])): ?>
						<div><?=sdwan_ui_escape($label)?> · <?=sdwan_ui_escape(gettext($reading['checks'][$field] ?? 'Unavailable'))?></div>
						<?php endif; ?>
					<?php endforeach; ?></td>
					<?php endif; ?>
					<?php if ($use_cost): ?>
					<td class="text-right"><?=sdwan_ui_escape($members[$member]['cost'] ?? '—')?></td>
					<?php endif; ?>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php endif; ?>
</div>
<?php endif;
sdwan_ui_actions([
	'/status_logs.php?logfile=gateways' => [gettext('Gateway Logs'), 'fa-list'],
	'/diag_packet_capture.php' => [gettext('Packet Capture'), 'fa-magnifying-glass'],
], true);
include('foot.inc');
