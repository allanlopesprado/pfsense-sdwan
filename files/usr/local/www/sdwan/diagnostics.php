<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$snapshot = sdwan_ui_snapshot($sdwan);
$policies = array_column($sdwan['policies'], null, 'name');
$requested = sdwan_ui_scalar($_GET, 'policy');
$current = $requested !== '' ? $requested : ($sdwan['policies'][0]['name'] ?? '');
$policy = $policies[$current] ?? null;
$result = $snapshot['policies'][$current] ?? null;
$slas = array_column($sdwan['slas'], null, 'name');
$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Diagnostics')];
include('head.inc');
sdwan_ui_tabs('diagnostics');
if ($requested !== '' && $policy === null) {
	print_input_errors([gettext('This policy is no longer configured. Select an available policy.')]);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Policy evaluation')?></h2></div>
	<div class="panel-body">
	<?php if (!$policies): ?>
		<p><?=gettext('Create a policy to inspect its candidate members.')?></p>
	<?php else: ?>
		<form method="get" action="/sdwan/diagnostics.php" class="form-inline">
			<div class="form-group">
				<label for="policy"><?=gettext('Policy')?></label>
				<select class="form-control" name="policy" id="policy" required>
					<?php if ($policy === null): ?><option value="" selected><?=gettext('Select a policy')?></option><?php endif; ?>
					<?php foreach ($sdwan['policies'] as $entry): ?>
					<option value="<?=sdwan_ui_escape($entry['name'])?>"<?=$current === $entry['name'] ? ' selected' : ''?>><?=sdwan_ui_escape($entry['name'])?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<button type="submit" class="btn btn-primary"><?=gettext('Inspect')?></button>
		</form>
	<?php endif; ?>
	</div>
	<?php if ($policy !== null):
		$sla = $slas[$policy['sla']];
	?>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?=gettext('Performance SLA')?></dt><dd><?=sdwan_ui_escape($sla['name'])?></dd>
			<dt><?=gettext('Maximum RTT')?></dt><dd><?=sdwan_ui_escape($sla['latency_ms'])?> ms</dd>
			<dt><?=gettext('Maximum loss')?></dt><dd><?=sdwan_ui_escape($sla['loss_pct'])?>%</dd>
			<dt><?=gettext('Recommended member')?></dt><dd><?=sdwan_ui_escape($result['selected'] ?? '—')?></dd>
			<?php if ($result !== null): ?>
			<dt><?=gettext('Selection reason')?></dt><dd><?=sdwan_ui_escape($result['reason'])?></dd>
			<?php endif; ?>
		</dl>
		<?php if ($result === null) {
			print_info_box(gettext('No current sample for this policy. Verify the observer service and gateway monitoring.'), 'warning', false);
		} ?>
	</div>
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
		<thead><tr><th scope="col"><?=gettext('Member')?></th><th scope="col"><?=gettext('Gateway state')?></th>
		<th scope="col"><?=gettext('RTT')?></th><th scope="col"><?=gettext('Loss')?></th><th scope="col"><?=gettext('Evaluation')?></th></tr></thead><tbody>
		<?php foreach ($policy['members'] as $member):
			$reading = $snapshot['members'][$member] ?? [];
			[$cell_class, $state_text] = sdwan_ui_gateway_state($reading['status'] ?? null);
		?>
			<tr><th scope="row"><?=sdwan_ui_escape($member)?></th>
				<td class="<?=$cell_class?>"><strong><?=sdwan_ui_escape($state_text)?></strong></td>
				<td><?=sdwan_ui_metric($reading['rtt_ms'] ?? null, ' ms')?></td>
				<td><?=sdwan_ui_metric($reading['loss_pct'] ?? null, '%')?></td>
				<td><?=sdwan_ui_escape($result['candidates'][$member] ?? gettext('Awaiting evaluation'))?></td></tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	<?php endif;
	sdwan_ui_links([SDWAN_UI_EVENT_LOG => gettext('SD-WAN events'),
	    '/status_logs.php?logfile=gateways' => gettext('Gateway logs'),
	    '/diag_packet_capture.php' => gettext('Packet capture')]); ?>
</div>
<?php include('foot.inc'); ?>
