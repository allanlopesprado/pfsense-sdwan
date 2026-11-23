<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$inventory = sdwan_gateways();
$policies = array_column($sdwan['policies'], null, 'name');
$requested = sdwan_ui_choice_value(sdwan_ui_scalar($_GET, 'policy'));
$selected_policy = $requested !== '' ? $requested : ($sdwan['policies'][0]['name'] ?? '');
$policy = $policies[$selected_policy] ?? null;
$members = array_column($sdwan['members'], null, 'name');
if (sdwan_ui_scalar($_GET, 'traffic') === 'sample') {
	header('Content-Type: application/json; charset=utf-8');
	header('Cache-Control: no-store');
	if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
		header('Allow: GET');
		http_response_code(405);
	} elseif ($policy === null) {
		http_response_code(404);
	} else {
		echo json_encode(sdwan_ui_traffic_sample($policy, $members, $inventory, sdwan_config_revision($sdwan)),
		    JSON_THROW_ON_ERROR);
	}
	exit;
}
$snapshot = sdwan_ui_snapshot($sdwan, $inventory, $sample_state);
$result = $snapshot['policies'][$selected_policy] ?? null;
$slas = array_column($sdwan['slas'], null, 'name');
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
		'policy' => [gettext('Policy'), $policy === null ? '' : sdwan_ui_choice($selected_policy), $options],
	], gettext('Inspect'));
}
if ($policy !== null):
	$issues = [];
	foreach ($policy['members'] as $member) {
		$gateway = $members[$member]['gateway'];
		$issue = sdwan_ui_gateway_config_issue($gateway, $inventory);
		if ($issue !== null) {
			$issues[] = sdwan_ui_escape(sprintf(gettext('%1$s (%2$s): %3$s. Check System > Routing.'),
			    $member, $gateway, $issue));
		}
	}
	if ($issues) {
		print_info_box(implode('<br>', $issues), 'warning', false);
	}
	$sla = $slas[$policy['sla']];
	$use_pool = $policy['strategy'] === 'balance';
	$selected = $use_pool ? null : ($result['selected'] ?? null);
	$use_cost = $policy['strategy'] === 'cost';
	$show_checks = (bool)array_column(array_intersect_key($members, array_fill_keys($policy['members'], true)), 'probe_primary');
	$overrides = array_column($policy['probe_requirements'] ?? [], null, 'member');
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
			print_info_box(sdwan_ui_sample_notice($sample_state), 'warning', false);
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
					<?php $requirements = sdwan_policy_probe_requirements($policy, $members[$member], $overrides[$member] ?? []); ?>
					<td><?php foreach (['probe_primary' => gettext('Primary'), 'probe_secondary' => gettext('Secondary')] as $field => $label): ?>
						<?php if (isset($members[$member][$field])): ?>
						<?php $requirement = $requirements[$field] ?? 'ignored'; ?>
						<div><?=sdwan_ui_escape($label)?> · <?=sdwan_ui_escape(gettext($reading['checks'][$field] ?? 'Unavailable'))?><?php if ($requirement !== 'optional'): ?> · <?=sdwan_ui_escape($requirement === 'required' ? gettext('Required') : gettext('Ignored'))?><?php endif; ?></div>
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
<?php if (function_exists('pfSense_get_interface_stats')):
	$traffic_url = '/sdwan/diagnostics.php?' . http_build_query([
		'policy' => sdwan_ui_choice($selected_policy), 'traffic' => 'sample',
	], '', '&', PHP_QUERY_RFC3986);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Interface traffic')?></h2></div>
	<div class="panel-body">
		<p><?=gettext('Measure the total traffic on this policy’s interfaces. This is independent of SLA and path selection.')?></p>
		<button type="button" class="btn btn-default" id="sdwan-traffic-measure"
		    data-url="<?=sdwan_ui_escape($traffic_url)?>"
		    data-wait="<?=sdwan_ui_escape(gettext('Measuring interface traffic…'))?>"
		    data-unavailable="<?=sdwan_ui_escape(gettext('No comparable interface counters. Try again.'))?>">
			<?=gettext('Measure')?></button>
		<p class="help-block" role="status" id="sdwan-traffic-report"></p>
		<div class="table-responsive" id="sdwan-traffic-results" hidden>
			<table class="table table-striped table-condensed">
				<thead><tr><th scope="col"><?=gettext('Interface')?></th>
				<th scope="col" class="text-right"><?=gettext('Receive')?></th>
				<th scope="col" class="text-right"><?=gettext('Transmit')?></th></tr></thead>
				<tbody></tbody>
			</table>
		</div>
	</div>
</div>
<script>
events.push(function () {
	const button = document.getElementById('sdwan-traffic-measure');
	const report = document.getElementById('sdwan-traffic-report');
	const results = document.getElementById('sdwan-traffic-results');
	const body = results.querySelector('tbody');
	const format = new Intl.NumberFormat(undefined, {maximumFractionDigits: 2});
	const units = [[1e9, 'Gbit/s'], [1e6, 'Mbit/s'], [1e3, 'kbit/s'], [1, 'bit/s']];
	const decimal = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value);
	function rate(delta, elapsed) {
		const bps = Number(delta) * 8e9 / Number(elapsed);
		const [scale, unit] = units.find(([value]) => bps >= value) || units[3];
		return format.format(bps / scale) + ' ' + unit;
	}
	button.addEventListener('click', async function () {
		button.disabled = true;
		results.hidden = true;
		body.replaceChildren();
		report.textContent = button.dataset.wait;
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 8000);
		try {
			async function sample() {
				const response = await fetch(button.dataset.url, {cache: 'no-store', signal: controller.signal});
				if (!response.ok) throw new Error('Interface sample unavailable');
				return response.json();
			}
			const first = await sample();
			await new Promise(resolve => setTimeout(resolve, 1500));
			const second = await sample();
			if (first.revision === second.revision) {
				for (const [device, current] of Object.entries(second.interfaces)) {
					const previous = first.interfaces[device];
					const keys = ['at_ns', 'inbytes', 'outbytes'];
					if (!previous || !keys.every(key => decimal(previous[key]) && decimal(current[key]))) continue;
					const elapsed = BigInt(current.at_ns) - BigInt(previous.at_ns);
					const received = BigInt(current.inbytes) - BigInt(previous.inbytes);
					const sent = BigInt(current.outbytes) - BigInt(previous.outbytes);
					if (elapsed < 1000000000n || elapsed > 30000000000n || received < 0n || sent < 0n) continue;
					const row = body.insertRow();
					const label = document.createElement('th');
					label.scope = 'row';
					label.textContent = device;
					row.append(label);
					for (const delta of [received, sent]) {
						const cell = row.insertCell();
						cell.className = 'text-right text-nowrap';
						cell.textContent = rate(delta, elapsed);
					}
				}
			}
			results.hidden = body.rows.length === 0;
		} catch {
			results.hidden = true;
		} finally {
			clearTimeout(timeout);
			report.textContent = results.hidden ? button.dataset.unavailable : '';
			button.disabled = false;
		}
	});
});
</script>
<?php endif; ?>
<?php endif;
sdwan_ui_actions([
	'/status_logs.php?logfile=gateways' => [gettext('Gateway Logs'), 'fa-list'],
	'/diag_packet_capture.php' => [gettext('Packet Capture'), 'fa-magnifying-glass'],
], true);
include('foot.inc');
