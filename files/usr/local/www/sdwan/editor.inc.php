<?php
if (!defined('SDWAN_GUI')) {
	http_response_code(404);
	exit;
}

$sections = [
	'members' => gettext('Members'),
	'slas' => gettext('Performance SLAs'),
	'policies' => gettext('Policies'),
];
$columns = [
	'members' => ['name' => gettext('Name'), 'gateway' => gettext('Gateway'), 'cost' => gettext('Cost'),
	    'probe_primary' => gettext('Primary service check'), 'probe_secondary' => gettext('Secondary service check')],
	'slas' => ['name' => gettext('Name'), 'latency_ms' => gettext('Maximum RTT (ms)'), 'rttsd_ms' => gettext('Maximum RTTsd (ms)'), 'loss_pct' => gettext('Maximum loss (%)')],
	'policies' => ['name' => gettext('Name'), 'sla' => gettext('Performance SLA'), 'members' => gettext('Members'), 'strategy' => gettext('Selection strategy')],
];
$strategies = ['cost' => gettext('Lowest cost'), 'latency' => gettext('Lowest RTT'),
    'balance' => gettext('Weighted balancing within SLA')];
$url = '/sdwan/' . $collection . '.php';
$revision = sdwan_config_revision($sdwan);
$rows = $sdwan[$collection];
$names = array_column($rows, 'name');
$editing = sdwan_ui_scalar($_GET, 'edit');
$original = $editing;
$display_form = isset($_GET['edit']) || isset($_GET['add']);
$errors = [];
$sdwan_record = [];
$used_by = [];
foreach ($sdwan['policies'] as $policy) {
	$references = $collection === 'members' ? $policy['members'] :
	    ($collection === 'slas' ? [$policy['sla']] : []);
	foreach ($references as $reference) {
		$used_by[$reference][] = $policy['name'];
	}
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = sdwan_ui_scalar($_POST, 'action');
	$original = sdwan_ui_scalar($_POST, 'original');
	$position = array_search($original, $names, true);
	$expected_revision = sdwan_ui_scalar($_POST, 'revision');
	if (!hash_equals($revision, $expected_revision)) {
		$errors[] = gettext('Configuration changed. Reload this page and review the current values.');
		$display_form = false;
	} elseif ($original !== '' && $position === false) {
		$errors[] = gettext('This entry no longer exists.');
	} elseif ($action === 'delete' && $original !== '') {
		if (isset($used_by[$original])) {
			$errors[] = sprintf(gettext('Remove this entry from the following policies first: %s.'), implode(', ', $used_by[$original]));
		} else {
			unset($rows[$position]);
		}
	} elseif ($action === 'save') {
		$display_form = true;
		foreach ($columns[$collection] as $key => $label) {
			if ($key === 'members') {
				$selected = $_POST[$key] ?? [];
				if (!is_array($selected) || array_filter($selected, 'is_string') !== $selected) {
					$errors[] = gettext('Select valid members.');
					$selected = [];
				}
				$sdwan_record[$key] = array_map('sdwan_ui_choice_value', array_values($selected));
			} elseif (in_array($key, ['sla', 'gateway'], true)) {
				$sdwan_record[$key] = sdwan_ui_choice_value(sdwan_ui_scalar($_POST, $key));
			} else {
				$sdwan_record[$key] = sdwan_ui_scalar($_POST, $key);
			}
		}
		if ($collection === 'policies') {
			foreach (['primary_check', 'secondary_check', 'degrade_samples', 'recover_seconds'] as $field) {
				if (array_key_exists($field, $_POST)) {
					$sdwan_record[$field] = sdwan_ui_scalar($_POST, $field);
				}
			}
		}
		$optional = ['members' => ['probe_primary', 'probe_secondary'], 'slas' => ['rttsd_ms'],
		    'policies' => ['primary_check', 'secondary_check', 'degrade_samples', 'recover_seconds']];
		$cleared = [];
		foreach ($optional[$collection] ?? [] as $field) {
			if (($sdwan_record[$field] ?? null) === '') {
				unset($sdwan_record[$field]);
				$cleared[$field] = true;
			}
		}
		if ($original === '') {
			$rows[] = $sdwan_record;
		} elseif ($sdwan_record['name'] === $original) {
			$rows[$position] = array_diff_key(array_replace($rows[$position], $sdwan_record), $cleared);
		} else {
			$errors[] = gettext('An existing entry must keep its name.');
		}
	} else {
		$errors[] = gettext('Unknown action.');
	}
	if (!$errors) {
		$candidate = $sdwan;
		$candidate[$collection] = array_values($rows);
		$errors = sdwan_save_config($candidate, $expected_revision, sdwan_can_edit_forwarding());
		if (!$errors) {
			header('Location: ' . $url . '?saved=1', true, 303);
			exit;
		}
	}
} elseif ($editing !== '') {
	$position = array_search($editing, $names, true);
	if ($position === false) {
		$errors[] = gettext('Entry not found.');
		$display_form = false;
	} else {
		$sdwan_record = $rows[$position];
	}
}

$gateways = ['' => gettext('Select a gateway')];
$prerequisite = '';
if ($collection === 'members') {
	$assigned = array_column($sdwan['members'], 'name', 'gateway');
	$current_gateways = array_column($sdwan['members'], 'gateway', 'name');
	$current_gateway = $current_gateways[$original] ?? '';
	foreach (sdwan_gateways() as $gateway_name => $metadata) {
		$gateway_name = (string)$gateway_name;
		if (($assigned[$gateway_name] ?? $original) !== $original ||
		    ($metadata['monitor_disabled'] && $gateway_name !== $current_gateway)) {
			continue;
		}
		$label = $gateway_name;
		if ($metadata['monitor_disabled']) {
			$label = sprintf(gettext('%s (monitoring disabled)'), $gateway_name);
		} elseif ($metadata['force_down']) {
			$label = sprintf(gettext('%s (marked down)'), $gateway_name);
		}
		$gateways[sdwan_ui_choice($gateway_name)] = $label;
	}
	if ($current_gateway !== '') {
		$gateways[sdwan_ui_choice($current_gateway)] ??= sprintf(gettext('%s (unavailable)'), $current_gateway);
	}
	if (count($gateways) === 1) {
		$prerequisite = gettext('To add a member, configure an unused gateway with monitoring enabled under System > Routing.');
	}
} elseif ($collection === 'policies' && (!$sdwan['members'] || !$sdwan['slas'])) {
	$prerequisite = gettext('To add a policy, configure at least one member and one performance SLA.');
}
$pgtitle = [gettext('Services'), gettext('SD-WAN'), $sections[$collection]];
include('head.inc');
sdwan_ui_tabs($collection);
if ($errors) {
	print_input_errors($errors);
} elseif (isset($_GET['saved'])) {
	print_info_box(gettext('SD-WAN configuration saved.'), 'success');
}

if (!$display_form): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=sdwan_ui_escape($sections[$collection])?></h2></div>
	<div class="panel-body">
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed<?=$rows ? ' table-rowdblclickedit' : ''?>">
		<thead><tr><?php foreach ($columns[$collection] as $label): ?>
			<th scope="col"><?=sdwan_ui_escape($label)?></th>
		<?php endforeach; ?><th scope="col"><?=gettext('Actions')?></th></tr></thead><tbody>
		<?php foreach ($sdwan[$collection] as $row): ?>
		<tr>
			<?php foreach ($columns[$collection] as $key => $label):
				$value = $row[$key] ?? gettext('Disabled');
				if ($key === 'members') {
					$value = implode(', ', $value);
				} elseif ($key === 'strategy') {
					$value = $strategies[$value] ?? $value;
				}
			?>
			<td><?=sdwan_ui_escape($value)?></td>
			<?php endforeach; ?>
			<td><form method="post" action="<?=$url?>" class="form-inline">
				<input type="hidden" name="revision" value="<?=sdwan_ui_escape($revision)?>">
				<input type="hidden" name="original" value="<?=sdwan_ui_escape($row['name'])?>">
				<a class="fa-solid fa-pencil" href="<?=$url?>?edit=<?=rawurlencode($row['name'])?>"
				    title="<?=gettext('Edit entry')?>" aria-label="<?=gettext('Edit entry')?>"></a>
				<?php if (isset($used_by[$row['name']])): ?>
				<?php $in_use = sdwan_ui_escape(sprintf(gettext('Used by: %s'), implode(', ', $used_by[$row['name']]))); ?>
				<i class="fa-solid fa-lock" title="<?=$in_use?>" aria-hidden="true"></i><span class="sr-only"><?=$in_use?></span>
				<?php else: ?>
				<button type="submit" name="action" value="delete" class="btn btn-link btn-xs fa-solid fa-trash-can"
				    title="<?=gettext('Delete entry')?>" aria-label="<?=gettext('Delete entry')?>"></button>
				<?php endif; ?>
			</form></td>
		</tr>
		<?php endforeach;
		if (!$sdwan[$collection]) {
			sdwan_ui_empty(gettext('No entries configured.'), count($columns[$collection]) + 1);
		}
		?>
		</tbody>
	</table></div>
	</div>
</div>
<?php endif;
if ($prerequisite !== ''):
	print_info_box($prerequisite, 'info', false);
elseif (!$display_form): ?>
	<nav class="action-buttons" aria-label="<?=gettext('Actions')?>">
		<a class="btn btn-success btn-sm" role="button" href="<?=$url?>?add=1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i> <?=gettext('Add')?></a>
	</nav>
<?php else:
	$form = new Form();
	$form->setAction($url);
	$form_titles = [
		'members' => [gettext('Add member'), gettext('Edit member')],
		'slas' => [gettext('Add performance SLA'), gettext('Edit performance SLA')],
		'policies' => [gettext('Add policy'), gettext('Edit policy')],
	];
	$section = new Form_Section($form_titles[$collection][$original === '' ? 0 : 1]);
	$name_input = new Form_Input('name', gettext('Name'), 'text', $sdwan_record['name'] ?? '', [
		'maxlength' => 32, 'pattern' => '[A-Za-z0-9][A-Za-z0-9_\-]{0,31}', 'required' => true,
	]);
	$name_input->setHelp(gettext('Use up to 32 letters, digits, hyphens or underscores. Start with a letter or digit.'));
	if ($original !== '') {
		$name_input->setReadonly();
	}
	$section->addInput($name_input);
	if ($collection === 'members') {
		$section->addInput(new Form_Select('gateway', gettext('Gateway'), sdwan_ui_choice($sdwan_record['gateway'] ?? ''), $gateways))
			->setAttribute('required', 'required')
			->setHelp(gettext('Each member uses one gateway. Assign each gateway a distinct Monitor IP under System > Routing.'));
		$section->addInput(new Form_Input('cost', gettext('Cost'), 'number', $sdwan_record['cost'] ?? '1',
			['min' => 0, 'max' => 65535, 'required' => true]))
			->setHelp(gettext('A smaller value is preferred by the lowest cost strategy.'));
		$section->addInput(new Form_Input('probe_primary', gettext('Primary service check'), 'text',
		    $sdwan_record['probe_primary'] ?? '', ['maxlength' => 512]))
		    ->setHelp(gettext('Optional. Enter a TCP service address such as tcp://192.0.2.20:587, or an HTTPS URL or DNS name followed by a space and the target IP. Add a host route through this gateway under System > Routing. HTTPS requires a valid certificate.'));
		$section->addInput(new Form_Input('probe_secondary', gettext('Secondary service check'), 'text',
		    $sdwan_record['probe_secondary'] ?? '', ['maxlength' => 512]))
		    ->setHelp(gettext('Use a different target IP and its own host route. A member with service checks needs at least one passing check.'));
	} elseif ($collection === 'slas') {
		$section->addInput(new Form_Input('latency_ms', gettext('Maximum RTT (ms)'), 'number', $sdwan_record['latency_ms'] ?? '',
			['min' => '0.000001', 'max' => '600000', 'step' => 'any', 'required' => true]));
		$section->addInput(new Form_Input('rttsd_ms', gettext('Maximum RTTsd (ms)'), 'number', $sdwan_record['rttsd_ms'] ?? '',
			['min' => '0', 'max' => '600000', 'step' => 'any']))
			->setHelp(gettext('Optional. Limit the standard deviation of round-trip time reported by the gateway monitor.'));
		$section->addInput(new Form_Input('loss_pct', gettext('Maximum loss (%)'), 'number', $sdwan_record['loss_pct'] ?? '',
			['min' => '0', 'max' => '100', 'step' => 'any', 'required' => true]));
	} else {
		$sla_options = ['' => gettext('Select an SLA')];
		foreach ($sdwan['slas'] as $sla) {
			$sla_options[sdwan_ui_choice($sla['name'])] = $sla['name'];
		}
		$selected_members = $sdwan_record['members'] ?? [];
		$available = array_column($sdwan['members'], 'name');
		// Browsers submit a multi-select in document order. Keep the saved tie order.
		$member_options = [];
		foreach (array_merge(array_intersect($selected_members, $available), $available) as $name) {
			$member_options[sdwan_ui_choice($name)] = $name;
		}
		$section->addInput(new Form_Select('sla', gettext('Performance SLA'), sdwan_ui_choice($sdwan_record['sla'] ?? ''), $sla_options))
			->setAttribute('required', 'required');
		$section->addInput(new Form_Select('members', gettext('Candidate members'), array_map('sdwan_ui_choice', $selected_members), $member_options, true))
			->setAttribute('required', 'required')
			->setHelp(gettext('Select one member to monitor a path, or two or more of the same address family to compare paths. For equal scores the first selected member in the displayed list wins.'));
		$section->addInput(new Form_Select('strategy', gettext('Selection strategy'), $sdwan_record['strategy'] ?? 'cost', $strategies));
		$check_modes = ['' => gettext('Member default'), 'ignored' => gettext('Ignore'),
		    'optional' => gettext('Optional'), 'required' => gettext('Required')];
		foreach (['primary_check' => gettext('Primary service check'), 'secondary_check' => gettext('Secondary service check')] as $field => $label) {
			$section->addInput(new Form_Select($field, $label, $sdwan_record[$field] ?? '', $check_modes))
			    ->setHelp(gettext('With both slots at their default, any configured check can pass. Choosing a mode for either slot ignores a slot left at its default. All required checks must pass. Without required checks, one selected optional check must pass.'));
		}
		$section->addInput(new Form_Input('degrade_samples', gettext('Confirm WAN degradation'), 'number',
		    $sdwan_record['degrade_samples'] ?? '', ['min' => '1', 'max' => '6', 'placeholder' => '1']))
		    ->setHelp(gettext('Consecutive samples before replacing an already applied path that exceeds a WAN threshold. Values above one allow temporary degraded forwarding. Down links, missing measurements and service failures take effect immediately.'));
		$section->addInput(new Form_Input('recover_seconds', gettext('Recovery hold (seconds)'), 'number',
		    $sdwan_record['recover_seconds'] ?? '', ['min' => '0', 'max' => '300', 'placeholder' => '30']))
		    ->setHelp(gettext('Keep a healthy current path while a better path recovers. Default is 30 seconds.'));

	}
	$form->add($section);
	foreach (['revision' => $revision, 'action' => 'save', 'original' => $original] as $field => $value) {
		$form->addGlobal(new Form_Input($field, '', 'hidden', $value));
	}
	$form->addGlobal(new Form_Button('cancel', gettext('Cancel'), $url, 'fa-solid fa-undo'));
	print($form);
endif;
include('foot.inc');
