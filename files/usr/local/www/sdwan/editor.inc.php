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
$service_fields = ['primary_check' => gettext('Primary service check'), 'secondary_check' => gettext('Secondary service check')];
$service_modes = ['' => gettext('Member default'), 'ignored' => gettext('Ignore'),
    'optional' => gettext('Optional'), 'required' => gettext('Required')];
$url = '/sdwan/' . $collection . '.php';
$revision = sdwan_config_revision($sdwan);
$rows = $sdwan[$collection];
$names = array_column($rows, 'name');
$editing = sdwan_ui_scalar($_GET, 'edit');
$original = $editing;
$display_form = isset($_GET['edit']) || isset($_GET['add']);
$confirm_deletion = false;
$errors = [];
$sdwan_record = [];
$optional_fields = match ($collection) {
	'members' => ['probe_primary', 'probe_secondary'],
	'slas' => ['rttsd_ms'],
	default => [],
};
$used_by = [];
foreach ($sdwan['policies'] as $policy) {
	$references = $collection === 'members' ? $policy['members'] :
	    ($collection === 'slas' ? [$policy['sla']] : []);
	foreach ($references as $reference) {
		$used_by[$reference][] = $policy['name'];
	}
}
$bound_policies = [];
$binding_error = '';
if ($collection === 'policies') {
	require_once('/usr/local/pkg/sdwan_steering.inc');
	try {
		foreach (sdwan_steering_bindings() as $binding) {
			$bound_policies[$binding['policy']] = true;
		}
	} catch (UnexpectedValueException) {
		$binding_error = gettext('Review the saved forwarding bindings before deleting policies.');
	}
}
$bound_message = gettext('Remove the forwarding binding before deleting this policy.');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = sdwan_ui_scalar($_POST, 'action');
	$submitted_original = $_POST['original'] ?? null;
	$original = is_string($submitted_original) ? $submitted_original : '';
	$position = array_search($original, $names, true);
	$expected_revision = sdwan_ui_scalar($_POST, 'revision');
	if (!hash_equals($revision, $expected_revision)) {
		$errors[] = gettext('Configuration changed. Reload this page and review the current values.');
		$display_form = false;
	} elseif ($submitted_original !== '' && !sdwan_valid_name($submitted_original)) {
		$errors[] = gettext('This entry could not be identified. Reload this page and try again.');
		$display_form = false;
	} elseif ($original !== '' && $position === false) {
		$errors[] = gettext('This entry no longer exists.');
	} elseif (in_array($action, ['review-delete', 'delete'], true) && $original !== '') {
		if (isset($used_by[$original])) {
			$errors[] = sprintf(gettext('Remove this entry from the following policies first: %s.'), implode(', ', $used_by[$original]));
		} elseif ($binding_error !== '') {
			$errors[] = $binding_error;
		} elseif (isset($bound_policies[$original])) {
			$errors[] = $bound_message;
		} elseif ($action === 'review-delete') {
			$confirm_deletion = true;
		} elseif (($_POST['confirm_delete'] ?? null) !== $original) {
			$errors[] = gettext('Review this entry before confirming its deletion.');
		} else {
			unset($rows[$position]);
		}
	} elseif ($action === 'save') {
		$display_form = true;
		$saved = $position === false ? [] : $rows[$position];
		$sdwan_record = $saved;
		$cleared = [];
		$policy_inputs = $_POST;
		if ($collection === 'policies' && array_key_exists('policy_selection', $_POST)) {
			$raw_selection = $_POST['policy_selection'];
			$selection = is_string($raw_selection) && strlen($raw_selection) <= 1048576 ?
			    json_decode($raw_selection, true, 5) : null;
			if (!is_array($selection) || count($selection) !== 2 || !is_array($selection['members'] ?? null) ||
			    !array_is_list($selection['members']) || !is_array($selection['overrides'] ?? null)) {
				$errors[] = gettext('The policy selection could not be read. Reload the form and try again.');
			} else {
				$policy_inputs = ['members' => $selection['members']] + $selection['overrides'];
				foreach ($selection['overrides'] as $field => $mode) {
					if (!is_string($field) || !preg_match('/\A(?:primary|secondary)_check_[A-Za-z0-9][A-Za-z0-9_-]{0,31}\z/', $field) ||
					    !is_string($mode) || !array_key_exists($mode, $service_modes)) {
						$errors[] = gettext('Select a valid member service check requirement.');
						break;
					}
				}
			}
		}
		foreach ($columns[$collection] as $key => $label) {
			if (in_array($key, $optional_fields, true)) {
				if (!array_key_exists($key, $_POST)) {
					continue;
				}
				$raw = $_POST[$key];
				$value = sdwan_ui_scalar($_POST, $key);
				if ($value !== '') {
					$sdwan_record[$key] = $value;
				} elseif (is_string($raw) && strlen($raw) <= 512 && trim($raw, ' ') === '') {
					$cleared[$key] = true;
				} else {
					$errors[] = sprintf(gettext('Enter a valid value for %s.'), $label);
				}
			} elseif ($key === 'members') {
				$selected = $policy_inputs[$key] ?? [];
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
			$previous = $saved['probe_requirements'] ?? [];
			$overrides = array_column($previous, null, 'member');
			$requirements = [];
			foreach (array_keys($service_fields) as $field) {
				if (!array_key_exists($field, $_POST)) {
					continue;
				}
				$mode = $_POST[$field];
				if (!is_string($mode) || !array_key_exists($mode, $service_modes)) {
					$errors[] = gettext('Select a valid service check requirement.');
				} elseif ($mode === '') {
					$cleared[$field] = true;
				} else {
					$sdwan_record[$field] = $mode;
				}
			}
			foreach (['degrade_samples', 'recover_seconds'] as $field) {
				if (!array_key_exists($field, $_POST)) {
					continue;
				}
				if (!is_string($_POST[$field])) {
					$errors[] = gettext('Enter valid degradation and recovery settings.');
				} elseif (trim($_POST[$field]) === '') {
					$cleared[$field] = true;
				} else {
					$sdwan_record[$field] = trim($_POST[$field]);
				}
			}
			foreach ($sdwan_record['members'] as $member) {
				if (!sdwan_valid_name($member)) {
					continue;
				}
				$override = $overrides[$member] ?? ['member' => $member];
				foreach (array_keys($service_fields) as $field) {
					$key = $field . '_' . $member;
					if (!array_key_exists($key, $policy_inputs)) {
						continue;
					}
					$mode = $policy_inputs[$key];
					if (!is_string($mode) || !array_key_exists($mode, $service_modes)) {
						$errors[] = gettext('Select a valid member service check requirement.');
					} elseif ($mode === '') {
						unset($override[$field]);
					} else {
						$override[$field] = $mode;
					}
				}
				if (count($override) > 1) {
					$requirements[] = $override;
				}
			}
			if ($requirements) {
				$sdwan_record['probe_requirements'] = $requirements;
			} else {
				$cleared['probe_requirements'] = true;
			}
		}
		$sdwan_record = array_diff_key($sdwan_record, $cleared);
		if ($original === '') {
			$rows[] = $sdwan_record;
		} elseif ($sdwan_record['name'] === $original) {
			$rows[$position] = $sdwan_record;
		} else {
			$errors[] = gettext('An existing entry must keep its name.');
			$sdwan_record['name'] = $original;
		}
	} else {
		$errors[] = gettext('Unknown action.');
	}
	if (!$errors && !$confirm_deletion) {
		$candidate = $sdwan;
		$candidate[$collection] = array_values($rows);
		$errors = sdwan_save_config($candidate, $expected_revision, sdwan_can_edit_forwarding());
		if (!$errors) {
			header('Location: ' . $url . '?saved=1', true, 303);
			exit;
		}
	}
} elseif (isset($_GET['edit'])) {
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

if (!$display_form && !$confirm_deletion): ?>
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
				<?php
				$reason = $binding_error;
				if (isset($used_by[$row['name']])) {
					$reason = sprintf(gettext('Used by: %s'), implode(', ', $used_by[$row['name']]));
				} elseif (isset($bound_policies[$row['name']])) {
					$reason = $bound_message;
				}
				if ($reason !== ''):
					$in_use = sdwan_ui_escape($reason);
				?>
				<i class="fa-solid fa-lock" title="<?=$in_use?>" aria-hidden="true"></i><span class="sr-only"><?=$in_use?></span>
				<?php else: ?>
				<button type="submit" name="action" value="review-delete" class="btn btn-link btn-xs fa-solid fa-trash-can"
				    title="<?=gettext('Review deletion')?>" aria-label="<?=gettext('Review deletion')?>"></button>
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
if ($confirm_deletion): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Confirm deletion')?></h2></div>
	<div class="panel-body">
		<p><?=sdwan_ui_escape(sprintf(gettext('Delete %s?'), $original))?></p>
		<form method="post" action="<?=$url?>" class="form-inline">
			<input type="hidden" name="revision" value="<?=sdwan_ui_escape($revision)?>">
			<input type="hidden" name="original" value="<?=sdwan_ui_escape($original)?>">
			<input type="hidden" name="confirm_delete" value="<?=sdwan_ui_escape($original)?>">
			<a class="btn btn-default" href="<?=$url?>"><?=gettext('Cancel')?></a>
			<button type="submit" name="action" value="delete" class="btn btn-danger"><?=gettext('Delete')?></button>
		</form>
	</div>
</div>
<?php elseif ($prerequisite !== ''):
	print_info_box($prerequisite, 'info', false);
elseif (!$display_form): ?>
	<nav class="action-buttons" aria-label="<?=gettext('Actions')?>">
		<a class="btn btn-success btn-sm" role="button" href="<?=$url?>?add=1"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i> <?=gettext('Add')?></a>
	</nav>
<?php else:
	$form = new Form();
	$form->setAction($url);
	if ($collection === 'policies') {
		$form->setAttribute('id', 'sdwan-policy-editor');
	}
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
		    ->setHelp(gettext('Optional. Enter a TCP service address such as tcp://192.0.2.20:587, or an HTTPS URL or DNS name followed by the target IP. Add a host route through this gateway. Prefix the check with fib=1 to use a preconfigured routing table. HTTPS requires a valid certificate. Append expect=ready to require that exact response body. DNS queries A records unless you append type=AAAA.'));
		$section->addInput(new Form_Input('probe_secondary', gettext('Secondary service check'), 'text',
		    $sdwan_record['probe_secondary'] ?? '', ['maxlength' => 512]))
		    ->setHelp(gettext('Use a different target IP within the same routing table. Each target needs a host route. Use Policies to select which service checks determine eligibility.'));
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
		$section->addInput(new Form_Input('degrade_samples', gettext('WAN degradation samples'), 'number',
		    $sdwan_record['degrade_samples'] ?? '', ['min' => 1, 'max' => 6, 'placeholder' => '1']))
		    ->setHelp(gettext('The default excludes a path on the first SLA breach. Higher values allow a currently applied path to remain briefly when service checks still pass. Down links and missing measurements take effect immediately.'));
		$section->addInput(new Form_Input('recover_seconds', gettext('Path recovery hold (seconds)'), 'number',
		    $sdwan_record['recover_seconds'] ?? '', ['min' => 0, 'max' => 300]))
		    ->setHelp(gettext('Lowest cost and lowest RTT wait before replacing a healthy path. The default is 30 seconds. Weighted balancing waits before rejoining a path when another healthy path remains in the pool. The default for balancing is immediate.'));
	}
	$form->add($section);
	if ($collection === 'policies' && (array_column($sdwan['members'], 'probe_primary') ||
	    array_intersect_key($sdwan_record, $service_fields))) {
		$section = new Form_Section(gettext('Service check requirements'));
		foreach ($service_fields as $field => $label) {
			$section->addInput(new Form_Select($field, $label, $sdwan_record[$field] ?? '', $service_modes))
			    ->setHelp(gettext('With both slots at their defaults, any configured check can pass. Setting either policy slot explicitly makes a slot left at its default ignored. Every required check must pass.'));
		}
		$overrides = array_column($sdwan_record['probe_requirements'] ?? [], null, 'member');
		$override_modes = array_replace($service_modes, ['' => gettext('Policy default')]);
		$slots = ['primary_check' => 'probe_primary', 'secondary_check' => 'probe_secondary'];
		foreach ($sdwan['members'] as $member) {
			$name = $member['name'];
			foreach ($service_fields as $field => $label) {
				if (!isset($member[$slots[$field]]) && !isset($overrides[$name][$field])) {
					continue;
				}
				$section->addInput(new Form_Select($field . '_' . $name,
				    sprintf(gettext('%1$s %2$s'), $name, $label), $overrides[$name][$field] ?? '', $override_modes))
				    ->setHelp(gettext('This override applies when the member is selected for this policy.'));
			}
		}
		$form->add($section);
	}
	foreach (['revision' => $revision, 'action' => 'save', 'original' => $original] as $field => $value) {
		$form->addGlobal(new Form_Input($field, '', 'hidden', $value));
	}
	$form->addGlobal(new Form_Button('cancel', gettext('Cancel'), $url, 'fa-solid fa-undo'));
	print($form);
if ($collection === 'policies'): ?>
	<script>
	events.push(function () {
		const form = document.getElementById('sdwan-policy-editor');
		form.addEventListener('formdata', function (event) {
			const data = event.formData;
			const members = data.getAll('members[]');
			const selected = new Set(members);
			const overrides = Object.create(null);
			for (const [field, mode] of Array.from(data.entries())) {
				const match = /^(?:primary|secondary)_check_([A-Za-z0-9][A-Za-z0-9_-]{0,31})$/.exec(field);
				if (match) {
					if (selected.has(':' + match[1])) {
						overrides[field] = mode;
					}
					data.delete(field);
				}
			}
			data.delete('members[]');
			data.set('policy_selection', JSON.stringify({members, overrides}));
		});
	});
	</script>
<?php endif;
endif;
include('foot.inc');
