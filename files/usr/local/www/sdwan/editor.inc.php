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
	'members' => ['name' => gettext('Name'), 'gateway' => gettext('Gateway'), 'cost' => gettext('Cost')],
	'slas' => ['name' => gettext('Name'), 'latency_ms' => gettext('Maximum RTT (ms)'), 'loss_pct' => gettext('Maximum loss (%)')],
	'policies' => ['name' => gettext('Name'), 'sla' => gettext('Performance SLA'), 'members' => gettext('Members'), 'strategy' => gettext('Selection strategy')],
];
$strategies = ['cost' => gettext('Lowest cost'), 'latency' => gettext('Lowest RTT')];
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
// Native Form_Select compares values loosely. Prefix identifiers so names
// such as "1" and "01" remain distinct in both single and multiple selects.
function sdwan_editor_choice(string $value): string {
	return $value === '' ? '' : ':' . $value;
}
function sdwan_editor_value(string $value): string {
	return str_starts_with($value, ':') ? substr($value, 1) : $value;
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
				$sdwan_record[$key] = array_map('sdwan_editor_value', array_values($selected));
			} elseif (in_array($key, ['sla', 'gateway'], true)) {
				$sdwan_record[$key] = sdwan_editor_value(sdwan_ui_scalar($_POST, $key));
			} else {
				$sdwan_record[$key] = sdwan_ui_scalar($_POST, $key);
			}
		}
		if ($original === '') {
			$rows[] = $sdwan_record;
		} elseif ($sdwan_record['name'] === $original) {
			$rows[$position] = array_replace($rows[$position], $sdwan_record);
		} else {
			$errors[] = gettext('An existing entry must keep its name.');
		}
	} else {
		$errors[] = gettext('Unknown action.');
	}
	if (!$errors) {
		$candidate = $sdwan;
		$candidate[$collection] = array_values($rows);
		$errors = sdwan_save_config($candidate, $expected_revision);
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
		$gateways[sdwan_editor_choice($gateway_name)] = $label;
	}
	if ($current_gateway !== '') {
		$gateways[sdwan_editor_choice($current_gateway)] ??= sprintf(gettext('%s (unavailable)'), $current_gateway);
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
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
		<thead><tr><?php foreach ($columns[$collection] as $label): ?>
			<th><?=sdwan_ui_escape($label)?></th>
		<?php endforeach; ?><th><?=gettext('Actions')?></th></tr></thead><tbody>
		<?php foreach ($sdwan[$collection] as $row): ?>
		<tr>
			<?php foreach ($columns[$collection] as $key => $label):
				$value = $row[$key];
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
				<a class="btn btn-default btn-xs" href="<?=$url?>?edit=<?=rawurlencode($row['name'])?>"><i class="fa-solid fa-pencil" aria-hidden="true"></i> <?=gettext('Edit')?></a>
				<?php if (isset($used_by[$row['name']])): ?>
				<small><?=sdwan_ui_escape(sprintf(gettext('Used by: %s'), implode(', ', $used_by[$row['name']])))?></small>
				<?php else: ?>
				<button type="submit" name="action" value="delete" class="btn btn-danger btn-xs"><i class="fa-solid fa-trash-can" aria-hidden="true"></i> <?=gettext('Delete')?></button>
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
<?php endif;
if ($prerequisite !== ''):
	print_info_box($prerequisite, 'info', false);
elseif (!$display_form): ?>
	<a class="btn btn-success btn-sm" href="<?=$url?>?add=1"><i class="fa-solid fa-plus" aria-hidden="true"></i> <?=gettext('Add')?></a>
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
		$section->addInput(new Form_Select('gateway', gettext('Gateway'), sdwan_editor_choice($sdwan_record['gateway'] ?? ''), $gateways))
			->setAttribute('required', 'required')
			->setHelp(gettext('Each member uses one gateway. Configure gateways and their monitors under System > Routing.'));
		$section->addInput(new Form_Input('cost', gettext('Cost'), 'number', $sdwan_record['cost'] ?? '1',
			['min' => 0, 'max' => 65535, 'required' => true]))
			->setHelp(gettext('A smaller value is preferred by the lowest cost strategy.'));
	} elseif ($collection === 'slas') {
		$section->addInput(new Form_Input('latency_ms', gettext('Maximum RTT (ms)'), 'number', $sdwan_record['latency_ms'] ?? '',
			['min' => '0.000001', 'max' => '600000', 'step' => 'any', 'required' => true]));
		$section->addInput(new Form_Input('loss_pct', gettext('Maximum loss (%)'), 'number', $sdwan_record['loss_pct'] ?? '',
			['min' => '0', 'max' => '100', 'step' => 'any', 'required' => true]));
	} else {
		$sla_options = ['' => gettext('Select an SLA')];
		foreach ($sdwan['slas'] as $sla) {
			$sla_options[sdwan_editor_choice($sla['name'])] = $sla['name'];
		}
		$selected_members = $sdwan_record['members'] ?? [];
		$available = array_column($sdwan['members'], 'name');
		// Browsers submit a multi-select in document order. Keep the saved tie order.
		$member_options = [];
		foreach (array_merge(array_intersect($selected_members, $available), $available) as $name) {
			$member_options[sdwan_editor_choice($name)] = $name;
		}
		$section->addInput(new Form_Select('sla', gettext('Performance SLA'), sdwan_editor_choice($sdwan_record['sla'] ?? ''), $sla_options))
			->setAttribute('required', 'required');
		$section->addInput(new Form_Select('members', gettext('Candidate members'), array_map('sdwan_editor_choice', $selected_members), $member_options, true))
			->setAttribute('required', 'required')
			->setHelp(gettext('Select one member to monitor a path, or two or more of the same address family to compare paths. For equal scores the first selected member in the displayed list wins.'));
		$section->addInput(new Form_Select('strategy', gettext('Selection strategy'), $sdwan_record['strategy'] ?? 'cost', $strategies));
	}
	$form->add($section);
	foreach (['revision' => $revision, 'action' => 'save', 'original' => $original] as $field => $value) {
		$form->addGlobal(new Form_Input($field, '', 'hidden', $value));
	}
	print($form);
?>
	<a class="btn btn-default" href="<?=$url?>"><?=gettext('Cancel')?></a>
<?php endif;
include('foot.inc');
