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
		unset($rows[$position]);
	} elseif ($action === 'save') {
		$display_form = true;
		foreach ($columns[$collection] as $key => $label) {
			if ($key === 'members') {
				$selected = $_POST[$key] ?? [];
				if (!is_array($selected) || array_filter($selected, 'is_string') !== $selected) {
					$errors[] = gettext('Select valid members.');
					$selected = [];
				}
				$sdwan_record[$key] = array_values($selected);
			} else {
				$sdwan_record[$key] = sdwan_ui_scalar($_POST, $key);
			}
		}
		if ($original === '') {
			$rows[] = $sdwan_record;
		} elseif ($sdwan_record['name'] === $original) {
			$rows[$position] = $sdwan_record;
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

$pgtitle = [gettext('Services'), gettext('SD-WAN'), $sections[$collection]];
include('head.inc');
sdwan_ui_tabs($collection);
if ($errors) {
	print_input_errors($errors);
} elseif (isset($_GET['saved'])) {
	print_info_box(gettext('Observer configuration saved.'), 'success');
}

?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=sdwan_ui_escape($sections[$collection])?></h2></div>
	<div class="table-responsive"><table class="table table-striped table-hover">
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
				<a class="btn btn-default btn-xs" href="<?=$url?>?edit=<?=rawurlencode($row['name'])?>"><?=gettext('Edit')?></a>
				<button type="submit" name="action" value="delete" class="btn btn-danger btn-xs"><?=gettext('Delete')?></button>
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
<?php if (!$display_form): ?>
	<a class="btn btn-success" href="<?=$url?>?add=1"><i class="fa-solid fa-plus" aria-hidden="true"></i> <?=gettext('Add')?></a>
<?php else:
	$form = new Form();
	$form->setAction($url);
	$section = new Form_Section($original === '' ? gettext('Add entry') : gettext('Edit entry'));
	$name_input = new Form_Input('name', gettext('Name'), 'text', $sdwan_record['name'] ?? '', [
		'maxlength' => 32, 'required' => true,
	]);
	$name_input->setHelp(gettext('Use up to 32 letters, digits, hyphens or underscores. Start with a letter or digit.'));
	if ($original !== '') {
		$name_input->setReadonly();
	}
	$section->addInput($name_input);
	if ($collection === 'members') {
		$gateways = ['' => gettext('Select a gateway')];
		foreach (sdwan_gateways() as $gateway_name => $metadata) {
			$gateways[$gateway_name] = $gateway_name;
		}
		$section->addInput(new Form_Select('gateway', gettext('Gateway'), $sdwan_record['gateway'] ?? '', $gateways))
			->setHelp(gettext('Choose a gateway monitored by pfSense. Configure new gateways under System > Routing.'));
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
			$sla_options[$sla['name']] = $sla['name'];
		}
		$member_options = array_column($sdwan['members'], 'name', 'name');
		$section->addInput(new Form_Select('sla', gettext('Performance SLA'), $sdwan_record['sla'] ?? '', $sla_options));
		$section->addInput(new Form_Select('members', gettext('Candidate members'), $sdwan_record['members'] ?? [], $member_options, true));
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
