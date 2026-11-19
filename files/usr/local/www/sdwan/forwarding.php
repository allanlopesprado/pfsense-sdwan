<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');
require_once('/usr/local/pkg/sdwan_steering.inc');

$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Forwarding')];
if (!sdwan_can_view_forwarding()) {
	http_response_code(403);
	include('head.inc');
	sdwan_ui_tabs('forwarding');
	print_info_box(gettext('Access to Firewall > Rules and System > Routing > Gateway Groups is required to inspect forwarding.'), 'warning', false);
	include('foot.inc');
	return;
}

$native_edit = sdwan_can_edit_forwarding();
$supported = sdwan_steering_supported();
$is_post = $_SERVER['REQUEST_METHOD'] === 'POST';
$form_source = $is_post ? $_POST : $_GET;
$policy_name = sdwan_ui_choice_value(sdwan_ui_scalar($form_source, 'policy'));
$group_name = sdwan_ui_choice_value(sdwan_ui_scalar($form_source, 'group'));
$policy_names = array_column($sdwan['policies'], 'name');
$groups = config_get_path('gateways/gateway_group', []);
$groups_by_name = array_column(is_array($groups) ? $groups : [], null, 'name');
try {
	$bindings_by_group = sdwan_steering_bindings();
} catch (UnexpectedValueException $error) {
	include('head.inc');
	sdwan_ui_tabs('forwarding');
	print_input_errors([$error->getMessage()]);
	include('foot.inc');
	return;
}
if (!$is_post && $group_name === '' && $policy_name === '' && count($bindings_by_group) === 1) {
	$only = reset($bindings_by_group);
	$group_name = $only['group'];
	$policy_name = $only['policy'];
}
$binding = $bindings_by_group[$group_name] ?? null;
$preview = null;
$errors = [];

if ($is_post) {
	$action = sdwan_ui_scalar($_POST, 'action');
	$revision = sdwan_ui_scalar($_POST, 'revision');
	if (!$native_edit) {
		http_response_code(403);
		$errors[] = gettext('Editing firewall rules and gateway groups requires additional privileges.');
	} elseif ($action === 'bind' && !$supported) {
		$errors[] = gettext('This firewall supports forwarding previews only.');
	} elseif ($action === 'bind') {
		$errors = sdwan_steering_bind($policy_name, $group_name, $revision);
	} elseif ($action === 'unbind') {
		$errors = sdwan_steering_unbind($group_name, $revision);
	} else {
		$errors[] = gettext('Unknown forwarding action.');
	}
	if (!$errors) {
		header('Location: /sdwan/forwarding.php?' . http_build_query(['policy' => $policy_name, 'group' => $group_name]), true, 303);
		exit;
	}
}
if ($policy_name !== '' || $group_name !== '') {
	$preview = sdwan_steering_preview($sdwan, $policy_name, $group_name);
}
$group = $groups_by_name[$group_name] ?? null;
$native_rules = [];
if ($group !== null) {
	$rules = config_get_path('filter/rule', []);
	foreach (is_array($rules) ? $rules : [] as $rule) {
		if (($rule['gateway'] ?? '') === $group_name) {
			$native_rules[] = $rule;
		}
	}
}
$sample = sdwan_ui_snapshot($sdwan);
$winner = $sample['policies'][$policy_name]['selected'] ?? null;
$member_gateways = array_column($sdwan['members'], 'gateway', 'name');
$strategy = array_column($sdwan['policies'], 'strategy', 'name')[$policy_name] ?? '';
$gateways = array_keys($sample['policies'][$policy_name]['candidates'] ?? [], 'Eligible', true);
$gateway_name = $strategy === 'balance' && $gateways
    ? implode(', ', array_map(static fn($name) => $member_gateways[$name] ?? $name, $gateways))
    : ($member_gateways[$winner ?? ''] ?? null);
$steering = $sample['steering'][$group_name] ?? [];
$target = $binding !== null && ($steering['revision'] ?? null) === sdwan_config_revision($binding) &&
    in_array($steering['gateway'] ?? null, $binding['gateways'], true)
    ? implode(', ', $steering['pool'] ?? [$steering['gateway']]) : null;
$pf_labels = [
	'applied' => gettext('Applied to new connections'),
	'blocked' => gettext('Blocked by the active filter'),
	'pending' => gettext('Waiting for a matching filter rule'),
	'unavailable' => gettext('Filter verification unavailable'),
];
$filter_status = $binding === null ? null : sdwan_steering_pf_status($binding, $steering, sdwan_gateways(),
    $supported ? sdwan_steering_pf_rules() : null);
$default_families = [];
foreach (['defaultgw4' => 'IPv4', 'defaultgw6' => 'IPv6'] as $key => $family) {
	if ($group !== null && config_get_path('gateways/' . $key) === $group_name) {
		$default_families[] = $family;
	}
}
include('head.inc');
sdwan_ui_tabs('forwarding');
if ($errors) {
	print_input_errors($errors);
}
if ($supported) {
	print_info_box(gettext('Experimental forwarding integration detected. Test binding and recovery on a lab firewall before deployment.'), 'warning', false);
} else {
	print_info_box(gettext('Preview mode. This pfSense core does not advertise the required forwarding integration. Compare the recommendation with the gateway group and its rules below.'), 'info', false);
}
$policy_options = ['' => gettext('Select a policy')];
foreach ($policy_names as $name) {
	$policy_options[sdwan_ui_choice($name)] = $name;
}
$group_options = ['' => gettext('Select a gateway group')];
foreach ($groups_by_name as $item) {
	$is_default = in_array($item['name'], [config_get_path('gateways/defaultgw4'), config_get_path('gateways/defaultgw6')], true);
	$group_options[sdwan_ui_choice($item['name'])] = $is_default
	    ? sprintf(gettext('%s (system default, preview only)'), $item['name']) : $item['name'];
}
$form = new Form(false);
$form->setAction('/sdwan/forwarding.php')->setMethod('get');
$section = new Form_Section(gettext('Forwarding Preview'));
$section->addInput(new Form_Select('policy', gettext('Policy'), sdwan_ui_choice($policy_name), $policy_options))
    ->setAttribute('required', 'required');
$section->addInput(new Form_Select('group', gettext('Gateway Group'), sdwan_ui_choice($group_name), $group_options))
    ->setAttribute('required', 'required');
$form->add($section);
$preview_button = $form->addGlobal(new Form_Button('preview', gettext('Preview'), null, 'fa-solid fa-search'))
    ->addClass('btn-primary');
if (!$policy_names || !$groups_by_name) {
	$preview_button->setAttribute('disabled', 'disabled');
}
print $form;
if (!$bindings_by_group && $native_edit): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Set up forwarding')?></h2></div>
	<div class="panel-body">
		<ol>
			<li><?=gettext('Configure members, a performance SLA and a policy.')?></li>
			<li><a href="/system_gateway_groups.php"><?=gettext('Gateway Groups')?></a> · <?=gettext('Create a dedicated group with the same gateways as the policy.')?></li>
			<li><a href="/firewall_rules.php"><?=gettext('Firewall Rules')?></a> · <?=gettext('Keep local and VPN exceptions first. Assign the group to the ingress pass rule and place a block or reject with the same match directly below it.')?></li>
			<li><?=gettext('Preview the policy and group above. Review the matching rules and bind the policy when the checks pass.')?></li>
		</ol>
	</div>
</div>
<?php endif;
if (!$policy_names || !$groups_by_name) {
	print_info_box(gettext('A forwarding preview requires an SD-WAN policy and a native gateway group.'), 'info', false);
}
if ($preview !== null):
	if ($preview['errors']) {
		print_input_errors($preview['errors']);
	} elseif ($preview['binding'] !== null) {
		print_info_box(sprintf(gettext('The policy matches the native group. Ingress rules in scope: %d.'), count($preview['binding']['trackers'])), 'success', false);
	}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=sdwan_ui_escape($group_name)?></h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?=gettext('Recommendation')?></dt><dd><?=sdwan_ui_escape($gateway_name ?? gettext('No current eligible gateway'))?></dd>
			<dt><?=gettext('Bound policy')?></dt><dd><?=sdwan_ui_escape($binding['policy'] ?? gettext('None'))?></dd>
			<?php if ($binding !== null): ?>
			<dt><?=gettext('Selected gateways')?></dt><dd><?=sdwan_ui_escape($target ?? gettext('No current target'))?></dd>
			<dt><?=gettext('Active filter')?></dt><dd><?=sdwan_ui_escape($pf_labels[$filter_status])?></dd>
			<?php endif; ?>
			<?php if ($default_families): ?>
			<dt><?=gettext('Default gateway')?></dt><dd><?=sdwan_ui_escape(implode(', ', $default_families))?></dd>
			<?php endif; ?>
		</dl>
		<?php if ($group !== null): ?>
		<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
			<thead><tr><th><?=gettext('Native gateway')?></th><th><?=gettext('Configured tier')?></th></tr></thead><tbody>
			<?php foreach (is_array($group['item'] ?? null) ? $group['item'] : [] as $item):
				if (!is_string($item)) {
					continue;
				}
				[$name, $tier] = array_pad(explode('|', $item, 3), 2, '');
			?><tr><td><?=sdwan_ui_escape($name)?></td><td><?=sdwan_ui_escape($tier)?></td></tr><?php endforeach; ?>
			</tbody>
		</table></div>
		<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
			<thead><tr><th><?=gettext('Rule tracker')?></th><th><?=gettext('Interface')?></th><th><?=gettext('Description')?></th><th><?=gettext('State')?></th><th><?=gettext('No eligible gateway')?></th></tr></thead><tbody>
			<?php foreach ($native_rules as $rule):
				$tracker = (string)($rule['tracker'] ?? '');
				$log_url = '/status_logs_filter.php?filterlogentries_submit=1&filterlogentries_tracker=' . rawurlencode($tracker);
			?><tr>
				<td><?php if ($tracker !== '' && isset($rule['log']) && isAllowedPage($log_url)): ?>
					<a href="<?=sdwan_ui_escape($log_url)?>" title="<?=gettext('View logged packets for this rule')?>"><?=sdwan_ui_escape($tracker)?></a>
				<?php else: ?><?=sdwan_ui_escape($tracker !== '' ? $tracker : '—')?><?php endif; ?></td>
				<td><?=sdwan_ui_escape($rule['interface'] ?? '—')?></td>
				<td><?=sdwan_ui_escape($rule['descr'] ?? '')?></td>
				<td><?=isset($rule['disabled']) ? gettext('Disabled') : gettext('Enabled')?></td>
				<td><?php $guard = $preview['rule_pairs'][$tracker] ?? null; ?>
					<?=sdwan_ui_escape($guard === null ? gettext('Guard not verified') : sprintf(
					    $guard['action'] === 'reject' ? gettext('Reject · rule %s') : gettext('Block · rule %s'), $guard['guard']))?>
				</td>
			</tr><?php endforeach;
			if (!$native_rules) {
				sdwan_ui_empty(gettext('No configured firewall rule references this group.'), 5);
			}
			?></tbody>
		</table></div>
		<p class="help-block"><?=gettext('Review rule order and exceptions for local and VPN traffic on the ingress interface. Capture a new connection to verify its egress path.')?></p>
		<?php endif; ?>
	</div>
</div>
<?php if ($supported && $native_edit && $binding === null && !$preview['errors'] && $preview['binding'] !== null): ?>
	<form method="post" action="/sdwan/forwarding.php" class="action-buttons">
		<input type="hidden" name="policy" value="<?=sdwan_ui_escape($policy_name)?>">
		<input type="hidden" name="group" value="<?=sdwan_ui_escape($group_name)?>">
		<input type="hidden" name="revision" value="<?=sdwan_ui_escape($preview['revision'])?>">
		<button type="submit" class="btn btn-primary btn-sm" name="action" value="bind"><i class="fa-solid fa-link icon-embed-btn" aria-hidden="true"></i> <?=gettext('Bind policy to this group')?></button>
	</form>
<?php endif;
endif;
if ($bindings_by_group): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Configured bindings')?></h2></div>
	<div class="panel-body">
	<div class="table-responsive"><table class="table table-striped table-hover table-condensed">
		<thead><tr><th scope="col"><?=gettext('Gateway Group')?></th><th scope="col"><?=gettext('Policy')?></th><th scope="col"><?=gettext('Actions')?></th></tr></thead><tbody>
		<?php $revision = sdwan_steering_revision();
		foreach ($bindings_by_group as $item): ?>
		<tr><td><a href="<?=sdwan_ui_escape('/sdwan/forwarding.php?' . http_build_query(['group' => $item['group'], 'policy' => $item['policy']]))?>"><?=sdwan_ui_escape($item['group'])?></a></td><td><?=sdwan_ui_escape($item['policy'])?></td>
		<td><?php if ($native_edit): ?>
		<form method="post" action="/sdwan/forwarding.php" class="form-inline">
			<input type="hidden" name="group" value="<?=sdwan_ui_escape($item['group'])?>">
			<input type="hidden" name="policy" value="<?=sdwan_ui_escape($item['policy'])?>">
			<input type="hidden" name="revision" value="<?=sdwan_ui_escape($revision)?>">
			<button type="submit" class="btn btn-link btn-xs fa-solid fa-trash-can" name="action" value="unbind"
			    title="<?=gettext('Remove binding')?>" aria-label="<?=gettext('Remove binding')?>"></button>
			<?php if (!$supported): ?><span class="help-block"><?=gettext('Clear the saved binding. Verify the active rules in pfSense before assuming native forwarding has resumed.')?></span><?php endif; ?>
		</form><?php else: ?>—<?php endif; ?></td></tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	</div>
</div>
<?php endif;
sdwan_ui_actions([
	'/system_gateway_groups.php' => [gettext('Gateway Groups'), 'fa-network-wired'],
	'/firewall_rules.php' => [gettext('Firewall Rules'), 'fa-list'],
	'/diag_packet_capture.php' => [gettext('Packet Capture'), 'fa-magnifying-glass'],
]);
include('foot.inc');
