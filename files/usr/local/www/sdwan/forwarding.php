<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');
require_once('/usr/local/pkg/sdwan_steering.inc');

$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Forwarding')];
$native_view = isAllowedPage('/firewall_rules.php') && isAllowedPage('/system_gateway_groups.php');
if (!$native_view) {
	http_response_code(403);
	include('head.inc');
	sdwan_ui_tabs('forwarding');
	print_info_box(gettext('Access to Firewall > Rules and System > Routing > Gateway Groups is required to inspect forwarding.'), 'warning', false);
	include('foot.inc');
	return;
}

$native_edit = isAllowedPage('/firewall_rules_edit.php') && isAllowedPage('/system_gateway_groups_edit.php');
$supported = sdwan_steering_supported();
$is_post = $_SERVER['REQUEST_METHOD'] === 'POST';
$form_source = $is_post ? $_POST : $_GET;
$policy_name = sdwan_ui_scalar($form_source, 'policy');
$group_name = sdwan_ui_scalar($form_source, 'group');
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
$gateway_name = $member_gateways[$winner ?? ''] ?? null;
$steering = $sample['steering'][$group_name] ?? [];
$target = $binding !== null && ($steering['revision'] ?? null) === sdwan_config_revision($binding) &&
    in_array($steering['gateway'] ?? null, $binding['gateways'], true) ? $steering['gateway'] : null;
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
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Forwarding preview')?></h2></div>
	<div class="panel-body">
	<form method="get" action="/sdwan/forwarding.php" class="form-inline">
		<label for="policy"><?=gettext('Policy')?></label>
		<select id="policy" name="policy" class="form-control" required>
			<option value=""><?=gettext('Select a policy')?></option>
			<?php foreach ($policy_names as $name): ?>
			<option value="<?=sdwan_ui_escape($name)?>"<?=$policy_name === $name ? ' selected' : ''?>><?=sdwan_ui_escape($name)?></option>
			<?php endforeach; ?>
		</select>
		<label for="group"><?=gettext('Gateway group')?></label>
		<select id="group" name="group" class="form-control" required>
			<option value=""><?=gettext('Select a gateway group')?></option>
			<?php foreach ($groups_by_name as $item): ?>
			<option value="<?=sdwan_ui_escape($item['name'])?>"<?=$group_name === $item['name'] ? ' selected' : ''?>><?=sdwan_ui_escape($item['name'])?></option>
			<?php endforeach; ?>
		</select>
		<button type="submit" class="btn btn-primary"><?=gettext('Preview')?></button>
	</form>
	<?php if (!$policy_names || !$groups_by_name): ?>
	<p class="help-block"><?=gettext('A forwarding preview requires an SD-WAN policy and a native gateway group.')?></p>
	<?php endif; ?>
	</div>
</div>
<?php if ($preview !== null):
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
			<dt><?=gettext('Observer target')?></dt><dd><?=sdwan_ui_escape($target ?? gettext('No current target'))?></dd>
			<?php endif; ?>
			<?php if ($default_families): ?>
			<dt><?=gettext('Default gateway')?></dt><dd><?=sdwan_ui_escape(implode(', ', $default_families))?></dd>
			<?php endif; ?>
		</dl>
		<?php if ($group !== null): ?>
		<table class="table table-striped">
			<thead><tr><th><?=gettext('Native gateway')?></th><th><?=gettext('Configured tier')?></th></tr></thead><tbody>
			<?php foreach (is_array($group['item'] ?? null) ? $group['item'] : [] as $item):
				if (!is_string($item)) {
					continue;
				}
				[$name, $tier] = array_pad(explode('|', $item, 3), 2, '');
			?><tr><td><?=sdwan_ui_escape($name)?></td><td><?=sdwan_ui_escape($tier)?></td></tr><?php endforeach; ?>
			</tbody>
		</table>
		<table class="table table-striped">
			<thead><tr><th><?=gettext('Rule tracker')?></th><th><?=gettext('Interface')?></th><th><?=gettext('Description')?></th><th><?=gettext('State')?></th></tr></thead><tbody>
			<?php foreach ($native_rules as $rule): ?><tr>
				<td><?=sdwan_ui_escape($rule['tracker'] ?? '—')?></td>
				<td><?=sdwan_ui_escape($rule['interface'] ?? '—')?></td>
				<td><?=sdwan_ui_escape($rule['descr'] ?? '')?></td>
				<td><?=isset($rule['disabled']) ? gettext('Disabled') : gettext('Enabled')?></td>
			</tr><?php endforeach;
			if (!$native_rules) {
				sdwan_ui_empty(gettext('No configured firewall rule references this group.'), 4);
			}
			?></tbody>
		</table>
		<p class="help-block"><?=gettext('Review rule order and exceptions for local and VPN traffic on the ingress interface. Use Diagnostics > Packet Capture with a new connection to verify the actual egress path.')?></p>
		<a href="/system_gateway_groups.php"><?=gettext('Gateway groups')?></a> · <a href="/firewall_rules.php"><?=gettext('Firewall rules')?></a>
		<?php endif; ?>
	</div>
</div>
<?php if ($supported && $native_edit && $binding === null && !$preview['errors'] && $preview['binding'] !== null): ?>
	<form method="post" action="/sdwan/forwarding.php">
		<input type="hidden" name="policy" value="<?=sdwan_ui_escape($policy_name)?>">
		<input type="hidden" name="group" value="<?=sdwan_ui_escape($group_name)?>">
		<input type="hidden" name="revision" value="<?=sdwan_ui_escape($preview['revision'])?>">
		<button type="submit" class="btn btn-primary" name="action" value="bind"><?=gettext('Bind policy to this group')?></button>
	</form>
<?php endif;
endif;
if ($bindings_by_group): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Configured bindings')?></h2></div>
	<div class="table-responsive"><table class="table table-striped">
		<thead><tr><th><?=gettext('Gateway group')?></th><th><?=gettext('Policy')?></th><th><?=gettext('Action')?></th></tr></thead><tbody>
		<?php $revision = sdwan_steering_revision();
		foreach ($bindings_by_group as $item): ?>
		<tr><td><?=sdwan_ui_escape($item['group'])?></td><td><?=sdwan_ui_escape($item['policy'])?></td>
		<td><?php if ($native_edit): ?>
		<form method="post" action="/sdwan/forwarding.php">
			<input type="hidden" name="group" value="<?=sdwan_ui_escape($item['group'])?>">
			<input type="hidden" name="policy" value="<?=sdwan_ui_escape($item['policy'])?>">
			<input type="hidden" name="revision" value="<?=sdwan_ui_escape($revision)?>">
			<button type="submit" class="btn btn-default btn-xs" name="action" value="unbind"><?=gettext('Remove binding')?></button>
			<?php if (!$supported): ?><span class="help-block"><?=gettext('Clear the saved binding. Verify the active rules in pfSense before assuming native forwarding has resumed.')?></span><?php endif; ?>
		</form><?php else: ?>—<?php endif; ?></td></tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
</div>
<?php endif; include('foot.inc'); ?>
