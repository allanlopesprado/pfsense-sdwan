<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$snapshot = sdwan_ui_snapshot($sdwan);
$names = array_column($sdwan['policies'], 'name');
$requested = sdwan_ui_scalar($_GET, 'policy');
$current = in_array($requested, $names, true) ? $requested : ($names[0] ?? '');
$result = $snapshot['policies'][$current] ?? null;
$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Diagnostics')];
include('head.inc');
sdwan_ui_tabs('diagnostics');
if (!$names) {
	print_info_box(gettext('Create a policy to inspect its candidate members.'), 'info', false);
} else {
?>
<form method="get" action="/sdwan/diagnostics.php" class="form-inline">
	<div class="form-group">
	<label for="policy"><?=gettext('Policy')?></label>
	<select class="form-control" name="policy" id="policy">
	<?php foreach ($names as $name): ?>
		<option value="<?=sdwan_ui_escape($name)?>"<?=$current === $name ? ' selected' : ''?>><?=sdwan_ui_escape($name)?></option>
	<?php endforeach; ?>
	</select>
	</div>
	<button type="submit" class="btn btn-primary"><?=gettext('Inspect')?></button>
</form>
<hr>
<?php
	if ($result === null) {
		print_info_box(gettext('No current sample for this policy. Verify the observer service and gateway monitoring.'), 'warning', false);
	} else {
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=sdwan_ui_escape($current)?></h2></div>
	<div class="panel-body">
		<strong><?=gettext('Recommended member')?></strong> <?=sdwan_ui_escape($result['selected'] ?? '—')?> · <?=sdwan_ui_escape($result['reason'])?>
		<p class="help-block"><?=gettext('Evaluation of the latest gateway sample. No test packets are sent by this page.')?></p>
	</div>
	<div class="table-responsive"><table class="table table-striped">
		<thead><tr><th><?=gettext('Candidate')?></th><th><?=gettext('Evaluation')?></th></tr></thead><tbody>
		<?php foreach ($result['candidates'] as $member => $explanation): ?>
		<tr><td><?=sdwan_ui_escape($member)?></td><td><?=sdwan_ui_escape($explanation)?></td></tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
</div>
<?php
	}
}
include('foot.inc');
