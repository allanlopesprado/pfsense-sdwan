<?php
require_once('guiconfig.inc');

/* index.php supplies the key on rendering. A refresh is a separate request. */
$sdwanDirectRequest = !isset($widgetkey);
if (!isAllowedPage('/sdwan/status.php')) {
	if ($sdwanDirectRequest) {
		http_response_code(403);
	}
	echo gettext('SD-WAN status permission is required.');
	return;
}
if ($sdwanDirectRequest) {
	$sdwanKey = $_POST['widgetkey'] ?? '';
	if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || ($_POST['ajax'] ?? '') !== 'ajax' ||
	    !is_string($sdwanKey) || !preg_match('/\Asdwan-[0-9]+\z/', $sdwanKey) ||
	    !is_valid_widgetkey($sdwanKey, $user_settings, __FILE__)) {
		http_response_code(400);
		return;
	}
}

require_once('/usr/local/pkg/sdwan.inc');
require_once('/usr/local/pkg/sdwan_engine.inc');

$sdwanRender = static function (): void {
	try {
		$config = sdwan_get_config();
	} catch (UnexpectedValueException $error) {
		echo '<p>' . gettext('The stored SD-WAN configuration cannot be read.') . '</p>';
		return;
	}
	if (!$config['policies']) {
		echo '<p>' . gettext('No SD-WAN policies configured.') . '</p>';
		return;
	}
	$snapshot = sdwan_read_snapshot();
	if (($snapshot['config_revision'] ?? null) !== sdwan_config_revision($config)) {
		echo '<p>' . gettext('Waiting for current gateway measurements.') . '</p>';
		return;
	}
	$escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	?>
	<div class="table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead><tr><th><?=gettext('Policy')?></th><th><?=gettext('Recommended member')?></th></tr></thead>
			<tbody>
			<?php foreach ($config['policies'] as $policy): ?>
				<tr><td><?=$escape($policy['name'])?></td>
					<td><?=$escape($snapshot['policies'][$policy['name']]['selected'] ?? gettext('No recommendation'))?></td></tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<p class="text-muted"><?=gettext('Last sample')?> &middot; <?=$escape(date('H:i:s T', $snapshot['generated_at']))?></p>
	<?php
};

if ($sdwanDirectRequest) {
	$sdwanRender();
	return;
}
$sdwanBodyId = 'sdwan-status-' . $widgetkey;
?>
<div id="<?=htmlspecialchars($sdwanBodyId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>"><?php $sdwanRender(); ?></div>
<script>
events.push(function () {
	register_ajax({
		name: "SD-WAN",
		url: "/widgets/widgets/sdwan.widget.php",
		parms: {ajax: "ajax", widgetkey: <?=json_encode($widgetkey, JSON_HEX_TAG)?>},
		freq: 10,
		callback: function (html) {
			$(document.getElementById(<?=json_encode($sdwanBodyId, JSON_HEX_TAG)?>)).html(html);
		}
	});
});
</script>
