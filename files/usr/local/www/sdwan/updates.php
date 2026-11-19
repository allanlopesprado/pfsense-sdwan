<?php
require_once('guiconfig.inc');
require_once('pkg-utils.inc');
require_once('pfsense-utils.inc');
require_once('/usr/local/pkg/sdwan_release.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$installed = sdwan_release_installed();
$requested = $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['check'] ?? null) === 'github';
$release = $requested ? sdwan_release_check() : null;

$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Updates')];
include('head.inc');
sdwan_ui_tabs('updates');

if ($requested && $release === null) {
	print_info_box(gettext('Could not verify release information from GitHub. Check network access, DNS, the proxy and the firewall clock, then retry.'), 'warning', false);
}
if ($installed === null) {
	print_info_box(gettext('The installed SD-WAN version could not be read from the local package database.'), 'warning', false);
} elseif ($release !== null) {
	$comparison = pkg_version_compare($installed, $release['version']);
	$messages = [
		'<' => gettext('A newer version is published on GitHub. Review the installation instructions before upgrading.'),
		'=' => gettext('The installed version matches the version published on GitHub.'),
		'>' => gettext('The installed version is newer than the version published on GitHub.'),
	];
	print_info_box($messages[$comparison] ?? gettext('Unable to compare package versions.'),
	    isset($messages[$comparison]) ? 'info' : 'warning', false);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Package version')?></h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?=gettext('Installed locally')?></dt><dd><?=sdwan_ui_escape($installed ?? gettext('Unknown'))?></dd>
			<?php if ($release !== null): ?>
			<dt><?=gettext('Published on GitHub')?></dt><dd><?=sdwan_ui_escape($release['version'])?></dd>
			<dt><?=gettext('Published SHA-256')?></dt><dd><code><?=sdwan_ui_escape($release['sha256'])?></code></dd>
			<?php endif; ?>
		</dl>
		<form method="post" action="/sdwan/updates.php">
			<p><?=gettext('Check the native-forwarding lab release on GitHub over HTTPS. The pfSense Package Manager uses its own catalog.')?></p>
			<button type="submit" name="check" value="github" class="btn btn-primary"><?=gettext('Check GitHub')?></button>
			<a class="btn btn-default" href="https://github.com/allanlopesprado/pfsense-sdwan/tree/dev/native-forwarding#readme" target="_blank" rel="noopener noreferrer"><?=gettext('Installation instructions')?></a>
		</form>
	</div>
</div>
<?php include('foot.inc'); ?>
