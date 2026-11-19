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
$form = new Form(false);
$form->setAction('/sdwan/updates.php');
$section = new Form_Section(gettext('Package Version'));
$section->addInput(new Form_StaticText(gettext('Installed Version'), sdwan_ui_escape($installed ?? gettext('Unknown'))));
if ($release !== null) {
	$section->addInput(new Form_StaticText(gettext('Published Version'), sdwan_ui_escape($release['version'])));
	$section->addInput(new Form_StaticText(gettext('Release Maturity'),
	    $release['maturity'] === 'experimental' ? gettext('Experimental') : gettext('Stable')));
	$digest = '<code>' . implode('<wbr>', array_map('sdwan_ui_escape', str_split($release['sha256'], 8))) . '</code>';
	$section->addInput(new Form_StaticText(gettext('SHA-256'), $digest));
}
$form->add($section);
$form->addGlobal(new Form_Input('check', '', 'hidden', 'github'));
$form->addGlobal(new Form_Button('check_release', gettext('Check GitHub'), null, 'fa-solid fa-arrows-rotate'))->addClass('btn-primary');
$form->addGlobal(new Form_Button('instructions', gettext('Installation Instructions'),
	'https://github.com/allanlopesprado/pfsense-sdwan/blob/main/README.md', 'fa-solid fa-arrow-up-right-from-square'))
    ->setAttribute('target', '_blank')->setAttribute('rel', 'noopener noreferrer');
print $form;
sdwan_ui_actions(['/pkg_mgr_installed.php' => [gettext('Installed Packages'), 'fa-box-archive']]);
include('foot.inc');
