<?php
require_once('guiconfig.inc');
require_once('pkg-utils.inc');
require_once('pfsense-utils.inc');
require_once('/usr/local/pkg/sdwan_release.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');
require_once('/usr/local/pkg/sdwan_log.inc');

$can_upgrade = isAllowedPage('/pkg_mgr_install.php');
$is_post = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$check = $is_post && isset($_POST['check_release']);
$upgrade = $is_post && isset($_POST['upgrade_release']);
$verify = $is_post && isset($_POST['verify_installation']);
$submit = $upgrade || $verify;
$target = ['version' => sdwan_ui_scalar($_POST, 'target_version'), 'sha256' => sdwan_ui_scalar($_POST, 'target_sha256')];
$result = null;
$message = null;
$severity = 'warning';
if ($submit) {
	if (!$can_upgrade) {
		http_response_code(403);
		$message = gettext('Upgrading SD-WAN requires the Package Manager installation privilege.');
	} else {
		if (!$verify) {
			ignore_user_abort(true);
			set_time_limit(0);
		}
		$result = sdwan_release_upgrade($target, $verify);
		$severity = in_array($result, ['success', 'verified'], true) ? 'success' : 'warning';
		$message = match ($result) {
			'success' => sprintf(gettext('SD-WAN %s was installed and the observer has a current sample.'), $target['version']),
			'verified' => sprintf(gettext('SD-WAN %s is installed and the observer has a current sample.'), $target['version']),
			'verify' => sprintf(gettext('SD-WAN %s is installed, but observer readiness could not be verified. Check Status > Services and System Logs, then verify the installation again.'), $target['version']),
			'verify_files' => gettext('The installed SD-WAN version or files could not be verified. Check System Logs.'),
			'invalid' => gettext('The upgrade request is invalid or this firewall is incompatible with the package.'),
			'busy' => gettext('An SD-WAN upgrade is already in progress. Reload this page in a moment.'),
			'not_newer' => $verify ? gettext('The installed version changed. Check the local package version before retrying.') :
			    gettext('This release is no longer newer than the installed package. Check GitHub again.'),
			'changed' => gettext('The installed or published version changed. Check GitHub again before upgrading.'),
			'unpublished' => gettext('The GitHub release asset could not be verified. Check GitHub again later.'),
			'download' => gettext('The package download did not complete. Check connectivity to GitHub and retry.'),
			'checksum' => gettext('The downloaded package failed SHA-256 verification. Check GitHub again before retrying.'),
			'signature' => gettext('The published Minisign signature could not be verified with the local signing key. The update was stopped.'),
			'storage' => gettext('The firewall could not stage the package. Check available space in /tmp.'),
			'manifest' => gettext('The downloaded package identity does not match the selected SD-WAN release.'),
			'backup' => gettext('The installed SD-WAN package could not be prepared for rollback. Check package integrity and available space in /tmp.'),
			'rolled_back' => gettext('The update failed and the previous SD-WAN package was restored. Check Status > Services and System Logs.'),
			'rollback_changed' => gettext('The installed SD-WAN version changed during the update. Review the installed package and System Logs.'),
			'rollback_failed' => gettext('The update and automatic rollback failed. System Logs contains the path to the local recovery archive.'),
			default => gettext('The package manager returned success, but the installed version, files or observer could not be verified. Check System Logs.'),
		};
		if ($upgrade && !$verify && in_array($result, ['success', 'signature', 'backup', 'rolled_back',
		    'rollback_changed', 'rollback_failed', 'verify', 'verify_files'], true)) {
			$priority = match ($result) {
				'success' => LOG_NOTICE, 'rollback_failed' => LOG_ERR, default => LOG_WARNING,
			};
			sdwan_log_emit($priority,
			    'Package upgrade to ' . $target['version'] . ': ' . $result . '.');
		}
	}
}

$installed = sdwan_release_installed();
$release = !$submit && $check ? sdwan_release_check() : null;
$available = false;
$verify_available = $installed === $target['version'] && in_array($result, ['verify', 'verify_files'], true);
if (!$submit && $check && $release === null) {
	$message = gettext('Could not verify release information from GitHub. Check network access, DNS, the proxy and the firewall clock, then retry.');
} elseif ($message === null && $installed === null) {
	$message = gettext('The installed SD-WAN version could not be read from the local package database.');
} elseif ($release !== null && $installed !== null) {
	$comparison = pkg_version_compare($installed, $release['version']);
	$severity = 'info';
	if ($comparison === '<' && $can_upgrade && sdwan_release_compatible()) {
		$available = sdwan_release_asset_size($release) !== null;
		$message = $available ? gettext('A newer version is ready to install.') :
		    gettext('The GitHub release asset could not be verified. Check GitHub again later.');
		$severity = $available ? 'info' : 'warning';
	} else {
		$message = match ($comparison) {
			'<' => $can_upgrade ? gettext('This firewall is incompatible with the published package.') :
			    gettext('A newer version is available. Upgrading requires the Package Manager installation privilege.'),
			'=' => gettext('SD-WAN is up to date.'),
			'>' => gettext('The installed version is newer than the version published on GitHub.'),
			default => gettext('Unable to compare package versions.'),
		};
	}
}

$pgtitle = [gettext('Services'), gettext('SD-WAN'), gettext('Updates')];
include('head.inc');
sdwan_ui_tabs('updates');
if ($message !== null) {
	print_info_box($message, $severity, false);
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
$form->addGlobal(new Form_Button('check_release', gettext('Check GitHub'), null, 'fa-solid fa-search'))
    ->addClass($available || $verify_available ? 'btn-default' : 'btn-primary');
if ($available || $verify_available) {
	$form_target = $available ? $release : $target;
	$form->addGlobal(new Form_Input('target_version', '', 'hidden', $form_target['version']));
	$form->addGlobal(new Form_Input('target_sha256', '', 'hidden', $form_target['sha256']));
}
if ($available) {
	$form->addGlobal(new Form_Button('upgrade_release', sprintf(gettext('Upgrade to %s'), $release['version']),
	    null, 'fa-solid fa-arrows-rotate'))->addClass('btn-success');
} elseif ($verify_available) {
	$form->addGlobal(new Form_Button('verify_installation', gettext('Verify Installation'),
	    null, 'fa-solid fa-check'))->addClass('btn-primary');
}
print $form;
if ($available): ?>
	<p id="sdwan-upgrade-progress" role="status" class="text-info hidden"><?=gettext('Installing the SD-WAN update. Please wait.')?></p>
	<script>
	events.push(function () {
		var upgrade = document.getElementById('upgrade_release');
		if (!upgrade) return;
		var submitting = false;
		upgrade.form.addEventListener('submit', function (event) {
			if (submitting) {
				event.preventDefault();
			} else if (event.submitter === upgrade) {
				submitting = true;
				document.getElementById('sdwan-upgrade-progress').classList.remove('hidden');
			}
		});
	});
	</script>
<?php endif;
include('foot.inc');
