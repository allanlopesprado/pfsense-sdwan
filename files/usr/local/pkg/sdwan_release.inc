<?php

const SDWAN_RELEASE_REPO = 'allanlopesprado/pfsense-sdwan';
const SDWAN_RELEASE_INDEX = 'https://raw.githubusercontent.com/' . SDWAN_RELEASE_REPO . '/main/dist/release.json';
const SDWAN_RELEASE_MAX_BYTES = 4096;
const SDWAN_RELEASE_PACKAGE = 'pfSense-pkg-SDWAN';
const SDWAN_RELEASE_PACKAGE_LIMIT = 2 * 1024 * 1024;
const SDWAN_RELEASE_SIGNATURE_LIMIT = 4096;
const SDWAN_RELEASE_SIGNING_KEY = '/conf/sdwan-minisign.pub';
const SDWAN_RELEASE_MINISIGN = '/usr/local/bin/minisign';
const SDWAN_RELEASE_ASSET_HOSTS = ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'];

function sdwan_release_pkg_version(string $value): bool {
	// Permit FreeBSD's revision and epoch suffixes in locally installed versions.
	return preg_match('/\A[0-9][0-9A-Za-z._,+-]{0,63}\z/', $value) === 1;
}

function sdwan_release_installed(): ?string {
	if (pkg_exec('query %v ' . SDWAN_RELEASE_PACKAGE, $stdout, $stderr) !== 0) {
		return null;
	}
	$version = trim($stdout);
	return sdwan_release_pkg_version($version) ? $version : null;
}

function sdwan_release_valid_target(array $target): bool {
	return is_string($target['version'] ?? null) &&
	    preg_match('/\A(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}\z/', $target['version']) === 1 &&
	    is_string($target['sha256'] ?? null) && preg_match('/\A[0-9a-f]{64}\z/', $target['sha256']) === 1;
}

function sdwan_release_parse(string $body): ?array {
	if (strlen($body) > SDWAN_RELEASE_MAX_BYTES) {
		return null;
	}
	$release = json_decode($body, true, 4);
	if (!is_array($release) || ($release['schema'] ?? null) !== 1 ||
	    ($release['package'] ?? null) !== SDWAN_RELEASE_PACKAGE || ($release['channel'] ?? null) !== 'main' ||
	    !in_array($release['maturity'] ?? null, ['experimental', 'stable'], true) ||
	    !sdwan_release_valid_target($release)) {
		return null;
	}
	return ['version' => $release['version'], 'sha256' => $release['sha256'], 'maturity' => $release['maturity']];
}

/* Downloads may expose a redirect for the caller to validate before following it. */
function sdwan_release_fetch(string $url, int $limit, int $timeout, ?string &$redirect = null): ?string {
	$redirect = null;
	$parts = parse_url($url);
	if (($parts['scheme'] ?? null) !== 'https' || isset($parts['user']) || isset($parts['pass']) ||
	    ($parts['port'] ?? 443) !== 443 ||
	    !in_array($parts['host'] ?? null, ['raw.githubusercontent.com', 'api.github.com', 'github.com',
	        ...SDWAN_RELEASE_ASSET_HOSTS], true)) {
		return null;
	}
	if (!function_exists('curl_init')) {
		return null;
	}
	$body = '';
	$ch = curl_init($url);
	if ($ch === false) {
		return null;
	}
	set_curlproxy($ch);
	$configured = curl_setopt_array($ch, [
		CURLOPT_SSL_VERIFYPEER => true,
		CURLOPT_SSL_VERIFYHOST => 2,
		CURLOPT_CAPATH => '/etc/ssl/certs/',
		CURLOPT_FOLLOWLOCATION => false,
		CURLOPT_CONNECTTIMEOUT => 3,
		CURLOPT_TIMEOUT => $timeout,
		CURLOPT_USERAGENT => 'pfSense-SDWAN-updater',
		CURLOPT_WRITEFUNCTION => static function ($handle, string $data) use (&$body, $limit): int {
			if (strlen($body) + strlen($data) > $limit) {
				return 0;
			}
			$body .= $data;
			return strlen($data);
		},
	]);
	if (!$configured) {
		return null;
	}
	$ok = curl_exec($ch) !== false;
	$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	if (func_num_args() === 4 && in_array($status, [301, 302, 303, 307, 308], true)) {
		$location = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
		$redirect = is_string($location) && $location !== '' ? $location : null;
	}
	return $ok && $status === 200 ? $body : null;
}

function sdwan_release_check(): ?array {
	$body = sdwan_release_fetch(SDWAN_RELEASE_INDEX, SDWAN_RELEASE_MAX_BYTES, 7);
	return $body === null ? null : sdwan_release_parse($body);
}

function sdwan_release_compatible(): bool {
	$version = trim((string)@file_get_contents('/etc/version'));
	return in_array($version, ['2.9.1-RELEASE', '2.9.2-RELEASE'], true) &&
	    pkg_exec('config ABI', $abi, $stderr) === 0 && trim($abi) === 'FreeBSD:16:amd64';
}

function sdwan_release_assets(array $release): ?array {
	if (!sdwan_release_valid_target($release)) {
		return null;
	}
	$tag = 'v' . $release['version'];
	$body = sdwan_release_fetch('https://api.github.com/repos/' . SDWAN_RELEASE_REPO . '/releases/tags/' . $tag,
	    128 * 1024, 7);
	$published = $body === null ? null : json_decode($body, true, 16);
	if (($published['tag_name'] ?? null) !== $tag || ($published['draft'] ?? null) !== false ||
	    ($published['prerelease'] ?? null) !== false || empty($published['published_at']) ||
	    !is_array($published['assets'] ?? null)) {
		return null;
	}
	$name = SDWAN_RELEASE_PACKAGE . '-' . $release['version'] . '.pkg';
	$package_size = null;
	$signature = null;
	foreach ($published['assets'] as $asset) {
		$asset_name = $asset['name'] ?? null;
		if (!in_array($asset_name, [$name, $name . '.minisig'], true)) {
			continue;
		}
		$size = $asset['size'] ?? null;
		$digest = $asset['digest'] ?? null;
		$limit = $asset_name === $name ? SDWAN_RELEASE_PACKAGE_LIMIT : SDWAN_RELEASE_SIGNATURE_LIMIT;
		if (($asset['state'] ?? null) !== 'uploaded' || !is_int($size) || $size <= 0 || $size > $limit ||
		    !is_string($digest) || !preg_match('/\Asha256:[0-9a-f]{64}\z/', $digest)) {
			return null;
		}
		if ($asset_name === $name) {
			if ($package_size !== null || !hash_equals('sha256:' . $release['sha256'], $digest)) {
				return null;
			}
			$package_size = $size;
		} else {
			if ($signature !== null) {
				return null;
			}
			$signature = ['size' => $size, 'sha256' => substr($digest, 7)];
		}
	}
	return $package_size === null ? null : ['size' => $package_size, 'signature' => $signature];
}

function sdwan_release_asset_size(array $release): ?int {
	return sdwan_release_assets($release)['size'] ?? null;
}

function sdwan_release_signature_download(string $version, string $name, array $asset): ?string {
	$url = 'https://github.com/' . SDWAN_RELEASE_REPO . '/releases/download/v' . $version . '/' . $name;
	$signature = sdwan_release_fetch($url, $asset['size'], 7, $redirect);
	if ($signature === null && $redirect !== null &&
	    in_array(parse_url($redirect, PHP_URL_HOST), SDWAN_RELEASE_ASSET_HOSTS, true)) {
		$signature = sdwan_release_fetch($redirect, $asset['size'], 7);
	}
	return $signature !== null && strlen($signature) === $asset['size'] &&
	    hash_equals($asset['sha256'], hash('sha256', $signature)) ? $signature : null;
}

function sdwan_release_signature_valid(string $archive, string $signature): bool {
	if (!is_file(SDWAN_RELEASE_SIGNING_KEY) || !is_executable(SDWAN_RELEASE_MINISIGN)) {
		return false;
	}
	return mwexec(escapeshellarg(SDWAN_RELEASE_MINISIGN) . ' -Vq -m ' . escapeshellarg($archive) .
	    ' -x ' . escapeshellarg($signature) . ' -p ' . escapeshellarg(SDWAN_RELEASE_SIGNING_KEY), true) === 0;
}

function sdwan_release_manifest_matches(string $path, string $version): bool {
	$file = escapeshellarg($path);
	return pkg_exec("query -F {$file} '%n %v %o'", $manifest, $stderr) === 0 &&
	    trim($manifest) === SDWAN_RELEASE_PACKAGE . ' ' . $version . ' net/' . SDWAN_RELEASE_PACKAGE;
}

function sdwan_release_files_intact(string $version): bool {
	return sdwan_release_installed() === $version &&
	    pkg_exec('check -s ' . SDWAN_RELEASE_PACKAGE, $stdout, $stderr) === 0;
}

function sdwan_release_restore(string $backup, string $previous, string $attempted): string {
	$current = sdwan_release_installed();
	if ($current !== null && $current !== $previous && $current !== $attempted) {
		return 'rollback_changed';
	}
	// Force is reserved for recovery from this attempt, using the archive made beforehand.
	$file = escapeshellarg($backup);
	return pkg_exec("add -f {$file} 2>&1", $output, $stderr) === 0 && sdwan_release_files_intact($previous) ?
	    'rolled_back' : 'rollback_failed';
}

function sdwan_release_verify_installation(string $version, ?int $installed_since = null): string {
	if (!sdwan_release_files_intact($version)) {
		return 'verify_files';
	}
	if (mwexec('/usr/local/etc/rc.d/sdwand.sh status', true) !== 0) {
		return 'verify';
	}
	// The native rc status tracks the daemon supervisor, including between worker restarts.
	$supervisor = trim((string)@file_get_contents('/var/run/sdwand.pid', false, null, 0, 32));
	if (!preg_match('/\A[1-9][0-9]{0,9}\z/', $supervisor)) {
		return 'verify';
	}
	require_once(__DIR__ . '/sdwan.inc');
	require_once(__DIR__ . '/sdwan_engine.inc');
	try {
		$snapshot = sdwan_current_snapshot(sdwan_get_config(), sdwan_gateways());
	} catch (UnexpectedValueException $e) {
		return 'verify';
	}
	$observer = $snapshot['observer'] ?? null;
	$pid = $observer['pid'] ?? null;
	if (!is_array($observer) || !is_int($pid) || $pid <= 0 || ($observer['version'] ?? null) !== $version ||
	    $snapshot['generated_at'] < ($installed_since ?? 0)) {
		return 'verify';
	}
	// Confirm that the current supervised worker published the sample from its installed build.
	$worker = '/bin/pgrep -P ' . $supervisor . ' -u 0 -fx ' .
	    escapeshellarg('/usr/local/bin/php /usr/local/sbin/sdwand\.php');
	return mwexec($worker . ' | /usr/bin/grep -Fx ' . $pid, true) === 0 ? 'verified' : 'verify';
}

/* The WebGUI caller checks the native install privilege and verifies CSRF before calling this. */
function sdwan_release_upgrade(array $target, bool $verify_only = false): string {
	if (!sdwan_release_valid_target($target) || !sdwan_release_compatible()) {
		return 'invalid';
	}
	$lock = sdwan_lock('sdwan-package-upgrade', 1);
	if (!is_resource($lock)) {
		return 'busy';
	}
	$directory = null;
	$staged_files = [];
	$preserved_backup = null;
	try {
		$installed = sdwan_release_installed();
		if ($installed === $target['version']) {
			return sdwan_release_verify_installation($installed);
		}
		if ($verify_only || $installed === null || pkg_version_compare($installed, $target['version']) !== '<') {
			return 'not_newer';
		}
		$release = sdwan_release_check();
		if ($release === null || $target['version'] !== $release['version'] ||
		    !hash_equals($target['sha256'], $release['sha256'])) {
			return 'changed';
		}
		$assets = sdwan_release_assets($release);
		if ($assets === null) {
			return 'unpublished';
		}
		$size = $assets['size'];
		$name = SDWAN_RELEASE_PACKAGE . '-' . $release['version'] . '.pkg';
		$archive = sdwan_release_fetch('https://raw.githubusercontent.com/' . SDWAN_RELEASE_REPO .
		    '/refs/tags/v' . $release['version'] . '/dist/' . $name, $size, 25);
		if ($archive === null) {
			return 'download';
		}
		if (strlen($archive) !== $size || !hash_equals($release['sha256'], hash('sha256', $archive))) {
			return 'checksum';
		}
		$staging = sys_get_temp_dir() . '/sdwan-upgrade-' . bin2hex(random_bytes(12));
		if (!@mkdir($staging, 0700)) {
			return 'storage';
		}
		$directory = $staging;
		$path = $directory . '/' . $name;
		$staged_files[] = $path;
		if (@file_put_contents($path, $archive) !== $size) {
			return 'storage';
		}
		if ($assets['signature'] !== null && (file_exists(SDWAN_RELEASE_SIGNING_KEY) || is_link(SDWAN_RELEASE_SIGNING_KEY))) {
			$signature_name = $name . '.minisig';
			$signature = sdwan_release_signature_download($release['version'], $signature_name, $assets['signature']);
			$signature_path = $directory . '/' . $signature_name;
			$staged_files[] = $signature_path;
			if ($signature === null || @file_put_contents($signature_path, $signature) !== strlen($signature) ||
			    !sdwan_release_signature_valid($path, $signature_path)) {
				return 'signature';
			}
		}
		if (!sdwan_release_manifest_matches($path, $release['version'])) {
			return 'manifest';
		}
		if (sdwan_release_installed() !== $installed) {
			return 'changed';
		}
		$backup = $directory . '/' . SDWAN_RELEASE_PACKAGE . '-' . $installed . '.pkg';
		$staged_files[] = $backup;
		if (!sdwan_release_files_intact($installed) ||
		    pkg_exec('create -q -o ' . escapeshellarg($directory) . ' ' . SDWAN_RELEASE_PACKAGE, $output, $stderr) !== 0 ||
		    !is_file($backup) || !sdwan_release_manifest_matches($backup, $installed)) {
			return 'backup';
		}
		if (sdwan_release_installed() !== $installed) {
			return 'changed';
		}
		// Drain pkg and its hook messages together, using pfSense's native environment.
		$installed_since = time();
		$file = escapeshellarg($path);
		$status = pkg_exec("add {$file} 2>&1", $output, $stderr) === 0 ?
		    sdwan_release_verify_installation($release['version'], $installed_since) : 'verify_files';
		if ($status === 'verify_files') {
			$status = sdwan_release_restore($backup, $installed, $release['version']);
			if ($status === 'rollback_failed') {
				$preserved_backup = $backup;
				if (function_exists('sdwan_log_emit')) {
					sdwan_log_emit(LOG_ERR, 'Automatic rollback failed. Local recovery archive: ' . $backup);
				}
			}
		}
		return $status === 'verified' ? 'success' : $status;
	} finally {
		foreach ($staged_files as $file) {
			if ($file !== $preserved_backup && is_file($file)) {
				unlink($file);
			}
		}
		if ($directory !== null && $preserved_backup === null) {
			rmdir($directory);
		}
		sdwan_unlock($lock);
	}
}
