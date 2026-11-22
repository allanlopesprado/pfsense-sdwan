<?php

const SDWAN_RELEASE_REPO = 'allanlopesprado/pfsense-sdwan';
const SDWAN_RELEASE_INDEX = 'https://raw.githubusercontent.com/' . SDWAN_RELEASE_REPO . '/main/dist/release.json';
const SDWAN_RELEASE_MAX_BYTES = 4096;
const SDWAN_RELEASE_PACKAGE = 'pfSense-pkg-SDWAN';
const SDWAN_RELEASE_PACKAGE_LIMIT = 2 * 1024 * 1024;

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

/* All callers construct destinations from the fixed repository and a checked version. */
function sdwan_release_fetch(string $url, int $limit, int $timeout): ?string {
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
	$ok = $configured && curl_exec($ch) !== false && curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200;
	return $ok ? $body : null;
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

function sdwan_release_asset_size(array $release): ?int {
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
	foreach ($published['assets'] as $asset) {
		if (($asset['name'] ?? null) === $name && ($asset['state'] ?? null) === 'uploaded' &&
		    ($asset['digest'] ?? null) === 'sha256:' . $release['sha256'] &&
		    is_int($asset['size'] ?? null) && $asset['size'] > 0 && $asset['size'] <= SDWAN_RELEASE_PACKAGE_LIMIT) {
			return $asset['size'];
		}
	}
	return null;
}

function sdwan_release_verify_installation(string $version, ?int $installed_since = null): string {
	if (sdwan_release_installed() !== $version ||
	    pkg_exec('check -s ' . SDWAN_RELEASE_PACKAGE, $stdout, $stderr) !== 0) {
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
	$lock = try_lock('sdwan-package-upgrade', 1);
	if (!is_resource($lock)) {
		return 'busy';
	}
	$directory = null;
	$path = null;
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
		$size = sdwan_release_asset_size($release);
		if ($size === null) {
			return 'unpublished';
		}
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
		if (@file_put_contents($path, $archive) !== $size) {
			return 'storage';
		}
		$file = escapeshellarg($path);
		if (pkg_exec("query -F {$file} '%n %v %o'", $manifest, $stderr) !== 0 ||
		    trim($manifest) !== SDWAN_RELEASE_PACKAGE . ' ' . $release['version'] . ' net/' . SDWAN_RELEASE_PACKAGE) {
			return 'manifest';
		}
		if (sdwan_release_installed() !== $installed) {
			return 'changed';
		}
		// Drain pkg and its hook messages together, using pfSense's native environment.
		$installed_since = time();
		if (pkg_exec("add {$file} 2>&1", $output, $stderr) !== 0) {
			return 'install';
		}
		$status = sdwan_release_verify_installation($release['version'], $installed_since);
		return $status === 'verified' ? 'success' : $status;
	} finally {
		if ($path !== null && is_file($path)) {
			unlink($path);
		}
		if ($directory !== null) {
			rmdir($directory);
		}
		unlock($lock);
	}
}
