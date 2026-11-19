<?php
// Release metadata is informational. Its contents are never used as an install target.
const SDWAN_RELEASE_INDEX = 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/main/dist/release.json';
const SDWAN_RELEASE_MAX_BYTES = 4096;

function sdwan_release_pkg_version(string $value): bool {
	// Permit FreeBSD's revision and epoch suffixes in locally installed versions.
	return preg_match('/\A[0-9][0-9A-Za-z._,+-]{0,63}\z/', $value) === 1;
}

function sdwan_release_installed(): ?string {
	if (pkg_exec('query %v pfSense-pkg-SDWAN', $stdout, $stderr) !== 0) {
		return null;
	}
	$version = trim($stdout);
	return sdwan_release_pkg_version($version) ? $version : null;
}

function sdwan_release_parse(string $body): ?array {
	if (strlen($body) > SDWAN_RELEASE_MAX_BYTES) {
		return null;
	}
	$release = json_decode($body, true, 4);
	if (!is_array($release) || ($release['schema'] ?? null) !== 1 ||
	    ($release['package'] ?? null) !== 'pfSense-pkg-SDWAN' || ($release['channel'] ?? null) !== 'main' ||
	    !in_array($release['maturity'] ?? null, ['experimental', 'stable'], true) ||
	    !is_string($release['version'] ?? null) ||
	    !preg_match('/\A(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}\z/', $release['version']) ||
	    !is_string($release['sha256'] ?? null) ||
	    !preg_match('/\A[0-9a-f]{64}\z/', $release['sha256'])) {
		return null;
	}
	return ['version' => $release['version'], 'sha256' => $release['sha256'], 'maturity' => $release['maturity']];
}

function sdwan_release_check(): ?array {
	if (!function_exists('curl_init')) {
		return null;
	}
	$body = '';
	$ch = curl_init(SDWAN_RELEASE_INDEX);
	if ($ch === false) {
		return null;
	}
	// Apply the same CA directory and system proxy as the pfSense HTTPS client.
	set_curlproxy($ch);
	$configured = curl_setopt_array($ch, [
		CURLOPT_SSL_VERIFYPEER => true,
		CURLOPT_SSL_VERIFYHOST => 2,
		CURLOPT_CAPATH => '/etc/ssl/certs/',
		CURLOPT_FOLLOWLOCATION => false,
		CURLOPT_CONNECTTIMEOUT => 3,
		CURLOPT_TIMEOUT => 7,
		CURLOPT_USERAGENT => 'pfSense-SDWAN-release-check',
		CURLOPT_WRITEFUNCTION => static function ($handle, string $data) use (&$body): int {
			if (strlen($body) + strlen($data) > SDWAN_RELEASE_MAX_BYTES) {
				return 0;
			}
			$body .= $data;
			return strlen($data);
		},
	]);
	$ok = $configured && curl_exec($ch) !== false && curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200;
	return $ok ? sdwan_release_parse($body) : null;
}
