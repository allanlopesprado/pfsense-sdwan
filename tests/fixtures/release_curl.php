<?php
foreach (['CURLOPT_SSL_VERIFYPEER', 'CURLOPT_SSL_VERIFYHOST', 'CURLOPT_CAPATH', 'CURLOPT_FOLLOWLOCATION',
    'CURLOPT_CONNECTTIMEOUT', 'CURLOPT_TIMEOUT', 'CURLOPT_USERAGENT', 'CURLOPT_WRITEFUNCTION',
    'CURLINFO_HTTP_CODE', 'CURLINFO_REDIRECT_URL'] as $id => $key) {
	if (!defined($key)) {
		define($key, $id + 1);
	}
}

function fixture_attach_release_signature(array $http, string $version, string $signature): array {
	$repo = 'allanlopesprado/pfsense-sdwan';
	$name = "pfSense-pkg-SDWAN-{$version}.pkg.minisig";
	$api = "https://api.github.com/repos/{$repo}/releases/tags/v{$version}";
	$metadata = json_decode($http[$api]['body'], true, 16, JSON_THROW_ON_ERROR);
	$metadata['assets'][] = ['name' => $name, 'state' => 'uploaded',
	    'digest' => 'sha256:' . hash('sha256', $signature), 'size' => strlen($signature)];
	$http[$api]['body'] = json_encode($metadata, JSON_THROW_ON_ERROR);
	$cdn = "https://release-assets.githubusercontent.com/{$name}";
	$http["https://github.com/{$repo}/releases/download/v{$version}/{$name}"] =
	    ['body' => '', 'status' => 302, 'redirect' => $cdn];
	$http[$cdn] = ['body' => $signature];
	return $http;
}

function fixture_release_http(string $version, string $archive): array {
	$repo = 'allanlopesprado/pfsense-sdwan';
	$digest = hash('sha256', $archive);
	$name = "pfSense-pkg-SDWAN-{$version}.pkg";
	return [
		"https://raw.githubusercontent.com/{$repo}/main/dist/release.json" => ['body' => json_encode([
			'schema' => 1, 'channel' => 'main', 'maturity' => 'experimental',
			'package' => 'pfSense-pkg-SDWAN', 'version' => $version, 'sha256' => $digest,
		])],
		"https://api.github.com/repos/{$repo}/releases/tags/v{$version}" => ['body' => json_encode([
			'tag_name' => "v{$version}", 'draft' => false, 'prerelease' => false,
			'published_at' => '2026-01-01T12:00:00Z',
			'assets' => [['name' => $name, 'state' => 'uploaded', 'digest' => "sha256:{$digest}", 'size' => strlen($archive)]],
		])],
		"https://raw.githubusercontent.com/{$repo}/refs/tags/v{$version}/dist/{$name}" => ['body' => $archive],
	];
}

if (function_exists('curl_init')) {
	throw new RuntimeException('Disable the real cURL functions for the release fixtures.');
} else {
	function curl_init($url) {
		global $release_http, $release_requests;
		$release_requests[] = $url;
		if (!isset($release_http[$url])) {
			throw new RuntimeException('Unexpected HTTP request ' . $url);
		}
		return (object)['url' => $url];
	}

	function set_curlproxy(&$handle): void {
		$handle->proxyConfigured = true;
	}

	function curl_setopt_array($handle, $options): bool {
		if (!$handle->proxyConfigured || $options[CURLOPT_SSL_VERIFYPEER] !== true ||
		    $options[CURLOPT_SSL_VERIFYHOST] !== 2 || $options[CURLOPT_FOLLOWLOCATION] !== false ||
		    $options[CURLOPT_CAPATH] !== '/etc/ssl/certs/' || $options[CURLOPT_TIMEOUT] > 25 ||
		    $options[CURLOPT_CONNECTTIMEOUT] > $options[CURLOPT_TIMEOUT]) {
			throw new RuntimeException('Unverified or unbounded release transport');
		}
		$handle->write = $options[CURLOPT_WRITEFUNCTION];
		return true;
	}

	function curl_exec($handle): bool {
		$response = $GLOBALS['release_http'][$handle->url];
		foreach (str_split($response['body'], 4096) as $chunk) {
			if (($handle->write)($handle, $chunk) !== strlen($chunk)) {
				return false;
			}
		}
		return $response['ok'] ?? true;
	}

	function curl_getinfo($handle, $key): int|string {
		if ($key === CURLINFO_REDIRECT_URL) {
			return $GLOBALS['release_http'][$handle->url]['redirect'] ?? '';
		}
		if ($key !== CURLINFO_HTTP_CODE) {
			throw new RuntimeException('Unexpected cURL information request');
		}
		return $GLOBALS['release_http'][$handle->url]['status'] ?? 200;
	}
}
