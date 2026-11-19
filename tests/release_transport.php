<?php
// Run in the CLI with the four cURL functions disabled, so no network is used.
foreach (['CURLOPT_SSL_VERIFYPEER', 'CURLOPT_SSL_VERIFYHOST', 'CURLOPT_CAPATH', 'CURLOPT_FOLLOWLOCATION',
    'CURLOPT_CONNECTTIMEOUT', 'CURLOPT_TIMEOUT', 'CURLOPT_USERAGENT', 'CURLOPT_WRITEFUNCTION', 'CURLINFO_HTTP_CODE'] as $id => $key) {
	if (!defined($key)) {
		define($key, $id + 1);
	}
}

require_once __DIR__ . '/../files/usr/local/pkg/sdwan_release.inc';

function check(bool $test): void {
	if (!$test) {
		throw new RuntimeException('Unexpected transport result near line ' . debug_backtrace()[0]['line']);
	}
}

if (function_exists('curl_init') || function_exists('curl_setopt_array') ||
    function_exists('curl_exec') || function_exists('curl_getinfo')) {
	throw new RuntimeException('Run with mocked cURL functions as in tests/run.sh');
} else {
	function curl_init($url) {
		check($url === 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/dev/native-forwarding/dist/release.json');
		return new stdClass();
	}

	function set_curlproxy(&$handle): void {
		$handle->proxyConfigured = true;
	}

	function curl_setopt_array($handle, $options): bool {
		check($handle->proxyConfigured && $options[CURLOPT_SSL_VERIFYPEER] === true);
		check($options[CURLOPT_SSL_VERIFYHOST] === 2 && $options[CURLOPT_FOLLOWLOCATION] === false);
		check($options[CURLOPT_CAPATH] === '/etc/ssl/certs/' && $options[CURLOPT_TIMEOUT] <= 10);
		check($options[CURLOPT_CONNECTTIMEOUT] <= $options[CURLOPT_TIMEOUT]);
		$handle->write = $options[CURLOPT_WRITEFUNCTION];
		return true;
	}

	function curl_exec($handle): bool {
		global $chunks, $transport_result;
		foreach ($chunks as $chunk) {
			if (($handle->write)($handle, $chunk) !== strlen($chunk)) {
				return false;
			}
		}
		return $transport_result;
	}

	function curl_getinfo($handle, $key): int {
		check($key === CURLINFO_HTTP_CODE);
		return $GLOBALS['http_status'];
	}
}

$release = ['version' => '0.2.0', 'sha256' => str_repeat('a', 64)];
$chunks = str_split(json_encode(['schema' => 1, 'channel' => 'lab', 'package' => 'pfSense-pkg-SDWAN'] + $release), 6);
$transport_result = true;
$http_status = 200;
check(sdwan_release_check() === $release);
foreach ([301, 403, 404, 500] as $http_status) {
	check(sdwan_release_check() === null);
}
$http_status = 200;
$transport_result = false;
check(sdwan_release_check() === null);
$transport_result = true;
$chunks[] = str_repeat(' ', SDWAN_RELEASE_MAX_BYTES);
check(sdwan_release_check() === null);
echo "ok - fixed GitHub destination, TLS, proxy, bounded body and transport failures\n";
