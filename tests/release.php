<?php
require_once __DIR__ . '/../files/usr/local/pkg/sdwan_release.inc';

function verify(bool $condition): void {
	if (!$condition) {
		throw new RuntimeException('Release check failed near line ' . debug_backtrace()[0]['line']);
	}
}

// Simulate the native API, including pkg errors and custom FreeBSD revisions.
function pkg_exec($command, &$stdout, &$stderr): int {
	verify($command === 'query %v pfSense-pkg-SDWAN');
	global $local_version, $pkg_rc;
	$stdout = $local_version;
	return $pkg_rc;
}

$pkg_rc = 0;
$local_version = "0.2.0_1,1\n";
verify(sdwan_release_installed() === '0.2.0_1,1');
foreach (['', "a\nb", "0.2.0'", "0.2.0; true"] as $local_version) {
	verify(sdwan_release_installed() === null);
}
$pkg_rc = 1;
$local_version = '0.2.0';
verify(sdwan_release_installed() === null);

$index = ['schema' => 1, 'channel' => 'lab', 'package' => 'pfSense-pkg-SDWAN', 'version' => '0.2.0', 'sha256' => str_repeat('a', 64)];
verify(sdwan_release_parse(json_encode($index)) === ['version' => '0.2.0', 'sha256' => str_repeat('a', 64)]);
foreach (['', 'null', '[]', '{', str_repeat(' ', SDWAN_RELEASE_MAX_BYTES) . json_encode($index)] as $invalid) {
	verify(sdwan_release_parse($invalid) === null);
}
foreach ([['schema', '1'], ['channel', 'stable'], ['package', 'pfSense'], ['version', []], ['version', '2.0'], ['version', '00.2.0'],
    ['version', '1.0.0;'], ['version', "1.0.0\n"], ['sha256', 'bogus'], ['sha256', []]] as [$key, $invalid]) {
	$test = $index;
	$test[$key] = $invalid;
	verify(sdwan_release_parse(json_encode($test)) === null);
}
$index['url'] = 'https://unused.invalid/';
verify(!array_key_exists('url', sdwan_release_parse(json_encode($index))));
echo "ok - local version, constrained GitHub metadata and malformed release responses\n";
