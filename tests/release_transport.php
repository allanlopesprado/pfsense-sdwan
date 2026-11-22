<?php
require_once __DIR__ . '/fixtures/release_curl.php';
require_once($argv[1] ?? __DIR__ . '/../files/usr/local/pkg/sdwan_release.inc');

function check(bool $test): void {
	if (!$test) {
		throw new RuntimeException('Unexpected release result near line ' . debug_backtrace()[0]['line']);
	}
}

function try_lock($name, $timeout) {
	check($name === 'sdwan-package-upgrade' && $timeout === 1);
	return tmpfile();
}

function unlock($lock): void {
	fclose($lock);
}

function pkg_exec($command, &$stdout, &$stderr): int {
	global $arg_root, $pkg_adds;
	check($arg_root !== null);
	$stderr = '';
	if (str_starts_with($command, 'add ')) {
		$pkg_adds++;
		$command = 'add -I ' . substr($command, 4); // Suppress pfSense hooks in the isolated FreeBSD root.
	}
	$native = '/usr/local/sbin/pkg-static -r ' . escapeshellarg($arg_root) .
	    ' -o ABI=FreeBSD:16:amd64 -o OSVERSION=1600018 ';
	exec($native . $command, $lines, $rc);
	$stdout = implode("\n", $lines);
	return $rc;
}

function pkg_version_compare($a, $b): string {
	pkg_exec('version -t ' . escapeshellarg($a) . ' ' . escapeshellarg($b), $stdout, $stderr);
	return trim($stdout);
}

function mwexec($command, $quiet): int {
	check($command === '/usr/local/etc/rc.d/sdwand.sh status' && $quiet);
	return 1; // The isolated database deliberately does not start the native observer.
}

$version = $argv[3] ?? '0.4.8';
$arg_root = $argv[2] ?? null;
$baseline = $argv[5] ?? null;
$archive = $arg_root === null ? 'fixture archive' : file_get_contents($argv[4]);
$index_http = fixture_release_http($version, $archive);
[$index, $api, $package] = array_keys($index_http);
$release_http = $index_http;
$release_requests = [];
$target = ['version' => $version, 'sha256' => hash('sha256', $archive)];
$release = $target + ['maturity' => 'experimental'];
$pkg_adds = 0;


check(sdwan_release_check() === $release);
check(sdwan_release_asset_size($release) === strlen($archive));
if ($arg_root !== null) {
	// Under FreeBSD, every package command operates on the real isolated pkg database.
	check(sdwan_release_installed() === $baseline);
	$release_http[$package]['body'] = substr($archive, 0, 80);
	$release_http[$package]['ok'] = false;
	check(sdwan_release_upgrade($target) === 'download' && $pkg_adds === 0);
	check(sdwan_release_installed() === $baseline);
	$release_http = $index_http;
	$release_http[$package]['body'] = str_repeat('x', strlen($archive));
	check(sdwan_release_upgrade($target) === 'checksum' && $pkg_adds === 0);
	check(sdwan_release_installed() === $baseline);
	$release_http = $index_http;
	check(sdwan_release_upgrade($target) === 'verify' && $pkg_adds === 1);
	check(sdwan_release_installed() === $version);
	$release_requests = [];
	check(sdwan_release_upgrade($target) === 'verify' && $pkg_adds === 1 && $release_requests === []);
	echo "ok - bad downloads preserve the package, the verified archive installs once, and readiness retry stays local\n";
	exit;
}

foreach ([301, 403, 404, 500] as $http_status) {
	$release_http[$index]['status'] = $http_status;
	check(sdwan_release_check() === null);
}
$release_http = $index_http;
$release_http[$index]['ok'] = false;
check(sdwan_release_check() === null);
$release_http = $index_http;
$release_http[$index]['body'] .= str_repeat(' ', SDWAN_RELEASE_MAX_BYTES);
check(sdwan_release_check() === null);
$release_http = $index_http;
foreach ([['draft', true], ['prerelease', true], ['tag_name', 'v0.4.9']] as [$key, $value]) {
	$body = json_decode($index_http[$api]['body'], true);
	$body[$key] = $value;
	$release_http[$api]['body'] = json_encode($body);
	check(sdwan_release_asset_size($release) === null);
}
foreach ([['state', 'new'], ['digest', 'sha256:' . str_repeat('0', 64)], ['size', SDWAN_RELEASE_PACKAGE_LIMIT + 1]] as [$key, $value]) {
	$body = json_decode($index_http[$api]['body'], true);
	$body['assets'][0][$key] = $value;
	$release_http[$api]['body'] = json_encode($body);
	check(sdwan_release_asset_size($release) === null);
}
check(sdwan_release_asset_size(['version' => '../wrong', 'sha256' => $target['sha256']]) === null);
echo "ok - fixed GitHub destinations, TLS, proxy, bounded transfers and published asset metadata\n";
