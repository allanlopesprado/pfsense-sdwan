<?php
require_once __DIR__ . '/fixtures/release_curl.php';
require_once($argv[1] ?? __DIR__ . '/../files/usr/local/pkg/sdwan_release.inc');

function check(bool $test): void {
	if (!$test) {
		throw new RuntimeException('Unexpected release result near line ' . debug_backtrace()[0]['line']);
	}
}

function sdwan_lock($name, $timeout) {
	check($name === 'sdwan-package-upgrade' && $timeout === 1);
	return tmpfile();
}

function sdwan_unlock($lock): void {
	fclose($lock);
}

function pkg_exec($command, &$stdout, &$stderr): int {
	global $arg_root, $pkg_adds, $pkg_rollbacks, $fail_after_native_add;
	check($arg_root !== null);
	$stderr = '';
	$inject_failure = null;
	$add_prefix = '-o DEVELOPER_MODE=yes add ';
	if (str_starts_with($command, $add_prefix)) {
		$arguments = substr($command, strlen($add_prefix));
		if (str_starts_with($arguments, '-f ')) {
			$pkg_rollbacks++;
		} else {
			$pkg_adds++;
			$inject_failure = $fail_after_native_add;
		}
		$command = $add_prefix . '-I ' . $arguments; // Suppress pfSense hooks in the isolated FreeBSD root.
	}
	$native = '/usr/local/sbin/pkg-static -r ' . escapeshellarg($arg_root) .
	    ' -o ABI=FreeBSD:16:amd64 -o OSVERSION=1600018 ';
	exec($native . $command, $lines, $rc);
	$stdout = implode("\n", $lines);
	if ($inject_failure === 'hook' && $rc === 0) {
		$stdout .= "\npkg-static: POST-INSTALL script failed\n";
	}
	return $inject_failure === 'exit' && $rc === 0 ? 1 : $rc;
}

function pkg_version_compare($a, $b): string {
	pkg_exec('version -t ' . escapeshellarg($a) . ' ' . escapeshellarg($b), $stdout, $stderr);
	return trim($stdout);
}

function mwexec($command, $quiet): int {
	check($command === '/usr/local/etc/rc.d/sdwand.sh status' && $quiet);
	return 0; // Model a ready supervisor while the isolated root deliberately skips pfSense hooks.
}

function g_get($key, $default) {
	return $key === 'varrun_path' ? $GLOBALS['arg_root'] . '/var/run' : $default;
}

function config_read_file($use_backup, $use_cache): bool {
	check(!$use_backup && !$use_cache);
	return true;
}

function get_package_id($name) {
	return $name === 'SDWAN' ? 0 : -1;
}

function config_get_path($path, $default = null) {
	return match ($path) {
		'installedpackages/package/0/version' => sdwan_release_installed(),
		'installedpackages/package/0/configurationfile' => 'sdwan.xml',
		'installedpackages/menu' => [['configfile' => 'sdwan.xml', 'url' => '/sdwan/status.php', 'section' => 'Services']],
		'installedpackages/service' => $GLOBALS['registration_failure'] && sdwan_release_installed() === $GLOBALS['version'] ?
		    [] : [['name' => 'sdwan', 'rcfile' => 'sdwand.sh']],
		default => $default,
	};
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
$pkg_rollbacks = 0;
$fail_after_native_add = null;
$registration_failure = false;


check(sdwan_release_check() === $release);
check(sdwan_release_asset_size($release) === strlen($archive));
if ($arg_root !== null) {
	// Under FreeBSD, every package command operates on the real isolated pkg database.
	check(sdwan_release_installed() === $baseline);
	$varrun = g_get('varrun_path', '/var/run');
	check(is_dir($varrun) || mkdir($varrun, 0700, true));
	$recovery = sdwan_release_recovery_dir();
	$backup = $recovery . '/pfSense-pkg-SDWAN-' . $baseline . '.pkg';
	$release_http[$package]['body'] = substr($archive, 0, 80);
	$release_http[$package]['ok'] = false;
	check(sdwan_release_upgrade($target) === 'download' && $pkg_adds === 0);
	check(sdwan_release_installed() === $baseline);
	$release_http = $index_http;
	$release_http[$package]['body'] = str_repeat('x', strlen($archive));
	check(sdwan_release_upgrade($target) === 'checksum' && $pkg_adds === 0);
	check(sdwan_release_installed() === $baseline);
	$release_http = $index_http;
	$fail_after_native_add = 'exit';
	check(sdwan_release_upgrade($target) === 'rollback_verify' && $pkg_adds === 1 && $pkg_rollbacks === 1);
	check(sdwan_release_installed() === $baseline && sdwan_release_files_intact($baseline));
	check(is_file($backup) && sdwan_release_read_recovery($recovery)['previous'] === $baseline);
	check(sdwan_release_upgrade($target) === 'recovery_pending' && $pkg_adds === 1);
	sdwan_release_clear_recovery($recovery, $backup);
	$fail_after_native_add = 'hook';
	check(sdwan_release_upgrade($target) === 'rollback_verify' && $pkg_adds === 2 && $pkg_rollbacks === 2);
	check(sdwan_release_installed() === $baseline && sdwan_release_files_intact($baseline));
	check(is_file($backup));
	sdwan_release_clear_recovery($recovery, $backup);
	$fail_after_native_add = null;
	$registration_failure = true;
	check(sdwan_release_upgrade($target) === 'rollback_verify' && $pkg_adds === 3 && $pkg_rollbacks === 3);
	check(sdwan_release_installed() === $baseline && is_file($backup));
	sdwan_release_clear_recovery($recovery, $backup);
	$registration_failure = false;
	check(sdwan_release_upgrade($target) === 'verify' && $pkg_adds === 4 && $pkg_rollbacks === 3);
	check(sdwan_release_installed() === $version);
	$release_requests = [];
	check(sdwan_release_upgrade($target) === 'verify' && $pkg_adds === 4 && $release_requests === [] && is_file($backup));
	sdwan_release_clear_recovery($recovery, $backup);
	echo "ok - bad downloads preserve the package, installation and registration failures roll back, pending recovery retains the archive\n";
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
$synthetic = 'signature fixture';
$release_http = fixture_attach_release_signature($index_http, $version, $synthetic);
[$signature_url, $signature_cdn] = array_slice(array_keys($release_http), -2);
$signature = sdwan_release_assets($release)['signature'];
check($signature === ['size' => strlen($synthetic), 'sha256' => hash('sha256', $synthetic)]);
$signature_name = "pfSense-pkg-SDWAN-{$version}.pkg.minisig";
check(sdwan_release_signature_download($version, $signature_name, $signature) === $synthetic);
$release_http[$signature_cdn]['body'] = str_repeat('x', strlen($synthetic));
check(sdwan_release_signature_download($version, $signature_name, $signature) === null);
$release_requests = [];
$release_http[$signature_url]['redirect'] = 'https://other.example.net/signature';
check(sdwan_release_signature_download($version, $signature_name, $signature) === null && $release_requests === [$signature_url]);
echo "ok - fixed GitHub destinations, TLS, proxy, bounded transfers, independent metadata and signature transport\n";
