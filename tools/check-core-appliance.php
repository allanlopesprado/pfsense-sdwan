<?php
declare(strict_types=1);

const SDWAN_CORE_STOCK_SHA256 = '70758089d12a271ff08ccf3e20a180d3f441f8d468e984be6b1476c366c66c30';

function sdwan_core_read_digest(string $path): ?string {
	clearstatcache(true, $path);
	$stat = @lstat($path);
	if ($stat === false || ($stat['mode'] & 0170000) !== 0100000) {
		return null;
	}
	$digest = @hash_file('sha256', $path);
	return $digest === false ? null : $digest;
}

/* This check reads a manifest, payload and stock rollback copy. It never
 * imports the supplied PHP files or changes the appliance. */
function sdwan_core_preflight(string $bundle, string $root, string $abi, string $stock_hash): string {
	$manifest_path = $bundle . '/sdwan-overlay.json';
	clearstatcache(true, $manifest_path);
	$stat = @lstat($manifest_path);
	$raw = $stat !== false && ($stat['mode'] & 0170000) === 0100000
	    ? @file_get_contents($manifest_path, false, null, 0, 1025) : false;
	$manifest = is_string($raw) && strlen($raw) <= 1024 ? json_decode($raw, true, 3) : null;
	$version = $manifest['ce_version'] ?? null;
	$generator = $manifest['generator_sha256'] ?? null;
	$adapter = $manifest['adapter_sha256'] ?? null;
	if (($manifest['schema'] ?? null) !== 1 || ($manifest['abi'] ?? null) !== 'FreeBSD:16:amd64' ||
	    !in_array($version, ['2.9.1-RELEASE', '2.9.2-RELEASE'], true) ||
	    ($manifest['stock_sha256'] ?? null) !== $stock_hash ||
	    !is_string($generator) || $generator === $stock_hash || !preg_match('/\A[a-f0-9]{64}\z/', $generator) ||
	    !is_string($adapter) || !preg_match('/\A[a-f0-9]{64}\z/', $adapter)) {
		throw new RuntimeException('Invalid overlay manifest. Prepare a bundle for this exact CE release.');
	}
	$installed = @file_get_contents($root . '/etc/version', false, null, 0, 65);
	if ($installed === false || strlen($installed) > 64 || trim($installed) !== $version) {
		throw new RuntimeException('Installed pfSense version differs from the bundle. Prepare an overlay for the installed CE release.');
	}
	if ($abi !== $manifest['abi']) {
		throw new RuntimeException('Package ABI differs from FreeBSD:16:amd64.');
	}
	if (sdwan_core_read_digest($bundle . '/rollback/filter.inc') !== $stock_hash) {
		throw new RuntimeException('Stock rollback copy is missing or does not match the audited generator.');
	}
	if (sdwan_core_read_digest($bundle . '/src/etc/inc/filter.inc') !== $generator ||
	    sdwan_core_read_digest($bundle . '/src/etc/inc/filter-sdwan.inc') !== $adapter) {
		throw new RuntimeException('Prepared overlay files are missing or do not match the manifest.');
	}
	$live_generator = sdwan_core_read_digest($root . '/etc/inc/filter.inc');
	$live_adapter_path = $root . '/etc/inc/filter-sdwan.inc';
	$live_adapter = sdwan_core_read_digest($live_adapter_path);
	if ($live_generator === $generator && $live_adapter === $adapter) {
		return 'Overlay pair matches on disk and the stock rollback copy is intact. Check verified boot and active PF in Forwarding.';
	}
	if ($live_generator === $stock_hash && $live_adapter === $adapter) {
		return 'Stock generator and rollback copy match. Restore the overlay pair and reboot after checking native safeguards.';
	}
	if ($live_generator === $stock_hash && $live_adapter === null && @lstat($live_adapter_path) === false) {
		return 'Stock generator and rollback copy match. Review native safeguards before installing this overlay and rebooting.';
	}
	throw new RuntimeException('Installed generator or adapter differs from this bundle. Review both files from the console before changing them.');
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
	if ($argc !== 2) {
		fwrite(STDERR, "Usage: php check-core-appliance.php <prepared-overlay-directory>\n");
		exit(2);
	}
	try {
		if (!function_exists('exec') || !is_executable('/usr/local/sbin/pkg')) {
			throw new RuntimeException('Could not read the native package ABI.');
		}
		exec('/usr/local/sbin/pkg config ABI 2>/dev/null', $output, $status);
		if ($status !== 0) {
			throw new RuntimeException('Could not read the native package ABI.');
		}
		echo sdwan_core_preflight($argv[1], '', implode("\n", $output), SDWAN_CORE_STOCK_SHA256), "\n";
	} catch (RuntimeException $error) {
		fwrite(STDERR, $error->getMessage() . "\n");
		exit(1);
	}
}
