<?php
declare(strict_types=1);

require __DIR__ . '/../tools/check-core-appliance.php';

$dir = sys_get_temp_dir() . '/sdwan-core-check-' . bin2hex(random_bytes(8));
$bundle = $dir . '/overlay';
$root = $dir . '/clone';
$manifest_path = $bundle . '/sdwan-overlay.json';
$rollback = $bundle . '/rollback/filter.inc';
$source = $bundle . '/src/etc/inc/filter.inc';
$adapter = $bundle . '/src/etc/inc/filter-sdwan.inc';
$version_path = $root . '/etc/version';
$live_generator = $root . '/etc/inc/filter.inc';
$live_adapter = $root . '/etc/inc/filter-sdwan.inc';
mkdir(dirname($rollback), 0700, true);
mkdir(dirname($source), 0700, true);
mkdir(dirname($live_generator), 0700, true);
register_shutdown_function(static function () use ($dir, $bundle, $root, $manifest_path, $rollback, $source,
    $adapter, $version_path, $live_generator, $live_adapter): void {
	foreach ([$manifest_path, $rollback, $source, $adapter, $version_path, $live_generator, $live_adapter] as $file) {
		if (is_file($file)) {
			unlink($file);
		}
	}
	foreach ([$bundle . '/rollback', dirname($source), $bundle . '/src/etc', $bundle . '/src', $bundle,
	    dirname($live_generator), $root . '/etc', $root, $dir] as $path) {
		rmdir($path);
	}
});

$stock = "<?php // Stock generator fixture\n";
$patched = "<?php throw new RuntimeException('The preflight must not execute the payload.');\n";
$helper = "<?php throw new RuntimeException('The preflight must not execute the helper.');\n";
$stock_digest = hash('sha256', $stock);
$abi = 'FreeBSD:16:amd64';
$manifest = ['schema' => 1, 'ce_version' => '2.9.1-RELEASE', 'abi' => $abi, 'stock_sha256' => $stock_digest,
    'generator_sha256' => hash('sha256', $patched), 'adapter_sha256' => hash('sha256', $helper)];
file_put_contents($manifest_path, json_encode($manifest));
file_put_contents($rollback, $stock);
file_put_contents($source, $patched);
file_put_contents($adapter, $helper);
file_put_contents($version_path, "2.9.1-RELEASE\n");
file_put_contents($live_generator, $stock);

function expect_core_result(string $message, callable $check, bool $failure = false): void {
	try {
		$result = $check();
	} catch (RuntimeException $error) {
		if ($failure && str_contains($error->getMessage(), $message)) {
			return;
		}
		throw $error;
	}
	if ($failure || !str_contains($result, $message)) {
		throw new RuntimeException("Unexpected preflight result: {$result}");
	}
}

$check = static fn(?string $target_abi = null) => sdwan_core_preflight($bundle, $root, $target_abi ?? $abi, $stock_digest);
expect_core_result('Stock generator and rollback copy match', $check);
file_put_contents($version_path, "2.9.2-RELEASE\n");
expect_core_result('Installed pfSense version differs', $check, true);
$manifest['ce_version'] = '2.9.2-RELEASE';
file_put_contents($manifest_path, json_encode($manifest));
expect_core_result('Stock generator and rollback copy match', $check);
expect_core_result('Package ABI differs', static fn() => $check('FreeBSD:15:amd64'), true);
expect_core_result('Invalid overlay manifest',
    static fn() => sdwan_core_preflight($bundle, $root, $abi, SDWAN_CORE_STOCK_SHA256), true);

unlink($rollback);
expect_core_result('Stock rollback copy is missing', $check, true);
file_put_contents($rollback, 'wrong stock file');
expect_core_result('Stock rollback copy is missing', $check, true);
file_put_contents($rollback, $stock);
file_put_contents($adapter, 'wrong helper file');
expect_core_result('Prepared overlay files are missing', $check, true);
file_put_contents($adapter, $helper);

file_put_contents($live_generator, $patched);
expect_core_result('Installed generator or adapter differs', $check, true);
file_put_contents($live_adapter, $helper);
expect_core_result('Overlay pair matches on disk', $check);
file_put_contents($live_generator, $stock);
expect_core_result('Restore the overlay pair and reboot', $check);
file_put_contents($live_adapter, 'unrecognized file');
expect_core_result('Installed generator or adapter differs', $check, true);
file_put_contents($live_adapter, $helper);
file_put_contents($live_generator, 'unexpected version of the generator');
expect_core_result('Installed generator or adapter differs', $check, true);
echo "ok - exact CE/ABI, intact rollback, bundle integrity and installed overlay identity\n";
