<?php
declare(strict_types=1);

require __DIR__ . '/../files/usr/local/pkg/sdwan_preflight.inc';
require __DIR__ . '/../tools/check-https-destinations.php';

$aliases = [
	['name' => 'ERP', 'type' => 'host', 'address' => '192.0.2.162 192.0.2.164 192.0.2.162'],
	['name' => 'Backup', 'type' => 'host', 'address' => '192.0.2.163'],
	['name' => 'Overlap', 'type' => 'host', 'address' => '192.0.2.164 192.0.2.163'],
	['name' => 'Dynamic', 'type' => 'host', 'address' => 'erp.sdwan.test'],
	['name' => 'IPv6', 'type' => 'host', 'address' => '2001:db8::1'],
	['name' => 'Network', 'type' => 'network', 'address' => '192.0.2.0/24'],
];
if (sdwan_https_destinations($aliases, 'ERP', 'Backup') !==
    ['ERP' => ['192.0.2.162', '192.0.2.164'], 'Backup' => ['192.0.2.163']]) {
	throw new RuntimeException('Disjoint destination scopes did not pass preview.');
}
foreach (['ERP' => 'overlap', 'Overlap' => 'overlap', 'Dynamic' => 'literal IPv4',
    'IPv6' => 'literal IPv4', 'Network' => 'native Host aliases', 'Absent' => 'native Host aliases'] as $alias => $reason) {
	try {
		sdwan_https_destinations($aliases, 'ERP', $alias);
	} catch (InvalidArgumentException $error) {
		if (str_contains($error->getMessage(), $reason)) {
			continue;
		}
		throw $error;
	}
	throw new RuntimeException("Unsafe destination scope {$alias} passed preview.");
}
echo "ok - read-only HTTPS destination preview rejects overlap, dynamic endpoints and invalid aliases\n";
