<?php
declare(strict_types=1);

/* The pilot can prove only disjoint, static IPv4 destinations. */
function sdwan_https_destinations(array $inventory, string $left, string $right): array {
	$scopes = [];
	foreach ([$left, $right] as $name) {
		$alias = sdwan_preflight_host_alias($inventory, $name);
		if ($alias === null) {
			throw new InvalidArgumentException('Select two configured native Host aliases.');
		}
		foreach ($alias['entries'] as $address) {
			if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
				throw new InvalidArgumentException("Alias {$name} must contain only literal IPv4 addresses.");
			}
			$scopes[$name][$address] = true;
		}
	}
	if ($left === $right || array_intersect_key($scopes[$left], $scopes[$right])) {
		throw new InvalidArgumentException('The aliases overlap. Give each policy its own destination or keep the shared IP on the native fallback.');
	}
	return array_map('array_keys', $scopes);
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
	if ($argc !== 3) {
		fwrite(STDERR, "Usage: php check-https-destinations.php <first-host-alias> <second-host-alias>\n");
		exit(2);
	}
	require_once('config.inc');
	require_once('/usr/local/pkg/sdwan_preflight.inc');
	try {
		$aliases = config_get_path('aliases/alias', []);
		if (!is_array($aliases)) {
			throw new InvalidArgumentException('Could not read the configured native aliases.');
		}
		$scopes = sdwan_https_destinations($aliases, $argv[1], $argv[2]);
		foreach ($scopes as $name => $addresses) {
			printf("%s: %s\n", $name, implode(', ', $addresses));
		}
		echo "Disjoint configured IPv4 destinations. Verify both active PF tables and new connections from the LAN.\n";
	} catch (InvalidArgumentException $error) {
		fwrite(STDERR, $error->getMessage() . "\n");
		exit(1);
	}
}
