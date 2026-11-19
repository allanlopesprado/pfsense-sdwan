<?php
/* Provide only the two gateway inventory functions called by the observer. */
function return_dpinger_defaults(): array {
	return ['latencyhigh' => 500, 'latencylow' => 150, 'losshigh' => 30, 'losslow' => 10];
}

function running_dpinger_processes(): array {
	return config_get_path('processes', []);
}
