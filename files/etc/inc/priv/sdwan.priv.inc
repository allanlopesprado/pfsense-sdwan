<?php

global $priv_list;

$sdwan_view_pages = ['sdwan/status.php*', 'sdwan/diagnostics.php*', 'widgets/widgets/sdwan.widget.php*'];
$priv_list['page-services-sdwan-view'] = [
	'name' => 'WebCfg - Services: SD-WAN status',
	'descr' => 'View SD-WAN health and path recommendations.',
	'match' => $sdwan_view_pages,
];
$priv_list['page-services-sdwan-manage'] = [
	'name' => 'WebCfg - Services: SD-WAN management',
	'descr' => 'Manage SD-WAN members, SLAs and policies.',
	'match' => array_merge($sdwan_view_pages, [
		'sdwan/members.php*',
		'sdwan/slas.php*',
		'sdwan/policies.php*',
		'sdwan/forwarding.php*',
		'sdwan/updates.php*',
	]),
];
unset($sdwan_view_pages);
