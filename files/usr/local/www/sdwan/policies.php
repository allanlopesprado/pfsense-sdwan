<?php
require_once('guiconfig.inc');
define('SDWAN_GUI', true);
require_once(__DIR__ . '/ui.inc.php');

$collection = 'policies';
require(__DIR__ . '/editor.inc.php');
