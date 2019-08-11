<?php

if (!is_string($_REQUEST['StateID'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing StateID-parameter');
}

$server = \SimpleSAML\Module\openidprovider\ProviderServer::getInstance();
$state = $server->loadState($_REQUEST['StateID']);
$server->processRequest($state);
