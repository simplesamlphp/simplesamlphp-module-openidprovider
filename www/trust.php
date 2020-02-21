<?php

if (!is_string($_REQUEST['StateID'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing StateID-parameter.');
}
$StateID = $_REQUEST['StateID'];

$server = \SimpleSAML\Module\openidprovider\ProviderServer::getInstance();
$state = $server->loadState($_REQUEST['StateID']);

$trustRoot = $state['request']->trust_root;
$identity = $server->getIdentity();
if ($identity === null) {
    $server->processRequest($state);
}

if (isset($_REQUEST['TrustYes'])) {
    if (isset($_REQUEST['TrustRemember'])) {
        $server->addTrustRoot($identity, $trustRoot);
    }

    $state['TrustResponse'] = true;
    $server->processRequest($state);
}

if (isset($_REQUEST['TrustNo'])) {
    $state['TrustResponse'] = false;
    $server->processRequest($state);
}

$globalConfig = \SimpleSAML\Configuration::getInstance();
$t = new \SimpleSAML\XHTML\Template($globalConfig, 'openidProvider:trust.twig');
$t->data['StateID'] = $_REQUEST['StateID'];
$t->data['trustRoot'] = $trustRoot;
$t->send();
