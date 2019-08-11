<?php

\SimpleSAML\Logger::info('OpenID - Provider: Accessing OpenID Provider endpoint');

$server = \SimpleSAML\Module\openidprovider\ProviderServer::getInstance();
$server->receiveRequest();
