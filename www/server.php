<?php

\SimpleSAML\Logger::info('OpenID - Provider: Accessing OpenID Provider endpoint');

$server = ProviderServer::getInstance();
$server->receiveRequest();
