<?php

namespace SimpleSAML\Module\openidprovider;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;

/*
 * Disable strict error reporting, since the OpenID library
 * used is PHP4-compatible, and not PHP5 strict-standards compatible.
 */

ProviderUtils::maskErrors(E_NOTICE | E_STRICT);
if (defined('E_DEPRECATED')) {
    // PHP 5.3 also has E_DEPRECATED
    ProviderUtils::maskErrors(constant('E_DEPRECATED'));
}

// Add the OpenID library search path.
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(dirname(dirname(dirname(__FILE__)))) . '/lib');
include_once('Auth/OpenID/SReg.php');
include_once('Auth/OpenID/AX.php');

/**
 * Helper class for the OpenID provider code.
 *
 * @package SimpleSAMLphp
 * @version $Id$
 */
class ProviderServer
{
    /**
     * The authentication source for this provider.
     *
     * @var Auth\Simple
     */
    private $authSource;

    /**
     * The attribute name where the username is stored.
     *
     * @var string
     */
    private $usernameAttribute;

    /**
     * authproc configuration option
     *
     * @var array
     */
    private $authProc;

    /**
     * The OpenID server.
     *
     * @var \Auth_OpenID_Server
     */
    private $server;

    /**
     * The directory which contains the trust roots for the users.
     *
     * @var string
     */
    private $trustStoreDir;

    /**
     * The instance of the OpenID provider class.
     *
     * @var ProviderServer|null
     */
    private static $instance = null;


    /**
     * Retrieve the OpenID provider class.
     *
     * @return ProviderServer  The OpenID Provider class.
     */
    public static function getInstance(): ProviderServer
    {
        if (self::$instance === null) {
            self::$instance = new ProviderServer();
        }
        return self::$instance;
    }


    /**
     * The constructor for the OpenID provider class.
     *
     * Initializes and validates the configuration.
     */
    private function __construct()
    {
        $config = Configuration::getConfig('module_openidProvider.php');

        $this->authSource = new Auth\Simple($config->getString('auth'));
        $this->usernameAttribute = $config->getString('username_attribute');
        $this->authProc = ['authproc' => $config->getArray('authproc', [])];

        try {
            $store = new \Auth_OpenID_FileStore($config->getString('filestore'));
            $this->server = new \Auth_OpenID_Server($store, $this->getServerURL());
        } catch (\Exception $e) {
            throw $e;
        }

        $this->trustStoreDir = realpath($config->getString('filestore')) . '/truststore';
        if (!is_dir($this->trustStoreDir)) {
            $res = mkdir($this->trustStoreDir, 0777, true);
            if (!$res) {
                throw new Error\Exception('Failed to create directory: ' . $this->trustStoreDir);
            }
        }
    }


    /**
     * Retrieve the authentication source used by the OpenID Provider.
     *
     * @return \SimpleSAML\Auth\Simple  The authentication source.
     */
    public function getAuthSource(): \SimpleSAML\Auth\Simple
    {
        return $this->authSource;
    }


    /**
     * Retrieve the current user ID.
     *
     * @return string|null  The current user ID, or NULL if the user isn't authenticated.
     */
    public function getUserId(): ?string
    {
        if (!$this->authSource->isAuthenticated()) {
            return null;
        }

        $attributes = $this->authSource->getAttributes();
        if (!array_key_exists($this->usernameAttribute, $attributes)) {
            throw new Error\Exception('Missing username attribute ' .
                var_export($this->usernameAttribute, true) . ' in the attributes of the user.');
        }

        $values = array_values($attributes[$this->usernameAttribute]);
        if (empty($values)) {
            throw new Error\Exception('Username attribute was empty.');
        }
        if (count($values) > 1) {
            throw new Error\Exception('More than one attribute value in username.');
        }

        return $values[0];
    }


    /**
     * Retrieve the current identity.
     *
     * @return string|null  The current identity, or NULL if the user isn't authenticated.
     */
    public function getIdentity(): ?string
    {
        $userId = $this->getUserId();
        if ($userId === null) {
            return null;
        }

        return Module::getModuleURL('openidProvider/user.php/' . $userId);
    }


    /**
     * Retrieve the URL of the server.
     *
     * @return string  The URL of the OpenID server.
     */
    public function getServerURL(): string
    {
        return Module::getModuleURL('openidProvider/server.php');
    }


    /**
     * Get the file that contains the trust roots for the user.
     *
     * @param string $identity  The identity of the user.
     * @return string  The file name.
     */
    private function getTrustFile(string $identity): string
    {
        return $this->trustStoreDir . '/' . sha1($identity) . '.serialized';
    }


    /**
     * Get the sites the user trusts.
     *
     * @param string $identity  The identity of the user.
     * @param array $trustRoots  The trust roots the user trusts.
     * @return void
     */
    public function saveTrustRoots(string $identity, array $trustRoots): void
    {
        $file = $this->getTrustFile($identity);
        $tmpFile = $file . '.new.' . getmypid();

        $data = serialize($trustRoots);

        $ok = file_put_contents($tmpFile, $data);
        if ($ok === false) {
            throw new Error\Exception('Failed to save file ' . var_export($tmpFile, true));
        }

        $ok = rename($tmpFile, $file);
        if ($ok === false) {
            throw new Error\Exception('Failed rename ' . var_export($tmpFile, true) .
                ' to ' . var_export($file, true) . '.');
        }
    }


    /**
     * Get the sites the user trusts.
     *
     * @param string $identity  The identity of the user.
     * @return array  The trust roots the user trusts.
     */
    public function getTrustRoots(string $identity): array
    {
        $file = $this->getTrustFile($identity);

        if (!file_exists($file)) {
            return [];
        }

        $data = file_get_contents($file);
        if ($data === false) {
            throw new Error\Exception('Failed to load file ' . var_export($file, true) . '.');
        }

        $data = unserialize($data);
        if ($data === false) {
            throw new Error\Exception('Error unserializing trust roots from file ' . var_export($file, true) . '.');
        }

        return $data;
    }


    /**
     * Add the given trust root to the user.
     *
     * @param string $identity  The identity of the user.
     * @param string $trustRoot  The trust root.
     * @return void
     */
    public function addTrustRoot(string $identity, string $trustRoot): void
    {
        $trs = $this->getTrustRoots($identity);
        if (!in_array($trustRoot, $trs, true)) {
            $trs[] = $trustRoot;
        }

        $this->saveTrustRoots($identity, $trs);
    }


    /**
     * Remove the given trust root from the trust list of the user.
     *
     * @param string $identity  The identity of the user.
     * @param string $trustRoot  The trust root.
     * @return void
     */
    public function removeTrustRoot(string $identity, string $trustRoot): void
    {
        $trs = $this->getTrustRoots($identity);

        $i = array_search($trustRoot, $trs, true);
        if ($i === false) {
            return;
        }
        array_splice($trs, $i, 1, []);
        $this->saveTrustRoots($identity, $trs);
    }


    /**
     * Is the given trust root trusted by the user?
     *
     * @param string $identity  The identity of the user.
     * @param string $trustRoot  The trust root.
     * @return bool TRUE if it is trusted, FALSE if not.
     */
    private function isTrusted(string $identity, string $trustRoot): bool
    {
        $trs = $this->getTrustRoots($identity);
        return in_array($trustRoot, $trs, true);
    }


    /**
     * Save the state, and return a URL that can contain a reference to the state.
     *
     * @param string $page  The name of the page.
     * @param array $state  The state array.
     * @return string  A URL with the state ID as a parameter.
     */
    private function getStateURL(string $page, array $state): string
    {
        $stateId = Auth\State::saveState($state, 'openidProvider:resumeState');
        $stateURL = Module::getModuleURL('openidProvider/' . $page);
        return Utils\HTTP::addURLParameters($stateURL, ['StateID' => $stateId]);
    }


    /**
     * Retrieve state by ID.
     *
     * @param string $stateId  The state ID.
     * @return array|null  The state array.
     */
    public function loadState(string $stateId): ?array
    {
        return Auth\State::loadState($stateId, 'openidProvider:resumeState');
    }


    /**
     * Send an OpenID response.
     *
     * This function never returns.
     *
     * @param \Auth_OpenID_ServerResponse $response  The response.
     * @return void
     */
    private function sendResponse(\Auth_OpenID_ServerResponse $response): void
    {
        Logger::debug('openidProvider::sendResponse');

        $webresponse = $this->server->encodeResponse($response);

        if ($webresponse->code !== 200) {
            header('HTTP/1.1 ' . $webresponse->code, true, $webresponse->code);
        }

        foreach ($webresponse->headers as $k => $v) {
            header($k . ': ' . $v);
        }
        header('Connection: Close');

        print($webresponse->body);
        exit(0);
    }


    /**
     * Process a request.
     *
     * This function never returns.
     *
     * @param array $state
     * @return void
     */
    public function processRequest(array $state): void
    {
        assert(isset($state["request"]));

        $request = $state['request'];

        $sreg_req = \Auth_OpenID_SRegRequest::fromOpenIDRequest($request);
        $ax_req = \Auth_OpenID_AX_FetchRequest::fromOpenIDRequest($request);

        /* In resume.php there should be a way to display data requested through sreg or ax. */

        if (!$this->authSource->isAuthenticated()) {
            if ($request->immediate) {
                /* Not logged in, and we cannot show a login form. */
                $this->sendResponse($request->answer(false));
            }

            $resumeURL = $this->getStateURL('resume.php', $state);
            $this->authSource->requireAuth(['ReturnTo' => $resumeURL]);
        }

        $identity = $this->getIdentity();
        assert($identity !== false); /* Should always be logged in here. */

        if (!$request->idSelect() && $identity !== $request->identity) {
            /* The identity in the request doesn't match the one of the logged in user. */
            throw new Error\Exception('Logged in as different user than the one requested.');
        }

        if ($this->isTrusted($identity, $request->trust_root)) {
            $trusted = true;
        } elseif (isset($state['TrustResponse'])) {
            $trusted = (bool)$state['TrustResponse'];
        } else {
            if ($request->immediate) {
                /* Not trusted, and we cannot show a trust-form. */
                $this->sendResponse($request->answer(false));
            }

            $trustURL = $this->getStateURL('trust.php', $state);
            Utils\HTTP::redirectTrustedURL($trustURL);
        }

        if (!$trusted) {
            /* The user doesn't trust this site. */
            $this->sendResponse($request->answer(false));
        }

        $response = $request->answer(true, null, $identity);

        // Process attributes
        $attributes = $this->authSource->getAttributes();
        foreach ($attributes as $key => $attr) {
            if (is_array($attr) && count($attr) === 1) {
                $attributes[$key] = $attr[0];
            }
        }

        $pc = new Auth\ProcessingChain($this->authProc, [], 'idp');
        $state = [
            'Attributes' => $attributes,
            'isPassive' => true
        ];

        $pc->processStatePassive($state);
        $attributes = $state['Attributes'];

        // Process SREG requests
        $sreg_resp = \Auth_OpenID_SRegResponse::extractResponse($sreg_req, $attributes);
        $sreg_resp->toMessage($response->fields);

        // Process AX requests
        if (!\Auth_OpenID_AX::isError($ax_req)) {
            $ax_resp = new \Auth_OpenID_AX_FetchResponse();
            foreach ($ax_req->iterTypes() as $type_uri) {
                if (isset($attributes[$type_uri])) {
                    $ax_resp->addValue($type_uri, $attributes[$type_uri]);
                }
            }
            $ax_resp->toMessage($response->fields);
        }

        /* The user is authenticated, and trusts this site. */
        $this->sendResponse($response);
    }


    /**
     * Receive an incoming request.
     *
     * This function never returns.
     * @return void
     */
    public function receiveRequest(): void
    {
        $request = $this->server->decodeRequest();

        if (!in_array($request->mode, ['checkid_immediate', 'checkid_setup'], true)) {
            $this->sendResponse($this->server->handleRequest($request));
        }

        $state = [
            'request' => $request,
        ];

        $this->processRequest($state);
    }
}
