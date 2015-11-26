<?php
/**
 * Intuit service.
 *
 * @author  Rachel Cheng <raychomp@gmail.com>
 */

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Vimeo service.
 *
 * @author  Pedro Amorim <contact@pamorim.fr>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link    https://developer.vimeo.com/
 * @link    https://developer.vimeo.com/api/authentication
 */
class Intuit extends AbstractService
{
    // API version
    const VERSION = '3';
    const NONCE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct(
            $credentials,
            $httpClient,
            $storage,
            $scopes,
            $baseApiUri,
            true
        );

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://sandbox-quickbooks.api.intuit.com/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://appcenter.intuit.com/Connect/Begin');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://oauth.intuit.com/oauth/v1/get_access_token');
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenEndpoint()
    {
        return new Uri('https://oauth.intuit.com/oauth/v1/get_request_token');
    }

    protected function _nonce($len = 5) 
    {
        
        $tmp = str_split(Intuit::NONCE);
        shuffle($tmp);
        
        return substr(implode('', $tmp), 0, $len);
    }

    /**
     * {@inheritdoc}
     */
    public function requestAccessToken($code = '', $state = null)
    {
        if (null !== $state) {
            $this->validateAuthorizationState($state);
        }

        $bodyParams = array(
            'oauth_callback'            => urlencode('http://www.oe.dev/intuit/authorize'),
            'oauth_consumer_key'        => $this->credentials->getConsumerId(),
            'oauth_nonce'               => $this->_nonce(),
            'oauth_signature_method'    => 'HMAC-SHA1',
            'oauth_timestamp'           => time(),
            'oauth_version'             => '1.0'
        );

        $queryParams = http_build_query($bodyParams);
        $signatureBase = 'GET&'.urlencode($this->getRequestTokenEndpoint()).'&'.urlencode($queryParams);
        $key = $this->credentials->getConsumerSecret().'&';
        $signature = hash_hmac("sha1", $signatureBase, $key, true);
        $signature = base64_encode($signature);
        $url = $this->getRequestTokenEndpoint()."?".$queryParams.'&oauth_signature='.$signature;
        $uri = new Uri($url);

        $responseBody = $this->httpClient->retrieveResponse(
            $uri,
            [],
            [],
            'GET'
        );

        $parsedResult = array();
        parse_str($responseBody, $parsedResult);

        $token = $this->parseAccessTokenResponse(json_encode($parsedResult));
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    public function getAccessToken($realmId, $oauthToken, $oauthVerifier)
    {
        $uri = new Uri($this->getAccessTokenEndpoint());
        $responseBody = $this->httpClient->retrieveResponse(
            $uri,
            [],
            [],
            'GET'
        );

        // save oauth stuff
        dd($responseBody);
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error_description'])) {
            throw new TokenResponseException(
                'Error in retrieving token: "' . $data['error_description'] . '"'
            );
        } elseif (isset($data['error'])) {
            throw new TokenResponseException(
                'Error in retrieving token: "' . $data['error'] . '"'
            );
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['oauth_token']);

        if (isset($data['expires_in'])) {
            $token->setLifeTime($data['expires_in']);
            unset($data['expires_in']);
        }
        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['oauth_token']);

        $token->setExtraParams($data);

        return $token;
    }

    public function getAuthorizationUrl($token, $callback)
    {
        return $this->getAuthorizationEndpoint().'?oauth_token='.$token->getAccessToken()."&oauth_callback=".$callback;
    }
}
