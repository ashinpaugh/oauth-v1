<?php

namespace Moop\Bundle\OAuthBundle\Util;


use Buzz\Browser;

/**
 * Generic oAuth utility built around Buzz.
 * 
 * @author Austin Shinpaugh
 */
class AuthConsumer
{
    /**
     * @var Browser
     */
    protected $client;
    
    /**
     * The token given to the oAuth consumer (application).
     * 
     * @var String
     */
    protected $consumer_key;
    
    /**
     * The secret given to the oAuth consumer (application).
     * 
     * @var String
     */
    protected $consumer_secret;
    
    /**
     * Token received by provider indicating access to
     * provider's user.
     * 
     * @var String
     */
    protected $oauth_token;
    
    /**
     * Validates the oauth token.
     * 
     * @var String
     */
    protected $oauth_token_secret;
    
    /**
     * @Construct
     * 
     * @param Browser $browser
     * @param String  $key
     * @param String  $secret
     */
    public function __construct(Browser $browser, $key = null, $secret = null)
    {
        $this->client          = $browser;
        $this->consumer_key    = $key;
        $this->consumer_secret = $secret;
    }
    
    /**
     * Make a request against the FatSecret APIs.
     * 
     * @param String $base_url
     * @param array  $params
     * @param string $method
     *
     * @return \Buzz\Message\MessageInterface
     */
    public function send($base_url, array $params = [], $method = 'GET')
    {
        if (!$this->isInitialized()) {
            throw new \ErrorException("The consumer key and secret must be set first.");
        }
        
        $params    = $this->parseParams($params);
        $signature = $this->getSignature($base_url, $params, $method);
        
        $params  = array_merge($params, ['oauth_signature' => $signature]);
        $api_url = $this->getAPIEndpoint($base_url, $method, $params);
        
        return $this->client->call($api_url, $method, [], $params);
    }
    
    /**
     * Retrieve the OAuth sig.
     * 
     * @param String   $base_url
     * @param String[] $params
     * @param String   $method
     *
     * @return string
     */
    protected function getSignature($base_url, $params, $method)
    {
        $sig_base   = $this->getSignatureBase($base_url, $method, $params);
        $sig_secret = $this->consumer_secret . '&' . $this->oauth_token_secret;
        
        return base64_encode(hash_hmac('sha1', $sig_base, $sig_secret, true));
    }
    
    /**
     * Build the Signature Base string that's used to encrypt the OAuth
     * Consumer Secret Key and Access Token Secret.
     * 
     * @param String   $base_url
     * @param String   $method
     * @param String[] $params
     *
     * @return string
     */
    protected function getSignatureBase($base_url, $method, array $params)
    {
        $normalized_url    = $base_url;
        $normalized_params = http_build_query($params, null, '&', PHP_QUERY_RFC3986);
        
        return strtoupper($method)
            . '&' . rawurlencode($normalized_url)
            . '&' . rawurlencode($normalized_params)
        ;
    }
    
    /**
     * Parses the input for token related parameters, merges the OAuth
     * Signature parameters, and returns the sorted results.
     *
     * @param array $params
     *
     * @return array
     */
    protected function parseParams(array $params)
    {
        if (array_key_exists('oauth_token', $params)) {
            $this->oauth_token = $params['oauth_token'];
        }
        
        if (array_key_exists('oauth_token_secret', $params)) {
            $this->oauth_token_secret = $params['oauth_token_secret'];
            unset($params['oauth_token_secret']);
        }
        
        $params = array_merge($this->getOAuthParams(), $params);
        
        return ksort($params) ? $params : [];
    }
    
    /**
     * Returns a list of OAuth params used to security verify.
     * 
     * @return array
     */
    protected function getOAuthParams()
    {
        return array_filter([
            'oauth_token'            => $this->oauth_token,
            'oauth_consumer_key'     => $this->consumer_key,
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp'        => time(),
            'oauth_nonce'            => md5(uniqid()),
            'oauth_version'          => '1.0',
        ]);
    }
    
    /**
     * Appends the parameters to the request query if we're using GET, otherwise
     * send the parameters in the request body.
     * 
     * @param String   $url
     * @param String   $method
     * @param String[] $params
     *
     * @return string
     */
    protected function getAPIEndpoint($url, $method, array $params)
    {
        if ('GET' !== strtoupper($method)) {
            return $url;
        }
        
        return "{$url}?" . http_build_query($params, null, '&', PHP_QUERY_RFC3986);
    }
    
    /**
     * Set method for setting the oAuth consumer secret.
     * 
     * @param String $key
     *
     * @return $this
     * @throws \ErrorException
     */
    public function setConsumerKey($key)
    {
        if (!$key || !is_string($key)) {
            throw new \ErrorException("The consumer key must be a string.");
        }
        
        $this->consumer_key = $key;
        return $this;
    }
    
    /**
     * Set method for setting the oAuth consumer secret.
     * 
     * @param String $secret
     *
     * @return $this
     * @throws \ErrorException
     */
    public function setConsumerSecret($secret)
    {
        if (!$secret || !is_string($secret)) {
            throw new \ErrorException("The consumer secret must be a string.");
        }
        
        $this->consumer_secret = $secret;
        return $this;
    }
    
    /**
     * @return Browser
     */
    public function getHttpClient()
    {
        return $this->client;
    }
    
    /**
     * @return String
     */
    public function getOAuthToken()
    {
        return $this->oauth_token;
    }
    
    /**
     * @param String $oauth_token
     *
     * @return AuthConsumer
     */
    public function setOAuthToken($oauth_token)
    {
        $this->oauth_token = $oauth_token;
        
        return $this;
    }
    
    /**
     * @return String
     */
    public function getOAuthTokenSecret()
    {
        return $this->oauth_token_secret;
    }
    
    /**
     * @param String $oauth_token_secret
     *
     * @return AuthConsumer
     */
    public function setOAuthTokenSecret($oauth_token_secret)
    {
        $this->oauth_token_secret = $oauth_token_secret;
        return $this;
    }
    
    /**
     * @return bool
     */
    protected function isInitialized()
    {
        return !empty($this->consumer_key) && !empty($this->consumer_secret);
    }
}