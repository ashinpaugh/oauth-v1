<?php

namespace Moop\Bundle\OAuthBundle\Decorator;

use Moop\Bundle\OAuthBundle\Entity\OAuthProvider;
use Moop\Bundle\OAuthBundle\Entity\OAuthToken;

/**
 * An OAuth interface for User objects.
 * 
 * @author Austin Shinpaugh
 */
interface oAuthConsumerInterface
{
    /**
     * Get the OAuth token.
     * 
     * @return OAuthToken[]
     */
    public function getOAuthTokens();
    
    /**
     * Get the OAuth token.
     * 
     * @param mixed $provider
     * 
     * @return OAuthToken
     */
    public function getOAuthToken($provider);
    
    /**
     * Set the OAuth token.
     * 
     * @param OAuthProvider $provider
     * @param String        $token
     * @param String        $secret
     * 
     * @return $this
     */
    public function addOAuthToken(OAuthProvider $provider, $token, $secret);
    
    /**
     * Remove a token that's associated with a user.
     * 
     * @param OAuthToken $token
     * 
     * @return $this
     */
    public function removeOAuthToken(OAuthToken $token);
}