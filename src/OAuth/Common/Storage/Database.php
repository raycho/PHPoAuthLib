<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;
use Predis\Client as Predis;

/*
 * Stores a token in a Redis server. Requires the Predis library available at https://github.com/nrk/predis
 */
class Database implements TokenStorageInterface
{
  /**
   * @var string
   */
  protected $key;

  protected $stateKey;

  /**
   * @var object|\Symfony\Component\Security\Core\User\
   */
  protected $user;

  /**
   * @param Predis $redis An instantiated and connected redis client
   * @param string $key The key to store the token under in redis
   * @param string $stateKey The key to store the state under in redis.
   */
  public function __construct(\User $user, $key, $stateKey)
  {
    $this->user = $user;
    $this->key = $key;
    $this->stateKey = $stateKey;
  }

  /**
   * {@inheritDoc}
   */
  public function retrieveAccessToken($service)
  {
    if (!$this->hasAccessToken($service)) {
      throw new TokenNotFoundException('Token not found in database');
    }

    $val = unserialize($this->user->__get($this->key));

    return $val;
  }

  /**
   * {@inheritDoc}
   */
  public function storeAccessToken($service, TokenInterface $token)
  {
    // (over)write the token
    $this->user->__set($this->key, serialize($token));
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function hasAccessToken($service)
  {
    if (!empty($this->user->__get($this->key))) {
      return true;
    }

    return false;
  }

  /**
   * {@inheritDoc}
   */
  public function clearToken($service)
  {
    $this->user->__set($this->key, '');
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function clearAllTokens()
  {
    $this->user->__set($this->key, '');
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function retrieveAuthorizationState($service)
  {
    if (!$this->hasAuthorizationState($service)) {
      throw new AuthorizationStateNotFoundException('State not found in database');
    }

    $val = $this->user->__get($this->stateKey);

    return $val;
  }

  /**
   * {@inheritDoc}
   */
  public function storeAuthorizationState($service, $state)
  {
    // (over)write the token
    $this->user->__set($this->stateKey, $state);
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function hasAuthorizationState($service)
  {
    if (!empty($this->user->__get($this->stateKey))) {
      return true;
    }

    return false;
  }

  /**
   * {@inheritDoc}
   */
  public function clearAuthorizationState($service)
  {
    $this->user->__set($this->stateKey, '');
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * {@inheritDoc}
   */
  public function clearAllAuthorizationStates()
  {
    $this->user->__set($this->stateKey, '');
    $this->user->save();

    // allow chaining
    return $this;
  }

  /**
   * @return Predis $redis
   */
  public function getUser()
  {
    return $this->user;
  }

  /**
   * @return string $key
   */
  public function getKey()
  {
    return $this->key;
  }
}
