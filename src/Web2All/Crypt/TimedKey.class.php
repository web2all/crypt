<?php

/**
 * Web2All Timed Key class
 * 
 * This class manages time based keys. The generated keys should be difficult
 * guessable and should be time limited.
 *
 * Main usage would be inclusion in forms which need to be protected from
 * bots/scripts.
 * Its by no means a total/secure solution but it should it make more difficult
 * for simple bots to succeed.
 * 
 * Do not use this class to generate keys which require high security. The 
 * generated keys can be guessed if the attacker knows the algorithm. Can be 
 * made slightly more difficult to guess by implementing real encryption like
 * Rijndael in CBC mode (only hashes implemented atm).
 * 
 * The idea behind this class is to construct a key which can be reconstructed 
 * without the need to store the key between requests. This eliminates the need 
 * to store it in the session or database. Offcource this makes it pretty weak
 * against a focussed attack, but its not intended for high security anyway.
 * 
 * Sample usage:
 *   $timedkeygen=$web2all->Plugin->Web2All_Crypt_TimedKey('kla83hdaklsas912');
 *   $timedkey=$timedkeygen->generateKey($web2all->getIP());
 *   // assign $timedkey to a form and on submit, check it again
 *   if(!$timedkeygen->validateKey($_POST['timedkey'],$web2all->getIP())){
 *     // it was a bot
 *   }
 * 
 * Note:
 *   Default encryption is SHA1 and the key is valid for 2-3 hours.
 * 
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2008 Web2All BV
 * @since 2008-09-09 
 */
class Web2All_Crypt_TimedKey extends Web2All_Manager_Plugin {
  
  protected $salt;
  
  /**
   * constructor
   *
   * @param Web2All_Manager_Main $web2all
   * @param string $salt  any random string
   */
  public function __construct(Web2All_Manager_Main $web2all,$salt='') {
    parent::__construct($web2all);
    
    // load config
    $defaultconfig=array(
      'ENCRYPTION_TYPE' => 'SHA1',
      'DEFAULT_SALT' => $salt,
      'BASE64_ENCODED_KEYS' => false,
      'TIMED_WINDOW_SECS' => 3600
    );
    
    $this->config=$this->Web2All->Config->makeConfig('Web2All_Crypt_TimedKey',$defaultconfig);
    
    $this->salt=$this->config['DEFAULT_SALT'];
    
  }
  
  /**
   * Generate a timed key
   *
   * @param string $extradata  [optional you can provide some extra data to include in the key]
   * @return string
   */
  public function generateKey($extradata='')
  {
    $key='';
    switch ($this->config['ENCRYPTION_TYPE']) {
      case 'SHA1':
        $key=sha1($this->salt . $this->getLastWindow() . $extradata);
        break;
      case 'MD5':
        $key=md5($this->salt . $this->getLastWindow() . $extradata);
        break;
      case 'CBC':
        // not yet implemented
      default:
        throw new Exception( 'Web2All_Crypt_TimedKey->generateKey: unknown ENCRYPTION_TYPE "'.$this->config['ENCRYPTION_TYPE'].'"' );
        break;
    }
    if($this->config['BASE64_ENCODED_KEYS']){
      $key=base64_encode($key);
    }
    return $key;
  }
  
  
  /**
   * validate a timed key
   *
   * @param string $key
   * @param string $extradata  [optional you can provide some extra data which was included in the key]
   * @param int $windowcount  [optional you can check [n] windows in the past]
   * @return boolean
   */
  public function validateKey($key,$extradata='',$windowcount=3)
  {
    if($this->config['BASE64_ENCODED_KEYS']){
      $key=base64_decode($key);
    }
    $lastwindow=$this->getLastWindow();
    // for each window we have to check
    for($i=0;$i<$windowcount;$i++){
      $window=$lastwindow-($this->config['TIMED_WINDOW_SECS']*$i);
      switch ($this->config['ENCRYPTION_TYPE']) {
        case 'SHA1':
          $testkey=sha1($this->salt . $window . $extradata);
          break;
        case 'MD5':
          $testkey=md5($this->salt . $window . $extradata);
          break;
        case 'CBC':
          // not yet implemented
          // in future allow mcrypt encryptions.
        default:
          throw new Exception( 'Web2All_Crypt_TimedKey->validateKey: unknown ENCRYPTION_TYPE "'.$this->config['ENCRYPTION_TYPE'].'"' );
          break;
      }
      if($testkey==$key){
        // key matches
        return true;
      }
    }
    return false;
  }
  
  /**
   * Get the start of our last window
   *
   * @return int
   */
  protected function getLastWindow()
  {
    $current_stamp=time();
    // get the start of our last window.
    $last_window=floor($current_stamp/$this->config['TIMED_WINDOW_SECS'])*$this->config['TIMED_WINDOW_SECS'];
    return $last_window;
  }
  
}
?>