<?php

Web2All_Manager_Main::loadClass('Web2All_Crypt_PassGen_IAlgorithm');

/**
 * Web2All Crypt PassGen RandomString Algorithm class
 * 
 * Generate random characters
 *
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2017 Web2All B.V.
 * @since 2017-04-26
 */
class Web2All_Crypt_PassGen_RandomStringAlgorithm extends Web2All_Manager_Plugin implements Web2All_Crypt_PassGen_IAlgorithm { 
  
  /**
   * Key generator
   *
   * @var Web2All_Crypt_KeyGen
   */
  protected $keygen;
  
  /**
   * How long should the random string be
   *
   * @var int
   */
  protected $string_length;
  
  /**
   * Constructor
   * 
   * @param Web2All_Manager_Main $web2all
   * @param int $length
   * @param string $chars  characters used in random string
   */
  public function __construct(Web2All_Manager_Main $web2all, $length=8, $chars=null)
  {
    parent::__construct($web2all);
    
    $this->string_length=$length;
    $this->keygen=$this->Web2All->Plugin->Web2All_Crypt_KeyGen();
    if(!is_null($chars)){
      $this->keygen->setKeyCharacters($chars);
    }
  }
  
  /**
   * Initialize algorithm with configuration array
   * 
   * @param array $settings
   */
  public function init($settings)
  {
    if(!is_array($settings)){
      return;
    }
    if(isset($settings['length'])){
      $this->string_length=$settings['length'];
    }
    if(isset($settings['chars'])){
      $this->keygen->setKeyCharacters($settings['chars']);
    }
  }
  
  /**
   * Return a string which will be used in a password
   * 
   * @return string
   */
  public function generate()
  {
    return $this->keygen->getRandomKeyStrong($this->string_length);
  }
}
?>