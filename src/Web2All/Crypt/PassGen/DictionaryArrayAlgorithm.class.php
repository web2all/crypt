<?php

Web2All_Manager_Main::loadClass('Web2All_Crypt_PassGen_IAlgorithm');

/**
 * Web2All Crypt PassGen DictionaryArray Algorithm class
 * 
 * Select string from a dictionary (php array)
 *
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2017 Web2All B.V.
 * @since 2017-04-28
 */
class Web2All_Crypt_PassGen_DictionaryArrayAlgorithm extends Web2All_Manager_Plugin implements Web2All_Crypt_PassGen_IAlgorithm { 
  
  /**
   * Key generator
   *
   * @var Web2All_Crypt_KeyGen
   */
  protected $keygen;
  
  /**
   * Dictionary
   *
   * @var string[]
   */
  protected $dictionary;
  
  /**
   * Amount of entries in the dictionary (do not exceed signed max int)
   *
   * @var int
   */
  protected $dictionary_size;
  
  /**
   * Constructor
   * 
   * @param Web2All_Manager_Main $web2all
   * @param string[] $dictionary
   */
  public function __construct(Web2All_Manager_Main $web2all, $dictionary=array('-'))
  {
    parent::__construct($web2all);
    
    $this->dictionary=array_values($dictionary);
    $this->dictionary_size=count($this->dictionary);
    $this->keygen=$this->Web2All->Plugin->Web2All_Crypt_KeyGen();
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
    if(isset($settings['dictionary']) && is_array($settings['dictionary'])){
      $this->dictionary=array_values($settings['dictionary']);
      $this->dictionary_size=count($this->dictionary);
    }
  }
  
  /**
   * Return a string which will be used in a password
   * 
   * @return string
   */
  public function generate()
  {
    $dictionary_entry=$this->keygen->getRandomNumber(0,$this->dictionary_size-1);
    return $this->dictionary[$dictionary_entry];
  }
}
?>