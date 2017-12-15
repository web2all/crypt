<?php

/**
 * Web2All Crypt PassGen Algorithm interface
 *
 * This interface needs to be implemented by all algorithms
 * usable bu the Web2All_Crypt_PassGen.
 * 
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2017 Web2All B.V.
 * @since 2017-04-26
 */
interface Web2All_Crypt_PassGen_IAlgorithm {
  
  /**
   * Initialize algorithm with configuration array
   * 
   * @param array $settings
   */
  public function init($settings);
  
  /**
   * Return a string which will be used in a password
   * 
   * @return string
   */
  public function generate();
  
}

?>