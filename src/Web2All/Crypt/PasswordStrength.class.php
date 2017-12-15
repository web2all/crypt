<?php

/**
 * Web2All Crypt PasswordStrength class
 * 
 * This class will help with analyzing the strength of a password.
 * 
 * Sample usage:
 *   $checker=$this->Web2All->Plugin->Web2All_Crypt_PasswordStrength();
 *   $checker->checkStrength('password');
 * 
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2014 Web2All BV
 * @since 2014-09-02 
 */
class Web2All_Crypt_PasswordStrength extends Web2All_Manager_Plugin {
  
  /**
   * STRENGTH_VERYWEAK: should never be used as a password
   * 
   * @var int
   */
  const STRENGTH_VERYWEAK     = 1;
  
  /**
   * STRENGTH_WEAK: only use for unimportant access. Do not use for things which should
   *                be secure in the future.
   * 
   * @var int
   */
  const STRENGTH_WEAK         = 2;
  
  /**
   * STRENGTH_ACCEPTABLE: reasonable safe password, but do not use for things which should
   *                      be secure in the future.
   * 
   * @var int
   */
  const STRENGTH_ACCEPTABLE   = 3;
  
  /**
   * STRENGTH_STRONG: strong password which will be secure even some years in the future.
   * 
   * @var int
   */
  const STRENGTH_STRONG       = 4;
  
  /**
   * STRENGTH_VERYSTRONG: very strong password which should be secure for a long time. It should 
   *                      even withstand an offline brute force attack.
   * 
   * @var int
   */
  const STRENGTH_VERYSTRONG       = 5;
  
  /**
   * constructor
   *
   * @param Web2All_Manager_Main $web2all
   */
  public function __construct(Web2All_Manager_Main $web2all) {
    parent::__construct($web2all);
    
  }
  
  /**
   * check password strength
   * 
   * Several things have influence on the password strength
   * - length
   * - variation of characters
   * - dictionary words
   * 
   * @param string $password
   * @return int
   */
  public function checkStrength($password)
  {
    $strength=self::STRENGTH_VERYWEAK;
    // analyze the password
    $password_length=strlen($password);
    // we check how many characters there are in each 'character class'
    $character_classes=array(
      'a-z',            // lowercase letters
      'A-Z',            // uppercase letters
      '0-9',            // numbers
      '\-_ ',           // word joiners
      '^a-zA-Z0-9\-_ '  // special characters
    );
    $character_classes_found=array();
    foreach($character_classes as $character_class){
      // we check in regex with negated class, so if negation exists already, remove it, or else add it
      if($character_class[0]=='^'){
        // negated, remove it
        $character_class_inverted=substr($character_class, 1);
      }else{
        $character_class_inverted='^'.$character_class;
      }
      $class_chars=preg_replace('/['.$character_class_inverted.']/','',$password);
      $class_chars_count=strlen($class_chars);
      if($class_chars_count>0){
        $character_classes_found[$character_class]=$class_chars_count;
      }
    }
    //error_log(print_r($character_classes_found,true));
    
    // now define the strength
    if(count($character_classes_found)==1){
      // only one type of character class found
      // this is very weak, unless the password is longer than 20 chars, in which case
      // we accept it as just weak
      if($password_length>=20){
        $strength=self::STRENGTH_WEAK;
      }
    }elseif(count($character_classes_found)==2){
      // only two types of character class found
      // this is very weak, unless the password is longer than 12 chars, in which case
      // we accept it as just weak
      if($password_length>=12){
        $strength=self::STRENGTH_WEAK;
      }
      // we might even classify it acceptable, but only if it is very long and each 
      // character class is used
      if($password_length>=22){
        if($this->minimumCharactersInClass($character_classes_found, 7)){
          $strength=self::STRENGTH_ACCEPTABLE;
        }
      }
    }elseif(count($character_classes_found)==3){
      // three types of character class found
      // this is weak, if the password is longer than 7 chars
      if($password_length>=8){
        $strength=self::STRENGTH_WEAK;
      }
      // we might even classify it acceptable, but only if it is at least 10 characters
      // and we do not want passwords like: Jeroen1984
      if($password_length>=10){
        // to prevent this last case we want at least 2 characters in each class
        if($this->minimumCharactersInClass($character_classes_found, 2)){
          $strength=self::STRENGTH_ACCEPTABLE;
        }
      }
      // we might even classify it strong, but only if it is very long and each 
      // character class is used
      if($password_length>=22){
        if($this->minimumCharactersInClass($character_classes_found, 5)){
          $strength=self::STRENGTH_STRONG;
        }
      }
    }elseif(count($character_classes_found)>=4){
      // four types of character class found
      // this is weak, if the password is longer than 7 chars
      if($password_length>=8){
        $strength=self::STRENGTH_WEAK;
      }
      // this is acceptable, if the password is longer than 10 chars
      if($password_length>=10){
        $strength=self::STRENGTH_ACCEPTABLE;
      }
      // we might even classify it strong, but only if it is at least 15 characters
      // and if each class is used at least 2 chars
      if($password_length>=15){
        // to prevent this last case we want at least 2 characters in each class
        if($this->minimumCharactersInClass($character_classes_found, 2)){
          $strength=self::STRENGTH_STRONG;
        }
      }
      // we might even classify it very strong, but only if it is very long and each 
      // character class is used
      if($password_length>=22){
        if($this->minimumCharactersInClass($character_classes_found, 3)){
          $strength=self::STRENGTH_VERYSTRONG;
        }
      }
    }
    return $strength;
  }
  
  /**
   * Check if each character class has at least the minimum of characters used
   * 
   * @param array $character_classes_found
   * @param int $minimum
   * @return boolean
   */
  protected function minimumCharactersInClass($character_classes_found, $minimum){
    foreach($character_classes_found as $count){
      if($count<$minimum){
        return false;
      }
    }
    return true;
  }

}
?>