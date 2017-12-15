<?php

Web2All_Manager_Main::loadClass('Web2All_Crypt_PassGen_IAlgorithm');

/**
 * Web2All Crypt PassGen DictionaryFile Algorithm class
 * 
 * Select string from a dictionary file. It must have one word for each line.
 * Whitespace in front and after the word is ignored and empty lines are not
 * supported.
 *
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2017 Web2All B.V.
 * @since 2017-04-28
 */
class Web2All_Crypt_PassGen_DictionaryFileAlgorithm extends Web2All_Manager_Plugin implements Web2All_Crypt_PassGen_IAlgorithm { 
  
  /**
   * constant CASING_LOWER
   * 
   * Make the chosen dictionary word lowercase
   *
   * @var int
   */
  const CASING_LOWER = 1;
  
  /**
   * constant CASING_UPPER
   * 
   * Make the chosen dictionary word uppercase
   *
   * @var int
   */
  const CASING_UPPER = 2;
  
  /**
   * constant CASING_FIRST
   * 
   * Make the chosen dictionary word lowercase and the first letter uppercase
   *
   * @var int
   */
  const CASING_FIRST = 4;
  
  /**
   * constant CASING_ALL
   * 
   * Enable all casing options
   *
   * @var int
   */
  const CASING_ALL = 7;
  
  /**
   * Key generator
   *
   * @var Web2All_Crypt_KeyGen
   */
  protected $keygen;
  
  /**
   * Dictionary
   *
   * @var string
   */
  protected $dictionary_file;
  
  /**
   * Amount of entries in the dictionary (do not exceed signed max int)
   *
   * @var int
   */
  protected $dictionary_size;
  
  /**
   * Bitmask of used casing options
   *
   * @var int
   */
  protected $casing_options = self::CASING_LOWER;
  
  /**
   * How many casing options are in use
   * 
   * Caching this so we don't need to re-calculate it every time
   *
   * @var int
   */
  protected $casing_options_count = 1;
  
  /**
   * Constructor
   * 
   * @param Web2All_Manager_Main $web2all
   * @param string $dictionary_file  full path to file
   */
  public function __construct(Web2All_Manager_Main $web2all, $dictionary_file=null)
  {
    parent::__construct($web2all);
    
    $this->dictionary_file=$dictionary_file;
    $this->dictionary_size=null;
    if(!is_null($this->dictionary_file)){
      $this->dictionary_size=self::countDictionaryEntries($this->dictionary_file);
    }
    $this->keygen=$this->Web2All->Plugin->Web2All_Crypt_KeyGen();
  }
  
  /**
   * Initialize algorithm with configuration array
   * 
   * Supported configuration keys:
   * - dictionary: (string) full path to dictionary file (one word for each line)
   * - casing: (int) bitmask, what casing to use on the selected word, see CASING_* class constants
   * 
   * @param array $settings
   * @thows Exception
   */
  public function init($settings)
  {
    if(!is_array($settings)){
      return;
    }
    if(isset($settings['dictionary'])){
      $this->dictionary_file=$settings['dictionary'];
      $this->dictionary_size=self::countDictionaryEntries($this->dictionary_file);
    }
    if(isset($settings['casing'])){
      if(!($settings['casing'] & self::CASING_ALL)){
        // there should be at least one casing option set
        throw new Exception('DictionaryFileAlgorithm: invalid "casing" setting');
      }
      // set only supported options
      $this->casing_options=($settings['casing'] & self::CASING_ALL);
      // count active casing options
      $this->casing_options_count=0;
      // set option_mask to the highest available option bit
      $option_mask=(self::CASING_ALL+1)/2;
      // and count the set bits (by shifting through each possible option)
      do{
        if($option_mask & $this->casing_options){
          $this->casing_options_count++;
        }
      }while($option_mask = $option_mask >> 1);
    }
  }
  
  /**
   * Count and validate the entries in the dictionary
   * 
   * Will throw exceptions if the dictionary file is not perfect
   * 
   * @param array $settings
   * @thows Exception
   */
  public static function countDictionaryEntries($dictionary_file)
  {
    if(!is_readable($dictionary_file)){
      // cannot read file
      throw new Exception('DictionaryFileAlgorithm: dictionary not readable file');
    }
    $handle = fopen($dictionary_file, "r");
    $wordcount=0;
    if ($handle) {
      while (($word = fgets($handle)) !== false) {
        // test for empty lines (we don't want that)
        if(trim($word)==""){
          // line contains only whitespace
          throw new Exception('DictionaryFileAlgorithm: dictionary file has empty lines');
        }
        $wordcount++;
      }
      if (!feof($handle)) {
        throw new Exception('DictionaryFileAlgorithm: unknown error while reading dictionary file');
      }
      fclose($handle);
    }else{
      throw new Exception('DictionaryFileAlgorithm: could not open dictionary file');
    }
    return $wordcount;
  }
  
  /**
   * Locate a specific entry in the dictionary
   * 
   * Will throw exceptions if something is wrong
   * 
   * @param array $settings
   * @thows Exception
   */
  public static function findDictionaryEntry($dictionary_file,$index)
  {
    if(!is_readable($dictionary_file)){
      // cannot read file
      throw new Exception('DictionaryFileAlgorithm: dictionary not readable file');
    }
    $handle = fopen($dictionary_file, "r");
    $wordcount=0;
    if ($handle) {
      while (($word = fgets($handle)) !== false) {
        if($index==$wordcount){
          // found
          fclose($handle);
          return trim($word);
        }
        $wordcount++;
      }
      fclose($handle);
      throw new Exception('DictionaryFileAlgorithm: could not find entry in dictionary file, not enough entries');
    }else{
      throw new Exception('DictionaryFileAlgorithm: could not open dictionary file');
    }
  }
  
  /**
   * Return a string which will be used in a password
   * 
   * Will throw exceptions if the dictionary is not configured
   * 
   * @return string
   * @thows Exception
   */
  public function generate()
  {
    if(is_null($this->dictionary_file)){
      throw new Exception('DictionaryFileAlgorithm: dictionary not configured');
    }
    if(!$this->dictionary_size){
      throw new Exception('DictionaryFileAlgorithm: dictionary is empty');
    }
    // get a random word from the dictionary
    $dictionary_entry=$this->keygen->getRandomNumber(0,$this->dictionary_size-1);
    $dictionary_word=self::findDictionaryEntry($this->dictionary_file,$dictionary_entry);
    // possibly apply casing to the selected word
    if($this->casing_options_count>1){
      $casing_method_index=$this->keygen->getRandomNumber(1,$this->casing_options_count);
    }else{
      $casing_method_index=1;
    }
    // set option_mask to the highest available option bit
    $option_mask=(self::CASING_ALL+1)/2;
    $i=1;
    $casing_method=0;
    // for each casing option (starting from the highest number)
    do{
      // check if the option is set
      if($option_mask & $this->casing_options){
        // and if it is set, check if it matches our random method
        if($i==$casing_method_index){
          // this is the one
          $casing_method=$option_mask;
          break;
        }else{
          // not this one, but we continue checking for the next
          $i++;
        }
      }
    }while($option_mask = $option_mask >> 1);
    // apply casing
    switch($casing_method){
      case self::CASING_LOWER:
        $dictionary_word=strtolower($dictionary_word);
        break;
      case self::CASING_UPPER:
        $dictionary_word=strtoupper($dictionary_word);
        break;
      case self::CASING_FIRST:
        $dictionary_word=ucfirst($dictionary_word);
        break;
      default:
        // should not be possible
        trigger_error('DictionaryFileAlgorithm: unknown casing method: '.$casing_method, E_USER_NOTICE);
        break;
    }
    // done, return the word with casing applied
    return $dictionary_word;
  }
}
?>