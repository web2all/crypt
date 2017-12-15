<?php
/**
 * Key generating class
 * 
 * Contains methods to generate keys.
 * 
 * For secure keys use getRandomKeyStrong()
 * If getRandomKeyStrong() is used, then /dev/urandom must
 * exist and have a good random source.
 *
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2007-2009 Web2All B.V.
 * @since 2007-08-23
 */
class Web2All_Crypt_KeyGen extends Web2All_Manager_Plugin { 
  
  protected $key_characters = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  protected $num_key_characters = 62;
  
  /**
   * Generates a string whith length random chars
   * 
   * This method uses the PHP mt_rand() function which
   * is too predictable for cryptographic use.
   * 
   * If you need a truly unpredictable key use
   * the method getRandomKeyStrong() instead.
   *
   * @param int $length  optional length of key, defaults to 40
   * @return string
   */
  public function getRandomKey($length=40) {
    $key = "";
    for($i=0;$i<$length;$i++) {
      $key .= $this->key_characters{mt_rand(0,$this->num_key_characters-1)};
    }
    return $key;
  }
  
  /**
   * Get a number of random bytes
   * 
   * This function needs the /dev/urandom device and will
   * thrown an exception when it cannot read it.
   *
   * @param int $length  optional amount of random bytes, defaults to 1
   * @return string  binary random bytes
   */
  public function getRandomBytes($length=1)
  {
    if (is_readable('/dev/urandom')) {
      $fp = fopen('/dev/urandom','rb');
      if ($fp !== false) {
        $random_bytes = @fread($fp, $length);
        fclose($fp);
        return $random_bytes;
      } else {
        throw new Exception('Web2All_Crypt_KeyGen::getRandomBytes(): error reading /dev/urandom');
      }
    }else{
      throw new Exception('Web2All_Crypt_KeyGen::getRandomBytes(): no /dev/urandom or not enough permissions');
    }
  }
  
  /**
   * Generates a string whith length random chars
   *
   * @param int $length  optional length of key, defaults to 40
   * @return string
   */
  public function getRandomKeyStrong($length=40) {
    $key = "";
    $numbers=$this->getRandomNumbersBaseX($this->num_key_characters,$length);
    foreach ($numbers as $num) {
      $key .= $this->key_characters{$num};
    }
    return $key;
  }
  
  /**
   * Get an array with random numbers in the range 0 to $base
   *
   * @param int $base
   * @param int $amount  amount of numbers returned
   * @return int[]  returns an array of integers
   */
  public function getRandomNumbersBaseX($base,$amount)
  {
    // we get random data from urandom to seed the pseudo random number generator
    // every 10 characters we re-seed with random data
    
    // how much random data do we need? we need 4 bytes for each seed.
    $reseed_every_x=30;
    $byte_chunks=4;// bytes needed for seed (int)
    
    $bytesneeded=(ceil($amount/$reseed_every_x)+1)*$byte_chunks;// and add an extra seed to reset after we are done
    $binarystring=$this->getRandomBytes($bytesneeded);
    
    $result=array();
    $resultcount=0;
    
    $last=false;
    // loop untill we have have enough numbers
    while (!$last) {
      
      if(!($resultcount<$amount)){
        $last=true;
      }
      if(($resultcount % $reseed_every_x)==0 || $last){
        // reseed
        assert('$binarystring!==""');//not enough random data for seed
        // get 4 random bytes for the seed
        $binarysubstr=substr($binarystring,0,$byte_chunks);// get 4 bytes
        $binarystring=substr($binarystring,$byte_chunks);// shrink our binary string by 4 bytes
        if ($binarystring===false) {
          // no more random data now
          $binarystring='';
        }
        
        // turn the $byte_chunks byte string into a decimal number (signed)
        $decimal = ord($binarysubstr{0});
        for ($chunk=1;$chunk<$byte_chunks;$chunk++){
          $decimal |= (ord($binarysubstr{$chunk})<<($chunk*8));
        }
        mt_srand($decimal);//error_log('seeding '.sprintf("%032b",$decimal).' leftover: '.$binarystring);
        if($last){
          continue;
        }
      }
      
      $rand_num=mt_rand(0,$base-1);
      
      $result[]=$rand_num;
      $resultcount++;
      
    }// end of loop
    return $result;
  }
  
  /**
   * Set the characters used in keys to all numbers and upper and lowercase
   * alphabet (this is the default)
   *
   */
  public function setBase62Chars()
  {
    $this->key_characters='1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $this->num_key_characters=62;
  }
  
  /**
   * Set the characters used in keys to the characters used in base64 encoding
   *
   */
  public function setBase64Chars()
  {
    $this->key_characters='1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/+';
    $this->num_key_characters=64;
  }
  
  /**
   * Set the characters you want to be used in key generation
   * 
   * Note: do not use more than 16777215 chars
   *
   * @param string $chars
   */
  public function setKeyCharacters($chars)
  {
    $this->key_characters=$chars;
    $this->num_key_characters=strlen($chars);
  }
  
  /**
   * Get the characters to be used in key generation
   * 
   * @return string
   */
  public function getKeyCharacters($chars)
  {
    return $this->key_characters;
  }
  
  /**
   * Fetch a random integer between $min and $max inclusive
   * 
   * Taken from https://github.com/paragonie/random_compat/blob/master/lib/random_int.php
   * and modified to remove float support.
   *
   * @param int $min
   * @param int $max
   *
   * @throws Exception
   *
   * @return int
   */
  function getRandomNumber($min, $max)
  {
    if(!is_int($min)) {
      throw new Exception('getRandomNumber(): $min must be an integer');
    }
    if(!is_int($max)) {
      throw new Exception('getRandomNumber(): $max must be an integer');
    }
    
    // sane value of min - max
    if ($min > $max) {
      throw new Exception('getRandomNumber(): Minimum value must be less than or equal to the maximum value');
    }
    if ($max === $min) {
      return $min;
    }
    
    /*
     * Initialize variables to 0
     *
     * We want to store:
     * $bytes => the number of random bytes we need
     * $mask => an integer bitmask (for use with the &) operator
     *          so we can minimize the number of discards
     */
    $attempts = $bits = $bytes = $mask = $valueShift = 0;
    
    /*
     * At this point, $range is a positive number greater than 0. It might
     * overflow, however, if $max - $min > PHP_INT_MAX. PHP will cast it to
     * a float and we will lose some precision.
     */
    $range = $max - $min;
    
    /*
     * Test for integer overflow (should not be possible?)
     */
    if (!is_int($range)) {
      throw new Exception('getRandomNumber(): Range is too big');
    } else {
      /*
       * $bits is effectively ceil(log($range, 2)) without dealing with
       * type juggling
       */
      while ($range > 0) {
          if ($bits % 8 === 0) {
              ++$bytes;
          }
          ++$bits;
          $range >>= 1;
          $mask = $mask << 1 | 1;
      }
      $valueShift = $min;
    }
    
    $val = 0;
    /*
     * Now that we have our parameters set up, let's begin generating
     * random integers until one falls between $min and $max
     */
    do {
      /*
       * The rejection probability is at most 0.5, so this corresponds
       * to a failure probability of 2^-128 for a working RNG
       */
      if ($attempts > 128) {
        throw new Exception('getRandomNumber(): RNG is broken - too many rejections');
      }

      /*
       * Let's grab the necessary number of random bytes
       */
      $randomByteString = $this->getRandomBytes($bytes);

      /*
       * Let's turn $randomByteString into an integer
       *
       * This uses bitwise operators (<< and |) to build an integer
       * out of the values extracted from ord()
       *
       * Example: [9F] | [6D] | [32] | [0C] =>
       *   159 + 27904 + 3276800 + 201326592 =>
       *   204631455
       */
      $val &= 0;
      for ($i = 0; $i < $bytes; ++$i) {
        $val |= ord($randomByteString[$i]) << ($i * 8);
      }
      
      /*
       * Apply mask
       */
      $val &= $mask;
      $val += $valueShift;
      
      ++$attempts;
      /*
       * If $val overflows to a floating point number,
       * ... or is larger than $max,
       * ... or smaller than $min,
       * then try again.
       */
    } while (!is_int($val) || $val > $max || $val < $min);

    return (int)$val;
  }
}
?>