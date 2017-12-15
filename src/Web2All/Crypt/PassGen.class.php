<?php
/**
 * Password generating class
 * 
 * Generate passwords which are more than just random characters
 *
 * @author Merijn van den Kroonenberg
 * @copyright (c) Copyright 2017 Web2All B.V.
 * @since 2017-04-26
 */
class Web2All_Crypt_PassGen extends Web2All_Manager_Plugin { 
  
  /**
   * config
   *
   * @var array
   */
  protected $config;
  
  /**
   * Algorithm instances (array) with as key the name
   *
   * @var Web2All_Crypt_PassGen_IAlgorithm[]
   */
  protected $algorithms;
  
  /**
   * The parts of the password and the algorithms used for it
   *
   * @var array
   */
  protected $algorithm_parts;
  
  /**
   * Assoc array of algorithm definitions
   *
   * @var array
   */
  protected $algorithm_definitions;
  
  /**
   * Constructor
   * 
   * @param Web2All_Manager_Main $web2all
   */
  public function __construct(Web2All_Manager_Main $web2all) 
  {
    parent::__construct($web2all);
    
    // load settings
    $defaultconfig=array(
      'debuglevel'      => 2,          // from which global debuglevel start debuglogging (so 0 is always and 6 is never)
      'algorithm_parts' => array(
        'RANDSTR8'
      ),
      'algorithms'      => array(
        'RANDSTR8' => array('Web2All_Crypt_PassGen_RandomStringAlgorithm')
      )
    );
    
    $this->config=$this->Web2All->Config->makeConfig(get_class($this),$defaultconfig);
    
    $this->setAlgorithmConfig($this->config['algorithms']);
    $this->setPasswordStructure($this->config['algorithm_parts']);
  }
  
  /**
   * Set the algorithms used
   * 
   * @param array $algorithms  assoc array algorithm name => array($classname,$settings)
   */
  public function setAlgorithmConfig($algorithms)
  {
    $this->algorithm_definitions=$algorithms;
    $this->initAlgorithms();
  }
  
  /**
   * Set the password structure
   * 
   * @param array $password_structure  array of algorithm names
   */
  public function setPasswordStructure($password_structure)
  {
    $this->algorithm_parts=$password_structure;
  }
  
  /**
   * Inintialize all algorithms
   * 
   */
  public function initAlgorithms() 
  {
    $this->algorithms=array();
    foreach($this->algorithm_definitions as $name => $definition){
      $class_name=array_shift($definition);
      $this->algorithms[$name]=$this->Web2All->Plugin->{$class_name}();
      if($definition){
        $settings=array_shift($definition);
        $this->algorithms[$name]->init($settings);
      }
    }
  }
  
  /**
   * Generate the password
   * 
   * @return string
   */
  public function generate()
  {
    $password='';
    foreach($this->algorithm_parts as $name){
      if(!isset($this->algorithms[$name])){
        throw new Exception('PassGen undefined algorithm "'.$name.'"');
      }
      $password.=$this->algorithms[$name]->generate();
    }
    return $password;
  }
  
}
?>