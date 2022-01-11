<?php
namespace booosta\db_authenticator;
use \booosta\Framework as b;
b::init_module('db_authenticator');

class DB_Authenticator extends \booosta\authenticator\Authenticator
{
  use moduletrait_db_authenticator;

  protected $user_table = 'user';
  protected $id_field = 'id';
  protected $username_field = 'username';
  protected $password_field = 'password';
  protected $cookie_field = 'logincookie';
  protected $token_field = 'token';
  protected $usergroup_field = 'usergroup';
  protected $password_encrypted = 'false';

  public function authenticate($username, $password)
  {
    $this->init_db();

    $this->username = $username = addcslashes($username, "'");
    ##$password = addcslashes($password, "'");

    if($this->password_encrypted) $pass = $this->crypter->encrypt($password); else $pass = addcslashes($password, "'");
    $found = $this->DB->query_value("select count(*) from `$this->user_table` where `$this->username_field`=? and `$this->password_field`=? and active='1'", [$username, $pass]);
    #debug("select count(*) from $this->user_table where $this->username_field='$username' and $this->password_field='$pass' and active='1'");    
    return ($found == 1);
  }

  public function authenticate_cookie()
  {
    $this->init_db();

    if($cookie = unserialize($_COOKIE['loginCredentials'])):
      $username = $cookie['username'];
      $secret = $this->crypter->encrypt($cookie['secret']);
      #debug("username: $username, secret: $secret");

      $found = $this->DB->query_value("select count(*) from `$this->user_table` where `$this->username_field`=? and `$this->cookie_field`=? and active='1'", [$username, $secret]);
      if($found == 1) return $username;
    endif;

    return false;
  }

  public function store_logincookie($username, $secret)
  {
    $secret = $this->crypter->encrypt($secret);

    $this->init_db();
    $this->DB->query("update `$this->user_table` set `$this->cookie_field`=? where `$this->username_field`=?", [$secret, $username]);
    #debug("update `$this->user_table` set `$this->cookie_field`=? where `$this->username_field`=? [$secret, $username]");
  }

  public function delete_logincookie($username)
  {
    $this->init_db();
    $this->DB->query("update `$this->user_table` set `$this->cookie_field`=null where `$this->username_field`=?", $username);
    #\booosta\debug("update `$this->user_table` set `$this->cookie_field`=null where `$this->username_field`=?, $username");
  }

  public function get_logincookie($username)
  {
    $this->init_db();
    $encrypted = $this->DB->query_value("select `$this->cookie_field` from `$this->user_table` where `$this->username_field`=?", $username);
    return $encrypted ? $this->crypter->decrypt($encrypted) : null;
  }

  public function authenticate_token($token)
  {
    $this->init_db();

    $secret = $this->crypter->encrypt($token);

    $username = $this->DB->query_value("select `$this->username_field` from `$this->user_table` where `$this->token_field`=? and active='1'", $secret);
    if($username) return $username;
    return null;
  }

  public function store_token($username, $token)
  {
    $secret = $this->crypter->encrypt($token);

    $this->init_db();
    $this->DB->query("update `$this->user_table` set `$this->token_field`=? where `$this->username_field`=?", [$secret, $username]);
  }

  public function delete_token($username)
  {
    $this->init_db();
    $this->DB->query("update `$this->user_table` set `$this->token_field`=null where `$this->username_field`=?", $username);
    #\booosta\debug("update `$this->user_table` set `$this->token_field`=null where `$this->username_field`=?, $username");
  }

  public function get_token($username)
  {
    $this->init_db();
    $encrypted = $this->DB->query_value("select `$this->token_field` from `$this->user_table` where `$this->username_field`=?", $username);
    return $encrypted ? $this->crypter->decrypt($encrypted) : null;
  }

  public function get_id($username)
  {
    $this->init_db();

    $username = addcslashes($username, "'");
    return $this->DB->query_value("select `$this->id_field` from `$this->user_table` where `$this->username_field`=?", $username);
  }

  public function get_usergroup($username = null)
  {
    $this->init_db();

    $username = $username ?? $this->username;
    return $this->DB->query_value("select `$this->usergroup_field` from `$this->user_table` where `$this->username_field`=?", $username);
  }

  public function username_exists($username, $usertable = null)
  {
    $count = $this->DB->query_value("select count(*) from `$usertable` where `$this->username_field`=?", $username);
    return $count > 0;
  }

  public function get_settings($username = null)
  {
    $this->init_db();

    $username = $username ?? $this->username;
    $str = $this->DB->query_value("select usersettings from `$this->user_table` where `$this->username_field`=?", $username);
    $arr = unserialize($str);
    #\booosta\debug("select usersettings from `$this->user_table` where `$this->username_field`='$this->username'");
    if(is_array($arr)) return $arr;

    return [];
  }
}
