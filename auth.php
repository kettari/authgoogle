<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();
define('GOOGLE_API_DIR', dirname(__FILE__).'/google/');

global $conf;
// define cookie and session id, append server port when securecookie is configured
if (!defined('AUTHGOOGLE_COOKIE')) define('AUTHGOOGLE_COOKIE', 'SPGG'.md5(DOKU_REL.(($conf['securecookie'])?$_SERVER['SERVER_PORT']:'')));

/**
 * Google Auth 2.0 authentication backend
 *
 * @author sentryperm@gmail.com
 */
class auth_plugin_authgoogle extends auth_plugin_authplain  { 

    public function __construct() {
        parent::__construct();
        $this->cando['external'] = true;
        $this->cando['logout'] = true; 
    }
    
    function trustExternal($user, $pass, $sticky = false) {
	global $USERINFO;
        
        //если есть информация о пользователе в сессии
        if (!empty($_SESSION[DOKU_COOKIE]['authgoogle']['info'])) {
            $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['name'];
            $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['mail'];
            $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['grps'];
            $USERINFO['is_google'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['is_google'];
            $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['authgoogle']['user'];
            return true;
	}
        
        //введены данные с формы
        if(!empty($user)){
            if($this->checkPass($user,$pass)){                
                $uinfo  = $this->getUserData($user);
                
                //передаем информацию о пользователе
                $USERINFO['name'] = $uinfo['name'];
                $USERINFO['mail'] = $uinfo['email'];
                $USERINFO['grps'] = $uinfo['grps'];
                $USERINFO['pass'] = $pass;
                
                //сохраняем данные в сессию
                $_SERVER['REMOTE_USER'] = $uinfo['name'];
                $_SESSION[DOKU_COOKIE]['authgoogle']['user'] = $uinfo['name'];                
                $_SESSION[DOKU_COOKIE]['authgoogle']['info'] = $USERINFO;
                
                return true;
            }else{
                //invalid credentials - log off
                msg($this->getLang('badlogin'),-1);                
                return false;
            }            
        }
        
        //если токен сохранен в куках - достаем
        if ($_COOKIE[AUTHGOOGLE_COOKIE]) {
            $_SESSION[DOKU_COOKIE]['authgoogle']['token'] = $_COOKIE[AUTHGOOGLE_COOKIE];
        }
        
        //google auth
        require_once GOOGLE_API_DIR.'/Google_Client.php';
        require_once GOOGLE_API_DIR.'/contrib/Google_Oauth2Service.php';
        
        $client = new Google_Client();
        $client->setApplicationName("Google Application");
        $client->setClientId($this->getConf('client_id'));
        $client->setClientSecret($this->getConf('client_secret'));
        $client->setRedirectUri(wl($ID,'id=start&do=login',true));

        $oauth2 = new Google_Oauth2Service($client);       
        //получаем код для авторизации        
        if (isset($_GET['code'])) {
            //получение токена            
            try {
                $client->authenticate($_GET['code']);
                //сохраняем токен
                $_SESSION[DOKU_COOKIE]['authgoogle']['token'] = $client->getAccessToken();
                //сохраняем токен в куки                
                $this->_updateCookie($_SESSION[DOKU_COOKIE]['authgoogle']['token'], time() + 60 * 60 * 24 * 365);
                //редирект на главную
                header("Location: ".wl($ID, '', true, '&'));
                die();
            } catch (Exception $e) {
                msg('Auth Google Error: '.$e->getMessage());                
            }            
        }
        //сохраняем state и auth_url
        $_SESSION[DOKU_COOKIE]['authgoogle']['state'] = $state;
        $_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'] = $client->createAuthUrl();
        $_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'] .= "&state=".$state;
        
        //устанавливаем токен авторизации
        if (isset($_SESSION[DOKU_COOKIE]['authgoogle']['token'])) {
            $client->setAccessToken($_SESSION[DOKU_COOKIE]['authgoogle']['token']);
        }
        
        //если авторизация успешна
        if ($client->getAccessToken()) {
            $user = $oauth2->userinfo->get();        
            $email = filter_var($user['email'], FILTER_SANITIZE_EMAIL);
            //$img = filter_var($user['picture'], FILTER_VALIDATE_URL);
            //$personMarkup = "$email<div><img src='$img?sz=50'></div>";
            
            //Проверяем, подтвержден ли email в google
            if (!$user['verified_email']) {
                msg('Auth Google Error: '.$email.' not verifed in google account');
                $this->logOff();                
                return false;
            }
            
            //проверяем email в списке разрешенных
            if (!$this->_check_email_domain($email)) {
                msg('Auth Google Error: access denied for '.$email);
                $this->logOff();                
                return false;
            }
            
            //создаем или обновляем пользователя в базе
            $login = 'google'.$user['id'];
            $udata = $this->getUserData($login);
            if (!$udata) {
                //группы по умолчанию
                $grps = null;
                if ($this->getConf('default_groups')) $grps = explode(' ', $this->getConf('default_groups'));
                //создаем пользователя
                $this->createUser($login, md5(rand().$login), $user['name'], $email, $grps);
                $udata = $this->getUserData($login);
            } elseif ($udata['name'] != $user['name'] || $udata['email'] != $email) {
                //обновляем пользователя
                $this->modifyUser($login, array('name'=>$user['name'], 'email'=>$email));
            }           
            
            //передаем информацию о пользователе
            $USERINFO['pass'] = "";
            $USERINFO['name'] = $user['name'];
            $USERINFO['mail'] = $email;
            $USERINFO['grps'] = $udata['grps'];
            $USERINFO['is_google'] = true;
            $_SERVER['REMOTE_USER'] = $user['name'];
            
            //сохраняем информацию в сессию
            $_SESSION[DOKU_COOKIE]['authgoogle']['user'] = $_SERVER['REMOTE_USER'];
            $_SESSION[DOKU_COOKIE]['authgoogle']['info'] = $USERINFO;
        
            // обновляем токен, так как может быть изменен
            $_SESSION['token'] = $client->getAccessToken();
            
            return true;
        } else {
            //нет токена            
        }
        
        return false;
    }
    
    function _check_email_domain($email) {
        //проверка домена email в списке разрешенных
        if ($this->getConf('allowed_domains')) {
            $domains = preg_split("/[ ]+/is", $this->getConf('allowed_domains'));
            foreach ($domains as $domain) {
                $domain = trim($domain);
                //все домены
                if ($domain == '*') return true;
                //определенный email
                if ($email == $domain) return true;
                //определенный домен
                if (preg_match("/^\\*@([^@ ]+)/is", $domain, $m)) {                    
                    if (preg_match("/@([^@ ]+)$/is", $email, $n)) {
                        if ($m[1] == $n[1]) return true;
                    }
                }
            }
        }          
        return false;        
    }
    
    function logOff(){
        unset($_SESSION[DOKU_COOKIE]['authgoogle']['token']);
        unset($_SESSION[DOKU_COOKIE]['authgoogle']['user']);
        unset($_SESSION[DOKU_COOKIE]['authgoogle']['info']);
        // clear the cookie
        $this->_updateCookie('', time() - 600000);
    }
    
    function _updateCookie($value, $time) {
        global $conf;

        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        if (version_compare(PHP_VERSION, '5.2.0', '>')) {
            setcookie(AUTHGOOGLE_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
        } else {
            setcookie(AUTHGOOGLE_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()));
        }
    }
}
?>