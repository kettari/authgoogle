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
        global $config_cascade;
        parent::__construct();

        // fix if acl no used
        $this->success = true;

        $this->cando['external'] = true;
        $this->cando['logout'] = true;
    }

    function trustExternal($user, $pass, $sticky = false) {
	global $USERINFO, $ID;

        //get user info in session
        if (!empty($_SESSION[DOKU_COOKIE]['authgoogle']['info'])) {
            $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['name'];
            $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['mail'];
            $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['grps'];
            $USERINFO['is_google'] = $_SESSION[DOKU_COOKIE]['authgoogle']['info']['is_google'];
            $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['authgoogle']['user'];
            return true;
	}

        //get form login info
        if(!empty($user)){
            if($this->checkPass($user,$pass)){
                $uinfo  = $this->getUserData($user);

                //set user info
                $USERINFO['name'] = $uinfo['name'];
                $USERINFO['mail'] = $uinfo['email'];
                $USERINFO['grps'] = $uinfo['grps'];
                $USERINFO['pass'] = $pass;

                //save data in session
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

        //if token saved in cookies - get it
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
        $client->setRedirectUri(wl('start',array('do'=>'login'),true, '&'));
        $client->setAccessType('online');
        $client->setApprovalPrompt('auto');

        $oauth2 = new Google_Oauth2Service($client);
        //get code from google redirect link
        if (isset($_GET['code'])) {
            //get token
            try {
                $client->authenticate($_GET['code']);
                //save token in session
                $_SESSION[DOKU_COOKIE]['authgoogle']['token'] = $client->getAccessToken();
                //save token in cookies
                $this->_updateCookie($_SESSION[DOKU_COOKIE]['authgoogle']['token'], time() + 60 * 60 * 24 * 365);
                //redirect to login page
                header("Location: ".wl('start', array('do'=>'login'), true, '&'));
                die();
            } catch (Exception $e) {
                msg('Auth Google Error: '.$e->getMessage());
            }
        }
        //save state and auth_url in session
        $_SESSION[DOKU_COOKIE]['authgoogle']['state'] = $state;
        $_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'] = $client->createAuthUrl();
        $_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'] .= "&state=".$state;

        //set token in client
        if (isset($_SESSION[DOKU_COOKIE]['authgoogle']['token'])) {
            try {
                $client->setAccessToken($_SESSION[DOKU_COOKIE]['authgoogle']['token']);
            } catch (Exception $e){
                $this->logOff();
                return false;
            }
        }

        //if successed auth
        if ($client->getAccessToken()) {
            
            // If the access token is expired, ask the user to login again
            if($client->isAccessTokenExpired()) {
                $authUrl = $client->createAuthUrl();
                header('Location: ' . filter_var($authUrl, FILTER_SANITIZE_URL));
            }
            
            $user = $oauth2->userinfo->get();
            $email = filter_var($user['email'], FILTER_SANITIZE_EMAIL);
            //$img = filter_var($user['picture'], FILTER_VALIDATE_URL);
            //$personMarkup = "$email<div><img src='$img?sz=50'></div>";

            //Check verify email in google
            if (!$user['verified_email']) {
                msg('Auth Google Error: '.$email.' not verifed in google account');
                $this->logOff();
                return false;
            }

            //check email in list allows
            if (!$this->_check_email_domain($email)) {
                msg('Auth Google Error: access denied for '.$email);
                $this->logOff();
                return false;
            }

            //create and update user in base
            $login = 'google'.$user['id'];
            $udata = $this->getUserData($login);
            if (!$udata) {
                //default groups
                $grps = null;
                if ($this->getConf('default_groups')) $grps = explode(' ', $this->getConf('default_groups'));
                //create user
                $this->createUser($login, md5(rand().$login), $user['name'], $email, $grps);
                $udata = $this->getUserData($login);
            } elseif ($udata['name'] != $user['name'] || $udata['email'] != $email) {
                //update user
                $this->modifyUser($login, array('name'=>$user['name'], 'email'=>$email));
            }

            //set user info
            $USERINFO['pass'] = "";
            $USERINFO['name'] = $user['name'];
            $USERINFO['mail'] = $email;
            $USERINFO['grps'] = $udata['grps'];
            $USERINFO['is_google'] = true;
            $_SERVER['REMOTE_USER'] = $user['name'];

            //save user info in session
            $_SESSION[DOKU_COOKIE]['authgoogle']['user'] = $_SERVER['REMOTE_USER'];
            $_SESSION[DOKU_COOKIE]['authgoogle']['info'] = $USERINFO;

            // update token
            $_SESSION['token'] = $client->getAccessToken();

            //if login page - redirect to main page
            if (isset($_GET['do']) && $_GET['do']=='login')
                header("Location: ".wl('start', '', true));

            return true;
        } else {
            //no auth
        }

        return false;
    }

    function _check_email_domain($email) {
        //check email in allow domains
        if ($this->getConf('allowed_domains')) {
            $domains = preg_split("/[ ]+/is", $this->getConf('allowed_domains'));
            foreach ($domains as $domain) {
                $domain = trim($domain);
                //all domains
                if ($domain == '*') return true;
                //email
                if ($email == $domain) return true;
                //domain
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

    function cleanUser($user){

        /* Sometimes system ask for a user in email format and we need to replace @ for _
         In this case, the user is not the logged in one. This happens mostly in  the admin tools*/
        if(filter_var($user, FILTER_VALIDATE_EMAIL)){
            return str_replace("@", "_",$user);
        }
        /* Sometimes system ask for $login info, that is generated in the registration process some lines above
         In this case we return the same username
        TODO: check with a regexp */
        if(substr( $user, 0, 6 ) === "google"){
            return $user;
        }
        /* When ACL checks the username, it ask for the name of the user (that can be a serious security bug)
           so, if the system ask for the name of the current user, I send the email replacing @ for _ cause  the
           user logged with googleauth can't change its email by hand.
        */
        if ($user == $_SESSION[DOKU_COOKIE]['authgoogle']['user'] ){
            return str_replace("@", "_", $_SESSION[DOKU_COOKIE]['authgoogle']['info']['mail']);
        }
        /*Every other case return the same that you sent*/
        return $user;
    }
}
?>
