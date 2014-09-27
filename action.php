<?php
// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();

define('GOOGLE_API_DIR', dirname(__FILE__).'/google/');

class action_plugin_authgoogle extends DokuWiki_Action_Plugin {    
    /**
     * Registers the event handlers.
     */
    function register(&$controller)
    {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE',  $this, 'hook_html_loginform_output', array());
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'hook_updateprofileform_output', array());
    }
    
    function hook_updateprofileform_output(&$event, $param) {
        global $USERINFO;
        
        if ($USERINFO['is_google']) {
            //print_r($event->data);
            //$event->data->replaceElement(0, form_makeTextField('fullname', $USERINFO['name'], $lang['fullname'], '', 'block', array('size'=>'50')));
            $elem = $event->data->getElementAt(2);
            $elem['disabled'] = 'disabled';
            $event->data->replaceElement(2, $elem);
            
            $elem = $event->data->getElementAt(3);
            $elem['disabled'] = 'disabled';
            $event->data->replaceElement(3, $elem);
            
            $event->data->replaceElement(10, null);
            $event->data->replaceElement(9, null);
            $event->data->replaceElement(8, null);
            $event->data->replaceElement(7, null);
            $event->data->replaceElement(6, null);
            $event->data->replaceElement(5, null);
            $event->data->replaceElement(4, null);     
            
            //print_r($event->data);
        }        
    }
    
    /**
     * Handles the login form rendering.
     */
    function hook_html_loginform_output(&$event, $param) {
        
        //$event->data = null;
        //echo print_r($event,true);
        //echo "111";        
        
        if (isset($_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'])) {
            $auth_url = $_SESSION[DOKU_COOKIE]['authgoogle']['auth_url'];
            
            $a_style = "width: 200px;margin:0 auto;color: #666666;cursor: pointer;text-decoration: none !important;display: block;padding-bottom:1.4em;";//-moz-linear-gradient(center top , #F8F8F8, #ECECEC)
            $div_style = "float:left;line-height: 30px;background-color: #F8F8F8;border: 1px solid #C6C6C6;border-radius: 2px 2px 2px 2px;padding: 0px 5px 0px 5px;position: relative;";
            $img_style = "width:20px;height:20px;margin:5px 5px 5px 0;background: url('/lib/plugins/authgoogle/images/social_google_box.png') no-repeat;float:left;";
            echo "<a href='$auth_url' style='$a_style' title='".$this->getLang('enter_google')."'><div style=\"$div_style\"><div style=\"$img_style\"></div>".$this->getLang('enter_google')."</div>";
            echo "<div style='clear: both;'></div></a>";
        }
    }
}
?>
