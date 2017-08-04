<?php

/**
* @package WPAuthenticator
* @version 1.0
*/

/*
Plugin Name: WPAuthenticator
Plugin URI: https://github.com/kpbowler/WPAuthenticator
Description: Creates a one-time login link for members
Author: K P Bowler
Version: 1.0
Author URI: https://kpbowler.co.uk
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
*/


/**
 * Installation of plugin - create database tables to store the one-time link.
 */
function wpauthenticator_install() {
    global $wpdb;

    $table_name = $wpdb->prefix . "wpauthenticator";
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `token` varchar(255) DEFAULT NULL,
  `generated_at` datetime DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) $charset_collate";
    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
    dbDelta( $sql );
}

/**
 * Deactivation of plugin - remove database tables.
 */
function wpauthenticator_deactivate() {
    global $wpdb;

    $table_name = $wpdb->prefix . "wpauthenticator";

    $sql = "DROP TABLE IF EXISTS $table_name";

    $wpdb->query($sql);
}

function wpauthenticator_uninstall() {

}

/**
 * Add new menu item to allow access to plugin's options
 */
function wpauthenticator_menu() {
    add_users_page( 'One-time member link', 'Authentication', 'manage_options', 'wpauthenticator-onetime', 'wpauthenticator_options' );
}

/**
 * Options page for plugin.
 */
function wpauthenticator_options() {
    if ( !current_user_can( 'manage_options' ) )  {
        wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
    }

    if(isset($_POST) && sizeof($_POST) > 0) {
        if(!get_option('wpauthenticator_email')) {
            $c = wpauthenticator_generate_ontetime();
            if($c > 0) {
                echo "<p>$c users have been emailed.</p>";
            }
            else {
                echo "<p>No emails sent. Please contact the site creators for assistance.</p>";
            }
        }
    }

    // Currently, only allow site admins to perform this action once, as this plugin emails all your users.
    //  You don't want to do that too often!

    if(!get_option('wpauthenticator_email')) {
        echo '<div class="wrap">';
        echo '<form method="POST">';
        echo '<input type="hidden" name="wpauthenticator" value="'. md5(time()).'"/>';
        echo '<input type="submit" value="Send One-time link to registered members">';
        echo '</form>';
        echo '</div>';
    }
    else {
        echo "<p>You have already emailed the users a confirmation link.</p>";
    }
}

/**
 * Generate the one-time token for each user with the subscriber role.
 * @todo Make the options for selecting users customisable from a settings page.
 * @todo Template the email message and allow configuration of message content.
 * @return int The number of tokens generated.
 */
function wpauthenticator_generate_ontetime() {
    global $wpdb;
    $users = get_users(
        array(
            'role' => 'subscriber'
        )
    );
    $count = 0;
    if(count($users) > 0) {
        foreach($users as $u) {
            $token = uniqid();

            $data = array(
                'user_id' => $u->ID,
                'token' => $token,
                'generated_at' => date('Y-m-d H:i:s'),
            );

            $table_name = $wpdb->prefix . "wpauthenticator";

            $wpdb->insert($table_name, $data);


            $headers = array('Content-Type: text/html; charset=UTF-8');
            $body = "<p>Dear $u->first_name,<br>
Please click on this link to log into the site:<br><br>".get_site_url().'/custom_auth?token='.$token."<br><br>";

            wp_mail($u->user_email, 'One-time login', $body, $headers);
            $count++;
            
        }
        add_option('wpauthenticator_email', true);
    }
    return $count;
}

/**
 * Custom URL handler to catch the action set up in the email.
 * This function logs users in without a password, just by verifying the token.
 * @todo Possibly look to improve this by passing User ID to the site as well.
 * @todo Make the URL customisable.
 */
function wpauthenticator_url_handler() {
    global $wpdb;
    if($_SERVER["REDIRECT_URL"] == '/custom_auth') {
        // Load the token from the database
        if(isset($_GET['token'])) {
            $token = $_GET['token'];

            $table_name = $wpdb->prefix . "wpauthenticator";
            $query = "SELECT `user_id` FROM $table_name WHERE `token` = \"%s\" AND `used_at` IS NULL";
            $sql = $wpdb->prepare($query, $token);
            $user_id = $wpdb->get_row($sql, OBJECT);

            // now we can get the user
            if($user_id) {
                $user = WP_User::get_data_by('id', intval($user_id->user_id));
                if(!$user) {
                    wp_redirect('/home', 301);
                    exit;
                }
                if(_wpauthenticator_login($user)) {
                    // user is now logged in!
                    $q = "UPDATE $table_name SET `used_at` = NOW() WHERE `user_id` = %d LIMIT 1";
                    $sql = $wpdb->prepare($q, intval($user_id->user_id));
                    $wpdb->query($sql);
                    wp_safe_redirect( '/member-profile/' );
                    exit();
                }
            }
            wp_safe_redirect( '/home' );
            exit();
        }
        else {
            wp_redirect('/home', 301);
            exit;
        }
    }
}

/**
 * Log in routine
 * @param $user The user to authenticate
 * @return bool The user's logged in state
 */
function _wpauthenticator_login($user) {
    if ( !is_wp_error( $user ) )
    {
        wp_clear_auth_cookie();
        wp_set_current_user ( $user->ID );
        wp_set_auth_cookie  ( $user->ID );

        return true;
    }
    return false;
}


/**
 * Wordpress actions
 */
add_action( 'admin_menu', 'wpauthenticator_menu' );
add_action('parse_request', 'wpauthenticator_url_handler');


register_activation_hook( __FILE__, 'wpauthenticator_install' );
register_deactivation_hook(__FILE__, 'wpauthenticator_deactivate');
register_uninstall_hook( __FILE__, 'wpauthenticator_uninstall' );