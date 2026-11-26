<?php
/**
 * Uninstall cleanup for ForgeHub SSL Redirect Guard.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpfh_ssl_settings' );
delete_option( 'wpfh_ssl_pro_settings' );
delete_option( 'wpfh_ssl_last_expiry_alert' );
delete_transient( 'wpfh_ssl_cert_health' );
wp_clear_scheduled_hook( 'wpfh_ssl_daily_cert_check' );
