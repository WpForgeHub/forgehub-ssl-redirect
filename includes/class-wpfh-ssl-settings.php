<?php
/**
 * Settings helper for ForgeHub SSL Redirect Guard.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_SSL_Settings
 */
class WPFH_SSL_Settings {

	/**
	 * Option name for core settings.
	 */
	const OPTION_NAME = 'wpfh_ssl_settings';

	/**
	 * Option name for Pro settings.
	 */
	const PRO_OPTION_NAME = 'wpfh_ssl_pro_settings';

	/**
	 * Return default core settings.
	 *
	 * @return array
	 */
	public static function get_defaults() {
		return array(
			'enable_https_redirect'      => false,
			'redirect_status_code'       => 301,
			'respect_proxy_headers'      => true,
			'exclude_paths'              => "/.well-known/acme-challenge/\n/robots.txt",
			'enable_mixed_content_fixer' => true,
			'fix_mixed_content_admin'    => false,
			'force_secure_cookies'       => true,
		);
	}

	/**
	 * Return default Pro settings.
	 *
	 * @return array
	 */
	public static function get_pro_defaults() {
		return array(
			'enable_hsts'             => false,
			'hsts_max_age'            => 31536000,
			'hsts_include_subdomains' => false,
			'hsts_preload'            => false,
			'enable_csp_upgrade'      => true,
			'enable_security_headers' => true,
			'expiry_alert_enabled'    => true,
			'expiry_alert_days'       => 14,
			'expiry_alert_email'      => get_option( 'admin_email', '' ),
		);
	}

	/**
	 * Get merged core settings.
	 *
	 * @return array
	 */
	public static function get() {
		$saved = get_option( self::OPTION_NAME, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, self::get_defaults() );
	}

	/**
	 * Get merged Pro settings.
	 *
	 * @return array
	 */
	public static function get_pro() {
		$saved = get_option( self::PRO_OPTION_NAME, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, self::get_pro_defaults() );
	}

	/**
	 * Sanitize core settings.
	 *
	 * @param array $input Raw form input.
	 * @return array
	 */
	public static function sanitize( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$status_code = isset( $input['redirect_status_code'] ) ? absint( $input['redirect_status_code'] ) : 301;
		if ( ! in_array( $status_code, array( 301, 302 ), true ) ) {
			$status_code = 301;
		}

		$raw_paths   = isset( $input['exclude_paths'] ) ? sanitize_textarea_field( wp_unslash( $input['exclude_paths'] ) ) : '';
		$clean_lines = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw_paths ) as $line ) {
			$line = trim( $line );
			if ( '' !== $line ) {
				if ( '/' !== substr( $line, 0, 1 ) ) {
					$line = '/' . $line;
				}
				$clean_lines[] = $line;
			}
		}

		return array(
			'enable_https_redirect'      => ! empty( $input['enable_https_redirect'] ),
			'redirect_status_code'       => $status_code,
			'respect_proxy_headers'      => ! empty( $input['respect_proxy_headers'] ),
			'exclude_paths'              => implode( "\n", array_unique( $clean_lines ) ),
			'enable_mixed_content_fixer' => ! empty( $input['enable_mixed_content_fixer'] ),
			'fix_mixed_content_admin'    => ! empty( $input['fix_mixed_content_admin'] ),
			'force_secure_cookies'       => ! empty( $input['force_secure_cookies'] ),
		);
	}

	/**
	 * Sanitize Pro settings.
	 *
	 * @param array $input Raw form input.
	 * @return array
	 */
	public static function sanitize_pro( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$max_age = isset( $input['hsts_max_age'] ) ? absint( $input['hsts_max_age'] ) : 31536000;
		$allowed = array( 300, 86400, 2592000, 15552000, 31536000, 63072000 );
		if ( ! in_array( $max_age, $allowed, true ) ) {
			$max_age = 31536000;
		}

		$alert_days = isset( $input['expiry_alert_days'] ) ? absint( $input['expiry_alert_days'] ) : 14;
		if ( $alert_days < 1 || $alert_days > 90 ) {
			$alert_days = 14;
		}

		$alert_email = isset( $input['expiry_alert_email'] ) ? sanitize_email( wp_unslash( $input['expiry_alert_email'] ) ) : '';
		if ( empty( $alert_email ) ) {
			$alert_email = get_option( 'admin_email', '' );
		}

		$enable_hsts             = ! empty( $input['enable_hsts'] );
		$hsts_include_subdomains = $enable_hsts && ! empty( $input['hsts_include_subdomains'] );
		$hsts_preload            = $hsts_include_subdomains && ! empty( $input['hsts_preload'] );

		return array(
			'enable_hsts'             => $enable_hsts,
			'hsts_max_age'            => $max_age,
			'hsts_include_subdomains' => $hsts_include_subdomains,
			'hsts_preload'            => $hsts_preload,
			'enable_csp_upgrade'      => ! empty( $input['enable_csp_upgrade'] ),
			'enable_security_headers' => ! empty( $input['enable_security_headers'] ),
			'expiry_alert_enabled'    => ! empty( $input['expiry_alert_enabled'] ),
			'expiry_alert_days'       => $alert_days,
			'expiry_alert_email'      => $alert_email,
		);
	}
}
