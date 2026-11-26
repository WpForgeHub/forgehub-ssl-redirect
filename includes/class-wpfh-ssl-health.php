<?php
/**
 * SSL Certificate & Environment Health Inspector.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_SSL_Health
 */
class WPFH_SSL_Health {

	/**
	 * Transient cache key for SSL certificate check.
	 */
	const CACHE_KEY = 'wpfh_ssl_cert_health';

	/**
	 * Detect whether the current HTTP request arrived over HTTPS (including reverse proxies).
	 *
	 * @param bool $respect_proxy Whether to inspect Cloudflare / load-balancer proxy headers.
	 * @return bool
	 */
	public static function is_ssl_request( $respect_proxy = true ) {
		if ( is_ssl() ) {
			return true;
		}

		if ( ! $respect_proxy ) {
			return false;
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) {
			$proto = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) );
			if ( false !== strpos( $proto, 'https' ) ) {
				return true;
			}
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) {
			$fwd_ssl = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) );
			if ( 'on' === $fwd_ssl || '1' === $fwd_ssl ) {
				return true;
			}
		}

		if ( ! empty( $_SERVER['HTTP_CF_VISITOR'] ) ) {
			$cf_raw = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_VISITOR'] ) );
			if ( false !== strpos( strtolower( $cf_raw ), 'https' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Inspect the site's SSL certificate and return structured health data.
	 *
	 * @param bool $force_refresh Ignore transient cache when true.
	 * @return array
	 */
	public static function get_certificate_health( $force_refresh = false ) {
		if ( ! $force_refresh ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$host   = wp_parse_url( home_url(), PHP_URL_HOST );
		$result = array(
			'host'            => (string) $host,
			'status'          => 'unreachable',
			'valid'           => false,
			'issuer'          => '',
			'subject'         => '',
			'valid_from'      => '',
			'valid_to'        => '',
			'days_remaining'  => null,
			'checked_at'      => gmdate( 'Y-m-d H:i:s' ),
			'home_is_https'   => 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ),
			'site_is_https'   => 'https' === wp_parse_url( site_url(), PHP_URL_SCHEME ),
			'current_https'   => self::is_ssl_request( true ),
			'error_message'   => '',
		);

		if ( empty( $host ) || ! function_exists( 'stream_socket_client' ) || ! function_exists( 'openssl_x509_parse' ) ) {
			$result['error_message'] = __( 'OpenSSL stream inspection is not available on this PHP environment.', 'forgehub-ssl-redirect' );
			set_transient( self::CACHE_KEY, $result, HOUR_IN_SECONDS );
			return $result;
		}

		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);

		$errno  = 0;
		$errstr = '';
		$client = stream_socket_client(
			'ssl://' . $host . ':443',
			$errno,
			$errstr,
			5,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if ( false === $client ) {
			$result['error_message'] = ! empty( $errstr ) ? sanitize_text_field( $errstr ) : __( 'Could not connect to port 443 over TLS.', 'forgehub-ssl-redirect' );
			set_transient( self::CACHE_KEY, $result, HOUR_IN_SECONDS );
			return $result;
		}

		$params = stream_context_get_params( $client );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $client );

		if ( empty( $params['options']['ssl']['peer_certificate'] ) ) {
			$result['error_message'] = __( 'No peer SSL certificate was returned by the server.', 'forgehub-ssl-redirect' );
			set_transient( self::CACHE_KEY, $result, HOUR_IN_SECONDS );
			return $result;
		}

		$parsed = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
		if ( ! is_array( $parsed ) ) {
			$result['error_message'] = __( 'Unable to parse the returned X.509 certificate.', 'forgehub-ssl-redirect' );
			set_transient( self::CACHE_KEY, $result, HOUR_IN_SECONDS );
			return $result;
		}

		$valid_from_ts  = isset( $parsed['validFrom_time_t'] ) ? (int) $parsed['validFrom_time_t'] : 0;
		$valid_to_ts    = isset( $parsed['validTo_time_t'] ) ? (int) $parsed['validTo_time_t'] : 0;
		$now            = time();
		$days_remaining = $valid_to_ts > 0 ? (int) floor( ( $valid_to_ts - $now ) / DAY_IN_SECONDS ) : null;

		$issuer_cn  = isset( $parsed['issuer']['O'] ) ? $parsed['issuer']['O'] : ( isset( $parsed['issuer']['CN'] ) ? $parsed['issuer']['CN'] : '' );
		$subject_cn = isset( $parsed['subject']['CN'] ) ? $parsed['subject']['CN'] : $host;

		$result['issuer']         = sanitize_text_field( is_array( $issuer_cn ) ? implode( ', ', $issuer_cn ) : (string) $issuer_cn );
		$result['subject']        = sanitize_text_field( is_array( $subject_cn ) ? implode( ', ', $subject_cn ) : (string) $subject_cn );
		$result['valid_from']     = $valid_from_ts > 0 ? gmdate( 'Y-m-d', $valid_from_ts ) : '';
		$result['valid_to']       = $valid_to_ts > 0 ? gmdate( 'Y-m-d', $valid_to_ts ) : '';
		$result['days_remaining'] = $days_remaining;

		if ( null !== $days_remaining && $days_remaining < 0 ) {
			$result['status'] = 'expired';
			$result['valid']  = false;
		} elseif ( null !== $days_remaining && $days_remaining <= 14 ) {
			$result['status'] = 'expiring_soon';
			$result['valid']  = true;
		} else {
			$result['status'] = 'valid';
			$result['valid']  = true;
		}

		set_transient( self::CACHE_KEY, $result, 6 * HOUR_IN_SECONDS );
		return $result;
	}
}
