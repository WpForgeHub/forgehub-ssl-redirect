<?php
/**
 * Pro Module: HSTS, CSP Upgrade-Insecure-Requests, Certificate Expiry Alerts & Mixed Content Scanner.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_SSL_Pro
 */
class WPFH_SSL_Pro {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_SSL_Pro|null
	 */
	private static $instance = null;

	/**
	 * Pro settings cache.
	 *
	 * @var array
	 */
	private $pro_settings = array();

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_SSL_Pro
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->pro_settings = WPFH_SSL_Settings::get_pro();

		add_action( 'send_headers', array( $this, 'send_security_headers' ), 10 );
		add_action( 'wpfh_ssl_daily_cert_check', array( $this, 'run_daily_expiry_check' ) );
		add_action( 'wp_ajax_wpfh_ssl_scan_mixed_content', array( $this, 'ajax_scan_mixed_content' ) );

		if ( ! empty( $this->pro_settings['expiry_alert_enabled'] ) && ! wp_next_scheduled( 'wpfh_ssl_daily_cert_check' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'wpfh_ssl_daily_cert_check' );
		}
	}

	/**
	 * Emit HSTS, CSP upgrade-insecure-requests, and baseline security headers on HTTPS responses.
	 *
	 * @return void
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		$core          = WPFH_SSL_Settings::get();
		$respect_proxy = ! empty( $core['respect_proxy_headers'] );
		if ( ! WPFH_SSL_Health::is_ssl_request( $respect_proxy ) ) {
			return;
		}

		if ( ! empty( $this->pro_settings['enable_hsts'] ) ) {
			$max_age = absint( $this->pro_settings['hsts_max_age'] );
			$header  = 'max-age=' . $max_age;
			if ( ! empty( $this->pro_settings['hsts_include_subdomains'] ) ) {
				$header .= '; includeSubDomains';
				if ( ! empty( $this->pro_settings['hsts_preload'] ) ) {
					$header .= '; preload';
				}
			}
			header( 'Strict-Transport-Security: ' . $header );
		}

		if ( ! empty( $this->pro_settings['enable_csp_upgrade'] ) ) {
			header( 'Content-Security-Policy: upgrade-insecure-requests' );
		}

		if ( ! empty( $this->pro_settings['enable_security_headers'] ) ) {
			header( 'X-Content-Type-Options: nosniff' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}
	}

	/**
	 * Daily WP-Cron callback to alert administrator if SSL certificate expires soon.
	 *
	 * @return void
	 */
	public function run_daily_expiry_check() {
		if ( empty( $this->pro_settings['expiry_alert_enabled'] ) ) {
			return;
		}

		$health    = WPFH_SSL_Health::get_certificate_health( true );
		$threshold = absint( $this->pro_settings['expiry_alert_days'] );
		$days      = isset( $health['days_remaining'] ) ? $health['days_remaining'] : null;

		if ( null === $days || $days > $threshold ) {
			return;
		}

		$last_alert = (int) get_option( 'wpfh_ssl_last_expiry_alert', 0 );
		if ( ( time() - $last_alert ) < DAY_IN_SECONDS ) {
			return;
		}

		$to = ! empty( $this->pro_settings['expiry_alert_email'] )
			? sanitize_email( $this->pro_settings['expiry_alert_email'] )
			: get_option( 'admin_email' );

		if ( empty( $to ) ) {
			return;
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: 1: site name, 2: remaining days */
		$subject = sprintf( __( '[%1$s] SSL Certificate Expiring in %2$d Days', 'forgehub-ssl-redirect' ), $site_name, (int) $days );
		$body    = sprintf(
			/* translators: 1: host name, 2: expiry date, 3: days remaining, 4: issuer */
			__( "SSL Certificate Expiry Warning\n\nDomain: %1\$s\nExpires On: %2\$s\nDays Remaining: %3\$d\nIssuer: %4\$s\n\nPlease renew your SSL certificate to avoid browser security warnings.", 'forgehub-ssl-redirect' ),
			$health['host'],
			$health['valid_to'],
			(int) $days,
			$health['issuer']
		);

		wp_mail( $to, $subject, $body );
		update_option( 'wpfh_ssl_last_expiry_alert', time(), false );
	}

	/**
	 * AJAX handler: crawl homepage and recent published URLs to detect raw http:// subresources.
	 *
	 * @return void
	 */
	public function ajax_scan_mixed_content() {
		check_ajax_referer( 'wpfh_ssl_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'forgehub-ssl-redirect' ) ), 403 );
		}

		$urls = array( home_url( '/' ) );

		$recent = get_posts(
			array(
				'post_type'      => array( 'page', 'post' ),
				'post_status'    => 'publish',
				'posts_per_page' => 9,
				'orderby'        => 'date',
				'order'          => 'DESC',
				'fields'         => 'ids',
			)
		);

		foreach ( $recent as $post_id ) {
			$permalink = get_permalink( $post_id );
			if ( $permalink && ! in_array( $permalink, $urls, true ) ) {
				$urls[] = $permalink;
			}
		}

		$findings     = array();
		$scanned_urls = 0;

		foreach ( $urls as $page_url ) {
			$response = wp_remote_get(
				$page_url,
				array(
					'timeout'     => 8,
					'redirection' => 3,
					'sslverify'   => false,
				)
			);

			if ( is_wp_error( $response ) ) {
				continue;
			}

			++$scanned_urls;
			$html = wp_remote_retrieve_body( $response );
			if ( '' === $html ) {
				continue;
			}

			if ( preg_match_all( '#<(img|script|iframe|link|source|audio|video)\b[^>]*\b(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']#i', $html, $matches, PREG_SET_ORDER ) ) {
				foreach ( $matches as $match ) {
					$asset_url = esc_url_raw( $match[2] );
					// Skip XML namespace / W3C schemas.
					if ( false !== strpos( $asset_url, 'w3.org' ) || false !== strpos( $asset_url, 'schema.org' ) || false !== strpos( $asset_url, 'gmpg.org' ) ) {
						continue;
					}
					$findings[] = array(
						'page'  => esc_url_raw( $page_url ),
						'tag'   => strtolower( sanitize_key( $match[1] ) ),
						'asset' => $asset_url,
					);
				}
			}
		}

		wp_send_json_success(
			array(
				'scanned'  => $scanned_urls,
				'findings' => array_slice( $findings, 0, 50 ),
				'total'    => count( $findings ),
			)
		);
	}
}
