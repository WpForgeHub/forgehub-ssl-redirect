<?php
/**
 * Core SSL Redirect, Mixed Content Fixer, and Secure Cookie Engine.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_SSL_Engine
 */
class WPFH_SSL_Engine {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_SSL_Engine|null
	 */
	private static $instance = null;

	/**
	 * Cached settings.
	 *
	 * @var array
	 */
	private $settings = array();

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_SSL_Engine
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
		$this->settings = WPFH_SSL_Settings::get();

		if ( ! empty( $this->settings['enable_https_redirect'] ) ) {
			add_action( 'template_redirect', array( $this, 'maybe_redirect_to_https' ), 1 );
			add_action( 'login_init', array( $this, 'maybe_redirect_to_https' ), 1 );
		}

		if ( ! empty( $this->settings['enable_mixed_content_fixer'] ) ) {
			add_action( 'template_redirect', array( $this, 'start_mixed_content_buffer' ), 2 );
			if ( ! empty( $this->settings['fix_mixed_content_admin'] ) && is_admin() ) {
				add_action( 'admin_init', array( $this, 'start_mixed_content_buffer' ), 2 );
			}
		}

		if ( ! empty( $this->settings['force_secure_cookies'] ) ) {
			add_filter( 'secure_auth_cookie', array( $this, 'filter_secure_cookie' ), 10, 1 );
			add_filter( 'secure_logged_in_cookie', array( $this, 'filter_secure_cookie' ), 10, 1 );
			add_filter( 'secure_signon_cookie', array( $this, 'filter_secure_cookie' ), 10, 1 );
		}
	}

	/**
	 * Redirect plain HTTP requests to HTTPS when enabled and not excluded.
	 *
	 * @return void
	 */
	public function maybe_redirect_to_https() {
		if ( $this->is_non_browser_request() ) {
			return;
		}

		$respect_proxy = ! empty( $this->settings['respect_proxy_headers'] );
		if ( WPFH_SSL_Health::is_ssl_request( $respect_proxy ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		if ( $this->is_path_excluded( $request_uri ) ) {
			return;
		}

		$host = '';
		if ( ! empty( $_SERVER['HTTP_HOST'] ) ) {
			$host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
		} else {
			$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}

		if ( empty( $host ) ) {
			return;
		}

		$target_url = 'https://' . $host . $request_uri;
		$code       = ( 302 === (int) $this->settings['redirect_status_code'] ) ? 302 : 301;

		wp_safe_redirect( $target_url, $code, 'ForgeHub SSL Redirect Guard' );
		exit;
	}

	/**
	 * Start output buffering to rewrite insecure http:// asset URLs on HTTPS pages.
	 *
	 * @return void
	 */
	public function start_mixed_content_buffer() {
		if ( $this->is_non_browser_request() || is_feed() ) {
			return;
		}

		$respect_proxy = ! empty( $this->settings['respect_proxy_headers'] );
		if ( ! WPFH_SSL_Health::is_ssl_request( $respect_proxy ) ) {
			return;
		}

		ob_start( array( $this, 'filter_mixed_content_html' ) );
	}

	/**
	 * Rewrite insecure HTTP asset references in HTML output to HTTPS.
	 *
	 * @param string $buffer Output buffer HTML.
	 * @return string
	 */
	public function filter_mixed_content_html( $buffer ) {
		if ( ! is_string( $buffer ) || '' === $buffer ) {
			return $buffer;
		}

		// Skip non-HTML responses (JSON, XML, plain text).
		if ( false === stripos( $buffer, '<html' ) && false === stripos( $buffer, '<head' ) && false === stripos( $buffer, '<body' ) ) {
			return $buffer;
		}

		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		if ( empty( $host ) ) {
			return $buffer;
		}

		$quoted_host = preg_quote( $host, '#' );

		// 1. Upgrade same-host http:// URLs inside asset attributes and CSS url().
		$buffer = preg_replace(
			'#(\b(?:src|href|action|poster|data-src|data-lazy-src)\s*=\s*["\'])http://(' . $quoted_host . '[^"\']*["\'])#i',
			'$1https://$2',
			$buffer
		);

		$buffer = preg_replace(
			'#(\bsrcset\s*=\s*["\'][^"\']*)http://(' . $quoted_host . ')#i',
			'$1https://$2',
			$buffer
		);

		$buffer = preg_replace(
			'#(url\(\s*["\']?)http://(' . $quoted_host . ')#i',
			'$1https://$2',
			$buffer
		);

		// 2. Upgrade external http:// passive/active subresources (img, script, link, iframe, source).
		$buffer = preg_replace(
			'#(<(?:img|script|iframe|source|audio|video)\b[^>]*\bsrc\s*=\s*["\'])http://#i',
			'$1https://',
			$buffer
		);

		$buffer = preg_replace(
			'#(<link\b[^>]*\bhref\s*=\s*["\'])http://#i',
			'$1https://',
			$buffer
		);

		return $buffer;
	}

	/**
	 * Enforce secure cookie flags when the request is served over HTTPS.
	 *
	 * @param bool $secure Existing secure flag.
	 * @return bool
	 */
	public function filter_secure_cookie( $secure ) {
		$respect_proxy = ! empty( $this->settings['respect_proxy_headers'] );
		if ( WPFH_SSL_Health::is_ssl_request( $respect_proxy ) ) {
			return true;
		}
		return $secure;
	}

	/**
	 * Determine if the request path matches any configured exclusion prefix.
	 *
	 * @param string $request_uri Request URI.
	 * @return bool
	 */
	private function is_path_excluded( $request_uri ) {
		$raw = isset( $this->settings['exclude_paths'] ) ? (string) $this->settings['exclude_paths'] : '';
		if ( '' === trim( $raw ) ) {
			return false;
		}

		$path = (string) wp_parse_url( $request_uri, PHP_URL_PATH );
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $prefix ) {
			$prefix = trim( $prefix );
			if ( '' !== $prefix && 0 === strpos( $path, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if current request is CLI, Cron, AJAX, or REST API.
	 *
	 * @return bool
	 */
	private function is_non_browser_request() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return true;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		return false;
	}
}
