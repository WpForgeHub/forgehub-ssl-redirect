<?php
/**
 * Plugin Name:       ForgeHub SSL Redirect Guard
 * Plugin URI:        https://wpforgehub.com/product/ssl-redirect/
 * Description:       Force HTTP to HTTPS 301 redirects, fix mixed content automatically, monitor SSL certificate health, and enable HSTS with zero server bloat.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WPForgeHub
 * Author URI:        https://wpforgehub.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       forgehub-ssl-redirect
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPFH_SSL_VERSION', '1.0.0' );
define( 'WPFH_SSL_FILE', __FILE__ );
define( 'WPFH_SSL_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPFH_SSL_URL', plugin_dir_url( __FILE__ ) );

// <wpfh-pro-only>
/**
 * Freemius SDK helper wrapper (included only in the Pro build).
 *
 * @return object
 */
if ( ! function_exists( 'wpfh_ssl_fs' ) ) {
	function wpfh_ssl_fs() {
		global $wpfh_ssl_fs;

		if ( ! isset( $wpfh_ssl_fs ) ) {
			$fs_config = apply_filters(
				'wpfh_ssl_fs_config',
				array(
					'id'         => get_option( 'wpfh_ssl_fs_id', '' ),
					'public_key' => get_option( 'wpfh_ssl_fs_public_key', '' ),
				)
			);
			$force_pro = defined( 'WPFH_SSL_FORCE_PRO' ) && WPFH_SSL_FORCE_PRO;
			$fs_path   = WPFH_SSL_PATH . 'freemius/start.php';

			if ( ! $force_pro && ! empty( $fs_config['id'] ) && ! empty( $fs_config['public_key'] ) && file_exists( $fs_path ) ) {
				require_once $fs_path;
				$wpfh_ssl_fs = fs_dynamic_init(
					array(
						'id'             => (string) $fs_config['id'],
						'slug'           => 'forgehub-ssl-redirect',
						'type'           => 'plugin',
						'public_key'     => (string) $fs_config['public_key'],
						'is_premium'     => false,
						'has_addons'     => false,
						'has_paid_plans' => true,
						'menu'           => array(
							'slug'       => 'forgehub-ssl-redirect',
							'first-path' => 'options-general.php?page=forgehub-ssl-redirect',
							'parent'     => array(
								'slug' => 'options-general.php',
							),
						),
					)
				);
				$wpfh_ssl_fs->add_action( 'after_uninstall', 'wpfh_ssl_uninstall_cleanup' );
			} else {
				$wpfh_ssl_fs = new class( $force_pro ) {
					private $force_pro;

					public function __construct( $force_pro = false ) {
						$this->force_pro = (bool) $force_pro;
					}

					public function can_use_premium_code() {
						if ( $this->force_pro ) {
							return true;
						}
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_can_use_premium_code__forgehub-ssl-redirect', false );
					}

					public function is__premium_only() {
						return $this->can_use_premium_code();
					}

					public function is_plan( $plan ) {
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_is_plan__forgehub-ssl-redirect', false, $plan );
					}

					public function get_upgrade_url() {
						return 'https://wpforgehub.com/product/ssl-redirect/#pricing';
					}
				};
			}
		}

		return $wpfh_ssl_fs;
	}

	wpfh_ssl_fs();
}

/**
 * Cleanup plugin data on uninstall (Pro build via after_uninstall hook).
 *
 * @return void
 */
function wpfh_ssl_uninstall_cleanup() {
	delete_option( 'wpfh_ssl_settings' );
	delete_option( 'wpfh_ssl_pro_settings' );
	delete_option( 'wpfh_ssl_last_expiry_alert' );
	delete_transient( 'wpfh_ssl_cert_health' );
	wp_clear_scheduled_hook( 'wpfh_ssl_daily_cert_check' );
}
// </wpfh-pro-only>

/**
 * Return the canonical upgrade URL.
 *
 * @return string
 */
function wpfh_ssl_get_upgrade_url() {
	$url = 'https://wpforgehub.com/product/ssl-redirect/#pricing';
	// <wpfh-pro-only>
	if ( function_exists( 'wpfh_ssl_fs' ) ) {
		$url = wpfh_ssl_fs()->get_upgrade_url();
	}
	// </wpfh-pro-only>
	return $url;
}

/**
 * Check whether Pro features are available and licensed.
 *
 * @return bool
 */
function wpfh_ssl_is_pro() {
	$is_pro = false;
	// <wpfh-pro-only>
	$is_pro = file_exists( WPFH_SSL_PATH . 'includes/pro/class-wpfh-ssl-pro.php' )
		&& function_exists( 'wpfh_ssl_fs' )
		&& wpfh_ssl_fs()->can_use_premium_code();
	// </wpfh-pro-only>
	return $is_pro;
}

/**
 * Main Plugin Bootstrap Class.
 */
final class WPFH_SSL_Redirect_Guard {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_SSL_Redirect_Guard|null
	 */
	private static $instance = null;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_SSL_Redirect_Guard
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
		add_action( 'plugins_loaded', array( $this, 'init' ), 10 );
		add_filter( 'plugin_action_links_' . plugin_basename( WPFH_SSL_FILE ), array( $this, 'action_links' ) );
		register_deactivation_hook( WPFH_SSL_FILE, array( $this, 'on_deactivate' ) );
	}

	/**
	 * Initialize plugin modules.
	 *
	 * @return void
	 */
	public function init() {
		require_once WPFH_SSL_PATH . 'includes/class-wpfh-ssl-settings.php';
		require_once WPFH_SSL_PATH . 'includes/class-wpfh-ssl-health.php';
		require_once WPFH_SSL_PATH . 'includes/class-wpfh-ssl-engine.php';
		require_once WPFH_SSL_PATH . 'includes/class-wpfh-ssl-admin.php';

		WPFH_SSL_Engine::get_instance();
		WPFH_SSL_Admin::get_instance();

		// <wpfh-pro-only>
		if ( wpfh_ssl_is_pro() ) {
			$pro_file = WPFH_SSL_PATH . 'includes/pro/class-wpfh-ssl-pro.php';
			if ( file_exists( $pro_file ) ) {
				require_once $pro_file;
				WPFH_SSL_Pro::get_instance();
			}
		}
		// </wpfh-pro-only>
	}

	/**
	 * Clear scheduled hooks on plugin deactivation.
	 *
	 * @return void
	 */
	public function on_deactivate() {
		wp_clear_scheduled_hook( 'wpfh_ssl_daily_cert_check' );
		delete_transient( 'wpfh_ssl_cert_health' );
	}

	/**
	 * Add Settings link to the Plugins screen.
	 *
	 * @param array $links Existing action links.
	 * @return array
	 */
	public function action_links( $links ) {
		$settings_url = admin_url( 'options-general.php?page=forgehub-ssl-redirect' );
		$custom_links = array(
			'<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'forgehub-ssl-redirect' ) . '</a>',
		);

		if ( ! wpfh_ssl_is_pro() ) {
			$custom_links[] = '<a href="' . esc_url( wpfh_ssl_get_upgrade_url() ) . '" target="_blank" rel="noopener noreferrer" style="color:#4f46e5;font-weight:600;">' . esc_html__( 'Upgrade to Pro', 'forgehub-ssl-redirect' ) . '</a>';
		}

		return array_merge( $custom_links, $links );
	}
}

WPFH_SSL_Redirect_Guard::get_instance();
