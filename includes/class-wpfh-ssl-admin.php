<?php
/**
 * Admin Settings Page & AJAX Actions for ForgeHub SSL Redirect Guard.
 *
 * @package ForgeHub_SSL_Redirect_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_SSL_Admin
 */
class WPFH_SSL_Admin {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_SSL_Admin|null
	 */
	private static $instance = null;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_SSL_Admin
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
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_wpfh_ssl_recheck_cert', array( $this, 'ajax_recheck_cert' ) );
		add_action( 'admin_post_wpfh_ssl_switch_urls', array( $this, 'handle_switch_urls' ) );
	}

	/**
	 * Register Settings submenu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_options_page(
			__( 'ForgeHub SSL Redirect Guard', 'forgehub-ssl-redirect' ),
			__( 'SSL Redirect Guard', 'forgehub-ssl-redirect' ),
			'manage_options',
			'forgehub-ssl-redirect',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Register plugin settings.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'wpfh_ssl_settings_group',
			WPFH_SSL_Settings::OPTION_NAME,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'WPFH_SSL_Settings', 'sanitize' ),
				'default'           => WPFH_SSL_Settings::get_defaults(),
			)
		);

		register_setting(
			'wpfh_ssl_settings_group',
			WPFH_SSL_Settings::PRO_OPTION_NAME,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'WPFH_SSL_Settings', 'sanitize_pro' ),
				'default'           => WPFH_SSL_Settings::get_pro_defaults(),
			)
		);
	}

	/**
	 * Enqueue admin CSS and JS with filemtime cache-busting.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( 'settings_page_forgehub-ssl-redirect' !== $hook ) {
			return;
		}

		$css_path = WPFH_SSL_PATH . 'assets/admin.css';
		$js_path  = WPFH_SSL_PATH . 'assets/admin.js';

		wp_enqueue_style(
			'wpfh-ssl-admin',
			WPFH_SSL_URL . 'assets/admin.css',
			array(),
			file_exists( $css_path ) ? (string) filemtime( $css_path ) : WPFH_SSL_VERSION
		);

		wp_enqueue_script(
			'wpfh-ssl-admin',
			WPFH_SSL_URL . 'assets/admin.js',
			array(),
			file_exists( $js_path ) ? (string) filemtime( $js_path ) : WPFH_SSL_VERSION,
			true
		);

		wp_localize_script(
			'wpfh-ssl-admin',
			'wpfhSslAdmin',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( 'wpfh_ssl_admin_nonce' ),
				'isPro'      => wpfh_ssl_is_pro(),
				'i18n'       => array(
					'checking'       => __( 'Checking SSL certificate...', 'forgehub-ssl-redirect' ),
					'scanning'       => __( 'Scanning pages for mixed content...', 'forgehub-ssl-redirect' ),
					'noIssues'       => __( 'Clean! No insecure http:// subresources detected on scanned pages.', 'forgehub-ssl-redirect' ),
					'requestFailed'  => __( 'Request failed. Please try again.', 'forgehub-ssl-redirect' ),
					'daysLeft'       => __( 'days remaining', 'forgehub-ssl-redirect' ),
				),
			)
		);
	}

	/**
	 * AJAX handler: force-refresh SSL certificate inspection.
	 *
	 * @return void
	 */
	public function ajax_recheck_cert() {
		check_ajax_referer( 'wpfh_ssl_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'forgehub-ssl-redirect' ) ), 403 );
		}

		$health = WPFH_SSL_Health::get_certificate_health( true );
		wp_send_json_success( $health );
	}

	/**
	 * Safely switch WordPress home and siteurl options from http:// to https://.
	 *
	 * @return void
	 */
	public function handle_switch_urls() {
		check_admin_referer( 'wpfh_ssl_switch_urls_action' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'forgehub-ssl-redirect' ) );
		}

		$home    = get_option( 'home', '' );
		$siteurl = get_option( 'siteurl', '' );

		if ( 0 === strpos( $home, 'http://' ) ) {
			update_option( 'home', preg_replace( '#^http://#i', 'https://', $home ) );
		}
		if ( 0 === strpos( $siteurl, 'http://' ) ) {
			update_option( 'siteurl', preg_replace( '#^http://#i', 'https://', $siteurl ) );
		}

		delete_transient( WPFH_SSL_Health::CACHE_KEY );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'forgehub-ssl-redirect',
					'wpfh_urls_synced' => '1',
				),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Render the Settings page.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings    = WPFH_SSL_Settings::get();
		$pro         = WPFH_SSL_Settings::get_pro();
		$is_pro      = wpfh_ssl_is_pro();
		$health      = WPFH_SSL_Health::get_certificate_health( false );
		$upgrade_url = wpfh_ssl_get_upgrade_url();

		$status_map = array(
			'valid'         => array(
				'label' => __( 'Valid SSL Certificate', 'forgehub-ssl-redirect' ),
				'class' => 'wpfh-ssl-badge--ok',
			),
			'expiring_soon' => array(
				'label' => __( 'Certificate Expiring Soon', 'forgehub-ssl-redirect' ),
				'class' => 'wpfh-ssl-badge--warn',
			),
			'expired'       => array(
				'label' => __( 'Certificate Expired', 'forgehub-ssl-redirect' ),
				'class' => 'wpfh-ssl-badge--error',
			),
			'unreachable'   => array(
				'label' => __( 'SSL Not Detected on Port 443', 'forgehub-ssl-redirect' ),
				'class' => 'wpfh-ssl-badge--error',
			),
		);

		$badge_info = isset( $status_map[ $health['status'] ] ) ? $status_map[ $health['status'] ] : $status_map['unreachable'];
		$urls_need_https = ( ! $health['home_is_https'] || ! $health['site_is_https'] );
		?>
		<div class="wrap wpfh-ssl-wrap">
			<div class="wpfh-ssl-header">
				<div>
					<h1><?php esc_html_e( 'ForgeHub SSL Redirect Guard', 'forgehub-ssl-redirect' ); ?></h1>
					<p class="wpfh-ssl-subtitle">
						<?php esc_html_e( 'Zero-bloat HTTPS enforcement, automatic mixed content protection, certificate health monitoring, and HSTS security headers.', 'forgehub-ssl-redirect' ); ?>
					</p>
				</div>
				<div class="wpfh-ssl-header-badges">
					<span class="wpfh-ssl-pill"><?php echo esc_html( 'v' . WPFH_SSL_VERSION ); ?></span>
					<?php if ( $is_pro ) : ?>
						<span class="wpfh-ssl-pill wpfh-ssl-pill--pro"><?php esc_html_e( 'PRO ACTIVE', 'forgehub-ssl-redirect' ); ?></span>
					<?php else : ?>
						<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="wpfh-ssl-btn wpfh-ssl-btn--primary">
							<?php esc_html_e( 'Upgrade to Pro', 'forgehub-ssl-redirect' ); ?>
						</a>
					<?php endif; ?>
				</div>
			</div>

			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['wpfh_urls_synced'] ) && '1' === sanitize_key( wp_unslash( $_GET['wpfh_urls_synced'] ) ) ) :
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'WordPress Site Address (home) and WordPress Address (siteurl) have been updated to HTTPS.', 'forgehub-ssl-redirect' ); ?></p>
				</div>
			<?php endif; ?>

			<!-- SSL Health Card -->
			<div class="wpfh-ssl-card" id="wpfh-ssl-health-card">
				<div class="wpfh-ssl-card-head">
					<div>
						<h2><?php esc_html_e( 'SSL Certificate & Environment Health', 'forgehub-ssl-redirect' ); ?></h2>
						<span class="wpfh-ssl-badge <?php echo esc_attr( $badge_info['class'] ); ?>" id="wpfh-ssl-status-badge">
							<?php echo esc_html( $badge_info['label'] ); ?>
						</span>
					</div>
					<button type="button" class="button wpfh-ssl-recheck-btn" id="wpfh-ssl-recheck-btn">
						<?php esc_html_e( 'Re-check SSL Now', 'forgehub-ssl-redirect' ); ?>
					</button>
				</div>

				<div class="wpfh-ssl-metrics">
					<div class="wpfh-ssl-metric">
						<span class="wpfh-ssl-metric-label"><?php esc_html_e( 'Domain', 'forgehub-ssl-redirect' ); ?></span>
						<strong id="wpfh-ssl-host"><?php echo esc_html( $health['host'] ); ?></strong>
					</div>
					<div class="wpfh-ssl-metric">
						<span class="wpfh-ssl-metric-label"><?php esc_html_e( 'Issuer', 'forgehub-ssl-redirect' ); ?></span>
						<strong id="wpfh-ssl-issuer"><?php echo esc_html( ! empty( $health['issuer'] ) ? $health['issuer'] : '—' ); ?></strong>
					</div>
					<div class="wpfh-ssl-metric">
						<span class="wpfh-ssl-metric-label"><?php esc_html_e( 'Expires On', 'forgehub-ssl-redirect' ); ?></span>
						<strong id="wpfh-ssl-expiry">
							<?php
							if ( ! empty( $health['valid_to'] ) && null !== $health['days_remaining'] ) {
								printf(
									/* translators: 1: expiry date, 2: days remaining */
									esc_html__( '%1$s (%2$d days remaining)', 'forgehub-ssl-redirect' ),
									esc_html( $health['valid_to'] ),
									(int) $health['days_remaining']
								);
							} else {
								echo '—';
							}
							?>
						</strong>
					</div>
					<div class="wpfh-ssl-metric">
						<span class="wpfh-ssl-metric-label"><?php esc_html_e( 'Site URLs Scheme', 'forgehub-ssl-redirect' ); ?></span>
						<strong id="wpfh-ssl-urls-scheme">
							<?php echo $urls_need_https ? esc_html__( 'HTTP (Needs Update)', 'forgehub-ssl-redirect' ) : esc_html__( 'HTTPS (Synced)', 'forgehub-ssl-redirect' ); ?>
						</strong>
					</div>
				</div>

				<?php if ( ! empty( $health['error_message'] ) ) : ?>
					<p class="wpfh-ssl-inline-note wpfh-ssl-inline-note--error" id="wpfh-ssl-error-msg">
						<?php echo esc_html( $health['error_message'] ); ?>
					</p>
				<?php endif; ?>

				<?php if ( $urls_need_https && $health['valid'] ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpfh-ssl-sync-bar">
						<input type="hidden" name="action" value="wpfh_ssl_switch_urls" />
						<?php wp_nonce_field( 'wpfh_ssl_switch_urls_action' ); ?>
						<span><?php esc_html_e( 'Your SSL certificate is valid, but WordPress Site/Home URLs still use http://.', 'forgehub-ssl-redirect' ); ?></span>
						<button type="submit" class="button button-primary">
							<?php esc_html_e( 'Switch Site URLs to HTTPS', 'forgehub-ssl-redirect' ); ?>
						</button>
					</form>
				<?php endif; ?>
			</div>

			<form method="post" action="options.php">
				<?php settings_fields( 'wpfh_ssl_settings_group' ); ?>

				<!-- Core Settings Card -->
				<div class="wpfh-ssl-card">
					<div class="wpfh-ssl-card-head">
						<h2><?php esc_html_e( 'Core HTTPS & Mixed Content Protection', 'forgehub-ssl-redirect' ); ?></h2>
					</div>

					<table class="form-table wpfh-ssl-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'Force HTTPS Redirect', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[enable_https_redirect]" value="1" <?php checked( $settings['enable_https_redirect'] ); ?> />
									<span><?php esc_html_e( 'Redirect all plain HTTP visitors to HTTPS automatically', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Verify your SSL certificate shows "Valid" above before enabling to prevent redirect loops.', 'forgehub-ssl-redirect' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row">
								<label for="wpfh-ssl-redirect-code"><?php esc_html_e( 'Redirect HTTP Status Code', 'forgehub-ssl-redirect' ); ?></label>
							</th>
							<td>
								<select id="wpfh-ssl-redirect-code" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[redirect_status_code]">
									<option value="301" <?php selected( (int) $settings['redirect_status_code'], 301 ); ?>>
										<?php esc_html_e( '301 Moved Permanently (Recommended for SEO)', 'forgehub-ssl-redirect' ); ?>
									</option>
									<option value="302" <?php selected( (int) $settings['redirect_status_code'], 302 ); ?>>
										<?php esc_html_e( '302 Found (Temporary — useful while testing)', 'forgehub-ssl-redirect' ); ?>
									</option>
								</select>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Reverse Proxy / Cloudflare Detection', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[respect_proxy_headers]" value="1" <?php checked( $settings['respect_proxy_headers'] ); ?> />
									<span><?php esc_html_e( 'Honor X-Forwarded-Proto and Cloudflare CF-Visitor headers', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<p class="description">
									<?php esc_html_e( 'Prevents infinite redirect loops when your site sits behind Cloudflare, Nginx proxy, or AWS/GCP load balancers.', 'forgehub-ssl-redirect' ); ?>
								</p>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Automatic Mixed Content Fixer', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[enable_mixed_content_fixer]" value="1" <?php checked( $settings['enable_mixed_content_fixer'] ); ?> />
									<span><?php esc_html_e( 'Upgrade insecure http:// images, scripts, stylesheets, and iframes on the fly', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<br />
								<label class="wpfh-ssl-toggle wpfh-ssl-subtoggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[fix_mixed_content_admin]" value="1" <?php checked( $settings['fix_mixed_content_admin'] ); ?> />
									<span><?php esc_html_e( 'Also run mixed content fixer inside the WordPress Admin dashboard', 'forgehub-ssl-redirect' ); ?></span>
								</label>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Secure Cookie Flags', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[force_secure_cookies]" value="1" <?php checked( $settings['force_secure_cookies'] ); ?> />
									<span><?php esc_html_e( 'Enforce Secure flag on authentication and logged-in cookies over HTTPS', 'forgehub-ssl-redirect' ); ?></span>
								</label>
							</td>
						</tr>

						<tr>
							<th scope="row">
								<label for="wpfh-ssl-exclude-paths"><?php esc_html_e( 'Excluded URL Paths', 'forgehub-ssl-redirect' ); ?></label>
							</th>
							<td>
								<textarea id="wpfh-ssl-exclude-paths" name="<?php echo esc_attr( WPFH_SSL_Settings::OPTION_NAME ); ?>[exclude_paths]" rows="3" class="large-text code"><?php echo esc_textarea( $settings['exclude_paths'] ); ?></textarea>
								<p class="description">
									<?php esc_html_e( 'One path prefix per line. Keep /.well-known/acme-challenge/ excluded so Let\'s Encrypt renewals never fail.', 'forgehub-ssl-redirect' ); ?>
								</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- Pro Hardening Card -->
				<div class="wpfh-ssl-card <?php echo $is_pro ? '' : 'wpfh-ssl-card--locked'; ?>">
					<div class="wpfh-ssl-card-head">
						<div>
							<h2><?php esc_html_e( 'Pro Security Headers, HSTS & Expiry Alerts', 'forgehub-ssl-redirect' ); ?></h2>
							<?php if ( ! $is_pro ) : ?>
								<span class="wpfh-ssl-pill wpfh-ssl-pill--pro"><?php esc_html_e( 'PRO', 'forgehub-ssl-redirect' ); ?></span>
							<?php endif; ?>
						</div>
						<?php if ( ! $is_pro ) : ?>
							<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="wpfh-ssl-btn wpfh-ssl-btn--primary">
								<?php esc_html_e( 'Unlock Pro Features', 'forgehub-ssl-redirect' ); ?>
							</a>
						<?php endif; ?>
					</div>

					<table class="form-table wpfh-ssl-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'HTTP Strict Transport Security (HSTS)', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[enable_hsts]" value="1" <?php checked( $pro['enable_hsts'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Send Strict-Transport-Security header on HTTPS responses', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<div class="wpfh-ssl-inline-controls">
									<label for="wpfh-ssl-hsts-age"><?php esc_html_e( 'Max-Age:', 'forgehub-ssl-redirect' ); ?></label>
									<select id="wpfh-ssl-hsts-age" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[hsts_max_age]" <?php disabled( ! $is_pro ); ?>>
										<option value="300" <?php selected( (int) $pro['hsts_max_age'], 300 ); ?>><?php esc_html_e( '5 Minutes (Testing)', 'forgehub-ssl-redirect' ); ?></option>
										<option value="86400" <?php selected( (int) $pro['hsts_max_age'], 86400 ); ?>><?php esc_html_e( '1 Day', 'forgehub-ssl-redirect' ); ?></option>
										<option value="2592000" <?php selected( (int) $pro['hsts_max_age'], 2592000 ); ?>><?php esc_html_e( '30 Days', 'forgehub-ssl-redirect' ); ?></option>
										<option value="15552000" <?php selected( (int) $pro['hsts_max_age'], 15552000 ); ?>><?php esc_html_e( '6 Months', 'forgehub-ssl-redirect' ); ?></option>
										<option value="31536000" <?php selected( (int) $pro['hsts_max_age'], 31536000 ); ?>><?php esc_html_e( '1 Year (Recommended)', 'forgehub-ssl-redirect' ); ?></option>
										<option value="63072000" <?php selected( (int) $pro['hsts_max_age'], 63072000 ); ?>><?php esc_html_e( '2 Years (Preload Standard)', 'forgehub-ssl-redirect' ); ?></option>
									</select>
								</div>
								<label class="wpfh-ssl-toggle wpfh-ssl-subtoggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[hsts_include_subdomains]" value="1" <?php checked( $pro['hsts_include_subdomains'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Include SubDomains (includeSubDomains)', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<br />
								<label class="wpfh-ssl-toggle wpfh-ssl-subtoggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[hsts_preload]" value="1" <?php checked( $pro['hsts_preload'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Enable HSTS Preload directive (requires includeSubDomains and valid SSL on all subdomains)', 'forgehub-ssl-redirect' ); ?></span>
								</label>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'CSP Upgrade & Security Headers', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[enable_csp_upgrade]" value="1" <?php checked( $pro['enable_csp_upgrade'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Send Content-Security-Policy: upgrade-insecure-requests', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<br />
								<label class="wpfh-ssl-toggle wpfh-ssl-subtoggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[enable_security_headers]" value="1" <?php checked( $pro['enable_security_headers'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Send X-Content-Type-Options: nosniff & Referrer-Policy: strict-origin-when-cross-origin', 'forgehub-ssl-redirect' ); ?></span>
								</label>
							</td>
						</tr>

						<tr>
							<th scope="row"><?php esc_html_e( 'Certificate Expiry Email Alert', 'forgehub-ssl-redirect' ); ?></th>
							<td>
								<label class="wpfh-ssl-toggle">
									<input type="checkbox" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[expiry_alert_enabled]" value="1" <?php checked( $pro['expiry_alert_enabled'] ); ?> <?php disabled( ! $is_pro ); ?> />
									<span><?php esc_html_e( 'Email me automatically before my SSL certificate expires', 'forgehub-ssl-redirect' ); ?></span>
								</label>
								<div class="wpfh-ssl-inline-controls">
									<label for="wpfh-ssl-alert-days"><?php esc_html_e( 'Warn when remaining days <=', 'forgehub-ssl-redirect' ); ?></label>
									<input id="wpfh-ssl-alert-days" type="number" min="1" max="90" class="small-text" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[expiry_alert_days]" value="<?php echo esc_attr( (int) $pro['expiry_alert_days'] ); ?>" <?php disabled( ! $is_pro ); ?> />
									<label for="wpfh-ssl-alert-email"><?php esc_html_e( 'Recipient:', 'forgehub-ssl-redirect' ); ?></label>
									<input id="wpfh-ssl-alert-email" type="email" class="regular-text" name="<?php echo esc_attr( WPFH_SSL_Settings::PRO_OPTION_NAME ); ?>[expiry_alert_email]" value="<?php echo esc_attr( $pro['expiry_alert_email'] ); ?>" <?php disabled( ! $is_pro ); ?> />
								</div>
							</td>
						</tr>
					</table>
				</div>

				<p class="submit">
					<?php submit_button( __( 'Save SSL Settings', 'forgehub-ssl-redirect' ), 'primary', 'submit', false ); ?>
				</p>
			</form>

			<!-- Pro Mixed Content Live Scanner Card -->
			<div class="wpfh-ssl-card <?php echo $is_pro ? '' : 'wpfh-ssl-card--locked'; ?>">
				<div class="wpfh-ssl-card-head">
					<div>
						<h2><?php esc_html_e( 'Mixed Content Live Scanner', 'forgehub-ssl-redirect' ); ?></h2>
						<?php if ( ! $is_pro ) : ?>
							<span class="wpfh-ssl-pill wpfh-ssl-pill--pro"><?php esc_html_e( 'PRO', 'forgehub-ssl-redirect' ); ?></span>
						<?php endif; ?>
					</div>
					<?php if ( $is_pro ) : ?>
						<button type="button" class="button button-secondary" id="wpfh-ssl-scan-btn">
							<?php esc_html_e( 'Run Mixed Content Scan', 'forgehub-ssl-redirect' ); ?>
						</button>
					<?php else : ?>
						<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="wpfh-ssl-btn wpfh-ssl-btn--secondary">
							<?php esc_html_e( 'Get Pro Scanner', 'forgehub-ssl-redirect' ); ?>
						</a>
					<?php endif; ?>
				</div>
				<p class="description">
					<?php esc_html_e( 'Crawls your homepage and recent published pages/posts to identify hardcoded http:// images, scripts, stylesheets, and iframes.', 'forgehub-ssl-redirect' ); ?>
				</p>
				<div id="wpfh-ssl-scan-results" class="wpfh-ssl-scan-results" aria-live="polite"></div>
			</div>
		</div>
		<?php
	}
}
