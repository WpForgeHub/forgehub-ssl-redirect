=== ForgeHub SSL Redirect Guard ===
Contributors: wpforgehub
Tags: ssl, https, redirect, mixed content, hsts
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Force HTTP to HTTPS 301 redirects, fix mixed content automatically, check SSL certificate health, and enforce secure cookies with zero bloat.

== Description ==

**ForgeHub SSL Redirect Guard** gives every newly launched site a rock-solid, zero-bloat HTTPS setup in seconds—without modifying `.htaccess` or slowing down your server.

When a site moves to HTTPS, visitors often hit insecure `http://` links, broken padlock warnings from mixed content, or infinite redirect loops behind Cloudflare and reverse proxies. ForgeHub SSL Redirect Guard solves all of these cleanly from one lightweight settings screen.

### Key Features (Free Version)
* **One-Click HTTP to HTTPS Redirect (301 or 302)**: Safely redirects plain HTTP traffic to HTTPS while automatically skipping CLI, Cron, AJAX, REST, and Let's Encrypt ACME challenge paths.
* **Reverse Proxy & Cloudflare Safe**: Respects `X-Forwarded-Proto`, `X-Forwarded-SSL`, and `CF-Visitor` headers to prevent infinite redirect loops behind proxies and CDNs.
* **Automatic Mixed Content Fixer**: Lightweight output buffer upgrades insecure `http://` images, scripts, stylesheets, and iframes to `https://` on the fly.
* **Live SSL Certificate Health Inspector**: Checks your domain's TLS certificate on port 443 and displays issuer, expiry date, remaining days, and `home`/`siteurl` scheme status.
* **One-Click Site URL HTTPS Sync**: Safely switches `home` and `siteurl` options to `https://` once your SSL certificate is verified.
* **Secure Cookie Enforcement**: Automatically sets the `Secure` flag on authentication and logged-in cookies over HTTPS.
* **Custom Path Exclusions**: Exclude specific URL prefixes such as `/.well-known/acme-challenge/` from HTTPS redirects.

### Pro Features (Separate Commercial Plugin)
Need enterprise transport security and proactive monitoring? The separate commercial Pro edition is available at [WPForgeHub](https://wpforgehub.com/product/ssl-redirect/) and is not bundled in this free plugin:
* **HSTS (`Strict-Transport-Security`) + Preload**: Configure `max-age`, `includeSubDomains`, and `preload` directives safely from the dashboard.
* **CSP `upgrade-insecure-requests` & Security Headers**: Automatically emit `Content-Security-Policy: upgrade-insecure-requests`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
* **SSL Certificate Expiry Email Alerts**: Daily local WP-Cron monitor emails you before your TLS certificate expires.
* **Mixed Content Live Scanner**: Crawls your homepage and recent pages/posts to pinpoint exact hardcoded `http://` asset references.

== Installation ==

1. Upload the `forgehub-ssl-redirect` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu.
3. Navigate to **Settings > SSL Redirect Guard**.
4. Verify your SSL certificate shows **Valid SSL Certificate**, then enable **Force HTTPS Redirect** and click **Save SSL Settings**.

== Frequently Asked Questions ==

= Will activating this plugin lock me out if SSL is not installed yet? =
No. Force HTTPS Redirect is disabled by default on fresh installations so you can verify your SSL certificate health first and enable redirects safely.

= Does this work behind Cloudflare or an Nginx reverse proxy? =
Yes. Reverse Proxy / Cloudflare header detection is enabled by default to detect upstream HTTPS termination and prevent redirect loops.

= Does it modify my .htaccess or server config files? =
No. All redirects, mixed content fixes, and headers run cleanly inside PHP without risking broken `.htaccess` rewrites.

= Does this plugin send any data to external servers? =
No. Certificate checks connect directly to your own domain on port 443, and all settings and scans stay 100% local.

= How do I exclude Let's Encrypt renewal paths from redirects? =
`/.well-known/acme-challenge/` is excluded by default in the Excluded URL Paths setting.

== Screenshots ==

1. SSL Redirect Guard settings panel showing live SSL certificate health, HTTPS redirect controls, mixed content fixer, and HSTS security options.

== Changelog ==

= 1.0.0 =
* Initial stable release with HTTP to HTTPS 301/302 redirects, Cloudflare/proxy detection, automatic mixed content fixer, live SSL certificate health inspector, secure cookie flags, and Pro HSTS/CSP/expiry alerts/scanner.
