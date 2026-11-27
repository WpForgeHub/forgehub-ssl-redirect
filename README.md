![ForgeHub SSL Redirect Guard](assets/banner-1544x500.png)

# ForgeHub SSL Redirect Guard

![Version](https://img.shields.io/badge/Version-1.0.0-0ea5e9?style=flat-square)
![License](https://img.shields.io/badge/License-GPLv2%20or%20later-10b981?style=flat-square)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-818cf8?style=flat-square)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-38bdf8?style=flat-square)
![WordPress.org](https://img.shields.io/badge/WP.org-Ready-22c55e?style=flat-square)
![Freemius](https://img.shields.io/badge/Pro-Freemius-f97316?style=flat-square)
![Architecture](https://img.shields.io/badge/Zero%20Bloat-100%25%20Local-0f172a?style=flat-square)
![Accessibility](https://img.shields.io/badge/WCAG%202.1%20AA-Compliant-14b8a6?style=flat-square)

Zero-bloat HTTP to HTTPS 301 redirect enforcement, automatic mixed content fixer, live SSL certificate health monitoring, and HSTS security headers.

## Free vs Pro Comparison

| Feature | Free | Pro |
| :--- | :---: | :---: |
| HTTP to HTTPS 301 / 302 Redirect | ✅ | ✅ |
| Cloudflare & Reverse Proxy Loop Protection | ✅ | ✅ |
| Automatic Mixed Content Fixer (Frontend + Optional Admin) | ✅ | ✅ |
| Live SSL Certificate Health & Expiry Inspector | ✅ | ✅ |
| One-Click Site & Home URL HTTPS Switcher | ✅ | ✅ |
| Secure Cookie Flag Enforcement | ✅ | ✅ |
| Custom Excluded URL Paths (ACME Safe) | ✅ | ✅ |
| HSTS (`Strict-Transport-Security`) + `includeSubDomains` + `preload` | — | ✅ |
| CSP `upgrade-insecure-requests` & Security Headers | — | ✅ |
| Automated SSL Expiry Email Alerts (Daily Cron) | — | ✅ |
| Mixed Content Live Page Scanner | — | ✅ |

---

## 📸 Admin Preview

<p align="center">
  <img src="assets/screenshot-1.png" alt="ForgeHub SSL Redirect Guard WordPress Admin Settings" width="100%" />
</p>

## Installation

1. Upload `forgehub-ssl-redirect` to `/wp-content/plugins/`.
2. Activate the plugin in **Admin > Plugins**.
3. Open **Settings > SSL Redirect Guard**, verify SSL health, and enable HTTPS redirect.

## Links

- Product Page: https://wpforgehub.com/product/ssl-redirect/
- Documentation: https://wpforgehub.com/docs/
- Support: [WPForgeHub Support Portal](https://wpforgehub.com/support/) & [GitHub Issues](https://github.com/WpForgeHub/forgehub-ssl-redirect/issues)
