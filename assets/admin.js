(function () {
	'use strict';

	if (typeof wpfhSslAdmin === 'undefined') {
		return;
	}

	var recheckBtn = document.getElementById('wpfh-ssl-recheck-btn');
	if (recheckBtn) {
		recheckBtn.addEventListener('click', function () {
			var originalText = recheckBtn.textContent;
			recheckBtn.disabled = true;
			recheckBtn.textContent = wpfhSslAdmin.i18n.checking;

			var body = new URLSearchParams();
			body.append('action', 'wpfh_ssl_recheck_cert');
			body.append('nonce', wpfhSslAdmin.nonce);

			fetch(wpfhSslAdmin.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			})
				.then(function (res) {
					return res.json();
				})
				.then(function (payload) {
					if (!payload || !payload.success || !payload.data) {
						return;
					}
					var d = payload.data;
					var issuerEl = document.getElementById('wpfh-ssl-issuer');
					var expiryEl = document.getElementById('wpfh-ssl-expiry');
					var badgeEl = document.getElementById('wpfh-ssl-status-badge');

					if (issuerEl) {
						issuerEl.textContent = d.issuer || '—';
					}
					if (expiryEl) {
						if (d.valid_to && d.days_remaining !== null) {
							expiryEl.textContent = d.valid_to + ' (' + d.days_remaining + ' ' + wpfhSslAdmin.i18n.daysLeft + ')';
						} else {
							expiryEl.textContent = '—';
						}
					}
					if (badgeEl) {
						badgeEl.className = 'wpfh-ssl-badge ' + (d.status === 'valid' ? 'wpfh-ssl-badge--ok' : d.status === 'expiring_soon' ? 'wpfh-ssl-badge--warn' : 'wpfh-ssl-badge--error');
						badgeEl.textContent = d.status === 'valid' ? 'Valid SSL Certificate' : d.status === 'expiring_soon' ? 'Certificate Expiring Soon' : d.status === 'expired' ? 'Certificate Expired' : 'SSL Not Detected on Port 443';
					}
				})
				.catch(function () {
					// Silent fallback; button re-enables below.
				})
				.finally(function () {
					recheckBtn.disabled = false;
					recheckBtn.textContent = originalText;
				});
		});
	}

	var scanBtn = document.getElementById('wpfh-ssl-scan-btn');
	var scanBox = document.getElementById('wpfh-ssl-scan-results');
	if (scanBtn && scanBox) {
		scanBtn.addEventListener('click', function () {
			var originalText = scanBtn.textContent;
			scanBtn.disabled = true;
			scanBox.textContent = wpfhSslAdmin.i18n.scanning;

			var body = new URLSearchParams();
			body.append('action', 'wpfh_ssl_scan_mixed_content');
			body.append('nonce', wpfhSslAdmin.nonce);

			fetch(wpfhSslAdmin.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			})
				.then(function (res) {
					return res.json();
				})
				.then(function (payload) {
					scanBox.textContent = '';
					if (!payload || !payload.success || !payload.data) {
						scanBox.textContent = wpfhSslAdmin.i18n.requestFailed;
						return;
					}
					var findings = payload.data.findings || [];
					if (findings.length === 0) {
						var okP = document.createElement('p');
						okP.className = 'wpfh-ssl-badge wpfh-ssl-badge--ok';
						okP.textContent = wpfhSslAdmin.i18n.noIssues + ' (' + payload.data.scanned + ' pages)';
						scanBox.appendChild(okP);
						return;
					}

					var table = document.createElement('table');
					table.className = 'wpfh-ssl-scan-table';
					var thead = document.createElement('thead');
					var hr = document.createElement('tr');
					['Page', 'Tag', 'Insecure Asset URL'].forEach(function (label) {
						var th = document.createElement('th');
						th.textContent = label;
						hr.appendChild(th);
					});
					thead.appendChild(hr);
					table.appendChild(thead);

					var tbody = document.createElement('tbody');
					findings.forEach(function (item) {
						var tr = document.createElement('tr');
						[item.page, '<' + item.tag + '>', item.asset].forEach(function (val) {
							var td = document.createElement('td');
							td.textContent = val;
							tr.appendChild(td);
						});
						tbody.appendChild(tr);
					});
					table.appendChild(tbody);
					scanBox.appendChild(table);
				})
				.catch(function () {
					scanBox.textContent = wpfhSslAdmin.i18n.requestFailed;
				})
				.finally(function () {
					scanBtn.disabled = false;
					scanBtn.textContent = originalText;
				});
		});
	}
})();
