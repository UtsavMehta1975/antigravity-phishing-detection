/**
 * ShieldCheck Frontend API Client & Test Fixture Provider
 */

const API_BASE = window.location.origin;

export const ApiClient = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/api/health`);
    return res.json();
  },

  async scanEmail(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/scan/email`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async scanUrl(url) {
    const res = await fetch(`${API_BASE}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async scanAttachment(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/scan/attachment`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async getRecentScans() {
    const res = await fetch(`${API_BASE}/api/scans?limit=25`);
    return res.json();
  },

  async submitFeedback(scanId, target, feedbackType, overrideVerdict, analystNotes) {
    const res = await fetch(`${API_BASE}/api/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: scanId,
        target,
        feedback_type: feedbackType,
        override_verdict: overrideVerdict,
        analyst_notes: analystNotes
      })
    });
    return res.json();
  },

  async getOverrides() {
    const res = await fetch(`${API_BASE}/api/overrides`);
    return res.json();
  },

  async scanBatch(urls, maxParallel = 20) {
    const res = await fetch(`${API_BASE}/api/scan/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls, max_parallel: maxParallel })
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async getMetrics() {
    const res = await fetch(`${API_BASE}/api/metrics`);
    return res.json();
  }
};


/** Pre-packaged Sample Data Generators for 1-Click Testing */
export const SampleFixtures = {
  getSvgSmugglingEml() {
    const boundary = "----=_Part_7491_89234821";
    return `From: "Microsoft Billing Operations" <accounts-verify@sec-m365-alert.top>
To: target-analyst@corp-defense.com
Subject: ACTION REQUIRED: Your Office 365 License Has Expired
MIME-Version: 1.0
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Reply-To: credential-collector@harvest-hub.lat
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/html; charset=UTF-8

<p>Your subscription is suspended. Review the attached invoice to prevent service interruption.</p>
<a href="http://login-microsoft-security-verify.top/auth">https://admin.microsoft.com/account-status</a>

--${boundary}
Content-Type: image/svg+xml; name="invoice_details.svg"
Content-Disposition: attachment; filename="invoice_details.svg"

<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <script>
        const b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA";
        const blob = new Blob([window.atob(b64)], {type: 'application/octet-stream'});
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = "license_renew.exe";
        link.click();
      </script>
    </div>
  </foreignObject>
</svg>

--${boundary}--`;
  },

  getCleanEml() {
    return `From: "GitHub Enterprise" <notifications@github.com>
To: dev-team@corp-defense.com
Subject: [Repo Security] Dependabot Alert Resolved
MIME-Version: 1.0
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/html; charset=UTF-8

<p>All dependencies have been audited and updated to safe versions.</p>
<a href="https://github.com/security">https://github.com/security</a>`;
  }
};
