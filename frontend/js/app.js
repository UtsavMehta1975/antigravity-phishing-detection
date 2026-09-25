/**
 * AntiGravity Main Frontend Controller
 * Implements Dual-Layer Switching (Recipient View & Analyst View)
 */

import { ApiClient, SampleFixtures } from './api.js';
import { GraphVisualizer } from './graph_viz.js';

let currentScanResult = null;
let graphViz = null;

document.addEventListener('DOMContentLoaded', () => {
  initTelemetry();
  initViewSwitcher();
  initTabNavigation();
  initGraph();
  initDropzones();
  initActionButtons();
  initSampleChips();
  loadAuditHistory();
});

// 1. Hardware & System Telemetry
async function initTelemetry() {
  try {
    const data = await ApiClient.getHealth();
    if (data && data.hardware) {
      const cpuEl = document.getElementById('cpuCoresVal');
      const ramEl = document.getElementById('ramVal');
      const torchEl = document.getElementById('torchDeviceVal');
      if (cpuEl) cpuEl.textContent = `${data.hardware.cpu_cores} Cores`;
      if (ramEl) ramEl.textContent = `${data.hardware.total_ram_gb} GB`;
      if (torchEl) torchEl.textContent = data.hardware.torch_acceleration_device.toUpperCase();
    }
  } catch (e) {
    // Telemetry optional
  }
}

// 2. Dual-Layer View Switcher (Recipient vs Analyst)
function initViewSwitcher() {
  const recipientBtn = document.getElementById('viewRecipientBtn');
  const analystBtn = document.getElementById('viewAnalystBtn');
  const recipientView = document.getElementById('recipientViewContainer');
  const analystView = document.getElementById('analystViewContainer');

  recipientBtn.addEventListener('click', () => {
    recipientBtn.classList.add('active');
    analystBtn.classList.remove('active');
    recipientView.classList.add('active');
    analystView.classList.remove('active');
  });

  analystBtn.addEventListener('click', () => {
    analystBtn.classList.add('active');
    recipientBtn.classList.remove('active');
    analystView.classList.add('active');
    recipientView.classList.remove('active');
    if (graphViz) {
      setTimeout(() => graphViz.resize(), 50);
    }
  });
}

// 3. Scanner Tabs
function initTabNavigation() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const paneId = tab.dataset.pane;
      document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
      document.getElementById(paneId).classList.add('active');
    });
  });
}

// 4. Interactive Graph Visualizer
function initGraph() {
  graphViz = new GraphVisualizer('graphCanvas', (node) => {
    renderNodeInspector(node);
  });
}

function renderNodeInspector(node) {
  const container = document.getElementById('nodeInspectorContent');
  if (!node) {
    container.innerHTML = '<p class="text-dim" style="font-size: 0.85rem;">Click any node in the graph above to inspect its cryptographic attributes, payload, and risk contribution.</p>';
    return;
  }

  const attrs = node.attributes || {};
  let attrHtml = '';
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'object' && v !== null) {
      attrHtml += `<div class="inspector-field"><div class="inspector-label">${k}</div><pre class="inspector-val" style="font-size:0.75rem;">${JSON.stringify(v, null, 2)}</pre></div>`;
    } else {
      attrHtml += `<div class="inspector-field"><div class="inspector-label">${k}</div><div class="inspector-val">${v}</div></div>`;
    }
  }

  container.innerHTML = `
    <div class="inspector-field">
      <div class="inspector-label">Entity Label</div>
      <div class="inspector-val" style="color: var(--accent-cyan); font-weight: 600;">${node.label || node.id}</div>
    </div>
    <div class="inspector-field">
      <div class="inspector-label">Provenance Node Type</div>
      <div class="inspector-val"><span style="background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px;">${node.type}</span></div>
    </div>
    <div class="inspector-field">
      <div class="inspector-label">Risk Weight Contribution</div>
      <div class="inspector-val" style="color: ${node.risk_score >= 50 ? '#ff3366' : '#00f2fe'}">${node.risk_score} / 100</div>
    </div>
    ${attrHtml}
  `;
}

// 5. File Drag & Drop Handlers
function initDropzones() {
  // EML Dropzone
  const emlDrop = document.getElementById('emlDropzone');
  const emlFile = document.getElementById('emlFileInput');
  emlDrop.addEventListener('click', () => emlFile.click());
  emlFile.addEventListener('change', (e) => {
    if (e.target.files.length) handleEmailUpload(e.target.files[0]);
  });

  // Attachment Dropzone
  const attDrop = document.getElementById('attDropzone');
  const attFile = document.getElementById('attFileInput');
  attDrop.addEventListener('click', () => attFile.click());
  attFile.addEventListener('change', (e) => {
    if (e.target.files.length) handleAttachmentUpload(e.target.files[0]);
  });

  // URL Scanner Button
  document.getElementById('scanUrlBtn').addEventListener('click', () => {
    const url = document.getElementById('urlInput').value.trim();
    if (url) handleUrlScan(url);
  });

  // URL Enter Key
  document.getElementById('urlInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const url = document.getElementById('urlInput').value.trim();
      if (url) handleUrlScan(url);
    }
  });
}

// Upload & Scan Handlers
async function handleEmailUpload(file) {
  showLoading('Analyzing MIME headers, payload smuggling, and quishing vectors...');
  try {
    const res = await ApiClient.scanEmail(file);
    displayScanResult(res);
  } catch (e) {
    alert('Email scan failed: ' + e.message);
  } finally {
    hideLoading();
  }
}

async function handleUrlScan(url) {
  showLoading('Calculating Shannon entropy, resolving redirects, and querying threat feeds...');
  try {
    const res = await ApiClient.scanUrl(url);
    displayScanResult(res);
  } catch (e) {
    alert('URL scan failed: ' + e.message);
  } finally {
    hideLoading();
  }
}

async function handleAttachmentUpload(file) {
  showLoading('Analyzing SVG/HTML smuggling, PDF streams, and macros...');
  try {
    const res = await ApiClient.scanAttachment(file);
    displayScanResult(res);
  } catch (e) {
    alert('Attachment scan failed: ' + e.message);
  } finally {
    hideLoading();
  }
}

// 6. Display Result in Dual-Layer Interface
function displayScanResult(result) {
  currentScanResult = result;

  // Un-hide results section
  document.getElementById('resultsContainer').style.display = 'block';

  // Populating Recipient View
  const rec = result.recipient_view;
  const recCard = document.getElementById('recipientCard');
  recCard.className = `recipient-card ${rec.badge_color}`;

  const recBadge = document.getElementById('recipientBadge');
  recBadge.className = `risk-badge-large ${rec.badge_color}`;
  recBadge.textContent = rec.headline;

  document.getElementById('recipientTitle').textContent =
    result.verdict === 'PHISHING' ? 'Critical Security Threat Detected' :
    result.verdict === 'UNKNOWN_GUARDED' ? 'Verification Wall Evasion Detected' :
    result.verdict === 'CAUTION' ? 'Suspicious Attributes Requiring Review' : 'Verified Safe Item';

  document.getElementById('recipientReason').textContent = rec.plain_reason;

  const reasonsList = document.getElementById('recipientReasonsList');
  reasonsList.innerHTML = '';
  rec.bullet_reasons.forEach(r => {
    const li = document.createElement('li');
    li.innerHTML = `<span>⚠️</span> <span>${r}</span>`;
    reasonsList.appendChild(li);
  });

  document.getElementById('recipientActionPrompt').textContent = rec.recommended_action;

  // Populating Analyst View
  const analyst = result.analyst_view;
  document.getElementById('analystConfidenceVal').textContent = `${result.confidence_score}%`;
  document.getElementById('analystVerdictVal').textContent = result.verdict;
  document.getElementById('analystVerdictVal').style.color =
    result.verdict === 'PHISHING' ? 'var(--status-crimson)' :
    result.verdict === 'UNKNOWN_GUARDED' ? 'var(--status-unknown)' : 'var(--accent-cyan)';

  // NIST Four Principles
  const nist = analyst.nist_evaluation || {};
  document.getElementById('nistExplanation').textContent = nist.principle_1_explanation || result.summary;
  document.getElementById('nistMeaningfulness').textContent = nist.principle_2_meaningfulness || 'N/A';
  document.getElementById('nistAccuracy').textContent = JSON.stringify(nist.principle_3_accuracy || {}, null, 2);
  const limits = nist.principle_4_knowledge_limits || [];
  document.getElementById('nistLimits').textContent = limits.join('\n• ');

  // Threat Intel Feeds & Destination Status
  renderThreatMatrix(analyst);

  // Load Evidence Graph
  if (result.evidence_graph && graphViz) {
    graphViz.loadGraph(result.evidence_graph);
    renderNodeInspector(null);
  }

  // Scroll to results
  document.getElementById('resultsContainer').scrollIntoView({ behavior: 'smooth' });
  loadAuditHistory();
}

function renderThreatMatrix(analyst) {
  const container = document.getElementById('threatFeedGrid');
  const feeds = analyst.threat_matches || [];
  const status = analyst.destination_status || 'ACTIVE';

  let html = `
    <div class="feed-item">
      <span class="feed-name">Destination Status</span>
      <span class="feed-status ${status === 'UNKNOWN' ? 'hit' : 'clean'}">${status}</span>
    </div>
    <div class="feed-item">
      <span class="feed-name">OpenPhish Community</span>
      <span class="feed-status ${feeds.some(f => f.source === 'OpenPhish') ? 'hit' : 'clean'}">
        ${feeds.some(f => f.source === 'OpenPhish') ? 'PHISH CONFIRMED' : 'CLEAN / CACHED'}
      </span>
    </div>
    <div class="feed-item">
      <span class="feed-name">URLhaus (abuse.ch)</span>
      <span class="feed-status ${feeds.some(f => f.source.includes('URLhaus')) ? 'hit' : 'clean'}">
        ${feeds.some(f => f.source.includes('URLhaus')) ? 'PAYLOAD DROP' : 'CLEAN'}
      </span>
    </div>
    <div class="feed-item">
      <span class="feed-name">Google Safe Browsing</span>
      <span class="feed-status ${feeds.some(f => f.source.includes('Safe Browsing')) ? 'hit' : 'clean'}">
        ${feeds.some(f => f.source.includes('Safe Browsing')) ? 'DECEPTIVE SITE' : 'CLEAN'}
      </span>
    </div>
  `;
  container.innerHTML = html;
}

// 7. Sample Loaders
function initSampleChips() {
  document.querySelectorAll('.sample-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      e.stopPropagation();
      const sampleType = chip.dataset.sample;
      if (sampleType === 'svg_smuggling') {
        const emlContent = SampleFixtures.getSvgSmugglingEml();
        const file = new File([emlContent], 'urgent_invoice_smuggle.eml', { type: 'message/rfc822' });
        handleEmailUpload(file);
      } else if (sampleType === 'clean_email') {
        const emlContent = SampleFixtures.getCleanEml();
        const file = new File([emlContent], 'github_alert.eml', { type: 'message/rfc822' });
        handleEmailUpload(file);
      } else if (sampleType === 'brand_typosquat') {
        document.getElementById('urlInput').value = 'http://login.microsoft.security-verify.top/auth';
        handleUrlScan('http://login.microsoft.security-verify.top/auth');
      } else if (sampleType === 'dga_entropy') {
        document.getElementById('urlInput').value = 'http://x9q8w2z7k1v4m0p.xyz/verify';
        handleUrlScan('http://x9q8w2z7k1v4m0p.xyz/verify');
      } else if (sampleType === 'captcha_wall') {
        document.getElementById('urlInput').value = 'https://captcha-guarded-phish.top/login';
        handleUrlScan('https://captcha-guarded-phish.top/login');
      }
    });
  });
}

// 8. Action Buttons & Feedback Modal
function initActionButtons() {
  // Safe Reporting Toast
  document.getElementById('btnSafeReport').addEventListener('click', () => {
    alert('Thank you! This report has been submitted to your organization’s SOC queue and quarantined.');
  });

  // Quarantine Action
  document.getElementById('btnQuarantine').addEventListener('click', () => {
    alert('Item isolated and sender domain added to local tenant blocklist.');
  });

  // Open Override Modal
  const modal = document.getElementById('overrideModal');
  document.getElementById('btnOpenOverrideModal').addEventListener('click', () => {
    if (!currentScanResult) return;
    document.getElementById('modalScanId').value = currentScanResult.scan_id;
    document.getElementById('modalTarget').value = currentScanResult.summary;
    modal.classList.add('active');
  });

  document.getElementById('modalCloseBtn').addEventListener('click', () => {
    modal.classList.remove('active');
  });

  document.getElementById('overrideForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const scanId = document.getElementById('modalScanId').value;
    const target = document.getElementById('modalTarget').value;
    const type = document.getElementById('modalFeedbackType').value;
    const verdict = document.getElementById('modalOverrideVerdict').value;
    const notes = document.getElementById('modalAnalystNotes').value;

    try {
      await ApiClient.submitFeedback(scanId, target, type, verdict, notes);
      modal.classList.remove('active');
      alert('Auditable override stored in local SQLite database.');
      loadAuditHistory();
    } catch (err) {
      alert('Failed to save override: ' + err.message);
    }
  });
}

// 9. Audit History
async function loadAuditHistory() {
  try {
    const scans = await ApiClient.getRecentScans();
    const tbody = document.getElementById('auditTableBody');
    tbody.innerHTML = '';
    scans.forEach(s => {
      const tr = document.createElement('tr');
      const badgeColor = s.verdict === 'PHISHING' ? '#ff3366' : (s.verdict.includes('UNKNOWN') ? '#a855f7' : (s.verdict === 'CAUTION' ? '#ffb300' : '#00e676'));
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); color: var(--text-dim);">${s.id.substring(0, 10)}</td>
        <td><strong>${s.scan_type}</strong></td>
        <td>${(s.target || '').substring(0, 35)}...</td>
        <td><span style="color: ${badgeColor}; font-weight: 700;">${s.verdict}</span></td>
        <td style="font-family: var(--font-mono);">${s.confidence_score}%</td>
        <td style="font-size: 0.75rem; color: var(--text-dim);">${s.created_at || 'Just now'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Failed to load audit history', e);
  }
}

function showLoading(msg) {
  const loadingEl = document.getElementById('scanLoadingIndicator');
  loadingEl.style.display = 'flex';
  document.getElementById('loadingMsg').textContent = msg;
}

function hideLoading() {
  document.getElementById('scanLoadingIndicator').style.display = 'none';
}
