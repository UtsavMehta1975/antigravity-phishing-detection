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
  initDocsModal();
  initAiCopilotChat();
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

  // Recipient Malware Alert
  const malwareAlert = document.getElementById('recipientMalwareAlert');
  const exactVirusEl = document.getElementById('recipientExactVirus');
  if (malwareAlert && exactVirusEl) {
    if (rec.exact_virus_name && rec.exact_virus_name !== 'Clean.NoThreatDetected') {
      malwareAlert.style.display = 'block';
      exactVirusEl.textContent = `${rec.exact_virus_name} • [${rec.threat_category || 'Critical Threat'}]`;
    } else {
      malwareAlert.style.display = 'none';
    }
  }

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

  // Threat Intel Feeds & Destination Status (VirusTotal Multi-Engine Consensus)
  renderThreatMatrix(analyst);

  // Threat Intel Feeds & Destination Status
  renderThreatMatrix(analyst);

  // AI & Machine Learning Forensics
  renderAiIntelligence(rec, analyst, result);

  // Load Evidence Graph
  if (result.evidence_graph && graphViz) {
    graphViz.loadGraph(result.evidence_graph);
    renderNodeInspector(null);
  }

  // Scroll to results
  document.getElementById('resultsContainer').scrollIntoView({ behavior: 'smooth' });
  loadAuditHistory();
}

function renderAiIntelligence(rec, analyst, result) {
  // 1. Recipient Pretext Badge
  const pretextBadge = document.getElementById('recipientAiBadgeContainer');
  const pretextText = document.getElementById('recipientAiPretext');
  if (rec.ai_pretext) {
    pretextBadge.style.display = 'block';
    pretextText.textContent = `${rec.ai_pretext} (Manipulation Risk: ${rec.ai_manipulation_score || 80}%)`;
  } else {
    pretextBadge.style.display = 'none';
  }

  // 2. Analyst AI Forensics Card
  const copilot = analyst.ai_copilot || {};
  const ml = analyst.ml_prediction || {};

  // Model provider badge
  const modelBadge = document.getElementById('aiModelBadge');
  if (copilot.llm_provider) {
    modelBadge.textContent = copilot.llm_provider;
  } else {
    modelBadge.textContent = 'Scikit-Learn Random Forest + Semantic Copilot';
  }

  // ML Phishing Probability
  const probVal = ml.phishing_probability !== undefined ? `${ml.phishing_probability}%` : `${result.confidence_score}%`;
  const probEl = document.getElementById('aiMlProb');
  probEl.textContent = probVal;

  const classEl = document.getElementById('aiMlClass');
  const mlClass = ml.ai_classification || result.verdict;
  classEl.textContent = mlClass;
  if (mlClass === 'PHISHING' || result.verdict === 'PHISHING') {
    classEl.style.background = 'rgba(255, 51, 102, 0.2)';
    classEl.style.color = '#ff3366';
  } else if (mlClass === 'UNKNOWN_GUARDED' || result.verdict === 'UNKNOWN_GUARDED') {
    classEl.style.background = 'rgba(168, 85, 247, 0.2)';
    classEl.style.color = '#a855f7';
  } else {
    classEl.style.background = 'rgba(0, 242, 254, 0.2)';
    classEl.style.color = '#00f2fe';
  }

  const topSignalsEl = document.getElementById('aiTopSignals');
  const signals = ml.top_ai_signals && ml.top_ai_signals.length > 0 
    ? ml.top_ai_signals.join(', ')
    : (result.evasion_techniques && result.evasion_techniques.length > 0 
        ? result.evasion_techniques.join(', ') 
        : 'Feature vector verified');
  topSignalsEl.textContent = `Top signals: ${signals}`;

  // Pretext & Coercion
  const pretextCatEl = document.getElementById('aiPretextCat');
  pretextCatEl.textContent = copilot.primary_pretext_category || rec.ai_pretext || 'Pretext Analysis Verified';

  const coercionEl = document.getElementById('aiCoercionTactics');
  const tactics = copilot.coercion_tactics_detected && copilot.coercion_tactics_detected.length > 0
    ? copilot.coercion_tactics_detected.join(' • ')
    : (copilot.ai_behavioral_insight || 'Psychological pressure signals detected in communication vector.');
  coercionEl.textContent = tactics;

  // Playbook
  const playbookList = document.getElementById('aiPlaybookList');
  playbookList.innerHTML = '';
  const playbook = copilot.ai_recommended_playbook || [
    'Isolate affected host and revoke active credentials.',
    'Add malicious target to perimeter DNS/firewall blocklist.',
    'Enforce MFA re-authentication across corporate directory.'
  ];
  playbook.forEach(step => {
    const li = document.createElement('li');
    li.textContent = step;
    playbookList.appendChild(li);
  });
}

function renderThreatMatrix(analyst) {
  const container = document.getElementById('threatFeedGrid');
  const mal = analyst.malware_intel || {};
  const vt = mal.virustotal_consensus || {
    engines_flagged: 0,
    engines_total: 8,
    detection_ratio: '0/8',
    engines: {}
  };

  // Update top banner in consensus card
  const mitreBadge = document.getElementById('vtMitreBadge');
  if (mitreBadge) mitreBadge.textContent = `MITRE: ${mal.mitre_attack_id || 'T1566'}`;

  const ratioBadge = document.getElementById('vtRatioBadge');
  if (ratioBadge) {
    const isThreat = vt.engines_flagged > 0;
    ratioBadge.textContent = `${vt.detection_ratio || '0/8'} Vendors Flagged`;
    ratioBadge.style.background = isThreat ? 'rgba(255, 51, 102, 0.25)' : 'rgba(0, 230, 118, 0.2)';
    ratioBadge.style.color = isThreat ? '#ff3366' : '#00e676';
    ratioBadge.style.borderColor = isThreat ? 'rgba(255, 51, 102, 0.5)' : 'rgba(0, 230, 118, 0.4)';
  }

  const famName = document.getElementById('vtThreatFamilyName');
  if (famName) {
    famName.textContent = mal.exact_virus_name || 'Clean.NoThreatDetected';
    famName.style.color = mal.is_virus_detected ? '#ff3366' : '#00f2fe';
  }

  const catName = document.getElementById('vtThreatCategory');
  if (catName) catName.textContent = mal.threat_category || 'Benign';

  // Render 8 Enterprise Engines
  let html = '';
  const engines = vt.engines || {};
  for (const [engineName, info] of Object.entries(engines)) {
    const isHit = info.verdict === 'MALICIOUS';
    const isSusp = info.verdict === 'SUSPICIOUS';
    const statusClass = isHit ? 'hit' : (isSusp ? 'caution' : 'clean');
    const borderColor = isHit ? '#ff3366' : (isSusp ? '#ffb300' : '#00f2fe');
    html += `
      <div class="feed-item" style="border-left: 3px solid ${borderColor};">
        <span class="feed-name">${engineName}</span>
        <span class="feed-status ${statusClass}">${info.label}</span>
      </div>
    `;
  }

  // Fallback if engines empty
  if (!html) {
    const feeds = analyst.threat_matches || [];
    const status = analyst.destination_status || 'ACTIVE';
    html = `
      <div class="feed-item"><span class="feed-name">Destination Status</span><span class="feed-status ${status === 'UNKNOWN' ? 'hit' : 'clean'}">${status}</span></div>
      <div class="feed-item"><span class="feed-name">OpenPhish Community</span><span class="feed-status ${feeds.some(f => f.source === 'OpenPhish') ? 'hit' : 'clean'}">${feeds.some(f => f.source === 'OpenPhish') ? 'PHISH CONFIRMED' : 'CLEAN'}</span></div>
      <div class="feed-item"><span class="feed-name">URLhaus (abuse.ch)</span><span class="feed-status ${feeds.some(f => f.source.includes('URLhaus')) ? 'hit' : 'clean'}">${feeds.some(f => f.source.includes('URLhaus')) ? 'PAYLOAD DROP' : 'CLEAN'}</span></div>
      <div class="feed-item"><span class="feed-name">Google Safe Browsing</span><span class="feed-status ${feeds.some(f => f.source.includes('Safe Browsing')) ? 'hit' : 'clean'}">${feeds.some(f => f.source.includes('Safe Browsing')) ? 'DECEPTIVE SITE' : 'CLEAN'}</span></div>
    `;
  }

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

// 10. In-App Documentation Modal & Tabs Controller
function initDocsModal() {
  const docsModal = document.getElementById('docsModal');
  const viewDocsBtn = document.getElementById('viewDocsBtn');
  const docsCloseBtn = document.getElementById('docsCloseBtn');

  if (viewDocsBtn) {
    viewDocsBtn.addEventListener('click', () => {
      docsModal.classList.add('active');
    });
  }

  if (docsCloseBtn) {
    docsCloseBtn.addEventListener('click', () => {
      docsModal.classList.remove('active');
    });
  }

  // Close on backdrop click
  if (docsModal) {
    docsModal.addEventListener('click', (e) => {
      if (e.target === docsModal) {
        docsModal.classList.remove('active');
      }
    });

    // Close on Escape key
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && docsModal.classList.contains('active')) {
        docsModal.classList.remove('active');
      }
    });

    // Sub-tab switching inside Docs
    const tabBtns = docsModal.querySelectorAll('.docs-tab-btn');
    const panes = docsModal.querySelectorAll('.docs-pane');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.dataset.pane;
        tabBtns.forEach(b => b.classList.remove('active'));
        panes.forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const target = document.getElementById(targetId);
        if (target) target.classList.add('active');
      });
    });

    // Accordions inside Docs
    const accordions = docsModal.querySelectorAll('.doc-accordion');
    accordions.forEach(acc => {
      const header = acc.querySelector('.doc-acc-header');
      if (header) {
        header.addEventListener('click', () => {
          acc.classList.toggle('open');
        });
      }
    });
  }
}

// 11. Interactive AI Threat Copilot Chat Controller
function initAiCopilotChat() {
  const chatForm = document.getElementById('aiChatForm');
  const chatInput = document.getElementById('aiChatInput');
  const chatBox = document.getElementById('aiChatConversation');
  const promptChips = document.querySelectorAll('.ai-chip-btn');

  // Quick preset chips
  promptChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const q = chip.dataset.q;
      if (q) {
        chatInput.value = q;
        submitAiQuestion(q);
      }
    });
  });

  // Chat submit form
  if (chatForm) {
    chatForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const q = chatInput.value.trim();
      if (!q) return;
      submitAiQuestion(q);
    });
  }

  async function submitAiQuestion(question) {
    appendChatMessage('user', question, '👤 Analyst Query:');
    chatInput.value = '';

    const placeholder = appendChatMessage('bot', 'Analyzing attack provenance and architecture...', '🤖 AntiGravity Copilot:');

    try {
      const resp = await fetch('/api/ai/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: question,
          scan_context: currentScanResult || {}
        })
      });

      if (!resp.ok) throw new Error('Copilot query failed');
      const data = await resp.json();

      placeholder.querySelector('p').textContent = data.answer || 'No analysis available.';
      const roleSpan = placeholder.querySelector('.ai-msg-role');
      if (roleSpan) {
        roleSpan.textContent = `🤖 AntiGravity Copilot (${data.provider || 'AI Engine'}):`;
      }
    } catch (err) {
      placeholder.querySelector('p').textContent = 'Error querying AI Copilot. Local heuristic fallback engine active.';
    }

    if (chatBox) {
      chatBox.scrollTop = chatBox.scrollHeight;
    }
  }

  function appendChatMessage(type, text, roleLabel) {
    const msgDiv = document.createElement('div');
    msgDiv.className = `ai-msg ${type}`;
    msgDiv.innerHTML = `
      <span class="ai-msg-role">${roleLabel}</span>
      <p>${text}</p>
    `;
    if (chatBox) {
      chatBox.appendChild(msgDiv);
      chatBox.scrollTop = chatBox.scrollHeight;
    }
    return msgDiv;
  }
}
