/**
 * ShieldCheck by AntiGravity — Main Frontend Controller
 * Universal UI: Landing Page → Simple Mode → Analyst Mode → Batch Mode
 */

import { ApiClient, SampleFixtures } from './api.js';
import { GraphVisualizer } from './graph_viz.js';

let currentScanResult = null;
let currentMode = 'simple';   // 'simple' | 'analyst'
let graphViz = null;

document.addEventListener('DOMContentLoaded', () => {
  initLandingPage();
  initAppPage();
  loadAuditHistory();
  loadLiveMetrics();
});

/* ================================================================
   LANDING PAGE
   ================================================================ */
function initLandingPage() {
  loadDailyQuote();

  // Nav buttons
  document.getElementById('navOpenApp')?.addEventListener('click', () => enterApp('simple'));
  document.getElementById('navDocs')?.addEventListener('click', openDocsModal);
  document.getElementById('footerJudgeDocs')?.addEventListener('click', openDocsModal);

  // Hero tabs
  document.querySelectorAll('.hero-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.hero-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.hero-input-pane').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const target = tab.dataset.target;
      document.getElementById(target)?.classList.add('active');
    });
  });

  // Hero scan button
  document.getElementById('heroScanBtn')?.addEventListener('click', async () => {
    const url = document.getElementById('heroUrlField')?.value?.trim();
    if (!url) return;
    enterApp('simple');
    // Small delay to let app render
    setTimeout(() => {
      document.getElementById('urlInput').value = url;
      // Switch to URL tab
      document.querySelector('[data-pane="urlPane"]')?.click();
      performUrlScan(url);
    }, 100);
  });

  document.getElementById('heroUrlField')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('heroScanBtn')?.click();
  });

  // Example pills on landing
  document.querySelectorAll('.example-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const url = pill.dataset.url;
      if (url) {
        document.getElementById('heroUrlField').value = url;
        document.getElementById('heroScanBtn')?.click();
      }
    });
  });

  // Hero dropzones
  setupHeroDropzone('heroEmailDrop', 'heroEmailFile', 'email');
  setupHeroDropzone('heroFileDrop', 'heroFileFileInput', 'attachment');

  // Persona CTA buttons
  document.querySelectorAll('.persona-cta').forEach(btn => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.mode;
      if (mode === 'api') {
        window.open('/api/docs', '_blank');
      } else {
        enterApp(mode === 'analyst' ? 'analyst' : 'simple');
      }
    });
  });
}

function setupHeroDropzone(dropId, inputId, scanType) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  if (!drop || !input) return;

  drop.addEventListener('click', () => input.click());
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag-over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('drag-over');
    const file = e.dataTransfer?.files[0];
    if (file) handleHeroFileUpload(file, scanType);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) handleHeroFileUpload(input.files[0], scanType);
  });
}

async function handleHeroFileUpload(file, scanType) {
  enterApp('simple');
  setTimeout(async () => {
    const tabId = scanType === 'email' ? 'emlPane' : 'attPane';
    document.querySelector(`[data-pane="${tabId}"]`)?.click();
    await performFileScan(file, scanType);
  }, 100);
}

function enterApp(mode = 'simple') {
  document.getElementById('landingPage').style.display = 'none';
  document.getElementById('appPage').style.display = 'block';
  setMode(mode);
  initGraph();
  initTelemetry();
}

/* ================================================================
   APP PAGE INIT
   ================================================================ */
function initAppPage() {
  // Back button
  document.getElementById('backToHome')?.addEventListener('click', () => {
    document.getElementById('landingPage').style.display = 'block';
    document.getElementById('appPage').style.display = 'none';
  });

  // Mode switcher
  document.getElementById('modeSimple')?.addEventListener('click', () => setMode('simple'));
  document.getElementById('modeAnalyst')?.addEventListener('click', () => setMode('analyst'));
  document.getElementById('modeDocsBtn')?.addEventListener('click', openDocsModal);
  document.getElementById('switchToAnalyst')?.addEventListener('click', () => setMode('analyst'));

  // Docs modal
  document.getElementById('docsCloseBtn')?.addEventListener('click', closeDocsModal);
  document.getElementById('docsModal')?.addEventListener('click', e => {
    if (e.target.id === 'docsModal') closeDocsModal();
  });

  // Docs tabs
  document.querySelectorAll('.docs-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.docs-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.docs-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.pane)?.classList.add('active');
    });
  });

  // Docs accordion
  document.querySelectorAll('.doc-acc-header').forEach(header => {
    header.addEventListener('click', () => {
      const acc = header.closest('.doc-accordion');
      acc.classList.toggle('open');
    });
  });

  // Scanner tabs
  document.querySelectorAll('.tab-btn').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tab.dataset.pane)?.classList.add('active');
    });
  });

  // URL scan
  document.getElementById('scanUrlBtn')?.addEventListener('click', () => {
    const url = document.getElementById('urlInput')?.value?.trim();
    if (url) performUrlScan(url);
  });
  document.getElementById('urlInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('scanUrlBtn')?.click();
  });

  // Quick URL chips
  document.querySelectorAll('.url-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.dataset.url;
      if (url) {
        document.getElementById('urlInput').value = url;
        performUrlScan(url);
      }
    });
  });

  // Email dropzone
  setupDropzone('emlDropzone', 'emlFileInput', 'email');

  // Attachment dropzone
  setupDropzone('attDropzone', 'attFileInput', 'attachment');

  // Sample chips
  document.querySelectorAll('.sample-chip').forEach(chip => {
    chip.addEventListener('click', () => handleSampleChip(chip.dataset.sample));
  });

  // Batch scan
  const batchInput = document.getElementById('batchUrlInput');
  batchInput?.addEventListener('input', () => {
    const count = batchInput.value.trim().split('\n').filter(l => l.trim()).length;
    document.getElementById('batchCount').textContent = `${count} URL${count !== 1 ? 's' : ''} entered`;
  });
  document.getElementById('batchScanBtn')?.addEventListener('click', performBatchScan);

  // Override modal
  document.getElementById('btnOpenOverrideModal')?.addEventListener('click', openOverrideModal);
  document.getElementById('modalCloseBtn')?.addEventListener('click', closeOverrideModal);
  document.getElementById('overrideModal')?.addEventListener('click', e => {
    if (e.target.id === 'overrideModal') closeOverrideModal();
  });
  document.getElementById('overrideForm')?.addEventListener('submit', handleOverrideSubmit);

  // Simple mode action buttons
  document.getElementById('btnSimpleReport')?.addEventListener('click', openOverrideModal);
  document.getElementById('btnMarkSafe')?.addEventListener('click', () => {
    if (currentScanResult) {
      openOverrideModal();
      document.getElementById('modalFeedbackType').value = 'false_positive';
      document.getElementById('modalOverrideVerdict').value = 'BENIGN';
    }
  });

  // AI Copilot
  initAiCopilotChat();

  // Metrics refresh
  document.getElementById('refreshMetrics')?.addEventListener('click', loadLiveMetrics);
}

function setMode(mode) {
  currentMode = mode;
  // Update buttons
  document.getElementById('modeSimple')?.classList.toggle('active', mode === 'simple');
  document.getElementById('modeAnalyst')?.classList.toggle('active', mode === 'analyst');

  // Toggle result sections
  const simpleResults = document.getElementById('simpleModeResults');
  const analystResults = document.getElementById('analystModeResults');

  if (mode === 'analyst') {
    simpleResults?.classList.remove('active');
    analystResults?.classList.add('active');
    if (graphViz) setTimeout(() => graphViz.resize(), 50);
  } else {
    analystResults?.classList.remove('active');
    simpleResults?.classList.add('active');
  }

  // If we have a result, re-render for the mode
  if (currentScanResult) {
    renderResults(currentScanResult);
  }
}

/* ================================================================
   GRAPH
   ================================================================ */
function initGraph() {
  if (graphViz) return;
  const canvas = document.getElementById('graphCanvas');
  if (!canvas) return;
  try {
    graphViz = new GraphVisualizer('graphCanvas', renderNodeInspector);
  } catch (e) { /* skip if graph not available */ }
}

function renderNodeInspector(node) {
  const container = document.getElementById('nodeInspectorContent');
  if (!container) return;
  if (!node) {
    container.innerHTML = '<p class="text-dim" style="font-size:0.85rem;">Click any node to inspect its attributes.</p>';
    return;
  }
  const attrs = node.attributes || {};
  let html = `<div class="inspector-field"><div class="inspector-label">Node Label</div><div class="inspector-val">${node.label || node.id}</div></div>`;
  html += `<div class="inspector-field"><div class="inspector-label">Risk Level</div><div class="inspector-val" style="color:${node.color || '#fff'}">${node.riskLevel || 'Unknown'}</div></div>`;
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'object' && v !== null) {
      html += `<div class="inspector-field"><div class="inspector-label">${k}</div><pre class="inspector-val" style="font-size:0.72rem;">${JSON.stringify(v, null, 2)}</pre></div>`;
    } else {
      html += `<div class="inspector-field"><div class="inspector-label">${k}</div><div class="inspector-val">${v}</div></div>`;
    }
  }
  container.innerHTML = html;
}

/* ================================================================
   SCAN EXECUTION
   ================================================================ */
async function performUrlScan(url) {
  showLoading('Checking with 8 security engines…');
  try {
    const result = await ApiClient.scanUrl(url);
    currentScanResult = result;
    renderResults(result);
    loadAuditHistory();
  } catch (err) {
    showError(err.message);
  } finally {
    hideLoading();
  }
}

async function performFileScan(file, scanType) {
  showLoading(scanType === 'email' ? 'Analysing email structure…' : 'Scanning attachment for threats…');
  try {
    const result = scanType === 'email'
      ? await ApiClient.scanEmail(file)
      : await ApiClient.scanAttachment(file);
    currentScanResult = result;
    renderResults(result);
    loadAuditHistory();
  } catch (err) {
    showError(err.message);
  } finally {
    hideLoading();
  }
}

async function performBatchScan() {
  const textarea = document.getElementById('batchUrlInput');
  const urls = textarea?.value.trim().split('\n').map(u => u.trim()).filter(u => u).slice(0, 100);
  if (!urls?.length) return;

  showLoading(`Batch scanning ${urls.length} URLs in parallel…`);
  try {
    const res = await fetch('/api/scan/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls })
    });
    const data = await res.json();
    renderBatchResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    hideLoading();
  }
}

function setupDropzone(dropId, inputId, scanType) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  if (!drop || !input) return;

  drop.addEventListener('click', () => input.click());
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag-over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('drag-over');
    const file = e.dataTransfer?.files[0];
    if (file) performFileScan(file, scanType);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) performFileScan(input.files[0], scanType);
  });
}

/* ================================================================
   RENDER RESULTS
   ================================================================ */
function renderResults(r) {
  const container = document.getElementById('resultsContainer');
  container.style.display = 'block';
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Hide batch results
  document.getElementById('batchResults').style.display = 'none';

  // Render both modes (user switches between them without re-scanning)
  renderSimpleMode(r);
  renderAnalystMode(r);
}

function renderSimpleMode(r) {
  const verdict    = r.verdict || 'UNKNOWN';
  const score      = r.confidence_score ?? r.risk_score ?? 50;
  const summary    = r.summary || r.recipient_summary || {};
  const malware    = r.malware_analysis || {};

  // Determine safe/danger/warning
  const isDanger  = ['PHISHING', 'MALICIOUS', 'CRITICAL'].some(v => verdict.includes(v));
  const isWarning = verdict.includes('SUSPICIOUS') || verdict.includes('UNKNOWN');
  const isSafe    = !isDanger && !isWarning;

  // Big card
  const card = document.getElementById('verdictHeroCard');
  card.className = 'verdict-hero-card ' + (isDanger ? 'danger' : isWarning ? 'warning' : 'safe');

  document.getElementById('verdictEmoji').textContent = isDanger ? '🔴' : isWarning ? '🟡' : '🟢';

  const headlines = {
    danger:  ['Dangerous! Do not click.', 'This is a scam — stay away.', 'Warning: Active threat detected!'],
    warning: ['Suspicious — be careful.', 'Something looks off here.', 'Proceed with caution.'],
    safe:    ['Looks safe! ✓', 'No threats detected.', 'This appears legitimate.']
  };
  const hSet = isDanger ? headlines.danger : isWarning ? headlines.warning : headlines.safe;
  document.getElementById('verdictHeadline').textContent = hSet[Math.floor(Math.random() * hSet.length)];

  // Subtext
  let subtext = 'Our AI analysed this with 8 security engines.';
  if (isDanger) subtext = summary.decision_rationale || 'This link is trying to steal your information or install malware.';
  else if (isWarning) subtext = 'We could not fully verify this. Treat it with caution.';
  else subtext = 'We checked this against our threat database and it passed.';
  document.getElementById('verdictSubtext').textContent = subtext;

  // Malware tag
  const malwareTag = document.getElementById('verdictThreatTag');
  const malwareName = document.getElementById('verdictThreatName');
  if (isDanger && malware.exact_virus_name && !malware.exact_virus_name.includes('Clean')) {
    malwareName.textContent = malware.exact_virus_name;
    malwareTag.style.display = 'inline-flex';
  } else {
    malwareTag.style.display = 'none';
  }

  // Risk meter
  const thumb = document.getElementById('riskMeterThumb');
  const scoreEl = document.getElementById('riskMeterScore');
  const pct = Math.min(100, Math.max(0, score));
  thumb.style.left = pct + '%';
  scoreEl.textContent = `${Math.round(pct)}/100`;

  // Action steps
  const steps = isDanger
    ? ['Do NOT click the link or open any attachments.', 'Delete this email or message immediately.', 'If you already clicked, change your passwords right now and contact IT.']
    : isWarning
    ? ['Do not enter any personal information on this site.', 'Contact your IT team if this was sent to you at work.', 'If in doubt, go directly to the official website instead.']
    : ['You can safely proceed, but always stay alert.', 'Never enter passwords on sites you did not navigate to yourself.'];

  document.getElementById('actionSteps').innerHTML = steps.map((s, i) =>
    `<div class="action-step"><div class="action-step-num">${i + 1}</div><div class="action-step-text">${s}</div></div>`
  ).join('');

  // Why list
  const reasons = (summary.flagged_reasons || r.recipient_summary?.flagged_reasons || []).slice(0, 5);
  const evasions = r.evasion_techniques || [];
  const whyItems = [...reasons, ...evasions].filter(Boolean).slice(0, 5);
  document.getElementById('whyList').innerHTML = whyItems.length
    ? whyItems.map(item => `<li>${item}</li>`).join('')
    : `<li>Risk score: ${Math.round(pct)}/100 — ${isSafe ? 'below detection threshold' : 'above safe threshold'}</li>`;
}

function renderAnalystMode(r) {
  const verdict   = r.verdict || 'UNKNOWN';
  const score     = r.confidence_score ?? r.risk_score ?? 50;
  const ai        = r.ai_analysis || {};
  const malware   = r.malware_analysis || {};
  const xai       = r.nist_xai || {};
  const graph     = r.evidence_graph || {};
  const meta      = r._meta || {};

  // Status bar
  const verdictEl = document.getElementById('analystVerdictVal');
  verdictEl.textContent = verdict;
  verdictEl.style.color = verdict.includes('PHISHING') || verdict.includes('MALICIOUS') ? 'var(--status-red)' : verdict.includes('SUSPICIOUS') ? 'var(--status-amber)' : 'var(--status-emerald)';

  document.getElementById('analystConfidenceVal').textContent = `${Math.round(score)}%`;
  document.getElementById('analystScanId').textContent = r.scan_id || '--';
  document.getElementById('analystLatency').textContent = meta.latency_ms ? `${meta.latency_ms}ms` : '--';

  // AI Forensics
  const ml = r.ml_classification || {};
  const se = r.social_engineering || ai;
  document.getElementById('aiMlProb').textContent = ml.phishing_probability != null ? `${ml.phishing_probability}%` : '--';
  const mlClass = document.getElementById('aiMlClass');
  mlClass.textContent = ml.ai_classification || '--';
  mlClass.style.background = ml.ai_classification === 'PHISHING' ? 'rgba(255,51,102,0.2)' : ml.ai_classification === 'SUSPICIOUS' ? 'rgba(255,179,0,0.2)' : 'rgba(0,230,118,0.2)';
  mlClass.style.color = ml.ai_classification === 'PHISHING' ? '#ff3366' : ml.ai_classification === 'SUSPICIOUS' ? '#ffb300' : '#00e676';

  document.getElementById('aiTopSignals').textContent = `Signals: ${(ml.top_ai_signals || []).join(', ') || '--'}`;
  document.getElementById('aiPretextCat').textContent = se.primary_pretext_category || '--';
  document.getElementById('aiCoercionTactics').textContent = `Tactics: ${(se.coercion_tactics_detected || []).join(', ') || 'None detected'}`;

  const playbook = se.ai_recommended_playbook || [];
  document.getElementById('aiPlaybookList').innerHTML = playbook.length
    ? playbook.map(step => `<li>${step}</li>`).join('')
    : '<li>No specific playbook generated.</li>';

  // AI model badge
  const badge = document.getElementById('aiModelBadge');
  badge.textContent = se.ai_copilot_enabled ? '🤖 Gemini LLM + RandomForest' : '🧠 RandomForest + Heuristics';

  // VirusTotal Consensus
  const vtData = malware.virustotal_consensus || {};
  const vtEngines = vtData.engines || {};
  document.getElementById('vtRatioBadge').textContent = `${vtData.engines_flagged ?? 0} / ${vtData.engines_total ?? 8} Flagged`;
  document.getElementById('vtMitreBadge').textContent = `MITRE: ${malware.mitre_attack_id || 'T1566'}`;
  document.getElementById('vtThreatFamilyName').textContent = malware.exact_virus_name || 'Clean.NoThreatDetected';
  document.getElementById('vtThreatCategory').textContent = malware.threat_category || 'Benign';

  const grid = document.getElementById('threatFeedGrid');
  grid.innerHTML = Object.entries(vtEngines).map(([vendor, det]) =>
    `<div class="feed-vendor-card">
      <div class="feed-vendor-name">${vendor}</div>
      <div class="feed-verdict ${det.verdict}">${det.verdict}</div>
      <div class="feed-label">${det.label || ''}</div>
    </div>`
  ).join('') || '<div class="text-muted" style="font-size:0.82rem;padding:0.5rem;">No engine data</div>';

  // NIST XAI
  if (xai.nist_explanation) {
    document.getElementById('nistExplanation').textContent  = xai.nist_explanation || '';
    document.getElementById('nistMeaningfulness').textContent = xai.nist_meaningfulness || '';
    document.getElementById('nistAccuracy').textContent     = xai.nist_accuracy || '';
    document.getElementById('nistLimits').textContent       = xai.nist_limits || '';
  }

  // Evidence Graph
  if (graphViz && graph.nodes) {
    graphViz.render(graph);
  }

  // Store for override modal
  document.getElementById('modalTarget').value  = r.target || '';
  document.getElementById('modalScanId').value  = r.scan_id || '';
}

function renderBatchResults(data) {
  const container = document.getElementById('resultsContainer');
  container.style.display = 'block';
  document.getElementById('simpleModeResults').classList.remove('active');
  document.getElementById('analystModeResults').classList.remove('active');

  const batchSection = document.getElementById('batchResults');
  batchSection.style.display = 'block';

  // Summary badges
  const total   = data.total_processed || 0;
  const danger  = data.phishing_detected || 0;
  const clean   = data.clean_count || 0;
  const timeMs  = data.processing_time_ms || 0;

  document.getElementById('batchSummaryBadges').innerHTML = `
    <span class="tag-badge red">🔴 ${danger} Threats</span>
    <span class="tag-badge cyan">🟢 ${clean} Safe</span>
    <span class="tag-badge" style="color:var(--text-dim);border-color:var(--border-dim);background:rgba(255,255,255,0.04);">⚡ ${timeMs}ms total · ${data.avg_per_url_ms}ms/URL</span>
  `;

  // Table
  const results = data.results || [];
  const rows = results.map(r => {
    const verd = r.verdict || (r.error ? 'ERROR' : r.skipped ? 'SKIPPED' : '—');
    const color = ['PHISHING','MALICIOUS'].some(v => String(verd).includes(v)) ? 'var(--status-red)' : verd === 'BENIGN' ? 'var(--status-emerald)' : 'var(--text-dim)';
    return `<tr>
      <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:0.72rem;">#${(r.index ?? 0) + 1}</td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;">${r.url || r.target || '—'}</td>
      <td style="color:${color};font-weight:700;font-family:var(--font-mono);">${verd}</td>
      <td>${r.confidence_score != null ? Math.round(r.confidence_score) + '%' : '—'}</td>
      <td style="color:${r._cache_hit ? 'var(--status-emerald)' : 'var(--text-muted)'};">${r._cache_hit ? '⚡ Cached' : '🔍 Fresh'}</td>
    </tr>`;
  }).join('');

  document.getElementById('batchResultsTable').innerHTML = `
    <table class="batch-table">
      <thead><tr><th>#</th><th>URL</th><th>Verdict</th><th>Score</th><th>Cache</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;

  batchSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ================================================================
   SAMPLE CHIPS
   ================================================================ */
function handleSampleChip(sample) {
  switch (sample) {
    case 'svg_smuggling': {
      const blob = new Blob([SampleFixtures.getSvgSmugglingEml()], { type: 'message/rfc822' });
      performFileScan(new File([blob], 'smuggling_test.eml'), 'email');
      document.querySelector('[data-pane="emlPane"]')?.click();
      break;
    }
    case 'brand_typosquat':
      document.getElementById('urlInput').value = 'http://login-microsoft-security.top/auth/renew';
      document.querySelector('[data-pane="urlPane"]')?.click();
      performUrlScan('http://login-microsoft-security.top/auth/renew');
      break;
    case 'dga_entropy':
      document.getElementById('urlInput').value = 'http://xk29qm4tz7vpb.top/download/payload.exe';
      document.querySelector('[data-pane="urlPane"]')?.click();
      performUrlScan('http://xk29qm4tz7vpb.top/download/payload.exe');
      break;
    case 'captcha_wall':
      document.getElementById('urlInput').value = 'http://invoice-confirm-cloudflare-secure.top/auth';
      document.querySelector('[data-pane="urlPane"]')?.click();
      performUrlScan('http://invoice-confirm-cloudflare-secure.top/auth');
      break;
    case 'clean_email': {
      const blob = new Blob([SampleFixtures.getCleanEml()], { type: 'message/rfc822' });
      performFileScan(new File([blob], 'clean_test.eml'), 'email');
      document.querySelector('[data-pane="emlPane"]')?.click();
      break;
    }
  }
}

/* ================================================================
   AI COPILOT CHAT
   ================================================================ */
function initAiCopilotChat() {
  document.querySelectorAll('.ai-chip-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('aiChatInput').value = btn.dataset.q;
      document.getElementById('aiChatForm')?.dispatchEvent(new Event('submit'));
    });
  });

  document.getElementById('aiChatForm')?.addEventListener('submit', async e => {
    e.preventDefault();
    const input = document.getElementById('aiChatInput');
    const question = input.value.trim();
    if (!question) return;

    appendChat('user', question);
    input.value = '';
    appendChat('bot', '…thinking…', 'thinking');

    try {
      const res = await fetch('/api/ai/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, scan_context: currentScanResult || {} })
      });
      const data = await res.json();
      const answer = data.ai_behavioral_insight || data.answer || data.response
        || (Array.isArray(data.ai_recommended_playbook)
            ? data.ai_recommended_playbook.join(' → ')
            : JSON.stringify(data, null, 2));
      removeThinking();
      appendChat('bot', answer);
    } catch (err) {
      removeThinking();
      appendChat('bot', `Error: ${err.message}`);
    }
  });
}

function appendChat(role, text, cls = '') {
  const box = document.getElementById('aiChatConversation');
  if (!box) return;
  const div = document.createElement('div');
  div.className = `ai-msg ${role} ${cls}`;
  div.innerHTML = `<span class="ai-msg-role">${role === 'bot' ? '🤖 Copilot:' : '👤 You:'}</span><p>${text}</p>`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function removeThinking() {
  document.querySelector('.ai-msg.thinking')?.remove();
}

/* ================================================================
   LOADING + ERROR
   ================================================================ */
function showLoading(msg = 'Scanning…') {
  const ind = document.getElementById('scanLoadingIndicator');
  const heroLoading = document.getElementById('heroLoadingBar');
  const msgEl = document.getElementById('loadingMsg');
  const heroMsg = document.getElementById('heroLoadingText');
  const heroFill = document.getElementById('heroProgressFill');
  if (ind) ind.style.display = 'flex';
  if (heroLoading) heroLoading.style.display = 'block';
  if (msgEl) msgEl.textContent = msg;
  if (heroMsg) heroMsg.textContent = msg;
  // Animate progress bar
  if (heroFill) {
    heroFill.style.width = '0%';
    setTimeout(() => { heroFill.style.width = '70%'; }, 50);
  }
}

function hideLoading() {
  const ind = document.getElementById('scanLoadingIndicator');
  const heroLoading = document.getElementById('heroLoadingBar');
  const heroFill = document.getElementById('heroProgressFill');
  if (ind) ind.style.display = 'none';
  if (heroFill) heroFill.style.width = '100%';
  setTimeout(() => { if (heroLoading) heroLoading.style.display = 'none'; }, 400);
}

function showError(msg) {
  const container = document.getElementById('resultsContainer');
  container.style.display = 'block';
  document.getElementById('simpleModeResults').classList.remove('active');
  const parsed = (() => { try { return JSON.parse(msg); } catch { return null; } })();
  const detail = parsed?.detail?.error || parsed?.detail || msg;
  container.innerHTML = `<div class="glass-panel" style="border-color:rgba(255,51,102,0.3);padding:1.5rem;">
    <div style="font-size:1rem;font-weight:800;color:var(--status-red);margin-bottom:0.5rem;">⚠️ Scan Error</div>
    <div style="font-size:0.88rem;color:var(--text-dim);">${detail}</div>
  </div>`;
}

/* ================================================================
   AUDIT HISTORY
   ================================================================ */
async function loadAuditHistory() {
  try {
    const scans = await ApiClient.getRecentScans();
    const tbody = document.getElementById('auditTableBody');
    if (!tbody || !scans?.length) return;
    tbody.innerHTML = scans.map(s => {
      const verd = s.verdict || '—';
      const color = ['PHISHING','MALICIOUS'].some(v => verd.includes(v)) ? 'var(--status-red)' : verd === 'BENIGN' ? 'var(--status-emerald)' : 'var(--status-amber)';
      return `<tr>
        <td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted);">${s.id?.substring(0, 16) || '--'}</td>
        <td>${s.scan_type || '—'}</td>
        <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${s.target || '—'}</td>
        <td style="color:${color};font-weight:700;font-family:var(--font-mono);font-size:0.78rem;">${verd}</td>
        <td>${Math.round(s.confidence_score || 0)}%</td>
        <td style="font-size:0.72rem;color:var(--text-muted);">${new Date(s.created_at || Date.now()).toLocaleTimeString()}</td>
      </tr>`;
    }).join('');
  } catch (_) { /* optional */ }
}

/* ================================================================
   LIVE METRICS
   ================================================================ */
async function loadLiveMetrics() {
  try {
    const health = await fetch('/api/health').then(r => r.json());
    const metrics = await fetch('/api/metrics').then(r => r.json());

    // Update header pills
    const cacheEl = document.getElementById('cacheHitPill');
    if (cacheEl) cacheEl.textContent = `Cache ${metrics.cache?.hit_rate_percent ?? 0}%`;

    // Show metrics section
    const section = document.getElementById('metricsSection');
    if (section) section.style.display = 'block';

    const cards = [
      { label: 'Total Scans', value: metrics.platform_counters?.scans_total ?? 0 },
      { label: 'Threats Found', value: metrics.platform_counters?.scans_phishing ?? 0 },
      { label: 'Avg Latency', value: `${metrics.performance?.avg_scan_latency_ms ?? 0}ms` },
      { label: 'Cache Hit Rate', value: `${metrics.performance?.cache_hit_rate_percent ?? 0}%` },
      { label: 'SSRF Blocked', value: metrics.security_events?.ssrf_attempts_blocked ?? 0 },
      { label: 'Rate Limits Hit', value: metrics.security_events?.rate_limit_triggers ?? 0 },
      { label: 'ML Precision', value: `${((metrics.ml_model_card?.precision ?? 0) * 100).toFixed(1)}%` },
      { label: 'ML Recall', value: `${((metrics.ml_model_card?.recall ?? 0) * 100).toFixed(1)}%` },
      { label: 'F1 Score', value: `${((metrics.ml_model_card?.f1_score ?? 0) * 100).toFixed(1)}%` },
      { label: 'Test Dataset', value: `${metrics.ml_model_card?.test_dataset_size ?? 0} samples` },
      { label: 'CPU Cores', value: health.hardware?.cpu_cores ?? '--' },
      { label: 'Uptime', value: formatUptime(metrics.platform_counters?.uptime_seconds ?? 0) },
    ];

    document.getElementById('metricsGrid').innerHTML = cards.map(c =>
      `<div class="metric-card"><div class="metric-card-label">${c.label}</div><div class="metric-card-value">${c.value}</div></div>`
    ).join('');
  } catch (_) { /* optional */ }
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

/* ================================================================
   SYSTEM TELEMETRY
   ================================================================ */
async function initTelemetry() {
  try {
    const data = await ApiClient.getHealth();
    const statusEl = document.getElementById('systemStatus');
    if (statusEl) {
      statusEl.textContent = data.status === 'HEALTHY' ? '● LIVE' : '● OFFLINE';
    }
  } catch (_) {
    const statusEl = document.getElementById('systemStatus');
    if (statusEl) { statusEl.textContent = '● OFFLINE'; statusEl.className = 'metric-pill'; }
  }
}

/* ================================================================
   OVERRIDE MODAL
   ================================================================ */
function openOverrideModal() {
  if (currentScanResult) {
    document.getElementById('modalTarget').value  = currentScanResult.target || '';
    document.getElementById('modalScanId').value  = currentScanResult.scan_id || '';
  }
  document.getElementById('overrideModal').classList.add('open');
}
function closeOverrideModal() {
  document.getElementById('overrideModal').classList.remove('open');
}

async function handleOverrideSubmit(e) {
  e.preventDefault();
  const scanId  = document.getElementById('modalScanId').value;
  const target  = document.getElementById('modalTarget').value;
  const feedbackType   = document.getElementById('modalFeedbackType').value;
  const overrideVerdict = document.getElementById('modalOverrideVerdict').value;
  const notes   = document.getElementById('modalAnalystNotes').value;
  try {
    await ApiClient.submitFeedback(scanId, target, feedbackType, overrideVerdict, notes);
    closeOverrideModal();
    document.getElementById('modalAnalystNotes').value = '';
    loadAuditHistory();
  } catch (err) {
    alert('Failed to submit: ' + err.message);
  }
}

/* ================================================================
   DOCS MODAL
   ================================================================ */
function openDocsModal() {
  document.getElementById('docsModal').classList.add('open');
}
function closeDocsModal() {
  document.getElementById('docsModal').classList.remove('open');
}

/* ================================================================
   AI DAILY QUOTE (External API Integration)
   ================================================================ */
async function loadDailyQuote() {
  const quoteEl = document.getElementById('aiDailyQuote');
  const authorEl = document.getElementById('aiDailyQuoteAuthor');
  if (!quoteEl) return;

  try {
    // Using a free, reliable API without keys as requested
    const res = await fetch('https://dummyjson.com/quotes/random');
    if (!res.ok) throw new Error('API Error');
    const data = await res.json();
    
    quoteEl.textContent = `"${data.quote}"`;
    authorEl.textContent = `— ${data.author}`;
  } catch (err) {
    // Fallback if network blocks the external API
    const fallbacks = [
      { q: "Artificial intelligence is the new electricity.", a: "Andrew Ng" },
      { q: "The question of whether a computer can think is no more interesting than the question of whether a submarine can swim.", a: "Edsger W. Dijkstra" },
      { q: "As more and more artificial intelligence is entering into the world, more and more emotional intelligence must enter into leadership.", a: "Amit Ray" }
    ];
    const fb = fallbacks[Math.floor(Math.random() * fallbacks.length)];
    quoteEl.textContent = `"${fb.q}"`;
    authorEl.textContent = `— ${fb.a}`;
  }
}

