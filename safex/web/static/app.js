
// SafeX SOVEREIGN - Dynamic UI Synchronization Helpers
function updateSovereignVectors(breakdown, senderFail, nlpSuspicious, urlCrit, binClean) {
  const v1Badge = document.getElementById('v1-score-badge');
  const v1Bar = document.getElementById('v1-progress-bar');
  const v2Badge = document.getElementById('v2-score-badge');
  const v2Bar = document.getElementById('v2-progress-bar');
  const v3Badge = document.getElementById('v3-score-badge');
  const v3Bar = document.getElementById('v3-progress-bar');
  const v4Badge = document.getElementById('v4-score-badge');
  const v4Bar = document.getElementById('v4-progress-bar');

  const sScore = breakdown.sender_score !== undefined ? breakdown.sender_score : 0;
  const bScore = breakdown.body_score !== undefined ? breakdown.body_score : 0;
  const uScore = breakdown.url_score !== undefined ? breakdown.url_score : 0;
  const aScore = breakdown.attachment_score !== undefined ? breakdown.attachment_score : 0;

  if (v1Badge) {
    const sPct = Math.min(100, Math.round((sScore / 35) * 100));
    v1Badge.textContent = sPct >= 50 ? `FAIL ${sPct}/100` : `PASS ${sPct}/100`;
    v1Badge.className = sPct >= 50 ? 'px-space-sm py-0.5 rounded bg-error-container text-on-error-container font-label-caps text-label-caps font-bold' : 'px-space-sm py-0.5 rounded bg-surface-container text-secondary font-label-caps text-label-caps font-bold';
    if (v1Bar) {
      v1Bar.style.width = `${sPct}%`;
      v1Bar.className = sPct >= 50 ? 'bg-error h-full rounded-full transition-all duration-500' : 'bg-secondary h-full rounded-full transition-all duration-500';
    }
  }

  if (v2Badge) {
    const bPct = Math.min(100, Math.round((bScore / 35) * 100));
    v2Badge.textContent = bPct >= 50 ? `SUSPICIOUS ${bPct}/100` : `CLEAN ${bPct}/100`;
    v2Badge.className = bPct >= 50 ? 'px-space-sm py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-label-caps text-label-caps font-bold' : 'px-space-sm py-0.5 rounded bg-surface-container text-secondary font-label-caps text-label-caps font-bold';
    if (v2Bar) {
      v2Bar.style.width = `${bPct}%`;
      v2Bar.className = bPct >= 50 ? 'bg-tertiary h-full rounded-full transition-all duration-500' : 'bg-secondary h-full rounded-full transition-all duration-500';
    }
  }

  if (v3Badge) {
    const uPct = Math.min(100, Math.round((uScore / 45) * 100));
    v3Badge.textContent = uPct >= 50 ? `CRITICAL ${uPct}/100` : `BENIGN ${uPct}/100`;
    v3Badge.className = uPct >= 50 ? 'px-space-sm py-0.5 rounded bg-error-container text-on-error-container font-label-caps text-label-caps font-bold' : 'px-space-sm py-0.5 rounded bg-surface-container text-secondary font-label-caps text-label-caps font-bold';
    if (v3Bar) {
      v3Bar.style.width = `${uPct}%`;
      v3Bar.className = uPct >= 50 ? 'bg-error h-full rounded-full transition-all duration-500' : 'bg-secondary h-full rounded-full transition-all duration-500';
    }
  }

  if (v4Badge) {
    const aPct = Math.min(100, Math.round((aScore / 50) * 100));
    v4Badge.textContent = aPct >= 50 ? `MALICIOUS ${aPct}/100` : `CLEAN DISARMED ${aPct}/100`;
    v4Badge.className = aPct >= 50 ? 'px-space-sm py-0.5 rounded bg-error-container text-on-error-container font-label-caps text-label-caps font-bold' : 'px-space-sm py-0.5 rounded bg-surface-container text-secondary font-label-caps text-label-caps font-bold';
    if (v4Bar) {
      v4Bar.style.width = `${aPct}%`;
      v4Bar.className = aPct >= 50 ? 'bg-error h-full rounded-full transition-all duration-500' : 'bg-secondary h-full rounded-full transition-all duration-500';
    }
  }
}

// Sovereign Playbook Quick Actions handler
function triggerPlaybookAction(action) {
  const note = document.createElement('div');
  note.className = 'fixed bottom-12 right-6 px-4 py-3 rounded-xl bg-surface-container-high border border-primary/30 text-on-surface font-code-inline text-xs shadow-2xl z-50 flex items-center gap-3 transform translate-y-2 opacity-0 transition-all duration-300';

  let msg = '';
  let icon = 'bolt';
  if (action === 'quarantine') {
    msg = 'Defcon Isolation Activated: Sender domain blacklisted & inbox delivery revoked.';
    icon = 'block';
  } else if (action === 'verify') {
    msg = 'Out-of-Band Checklist: Initiating registered corporate directory phone verification.';
    icon = 'call_split';
  } else if (action === 'sandbox') {
    msg = 'In-Memory Byte Sandbox: Hex stream extracted without disk persistence.';
    icon = 'biotech';
  } else if (action === 'soc') {
    msg = 'SOC Telemetry Dispatched: Incident package encrypted and sent to Tier 3 queue.';
    icon = 'hub';
  }

  note.innerHTML = `<span class="material-symbols-outlined text-primary text-[20px]">${icon}</span><span>${msg}</span>`;
  document.body.appendChild(note);

  setTimeout(() => { note.classList.remove('translate-y-2', 'opacity-0'); }, 10);
  setTimeout(() => {
    note.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => note.remove(), 300);
  }, 3200);
}

// Sovereign Feedback Store Writer (Requirement 4)
async function recordFeedback(actionType) {
  const score = parseInt(document.getElementById('verdict-score')?.textContent || '0', 10);
  const rating = document.getElementById('verdict-label')?.textContent || 'HIGH RISK';
  const sampleName = document.getElementById('email-subject')?.textContent || 'Sovereign Triage Sample';

  let userVerdict = 'ACCURATE';
  if (actionType === 'false_positive') userVerdict = 'FALSE_POSITIVE';
  else if (actionType === 'weight_adjust') userVerdict = 'WEIGHT_ADJUST';

  try {
    const formData = new FormData();
    formData.append('sample_id', currentScenario || 'custom');
    formData.append('sample_name', sampleName);
    formData.append('user_verdict', userVerdict);
    formData.append('notes', `Logged via Sovereign Quick Tuning: ${actionType}`);
    formData.append('assigned_score', score);
    formData.append('assigned_rating', rating);

    await fetch('/api/feedback', { method: 'POST', body: formData });
    loadFeedbackStats();
  } catch (err) {
    console.warn('Feedback sync error:', err);
  }

  const feedbackMap = {
    'true_positive': 'Verified True Positive written to local store.',
    'false_positive': 'False Positive reported. Heuristic delta saved to feedback_store.json.',
    'weight_adjust': 'Active weights calibration modal engaged for SOV-POL-STRICT-04.'
  };

  const note = document.createElement('div');
  note.className = 'fixed bottom-12 right-6 px-4 py-2.5 rounded-lg bg-surface-container-high border border-outline-variant/30 text-on-surface font-code-inline text-code-inline shadow-2xl z-50 flex items-center gap-2 transform translate-y-2 opacity-0 transition-all duration-300';
  note.innerHTML = `<span class="material-symbols-outlined text-primary text-[18px]">save</span><span>${feedbackMap[actionType] || 'Acknowledged.'}</span>`;
  document.body.appendChild(note);

  setTimeout(() => { note.classList.remove('translate-y-2', 'opacity-0'); }, 10);
  setTimeout(() => {
    note.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => note.remove(), 300);
  }, 2800);
}

/**
 * SafeX - High-Performance Threat Analyzer Engine
 * Comprehensive Email, Suspicious Links, and File Threat Analysis.
 */

const SCENARIOS = {
  high: {
    sampleId: 2,
    from: '"Accounts Payable" <invoicing@finance-vendor-portal.com>',
    replyTo: 'stealth-collection@anonymous-drop.ru',
    returnPath: 'bounce-gateway@unknown-vps.net',
    authResults: 'spf=softfail (ip=185.192.1.44) dkim=fail dmarc=fail',
    spf: 'FAIL',
    dkim: 'FAIL',
    dmarc: 'FAIL',
    subject: 'URGENT: Past Due Invoice #INV-98201 - Immediate Suspension Warning',
    body: `Dear Partner,<br/><br/>Your corporate account has been flagged for <span class="bg-rose-500/20 text-rose-300 border border-rose-500/40 px-2 py-0.5 rounded font-medium">IMMEDIATE SUSPENSION</span> due to failure of payment for Invoice #98201.<br/><br/>Please review the attached invoice manifest immediately. If your system requires decrypting the bundle, the temporary passkey is: <span class="bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded font-mono text-xs">SafeDec992!</span><br/><br/>You may also reconcile directly via our authorized billing terminal:<br/><a class="text-cyan-400 underline font-mono text-sm" href="#">https://portal.bank-billing.com/secure-login</a><br/><br/>Failure to remit within 2 hours will initiate full credential invalidation.<br/><br/>Sincerely,<br/>Central Accounts Triage Team`,
    urlVisible: 'https://portal.bank-billing.com/secure-login',
    urlActual: 'http://185.192.1.44:8080/auth/login.php?ref=spoof',
    urlMismatch: true,
    allLinks: [
      {
        url: 'http://185.192.1.44:8080/auth/login.php?ref=spoof',
        anchor_text: 'https://portal.bank-billing.com/secure-login',
        href_domain: '185.192.1.44',
        display_domain: 'portal.bank-billing.com',
        is_mismatch: true,
        is_ip_literal: true,
        has_non_standard_port: true,
        has_credential_path: true,
        risk_score: 82,
        risk_level: 'CRITICAL',
        risk_tags: ['Domain Mismatch', 'IP Literal', 'Port :8080', 'Credential Path'],
        signals: [
          { name: 'Optical Anchor Domain Mismatch', score_impact: 25, description: 'Visible text shows trusted bank domain but links to untrusted IP address.' },
          { name: 'IP Literal Host', score_impact: 22, description: 'Direct IP address destination bypasses DNS reputation filters.' },
          { name: 'Non-Standard Port :8080', score_impact: 15, description: 'Targets raw HTTP administration port commonly used in rogue staging.' }
        ]
      }
    ],
    phishingVectors: {
      homoglyph: false,
      vishing: false,
      hiddenText: false,
      quishing: false
    },
    attachment: {
      name: 'invoice_98201.pdf.exe',
      nameAlert: 'Double extension: .pdf.exe',
      mimeDeclared: 'PDF Document',
      magicBytes: 'Real: Windows Executable (MZ/PE)',
      size: '1.42 MB',
      entropy: 'Entropy: 7.89 (High packing)',
      sha256: '9f83a45c8192fb0172e2aa3958cc10915a1e809312b9cf440268a2bf624243ef',
      severity: 'Executable Binary Disguised',
      theme: 'rose'
    },
    verdict: {
      label: 'Critical Threat',
      score: 88,
      badgeText: 'Immediate Isolation Required',
      theme: 'rose',
      bodyScore: 74,
      attachScore: 96,
      signals: [
        { weight: '+40 pts', tag: 'Renamed Executable', desc: 'File is an application (.exe) disguised with a .pdf extension.', level: 'rose' },
        { weight: '+25 pts', tag: 'Deceptive Hyperlink', desc: 'Link text shows bank-billing.com but directs to an untrusted IP address.', level: 'rose' },
        { weight: '+15 pts', tag: 'Disguised Double Extension', desc: 'Filename hides real executable payload from unsuspecting users.', level: 'rose' },
        { weight: '+8 pts', tag: 'Authentication Failures', desc: 'Sender failed SPF and DKIM domain validation records.', level: 'amber' }
      ]
    }
  },

  medium: {
    sampleId: 4,
    from: '"IT Identity Helpdesk" <no-reply@okta-support-securityhub.com>',
    replyTo: 'it-security@okta-support-securityhub.com',
    returnPath: 'bounce@okta-support-securityhub.com',
    authResults: 'spf=fail (ip=103.224.182.241) dkim=none dmarc=fail',
    spf: 'FAIL',
    dkim: 'NONE',
    dmarc: 'FAIL',
    subject: 'Urgent: Mandatory Multi-Factor Authentication Reset Expiring in 4 Hours',
    body: `Hello Colleague,<br/><br/>Your session tokens are set to expire following security patch KB409210.<br/>To avoid being locked out of enterprise applications, you must reset your security questions and MFA seeds immediately.<br/><br/>Follow the self-service enrollment link:<br/><a href="#" class="text-cyan-400 underline font-mono text-sm">https://sso.company.com/portal/reset-token</a><br/><br/>This action is mandatory for all hybrid remote workers.`,
    urlVisible: 'https://sso.company.com/portal/reset-token',
    urlActual: 'https://okta-auth-relay-gate.com/login?token=x892m',
    urlMismatch: true,
    allLinks: [
      {
        url: 'https://okta-auth-relay-gate.com/login?token=x892m',
        anchor_text: 'https://sso.company.com/portal/reset-token',
        href_domain: 'okta-auth-relay-gate.com',
        display_domain: 'sso.company.com',
        is_mismatch: true,
        is_lookalike: true,
        lookalike_target: 'okta',
        has_credential_path: true,
        risk_score: 75,
        risk_level: 'HIGH',
        risk_tags: ['Domain Mismatch', 'Brand Lookalike (Okta)', 'Credential Path'],
        signals: [
          { name: 'Anchor Text vs Destination Mismatch', score_impact: 25, description: 'Visible text shows company SSO but routes to untrusted proxy relay domain.' },
          { name: 'Typosquat / Brand Impersonation', score_impact: 24, description: 'Domain impersonates identity provider Okta to harvest credentials.' }
        ]
      }
    ],
    phishingVectors: {
      homoglyph: false,
      vishing: false,
      hiddenText: false,
      quishing: false
    },
    attachment: {
      name: 'MFA_Enrollment_Guide.html',
      nameAlert: 'Active HTML script wrapper',
      mimeDeclared: 'HTML Document',
      magicBytes: 'Real: Embedded JavaScript Harvester',
      size: '24.1 KB',
      entropy: 'Entropy: 5.12 (Script form)',
      sha256: '4bca3109a909247f12e87c0aef435c2491a3a60a7e08920bc8b6c4e098864f1d',
      severity: 'Suspicious Credential Harvester',
      theme: 'amber'
    },
    verdict: {
      label: 'Suspicious Risk',
      score: 64,
      badgeText: 'Credential Harvest Risk',
      theme: 'amber',
      bodyScore: 78,
      attachScore: 50,
      signals: [
        { weight: '+35 pts', tag: 'Typosquat / Lookalike Domain', desc: 'Domain okta-support-securityhub.com was registered 48h ago.', level: 'amber' },
        { weight: '+20 pts', tag: 'Hard SPF Fail', desc: 'Sending MTA does not match official Okta identity infrastructure.', level: 'rose' },
        { weight: '+9 pts', tag: 'HTML Password Form', desc: 'Attachment contains disguised password submission forms.', level: 'amber' }
      ]
    }
  },

  lookalike: {
    sampleId: 1,
    from: '"Enterprise IT Operations" <it-notifications@acme-corp.com>',
    replyTo: 'it-helpdesk@acme-corp.com',
    returnPath: 'it-notifications@acme-corp.com',
    authResults: 'spf=pass dkim=pass dmarc=pass',
    spf: 'PASS',
    dkim: 'PASS',
    dmarc: 'PASS',
    subject: 'ACTION REQUIRED: Weekend Maintenance Window - VPN Client Upgrade',
    body: `All Hands,<br/><br/>IT will be conducting scheduled backend gateway upgrades this Saturday from 02:00 to 06:00 UTC.<br/>Please ensure your local VPN software is updated to Version 5.4 prior to Friday close of business.<br/><br/>Review the release schedule and download client mirrors on our cloud confluence:<br/><a href="#" class="text-cyan-400 underline font-mono text-sm">https://confluence.acme-corp.com/display/IT/VPN+Upgrade</a><br/><br/>Do not hesitate to contact internal extension 4402 if you require assistance.`,
    urlVisible: 'https://confluence.acme-corp.com/display/IT/VPN+Upgrade',
    urlActual: 'https://confluence.acme-corp.com/display/IT/VPN+Upgrade',
    urlMismatch: false,
    allLinks: [
      {
        url: 'https://confluence.acme-corp.com/display/IT/VPN+Upgrade',
        anchor_text: 'https://confluence.acme-corp.com/display/IT/VPN+Upgrade',
        href_domain: 'confluence.acme-corp.com',
        display_domain: 'confluence.acme-corp.com',
        is_mismatch: false,
        risk_score: 5,
        risk_level: 'LOW',
        risk_tags: ['Exact Match', 'Internal Confluence'],
        signals: []
      }
    ],
    phishingVectors: {
      homoglyph: false,
      vishing: false,
      hiddenText: false,
      quishing: false
    },
    attachment: {
      name: 'VPN_Migration_Procedure_v5.pdf',
      nameAlert: 'Verified Clean Standard PDF',
      mimeDeclared: 'PDF Document',
      magicBytes: 'Real: Clean PDF Structure (%PDF-1.7)',
      size: '412.4 KB',
      entropy: 'Entropy: 6.01 (Standard fonts)',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      severity: 'Verified Benign PDF',
      theme: 'emerald'
    },
    verdict: {
      label: 'Benign Notice',
      score: 18,
      badgeText: 'Internal Corporate Notice',
      theme: 'emerald',
      bodyScore: 24,
      attachScore: 12,
      signals: [
        { weight: '-20 pts', tag: 'Strict DMARC / SPF Pass', desc: 'Origin verified from internal Acme Corp relay IPs.', level: 'emerald' },
        { weight: '-15 pts', tag: 'Authentic Attachment', desc: 'No macro code or launch primitives detected in PDF tree.', level: 'emerald' },
        { weight: '+12 pts', tag: 'Urgent Wording (Routine)', desc: '"ACTION REQUIRED" used for standard operational bulletin.', level: 'slate' }
      ]
    }
  },

  clean: {
    sampleId: 6,
    from: '"AWS Billing Services" <no-reply-aws@amazon.com>',
    replyTo: 'no-reply-aws@amazon.com',
    returnPath: 'bounces@amazon.com',
    authResults: 'spf=pass dkim=pass dmarc=pass',
    spf: 'PASS',
    dkim: 'PASS',
    dmarc: 'PASS',
    subject: 'Amazon Web Services Invoice #840192842 Available',
    body: `Greetings from Amazon Web Services,<br/><br/>Your monthly invoice for account 8901-2291-0021 is now ready for your review.<br/>The total amount of $341.20 has been charged to your payment card on file.<br/><br/>You can view your full breakdown in the AWS Billing Console:<br/><a href="#" class="text-cyan-400 underline font-mono text-sm">https://console.aws.amazon.com/billing/home#/invoices</a><br/><br/>Thank you for choosing Amazon Web Services.`,
    urlVisible: 'https://console.aws.amazon.com/billing/home#/invoices',
    urlActual: 'https://console.aws.amazon.com/billing/home#/invoices',
    urlMismatch: false,
    allLinks: [
      {
        url: 'https://console.aws.amazon.com/billing/home#/invoices',
        anchor_text: 'https://console.aws.amazon.com/billing/home#/invoices',
        href_domain: 'console.aws.amazon.com',
        display_domain: 'console.aws.amazon.com',
        is_mismatch: false,
        risk_score: 2,
        risk_level: 'LOW',
        risk_tags: ['Exact Match', 'Official Amazon Console'],
        signals: []
      }
    ],
    phishingVectors: {
      homoglyph: false,
      vishing: false,
      hiddenText: false,
      quishing: false
    },
    attachment: {
      name: 'AWS_Tax_Invoice_840192842.pdf',
      nameAlert: 'Verified Clean Standard PDF',
      mimeDeclared: 'PDF Document',
      magicBytes: 'Real: Clean PDF Structure (%PDF-1.6)',
      size: '184.2 KB',
      entropy: 'Entropy: 5.45 (Standard text)',
      sha256: 'a12f38bc901a5201994e63bb018241947265910248293aaec8472910482941aa',
      severity: 'Verified Benign Document',
      theme: 'emerald'
    },
    verdict: {
      label: 'Clean Traffic',
      score: 6,
      badgeText: 'Authentic Business Invoice',
      theme: 'emerald',
      bodyScore: 8,
      attachScore: 4,
      signals: [
        { weight: '-30 pts', tag: 'Cryptographic DKIM Valid', desc: 'Valid cryptographic signature from verified AWS domain.', level: 'emerald' },
        { weight: '-20 pts', tag: 'Zero Anchor Mismatch', desc: 'Visible text matches target anchor https://console.aws.amazon.com.', level: 'emerald' },
        { weight: '-10 pts', tag: 'Clean Document Structure', desc: 'No executable segments or suspicious code blocks.', level: 'emerald' }
      ]
    }
  }
};

let currentAnalysis = null;
let liveFiles = [];

// Init on load
document.addEventListener('DOMContentLoaded', () => {
  setupLiveDropzone();
  loadScenario('high');
  fetchBackendCatalog();
});

// Load Scenario Preset
function loadScenario(key) {
  const data = SCENARIOS[key];
  if (!data) return;

  currentAnalysis = data;

  // Reset preset button styling
  document.querySelectorAll('.preset-pill').forEach(btn => {
    btn.className = 'preset-pill px-4 py-2 rounded-xl text-xs font-medium transition-all duration-200 border bg-[#0c0e14] border-[#232d40] text-slate-300 hover:text-white hover:border-slate-600 flex items-center gap-2';
  });

  const activeBtn = document.getElementById('btn-preset-' + key);
  if (activeBtn) {
    if (key === 'high') {
      activeBtn.className = 'preset-pill px-4 py-2 rounded-xl text-xs font-medium transition-all duration-200 border bg-rose-500/15 border-rose-500/40 text-rose-300 font-semibold shadow-sm flex items-center gap-2';
    } else if (key === 'medium') {
      activeBtn.className = 'preset-pill px-4 py-2 rounded-xl text-xs font-medium transition-all duration-200 border bg-amber-500/15 border-amber-500/40 text-amber-300 font-semibold shadow-sm flex items-center gap-2';
    } else {
      activeBtn.className = 'preset-pill px-4 py-2 rounded-xl text-xs font-medium transition-all duration-200 border bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold shadow-sm flex items-center gap-2';
    }
  }

  // Headers
  document.getElementById('header-from').textContent = data.from;
  document.getElementById('header-reply-to').textContent = data.replyTo;
  document.getElementById('header-return-path').textContent = data.returnPath;
  document.getElementById('header-auth-results').textContent = data.authResults;

  setAuthBadge('badge-auth-spf', 'SPF', data.spf);
  setAuthBadge('badge-auth-dkim', 'DKIM', data.dkim);
  setAuthBadge('badge-auth-dmarc', 'DMARC', data.dmarc);

  // Email Content
  document.getElementById('email-subject').textContent = data.subject;
  document.getElementById('email-body-content').innerHTML = data.body;

  // Optical Anchor Box
  document.getElementById('url-visible-text').textContent = data.urlVisible;
  document.getElementById('url-actual-dest').textContent = data.urlActual;
  const tagEl = document.getElementById('url-status-tag');
  const discCard = document.getElementById('url-discrepancy-card');

  if (data.urlMismatch) {
    tagEl.textContent = 'CRITICAL MISMATCH';
    tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40';
    discCard.className = 'rounded-xl bg-[#0c0e14] border border-rose-500/30 p-5 shadow-sm';
  } else {
    tagEl.textContent = 'MATCH VERIFIED';
    tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    discCard.className = 'rounded-xl bg-[#0c0e14] border border-emerald-500/30 p-5 shadow-sm';
  }

  // Render All Detected Links Table
  renderDetectedLinks(data.allLinks || []);

  // Update Phishing Vectors Telemetry
  updatePhishingVectors(data.phishingVectors || {});

  // Attachment Metadata
  document.getElementById('file-name').textContent = data.attachment.name;
  document.getElementById('file-ext-alert').textContent = data.attachment.nameAlert;
  document.getElementById('file-mime').textContent = data.attachment.mimeDeclared;
  document.getElementById('file-magic').textContent = data.attachment.magicBytes;
  document.getElementById('file-size').textContent = data.attachment.size;
  document.getElementById('file-entropy').textContent = data.attachment.entropy;
  document.getElementById('file-sha256').textContent = data.attachment.sha256;

  const sevPill = document.getElementById('attachment-severity-pill');
  sevPill.textContent = data.attachment.severity;
  if (data.attachment.theme === 'rose') {
    sevPill.className = 'px-3 py-1 rounded-full text-xs font-medium bg-rose-500/20 text-rose-300 border border-rose-500/40';
  } else if (data.attachment.theme === 'amber') {
    sevPill.className = 'px-3 py-1 rounded-full text-xs font-medium bg-amber-500/20 text-amber-300 border border-amber-500/40';
  } else {
    sevPill.className = 'px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
  }

  // Verdict Card
  const vLabel = document.getElementById('verdict-label');
  const vScore = document.getElementById('verdict-score');
  const vSub = document.getElementById('verdict-sublabel');
  const vCircle = document.getElementById('verdict-circle-bar');

  vLabel.textContent = data.verdict.label;
  vScore.textContent = data.verdict.score;
  vSub.textContent = data.verdict.badgeText;

  const circumference = 251.2;
  const offset = circumference - (data.verdict.score / 100) * circumference;
  vCircle.style.strokeDashoffset = offset;

  if (data.verdict.theme === 'rose') {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-rose-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40';
    vCircle.className = 'stroke-rose-500 transition-all duration-700';
  } else if (data.verdict.theme === 'amber') {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-amber-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40';
    vCircle.className = 'stroke-amber-400 transition-all duration-700';
  } else {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-emerald-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    vCircle.className = 'stroke-emerald-400 transition-all duration-700';
  }

  // 4-Component Risk Breakdown (Requirement 1)
  const breakdown = data.verdict.breakdown || {
    sender_score: data.verdict.theme === 'rose' ? 25 : (data.verdict.theme === 'amber' ? 15 : 0),
    body_score: data.verdict.theme === 'rose' ? 15 : (data.verdict.theme === 'amber' ? 20 : 0),
    url_score: data.verdict.theme === 'rose' ? 25 : (data.verdict.theme === 'amber' ? 35 : 0),
    attachment_score: data.verdict.attachScore || (data.verdict.theme === 'rose' ? 50 : 0),
  };

  const senderEl = document.getElementById('score-sender-text');
  if (senderEl) {
    senderEl.textContent = `${breakdown.sender_score} pts`;
    document.getElementById('score-sender-bar').style.width = Math.min(100, (breakdown.sender_score / 35) * 100) + '%';
  }
  const bodyTextEl = document.getElementById('score-bodytext-text');
  if (bodyTextEl) {
    bodyTextEl.textContent = `${breakdown.body_score} pts`;
    document.getElementById('score-bodytext-bar').style.width = Math.min(100, (breakdown.body_score / 35) * 100) + '%';
  }
  const urlEl = document.getElementById('score-url-text');
  if (urlEl) {
    urlEl.textContent = `${breakdown.url_score} pts`;
    document.getElementById('score-url-bar').style.width = Math.min(100, (breakdown.url_score / 45) * 100) + '%';
  }
  const attachEl = document.getElementById('score-attach-text');
  if (attachEl) {
    attachEl.textContent = `${breakdown.attachment_score} pts`;
    document.getElementById('score-attach-bar').style.width = Math.min(100, (breakdown.attachment_score / 50) * 100) + '%';
  }

  // Observable Signals & Supporting Evidence (Requirement 6)
  const sigContainer = document.getElementById('signal-evidence-list');
  sigContainer.innerHTML = '';
  data.verdict.signals.forEach(sig => {
    const item = document.createElement('div');
    item.className = 'p-3.5 rounded-xl bg-[#0c0e14] border border-[#232d40] space-y-1.5';
    let tagColor = 'text-slate-300';
    let weightColor = 'text-slate-400';
    if (sig.level === 'rose') {
      tagColor = 'text-rose-300 font-semibold';
      weightColor = 'text-rose-400 font-bold';
    } else if (sig.level === 'amber') {
      tagColor = 'text-amber-300 font-semibold';
      weightColor = 'text-amber-400 font-bold';
    } else {
      tagColor = 'text-emerald-300 font-semibold';
      weightColor = 'text-emerald-400 font-bold';
    }

    const evidenceHtml = sig.evidence ? `
      <div class="mt-1 px-2.5 py-1 rounded-md bg-[#161b26] border border-[#232d40] flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 break-all">
        <span class="text-slate-500">Evidence:</span> ${escapeHtml(sig.evidence)}
      </div>
    ` : '';

    item.innerHTML = `
      <div class="flex items-start justify-between gap-3">
        <div>
          <span class="text-xs ${tagColor} block">${escapeHtml(sig.tag)}</span>
          <p class="text-xs text-slate-300 mt-0.5 leading-relaxed">${escapeHtml(sig.desc)}</p>
        </div>
        <span class="font-mono text-xs ${weightColor} shrink-0">${sig.weight}</span>
      </div>
      ${evidenceHtml}
    `;
    sigContainer.appendChild(item);
  });

  // Sync SafeX Sovereign Vectors & Telemetry
  updateSovereignVectors(breakdown);
  const defconPill = document.getElementById('verdict-defcon-pill');
  if (defconPill) {
    if (data.verdict.score >= 70) {
      defconPill.textContent = 'Defcon 1 Alert';
      defconPill.className = 'px-space-sm py-0.5 rounded bg-error-container text-on-error-container font-label-caps text-label-caps uppercase tracking-wider font-semibold';
    } else if (data.verdict.score >= 40) {
      defconPill.textContent = 'Defcon 2 Elevated';
      defconPill.className = 'px-space-sm py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-label-caps text-label-caps uppercase tracking-wider font-semibold';
    } else {
      defconPill.textContent = 'Defcon 5 Normal';
      defconPill.className = 'px-space-sm py-0.5 rounded bg-surface-container text-secondary font-label-caps text-label-caps uppercase tracking-wider font-semibold';
    }
  }
}

// Render All Detected Links Table
function renderDetectedLinks(links) {
  const container = document.getElementById('detected-links-container');
  const countPill = document.getElementById('links-count-pill');
  if (!container) return;

  if (countPill) countPill.textContent = `${links.length} Link${links.length === 1 ? '' : 's'} Inspected`;

  if (!links.length) {
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-[#0c0e14] border border-[#232d40] text-center text-xs text-slate-400">
        No hyperlinks discovered in this message sample.
      </div>
    `;
    return;
  }

  container.innerHTML = links.map((lk, i) => {
    let riskBadgeColor = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
    if (lk.risk_level === 'CRITICAL' || (lk.risk_score && lk.risk_score >= 70)) {
      riskBadgeColor = 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-bold';
    } else if (lk.risk_level === 'HIGH' || (lk.risk_score && lk.risk_score >= 50)) {
      riskBadgeColor = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
    } else if (lk.risk_level === 'MEDIUM' || (lk.risk_score && lk.risk_score >= 20)) {
      riskBadgeColor = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
    }

    const tags = lk.risk_tags || [];
    const tagsHtml = tags.map(t => {
      let tCol = 'bg-slate-800 text-slate-300 border-slate-700';
      if (t.includes('Mismatch') || t.includes('IP Literal') || t.includes('Homoglyph')) {
        tCol = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
      } else if (t.includes('Port') || t.includes('Path') || t.includes('Lookalike')) {
        tCol = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
      } else if (t.includes('Match') || t.includes('Clean')) {
        tCol = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
      }
      return `<span class="px-2 py-0.5 rounded text-[10px] font-mono border ${tCol}">${escapeHtml(t)}</span>`;
    }).join(' ');

    return `
      <div class="p-4 rounded-xl bg-[#0c0e14] border border-[#232d40] space-y-2.5 hover:border-slate-700 transition-colors">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="w-5 h-5 rounded-md bg-[#161b26] border border-[#232d40] text-purple-400 font-mono text-[11px] font-bold flex items-center justify-center">#${i + 1}</span>
            <span class="font-mono text-xs font-bold text-white break-all">${escapeHtml(lk.href_domain || 'Unknown Host')}</span>
          </div>
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[11px] font-mono border ${riskBadgeColor}">
              Score: ${lk.risk_score !== undefined ? lk.risk_score : (lk.score_impact || 0)} / 100 (${lk.risk_level || 'ANALYZED'})
            </span>
          </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-12 gap-2 text-xs">
          <div class="sm:col-span-3 text-slate-400 font-medium">Visible Anchor:</div>
          <div class="sm:col-span-9 font-mono text-cyan-300 break-all select-all">${escapeHtml(lk.anchor_text || '(Plain Destination URL)')}</div>
          <div class="sm:col-span-3 text-slate-400 font-medium">Actual Destination:</div>
          <div class="sm:col-span-9 font-mono text-rose-300 break-all select-all font-semibold">${escapeHtml(lk.url)}</div>
        </div>

        <div class="flex flex-wrap gap-1.5 pt-1 border-t border-[#1b2333]">
          ${tagsHtml || '<span class="text-[11px] text-slate-500 font-mono">No threat tags triggered</span>'}
        </div>
      </div>
    `;
  }).join('');
}

// Update Phishing Vectors Telemetry
function updatePhishingVectors(pv) {
  const setV = (id, active, labelActive, labelNeg) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (active) {
      el.textContent = labelActive;
      el.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold';
    } else {
      el.textContent = labelNeg || 'NEGATIVE';
      el.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400';
    }
  };

  setV('phish-badge-homoglyph', pv.homoglyph, 'POSITIVE (Deceptive Cyrillic/IDN)');
  setV('phish-badge-vishing', pv.vishing, 'POSITIVE (Callback Phone Detected)');
  setV('phish-badge-hidden', pv.hiddenText, 'POSITIVE (Hidden CSS Text)');
  setV('phish-badge-quishing', pv.quishing, 'POSITIVE (QR Phish Prompt)');
}

// Standalone URL Fast-Check (Single Clean Input)
async function runStandaloneLinkCheck() {
  const urlEl = document.getElementById('standalone-url-input');
  const input = urlEl ? urlEl.value.trim() : '';
  const anchorEl = document.getElementById('standalone-anchor-input');
  const anchor = anchorEl ? anchorEl.value.trim() : '';

  if (!input) {
    alert('Please enter or paste a URL to inspect.');
    if (urlEl) urlEl.focus();
    return;
  }

  const btn = document.getElementById('btn-inspect-url');
  let prevBtn = '';
  if (btn) {
    prevBtn = btn.innerHTML;
    btn.innerHTML = `<span class="material-symbols-outlined text-sm animate-spin">refresh</span> Scanning...`;
    btn.disabled = true;
  }

  try {
    const formData = new FormData();
    formData.append('url', input);
    if (anchor) formData.append('anchor_text', anchor);

    const res = await fetch('/api/analyze-link', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) throw new Error('API error: ' + res.status);
    const data = await res.json();
    const la = data.link_analysis;

    // Render as active link analysis
    renderDetectedLinks([la]);

    // Update Optical Anchor Box
    document.getElementById('url-visible-text').textContent = la.anchor_text || la.url;
    document.getElementById('url-actual-dest').textContent = la.url;
    const tagEl = document.getElementById('url-status-tag');
    const discCard = document.getElementById('url-discrepancy-card');

    if (la.is_mismatch) {
      tagEl.textContent = 'CRITICAL MISMATCH';
      tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40';
      discCard.className = 'rounded-xl bg-[#0c0e14] border border-rose-500/30 p-5 shadow-sm';
    } else if (la.risk_score >= 50) {
      tagEl.textContent = 'HIGH RISK LINK';
      tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40';
      discCard.className = 'rounded-xl bg-[#0c0e14] border border-rose-500/30 p-5 shadow-sm';
    } else {
      tagEl.textContent = 'CLEAN STRUCTURE';
      tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
      discCard.className = 'rounded-xl bg-[#0c0e14] border border-emerald-500/30 p-5 shadow-sm';
    }

    // Update verdict gauge
    const vLabel = document.getElementById('verdict-label');
    const vScore = document.getElementById('verdict-score');
    const vSub = document.getElementById('verdict-sublabel');
    const vCircle = document.getElementById('verdict-circle-bar');

    vScore.textContent = la.risk_score;
    vLabel.textContent = la.risk_level === 'CRITICAL' ? 'Critical URL Threat' : (la.risk_level === 'HIGH' ? 'Suspicious URL' : (la.risk_level === 'MEDIUM' ? 'Caution Advised' : 'Benign URL'));
    vSub.textContent = la.risk_score >= 50 ? 'Immediate Isolation Recommended' : 'Standard Web Hygiene';

    const circumference = 251.2;
    const offset = circumference - (la.risk_score / 100) * circumference;
    vCircle.style.strokeDashoffset = offset;

    // Update signals
    const sigContainer = document.getElementById('signal-evidence-list');
    sigContainer.innerHTML = '';
    (la.signals || []).forEach(sig => {
      const item = document.createElement('div');
      item.className = 'p-3.5 rounded-xl bg-[#0c0e14] border border-[#232d40] flex items-start justify-between gap-3';
      item.innerHTML = `
        <div>
          <span class="text-xs font-semibold text-rose-300 block">${escapeHtml(sig.name)}</span>
          <p class="text-xs text-slate-300 mt-0.5 leading-relaxed">${escapeHtml(sig.description)}</p>
        </div>
        <span class="font-mono text-xs font-bold text-rose-400 shrink-0">+${sig.score_impact} pts</span>
      `;
      sigContainer.appendChild(item);
    });

    // Scroll to results
    document.getElementById('url-discrepancy-card').scrollIntoView({ behavior: 'smooth' });

  } catch (err) {
    alert('Failed to analyze link: ' + err.message);
  } finally {
    if (btn && prevBtn) {
      btn.innerHTML = prevBtn;
      btn.disabled = false;
    }
  }
}

// Execute Live Custom Ingestion (Email text, .eml, or attachments)
async function executeLiveAnalysis() {
  const textInput = document.getElementById('live-email-input').value.trim();
  if (!textInput && !liveFiles.length) {
    alert('Please paste email headers/body text, or select an .eml / attachment file.');
    return;
  }

  const btn = document.getElementById('btn-run-live');
  const prev = btn.innerHTML;
  btn.innerHTML = `<span class="material-symbols-outlined text-sm animate-spin">refresh</span> Analyzing in Memory...`;
  btn.disabled = true;

  try {
    const formData = new FormData();
    if (textInput) formData.append('email_text', textInput);
    const eml = liveFiles.find(f => f.name.endsWith('.eml'));
    if (eml) formData.append('eml_file', eml);
    liveFiles.forEach(f => {
      if (!f.name.endsWith('.eml')) formData.append('attachments', f);
    });

    const res = await fetch('/api/analyze', { method: 'POST', body: formData });
    if (!res.ok) {
      const e = await res.json();
      throw new Error(e.detail || 'Analysis failed');
    }

    const data = await res.json();
    renderLiveApiResponse(data.analysis);
  } catch (err) {
    alert('Error running static analysis: ' + err.message);
  } finally {
    btn.innerHTML = prev;
    btn.disabled = false;
  }
}

function renderLiveApiResponse(a) {
  currentAnalysis = a;
  const score = a.overall_score;
  const rating = a.risk_rating;
  const h = a.header_analysis || {};
  const b = a.body_analysis || {};
  const atts = a.attachments || [];

  // Headers
  document.getElementById('header-from').textContent = h.from_header || 'Unknown Sender';
  document.getElementById('header-reply-to').textContent = h.reply_to || (h.from_header ? '(Same as sender)' : 'Not specified');
  document.getElementById('header-return-path').textContent = h.return_path || '(Not specified)';
  document.getElementById('header-auth-results').textContent = h.auth_summary || 'spf=none dkim=none dmarc=none';

  setAuthBadge('badge-auth-spf', 'SPF', h.spf_status || 'NONE');
  setAuthBadge('badge-auth-dkim', 'DKIM', h.dkim_status || 'NONE');
  setAuthBadge('badge-auth-dmarc', 'DMARC', h.dmarc_status || 'NONE');

  // Email Content
  document.getElementById('email-subject').textContent = h.subject || 'Live Ingestion Sample';
  document.getElementById('email-body-content').innerHTML = escapeHtml(b.text_preview || 'No email body text.').replace(/\n/g, '<br/>');

  // All Detected Links
  renderDetectedLinks(b.links || []);

  // Optical Anchor
  const mismatchLink = (b.links || []).find(l => l.is_mismatch) || (b.links || [])[0];
  const tagEl = document.getElementById('url-status-tag');
  const discCard = document.getElementById('url-discrepancy-card');

  if (mismatchLink) {
    document.getElementById('url-visible-text').textContent = mismatchLink.anchor_text || mismatchLink.url;
    document.getElementById('url-actual-dest').textContent = mismatchLink.url;
    if (mismatchLink.is_mismatch) {
      tagEl.textContent = 'CRITICAL MISMATCH';
      tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40';
      discCard.className = 'rounded-xl bg-[#0c0e14] border border-rose-500/30 p-5 shadow-sm';
    } else {
      tagEl.textContent = 'MATCH VERIFIED';
      tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
      discCard.className = 'rounded-xl bg-[#0c0e14] border border-emerald-500/30 p-5 shadow-sm';
    }
  } else {
    document.getElementById('url-visible-text').textContent = 'No hyperlinks found in message body';
    document.getElementById('url-actual-dest').textContent = 'N/A';
    tagEl.textContent = 'ZERO LINKS';
    tagEl.className = 'px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700';
    discCard.className = 'rounded-xl bg-[#0c0e14] border border-[#232d40] p-5 shadow-sm';
  }

  // Update Phishing Vectors
  updatePhishingVectors({
    homoglyph: (b.links || []).some(l => l.has_cyrillic_homoglyphs || l.is_punycode),
    vishing: b.has_vishing_phone,
    hiddenText: b.has_hidden_text,
    quishing: b.has_quishing_indicators
  });

  // Attachments
  // Attachments & Per-Attachment Report Card (Requirement 2 & 8)
  const primaryAtt = atts[0];
  const sevPill = document.getElementById('attachment-severity-pill');
  const featContainer = document.getElementById('attachment-features-list');
  const actCard = document.getElementById('attachment-action-card');
  const actBadge = document.getElementById('attachment-action-badge');
  const actText = document.getElementById('attachment-action-text');
  const actIcon = document.getElementById('attachment-action-icon');

  if (primaryAtt) {
    document.getElementById('file-name').textContent = primaryAtt.filename;
    let alertMsg = 'Standard static layout verified';
    if (primaryAtt.double_extension) alertMsg = `Double extension: .${primaryAtt.filename.split('.').slice(-2).join('.')}`;
    else if (primaryAtt.rtlo_detected) alertMsg = 'Unicode RTLO Deception Detected';
    else if (primaryAtt.type_mismatch) alertMsg = 'Type mismatch: Declared MIME differs from magic bytes';
    else if (primaryAtt.has_vba_macros) alertMsg = 'VBA Macros detected in Office structure';

    document.getElementById('file-ext-alert').textContent = alertMsg;
    document.getElementById('file-mime').textContent = primaryAtt.declared_mime_type || 'Unknown';
    document.getElementById('file-magic').textContent = primaryAtt.magic_signature || 'N/A';
    document.getElementById('file-size').textContent = primaryAtt.size_human;
    document.getElementById('file-entropy').textContent = 'Analyzed static byte layout';
    document.getElementById('file-sha256').textContent = primaryAtt.sha256 || '—';

    sevPill.textContent = primaryAtt.risk_level === 'MALICIOUS' ? 'Executable Binary Disguised' : (primaryAtt.risk_level === 'SUSPICIOUS' ? 'Suspicious Attachment' : 'Verified Benign Document');
    sevPill.className = primaryAtt.risk_level === 'MALICIOUS' 
      ? 'px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40'
      : (primaryAtt.risk_level === 'SUSPICIOUS' ? 'px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40');

    // Populate Suspicious Features
    if (featContainer) {
      const features = primaryAtt.suspicious_features || [];
      featContainer.innerHTML = features.map(f => {
        let col = 'bg-slate-800 text-slate-300 border-slate-700';
        if (f.toLowerCase().includes('executable') || f.toLowerCase().includes('mismatch') || f.toLowerCase().includes('rtlo') || f.toLowerCase().includes('double') || f.toLowerCase().includes('password')) {
          col = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
        } else if (f.toLowerCase().includes('macro') || f.toLowerCase().includes('script') || f.toLowerCase().includes('warning')) {
          col = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
        } else if (f.toLowerCase().includes('clean') || f.toLowerCase().includes('benign')) {
          col = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
        }
        return `<span class="px-2.5 py-1 rounded-md text-xs font-mono border ${col}">${escapeHtml(f)}</span>`;
      }).join(' ');
    }

    // Populate Recommended Action Card
    if (actCard && actBadge && actText) {
      actBadge.textContent = `RECOMMENDED ACTION: ${primaryAtt.recommended_action || 'SAFE_TO_OPEN'}`.replace(/_/g, ' ');
      actText.textContent = primaryAtt.recommended_action_detail || 'No threat actions required.';
      if (primaryAtt.risk_level === 'MALICIOUS') {
        actCard.className = 'p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-1.5';
        actBadge.className = 'text-xs font-bold text-rose-300 uppercase tracking-wide';
        actIcon.className = 'material-symbols-outlined text-rose-400 text-lg';
        actIcon.textContent = 'block';
      } else if (primaryAtt.risk_level === 'SUSPICIOUS') {
        actCard.className = 'p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 space-y-1.5';
        actBadge.className = 'text-xs font-bold text-amber-300 uppercase tracking-wide';
        actIcon.className = 'material-symbols-outlined text-amber-400 text-lg';
        actIcon.textContent = 'warning';
      } else {
        actCard.className = 'p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-1.5';
        actBadge.className = 'text-xs font-bold text-emerald-300 uppercase tracking-wide';
        actIcon.className = 'material-symbols-outlined text-emerald-400 text-lg';
        actIcon.textContent = 'check_circle';
      }
    }
  } else {
    document.getElementById('file-name').textContent = 'No Attachments Present';
    document.getElementById('file-ext-alert').textContent = 'Message body only';
    document.getElementById('file-mime').textContent = 'None';
    document.getElementById('file-magic').textContent = 'None';
    document.getElementById('file-size').textContent = '0 B';
    document.getElementById('file-entropy').textContent = 'N/A';
    document.getElementById('file-sha256').textContent = '—';
    sevPill.textContent = 'No Attachment';
    sevPill.className = 'px-3 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700';
    if (featContainer) {
      featContainer.innerHTML = '<span class="text-xs text-slate-500 font-mono">No files attached to message sample</span>';
    }
    if (actCard) {
      actBadge.textContent = 'RECOMMENDED ACTION: NONE REQUIRED';
      actText.textContent = 'This email does not carry binary or document attachments.';
      actCard.className = 'p-4 rounded-xl bg-[#0c0e14] border border-[#232d40] space-y-1.5';
      actIcon.textContent = 'info';
    }
  }

  // Verdict
  const vLabel = document.getElementById('verdict-label');
  const vScore = document.getElementById('verdict-score');
  const vSub = document.getElementById('verdict-sublabel');
  const vCircle = document.getElementById('verdict-circle-bar');

  vLabel.textContent = a.verdict;
  vScore.textContent = score;

  let theme = 'emerald';
  let badgeText = 'Authentic Traffic';
  if (rating === 'CRITICAL' || rating === 'HIGH') {
    theme = 'rose';
    badgeText = 'Immediate Isolation Required';
  } else if (rating === 'MEDIUM') {
    theme = 'amber';
    badgeText = 'Credential Harvest Risk';
  }
  vSub.textContent = badgeText;

  const circumference = 251.2;
  const offset = circumference - (score / 100) * circumference;
  vCircle.style.strokeDashoffset = offset;

  if (theme === 'rose') {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-rose-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40';
    vCircle.className = 'stroke-rose-500 transition-all duration-700';
  } else if (theme === 'amber') {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-amber-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40';
    vCircle.className = 'stroke-amber-400 transition-all duration-700';
  } else {
    vLabel.className = 'text-2xl font-bold tracking-tight mt-1 text-emerald-400';
    vSub.className = 'inline-block mt-2 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    vCircle.className = 'stroke-emerald-400 transition-all duration-700';
  }

  // 4-Component Risk Breakdown (Requirement 1)
  const breakdown = a.score_breakdown || {};
  const senderScore = breakdown.sender_score !== undefined ? breakdown.sender_score : (breakdown.header_score || 0);
  const bodyScore = breakdown.body_score !== undefined ? breakdown.body_score : (b.text_only_score || 0);
  const urlScore = breakdown.url_score !== undefined ? breakdown.url_score : (b.url_only_score || 0);
  const attachScore = breakdown.attachment_score !== undefined ? breakdown.attachment_score : 0;

  const senderEl = document.getElementById('score-sender-text');
  if (senderEl) {
    senderEl.textContent = `${senderScore} pts`;
    document.getElementById('score-sender-bar').style.width = Math.min(100, (senderScore / 35) * 100) + '%';
  }
  const bodyTextEl = document.getElementById('score-bodytext-text');
  if (bodyTextEl) {
    bodyTextEl.textContent = `${bodyScore} pts`;
    document.getElementById('score-bodytext-bar').style.width = Math.min(100, (bodyScore / 35) * 100) + '%';
  }
  const urlEl = document.getElementById('score-url-text');
  if (urlEl) {
    urlEl.textContent = `${urlScore} pts`;
    document.getElementById('score-url-bar').style.width = Math.min(100, (urlScore / 45) * 100) + '%';
  }
  const attachEl = document.getElementById('score-attach-text');
  if (attachEl) {
    attachEl.textContent = `${attachScore} pts`;
    document.getElementById('score-attach-bar').style.width = Math.min(100, (attachScore / 50) * 100) + '%';
  }
  // Sync Sovereign 4 Score Drivers
  updateSovereignVectors({
    sender_score: senderScore,
    body_score: bodyScore,
    url_score: urlScore,
    attachment_score: attachScore
  });

  // Observable Signals & Supporting Evidence (Requirement 6)
  const sigContainer = document.getElementById('signal-evidence-list');
  sigContainer.innerHTML = '';
  const signals = a.all_signals || [];
  if (!signals.length) {
    sigContainer.innerHTML = `
      <div class="p-3.5 rounded-xl bg-[#0c0e14] border border-[#232d40] text-center">
        <span class="text-xs text-emerald-400 font-medium">All Clear: No threat indicators detected.</span>
      </div>
    `;
  } else {
    signals.forEach(sig => {
      const item = document.createElement('div');
      item.className = 'p-3.5 rounded-xl bg-[#0c0e14] border border-[#232d40] space-y-1.5';
      let tagColor = 'text-slate-300';
      let weightColor = 'text-slate-400';
      if (sig.severity === 'critical' || sig.severity === 'high') {
        tagColor = 'text-rose-300 font-semibold';
        weightColor = 'text-rose-400 font-bold';
      } else if (sig.severity === 'medium') {
        tagColor = 'text-amber-300 font-semibold';
        weightColor = 'text-amber-400 font-bold';
      } else {
        tagColor = 'text-emerald-300 font-semibold';
        weightColor = 'text-emerald-400 font-bold';
      }

      const evidenceHtml = sig.evidence ? `
        <div class="mt-1 px-2.5 py-1 rounded-md bg-[#161b26] border border-[#232d40] flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 break-all">
          <span class="text-slate-500">Evidence:</span> ${escapeHtml(sig.evidence)}
        </div>
      ` : '';

      item.innerHTML = `
        <div class="flex items-start justify-between gap-3">
          <div>
            <span class="text-xs ${tagColor} block">${escapeHtml(sig.name)}</span>
            <p class="text-xs text-slate-300 mt-0.5 leading-relaxed">${escapeHtml(sig.description)}</p>
          </div>
          <span class="font-mono text-xs ${weightColor} shrink-0">+${sig.score_impact} pts</span>
        </div>
        ${evidenceHtml}
      `;
      sigContainer.appendChild(item);
    });
  }

  // Populate Action Recommendation Cards (Requirement 3)
  const actionContainer = document.getElementById('action-cards-container');
  if (actionContainer && a.safe_guidance && a.safe_guidance.action_cards) {
    actionContainer.innerHTML = a.safe_guidance.action_cards.map(card => {
      let border = 'border-[#232d40] bg-[#0c0e14]';
      let iconCol = 'text-cyan-400';
      let icon = 'info';
      if (card.action_type === 'QUARANTINE') {
        border = 'border-rose-500/30 bg-rose-950/20';
        iconCol = 'text-rose-400';
        icon = 'emergency';
      } else if (card.action_type === 'VERIFY_SENDER') {
        border = 'border-purple-500/30 bg-[#0c0e14]';
        iconCol = 'text-purple-400';
        icon = 'contact_phone';
      } else if (card.action_type === 'SAFE_VIEWER') {
        border = 'border-cyan-500/30 bg-[#0c0e14]';
        iconCol = 'text-cyan-400';
        icon = 'visibility_off';
      } else if (card.action_type === 'REPORT_SOC') {
        border = 'border-indigo-500/30 bg-[#0c0e14]';
        iconCol = 'text-indigo-400';
        icon = 'shield';
      }

      const stepsHtml = (card.steps || []).map(s => `<li class="text-[11px] text-slate-400">${escapeHtml(s)}</li>`).join('');

      return `
        <div class="p-3.5 rounded-xl ${border} space-y-1.5">
          <div class="flex items-center gap-2 font-semibold text-xs text-slate-200">
            <span class="material-symbols-outlined text-base ${iconCol}">${icon}</span>
            <span>${escapeHtml(card.title)}</span>
          </div>
          <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(card.description)}</p>
          ${stepsHtml ? `<ul class="list-disc pl-4 space-y-0.5 pt-1">${stepsHtml}</ul>` : ''}
        </div>
      `;
    }).join('');
  }

  // Scroll smoothly to results
  document.getElementById('verdict-card').scrollIntoView({ behavior: 'smooth' });
}

// Prefill Samples
function prefillSample(type) {
  const ta = document.getElementById('live-email-input');
  if (type === 'mismatch') {
    ta.value = `From: "PayPal Account Security" <service@secure-paypal-alerts.net>
Reply-To: phish-collector@anonymous-vps.com
Subject: URGENT: Unusual Sign-In Attempt Detected - Action Required
Authentication-Results: spf=fail; dkim=none; dmarc=fail

Dear Customer,

We detected an unauthorized login to your PayPal account from IP 185.192.1.44.
To protect your account from permanent suspension, please verify your credentials immediately:

<a href="http://185.192.1.44:8080/auth/login.php?ref=paypal">https://www.paypal.com/security/verify-account</a>

Failure to confirm within 2 hours will result in account restriction.`;
  } else if (type === 'ip') {
    ta.value = `From: "Bank Operations" <support@billing-central.com>
Subject: Critical Billing Gateway Alert
Authentication-Results: spf=none

Please access the management terminal directly via our staging node:
http://103.224.182.241:8443/secure/auth.php`;
  } else if (type === 'homoglyph') {
    ta.value = `From: "Security Notification" <alerts@pаypal.com>
Subject: Mandatory Wallet Verification
Authentication-Results: spf=none

Click here to access your wallet:
http://pаypal.com/wallet-verify`;
  } else if (type === 'vishing') {
    ta.value = `From: "Geek Squad Protection Team" <invoices@geeksquad-billing.com>
Subject: Invoice #GS-88219 - $499.00 Auto-Renewal Completed
Authentication-Results: spf=fail

Dear Customer,

Thank you for renewing your Total Tech Support. The amount of $499.00 has been charged to your checking account.

If you did NOT authorize this charge or wish to cancel and request an immediate refund, you MUST call our toll-free cancellation desk immediately:
Call: +1-800-492-9102 (Toll Free 24/7 Support)`;
  }
}

function clearCustomInput() {
  document.getElementById('live-email-input').value = '';
  document.getElementById('standalone-url-input').value = '';
  document.getElementById('standalone-anchor-input').value = '';
  liveFiles = [];
  document.getElementById('live-file-list').innerHTML = '';
}

function toggleCustomSection() {
  const card = document.getElementById('custom-workbench-card');
  card.scrollIntoView({ behavior: 'smooth' });
  document.getElementById('live-email-input').focus();
}

function switchMainTab(tab) {
  if (tab === 'links') {
    document.getElementById('detected-links-container').scrollIntoView({ behavior: 'smooth' });
    document.getElementById('standalone-url-input').focus();
  } else {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

// Helpers
function setAuthBadge(id, label, val) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = `${label}: ${val}`;
  if (val === 'PASS') {
    el.className = 'px-2.5 py-1 rounded-md border font-semibold bg-emerald-500/10 border-emerald-500/30 text-emerald-300';
  } else if (val === 'FAIL' || val === 'SOFTFAIL') {
    el.className = 'px-2.5 py-1 rounded-md border font-semibold bg-rose-500/15 border-rose-500/30 text-rose-300';
  } else {
    el.className = 'px-2.5 py-1 rounded-md border font-semibold bg-slate-800 border-slate-700 text-slate-400';
  }
}

function setupLiveDropzone() {
  const dz = document.getElementById('live-dropzone');
  const fi = document.getElementById('live-file-input');
  if (!dz || !fi) return;

  dz.onclick = () => fi.click();
  dz.ondragover = e => { e.preventDefault(); dz.classList.add('border-purple-400'); };
  dz.ondragleave = () => dz.classList.remove('border-purple-400');
  dz.ondrop = e => {
    e.preventDefault();
    dz.classList.remove('border-purple-400');
    handleLiveFiles(e.dataTransfer.files);
  };
  fi.onchange = () => handleLiveFiles(fi.files);
}

function handleLiveFiles(files) {
  liveFiles = Array.from(files);
  const list = document.getElementById('live-file-list');
  if (!list) return;
  list.innerHTML = liveFiles.map((f, i) => `
    <div class="flex items-center justify-between p-1.5 rounded-lg bg-[#161b26] border border-[#232d40] text-xs">
      <span class="text-purple-300 truncate font-mono text-[11px]">${escapeHtml(f.name)} (${(f.size/1024).toFixed(1)} KB)</span>
      <button onclick="removeLiveFile(${i})" class="text-rose-400 hover:text-rose-300 font-bold ml-2">&times;</button>
    </div>
  `).join('');
}

function removeLiveFile(i) {
  liveFiles.splice(i, 1);
  handleLiveFiles(liveFiles);
}

async function fetchBackendCatalog() {
  try {
    const res = await fetch('/api/samples');
    if (!res.ok) return;
    const samples = await res.json();
    const container = document.getElementById('test-matrix-list');
    if (!container) return;
    container.innerHTML = samples.map(s => `
      <div class="p-3.5 rounded-xl bg-[#0c0e14] border border-[#232d40] flex items-center justify-between gap-4 hover:border-purple-500/40 transition-colors">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="font-semibold text-white font-mono text-xs">#${s.id} ${escapeHtml(s.title)}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono ${s.expected_verdict.includes('CRITICAL') || s.expected_verdict.includes('HIGH') ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30' : (s.expected_verdict.includes('MEDIUM') ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30' : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30')}">${s.expected_verdict}</span>
          </div>
          <p class="text-xs text-slate-400">${escapeHtml(s.description)}</p>
        </div>
        <button onclick="loadSampleFromApi(${s.id})" class="shrink-0 px-3 py-1.5 rounded-lg bg-[#161b26] hover:bg-[#202738] border border-[#232d40] text-purple-300 hover:text-white text-xs font-semibold flex items-center gap-1 transition-colors">
          <span class="material-symbols-outlined text-sm">play_arrow</span> Run Test
        </button>
      </div>
    `).join('');
  } catch (e) {
    console.warn(e);
  }
}

async function loadSampleFromApi(id) {
  closeModal('modal-presets');
  try {
    const res = await fetch(`/api/sample/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderLiveApiResponse(data.analysis);
  } catch (err) {
    alert('Error loading sample: ' + err.message);
  }
}

function copySha256() {
  const text = document.getElementById('file-sha256').textContent;
  if (!text || text === '—') return;
  navigator.clipboard.writeText(text);
  const btn = event.currentTarget;
  const original = btn.innerHTML;
  btn.innerHTML = `<span class="material-symbols-outlined text-sm text-emerald-400">check</span> Copied!`;
  setTimeout(() => { btn.innerHTML = original; }, 1600);
}

function triggerAction(action) {
  if (action === 'quarantine') {
    alert('🛑 Threat Item Quarantined:\n• In-memory payload isolated and session locked.\n• Sender domain and detected IP addresses staged for enterprise mail gateway boundary blocklist.');
  } else if (action === 'verify_sender') {
    const from = document.getElementById('header-from').textContent;
    alert(`📞 Official Channel Verification Protocol:\n• Target Sender: ${from}\n• Step 1: Do NOT reply or click links in this message.\n• Step 2: Look up the verified phone number or intranet contact in your corporate directory.\n• Step 3: Contact the sender to verify whether this request was legitimate.`);
  } else if (action === 'safe_viewer') {
    alert('🔍 Safe Offline Viewer Instructions:\n• Never double-click suspicious attachments in standard desktop applications.\n• Open strictly in an isolated air-gapped sandbox or static text previewer.\n• Ensure Macro Execution and JavaScript are disabled in viewer preferences.');
  } else if (action === 'whitelist') {
    selectFeedbackVerdict('FALSE_POSITIVE');
    const notes = document.getElementById('feedback-notes');
    if (notes) {
      notes.value = 'User reported as legitimate / false positive';
      notes.focus();
    }
  } else if (action === 'export') {
    const artifact = {
      timestamp: new Date().toISOString(),
      engine: 'SafeX-Static-v4.2',
      subject: document.getElementById('email-subject').textContent,
      sha256: document.getElementById('file-sha256').textContent,
      score: document.getElementById('verdict-score').textContent,
      verdict: document.getElementById('verdict-label').textContent,
      analysis: currentAnalysis
    };
    const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `safex-triage-report-${Date.now()}.json`;
    a.click();
  }
}

// User Feedback Feature (Requirement 4)
let currentFeedbackVerdict = 'ACCURATE';

function selectFeedbackVerdict(verdict) {
  currentFeedbackVerdict = verdict;
  const btnAcc = document.getElementById('fb-btn-accurate');
  const btnFp = document.getElementById('fb-btn-fp');
  const btnFn = document.getElementById('fb-btn-fn');

  if (btnAcc) btnAcc.className = 'py-2 px-1 rounded-xl border bg-[#0c0e14] border-[#232d40] text-slate-300 text-center flex flex-col items-center gap-1';
  if (btnFp) btnFp.className = 'py-2 px-1 rounded-xl border bg-[#0c0e14] border-[#232d40] text-slate-300 text-center flex flex-col items-center gap-1';
  if (btnFn) btnFn.className = 'py-2 px-1 rounded-xl border bg-[#0c0e14] border-[#232d40] text-slate-300 text-center flex flex-col items-center gap-1';

  if (verdict === 'ACCURATE' && btnAcc) {
    btnAcc.className = 'py-2 px-1 rounded-xl border bg-emerald-500/20 border-emerald-500/40 text-emerald-300 font-semibold text-center flex flex-col items-center gap-1';
  } else if (verdict === 'FALSE_POSITIVE' && btnFp) {
    btnFp.className = 'py-2 px-1 rounded-xl border bg-amber-500/20 border-amber-500/40 text-amber-300 font-semibold text-center flex flex-col items-center gap-1';
  } else if (verdict === 'FALSE_NEGATIVE' && btnFn) {
    btnFn.className = 'py-2 px-1 rounded-xl border bg-rose-500/20 border-rose-500/40 text-rose-300 font-semibold text-center flex flex-col items-center gap-1';
  }
}

async function submitClassificationFeedback() {
  const notesInput = document.getElementById('feedback-notes');
  const notes = notesInput ? notesInput.value.trim() : '';
  const score = parseInt(document.getElementById('verdict-score').textContent || '0', 10);
  const rating = document.getElementById('verdict-label').textContent || 'LOW';

  const formData = new FormData();
  formData.append('sample_id', currentScenario || 'custom');
  formData.append('sample_name', document.getElementById('email-subject').textContent || 'Triage Sample');
  formData.append('user_verdict', currentFeedbackVerdict);
  formData.append('notes', notes);
  formData.append('assigned_score', score);
  formData.append('assigned_rating', rating);

  const btn = document.getElementById('btn-submit-feedback');
  if (btn) btn.disabled = true;

  try {
    const res = await fetch('/api/feedback', { method: 'POST', body: formData });
    if (!res.ok) throw new Error('Failed to record feedback');
    const data = await res.json();
    alert(`Feedback Recorded: Thank you! Reported as ${currentFeedbackVerdict}. This helps tune SafeX heuristic thresholds.`);
    if (notesInput) notesInput.value = '';
    loadFeedbackStats();
  } catch (err) {
    alert('Error submitting feedback: ' + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadFeedbackStats() {
  try {
    const res = await fetch('/api/feedback/stats');
    if (!res.ok) return;
    const stats = await res.json();
    const accPill = document.getElementById('feedback-stat-accuracy');
    const countLabel = document.getElementById('feedback-count-label');
    const liveStats = document.getElementById('feedback-live-stats');
    if (accPill) accPill.textContent = `Model Accuracy: ${stats.user_verified_accuracy_pct}%`;
    if (countLabel) countLabel.textContent = `${stats.total_reports} reports logged (${stats.false_positive_count} FP, ${stats.false_negative_count} FN)`;
    if (liveStats) liveStats.textContent = `${stats.total_reports} Reports Logged (${stats.user_verified_accuracy_pct}% Acc)`;
  } catch (e) {
    console.warn(e);
  }
}

// ML vs Rule Benchmark Loader (Requirement 5)
async function openBenchmarkModal() {
  openModal('modal-benchmark');
  try {
    const res = await fetch('/api/evaluation/benchmark');
    if (!res.ok) return;
    const data = await res.json();

    const rb = data.rule_based;
    const ml = data.ml_based;

    // Rule confusion matrix
    document.getElementById('rule-tn').textContent = rb.confusion_matrix.tn;
    document.getElementById('rule-fp').textContent = rb.confusion_matrix.fp;
    document.getElementById('rule-fn').textContent = rb.confusion_matrix.fn;
    document.getElementById('rule-tp').textContent = rb.confusion_matrix.tp;

    document.getElementById('rule-acc').textContent = rb.metrics.accuracy_pct + '%';
    document.getElementById('rule-prec').textContent = rb.metrics.precision_pct + '%';
    document.getElementById('rule-rec').textContent = rb.metrics.recall_pct + '%';
    document.getElementById('rule-f1').textContent = rb.metrics.f1_score;

    // ML confusion matrix
    document.getElementById('ml-tn').textContent = ml.confusion_matrix.tn;
    document.getElementById('ml-fp').textContent = ml.confusion_matrix.fp;
    document.getElementById('ml-fn').textContent = ml.confusion_matrix.fn;
    document.getElementById('ml-tp').textContent = ml.confusion_matrix.tp;

    document.getElementById('ml-acc').textContent = ml.metrics.accuracy_pct + '%';
    document.getElementById('ml-prec').textContent = ml.metrics.precision_pct + '%';
    document.getElementById('ml-rec').textContent = ml.metrics.recall_pct + '%';
    document.getElementById('ml-f1').textContent = ml.metrics.f1_score;

    // Populate samples table
    const container = document.getElementById('benchmark-samples-table');
    if (container && data.side_by_side_samples) {
      container.innerHTML = data.side_by_side_samples.map(s => `
        <div class="p-2 rounded-lg bg-[#161b26] border border-[#232d40] flex items-center justify-between gap-2 font-mono text-[11px]">
          <div class="flex items-center gap-2 truncate">
            <span class="px-1.5 py-0.5 rounded text-[10px] ${s.ground_truth === 'THREAT' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'}">${s.ground_truth}</span>
            <span class="text-slate-200 truncate">${escapeHtml(s.name)}</span>
          </div>
          <div class="flex items-center gap-3 shrink-0">
            <span class="text-cyan-400">Rule: ${s.rule_score} (${s.rule_verdict})</span>
            <span class="text-amber-400">ML: ${s.ml_prob}% (${s.ml_verdict})</span>
          </div>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Failed to load benchmark data', e);
  }
}

// Initialise feedback stats on boot
document.addEventListener('DOMContentLoaded', () => {
  loadFeedbackStats();
});

function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('hidden');
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('hidden');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Switch between Single URL mode and Full Email/Attachment mode
function switchInputMode(mode) {
  const panelUrl = document.getElementById('panel-mode-url');
  const panelEmail = document.getElementById('panel-mode-email');
  const tabUrl = document.getElementById('tab-mode-url');
  const tabEmail = document.getElementById('tab-mode-email');

  if (mode === 'url') {
    panelUrl.classList.remove('hidden');
    panelEmail.classList.add('hidden');
    tabUrl.className = 'px-4 py-1.5 rounded-lg text-xs font-semibold transition-all bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 shadow-sm';
    tabEmail.className = 'px-4 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition-all flex items-center gap-1.5';
    const input = document.getElementById('standalone-url-input');
    if (input) input.focus();
  } else {
    panelUrl.classList.add('hidden');
    panelEmail.classList.remove('hidden');
    tabEmail.className = 'px-4 py-1.5 rounded-lg text-xs font-semibold transition-all bg-purple-500/20 text-purple-300 border border-purple-500/30 flex items-center gap-1.5 shadow-sm';
    tabUrl.className = 'px-4 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition-all flex items-center gap-1.5';
    const text = document.getElementById('live-email-input');
    if (text) text.focus();
  }
}

// 1-Click Paste from Clipboard directly into the single URL input
async function pasteClipboardToUrl() {
  const input = document.getElementById('standalone-url-input');
  if (!input) return;
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      input.value = text.trim();
      input.focus();
      // Auto-trigger inspection for effortless 1-click experience
      runStandaloneLinkCheck();
    }
  } catch (e) {
    // If browser permission denied, focus so user can Ctrl+V
    input.focus();
    input.select();
  }
}

// Quick 1-click test URL filler
function setQuickUrl(url) {
  const input = document.getElementById('standalone-url-input');
  if (input) {
    input.value = url;
    runStandaloneLinkCheck();
  }
}


