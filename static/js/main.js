/**
 * CyberShield AI - Core Frontend Logic
 * Manages URL validation, cyber scanning animations, API calls, and result presentation.
 */

document.addEventListener('DOMContentLoaded', () => {
  initScanner();
  initPresetChips();
  initContactForm();
  initMobileMenu();
});

/* ==========================================================================
   Toast Notification System
   ========================================================================== */
function showToast(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const iconSvg = type === 'success' 
    ? '<svg width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>'
    : type === 'error'
    ? '<svg width="18" height="18" fill="none" stroke="#ef4444" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>'
    : '<svg width="18" height="18" fill="none" stroke="#00f5d4" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';

  toast.innerHTML = `
    <div style="display:flex; align-items:center; gap:0.6rem;">
      ${iconSvg}
      <span>${escapeHtml(message)}</span>
    </div>
    <button style="background:transparent; border:none; color:#64748b; cursor:pointer;" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/* ==========================================================================
   Scanner Execution & Cyber Animation Sequence
   ========================================================================== */
function initScanner() {
  const form = document.getElementById('scanForm');
  const input = document.getElementById('urlInput');
  const btnScan = document.getElementById('btnScan');
  const terminal = document.getElementById('scanningTerminal');
  const terminalLogs = document.getElementById('terminalLogs');
  const resultsSection = document.getElementById('resultsSection');

  if (!form || !input) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const rawUrl = input.value.trim();

    if (!rawUrl) {
      showToast('Please enter a website URL to scan.', 'error');
      input.focus();
      return;
    }

    // Set UI to scanning state
    btnScan.disabled = true;
    btnScan.innerHTML = `<span class="log-spinner"></span> Scanning...`;
    resultsSection.style.display = 'none';
    terminal.style.display = 'block';
    terminalLogs.innerHTML = '';

    // Scroll to terminal smoothly
    terminal.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Step-by-step simulated cyber analysis logs
    const scanSteps = [
      "Normalizing URL structure and target scheme...",
      "Resolving hostname & inspecting IP address vectors...",
      "Verifying SSL / Transport Layer Security (TLS)...",
      "Scanning for Punycode homographs & typosquatting...",
      "Executing lexical keyword & brand impersonation heuristics...",
      "Calculating Shannon entropy & synthesizing AI risk score..."
    ];

    let stepIndex = 0;
    const stepInterval = setInterval(() => {
      if (stepIndex < scanSteps.length) {
        const line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = `<span class="log-prefix">&gt;</span> <span>${scanSteps[stepIndex]}</span>`;
        terminalLogs.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
        stepIndex++;
      }
    }, 220);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl })
      });

      const data = await response.json();

      // Ensure minimum animation time for presentation feel (approx 1.2s)
      setTimeout(() => {
        clearInterval(stepInterval);
        btnScan.disabled = false;
        btnScan.innerHTML = `
          <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          Scan Website
        `;
        terminal.style.display = 'none';

        if (data.success) {
          renderScanResults(data);
          resultsSection.style.display = 'block';
          resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
          showToast(`Security assessment complete: ${data.risk_label}`, data.risk_level === 'Low' ? 'success' : data.risk_level === 'Medium' ? 'info' : 'error');
        } else {
          showToast(data.error || 'Failed to analyze URL. Please check input syntax.', 'error');
        }
      }, 1400);

    } catch (err) {
      clearInterval(stepInterval);
      btnScan.disabled = false;
      btnScan.innerHTML = `Scan Website`;
      terminal.style.display = 'none';
      showToast('Server communication error. Check your local Flask connection.', 'error');
      console.error(err);
    }
  });
}

/* ==========================================================================
   Render Comprehensive Scan Results
   ========================================================================== */
function renderScanResults(data) {
  // 1. URL and metadata
  document.getElementById('resTargetUrl').textContent = data.url;
  document.getElementById('resHostname').textContent = data.hostname;
  document.getElementById('resTimestamp').textContent = data.scan_timestamp;

  // 2. Risk Level Badge
  const statusBadge = document.getElementById('resStatusBadge');
  statusBadge.className = `badge ${data.badge_class}`;
  statusBadge.innerHTML = `<span class="badge-pulse"></span> ${data.risk_label}`;

  // 3. Circular Gauge Animation
  const gaugeNumber = document.getElementById('resGaugeNumber');
  const progressCircle = document.getElementById('resGaugeProgress');
  const gaugeClassification = document.getElementById('resGaugeClassification');

  gaugeClassification.textContent = data.risk_label;
  gaugeClassification.style.color = data.color;

  // Animate count-up number
  animateCountUp(gaugeNumber, 0, data.risk_score, 1200);

  // Animate SVG stroke offset (circumference = 2 * PI * 90 ≈ 565.48)
  const circumference = 565.48;
  const offset = circumference - (data.risk_score / 100) * circumference;
  progressCircle.style.stroke = data.color;
  // trigger animation
  setTimeout(() => {
    progressCircle.style.strokeDashoffset = offset;
  }, 50);

  // 4. Key Indicators
  const protocolValue = document.getElementById('resProtocolValue');
  if (data.is_https) {
    protocolValue.innerHTML = `<span style="color:#10b981;">✓ HTTPS Encrypted</span>`;
  } else {
    protocolValue.innerHTML = `<span style="color:#ef4444;">⚠ Plain HTTP (Unsafe)</span>`;
  }

  const hostTypeValue = document.getElementById('resHostTypeValue');
  hostTypeValue.textContent = data.is_ip ? 'Raw IP Address (High Risk)' : 'Standard Named Domain';
  hostTypeValue.style.color = data.is_ip ? '#ef4444' : '#f8fafc';

  const tldValue = document.getElementById('resTldValue');
  tldValue.textContent = data.tld ? `.${data.tld}` : 'None (IP Host)';

  const warningsCountValue = document.getElementById('resWarningsCountValue');
  warningsCountValue.textContent = `${data.warnings.length} Active Vectors`;
  warningsCountValue.style.color = data.warnings.length > 0 ? (data.risk_level === 'High' ? '#ef4444' : '#f59e0b') : '#10b981';

  // 5. Warning Signs List
  const warningsList = document.getElementById('resWarningsList');
  warningsList.innerHTML = '';

  if (data.warnings.length === 0) {
    warningsList.innerHTML = `
      <div class="signal-item positive">
        <div class="signal-icon-wrapper">
          <svg width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        </div>
        <div class="signal-content">
          <h5>No Obvious Heuristic Threat Flags</h5>
          <p>No high-risk keywords, typosquatting patterns, or raw IP redirects were detected.</p>
        </div>
      </div>
    `;
  } else {
    data.warnings.forEach(w => {
      const item = document.createElement('div');
      item.className = `signal-item ${w.severity}`;
      const iconColor = w.severity === 'critical' ? '#ef4444' : w.severity === 'warning' ? '#f59e0b' : '#3b82f6';

      item.innerHTML = `
        <div class="signal-icon-wrapper">
          <svg width="18" height="18" fill="none" stroke="${iconColor}" stroke-width="2" viewBox="0 0 24 24">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </div>
        <div class="signal-content">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <h5>${escapeHtml(w.title)}</h5>
            <span style="font-size:0.75rem; font-weight:700; color:${iconColor}; background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:4px;">
              +${w.points} Pts
            </span>
          </div>
          <p>${escapeHtml(w.desc)}</p>
        </div>
      `;
      warningsList.appendChild(item);
    });
  }

  // 6. Positive Trust Signals List
  const positiveList = document.getElementById('resPositiveList');
  positiveList.innerHTML = '';
  if (data.positive_signals.length === 0) {
    positiveList.innerHTML = `
      <div class="signal-item warning">
        <div class="signal-icon-wrapper">
          <svg width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        </div>
        <div class="signal-content">
          <h5>Limited Trust Signals</h5>
          <p>Website lacks standard baseline trust indicators like TLS certificates or reputable domain registration.</p>
        </div>
      </div>
    `;
  } else {
    data.positive_signals.forEach(p => {
      const item = document.createElement('div');
      item.className = 'signal-item positive';
      item.innerHTML = `
        <div class="signal-icon-wrapper">
          <svg width="18" height="18" fill="none" stroke="#10b981" stroke-width="2" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        </div>
        <div class="signal-content">
          <h5>${escapeHtml(p.title)}</h5>
          <p>${escapeHtml(p.desc)}</p>
        </div>
      `;
      positiveList.appendChild(item);
    });
  }

  // 7. Score Explanation Accordion / List
  const reasonsList = document.getElementById('resScoreReasonsList');
  reasonsList.innerHTML = '';
  data.score_reasons.forEach(r => {
    const li = document.createElement('li');
    const isWarn = r.type === 'warning';
    li.innerHTML = `
      <strong style="color:${isWarn ? '#f87171' : '#6ee7b7'};">${escapeHtml(r.factor)}</strong>
      <span>(${escapeHtml(r.impact)}):</span>
      <span style="color:#94a3b8;">${escapeHtml(r.detail)}</span>
    `;
    reasonsList.appendChild(li);
  });

  // 8. Actionable Recommendations
  const recList = document.getElementById('resRecommendationsList');
  recList.innerHTML = '';
  data.recommendations.forEach(rec => {
    const li = document.createElement('li');
    li.innerHTML = `
      <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
        <path d="M9 18l6-6-6-6"></path>
      </svg>
      <span>${escapeHtml(rec)}</span>
    `;
    recList.appendChild(li);
  });

  // 9. Attach Copy Report handler
  const btnCopyReport = document.getElementById('btnCopyReport');
  if (btnCopyReport) {
    btnCopyReport.onclick = () => {
      const summaryText = `CyberShield AI Threat Report\nURL: ${data.url}\nRisk Score: ${data.risk_score}/100 (${data.risk_label})\nProtocol: ${data.is_https ? 'HTTPS' : 'HTTP'}\nWarnings: ${data.warnings.map(w => w.title).join(', ')}\nAssessed: ${data.scan_timestamp}`;
      navigator.clipboard.writeText(summaryText)
        .then(() => showToast('Summary copied to clipboard!', 'success'))
        .catch(() => showToast('Could not copy to clipboard.', 'error'));
    };
  }
}

/* ==========================================================================
   Count-Up Animation Helper
   ========================================================================== */
function animateCountUp(element, start, end, duration) {
  let startTime = null;
  const step = (timestamp) => {
    if (!startTime) startTime = timestamp;
    const progress = Math.min((timestamp - startTime) / duration, 1);
    element.textContent = Math.floor(progress * (end - start) + start);
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      element.textContent = end;
    }
  };
  window.requestAnimationFrame(step);
}

/* ==========================================================================
   Preset Demo URL Pills
   ========================================================================== */
function initPresetChips() {
  const chips = document.querySelectorAll('.preset-chip');
  const input = document.getElementById('urlInput');
  const form = document.getElementById('scanForm');

  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const targetUrl = chip.getAttribute('data-url');
      if (targetUrl && input) {
        input.value = targetUrl;
        form.dispatchEvent(new Event('submit'));
      }
    });
  });
}

/* ==========================================================================
   Contact / Threat Report Form
   ========================================================================== */
function initContactForm() {
  const contactForm = document.getElementById('contactForm');
  if (!contactForm) return;

  contactForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btnSubmit = contactForm.querySelector('button[type="submit"]');

    const name = document.getElementById('contactName').value.trim();
    const email = document.getElementById('contactEmail').value.trim();
    const subject = document.getElementById('contactSubject').value.trim();
    const message = document.getElementById('contactMessage').value.trim();
    const reportType = document.getElementById('contactType').value;

    if (!name || !email || !message) {
      showToast('Please fill out all required fields.', 'error');
      return;
    }

    btnSubmit.disabled = true;
    btnSubmit.textContent = 'Submitting...';

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, subject, message, report_type: reportType })
      });

      const result = await response.json();
      if (result.success) {
        showToast(result.message, 'success');
        contactForm.reset();
      } else {
        showToast(result.error || 'Failed to submit report.', 'error');
      }
    } catch (err) {
      showToast('Submission error. Please try again.', 'error');
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.textContent = 'Submit Security Report';
    }
  });
}

/* ==========================================================================
   Mobile Navigation Toggle
   ========================================================================== */
function initMobileMenu() {
  const menuBtn = document.getElementById('mobileMenuBtn');
  const navLinks = document.getElementById('navLinks');
  if (!menuBtn || !navLinks) return;

  menuBtn.addEventListener('click', () => {
    navLinks.classList.toggle('mobile-open');
  });
}
