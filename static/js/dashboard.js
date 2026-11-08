/**
 * CyberShield AI - Dashboard Logic
 * Manages Chart.js visualizations, history filtering, search, modal inspection, and clearing history.
 */

let riskChartInstance = null;
let threatChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
  initDashboardStats();
  initTableFilteringAndSearch();
  initClearHistoryModal();
  initModals();
});

/* ==========================================================================
   Dashboard Stats & Charts Initialization
   ========================================================================== */
async function initDashboardStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    if (data.success && data.stats) {
      updateStatNumbers(data.stats);
      renderCharts(data.stats);
    }
  } catch (err) {
    console.error('Failed to load dashboard stats:', err);
  }
}

function updateStatNumbers(stats) {
  const elTotal = document.getElementById('statTotalScans');
  const elLow = document.getElementById('statLowRisk');
  const elMed = document.getElementById('statMedRisk');
  const elHigh = document.getElementById('statHighRisk');
  const elHttps = document.getElementById('statHttpsRate');

  if (elTotal) elTotal.textContent = stats.total_scanned;
  if (elLow) elLow.textContent = stats.low_risk_count;
  if (elMed) elMed.textContent = stats.medium_risk_count;
  if (elHigh) elHigh.textContent = stats.high_risk_count;
  if (elHttps) elHttps.textContent = `${stats.https_adoption_percent}%`;
}

function renderCharts(stats) {
  const ctxRisk = document.getElementById('riskDistChart');
  const ctxThreat = document.getElementById('threatVectorsChart');

  const low = stats.low_risk_count || 0;
  const med = stats.medium_risk_count || 0;
  const high = stats.high_risk_count || 0;
  const total = low + med + high;

  if (typeof Chart === 'undefined') {
    // Offline Fallback: Render pure SVG / CSS visual charts if CDN is inaccessible
    if (ctxRisk && ctxRisk.parentElement) {
      const lowPct = total ? Math.round((low / total) * 100) : 33;
      const medPct = total ? Math.round((med / total) * 100) : 33;
      const highPct = total ? Math.round((high / total) * 100) : 34;

      ctxRisk.parentElement.innerHTML = `
        <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; width:100%; height:100%; gap:1.2rem;">
          <div style="display:flex; align-items:center; gap:0.5rem; width:80%; height:24px; border-radius:12px; overflow:hidden; background:rgba(255,255,255,0.05); padding:2px;">
            <div style="width:${lowPct}%; height:100%; background:#10b981; border-radius:8px;" title="Low: ${low}"></div>
            <div style="width:${medPct}%; height:100%; background:#f59e0b; border-radius:8px;" title="Med: ${med}"></div>
            <div style="width:${highPct}%; height:100%; background:#ef4444; border-radius:8px;" title="High: ${high}"></div>
          </div>
          <div style="display:flex; gap:1rem; font-size:0.8rem; color:#94a3b8;">
            <span style="color:#10b981;">● Safe: ${low} (${lowPct}%)</span>
            <span style="color:#f59e0b;">● Suspicious: ${med} (${medPct}%)</span>
            <span style="color:#ef4444;">● High Risk: ${high} (${highPct}%)</span>
          </div>
        </div>
      `;
    }

    if (ctxThreat && ctxThreat.parentElement) {
      ctxThreat.parentElement.innerHTML = `
        <div style="display:flex; flex-direction:column; justify-content:center; width:100%; height:100%; gap:0.9rem; padding:0.5rem 1rem;">
          <div>
            <div style="display:flex; justify-content:space-between; font-size:0.82rem; margin-bottom:4px;">
              <span style="color:#10b981;">Low Risk Verified</span>
              <span style="color:#fff; font-weight:700;">${low}</span>
            </div>
            <div style="width:100%; height:10px; background:rgba(255,255,255,0.05); border-radius:5px; overflow:hidden;">
              <div style="width:${total ? (low/total*100) : 0}%; height:100%; background:#10b981;"></div>
            </div>
          </div>
          <div>
            <div style="display:flex; justify-content:space-between; font-size:0.82rem; margin-bottom:4px;">
              <span style="color:#f59e0b;">Suspicious Signals</span>
              <span style="color:#fff; font-weight:700;">${med}</span>
            </div>
            <div style="width:100%; height:10px; background:rgba(255,255,255,0.05); border-radius:5px; overflow:hidden;">
              <div style="width:${total ? (med/total*100) : 0}%; height:100%; background:#f59e0b;"></div>
            </div>
          </div>
          <div>
            <div style="display:flex; justify-content:space-between; font-size:0.82rem; margin-bottom:4px;">
              <span style="color:#ef4444;">Critical Threats</span>
              <span style="color:#fff; font-weight:700;">${high}</span>
            </div>
            <div style="width:100%; height:10px; background:rgba(255,255,255,0.05); border-radius:5px; overflow:hidden;">
              <div style="width:${total ? (high/total*100) : 0}%; height:100%; background:#ef4444;"></div>
            </div>
          </div>
        </div>
      `;
    }
    return;
  }

    riskChartInstance = new Chart(ctxRisk, {
      type: 'doughnut',
      data: {
        labels: isEmpty ? ['No Data'] : ['Low Risk (Safe)', 'Medium Risk (Suspicious)', 'High Risk (Critical)'],
        datasets: [{
          data: isEmpty ? [1] : [low, med, high],
          backgroundColor: isEmpty 
            ? ['rgba(255, 255, 255, 0.1)']
            : ['#10b981', '#f59e0b', '#ef4444'],
          borderColor: '#0d1322',
          borderWidth: 3,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { family: 'Inter', size: 12 },
              padding: 16
            }
          },
          tooltip: {
            backgroundColor: '#0a0f1d',
            titleColor: '#00f5d4',
            bodyColor: '#ffffff',
            borderColor: 'rgba(0, 245, 212, 0.3)',
            borderWidth: 1,
            padding: 10
          }
        },
        cutout: '72%'
      }
    });
  }

  // 2. Bar Chart: Threat Vectors & Protocol
  const ctxThreat = document.getElementById('threatVectorsChart');
  if (ctxThreat) {
    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctxThreat, {
      type: 'bar',
      data: {
        labels: ['Low Risk', 'Suspicious', 'Critical Threats'],
        datasets: [{
          label: 'Scan Count',
          data: [stats.low_risk_count, stats.medium_risk_count, stats.high_risk_count],
          backgroundColor: [
            'rgba(16, 185, 129, 0.65)',
            'rgba(245, 158, 11, 0.65)',
            'rgba(239, 68, 68, 0.65)'
          ],
          borderColor: [
            '#10b981',
            '#f59e0b',
            '#ef4444'
          ],
          borderWidth: 1.5,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0a0f1d',
            borderColor: 'rgba(255, 255, 255, 0.15)',
            borderWidth: 1
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#94a3b8' }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', stepSize: 1 }
          }
        }
      }
    });
  }
}

/* ==========================================================================
   Table Filtering, Live Search & View Trigger
   ========================================================================== */
function initTableFilteringAndSearch() {
  const searchInput = document.getElementById('tableSearchInput');
  const filterPills = document.querySelectorAll('.filter-pill');
  const rows = document.querySelectorAll('.cyber-table tbody tr');

  let activeFilter = 'all';

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeFilter = pill.getAttribute('data-filter').toLowerCase();
      applyFilters();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      applyFilters();
    });
  }

  function applyFilters() {
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

    rows.forEach(row => {
      const level = (row.getAttribute('data-level') || '').toLowerCase();
      const text = row.textContent.toLowerCase();

      const matchesFilter = (activeFilter === 'all') || (level === activeFilter);
      const matchesSearch = (!query) || text.includes(query);

      if (matchesFilter && matchesSearch) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  }
}

/* ==========================================================================
   Deep Analysis Modal Inspector
   ========================================================================== */
async function openScanDetailModal(scanId) {
  const modal = document.getElementById('scanDetailModal');
  const modalBody = document.getElementById('modalDetailBody');
  if (!modal || !modalBody) return;

  modalBody.innerHTML = `
    <div style="text-align:center; padding:3rem 0;">
      <span class="log-spinner" style="width:28px; height:28px; border-width:3px;"></span>
      <p style="margin-top:1rem; color:#94a3b8;">Loading heuristic threat inspection...</p>
    </div>
  `;
  modal.style.display = 'flex';

  try {
    const res = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();

    if (!data.success || !data.scan) {
      modalBody.innerHTML = `<p style="color:#ef4444;">Failed to load report #${scanId}.</p>`;
      return;
    }

    const s = data.scan;
    const isHigh = s.risk_level === 'High';
    const isMed = s.risk_level === 'Medium';
    const color = isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#10b981';

    let warningsHtml = '';
    if (s.warnings && s.warnings.length > 0) {
      warningsHtml = s.warnings.map(w => `
        <div style="background:rgba(255,255,255,0.03); border-left:3px solid ${w.severity === 'critical' ? '#ef4444' : '#f59e0b'}; padding:0.75rem 1rem; border-radius:6px; margin-bottom:0.5rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:#fff; font-size:0.9rem;">${escapeHtml(w.title)}</strong>
            <span style="font-size:0.75rem; color:${color}; font-weight:700;">+${w.points} Pts</span>
          </div>
          <p style="font-size:0.82rem; color:#94a3b8; margin-top:0.2rem;">${escapeHtml(w.desc)}</p>
        </div>
      `).join('');
    } else {
      warningsHtml = `<p style="font-size:0.85rem; color:#10b981;">No active threat indicators identified.</p>`;
    }

    let recsHtml = '';
    if (s.recommendations && s.recommendations.length > 0) {
      recsHtml = s.recommendations.map(r => `
        <li style="margin-bottom:0.4rem; font-size:0.85rem; color:#cbd5e1; display:flex; gap:0.5rem; align-items:flex-start;">
          <span style="color:#00f5d4;">›</span> ${escapeHtml(r)}
        </li>
      `).join('');
    }

    modalBody.innerHTML = `
      <div style="margin-bottom:1.5rem; border-bottom:1px solid rgba(255,255,255,0.08); padding-bottom:1.2rem;">
        <span class="badge ${s.badge_class || 'status-low'}" style="margin-bottom:0.6rem;">${s.risk_label}</span>
        <h3 style="font-family:var(--font-mono); font-size:1.15rem; color:#fff; word-break:break-all;">${escapeHtml(s.url)}</h3>
        <p style="font-size:0.8rem; color:#64748b; margin-top:0.3rem;">Host: ${escapeHtml(s.hostname)} | Assessed: ${s.scan_timestamp || s.db_created_at}</p>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:0.8rem; margin-bottom:1.5rem;">
        <div style="background:rgba(255,255,255,0.02); padding:0.8rem; border-radius:8px; border:1px solid rgba(255,255,255,0.05); text-align:center;">
          <div style="font-size:0.72rem; color:#64748b; text-transform:uppercase;">Risk Score</div>
          <div style="font-size:1.6rem; font-weight:800; color:${color}; font-family:var(--font-mono);">${s.risk_score}/100</div>
        </div>
        <div style="background:rgba(255,255,255,0.02); padding:0.8rem; border-radius:8px; border:1px solid rgba(255,255,255,0.05); text-align:center;">
          <div style="font-size:0.72rem; color:#64748b; text-transform:uppercase;">Protocol</div>
          <div style="font-size:1.1rem; font-weight:700; color:${s.is_https ? '#10b981' : '#ef4444'}; margin-top:0.3rem;">${s.is_https ? 'HTTPS' : 'HTTP'}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02); padding:0.8rem; border-radius:8px; border:1px solid rgba(255,255,255,0.05); text-align:center;">
          <div style="font-size:0.72rem; color:#64748b; text-transform:uppercase;">Host Type</div>
          <div style="font-size:1.1rem; font-weight:700; color:#fff; margin-top:0.3rem;">${s.is_ip ? 'IP Address' : 'Domain'}</div>
        </div>
      </div>

      <div style="margin-bottom:1.5rem;">
        <h4 style="font-size:0.95rem; font-weight:700; margin-bottom:0.75rem; color:#fff;">Detected Warning Signals:</h4>
        ${warningsHtml}
      </div>

      <div style="background:rgba(13,22,45,0.6); border:1px solid rgba(59,130,246,0.3); border-radius:8px; padding:1.2rem; margin-bottom:1.5rem;">
        <h4 style="font-size:0.92rem; font-weight:700; margin-bottom:0.5rem; color:#93c5fd;">Recommended Protective Actions:</h4>
        <ul style="list-style:none; padding-left:0;">${recsHtml}</ul>
      </div>

      <div style="font-size:0.78rem; color:#fbbf24; background:rgba(245,158,11,0.08); padding:0.75rem; border-radius:6px; border:1px dashed rgba(245,158,11,0.3);">
        <strong>Disclaimer:</strong> This is a preliminary heuristic threat evaluation. Always verify URLs independently before sharing confidential credentials.
      </div>
    `;
  } catch (err) {
    modalBody.innerHTML = `<p style="color:#ef4444;">Server error retrieving scan details.</p>`;
  }
}

function closeScanDetailModal() {
  const modal = document.getElementById('scanDetailModal');
  if (modal) modal.style.display = 'none';
}

function initModals() {
  const detailModal = document.getElementById('scanDetailModal');
  if (detailModal) {
    detailModal.addEventListener('click', (e) => {
      if (e.target === detailModal) closeScanDetailModal();
    });
  }

  const confirmModal = document.getElementById('confirmClearModal');
  if (confirmModal) {
    confirmModal.addEventListener('click', (e) => {
      if (e.target === confirmModal) confirmModal.style.display = 'none';
    });
  }
}

/* ==========================================================================
   Clear History Confirmation & Execution
   ========================================================================== */
function initClearHistoryModal() {
  const btnClear = document.getElementById('btnClearHistory');
  const modalConfirm = document.getElementById('confirmClearModal');
  const btnConfirmYes = document.getElementById('btnConfirmClearYes');
  const btnConfirmNo = document.getElementById('btnConfirmClearNo');

  if (btnClear && modalConfirm) {
    btnClear.addEventListener('click', () => {
      modalConfirm.style.display = 'flex';
    });
  }

  if (btnConfirmNo && modalConfirm) {
    btnConfirmNo.addEventListener('click', () => {
      modalConfirm.style.display = 'none';
    });
  }

  if (btnConfirmYes && modalConfirm) {
    btnConfirmYes.addEventListener('click', async () => {
      btnConfirmYes.disabled = true;
      btnConfirmYes.textContent = 'Clearing...';

      try {
        const res = await fetch('/api/clear-history', { method: 'POST' });
        const data = await res.json();

        if (data.success) {
          showToast('Scan history cleared successfully.', 'success');
          modalConfirm.style.display = 'none';
          // Reload dashboard or empty table
          setTimeout(() => window.location.reload(), 600);
        } else {
          showToast(data.error || 'Failed to clear history.', 'error');
        }
      } catch (err) {
        showToast('Error communicating with server.', 'error');
      } finally {
        btnConfirmYes.disabled = false;
        btnConfirmYes.textContent = 'Yes, Clear All';
      }
    });
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
