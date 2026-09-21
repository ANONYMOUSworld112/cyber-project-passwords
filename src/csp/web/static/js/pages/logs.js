(function() {
function renderLogs({ apiGet, apiPost, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  app.appendChild(el('div', { className: 'page-header' },
    el('h1', null, 'Log Analyzer')));

  // Analyze section
  const analyzeCard = el('div', { className: 'card' });
  analyzeCard.appendChild(el('h2', null, 'Analyze a log file'));
  analyzeCard.appendChild(formGroup('File path', el('input', { type: 'text', id: 'logs-path', placeholder: '/path/to/logfile.log' })));
  const analyzeBtn = el('button', { className: 'btn btn-primary' }, 'Analyze');
  analyzeCard.appendChild(analyzeBtn);
  const analyzeResult = el('div', { id: 'logs-analyze-result', style: 'margin-top:12px;' });
  analyzeCard.appendChild(analyzeResult);
  app.appendChild(analyzeCard);

  // Runs section
  const runsCard = el('div', { className: 'card' });
  runsCard.appendChild(el('h2', null, 'Past runs'));
  const runsDiv = el('div', { id: 'logs-runs' });
  runsCard.appendChild(runsDiv);
  app.appendChild(runsCard);

  analyzeBtn.addEventListener('click', async () => {
    const path = document.getElementById('logs-path').value.trim();
    if (!path) { showFlash('File path is required', 'error'); return; }
    try {
      const res = await apiPost('/api/logs/analyze', { path });
      renderAnalyzeResult(res);
      showFlash('Analysis complete', 'success');
      loadRuns();
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  document.getElementById('logs-path').addEventListener('keydown', e => {
    if (e.key === 'Enter') analyzeBtn.click();
  });

  function renderAnalyzeResult(r) {
    const div = document.getElementById('logs-analyze-result');
    div.innerHTML = '';
    div.appendChild(el('div', { style: 'font-size:20px;' },
      el('p', null, `Format: ${r.format}`),
      el('p', null, `Lines: ${r.lines}`),
      el('p', null, `Run ID: ${r.id}`)));

    if (r.levels && Object.keys(r.levels).length > 0) {
      div.appendChild(el('h3', { style: 'margin-top:12px;font-size:20px;color:var(--text2);' }, 'Levels:'));
      Object.entries(r.levels).forEach(([k, v]) => {
        div.appendChild(el('div', { style: 'padding-left:12px;font-size:18px;' }, `${k}: ${v}`));
      });
    }

    if (r.top_patterns && r.top_patterns.length > 0) {
      div.appendChild(el('h3', { style: 'margin-top:12px;font-size:20px;color:var(--text2);' }, 'Top patterns:'));
      r.top_patterns.slice(0, 10).forEach(p => {
        div.appendChild(el('div', { style: 'padding-left:12px;font-size:18px;' }, `${String(p.count).padStart(5)}  ${(p.pattern || '').slice(0, 120)}`));
      });
    }

    if (r.error_lines && r.error_lines.length > 0) {
      div.appendChild(el('h3', { style: 'margin-top:14px;font-size:20px;color:var(--c-pure-white);font-family:var(--font-display);letter-spacing:1px;' }, '[!] ANOMALY & ERROR LOG ENTRIES:'));
      r.error_lines.slice(0, 10).forEach(l => {
        div.appendChild(el('div', { style: 'padding:6px 12px;margin-bottom:4px;font-size:17px;font-family:var(--font-mono);color:var(--c-pure-white);background:var(--c-pitch-black);border-left:2px solid var(--c-pure-white);white-space:pre-wrap;word-break:break-all;' }, l));
      });
    }
  }

  async function loadRuns() {
    try {
      const runs = await apiGet('/api/logs/runs');
      const div = document.getElementById('logs-runs');
      div.innerHTML = '';
      if (runs.length === 0) {
        div.appendChild(el('p', { style: 'color:var(--text2);font-size:20px;' }, 'No runs yet.'));
        return;
      }
      const tbl = el('table');
      const thead = el('thead');
      thead.appendChild(el('tr', null,
        el('th', null, 'ID'),
        el('th', null, 'Format'),
        el('th', null, 'Lines'),
        el('th', null, 'Path'),
        el('th', null, 'Analyzed at')));
      tbl.appendChild(thead);
      const tbody = el('tbody');
      runs.forEach(r => {
        const tr = el('tr', { style: 'cursor:pointer;' });
        tr.appendChild(el('td', null, r.id || ''));
        tr.appendChild(el('td', null, r.format || ''));
        tr.appendChild(el('td', null, String(r.lines || '')));
        tr.appendChild(el('td', null, (r.path || '').slice(-40)));
        tr.appendChild(el('td', null, (r.analyzed_at || '').slice(0, 16)));
        tr.addEventListener('click', () => showRun(r));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      div.appendChild(tbl);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  function showRun(r) {
    const m = modal('Run details', body => {
      ['id', 'path', 'format', 'lines', 'analyzed_at'].forEach(f => {
        body.appendChild(el('div', { className: 'form-group' },
          el('label', null, f),
          el('div', { style: 'padding:8px 0;font-size:20px;' }, String(r[f] || ''))));
      });
      if (r.levels) {
        body.appendChild(el('h3', { style: 'margin-top:12px;font-size:20px;' }, 'Levels:'));
        Object.entries(r.levels).forEach(([k, v]) => {
          body.appendChild(el('div', { style: 'padding-left:12px;font-size:18px;' }, `${k}: ${v}`));
        });
      }
    }, actions => {
      const closeBtn = el('button', { className: 'btn' }, 'Close');
      closeBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(closeBtn);
    });
  }

  loadRuns();
}

window.CSP.registerPage('/logs', renderLogs);
})();
