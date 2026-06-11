(function() {
function renderFIM({ apiGet, apiPost, apiDelete, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  app.appendChild(el('div', { className: 'page-header' },
    el('h1', null, 'File Integrity Monitor')));

  // Watches section
  const watchCard = el('div', { className: 'card' });
  watchCard.appendChild(el('h2', null, 'Watched paths'));
  const watchList = el('div', { id: 'fim-watches' });
  watchCard.appendChild(watchList);
  const addWatchRow = el('div', { style: 'display:flex;gap:8px;margin-top:8px;' });
  const watchInput = el('input', { type: 'text', id: 'fim-watch-path', placeholder: '/path/to/watch', style: 'flex:1;' });
  addWatchRow.appendChild(watchInput);
  const addWatchBtn = el('button', { className: 'btn btn-sm btn-primary' }, 'Add watch');
  addWatchRow.appendChild(addWatchBtn);
  watchCard.appendChild(addWatchRow);
  app.appendChild(watchCard);

  // Actions section
  const actionCard = el('div', { className: 'card' });
  actionCard.appendChild(el('h2', null, 'Actions'));
  const toolbar = el('div', { className: 'toolbar' });

  const baselineBtn = el('button', { className: 'btn' }, 'Run baseline');
  toolbar.appendChild(baselineBtn);
  const scanBtn = el('button', { className: 'btn' }, 'Run scan');
  toolbar.appendChild(scanBtn);

  actionCard.appendChild(toolbar);
  app.appendChild(actionCard);

  // Results section
  const resultCard = el('div', { className: 'card', id: 'fim-results' });
  resultCard.appendChild(el('h2', null, 'Results'));
  resultCard.appendChild(el('div', { id: 'fim-result-content', style: 'color:var(--text2);font-size:13px;' }, 'Run a baseline or scan to see results.'));
  app.appendChild(resultCard);

  function renderWatches(paths) {
    watchList.innerHTML = '';
    if (paths.length === 0) {
      watchList.appendChild(el('p', { style: 'color:var(--text2);font-size:13px;' }, 'No watched paths.'));
      return;
    }
    paths.forEach(p => {
      const row = el('div', { style: 'display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid var(--border);' });
      row.appendChild(el('span', { style: 'font-size:13px;' }, p));
      const rmBtn = el('button', { className: 'btn btn-sm btn-danger' }, 'Remove');
      rmBtn.addEventListener('click', async () => {
        try {
          await apiDelete('/api/fim/watches', { path: p });
          showFlash('Watch removed', 'success');
          loadWatches();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
      row.appendChild(rmBtn);
      watchList.appendChild(row);
    });
  }

  async function loadWatches() {
    try {
      const paths = await apiGet('/api/fim/watches');
      renderWatches(paths);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  addWatchBtn.addEventListener('click', async () => {
    const path = watchInput.value.trim();
    if (!path) { showFlash('Path is required', 'error'); return; }
    try {
      await apiPost('/api/fim/watches', { path });
      showFlash('Watch added', 'success');
      watchInput.value = '';
      loadWatches();
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  function renderResult(data) {
    const content = document.getElementById('fim-result-content');
    content.innerHTML = '';

    if (data.scans) {
      data.scans.forEach(s => {
        content.appendChild(el('h3', { style: 'margin:12px 0 8px;font-size:14px;' }, s.root));
        content.appendChild(el('p', { style: 'font-size:13px;' },
          `Added: ${s.added.length} | Removed: ${s.removed.length} | Changed: ${s.changed.length}`));
        if (s.added.length > 0) {
          content.appendChild(el('div', { style: 'margin-top:4px;' }, el('strong', null, 'Added:')));
          s.added.slice(0, 20).forEach(f =>
            content.appendChild(el('div', { style: 'font-size:12px;color:var(--green);padding-left:12px;' }, `+ ${f}`)));
        }
        if (s.removed.length > 0) {
          content.appendChild(el('div', { style: 'margin-top:4px;' }, el('strong', null, 'Removed:')));
          s.removed.slice(0, 20).forEach(f =>
            content.appendChild(el('div', { style: 'font-size:12px;color:var(--red);padding-left:12px;' }, `- ${f}`)));
        }
        if (s.changed.length > 0) {
          content.appendChild(el('div', { style: 'margin-top:4px;' }, el('strong', null, 'Changed:')));
          s.changed.slice(0, 20).forEach(f =>
            content.appendChild(el('div', { style: 'font-size:12px;color:var(--orange);padding-left:12px;' }, `* ${f}`)));
        }
      });
    } else if (data.root) {
      content.appendChild(el('p', { style: 'font-size:13px;' },
        `Baseline stored for ${data.root}: ${data.files} files${data.errors && data.errors.length > 0 ? `, ${data.errors.length} errors` : ''}`));
    }
  }

  baselineBtn.addEventListener('click', () => {
    const m = modal('Run baseline', body => {
      body.appendChild(formGroup('Directory path', el('input', { type: 'text', id: 'fim-baseline-path', placeholder: '/path/to/directory' })));
    }, actions => {
      const runBtn = el('button', { className: 'btn btn-primary' }, 'Run');
      actions.appendChild(runBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      runBtn.addEventListener('click', async () => {
        const path = document.getElementById('fim-baseline-path').value.trim();
        if (!path) { showFlash('Path is required', 'error'); return; }
        try {
          const res = await apiPost('/api/fim/baseline', { path });
          m.overlay.remove();
          renderResult(res);
          showFlash('Baseline created', 'success');
          loadWatches();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  });

  scanBtn.addEventListener('click', () => {
    const m = modal('Run scan', body => {
      body.appendChild(formGroup('Path (leave empty for all)', el('input', { type: 'text', id: 'fim-scan-path', placeholder: 'Optional specific path' })));
    }, actions => {
      const runBtn = el('button', { className: 'btn btn-primary' }, 'Scan');
      actions.appendChild(runBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      runBtn.addEventListener('click', async () => {
        const path = document.getElementById('fim-scan-path').value.trim();
        try {
          const res = await apiPost('/api/fim/scan', path ? { path } : {});
          m.overlay.remove();
          renderResult(res);
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  });

  loadWatches();
}

window.CSP.registerPage('/fim', renderFIM);
})();
