(function() {
function renderHashDB({ apiGet, apiPost, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  app.appendChild(el('div', { className: 'page-header' },
    el('h1', null, 'Hash Database')));

  // Import section
  const importCard = el('div', { className: 'card' });
  importCard.appendChild(el('h2', null, 'Import hashes'));
  importCard.appendChild(formGroup('File path', el('input', { type: 'text', id: 'hashdb-import-path', placeholder: '/path/to/hashes.txt' })));
  const kindSelect = el('select', { id: 'hashdb-import-kind' });
  kindSelect.appendChild(el('option', { value: 'malicious' }, 'Malicious'));
  kindSelect.appendChild(el('option', { value: 'clean' }, 'Clean'));
  importCard.appendChild(formGroup('Label kind', kindSelect));
  const importBtn = el('button', { className: 'btn btn-primary' }, 'Import');
  importCard.appendChild(importBtn);
  app.appendChild(importCard);

  // Lookup section
  const lookupCard = el('div', { className: 'card' });
  lookupCard.appendChild(el('h2', null, 'Lookup'));
  const lookupTabs = el('div', { style: 'display:flex;gap:8px;margin-bottom:12px;' });
  const hashTab = el('button', { className: 'btn btn-sm btn-primary', id: 'hashdb-lookup-hash-tab' }, 'By hash');
  const fileTab = el('button', { className: 'btn btn-sm', id: 'hashdb-lookup-file-tab' }, 'By file');
  lookupTabs.appendChild(hashTab);
  lookupTabs.appendChild(fileTab);
  lookupCard.appendChild(lookupTabs);

  const lookupHashDiv = el('div', { id: 'hashdb-lookup-hash' });
  lookupHashDiv.appendChild(formGroup('SHA-256 hash', el('input', { type: 'text', id: 'hashdb-lookup-hash-input', placeholder: '64 hex chars' })));
  const lookupHashBtn = el('button', { className: 'btn btn-primary' }, 'Lookup');
  lookupHashDiv.appendChild(lookupHashBtn);
  lookupCard.appendChild(lookupHashDiv);

  const lookupFileDiv = el('div', { id: 'hashdb-lookup-file', style: 'display:none;' });
  lookupFileDiv.appendChild(formGroup('File path', el('input', { type: 'text', id: 'hashdb-lookup-file-input', placeholder: '/path/to/file' })));
  const lookupFileBtn = el('button', { className: 'btn btn-primary' }, 'Lookup');
  lookupFileDiv.appendChild(lookupFileBtn);
  lookupCard.appendChild(lookupFileDiv);

  const lookupResult = el('div', { id: 'hashdb-lookup-result', style: 'margin-top:12px;' });
  lookupCard.appendChild(lookupResult);
  app.appendChild(lookupCard);

  // Sources section
  const sourcesCard = el('div', { className: 'card' });
  sourcesCard.appendChild(el('h2', null, 'Import sources'));
  const sourcesDiv = el('div', { id: 'hashdb-sources' });
  sourcesCard.appendChild(sourcesDiv);
  app.appendChild(sourcesCard);

  hashTab.addEventListener('click', () => {
    hashTab.className = 'btn btn-sm btn-primary';
    fileTab.className = 'btn btn-sm';
    lookupHashDiv.style.display = '';
    lookupFileDiv.style.display = 'none';
  });
  fileTab.addEventListener('click', () => {
    fileTab.className = 'btn btn-sm btn-primary';
    hashTab.className = 'btn btn-sm';
    lookupFileDiv.style.display = '';
    lookupHashDiv.style.display = 'none';
  });

  importBtn.addEventListener('click', async () => {
    const path = document.getElementById('hashdb-import-path').value.trim();
    const kind = document.getElementById('hashdb-import-kind').value;
    if (!path) { showFlash('File path is required', 'error'); return; }
    try {
      const res = await apiPost('/api/hashdb/import', { path, label_kind: kind });
      showFlash(`Imported ${res.added} hashes (${res.skipped} skipped)`, 'success');
      loadSources();
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  lookupHashBtn.addEventListener('click', async () => {
    const hash = document.getElementById('hashdb-lookup-hash-input').value.trim();
    if (!hash) { showFlash('Hash is required', 'error'); return; }
    try {
      const res = await apiGet(`/api/hashdb/lookup?hash=${encodeURIComponent(hash)}`);
      renderLookup(res);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  lookupFileBtn.addEventListener('click', async () => {
    const path = document.getElementById('hashdb-lookup-file-input').value.trim();
    if (!path) { showFlash('File path is required', 'error'); return; }
    try {
      const res = await apiGet(`/api/hashdb/lookup?file=${encodeURIComponent(path)}`);
      renderLookup(res);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  function renderLookup(res) {
    const div = document.getElementById('hashdb-lookup-result');
    div.innerHTML = '';
    const status = res.status || 'unknown';
    const badge = el('span', { className: `badge badge-${status === 'malicious' ? 'malicious' : 'clean'}` }, status);
    div.appendChild(badge);
    if (res.label) div.appendChild(el('p', { style: 'margin-top:4px;font-size:20px;' }, `Label: ${res.label}`));
    if (res.source) div.appendChild(el('p', { style: 'margin-top:4px;font-size:20px;' }, `Source: ${res.source}`));
  }

  async function loadSources() {
    try {
      const sources = await apiGet('/api/hashdb/sources');
      const div = document.getElementById('hashdb-sources');
      div.innerHTML = '';
      if (sources.length === 0) {
        div.appendChild(el('p', { style: 'color:var(--c-silver-gray);font-size:20px;' }, 'No imports yet.'));
        return;
      }
      sources.forEach(s => {
        div.appendChild(el('div', { style: 'font-size:18px;padding:6px 0;border-bottom:1px solid var(--border);' },
          `${s.imported_at || ''} | ${s.label_kind || '?'} | +${s.added || 0} | ${s.path || ''}`));
      });
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  loadSources();
  // Enter key on lookup inputs
  document.getElementById('hashdb-lookup-hash-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') lookupHashBtn.click();
  });
  document.getElementById('hashdb-lookup-file-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') lookupFileBtn.click();
  });
}

window.CSP.registerPage('/hashdb', renderHashDB);
})();
