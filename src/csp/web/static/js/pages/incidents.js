(function() {
function renderIncidents({ apiGet, apiPost, apiPut, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const header = el('div', { className: 'page-header' });
  header.appendChild(el('h1', null, 'Incidents'));
  const addBtn = el('button', { className: 'btn btn-primary' }, '+ Add incident');
  header.appendChild(addBtn);
  app.appendChild(header);

  const filterBar = el('div', { style: 'margin-bottom:16px;display:flex;gap:8px;align-items:center;' });
  const filterLabel = el('label', { style: 'display:flex;align-items:center;gap:6px;font-size:20px;' });
  const filterCheck = el('input', { type: 'checkbox', id: 'inc-filter-open' });
  filterLabel.appendChild(filterCheck);
  filterLabel.appendChild(document.createTextNode('Open only'));
  filterBar.appendChild(filterLabel);
  app.appendChild(filterBar);

  const tableWrap = el('div', { id: 'inc-table' });
  app.appendChild(tableWrap);

  function sevBadge(s) {
    return el('span', { className: `badge badge-${s}` }, s);
  }

  function statusBadge(s) {
    return el('span', { className: `badge badge-${s}` }, s);
  }

  function renderTable(data) {
    tableWrap.innerHTML = '';
    if (data.length === 0) {
      tableWrap.appendChild(el('div', { className: 'card', style: 'text-align:center;padding:48px 24px;border:1px dashed var(--c-dark-charcoal);' },
        el('div', { style: 'font-family:var(--font-display);font-size:24px;color:var(--c-silver-gray);letter-spacing:1px;margin-bottom:8px;' }, 'NO ACTIVE INCIDENTS REPORTED'),
        el('p', { style: 'color:var(--c-mid-gray);font-size:19px;margin-bottom:18px;' }, 'All security parameters nominal. You can file a new incident investigation report anytime.'),
        el('button', { className: 'btn btn-primary', onclick: () => newBtn.click() }, '+ FILE INCIDENT')
      ));
      return;
    }
    const tbl = el('table');
    const thead = el('thead');
    thead.appendChild(el('tr', null,
      el('th', null, 'Title'),
      el('th', null, 'Severity'),
      el('th', null, 'Status'),
      el('th', null, 'Created'),
      el('th', null, 'Actions')));
    tbl.appendChild(thead);
    const tbody = el('tbody');
    data.forEach(i => {
      const tr = el('tr', { style: 'cursor:pointer;' });
      tr.appendChild(el('td', null, i.title || ''));
      const sevTd = el('td', null); sevTd.appendChild(sevBadge(i.severity || 'low')); tr.appendChild(sevTd);
      const stTd = el('td', null); stTd.appendChild(statusBadge(i.status || 'open')); tr.appendChild(stTd);
      tr.appendChild(el('td', null, (i.created || '').slice(0, 10)));
      const actionsTd = el('td', null);
      const viewBtn = el('button', { className: 'btn btn-sm', dataset: { id: i.id } }, 'View');
      actionsTd.appendChild(viewBtn);
      if (i.status === 'open') {
        const closeBtn = el('button', { className: 'btn btn-sm btn-success', dataset: { id: i.id }, style: 'margin-left:6px;' }, 'Close');
        actionsTd.appendChild(closeBtn);
        closeBtn.addEventListener('click', e => { e.stopPropagation(); closeInc(i.id); });
      }
      tr.appendChild(actionsTd);
      viewBtn.addEventListener('click', e => { e.stopPropagation(); showInc(i.id); });
      tr.addEventListener('click', () => showInc(i.id));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tableWrap.appendChild(tbl);
  }

  async function loadData() {
    try {
      const openOnly = filterCheck.checked;
      let url = '/api/incidents';
      if (openOnly) url += '?open_only=true';
      const data = await apiGet(url);
      renderTable(data);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  filterCheck.addEventListener('change', loadData);

  function showInc(id) {
    apiGet(`/api/incidents/${id}`).then(i => {
      const m = modal('Incident', body => {
        ['id', 'title', 'severity', 'status', 'created', 'updated', 'notes', 'iocs'].forEach(f => {
          const val = f === 'iocs' ? (i[f] || []).join(', ') : String(i[f] || '');
          body.appendChild(el('div', { className: 'form-group' },
            el('label', null, f),
            el('div', { style: 'padding:8px 0;word-break:break-all;' }, val)));
        });
      }, actions => {
        const editBtn = el('button', { className: 'btn btn-primary' }, 'Edit');
        actions.appendChild(editBtn);
        const closeBtn = el('button', { className: 'btn' }, 'Close');
        closeBtn.addEventListener('click', () => m.overlay.remove());
        actions.appendChild(closeBtn);

        editBtn.addEventListener('click', () => {
          m.overlay.remove();
          editInc(i);
        });
      });
    }).catch(e => showFlash(e.message, 'error'));
  }

  function editInc(i) {
    const m = modal('Edit incident', body => {
      body.appendChild(formGroup('Title', el('input', { type: 'text', id: 'edit-inc-title', value: i.title || '' })));
      const sevSelect = el('select', { id: 'edit-inc-severity' });
      ['low', 'med', 'high', 'critical'].forEach(s => {
        const opt = el('option', { value: s }, s);
        if (s === i.severity) opt.selected = true;
        sevSelect.appendChild(opt);
      });
      body.appendChild(formGroup('Severity', sevSelect));
      body.appendChild(formGroup('Notes', el('textarea', { id: 'edit-inc-notes' }, i.notes || '')));
    }, actions => {
      const saveBtn = el('button', { className: 'btn btn-primary' }, 'Save');
      actions.appendChild(saveBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      saveBtn.addEventListener('click', async () => {
        try {
          await apiPut(`/api/incidents/${i.id}`, {
            title: document.getElementById('edit-inc-title').value,
            severity: document.getElementById('edit-inc-severity').value,
            notes: document.getElementById('edit-inc-notes').value,
          });
          m.overlay.remove();
          showFlash('Incident updated', 'success');
          loadData();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  }

  function closeInc(id) {
    apiPost(`/api/incidents/${id}/close`).then(() => {
      showFlash('Incident closed', 'success');
      loadData();
    }).catch(e => showFlash(e.message, 'error'));
  }

  addBtn.addEventListener('click', () => {
    const m = modal('Add incident', body => {
      body.appendChild(formGroup('Title', el('input', { type: 'text', id: 'add-inc-title' })));
      const sevSelect = el('select', { id: 'add-inc-severity' });
      ['low', 'med', 'high', 'critical'].forEach(s => {
        sevSelect.appendChild(el('option', { value: s }, s));
      });
      body.appendChild(formGroup('Severity', sevSelect));
      body.appendChild(formGroup('Notes', el('textarea', { id: 'add-inc-notes' })));
    }, actions => {
      const saveBtn = el('button', { className: 'btn btn-primary' }, 'Save');
      actions.appendChild(saveBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      saveBtn.addEventListener('click', async () => {
        const title = document.getElementById('add-inc-title').value;
        if (!title) { showFlash('Title is required', 'error'); return; }
        try {
          await apiPost('/api/incidents', {
            title,
            severity: document.getElementById('add-inc-severity').value,
            notes: document.getElementById('add-inc-notes').value,
          });
          m.overlay.remove();
          showFlash('Incident added', 'success');
          loadData();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  });

  loadData();
}

window.CSP.registerPage('/incidents', renderIncidents);
})();
