(function() {
function renderVault({ apiGet, apiPost, apiPut, apiDelete, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const header = el('div', { className: 'page-header' });
  header.appendChild(el('h1', null, 'Credential Vault'));
  const addBtn = el('button', { className: 'btn btn-primary' }, '+ Add credential');
  header.appendChild(addBtn);
  app.appendChild(header);

  const searchBar = el('div', { className: 'search-bar' });
  const searchInput = el('input', { type: 'text', id: 'vault-search', placeholder: 'Search credentials...' });
  searchBar.appendChild(searchInput);
  const showPwLabel = el('label', { style: 'display:flex;align-items:center;gap:6px;font-size:20px;white-space:nowrap;' });
  const showPwCheck = el('input', { type: 'checkbox', id: 'vault-showpw' });
  showPwLabel.appendChild(showPwCheck);
  showPwLabel.appendChild(document.createTextNode('Show passwords'));
  searchBar.appendChild(showPwLabel);
  app.appendChild(searchBar);

  const tableWrap = el('div', { id: 'vault-table' });
  app.appendChild(tableWrap);

  function renderTable(data) {
    tableWrap.innerHTML = '';
    if (data.length === 0) {
      tableWrap.appendChild(el('div', { className: 'card', style: 'text-align:center;padding:48px 24px;border:1px dashed var(--c-dark-charcoal);' },
        el('div', { style: 'font-family:var(--font-display);font-size:24px;color:var(--c-silver-gray);letter-spacing:1px;margin-bottom:8px;' }, 'NO ENCRYPTED CREDENTIALS STORED'),
        el('p', { style: 'color:var(--c-mid-gray);font-size:19px;margin-bottom:18px;' }, 'Your secure vault is currently empty. Store your first encrypted credential entry.'),
        el('button', { className: 'btn btn-primary', onclick: () => addBtn.click() }, '+ ADD CREDENTIAL')
      ));
      return;
    }
    const tbl = el('table');
    const thead = el('thead');
    thead.appendChild(el('tr', null,
      el('th', null, 'Title'),
      el('th', null, 'Username'),
      el('th', null, 'URL'),
      el('th', null, 'Actions')));
    tbl.appendChild(thead);
    const tbody = el('tbody');
    data.forEach(c => {
      const tr = el('tr', { style: 'cursor:pointer;' });
      tr.appendChild(el('td', null, c.title || ''));
      tr.appendChild(el('td', null, c.username || ''));
      tr.appendChild(el('td', null, c.url || ''));
      const actionsTd = el('td', null);
      const viewBtn = el('button', { className: 'btn btn-sm', dataset: { id: c.id } }, 'View');
      const delBtn = el('button', { className: 'btn btn-sm btn-danger', dataset: { id: c.id }, style: 'margin-left:6px;' }, 'Delete');
      actionsTd.appendChild(viewBtn);
      actionsTd.appendChild(delBtn);
      tr.appendChild(actionsTd);

      viewBtn.addEventListener('click', e => { e.stopPropagation(); showCred(c.id); });
      delBtn.addEventListener('click', e => { e.stopPropagation(); deleteCred(c.id); });
      tr.addEventListener('click', () => showCred(c.id));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    tableWrap.appendChild(tbl);
  }

  async function loadData() {
    try {
      const q = searchInput.value.trim();
      const showPw = showPwCheck.checked;
      let url = '/api/vault/credentials';
      if (q) url += `?search=${encodeURIComponent(q)}`;
      if (showPw) url += (q ? '&' : '?') + 'show_passwords=true';
      const data = await apiGet(url);
      renderTable(data);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  searchInput.addEventListener('input', loadData);
  showPwCheck.addEventListener('change', loadData);

  function showCred(id) {
    apiGet(`/api/vault/credentials/${id}`).then(c => {
      const m = modal('Credential', body => {
        const fields = ['id', 'title', 'username', 'password', 'url', 'notes', 'created', 'updated'];
        fields.forEach(f => {
          body.appendChild(el('div', { className: 'form-group' },
            el('label', null, f),
            el('div', { style: 'padding:8px 0;word-break:break-all;' }, String(c[f] || ''))));
        });
      }, actions => {
        const editBtn = el('button', { className: 'btn btn-primary' }, 'Edit');
        actions.appendChild(editBtn);
        const closeBtn = el('button', { className: 'btn' }, 'Close');
        closeBtn.addEventListener('click', () => m.overlay.remove());
        actions.appendChild(closeBtn);

        editBtn.addEventListener('click', () => {
          m.overlay.remove();
          editCred(c);
        });
      });
    }).catch(e => showFlash(e.message, 'error'));
  }

  function editCred(c) {
    const m = modal('Edit credential', body => {
      const fields = [
        { key: 'title', label: 'Title', type: 'text' },
        { key: 'username', label: 'Username', type: 'text' },
        { key: 'password', label: 'Password', type: 'text' },
        { key: 'url', label: 'URL', type: 'text' },
        { key: 'notes', label: 'Notes', type: 'textarea' },
      ];
      fields.forEach(f => {
        const inp = f.type === 'textarea'
          ? el('textarea', { id: `edit-${f.key}` }, c[f.key] || '')
          : el('input', { type: 'text', id: `edit-${f.key}`, value: c[f.key] || '' });
        body.appendChild(formGroup(f.label, inp));
      });
    }, actions => {
      const saveBtn = el('button', { className: 'btn btn-primary' }, 'Save');
      actions.appendChild(saveBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      saveBtn.addEventListener('click', async () => {
        const updates = {};
        ['title', 'username', 'password', 'url', 'notes'].forEach(k => {
          const inp = document.getElementById(`edit-${k}`);
          if (inp) updates[k] = inp.value;
        });
        try {
          await apiPut(`/api/vault/credentials/${c.id}`, updates);
          m.overlay.remove();
          showFlash('Credential updated', 'success');
          loadData();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  }

  function deleteCred(id) {
    const m = modal('Delete credential', body => {
      body.appendChild(el('p', null, 'Are you sure you want to delete this credential? This cannot be undone.'));
    }, actions => {
      const delBtn = el('button', { className: 'btn btn-danger' }, 'Delete');
      actions.appendChild(delBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      delBtn.addEventListener('click', async () => {
        try {
          await apiDelete(`/api/vault/credentials/${id}`);
          m.overlay.remove();
          showFlash('Credential deleted', 'success');
          loadData();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  }

  addBtn.addEventListener('click', () => {
    const m = modal('Add credential', body => {
      body.appendChild(formGroup('Title', el('input', { type: 'text', id: 'add-title' })));
      body.appendChild(formGroup('Username', el('input', { type: 'text', id: 'add-username' })));
      const pwRow = el('div', { style: 'display:flex;gap:8px;align-items:end;' });
      const pwG = el('div', { className: 'form-group', style: 'flex:1;' });
      pwG.appendChild(el('label', null, 'Password'));
      const pwInp = el('input', { type: 'text', id: 'add-password', placeholder: 'Type or "gen" to generate' });
      pwG.appendChild(pwInp);
      pwRow.appendChild(pwG);
      pwRow.appendChild(el('button', { className: 'btn btn-sm', id: 'add-genpw', style: 'margin-bottom:14px;' }, 'Generate'));
      body.appendChild(pwRow);
      body.appendChild(formGroup('URL', el('input', { type: 'text', id: 'add-url' })));
      body.appendChild(formGroup('Notes', el('textarea', { id: 'add-notes' })));

      document.getElementById('add-genpw').addEventListener('click', async () => {
        try {
          const data = await apiGet('/api/vault/genpw?length=20');
          document.getElementById('add-password').value = data.password;
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    }, actions => {
      const saveBtn = el('button', { className: 'btn btn-primary' }, 'Save');
      actions.appendChild(saveBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      saveBtn.addEventListener('click', async () => {
        const cred = {
          title: document.getElementById('add-title').value,
          username: document.getElementById('add-username').value,
          password: document.getElementById('add-password').value,
          url: document.getElementById('add-url').value,
          notes: document.getElementById('add-notes').value,
        };
        if (!cred.title || !cred.username || !cred.password) {
          showFlash('Title, username, and password are required', 'error');
          return;
        }
        try {
          await apiPost('/api/vault/credentials', cred);
          m.overlay.remove();
          showFlash('Credential added', 'success');
          loadData();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  });

  loadData();
}

window.CSP.registerPage('/vault', renderVault);
})();
