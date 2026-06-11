(function() {
function renderSettings({ apiGet, apiPost, apiDelete, el, showFlash, modal, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  app.appendChild(el('div', { className: 'page-header' },
    el('h1', null, 'Settings')));

  // Change password
  const pwCard = el('div', { className: 'card' });
  pwCard.appendChild(el('h2', null, 'Change password'));
  pwCard.appendChild(formGroup('Current password', el('input', { type: 'password', id: 'settings-old-pw' })));
  pwCard.appendChild(formGroup('New password', el('input', { type: 'password', id: 'settings-new-pw', placeholder: 'Min 12 chars, 3 of lower/upper/digit/symbol' })));
  pwCard.appendChild(formGroup('Confirm new password', el('input', { type: 'password', id: 'settings-new-pw2' })));
  const changePwBtn = el('button', { className: 'btn btn-primary' }, 'Change password');
  pwCard.appendChild(changePwBtn);
  app.appendChild(pwCard);

  // User management
  const userCard = el('div', { className: 'card' });
  userCard.appendChild(el('h2', null, 'User management'));
  const userListDiv = el('div', { id: 'settings-user-list', style: 'margin-bottom:12px;' });
  userCard.appendChild(userListDiv);
  const addUserBtn = el('button', { className: 'btn btn-primary btn-sm' }, '+ Add user');
  userCard.appendChild(addUserBtn);
  app.appendChild(userCard);

  changePwBtn.addEventListener('click', async () => {
    const old = document.getElementById('settings-old-pw').value;
    const new1 = document.getElementById('settings-new-pw').value;
    const new2 = document.getElementById('settings-new-pw2').value;
    if (!old || !new1) { showFlash('All fields are required', 'error'); return; }
    if (new1 !== new2) { showFlash('New passwords do not match', 'error'); return; }
    try {
      await apiPost('/api/passwd', { old_password: old, new_password: new1 });
      showFlash('Password changed', 'success');
      document.getElementById('settings-old-pw').value = '';
      document.getElementById('settings-new-pw').value = '';
      document.getElementById('settings-new-pw2').value = '';
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  async function loadUsers() {
    try {
      const users = await apiGet('/api/users');
      const div = document.getElementById('settings-user-list');
      div.innerHTML = '';
      if (users.length === 0) {
        div.appendChild(el('p', { style: 'color:var(--text2);font-size:13px;' }, 'No users.'));
        return;
      }
      const tbl = el('table');
      const thead = el('thead');
      thead.appendChild(el('tr', null, el('th', null, 'Username'), el('th', null, 'Actions')));
      tbl.appendChild(thead);
      const tbody = el('tbody');
      users.forEach(u => {
        const tr = el('tr');
        tr.appendChild(el('td', null, u));
        const actionsTd = el('td', null);
        if (users.length > 1) {
          const rmBtn = el('button', { className: 'btn btn-sm btn-danger' }, 'Remove');
          rmBtn.addEventListener('click', () => removeUser(u));
          actionsTd.appendChild(rmBtn);
        }
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      div.appendChild(tbl);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }

  function removeUser(username) {
    const m = modal('Remove user', body => {
      body.appendChild(el('p', null, `Are you sure you want to remove user "${username}"? This cannot be undone.`));
      body.appendChild(formGroup(`Type "${username}" to confirm`, el('input', { type: 'text', id: 'settings-rm-confirm' })));
    }, actions => {
      const rmBtn = el('button', { className: 'btn btn-danger' }, 'Remove');
      actions.appendChild(rmBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      rmBtn.addEventListener('click', async () => {
        const confirm = document.getElementById('settings-rm-confirm').value;
        if (confirm !== username) { showFlash('Confirmation did not match', 'error'); return; }
        try {
          await apiDelete(`/api/users/${encodeURIComponent(username)}`);
          m.overlay.remove();
          showFlash(`User "${username}" removed`, 'success');
          loadUsers();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  }

  addUserBtn.addEventListener('click', () => {
    const m = modal('Add user', body => {
      body.appendChild(formGroup('Username', el('input', { type: 'text', id: 'settings-add-user' })));
      body.appendChild(formGroup('Password', el('input', { type: 'password', id: 'settings-add-pw' })));
      body.appendChild(formGroup('Confirm password', el('input', { type: 'password', id: 'settings-add-pw2' })));
      body.appendChild(formGroup('Hint question', el('input', { type: 'text', id: 'settings-add-q' })));
      body.appendChild(formGroup('Hint answer', el('input', { type: 'password', id: 'settings-add-a' })));
    }, actions => {
      const createBtn = el('button', { className: 'btn btn-primary' }, 'Create');
      actions.appendChild(createBtn);
      const cancelBtn = el('button', { className: 'btn' }, 'Cancel');
      cancelBtn.addEventListener('click', () => m.overlay.remove());
      actions.appendChild(cancelBtn);

      createBtn.addEventListener('click', async () => {
        const username = document.getElementById('settings-add-user').value.trim();
        const password = document.getElementById('settings-add-pw').value;
        const pw2 = document.getElementById('settings-add-pw2').value;
        const question = document.getElementById('settings-add-q').value.trim();
        const answer = document.getElementById('settings-add-a').value;
        if (!username || !password || !question || !answer) {
          showFlash('All fields are required', 'error');
          return;
        }
        if (password !== pw2) { showFlash('Passwords do not match', 'error'); return; }
        try {
          await apiPost('/api/users', { username, password, hint_question: question, hint_answer: answer });
          m.overlay.remove();
          showFlash(`User "${username}" created`, 'success');
          loadUsers();
        } catch (e) {
          showFlash(e.message, 'error');
        }
      });
    });
  });

  loadUsers();
}

window.CSP.registerPage('/settings', renderSettings);
})();
