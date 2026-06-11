(function() {
function renderLogin({ apiGet, apiPost, el, showFlash }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const card = el('div', { className: 'card', style: 'max-width:400px;margin:60px auto;' });
  card.appendChild(el('h2', { style: 'text-align:center;margin-bottom:20px;' }, 'csp'));

  const form = el('div', null);

  const userSelect = el('select', { id: 'login-user' });
  userSelect.appendChild(el('option', { value: '' }, 'Loading users...'));
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Username'), userSelect));

  const pwInput = el('input', { type: 'password', id: 'login-pw', placeholder: 'Password' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Password'), pwInput));

  const submitBtn = el('button', { className: 'btn btn-primary', style: 'width:100%;' }, 'Login');
  form.appendChild(submitBtn);

  const recoverLink = el('a', { href: '#/recovery', style: 'display:block;text-align:center;margin-top:12px;font-size:13px;' }, 'Forgot password?');
  form.appendChild(recoverLink);

  const resetLink = el('a', { href: '#', id: 'reset-link', style: 'display:block;text-align:center;margin-top:6px;font-size:12px;color:var(--red);' }, 'Reset all data (factory reset)');
  form.appendChild(resetLink);

  card.appendChild(form);
  app.appendChild(card);

  // Load users
  apiGet('/api/users').then(users => {
    userSelect.innerHTML = '';
    users.forEach(u => {
      userSelect.appendChild(el('option', { value: u }, u));
    });
    if (users.length === 0) {
      userSelect.appendChild(el('option', { value: '' }, 'No users found'));
    }
  }).catch(() => {
    userSelect.innerHTML = '<option value="">Error loading users</option>';
  });

  submitBtn.addEventListener('click', async () => {
    const username = userSelect.value;
    const password = pwInput.value;
    if (!username || !password) {
      showFlash('Please select a user and enter a password', 'error');
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';
    try {
      await apiPost('/api/login', { username, password });
      window.location.hash = '#/';
    } catch (e) {
      showFlash(e.message, 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Login';
    }
  });

  pwInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitBtn.click();
  });

  document.getElementById('reset-link').addEventListener('click', e => {
    e.preventDefault();
    const overlay = el('div', { className: 'modal-overlay' });
    const m = el('div', { className: 'modal' });
    m.appendChild(el('h2', null, 'Factory reset'));
    m.appendChild(el('p', { style: 'margin-bottom:12px;font-size:13px;' },
      'This will permanently delete ALL data including all users, vaults, incidents, and settings. This cannot be undone.'));
    const input = el('input', { type: 'text', placeholder: 'Type RESET to confirm', style: 'width:100%;margin-bottom:12px;' });
    m.appendChild(input);
    const actions = el('div', { className: 'modal-actions' });
    const confirmBtn = el('button', { className: 'btn btn-danger', disabled: true }, 'Reset');
    actions.appendChild(confirmBtn);
    actions.appendChild(el('button', { className: 'btn', onclick: () => overlay.remove() }, 'Cancel'));
    m.appendChild(actions);
    overlay.appendChild(m);
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);

    input.addEventListener('input', () => {
      confirmBtn.disabled = input.value !== 'RESET';
    });
    confirmBtn.addEventListener('click', async () => {
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Resetting...';
      try {
        await apiPost('/api/reset');
        overlay.remove();
        showFlash('System reset. Redirecting to setup...', 'success');
        setTimeout(() => window.location.hash = '#/setup', 1500);
      } catch (e) {
        showFlash(e.message, 'error');
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Reset';
      }
    });
  });
}

window.CSP.registerPage('/login', renderLogin);
})();
