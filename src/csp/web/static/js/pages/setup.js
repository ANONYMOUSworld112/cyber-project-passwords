(function() {
function renderSetup({ apiGet, apiPost, el, showFlash, renderErrorPage }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const card = el('div', { className: 'card', style: 'max-width:650px;margin:40px auto;border:1px solid var(--c-silver-gray);box-shadow:0 16px 40px rgba(0,0,0,0.9), 0 0 25px rgba(255,255,255,0.08);' });
  const header = el('div', { style: 'margin-bottom:24px;padding-bottom:14px;border-bottom:1px solid var(--c-dark-charcoal);' });
  header.appendChild(el('h2', { style: 'font-family:var(--font-display);font-size:32px;color:var(--c-pure-white);letter-spacing:1.5px;' }, 'SYSTEM INITIALIZATION // FIRST-RUN'));
  header.appendChild(el('p', { style: 'font-family:var(--font-display);color:var(--c-silver-gray);font-size:18px;margin-top:6px;letter-spacing:1px;' },
    '[PROVISIONING ROOT USER CREDENTIALS & ARGON2ID/AES-GCM KEY VAULT]'));
  card.appendChild(header);

  const form = el('div', { className: 'form' });

  const usernameInput = el('input', { type: 'text', id: 'setup-user', placeholder: 'e.g. sec_admin', autocomplete: 'off' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Username (3-32 chars [a-z0-9_-])'), usernameInput));

  const pwInput = el('input', { type: 'password', id: 'setup-pw', placeholder: 'Min 12 chars, 3 of lower/upper/digit/symbol' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Password'), pwInput));

  const pw2Input = el('input', { type: 'password', id: 'setup-pw2', placeholder: 'Confirm password' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Confirm password'), pw2Input));

  const qInput = el('input', { type: 'text', id: 'setup-q', placeholder: 'e.g. What is my recovery phrase?' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Recovery hint question'), qInput));

  const aInput = el('input', { type: 'password', id: 'setup-a', placeholder: 'Hint answer' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Recovery hint answer'), aInput));

  const a2Input = el('input', { type: 'password', id: 'setup-a2', placeholder: 'Confirm hint answer' });
  form.appendChild(el('div', { className: 'form-group' },
    el('label', null, 'Confirm hint answer'), a2Input));

  const submitBtn = el('button', { className: 'btn btn-primary', style: 'margin-top:12px;font-weight:700;width:100%;padding:14px;' }, 'INITIALIZE SYSTEM VAULT');
  const statusEl = el('div', { style: 'margin-top:12px;font-size:20px;color:var(--c-silver-gray);' });
  form.appendChild(submitBtn);
  form.appendChild(statusEl);
  card.appendChild(form);
  app.appendChild(card);

  // Check if already set up
  apiGet('/api/setup/status').then(st => {
    if (!st.first_run && st.users.length > 0) {
      if (renderErrorPage) {
        renderErrorPage({
          code: '403',
          title: 'Setup Locked // Already Initialized',
          message: 'The cryptographic security system has already been initialized with root administrator credentials. New setup provisioning is permanently locked.',
          guidance: '<strong>REQUIRED ACTION:</strong> Please navigate to the login terminal to authenticate, or utilize your recovery hint credentials if your master password was forgotten.',
          path: '#/setup'
        });
      } else {
        statusEl.textContent = 'System is already set up. Redirecting to login...';
        setTimeout(() => window.location.hash = '#/login', 1500);
      }
    }
  });

  submitBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = pwInput.value;
    const password2 = pw2Input.value;
    const question = qInput.value.trim();
    const answer = aInput.value;
    const answer2 = a2Input.value;

    if (!username || !password || !question || !answer) {
      showFlash('All fields are required', 'error');
      return;
    }
    if (password !== password2) {
      showFlash('Passwords do not match', 'error');
      return;
    }
    if (answer !== answer2) {
      showFlash('Hint answers do not match', 'error');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating...';
    try {
      await apiPost('/api/setup', { username, password, hint_question: question, hint_answer: answer });
      showFlash('Account created. You can now log in.', 'success');
      setTimeout(() => window.location.hash = '#/login', 1000);
    } catch (e) {
      showFlash(e.message, 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create account';
    }
  });
}

window.CSP.registerPage('/setup', renderSetup);
})();
