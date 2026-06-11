(function() {
function renderSetup({ apiGet, apiPost, el, showFlash }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const card = el('div', { className: 'card' });
  card.appendChild(el('h2', null, 'First-time setup'));
  card.appendChild(el('p', { style: 'margin-bottom:16px;color:var(--text2);' },
    'Create the first user account. This is the only time you will configure the recovery hint.'));

  const form = el('div', { className: 'form' });

  const usernameInput = el('input', { type: 'text', id: 'setup-user', placeholder: 'e.g. admin', autocomplete: 'off' });
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

  const submitBtn = el('button', { className: 'btn btn-primary', style: 'margin-top:8px;' }, 'Create account');
  const statusEl = el('div', { style: 'margin-top:12px;font-size:13px;' });
  form.appendChild(submitBtn);
  form.appendChild(statusEl);
  card.appendChild(form);
  app.appendChild(card);

  // Check if already set up
  apiGet('/api/setup/status').then(st => {
    if (!st.first_run && st.users.length > 0) {
      statusEl.textContent = 'System is already set up. Redirecting to login...';
      statusEl.style.color = 'var(--accent)';
      setTimeout(() => window.location.hash = '#/login', 1500);
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
