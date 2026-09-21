(function() {
function renderRecovery({ apiGet, apiPost, el, showFlash, formGroup }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  const card = el('div', { className: 'card', style: 'max-width:560px;margin:50px auto;border:1px solid var(--c-silver-gray);box-shadow:0 16px 40px rgba(0,0,0,0.9), 0 0 25px rgba(255,255,255,0.08);' });
  card.appendChild(el('h2', { style: 'font-family:var(--font-display);font-size:32px;color:var(--c-pure-white);letter-spacing:1.5px;margin-bottom:16px;' }, 'PASSWORD RECOVERY'));

  card.appendChild(el('p', { style: 'color:var(--c-silver-gray);font-size:20px;margin-bottom:20px;line-height:1.5;' },
    'If both your master password and hint answer are forgotten, encrypted vault data is permanently unrecoverable. Zero backdoors.'));

  // Load users
  const userSelect = el('select', { id: 'recovery-user' });
  userSelect.appendChild(el('option', { value: '' }, 'Loading...'));

  const answerInput = el('input', { type: 'password', id: 'recovery-answer', placeholder: 'Hint answer' });
  const step1Form = el('div', null);
  step1Form.appendChild(formGroup('Username', userSelect));
  step1Form.appendChild(formGroup('Hint answer', answerInput));
  const step1Btn = el('button', { className: 'btn btn-primary', style: 'width:100%;padding:14px;' }, 'VERIFY & RECOVER');
  step1Form.appendChild(step1Btn);
  card.appendChild(step1Form);

  const hintDiv = el('div', { id: 'recovery-hint', style: 'display:none;' });
  card.appendChild(hintDiv);

  const step2Form = el('div', { id: 'recovery-step2', style: 'display:none;' });
  step2Form.appendChild(formGroup('Confirm hint answer', el('input', { type: 'password', id: 'recovery-answer2' })));
  step2Form.appendChild(formGroup('New password', el('input', { type: 'password', id: 'recovery-newpw', placeholder: 'Min 12 chars' })));
  step2Form.appendChild(formGroup('Confirm new password', el('input', { type: 'password', id: 'recovery-newpw2' })));
  const step2Btn = el('button', { className: 'btn btn-primary', style: 'width:100%;padding:14px;' }, 'RESET PASSWORD & PURGE OLD VAULT');
  step2Form.appendChild(step2Btn);
  card.appendChild(step2Form);

  const backLink = el('a', { href: '#/login', style: 'display:block;text-align:center;margin-top:20px;font-size:20px;color:var(--c-silver-gray);' }, '← Back to login');
  card.appendChild(backLink);

  app.appendChild(card);

  apiGet('/api/users').then(users => {
    userSelect.innerHTML = '';
    users.forEach(u => userSelect.appendChild(el('option', { value: u }, u)));
    if (users.length === 0) {
      userSelect.innerHTML = '<option value="">No users</option>';
    }
  }).catch(() => {
    userSelect.innerHTML = '<option value="">Error</option>';
  });

  step1Btn.addEventListener('click', async () => {
    const username = userSelect.value;
    const answer = answerInput.value;
    if (!username || !answer) { showFlash('All fields required', 'error'); return; }
    try {
      const res = await apiPost('/api/recovery/start', { username, answer });
      document.getElementById('recovery-hint').innerHTML = el('div', { className: 'flash flash-info', style: 'margin-top:12px;' },
        `Hint question: ${res.hint_question}`).outerHTML;
      document.getElementById('recovery-hint').style.display = '';
      document.getElementById('recovery-step2').style.display = '';
      step1Form.style.display = 'none';
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });

  step2Btn.addEventListener('click', async () => {
    const username = userSelect.value;
    const answer = document.getElementById('recovery-answer2').value;
    const newpw = document.getElementById('recovery-newpw').value;
    const newpw2 = document.getElementById('recovery-newpw2').value;
    if (!answer || !newpw) { showFlash('All fields required', 'error'); return; }
    if (newpw !== newpw2) { showFlash('Passwords do not match', 'error'); return; }
    try {
      await apiPost('/api/recovery/complete', { username, answer, new_password: newpw });
      showFlash('Password reset. Old vault data is lost. You can now log in.', 'success');
      setTimeout(() => window.location.hash = '#/login', 2000);
    } catch (e) {
      showFlash(e.message, 'error');
    }
  });
}

window.CSP.registerPage('/recovery', renderRecovery);
})();
