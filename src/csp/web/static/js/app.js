(function() {
'use strict';

const CSP_PAGES = {};

function formatErrorMessage(msg, status) {
  if (!msg) return `Request failed (HTTP ${status || 'unknown'})`;
  const lower = String(msg).toLowerCase();
  if (lower.includes('at least 12 characters') || lower.includes('length')) {
    return 'Password Security Policy: Master password must contain at least 12 characters and mix character classes.';
  }
  if (lower.includes('do not match') || lower.includes('mismatch')) {
    return 'Verification Mismatch: The entered confirmation password does not match.';
  }
  if (lower.includes('invalid username or password') || lower.includes('invalid credentials')) {
    return 'Authentication Failed: Invalid username or password. Check credentials or use recovery phrase.';
  }
  if (lower.includes('locked')) {
    return 'Account Security Lockout: This account is temporarily locked due to repeated failed attempts. Please wait 15 minutes or enter your recovery phrase.';
  }
  if (lower.includes('confirm') || lower.includes('reset')) {
    return 'Confirmation Required: Type "RESET" in uppercase to authorize data purge.';
  }
  if (lower.includes('setup has already completed') || lower.includes('setup already completed') || lower.includes('first run')) {
    return 'Initialization Locked: CSP setup has already completed. Direct setup access is blocked.';
  }
  if (lower.includes('corrupt') || lower.includes('decrypt')) {
    return 'Cryptographic Integrity Failure: Vault file cannot be decrypted or has been corrupted.';
  }
  if (lower.includes('already exists')) {
    return 'Account Conflict: A user with this username already exists. Choose a different username or log in.';
  }
  return msg;
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(path, opts);
  } catch (networkErr) {
    const offlineMsg = 'Connection Failure: Local CSP daemon unreachable at ' + window.location.origin + '. Verify that the service is running.';
    showFlash(offlineMsg, 'error', 8000);
    throw new Error(offlineMsg);
  }

  let data = {};
  try {
    data = await res.json();
  } catch {
    if (!res.ok) {
      const statusMsg = `Server error HTTP ${res.status}: ${res.statusText || 'Operation failed'}`;
      showFlash(statusMsg, 'error');
      throw new Error(statusMsg);
    }
  }

  if (!res.ok) {
    if (res.status === 401) {
      const sessionMsg = 'Session Expired: Your cryptographic authorization token has expired. Please authenticate to unlock.';
      showFlash(sessionMsg, 'warning');
      window.location.hash = '#/login';
      throw new Error(sessionMsg);
    }
    if (res.status === 403) {
      const forbiddenMsg = data.error || 'Access Denied: You do not have permission for this operation.';
      const formatted = formatErrorMessage(forbiddenMsg, 403);
      showFlash(formatted, 'error');
      throw new Error(formatted);
    }
    const rawMsg = data.error || `HTTP ${res.status} Error`;
    const formatted = formatErrorMessage(rawMsg, res.status);
    throw new Error(formatted);
  }

  return data;
}

async function apiGet(path) { return api('GET', path); }
async function apiPost(path, body) { return api('POST', path, body); }
async function apiPut(path, body) { return api('PUT', path, body); }
async function apiDelete(path, body) { return api('DELETE', path, body); }

function $(sel, ctx) { return (ctx || document).querySelector(sel); }
function $$(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }
function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'className') e.className = v;
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c != null) {
      if (typeof c === 'string' || typeof c === 'number') {
        e.appendChild(document.createTextNode(String(c)));
      } else {
        e.appendChild(c);
      }
    }
  }
  return e;
}

function renderTable(headers, rows, rowFn) {
  const table = el('table');
  const thead = el('thead');
  const tr = el('tr');
  headers.forEach(h => tr.appendChild(el('th', null, h)));
  thead.appendChild(tr);
  table.appendChild(thead);
  const tbody = el('tbody');
  rows.forEach((r, i) => {
    const tr2 = el('tr');
    rowFn(tr2, r, i);
    tbody.appendChild(tr2);
  });
  table.appendChild(tbody);
  const wrap = el('div', { className: 'table-wrap' });
  wrap.appendChild(table);
  return wrap;
}

function showFlash(msg, type = 'info', duration = 6000) {
  let container = $('#flash-container');
  if (!container) {
    container = el('div', { id: 'flash-container', className: 'flash-container' });
    document.body.appendChild(container);
  }
  const icon = type === 'error' ? '[!]' : (type === 'success' ? '[✓]' : (type === 'warning' ? '[▲]' : '[i]'));
  const f = el('div', { className: `flash flash-${type}` });
  const content = el('div', { className: 'flash-content' },
    el('span', { className: 'flash-icon' }, icon),
    el('span', { className: 'flash-text' }, msg)
  );
  const closeBtn = el('button', {
    className: 'flash-close-btn',
    onclick: () => {
      f.style.opacity = '0';
      f.style.transform = 'translateY(-12px)';
      setTimeout(() => f.remove(), 200);
    }
  }, '×');
  f.appendChild(content);
  f.appendChild(closeBtn);
  container.appendChild(f);
  if (duration > 0) {
    setTimeout(() => {
      if (f.parentNode) {
        f.style.opacity = '0';
        f.style.transform = 'translateY(-12px)';
        setTimeout(() => f.remove(), 200);
      }
    }, duration);
  }
}

function renderErrorPage({ code = '404', title = 'Page Not Found', message = '', guidance = '', path = '' }) {
  const app = $('#app');
  app.innerHTML = '';

  const container = el('div', { className: 'error-page' });
  const badge = el('div', { className: 'error-badge' }, `[ ${code} // SYSTEM DIAGNOSTIC ]`);
  const heading = el('h1', { className: 'error-title' }, title);
  const msgBox = el('div', { className: 'error-message' }, message);

  let traceBox = null;
  if (path) {
    traceBox = el('div', { className: 'error-details-box' },
      el('span', { className: 'terminal-prefix' }, 'ROUTE_REQUEST > '),
      el('span', null, path)
    );
  }

  const guidanceEl = el('div', { className: 'error-guidance' });
  if (guidance) {
    guidanceEl.innerHTML = guidance;
  } else {
    guidanceEl.innerHTML = `
      <strong>RECOMMENDED ACTIONS:</strong>
      <ul>
        <li>Verify the requested command path or URL hash syntax.</li>
        <li>Ensure your cryptographic session is active and not timed out.</li>
        <li>Return to the main command dashboard.</li>
      </ul>
    `;
  }

  const actions = el('div', { className: 'error-actions' });
  const dashBtn = el('button', {
    className: 'btn btn-primary',
    onclick: () => { window.location.hash = '#/'; }
  }, 'RETURN TO DASHBOARD');
  const vaultBtn = el('button', {
    className: 'btn btn-terminal',
    onclick: () => { window.location.hash = '#/vault'; }
  }, 'ACCESS VAULT');
  const reloadBtn = el('button', {
    className: 'btn btn-terminal',
    onclick: () => { window.location.reload(); }
  }, 'RELOAD TERMINAL');

  actions.appendChild(dashBtn);
  actions.appendChild(vaultBtn);
  actions.appendChild(reloadBtn);

  container.appendChild(badge);
  container.appendChild(heading);
  container.appendChild(msgBox);
  if (traceBox) container.appendChild(traceBox);
  container.appendChild(guidanceEl);
  container.appendChild(actions);

  app.appendChild(container);
}

function modal(title, bodyFn, actionsFn) {
  const overlay = el('div', { className: 'modal-overlay' });
  const m = el('div', { className: 'modal' });
  m.appendChild(el('h2', null, title));
  const bodyDiv = el('div', null);
  m.appendChild(bodyDiv);
  if (actionsFn) {
    const a = el('div', { className: 'modal-actions' });
    m.appendChild(a);
  }
  overlay.appendChild(m);
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.remove();
  });
  document.body.appendChild(overlay);
  bodyFn(bodyDiv);
  if (actionsFn) {
    const a = overlay.querySelector('.modal-actions');
    actionsFn(a);
  }
  return { overlay, modal: m, body: bodyDiv };
}

function formGroup(labelText, inputEl) {
  const g = el('div', { className: 'form-group' });
  g.appendChild(el('label', null, labelText));
  g.appendChild(inputEl);
  return g;
}

async function checkAuth() {
  try {
    const data = await apiGet('/api/status');
    return data.user || null;
  } catch {
    return null;
  }
}

function showNav(visible) {
  const nav = $('#nav');
  if (nav) nav.classList.toggle('hidden', !visible);
}

async function navigate() {
  const hash = window.location.hash.slice(1) || '/';
  const page = CSP_PAGES[hash];

  if (!page) {
    showNav(false);
    renderErrorPage({
      code: '404',
      title: 'Interface Node Not Found',
      message: `The security route "${hash}" does not map to any recognized system module or interface endpoint.`,
      guidance: `
        <strong>NAVIGATION DIRECTORY:</strong>
        <p>Available operational modules on this encrypted terminal:</p>
        <ul>
          <li><a href="#/"><strong>Dashboard</strong></a> - System telemetry, vault overview, incident stats</li>
          <li><a href="#/vault"><strong>Vault</strong></a> - Encrypted credential management & generator</li>
          <li><a href="#/incidents"><strong>Incidents</strong></a> - Security response logs and postmortems</li>
          <li><a href="#/fim"><strong>FIM</strong></a> - File integrity monitoring & change scanner</li>
          <li><a href="#/hashdb"><strong>HashDB</strong></a> - Known malicious hash database</li>
          <li><a href="#/logs"><strong>Logs</strong></a> - Audit log parser and anomaly detector</li>
          <li><a href="#/settings"><strong>Settings</strong></a> - System parameters and user administration</li>
        </ul>
      `,
      path: window.location.hash
    });
    return;
  }

  const user = await checkAuth();
  const isSetup = hash === '/setup';
  const isLogin = hash === '/login';
  const isRecovery = hash === '/recovery';

  if (isSetup || isLogin || isRecovery) {
    showNav(false);
  } else if (!user) {
    try {
      const st = await apiGet('/api/setup/status');
      if (st.first_run) {
        window.location.hash = '#/setup';
        showNav(false);
        return;
      }
    } catch {}
    window.location.hash = '#/login';
    showNav(false);
    return;
  } else {
    showNav(true);
  }

  const app = $('#app');
  app.innerHTML = `
    <div class="loading-state">
      <div class="telemetry-pill"><span class="pulse-dot"></span>INITIALIZING NODE [ ${hash.toUpperCase()} ]...</div>
    </div>
  `;
  try {
    await page({ apiGet, apiPost, apiPut, apiDelete, showFlash, renderTable, modal, formGroup, el, renderErrorPage });
  } catch (e) {
    renderErrorPage({
      code: '500',
      title: 'Interface Execution Error',
      message: `An unexpected operational error occurred while rendering module "${hash}": ${e.message}`,
      guidance: `
        <strong>FAULT DIAGNOSIS & RECOVERY:</strong>
        <ul>
          <li>The interface module encountered a client execution fault.</li>
          <li>Verify local browser storage and session integrity.</li>
          <li>Reload the terminal or authenticate with master credentials again.</li>
        </ul>
      `,
      path: window.location.hash
    });
  }
}

function registerPage(hash, fn) {
  CSP_PAGES[hash] = fn;
}

window.addEventListener('hashchange', navigate);
window.addEventListener('load', navigate);

document.addEventListener('click', e => {
  if (e.target.id === 'logout-btn') {
    e.preventDefault();
    apiPost('/api/logout').then(() => {
      showFlash('Session locked. Cryptographic keys scrubbed.', 'info');
      window.location.hash = '#/login';
    }).catch(() => {
      window.location.hash = '#/login';
    });
  }
});

window.CSP = { registerPage, apiGet, apiPost, apiPut, apiDelete, showFlash, renderErrorPage, el, modal, formGroup };
})();
