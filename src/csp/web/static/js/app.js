(function() {
'use strict';

const CSP_PAGES = {};

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
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
    if (c != null) e.append(c);
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

function showFlash(msg, type) {
  const app = $('#app');
  const f = el('div', { className: `flash flash-${type || 'info'}` }, msg);
  app.insertBefore(f, app.firstChild);
  setTimeout(() => f.remove(), 4000);
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
  nav.classList.toggle('hidden', !visible);
}

async function navigate() {
  const hash = window.location.hash.slice(1) || '/';
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
  const page = CSP_PAGES[hash];
  if (page) {
    app.innerHTML = '<div class="flash flash-info">Loading...</div>';
    try {
      page({ apiGet, apiPost, apiPut, apiDelete, showFlash, renderTable, modal, formGroup, el });
    } catch (e) {
      app.innerHTML = `<div class="flash flash-error">Error: ${e.message}</div>`;
    }
  } else {
    app.innerHTML = '<h1>Page not found</h1><p><a href="#/">Go to Dashboard</a></p>';
  }
}

// Page registrations
function registerPage(hash, fn) {
  CSP_PAGES[hash] = fn;
}

// Run
window.addEventListener('hashchange', navigate);
window.addEventListener('load', navigate);

// Logout
document.addEventListener('click', e => {
  if (e.target.id === 'logout-btn') {
    e.preventDefault();
    apiPost('/api/logout').then(() => {
      window.location.hash = '#/login';
    }).catch(() => {
      window.location.hash = '#/login';
    });
  }
});

// Expose for page modules
window.CSP = { registerPage, apiGet, apiPost, apiPut, apiDelete };
})();
