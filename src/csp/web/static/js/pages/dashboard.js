(function() {
function renderDashboard({ apiGet, el, showFlash }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  // Shapely Hero Banner
  const hero = el('div', { className: 'card', style: 'padding:36px 32px;margin-bottom:32px;background:var(--bg-card);border:1px solid var(--c-dark-charcoal);position:relative;overflow:hidden;' });
  const heroBadge = el('div', { className: 'badge', style: 'margin-bottom:16px;background:var(--c-dark-charcoal);border-color:var(--c-silver-gray);color:var(--c-pure-white);' }, 'SECURITY STATUS: AIR-GAPPED // ACTIVE');
  const heroTitle = el('h1', { style: 'font-family:var(--font-display);font-size:44px;letter-spacing:2px;color:var(--c-pure-white);margin-bottom:12px;text-transform:uppercase;' }, 'SECURITY OPERATIONS // DASHBOARD');
  const heroDesc = el('p', { style: 'font-size:20px;color:var(--c-silver-gray);line-height:1.7;max-width:900px;margin-bottom:24px;' },
    'Offline cryptographic terminal for multi-user credentials management, file integrity monitoring (FIM), threat hash detection, and anomaly log analysis. All vaults are protected with Argon2id key derivation and AES-256-GCM authenticated encryption.');
  
  const heroToolbar = el('div', { className: 'toolbar', style: 'margin-bottom:0;' });
  const heroBtns = [
    { text: '+ STORE CREDENTIAL', hash: '#/vault', primary: true },
    { text: 'RUN FIM SCAN', hash: '#/fim', primary: false },
    { text: 'VIEW INCIDENTS', hash: '#/incidents', primary: false },
    { text: 'SEARCH HASHDB', hash: '#/hashdb', primary: false }
  ];
  heroBtns.forEach(b => {
    const btnClass = b.primary ? 'btn btn-primary' : 'btn btn-terminal';
    heroToolbar.appendChild(el('a', { href: b.hash, className: btnClass }, b.text));
  });

  hero.appendChild(heroBadge);
  hero.appendChild(heroTitle);
  hero.appendChild(heroDesc);
  hero.appendChild(heroToolbar);
  app.appendChild(hero);

  // Stat Grid (Nova Bomb metric counters)
  const grid = el('div', { className: 'dashboard-grid' });
  const stats = [
    { label: 'Vault Credentials', key: 'cred_count' },
    { label: 'Active Incidents', key: 'inc_count' },
    { label: 'FIM Watched Paths', key: 'watch_count' },
    { label: 'HashDB Datasets', key: 'hash_count' },
    { label: 'Analyzed Logs', key: 'log_count' },
  ];
  stats.forEach(s => {
    const card = el('div', { className: 'stat-card' });
    card.appendChild(el('div', { className: 'num', id: `stat-${s.key}` }, '-'));
    card.appendChild(el('div', { className: 'label' }, s.label));
    grid.appendChild(card);
  });
  app.appendChild(grid);

  // Shapely Two-Column Feature Section
  const featureRow = el('div', { style: 'display:grid;grid-template-columns:repeat(auto-fit, minmax(340px, 1fr));gap:24px;margin-bottom:32px;' });

  // Telemetry Card
  const telemetryCard = el('div', { className: 'card', style: 'margin-bottom:0;' });
  telemetryCard.appendChild(el('h2', null, 'SYSTEM SECURITY ARCHITECTURE'));
  const teleTable = el('div', { style: 'font-size:19px;display:flex;flex-direction:column;gap:14px;margin-top:16px;' },
    el('div', { style: 'display:flex;justify-content:space-between;border-bottom:1px solid var(--c-dark-charcoal);padding-bottom:8px;' },
      el('span', { style: 'color:var(--c-silver-gray);' }, 'AUTHENTICATION & KDF'),
      el('strong', { style: 'color:var(--c-pure-white);font-family:var(--font-mono);' }, 'Argon2id (m=64MB, t=3, p=4)')
    ),
    el('div', { style: 'display:flex;justify-content:space-between;border-bottom:1px solid var(--c-dark-charcoal);padding-bottom:8px;' },
      el('span', { style: 'color:var(--c-silver-gray);' }, 'PAYLOAD ENCRYPTION'),
      el('strong', { style: 'color:var(--c-pure-white);font-family:var(--font-mono);' }, 'AES-256-GCM AEAD (12-byte IV)')
    ),
    el('div', { style: 'display:flex;justify-content:space-between;border-bottom:1px solid var(--c-dark-charcoal);padding-bottom:8px;' },
      el('span', { style: 'color:var(--c-silver-gray);' }, 'MULTI-USER ISOLATION'),
      el('strong', { style: 'color:var(--c-pure-white);font-family:var(--font-mono);' }, 'ContextVar Async Binding')
    ),
    el('div', { style: 'display:flex;justify-content:space-between;border-bottom:1px solid var(--c-dark-charcoal);padding-bottom:8px;' },
      el('span', { style: 'color:var(--c-silver-gray);' }, 'LOCKOUT POLICY'),
      el('strong', { style: 'color:var(--c-pure-white);font-family:var(--font-mono);' }, '5 Attempts / 15m Lockout')
    ),
    el('div', { style: 'display:flex;justify-content:space-between;padding-bottom:4px;' },
      el('span', { style: 'color:var(--c-silver-gray);' }, 'STORAGE INTEGRITY'),
      el('strong', { style: 'color:var(--c-pure-white);font-family:var(--font-mono);' }, 'Atomic Writes + Private Perms')
    )
  );
  telemetryCard.appendChild(teleTable);
  featureRow.appendChild(telemetryCard);

  // Tactical Operations Card
  const opsCard = el('div', { className: 'card', style: 'margin-bottom:0;' });
  opsCard.appendChild(el('h2', null, 'TACTICAL SHORTCUTS & OPERATIONS'));
  opsCard.appendChild(el('p', { style: 'font-size:20px;color:var(--c-silver-gray);margin-top:8px;margin-bottom:18px;line-height:1.6;' },
    'Access key terminal nodes directly to perform defensive operations, file integrity comparisons, or threat hash imports.'));

  const opsList = el('div', { style: 'display:flex;flex-direction:column;gap:10px;' });
  const opLinks = [
    { title: 'CREDENTIAL VAULT', sub: 'Generate, encrypt, inspect, and rotate secret keys', hash: '#/vault' },
    { title: 'INCIDENT TRACKER', sub: 'Record security threats, assign severities, write postmortems', hash: '#/incidents' },
    { title: 'FILE INTEGRITY (FIM)', sub: 'Baseline and audit local file trees for unauthorized changes', hash: '#/fim' },
    { title: 'THREAT HASHDB', sub: 'Import and query known malicious SHA-256 indicators', hash: '#/hashdb' },
  ];
  opLinks.forEach(op => {
    const item = el('a', {
      href: op.hash,
      style: 'display:block;padding:12px 16px;background:var(--c-pitch-black);border:1px solid var(--c-dark-charcoal);border-radius:4px;text-decoration:none;'
    });
    item.appendChild(el('div', { style: 'font-family:var(--font-display);font-size:20px;color:var(--c-pure-white);letter-spacing:1px;' }, `> ${op.title}`));
    item.appendChild(el('div', { style: 'font-size:17px;color:var(--c-mid-gray);margin-top:4px;' }, op.sub));
    opsList.appendChild(item);
  });
  opsCard.appendChild(opsList);
  featureRow.appendChild(opsCard);

  app.appendChild(featureRow);

  // Load stats
  async function loadStats() {
    try {
      const status = await apiGet('/api/status');
      if (!status.user) return;

      const vault = await apiGet('/api/vault/credentials');
      const credEl = document.getElementById('stat-cred_count');
      if (credEl) credEl.textContent = vault.length;

      const incidents = await apiGet('/api/incidents?open_only=true');
      const incEl = document.getElementById('stat-inc_count');
      if (incEl) incEl.textContent = incidents.length;

      const watches = await apiGet('/api/fim/watches');
      const watchEl = document.getElementById('stat-watch_count');
      if (watchEl) watchEl.textContent = watches.length;

      const sources = await apiGet('/api/hashdb/sources');
      const hashEl = document.getElementById('stat-hash_count');
      if (hashEl) hashEl.textContent = sources.length;

      const runs = await apiGet('/api/logs/runs');
      const logEl = document.getElementById('stat-log_count');
      if (logEl) logEl.textContent = runs.length;
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }
  loadStats();
}

window.CSP.registerPage('/', renderDashboard);
})();
