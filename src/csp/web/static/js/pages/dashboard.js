(function() {
function renderDashboard({ apiGet, el, showFlash }) {
  const app = document.getElementById('app');
  app.innerHTML = '';

  app.appendChild(el('div', { className: 'page-header' },
    el('h1', null, 'Dashboard')));

  const grid = el('div', { className: 'dashboard-grid' });
  const stats = [
    { label: 'Credentials', key: 'cred_count', icon: '' },
    { label: 'Open Incidents', key: 'inc_count', icon: '' },
    { label: 'Watched Paths', key: 'watch_count', icon: '' },
    { label: 'HashDB Entries', key: 'hash_count', icon: '' },
    { label: 'Log Runs', key: 'log_count', icon: '' },
  ];
  stats.forEach(s => {
    const card = el('div', { className: 'stat-card' });
    card.appendChild(el('div', { className: 'num', id: `stat-${s.key}` }, '-'));
    card.appendChild(el('div', { className: 'label' }, s.label));
    grid.appendChild(card);
  });
  app.appendChild(grid);

  // Quick actions
  const actionsCard = el('div', { className: 'card' });
  actionsCard.appendChild(el('h2', null, 'Quick actions'));
  const toolbar = el('div', { className: 'toolbar' });
  const buttons = [
    { text: 'Add credential', hash: '#/vault' },
    { text: 'Add incident', hash: '#/incidents' },
    { text: 'Run FIM scan', hash: '#/fim' },
    { text: 'Analyze a log', hash: '#/logs' },
  ];
  buttons.forEach(b => {
    const btn = el('a', { href: b.hash, className: 'btn btn-primary btn-sm' }, b.text);
    toolbar.appendChild(btn);
  });
  actionsCard.appendChild(toolbar);
  app.appendChild(actionsCard);

  // Load stats
  async function loadStats() {
    try {
      const status = await apiGet('/api/status');
      if (!status.user) return;

      const vault = await apiGet('/api/vault/credentials');
      document.getElementById('stat-cred_count').textContent = vault.length;

      const incidents = await apiGet('/api/incidents?open_only=true');
      document.getElementById('stat-inc_count').textContent = incidents.length;

      const watches = await apiGet('/api/fim/watches');
      document.getElementById('stat-watch_count').textContent = watches.length;

      const sources = await apiGet('/api/hashdb/sources');
      document.getElementById('stat-hash_count').textContent = sources.length;

      const runs = await apiGet('/api/logs/runs');
      document.getElementById('stat-log_count').textContent = runs.length;
    } catch (e) {
      showFlash(e.message, 'error');
    }
  }
  loadStats();
}

window.CSP.registerPage('/', renderDashboard);
})();
