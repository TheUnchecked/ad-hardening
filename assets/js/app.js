/* ================================================
   AD HARDENING — app.js
   ================================================ */

let allItems       = [];
let activeFilter   = 'all';
let activeCategory = null;

// ── CARICAMENTO DATI ──────────────────────────────
async function loadData() {
  const res  = await fetch('data/checklist.json');
  const data = await res.json();
  allItems = data.categories;
  buildNav();
  render();
}

// ── SIDEBAR NAV ───────────────────────────────────
function buildNav() {
  const ul = document.getElementById('category-nav');
  ul.innerHTML = '';

  const liAll = document.createElement('li');
  liAll.innerHTML = `<a href="#" class="${activeCategory === null ? 'active' : ''}">
    <span>Tutte le categorie</span>
    <span class="nav-count">${allItems.reduce((a,c) => a + c.items.length, 0)}</span>
  </a>`;
  liAll.querySelector('a').addEventListener('click', e => { e.preventDefault(); setCategory(null); });
  ul.appendChild(liAll);

  allItems.forEach(cat => {
    const li = document.createElement('li');
    li.innerHTML = `<a href="#cat-${cat.id}" class="${activeCategory === cat.id ? 'active' : ''}">
      <span>${cat.name}</span>
      <span class="nav-count">${cat.items.length}</span>
    </a>`;
    li.querySelector('a').addEventListener('click', e => {
      e.preventDefault();
      setCategory(cat.id);
      document.getElementById('cat-' + cat.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    ul.appendChild(li);
  });
}

function setCategory(id) {
  activeCategory = id;
  buildNav();
  render();
}

// ── RENDER ────────────────────────────────────────
function render() {
  const content = document.getElementById('content');
  const query   = document.getElementById('search-input').value.toLowerCase().trim();
  content.innerHTML = '';

  const categories = activeCategory
    ? allItems.filter(c => c.id === activeCategory)
    : allItems;

  categories.forEach(cat => {
    let items = cat.items;
    if (activeFilter !== 'all') items = items.filter(i => i.severity === activeFilter);
    if (query) items = items.filter(i =>
      i.title.toLowerCase().includes(query) ||
      (i.description || '').toLowerCase().includes(query) ||
      (i.tags || []).some(t => t.includes(query))
    );
    if (!items.length) return;

    const section = document.createElement('section');
    section.className = 'section';
    section.id = 'cat-' + cat.id;
    section.innerHTML = `
      <div class="section-header">
        <h2 class="section-title">${cat.name}</h2>
        <span class="section-count">${items.length} controlli</span>
      </div>
      <div class="checklist" id="list-${cat.id}"></div>
    `;
    const list = section.querySelector('.checklist');
    items.forEach(item => list.appendChild(buildCard(item)));
    content.appendChild(section);
  });

  if (!content.innerHTML) {
    content.innerHTML = `<div class="empty-state"><p>Nessun controllo trovato.</p></div>`;
  }
}

// ── CARD ──────────────────────────────────────────
function buildCard(item) {
  const wrap = document.createElement('div');
  wrap.className = 'card';
  wrap.dataset.id = item.id;

  const hasQuick = item.command_quick?.trim();
  const hasFull  = item.command_full?.trim();
  const hasGuid  = item.guidance;
  const tags     = (item.tags || []).map(t => `<span class="tag">${t}</span>`).join('');

  wrap.innerHTML = `
    <div class="card-header">
      <div class="card-main">
        <div class="card-title">${item.title}</div>
        <div class="card-desc">${item.description}</div>
        <div class="card-meta">
          <span class="badge badge-${item.severity}">${labelSev(item.severity)}</span>
          ${item.ref ? `<span class="card-ref">${item.ref}</span>` : ''}
        </div>
        ${tags ? `<div class="card-tags">${tags}</div>` : ''}
      </div>
      ${hasGuid ? `<button class="btn-detail" title="Elite Guidance">⚡ Elite Guidance</button>` : ''}
    </div>

    ${hasQuick ? `
    <div class="cmd-block">
      <div class="cmd-label">Comando rapido <button class="btn-copy-cmd" data-target="quick-${item.id}">copia</button></div>
      <pre id="quick-${item.id}" class="cmd-pre">${escHtml(item.command_quick)}</pre>
      ${hasFull ? `<button class="btn-expand-cmd" data-id="${item.id}">▸ Mostra comando completo</button>` : ''}
    </div>` : ''}

    ${hasFull ? `
    <div class="cmd-block cmd-full" id="full-block-${item.id}" style="display:none">
      <div class="cmd-label">Comando completo <button class="btn-copy-cmd" data-target="full-${item.id}">copia</button></div>
      <pre id="full-${item.id}" class="cmd-pre">${escHtml(item.command_full)}</pre>
    </div>` : ''}

    ${hasGuid ? `
    <div class="guidance-panel" id="guid-${item.id}" style="display:none">
      ${guidanceHtml(item)}
    </div>` : ''}
  `;

  // Espandi comando completo
  wrap.querySelector('.btn-expand-cmd')?.addEventListener('click', function() {
    const fb = document.getElementById('full-block-' + this.dataset.id);
    const open = fb.style.display === 'none';
    fb.style.display = open ? '' : 'none';
    this.textContent = open ? '▾ Nascondi comando completo' : '▸ Mostra comando completo';
  });

  // Elite Guidance
  wrap.querySelector('.btn-detail')?.addEventListener('click', function() {
    const panel = document.getElementById('guid-' + item.id);
    const open  = panel.style.display === 'none';
    panel.style.display = open ? '' : 'none';
    this.textContent = open ? '✕ Chiudi' : '⚡ Elite Guidance';
  });

  // Copia comandi
  wrap.querySelectorAll('.btn-copy-cmd').forEach(btn => {
    btn.addEventListener('click', function() {
      const pre = document.getElementById(this.dataset.target);
      navigator.clipboard.writeText(pre.textContent).then(() => {
        const orig = this.textContent;
        this.textContent = '✓';
        setTimeout(() => this.textContent = orig, 1500);
      });
    });
  });

  return wrap;
}

// ── GUIDANCE HTML ────────────────────────────────
function guidanceHtml(item) {
  const g = item.guidance;
  if (!g) return '';

  const related = (g.related || []).map(id => {
    const found = findItem(id);
    return found
      ? `<span class="rel-tag" data-id="${id}">${id}: ${found.title}</span>`
      : `<span class="rel-tag">${id}</span>`;
  }).join('');

  const steps = (g.execution || []).map((s, i) =>
    `<li>${i + 1}. ${s}</li>`
  ).join('');

  return `
    <div class="guid-section">
      <div class="guid-title">☠ Real-World Exposure</div>
      <p class="guid-text">${g.exposure || '—'}</p>
    </div>
    ${steps ? `
    <div class="guid-section">
      <div class="guid-title">⚙ Practical Execution</div>
      <ul class="guid-steps">${steps}</ul>
    </div>` : ''}
    ${g.verification ? `
    <div class="guid-section">
      <div class="guid-title">✔ Verification</div>
      <pre class="cmd-pre">${escHtml(g.verification)}</pre>
    </div>` : ''}
    ${g.considerations ? `
    <div class="guid-section">
      <div class="guid-title">⚠ Considerations</div>
      <p class="guid-text">${g.considerations}</p>
    </div>` : ''}
    ${g.signals ? `
    <div class="guid-section">
      <div class="guid-title">◎ Operational Signals</div>
      <pre class="cmd-pre">${escHtml(g.signals)}</pre>
    </div>` : ''}
    ${related ? `
    <div class="guid-section">
      <div class="guid-title">⇢ Related Items</div>
      <div class="rel-tags">${related}</div>
    </div>` : ''}
  `;
}

// ── UTILITY ───────────────────────────────────────
function findItem(id) {
  for (const cat of allItems) {
    const found = cat.items.find(i => i.id === id);
    if (found) return found;
  }
  return null;
}

function escHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function labelSev(s) {
  return { critical: 'Critico', high: 'Alto', medium: 'Medio', low: 'Basso' }[s] || s;
}

// ── SEARCH ────────────────────────────────────────
document.getElementById('search-input').addEventListener('input', () => render());

// ── FILTRI ────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.severity;
    render();
  });
});

// ── SIDEBAR MOBILE ────────────────────────────────
document.getElementById('sidebar-toggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// ── AVVIO ─────────────────────────────────────────
loadData();
