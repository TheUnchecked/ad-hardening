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
  liAll.innerHTML = `<a href="#" data-cat="all" class="${activeCategory === null ? 'active' : ''}">
    <span>Tutte le categorie</span>
    <span class="nav-count">${totalItems()}</span>
  </a>`;
  liAll.querySelector('a').addEventListener('click', e => { e.preventDefault(); setCategory(null); });
  ul.appendChild(liAll);

  allItems.forEach(cat => {
    const li = document.createElement('li');
    li.innerHTML = `<a href="#cat-${cat.id}" data-cat="${cat.id}" class="${activeCategory === cat.id ? 'active' : ''}">
      <span>${cat.name}</span>
      <span class="nav-count">${cat.items.length}</span>
    </a>`;
    li.querySelector('a').addEventListener('click', e => {
      e.preventDefault();
      setCategory(cat.id);
      const el = document.getElementById('cat-' + cat.id);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    ul.appendChild(li);
  });
}

function totalItems() {
  return allItems.reduce((acc, c) => acc + c.items.length, 0);
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
      (i.description || '').toLowerCase().includes(query)
    );

    if (items.length === 0) return;

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
    items.forEach(item => list.appendChild(buildItem(item)));
    content.appendChild(section);
  });

  if (content.innerHTML === '') {
    content.innerHTML = `<div class="empty-state"><p>Nessun controllo trovato.</p></div>`;
  }
}

// ── ITEM ─────────────────────────────────────────
function buildItem(item) {
  const div = document.createElement('div');
  div.className = 'check-item';
  div.dataset.id = item.id;

  const hasDesc = item.description && item.description.trim();

  div.innerHTML = `
    <div class="item-body">
      <div class="item-title">${item.title}</div>
      ${hasDesc ? `<div class="item-desc">${item.description}</div>` : ''}
      <div class="item-meta">
        <span class="badge badge-${item.severity}">${labelSeverity(item.severity)}</span>
        ${item.ref ? `<span class="item-ref">${item.ref}</span>` : ''}
      </div>
    </div>
    ${hasDesc ? `<button class="item-expand-btn" title="Dettagli">+</button>` : ''}
  `;

  const btn = div.querySelector('.item-expand-btn');
  if (btn) {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const expanded = div.classList.toggle('expanded');
      btn.textContent = expanded ? '−' : '+';
    });
  }

  return div;
}

function labelSeverity(s) {
  const map = { critical: 'Critico', high: 'Alto', medium: 'Medio', low: 'Basso' };
  return map[s] || s;
}

// ── SEARCH ────────────────────────────────────────
document.getElementById('search-input').addEventListener('input', () => render());

// ── FILTRI SEVERITÀ ───────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.severity;
    render();
  });
});

// ── SIDEBAR MOBILE ───────────────────────────────
document.getElementById('sidebar-toggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// ── AVVIO ─────────────────────────────────────────
loadData();
