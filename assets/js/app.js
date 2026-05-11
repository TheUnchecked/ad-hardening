/* ================================================
   AD HARDENING — app.js
   ================================================ */

const STORAGE_KEY = 'ad-hardening-checks';

let allItems   = [];
let checks     = {};
let activeFilter   = 'all';
let activeCategory = null;

// ── CARICAMENTO DATI ──────────────────────────────
async function loadData() {
  const res  = await fetch('data/checklist.json');
  const data = await res.json();
  allItems = data.categories;
  checks   = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  buildNav();
  render();
}

// ── SIDEBAR NAV ───────────────────────────────────
function buildNav() {
  const ul = document.getElementById('category-nav');
  ul.innerHTML = '';

  // Voce "Tutti"
  const liAll = document.createElement('li');
  liAll.innerHTML = `<a href="#" data-cat="all" class="${activeCategory === null ? 'active' : ''}">
    <span>Tutte le categorie</span>
    <span class="nav-count">${totalItems()}</span>
  </a>`;
  liAll.querySelector('a').addEventListener('click', e => { e.preventDefault(); setCategory(null); });
  ul.appendChild(liAll);

  allItems.forEach(cat => {
    const li = document.createElement('li');
    const done = cat.items.filter(i => checks[i.id]).length;
    li.innerHTML = `<a href="#cat-${cat.id}" data-cat="${cat.id}" class="${activeCategory === cat.id ? 'active' : ''}">
      <span>${cat.name}</span>
      <span class="nav-count">${done}/${cat.items.length}</span>
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
  const content  = document.getElementById('content');
  const query    = document.getElementById('search-input').value.toLowerCase().trim();
  content.innerHTML = '';

  let totalShown   = 0;
  let totalChecked = 0;

  const categories = activeCategory
    ? allItems.filter(c => c.id === activeCategory)
    : allItems;

  categories.forEach(cat => {
    let items = cat.items;

    // Filtro severità
    if (activeFilter !== 'all') items = items.filter(i => i.severity === activeFilter);

    // Filtro ricerca
    if (query) items = items.filter(i =>
      i.title.toLowerCase().includes(query) ||
      (i.description || '').toLowerCase().includes(query)
    );

    if (items.length === 0) return;

    totalShown   += items.length;
    totalChecked += items.filter(i => checks[i.id]).length;

    const section = document.createElement('section');
    section.className = 'section';
    section.id = 'cat-' + cat.id;

    const doneInCat = items.filter(i => checks[i.id]).length;
    section.innerHTML = `
      <div class="section-header">
        <h2 class="section-title">${cat.name}</h2>
        <span class="section-count">${doneInCat}/${items.length} completati</span>
      </div>
      <div class="checklist" id="list-${cat.id}"></div>
    `;

    const list = section.querySelector('.checklist');
    items.forEach(item => {
      list.appendChild(buildItem(item));
    });

    content.appendChild(section);
  });

  if (content.innerHTML === '') {
    content.innerHTML = `<div class="empty-state"><p>Nessun controllo trovato.</p></div>`;
  }

  updateProgress(totalChecked, totalShown);
}

// ── ITEM ─────────────────────────────────────────
function buildItem(item) {
  const div = document.createElement('div');
  div.className = 'check-item' + (checks[item.id] ? ' done' : '');
  div.dataset.id = item.id;

  const hasDesc = item.description && item.description.trim();

  div.innerHTML = `
    <input type="checkbox" ${checks[item.id] ? 'checked' : ''} />
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

  const cb  = div.querySelector('input[type="checkbox"]');
  const btn = div.querySelector('.item-expand-btn');

  cb.addEventListener('change', e => {
    e.stopPropagation();
    checks[item.id] = cb.checked;
    save();
    div.classList.toggle('done', cb.checked);
    buildNav();
    updateProgressFromDOM();
  });

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

// ── PROGRESS ──────────────────────────────────────
function updateProgress(checked, total) {
  const label = document.getElementById('progress-label');
  const fill  = document.getElementById('progress-fill');
  label.textContent = `${checked} / ${total}`;
  fill.style.width  = total > 0 ? `${Math.round(checked / total * 100)}%` : '0%';
}

function updateProgressFromDOM() {
  const items   = document.querySelectorAll('.check-item');
  const checked = document.querySelectorAll('.check-item.done');
  updateProgress(checked.length, items.length);
}

// ── SALVATAGGIO ───────────────────────────────────
function save() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(checks));
}

// ── RESET ─────────────────────────────────────────
document.getElementById('btn-reset').addEventListener('click', () => {
  if (!confirm('Azzerare tutte le spunte?')) return;
  checks = {};
  save();
  buildNav();
  render();
});

// ── EXPORT ────────────────────────────────────────
document.getElementById('btn-export').addEventListener('click', () => {
  let md = '# AD Hardening — Checklist\n\n';
  allItems.forEach(cat => {
    md += `## ${cat.name}\n\n`;
    cat.items.forEach(item => {
      const tick = checks[item.id] ? '[x]' : '[ ]';
      md += `- ${tick} **${item.title}** *(${labelSeverity(item.severity)})*\n`;
      if (item.ref) md += `  > Ref: ${item.ref}\n`;
    });
    md += '\n';
  });

  const blob = new Blob([md], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ad-hardening-checklist.md';
  a.click();
});

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
