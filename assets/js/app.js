/* ═══════════════════════════════════════════════════════════
   AD Hardening — TheUnchecked  |  Cyber HUD  |  app.js
   ═══════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ── DOM refs ── */
  const sidebarNav    = document.getElementById('sidebar-nav');
  const checklistEl   = document.getElementById('checklist');
  const searchInput   = document.getElementById('search-input');
  const severityPills = document.querySelectorAll('.pill[data-severity]');
  const sidebar       = document.getElementById('sidebar');
  const menuBtn       = document.getElementById('btn-menu');

  let DATA = null; // loaded checklist

  /* ══════════════ LOAD DATA ══════════════ */
  fetch('data/checklist.json')
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(d => { DATA = d; init(); })
    .catch(e => {
      checklistEl.innerHTML =
        '<p style="color:var(--critical)">Errore nel caricamento di checklist.json: ' + e.message + '</p>';
    });

  /* ══════════════ INIT ══════════════ */
  function init () {
    renderSidebar();
    renderChecklist();
    bindFilters();
    bindMenu();
    observeSections();
  }

  /* ══════════════ SIDEBAR ══════════════ */
  function renderSidebar () {
    sidebarNav.innerHTML = '';
    DATA.categories.forEach((cat, i) => {
      const num = String(i + 1).padStart(2, '0');
      const count = cat.items ? cat.items.length : 0;
      const a = document.createElement('a');
      a.className = 'sidebar__link';
      a.href = '#cat-' + cat.id;
      a.dataset.cat = cat.id;
      a.innerHTML =
        '<span class="sidebar__num">' + num + '</span>' +
        '<span>' + cat.name + '</span>' +
        '<span class="sidebar__badge">' + count + '</span>';
      a.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.getElementById('cat-' + cat.id);
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        // close mobile sidebar
        sidebar.classList.remove('open');
      });
      sidebarNav.appendChild(a);
    });
  }

  /* ══════════════ CHECKLIST ══════════════ */
  function renderChecklist () {
    const activeSeverities = getActiveSeverities();
    const query = searchInput.value.trim().toLowerCase();

    checklistEl.innerHTML = '';

    DATA.categories.forEach(cat => {
      const items = (cat.items || []).filter(item => {
        if (!activeSeverities.includes(item.severity)) return false;
        if (query) {
          const haystack = (item.title + ' ' + item.description + ' ' + (item.tags || []).join(' ')).toLowerCase();
          if (!haystack.includes(query)) return false;
        }
        return true;
      });

      // always show section anchor (for sidebar scroll), hide if empty
      const section = document.createElement('section');
      section.className = 'cat-section';
      section.id = 'cat-' + cat.id;

      if (items.length === 0) {
        section.style.display = 'none';
        checklistEl.appendChild(section);
        return;
      }

      const h2 = document.createElement('h2');
      h2.className = 'cat-section__title';
      h2.textContent = cat.name;
      section.appendChild(h2);

      items.forEach(item => section.appendChild(buildCard(item)));
      checklistEl.appendChild(section);
    });

    // update sidebar badges with visible counts
    DATA.categories.forEach(cat => {
      const badge = sidebarNav.querySelector('[data-cat="' + cat.id + '"] .sidebar__badge');
      if (!badge) return;
      const sec = document.getElementById('cat-' + cat.id);
      const count = sec ? sec.querySelectorAll('.card').length : 0;
      badge.textContent = count;
    });
  }

  /* ══════════════ BUILD CARD ══════════════ */
  function buildCard (item) {
    const card = document.createElement('div');
    card.className = 'card';
    card.dataset.severity = item.severity;

    // ── header ──
    let html = '<div class="card__header">';
    html += '<span class="card__id">' + esc(item.id) + '</span>';
    html += '<span class="card__title">' + esc(item.title) + '</span>';
    html += '<span class="badge badge--' + item.severity + '">' + esc(item.severity) + '</span>';
    html += '</div>';

    if (item.ref) html += '<div class="card__ref">' + esc(item.ref) + '</div>';
    if (item.description) html += '<div class="card__desc">' + esc(item.description) + '</div>';

    // tags
    if (item.tags && item.tags.length) {
      html += '<div class="card__tags">';
      item.tags.forEach(t => { html += '<span class="tag">' + esc(t) + '</span>'; });
      html += '</div>';
    }

    // quick command
    if (item.command_quick) {
      html += codeBlock('Comando Rapido', item.command_quick, true);
    }

    // action buttons
    html += '<div class="card__actions">';
    if (item.guidance) html += '<button class="btn btn--accent js-toggle-guidance">⚡ Elite Guidance</button>';
    if (item.command_full) html += '<button class="btn js-toggle-full">Comando Completo</button>';
    html += '</div>';

    // full command (hidden)
    if (item.command_full) {
      html += '<div class="full-cmd" style="display:none">';
      html += codeBlock('Comando Completo', item.command_full, false);
      html += '</div>';
    }

    // guidance panel (hidden)
    if (item.guidance) {
      html += buildGuidance(item.guidance);
    }

    card.innerHTML = html;

    // ── wire events ──
    const guidanceBtn = card.querySelector('.js-toggle-guidance');
    const guidancePanel = card.querySelector('.guidance');
    if (guidanceBtn && guidancePanel) {
      guidanceBtn.addEventListener('click', () => guidancePanel.classList.toggle('open'));
    }

    const fullBtn = card.querySelector('.js-toggle-full');
    const fullDiv = card.querySelector('.full-cmd');
    if (fullBtn && fullDiv) {
      fullBtn.addEventListener('click', () => {
        const open = fullDiv.style.display !== 'none';
        fullDiv.style.display = open ? 'none' : 'block';
        fullBtn.textContent = open ? 'Comando Completo' : 'Nascondi Completo';
      });
    }

    // copy buttons
    card.querySelectorAll('.btn-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const code = btn.closest('.code-wrap').querySelector('.code-content').textContent;
        navigator.clipboard.writeText(code).then(() => {
          btn.textContent = '✓ Copiato';
          btn.classList.add('copied');
          setTimeout(() => { btn.textContent = 'Copia'; btn.classList.remove('copied'); }, 1500);
        });
      });
    });

    // guidance tabs
    card.querySelectorAll('.guidance__tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const panel = tab.closest('.guidance');
        panel.querySelectorAll('.guidance__tab').forEach(t => t.classList.remove('active'));
        panel.querySelectorAll('.guidance__panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        panel.querySelector('.guidance__panel[data-panel="' + tab.dataset.tab + '"]').classList.add('active');
      });
    });

    return card;
  }

  /* ══════════════ CODE BLOCK HTML ══════════════ */
  function codeBlock (label, code, isQuick) {
    const lines = code.split('\n');
    let html = '<div class="code-wrap' + (isQuick ? ' code-quick' : '') + '">';
    html += '<div class="code-header"><span class="code-header__label">' + label + '</span>';
    html += '<button class="btn-copy">Copia</button></div>';
    html += '<div class="code-body">';
    if (!isQuick) {
      html += '<div class="code-lines">';
      lines.forEach((_, i) => { html += '<span>' + (i + 1) + '</span>'; });
      html += '</div>';
    }
    html += '<div class="code-content">' + esc(code) + '</div>';
    html += '</div></div>';
    return html;
  }

  /* ══════════════ GUIDANCE PANEL HTML ══════════════ */
  function buildGuidance (g) {
    const tabs = [
      { key: 'exposure',       label: 'Impatto' },
      { key: 'execution',      label: 'Esecuzione' },
      { key: 'verification',   label: 'Verifica' },
      { key: 'considerations', label: 'Considerazioni' },
      { key: 'signals',        label: 'Segnali' },
      { key: 'related',        label: 'Correlati' }
    ];

    // keep only tabs that have content
    const available = tabs.filter(t => {
      const v = g[t.key];
      return v && (Array.isArray(v) ? v.length > 0 : String(v).trim() !== '');
    });
    if (available.length === 0) return '';

    let html = '<div class="guidance">';
    html += '<div class="guidance__tabs">';
    available.forEach((t, i) => {
      html += '<button class="guidance__tab' + (i === 0 ? ' active' : '') + '" data-tab="' + t.key + '">' + t.label + '</button>';
    });
    html += '</div><div class="guidance__panels">';

    available.forEach((t, i) => {
      html += '<div class="guidance__panel' + (i === 0 ? ' active' : '') + '" data-panel="' + t.key + '">';
      const val = g[t.key];
      if (Array.isArray(val)) {
        html += '<ul>';
        val.forEach(v => { html += '<li>' + esc(String(v)) + '</li>'; });
        html += '</ul>';
      } else {
        // if it looks like code (starts with # or contains \n with commands)
        if (String(val).includes('\n') || String(val).trim().startsWith('#')) {
          html += '<div class="code-wrap code-quick" style="margin:0"><div class="code-header"><span class="code-header__label">' + t.label + '</span><button class="btn-copy">Copia</button></div><div class="code-body"><div class="code-content">' + esc(String(val)) + '</div></div></div>';
        } else {
          html += '<p>' + esc(String(val)) + '</p>';
        }
      }
      html += '</div>';
    });
    html += '</div></div>';
    return html;
  }

  /* ══════════════ FILTERS ══════════════ */
  function bindFilters () {
    severityPills.forEach(pill => {
      pill.addEventListener('click', () => {
        pill.classList.toggle('active');
        renderChecklist();
      });
    });
    searchInput.addEventListener('input', debounce(renderChecklist, 200));
  }

  function getActiveSeverities () {
    return Array.from(severityPills)
      .filter(p => p.classList.contains('active'))
      .map(p => p.dataset.severity);
  }

  /* ══════════════ MOBILE MENU ══════════════ */
  function bindMenu () {
    menuBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
    // close when clicking outside
    document.addEventListener('click', e => {
      if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== menuBtn) {
        sidebar.classList.remove('open');
      }
    });
  }

  /* ══════════════ INTERSECTION OBSERVER (active sidebar link) ══════════════ */
  function observeSections () {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const id = entry.target.id.replace('cat-', '');
          sidebarNav.querySelectorAll('.sidebar__link').forEach(l => l.classList.remove('active'));
          const active = sidebarNav.querySelector('[data-cat="' + id + '"]');
          if (active) active.classList.add('active');
        }
      });
    }, { rootMargin: '-20% 0px -60% 0px' });

    // observe after first render
    setTimeout(() => {
      document.querySelectorAll('.cat-section').forEach(s => observer.observe(s));
    }, 100);
  }

  /* ══════════════ UTILS ══════════════ */
  function esc (s) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function debounce (fn, ms) {
    let t;
    return function () { clearTimeout(t); t = setTimeout(fn, ms); };
  }

})();
