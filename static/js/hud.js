/* =========================================================================
   AegisHUD — Advanced UI behaviors
   - Particle background canvas
   - Stat counter animation
   - Posture ring stroke animation
   - Toast stack + flash bridge
   - Detail drawer (escalation / over-priv / conflict)
   - Command palette (Ctrl/Cmd + K)
   - Filter chips (severity + type)
   - MITRE heatmap click → drawer
   - Search wirings (table + cards)
   - Upload scan animation
   - PDF generation (themed, dark-mode safe)
   ========================================================================= */
window.AegisHUD = (function () {
  'use strict';

  // -----------------------------------------------------------------------
  // Utility: safely parse a JSON <script> element by id.
  // Returns null if missing or malformed.
  function safeJSON(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try { return JSON.parse(el.textContent.trim()); } catch (e) { return null; }
  }

  function escapeHTML(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // -----------------------------------------------------------------------
  // Search wirings
  function wireSearch(inputId, tableId) {
    var input = document.getElementById(inputId);
    var table = document.getElementById(tableId);
    if (!input || !table) return;
    input.addEventListener('input', function () {
      var q = (this.value || '').trim().toLowerCase();
      var rows = table.querySelectorAll('tbody tr');
      rows.forEach(function (r) {
        r.style.display = r.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
      });
    });
  }

  function wireSearchCards(inputId, containerId) {
    var input = document.getElementById(inputId);
    var box = document.getElementById(containerId);
    if (!input || !box) return;
    input.addEventListener('input', function () {
      var q = (this.value || '').trim().toLowerCase();
      // direct children only — avoids matching nested filterables
      var children = Array.prototype.filter.call(box.children, function (c) {
        return c.nodeType === 1;
      });
      children.forEach(function (c) {
        c.style.display = c.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
      });
    });
  }

  // -----------------------------------------------------------------------
  // Upload form scanning shimmer
  function wireUploadScan(formId, hudId) {
    var form = document.getElementById(formId);
    var hud  = document.getElementById(hudId);
    if (!form) return;
    // Auto-submit when file is picked
    var fileInput = form.querySelector('input[type="file"]');
    if (fileInput) {
      fileInput.addEventListener('change', function () {
        if (!this.files || !this.files.length) return;
        var f = this.files[0];
        // Client-side guard: extension + size
        if (!/\.json$/i.test(f.name)) {
          toast('File must have a .json extension', 'critical');
          this.value = '';
          return;
        }
        if (f.size > 2 * 1024 * 1024) {
          toast('File exceeds 2 MB upload cap', 'critical');
          this.value = '';
          return;
        }
        toast('Uploading ' + f.name + '...', 'info', { duration: 3000 });
        if (hud) hud.classList.add('scanning');
        form.submit();
      });
    }
    form.addEventListener('submit', function () {
      if (hud) hud.classList.add('scanning');
    });
  }

  // -----------------------------------------------------------------------
  // Stat number count-up
  function animateStatCounts() {
    var nodes = document.querySelectorAll('.aegis-stat-value[data-count]');
    nodes.forEach(function (el) {
      var target = parseInt(el.getAttribute('data-count'), 10) || 0;
      if (target === 0) { el.textContent = '0'; return; }
      var startedAt = null;
      var duration = 700; // ms
      function step(ts) {
        if (!startedAt) startedAt = ts;
        var t = Math.min(1, (ts - startedAt) / duration);
        var eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
        el.textContent = Math.round(target * eased).toString();
        if (t < 1) requestAnimationFrame(step);
        else el.textContent = target.toString();
      }
      requestAnimationFrame(step);
    });
  }

  // -----------------------------------------------------------------------
  // Posture ring stroke fill
  function installPostureRing() {
    var ring = document.querySelector('.aegis-posture-ring');
    if (!ring) return;
    var prog = document.getElementById('postureProgress');
    if (!prog) return;
    var score = parseFloat(ring.getAttribute('data-score')) || 0;
    var radius = 58;
    var circumference = 2 * Math.PI * radius; // ≈ 364.42
    prog.style.strokeDasharray = circumference.toFixed(2);
    prog.style.strokeDashoffset = circumference.toFixed(2);
    // ease-in-out fill on next tick
    setTimeout(function () {
      prog.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(0.22, 1, 0.36, 1)';
      var offset = circumference - (Math.max(0, Math.min(100, score)) / 100) * circumference;
      prog.style.strokeDashoffset = offset.toFixed(2);
    }, 80);
  }

  // -----------------------------------------------------------------------
  // Particle field (lightweight, opt-out via reduced-motion)
  function startParticles(canvasId) {
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext('2d');
    var particles = [];
    var count = 0;
    var dpr = window.devicePixelRatio || 1;
    var rafId = null;

    function resize() {
      var w = window.innerWidth;
      var h = window.innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // Density: cap for perf
      count = Math.min(80, Math.round((w * h) / 28000));
      particles = [];
      for (var i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.25,
          vy: (Math.random() - 0.5) * 0.25,
          r: Math.random() * 1.4 + 0.4,
          a: Math.random() * 0.5 + 0.2
        });
      }
    }

    function tick() {
      var w = window.innerWidth;
      var h = window.innerHeight;
      ctx.clearRect(0, 0, w, h);

      // connecting lines
      for (var i = 0; i < particles.length; i++) {
        for (var j = i + 1; j < particles.length; j++) {
          var dx = particles[i].x - particles[j].x;
          var dy = particles[i].y - particles[j].y;
          var d = Math.sqrt(dx * dx + dy * dy);
          if (d < 110) {
            ctx.strokeStyle = 'rgba(0, 245, 255,' + (0.10 * (1 - d / 110)).toFixed(3) + ')';
            ctx.lineWidth = 0.6;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // dots
      for (var k = 0; k < particles.length; k++) {
        var p = particles[k];
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        ctx.fillStyle = 'rgba(103, 232, 249,' + p.a.toFixed(2) + ')';
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
      rafId = requestAnimationFrame(tick);
    }

    function stop() { if (rafId) cancelAnimationFrame(rafId); }

    resize();
    window.addEventListener('resize', function () { stop(); resize(); tick(); });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop(); else { stop(); tick(); }
    });
    tick();
  }

  // -----------------------------------------------------------------------
  // Toast system
  function toast(message, kind, opts) {
    kind = kind || 'info';
    opts = opts || {};
    var stack = document.getElementById('aegisToasts');
    if (!stack) return;

    var iconPath = {
      info:     'M12 8v5M12 16h.01M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z',
      success:  'M5 12l5 5L20 7',
      warning:  'M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
      critical: 'M12 9v4M12 17h.01M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z'
    }[kind] || 'M12 8v5M12 16h.01M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z';

    var el = document.createElement('div');
    el.className = 'aegis-toast aegis-toast-' + kind;
    el.setAttribute('role', kind === 'critical' || kind === 'warning' ? 'alert' : 'status');
    el.innerHTML =
      '<svg viewBox="0 0 24 24" class="aegis-toast-icon fill-none stroke-current stroke-2">' +
      '<path d="' + iconPath + '" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '<div class="aegis-toast-body">' + escapeHTML(message) + '</div>' +
      '<button type="button" class="aegis-toast-close" aria-label="Dismiss">×</button>';

    stack.appendChild(el);
    requestAnimationFrame(function () { el.classList.add('is-shown'); });

    var timeout = opts.duration || (kind === 'critical' ? 8000 : 5000);
    var dismiss = function () {
      el.classList.remove('is-shown');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 350);
    };
    el.querySelector('.aegis-toast-close').addEventListener('click', dismiss);
    setTimeout(dismiss, timeout);
  }

  // Convert Flask flash messages into toasts (so server logs get UI presence)
  function flashToToast(sourceId) {
    var src = document.getElementById(sourceId);
    if (!src) return;
    var msgs = src.querySelectorAll('.flash-msg');
    msgs.forEach(function (m) {
      var text = (m.textContent || '').trim();
      if (!text) return;
      var lower = text.toLowerCase();
      var kind = 'info';
      if (lower.indexOf('error') !== -1 || lower.indexOf('invalid') !== -1) kind = 'critical';
      else if (lower.indexOf('reset') !== -1) kind = 'warning';
      else if (lower.indexOf('loaded') !== -1 || lower.indexOf('initialized') !== -1) kind = 'success';
      toast(text, kind);
    });
  }

  // -----------------------------------------------------------------------
  // Detail drawer
  function openDrawer(eyebrow, title, html) {
    var drawer = document.getElementById('aegisDrawer');
    if (!drawer) return;
    document.getElementById('aegisDrawerEyebrow').textContent = eyebrow || '';
    document.getElementById('aegisDrawerTitle').textContent = title || '';
    document.getElementById('aegisDrawerBody').innerHTML = html || '';
    drawer.classList.add('is-open');
    drawer.setAttribute('aria-hidden', 'false');
  }
  function closeDrawer() {
    var drawer = document.getElementById('aegisDrawer');
    if (!drawer) return;
    drawer.classList.remove('is-open');
    drawer.setAttribute('aria-hidden', 'true');
  }

  function installDrawer() {
    var drawer = document.getElementById('aegisDrawer');
    if (!drawer) return;
    drawer.querySelectorAll('[data-drawer-close]').forEach(function (el) {
      el.addEventListener('click', closeDrawer);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && drawer.classList.contains('is-open')) closeDrawer();
    });
  }

  // Hooks for finding rows / cards → drawer with full detail
  function installFindingDrawer() {
    var findings   = safeJSON('findingsPayload') || [];
    var overpriv   = safeJSON('overprivPayload') || [];
    var conflicts  = safeJSON('conflictsPayload') || [];

    document.querySelectorAll('.aegis-finding-row, .aegis-finding-card').forEach(function (el) {
      el.addEventListener('click', function () {
        var type = el.getAttribute('data-finding-type');
        var idx  = parseInt(el.getAttribute('data-finding-index'), 10);
        if (type === 'escalation' && findings[idx]) {
          openDrawer('module 03 · escalation', findings[idx].principal,
                     renderEscalation(findings[idx]));
        } else if (type === 'overprivileged' && overpriv[idx]) {
          openDrawer('module 05 · over-privileged', overpriv[idx].principal,
                     renderOverpriv(overpriv[idx]));
        } else if (type === 'conflict' && conflicts[idx]) {
          openDrawer('module 06 · separation of duties', conflicts[idx].principal,
                     renderConflict(conflicts[idx]));
        }
      });
    });
  }

  function renderMitre(list) {
    if (!list || !list.length) return '<div style="color:rgba(207,250,254,0.5);font-size:11px;">No mapped techniques.</div>';
    return '<ul>' + list.map(function (m) {
      return '<li>' +
        '<div style="font-family:JetBrains Mono,monospace;font-size:11px;color:#22D3EE;font-weight:700;">' +
          escapeHTML(m.id) + ' · ' + escapeHTML(m.tactic || '') +
        '</div>' +
        '<div style="font-weight:600;color:#cffafe;margin-top:2px;">' +
          escapeHTML(m.technique) +
        '</div>' +
        '<div style="font-size:11px;color:rgba(207,250,254,0.65);margin-top:2px;">' +
          escapeHTML(m.note || '') +
        '</div>' +
        '<code style="margin-top:4px;">' + escapeHTML(m.permission) + '</code>' +
      '</li>';
    }).join('') + '</ul>';
  }

  function renderEscalation(f) {
    var sevColor = { Critical: '#FF355E', High: '#FFB020', Medium: '#FACC15', Low: '#22D3EE' }[f.severity] || '#22D3EE';
    return [
      '<h4>Severity</h4>',
      '<div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid ' + sevColor + ';border-radius:999px;color:' + sevColor + ';font-family:JetBrains Mono,monospace;font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;">' + escapeHTML(f.severity) + ' · ' + escapeHTML(String(f.steps || 0)) + ' steps</div>',
      '<h4>Escalation Chain</h4>',
      '<pre>' + escapeHTML(f.chain || '') + '</pre>',
      '<h4>Root Cause</h4>',
      '<div>' + escapeHTML(f.root_cause || '') + '</div>',
      '<h4>Recommended Remediation</h4>',
      '<div>' + escapeHTML(f.remediation_summary || '') + '</div>',
      f.patch_steps && f.patch_steps.length ? '<h4>Patch Steps</h4><ol style="padding-left:18px;margin:0;">' + f.patch_steps.map(function (s) { return '<li style="margin-bottom:6px;">' + escapeHTML(s) + '</li>'; }).join('') + '</ol>' : '',
      f.strategy && f.strategy.length ? '<h4>Strategy</h4><ul>' + f.strategy.map(function (s) { return '<li>' + escapeHTML(s) + '</li>'; }).join('') + '</ul>' : '',
      '<h4>MITRE ATT&amp;CK Context</h4>',
      renderMitre(f.mitre)
    ].join('');
  }

  function renderOverpriv(u) {
    return [
      '<h4>Risk Reasons</h4>',
      '<ul>' + (u.reasons || []).map(function (r) { return '<li>' + escapeHTML(r) + '</li>'; }).join('') + '</ul>',
      '<h4>Permission Sample</h4>',
      '<pre>' + escapeHTML(u.permission_sample || '(none)') + '</pre>',
      '<h4>Suggested Remediation</h4>',
      '<ul>',
        '<li>Revoke wildcard or admin-equivalent permissions; replace with scoped actions.</li>',
        '<li>Enforce explicit Resource ARNs on every Allow statement.</li>',
        '<li>Move privileged actions behind Just-In-Time (JIT) elevation.</li>',
        '<li>Enable AWS Access Analyzer to surface unused permissions.</li>',
      '</ul>',
      '<h4>MITRE ATT&amp;CK Context</h4>',
      renderMitre(u.mitre)
    ].join('');
  }

  function renderConflict(c) {
    return [
      '<h4>Conflict Pairs</h4>',
      '<ul>' + (c.conflicts || []).map(function (item) {
        return '<li>' +
          '<div style="font-weight:600;color:#FFB020;">' + escapeHTML(item.label) + '</div>' +
          '<code>' + escapeHTML((item.pair || []).join('  +  ')) + '</code>' +
          '</li>';
      }).join('') + '</ul>',
      '<h4>Why It Matters</h4>',
      '<div>Holding both write and read/list duties on the same domain enables a principal to alter privilege configuration <em>and</em> hide the change in audit telemetry. Industry frameworks (SOX, ISO 27001 A.5.3, NIST AC-5) require these duties be segregated.</div>',
      '<h4>Remediation</h4>',
      '<ul>',
        '<li>Split write and audit/read responsibilities across distinct principals.</li>',
        '<li>Introduce an approval boundary (SCP / Permission Boundary) for privileged writes.</li>',
        '<li>Forward CloudTrail events for these APIs to an immutable audit account.</li>',
      '</ul>'
    ].join('');
  }

  // -----------------------------------------------------------------------
  // MITRE Heatmap → drawer
  function installHeatmapClicks() {
    var cells = document.querySelectorAll('.aegis-heat-cell');
    cells.forEach(function (c) {
      c.addEventListener('click', function () {
        var id = c.getAttribute('data-tech-id') || '?';
        var name = c.getAttribute('data-tech-name') || 'Unknown';
        var tactic = c.getAttribute('data-tactic') || '';
        var tacticId = c.getAttribute('data-tactic-id') || '';
        var principalsStr = c.getAttribute('data-principals') || '';
        var principals = principalsStr ? principalsStr.split(', ') : [];
        var html =
          '<h4>Tactic</h4>' +
          '<code>' + escapeHTML(tacticId) + '</code> ' + escapeHTML(tactic) +
          '<h4>Affected Principals (' + principals.length + ')</h4>' +
          (principals.length
            ? '<ul>' + principals.map(function (p) { return '<li><code>' + escapeHTML(p) + '</code></li>'; }).join('') + '</ul>'
            : '<div style="color:rgba(207,250,254,0.5);">None.</div>') +
          '<h4>Reference</h4>' +
          '<div>See the full ATT&amp;CK technique writeup for detection guidance and adversary tradecraft examples.</div>';
        openDrawer('module 02 · attack technique', id + ' — ' + name, html);
      });
    });
  }

  // -----------------------------------------------------------------------
  // Filter chip bar — severity + type
  function installFilterBar() {
    var bar = document.getElementById('filterBar');
    if (!bar) return;
    var state = { severity: 'all', type: 'all' };

    function applyFilters() {
      var rows = document.querySelectorAll('.aegis-finding-row, .aegis-finding-card');
      rows.forEach(function (r) {
        var rType = r.getAttribute('data-finding-type');
        var rSev  = r.getAttribute('data-finding-severity');
        var match =
          (state.type === 'all' || state.type === rType) &&
          (state.severity === 'all' || state.severity === rSev);
        if (match) r.classList.remove('aegis-filter-hidden');
        else       r.classList.add('aegis-filter-hidden');
      });
    }

    bar.querySelectorAll('[data-filter]').forEach(function (chip) {
      chip.addEventListener('click', function () {
        bar.querySelectorAll('[data-filter]').forEach(function (c) { c.classList.remove('is-active'); });
        chip.classList.add('is-active');
        state.severity = chip.getAttribute('data-filter');
        applyFilters();
      });
    });
    bar.querySelectorAll('[data-type]').forEach(function (chip) {
      chip.addEventListener('click', function () {
        bar.querySelectorAll('[data-type]').forEach(function (c) { c.classList.remove('is-active'); });
        chip.classList.add('is-active');
        state.type = chip.getAttribute('data-type');
        applyFilters();
      });
    });
  }

  // -----------------------------------------------------------------------
  // Command Palette (Ctrl/Cmd + K)
  var paletteState = { items: [], filtered: [], cursor: 0, open: false };

  function buildPaletteItems() {
    var items = [
      { title: 'Go to Dashboard',         sub: 'Home / HUD',        href: '/' },
      { title: 'Open Graph View',         sub: 'Trust relationships', href: '/graph' },
      { title: 'Open Dynamic Playbook',   sub: 'Per-finding remediation', href: '/playbook' },
      { title: 'Open Intel Retrieval Lab',sub: 'AWS / Azure / GCP exports', href: '/intel' },
      { title: 'Export findings JSON',    sub: 'Download intel', href: '/api/export/json' },
      { title: 'Export findings CSV',     sub: 'Spreadsheet-ready', href: '/api/export/csv' },
    ];
    // findings as searchable entries
    var findings = safeJSON('findingsPayload') || [];
    findings.forEach(function (f, i) {
      items.push({
        title: 'Escalation: ' + f.principal,
        sub: (f.severity || '') + ' · ' + (f.chain || ''),
        action: function () { openFindingByIndex('escalation', i); }
      });
    });
    var overpriv = safeJSON('overprivPayload') || [];
    overpriv.forEach(function (u, i) {
      items.push({
        title: 'Over-Privileged: ' + u.principal,
        sub: 'High Risk · ' + ((u.reasons || [])[0] || ''),
        action: function () { openFindingByIndex('overprivileged', i); }
      });
    });
    var conflicts = safeJSON('conflictsPayload') || [];
    conflicts.forEach(function (c, i) {
      items.push({
        title: 'SoD Conflict: ' + c.principal,
        sub: 'Medium · ' + ((c.conflicts || []).map(function (x) { return x.label; }).join(' / ')),
        action: function () { openFindingByIndex('conflict', i); }
      });
    });
    return items;
  }

  function openFindingByIndex(type, idx) {
    var sel = '[data-finding-type="' + type + '"][data-finding-index="' + idx + '"]';
    var el = document.querySelector(sel);
    if (el) el.click();
  }

  function renderPalette() {
    var list = document.getElementById('aegisPaletteList');
    if (!list) return;
    list.innerHTML = '';
    paletteState.filtered.forEach(function (item, i) {
      var li = document.createElement('li');
      li.className = 'aegis-palette-item' + (i === paletteState.cursor ? ' is-active' : '');
      li.setAttribute('role', 'option');
      li.innerHTML =
        '<span class="pi-icon">' +
          '<svg viewBox="0 0 24 24" class="h-3.5 w-3.5 fill-none stroke-current stroke-2">' +
          '<path d="M9 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
        '</span>' +
        '<div class="pi-body">' +
          '<div class="pi-title">' + escapeHTML(item.title) + '</div>' +
          '<div class="pi-sub">' + escapeHTML(item.sub || '') + '</div>' +
        '</div>';
      li.addEventListener('click', function () { execPaletteItem(item); });
      list.appendChild(li);
    });
    if (paletteState.filtered.length === 0) {
      list.innerHTML = '<li class="aegis-palette-item" style="opacity:0.6;cursor:default;">' +
                       '<div class="pi-body"><div class="pi-title">No matches.</div>' +
                       '<div class="pi-sub">try a different keyword</div></div></li>';
    }
  }

  function filterPalette(q) {
    q = (q || '').toLowerCase().trim();
    if (!q) {
      paletteState.filtered = paletteState.items.slice(0, 10);
    } else {
      paletteState.filtered = paletteState.items.filter(function (it) {
        return (it.title + ' ' + (it.sub || '')).toLowerCase().indexOf(q) !== -1;
      });
    }
    paletteState.cursor = 0;
    renderPalette();
  }

  function execPaletteItem(item) {
    closePalette();
    if (item.href) {
      window.location.href = item.href;
    } else if (typeof item.action === 'function') {
      // small delay so palette finishes its close transition first
      setTimeout(item.action, 60);
    }
  }

  function openPalette() {
    var p = document.getElementById('aegisPalette');
    if (!p) return;
    paletteState.open = true;
    paletteState.items = buildPaletteItems();
    paletteState.filtered = paletteState.items.slice(0, 10);
    paletteState.cursor = 0;
    renderPalette();
    p.classList.add('is-open');
    p.setAttribute('aria-hidden', 'false');
    var input = document.getElementById('aegisPaletteInput');
    if (input) { input.value = ''; setTimeout(function () { input.focus(); }, 60); }
  }

  function closePalette() {
    var p = document.getElementById('aegisPalette');
    if (!p) return;
    paletteState.open = false;
    p.classList.remove('is-open');
    p.setAttribute('aria-hidden', 'true');
  }

  function installCommandPalette() {
    var p = document.getElementById('aegisPalette');
    if (!p) return;
    var btn = document.getElementById('aegisCmdKBtn');
    var input = document.getElementById('aegisPaletteInput');

    if (btn) btn.addEventListener('click', openPalette);
    p.querySelectorAll('[data-palette-close]').forEach(function (el) {
      el.addEventListener('click', closePalette);
    });

    document.addEventListener('keydown', function (e) {
      var isMeta = e.ctrlKey || e.metaKey;
      if (isMeta && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        if (paletteState.open) closePalette(); else openPalette();
        return;
      }
      if (!paletteState.open) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (paletteState.filtered.length === 0) return;
        paletteState.cursor = (paletteState.cursor + 1) % paletteState.filtered.length;
        renderPalette();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (paletteState.filtered.length === 0) return;
        paletteState.cursor = (paletteState.cursor - 1 + paletteState.filtered.length) % paletteState.filtered.length;
        renderPalette();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        var it = paletteState.filtered[paletteState.cursor];
        if (it) execPaletteItem(it);
      }
    });

    if (input) input.addEventListener('input', function () { filterPalette(this.value); });
  }

  // -----------------------------------------------------------------------
  // PDF generation — themed, color-safe for html2canvas
  function generatePDF(elementId, filename) {
    var element = document.getElementById(elementId);
    if (!element || typeof html2pdf === 'undefined') {
      toast('PDF library not available — please retry.', 'warning');
      return;
    }
    document.body.classList.add('aegis-pdf-mode');
    toast('Generating intelligence report...', 'info');
    var opt = {
      margin:       0.4,
      filename:     filename || 'Aegis-IAM-Intelligence-Report.pdf',
      image:        { type: 'jpeg', quality: 0.95 },
      html2canvas:  { scale: 2, backgroundColor: '#05070d', logging: false, useCORS: true },
      jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
    };
    html2pdf().set(opt).from(element).save()
      .then(function () {
        document.body.classList.remove('aegis-pdf-mode');
        toast('Report exported.', 'success');
      })
      .catch(function (err) {
        document.body.classList.remove('aegis-pdf-mode');
        toast('PDF export failed: ' + (err && err.message ? err.message : 'unknown'), 'critical');
      });
  }

  // -----------------------------------------------------------------------
  // Public API
  return {
    wireSearch: wireSearch,
    wireSearchCards: wireSearchCards,
    wireUploadScan: wireUploadScan,
    animateStatCounts: animateStatCounts,
    installPostureRing: installPostureRing,
    startParticles: startParticles,
    toast: toast,
    flashToToast: flashToToast,
    openDrawer: openDrawer,
    closeDrawer: closeDrawer,
    installDrawer: installDrawer,
    installFindingDrawer: installFindingDrawer,
    installHeatmapClicks: installHeatmapClicks,
    installFilterBar: installFilterBar,
    installCommandPalette: installCommandPalette,
    generatePDF: generatePDF
  };
})();
