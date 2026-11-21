/* Доступность без переписывания разметки: имена полей, окна как диалоги с фокусом, значки без озвучивания.
   Работает поверх готовой разметки и динамически созданных полей (наблюдатель за DOM). */
(function () {
  var uid = 0;
  function nid(p) { return p + (++uid); }
  var FOCUSABLE = 'a[href],button:not([disabled]),input:not([type=hidden]):not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
  function visible(el) { return el.offsetParent !== null || el === document.activeElement; }
  function focusables(root) { return Array.prototype.filter.call(root.querySelectorAll(FOCUSABLE), visible); }

  /* ---------- Окна ---------- */
  function setupModal(ov) {
    if (ov.__a11y) return;
    ov.__a11y = true;
    var card = ov.querySelector('.modal-card') || ov;
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    var h = card.querySelector('h3');
    if (h) { if (!h.id) h.id = nid('mdl-t'); card.setAttribute('aria-labelledby', h.id); }
    var prev = null, open = false;
    new MutationObserver(function () {
      var now = ov.style.display === 'flex';
      if (now && !open) {
        open = true; prev = document.activeElement;
        setTimeout(function () {
          var f = focusables(card);
          var first = f.filter(function (e) { return /^(INPUT|SELECT|TEXTAREA)$/.test(e.tagName); })[0] ||
                      f.filter(function (e) { return !e.classList.contains('modal-x'); })[0] || f[0];
          if (first) first.focus();
        }, 30);
      } else if (!now && open) {
        open = false;
        if (prev && document.contains(prev)) { try { prev.focus(); } catch (e) {} }
      }
    }).observe(ov, {attributes: true, attributeFilter: ['style']});
    ov.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var f = focusables(card);
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && (document.activeElement === first || !card.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }

  /* ---------- Имена полей ---------- */
  function labelFor(el) {
    if (el.id) { var l = document.querySelector('label[for="' + el.id.replace(/"/g, '\\"') + '"]'); if (l) return l; }
    var p = el.previousElementSibling, n = 0;
    while (p && n < 3) { if (p.tagName === 'LABEL' && !p.querySelector('input,select,textarea')) return p; p = p.previousElementSibling; n++; }
    var par = el.parentElement;
    if (par && (par.classList.contains('form-group') || par.classList.contains('copy-row'))) {
      var g = par.parentElement && par.classList.contains('copy-row') ? par.parentElement : par;
      var first = g.querySelector(':scope > label');
      if (first) return first;
    }
    return null;
  }
  function nameControls() {
    document.querySelectorAll('input,select,textarea').forEach(function (el) {
      if (el.type === 'hidden' || el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby') || el.closest('label')) return;
      var l = labelFor(el);
      if (l) { if (!l.id) l.id = nid('lbl-'); el.setAttribute('aria-labelledby', l.id); return; }
      var t = el.getAttribute('placeholder') || el.getAttribute('title');
      if (t) el.setAttribute('aria-label', t);
    });
    // свои выпадающие списки: кнопка берёт имя у подписи исходного select
    document.querySelectorAll('.cs-btn[data-for]').forEach(function (b) {
      if (b.hasAttribute('aria-labelledby') || b.hasAttribute('aria-label')) return;
      var sel = document.getElementById(b.getAttribute('data-for'));
      var l = sel && labelFor(sel);
      if (!l) { var t = sel && (sel.getAttribute('aria-label') || sel.title); if (t) b.setAttribute('aria-label', t); return; }
      if (!l.id) l.id = nid('lbl-');
      if (!b.id) b.id = nid('cs-');
      b.setAttribute('aria-labelledby', l.id + ' ' + b.id);
    });
  }

  /* ---------- Значки ---------- */
  function iconsAndButtons() {
    document.querySelectorAll('svg:not([role]):not([aria-label]):not([aria-hidden])').forEach(function (s) {
      if (s.classList.contains('chart-svg')) return; // график размечается отдельно
      s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
    });
    document.querySelectorAll('button,a[href]').forEach(function (b) {
      if (b.hasAttribute('aria-label') || b.hasAttribute('aria-labelledby')) return;
      if (b.textContent.trim()) return;
      var t = b.getAttribute('title');
      if (t) b.setAttribute('aria-label', t);
    });
  }

  function run() {
    document.querySelectorAll('.modal-overlay').forEach(setupModal);
    nameControls();
    iconsAndButtons();
  }

  var timer = null;
  function later() { clearTimeout(timer); timer = setTimeout(run, 200); }
  run();
  new MutationObserver(later).observe(document.body, {childList: true, subtree: true});
})();
