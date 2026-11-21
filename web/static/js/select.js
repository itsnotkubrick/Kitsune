/* Выпадающие списки в стиле панели: обычный <select> остаётся в странице (значение, события, формы), а вместо него рисуется кнопка и своё меню */
(function () {
  if (window.__kitSelect) return;
  window.__kitSelect = true;

  var valDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  var idxDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');
  var opened = null;

  function chev() {
    return '<svg class="cs-ar" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';
  }

  function closeMenu(focusBtn) {
    if (!opened) return;
    var o = opened; opened = null;
    o.pop.remove();
    o.btn.setAttribute('aria-expanded', 'false');
    if (focusBtn) o.btn.focus();
  }

  function enhance(sel) {
    if (sel.__cs || sel.multiple || sel.size > 1 || sel.hasAttribute('data-native')) return;
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cs-btn ' + sel.className;
    btn.style.cssText = sel.style.cssText;
    btn.setAttribute('aria-haspopup', 'listbox');
    btn.setAttribute('aria-expanded', 'false');
    var id = sel.id; if (id) btn.setAttribute('data-for', id);
    sel.classList.add('cs-native');
    sel.insertAdjacentElement('afterend', btn);

    function sync() {
      var o = sel.options[sel.selectedIndex];
      btn.innerHTML = '<span class="cs-tx"></span>' + chev();
      btn.firstChild.textContent = o ? o.textContent : '';
      btn.disabled = sel.disabled;
    }

    function choose(i) {
      idxDesc.set.call(sel, i);
      sync();
      sel.dispatchEvent(new Event('input', { bubbles: true }));
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function openMenu() {
      closeMenu();
      var pop = document.createElement('div');
      pop.className = 'cs-pop'; pop.setAttribute('role', 'listbox');
      var cur = sel.selectedIndex;
      [].forEach.call(sel.options, function (o, i) {
        if (o.hidden) return;
        var it = document.createElement('button');
        it.type = 'button'; it.className = 'cs-it' + (i === cur ? ' on' : '') + (o.disabled ? ' off' : '');
        it.setAttribute('role', 'option'); it.setAttribute('aria-selected', i === cur ? 'true' : 'false');
        it.dataset.i = i; it.disabled = o.disabled;
        it.innerHTML = '<span></span><svg class="cs-ck" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="4 12 10 18 20 6"/></svg>';
        it.firstChild.textContent = o.textContent;
        it.onclick = function () { closeMenu(true); choose(i); };
        pop.appendChild(it);
      });
      document.body.appendChild(pop);
      var r = btn.getBoundingClientRect(), w = Math.max(r.width, 180);
      pop.style.minWidth = Math.min(w, window.innerWidth - 16) + 'px';
      pop.style.maxWidth = (window.innerWidth - 16) + 'px'; // на узком экране меню не прижимается к краю
      var h = pop.offsetHeight, below = window.innerHeight - r.bottom, up = below < Math.min(h, 240) + 12 && r.top > below;
      pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - Math.max(w, pop.offsetWidth) - 8)) + 'px';
      pop.style.top = (up ? Math.max(8, r.top - Math.min(h, r.top - 16) - 4) : r.bottom + 4) + 'px';
      pop.style.maxHeight = (up ? r.top - 16 : below - 16) + 'px';
      btn.setAttribute('aria-expanded', 'true');
      opened = { btn: btn, pop: pop, sel: sel };
      var on = pop.querySelector('.on') || pop.querySelector('.cs-it:not(.off)');
      if (on) { on.focus({ preventScroll: true }); on.scrollIntoView({ block: 'nearest' }); }
    }

    btn.onclick = function () { opened && opened.btn === btn ? closeMenu(true) : openMenu(); };
    btn.onkeydown = function (e) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); openMenu(); }
    };
    sel.__cs = { sync: sync };
    new MutationObserver(sync).observe(sel, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled'] });
    sync();
  }

  // Клавиши внутри открытого меню
  document.addEventListener('keydown', function (e) {
    if (!opened) return;
    var items = [].slice.call(opened.pop.querySelectorAll('.cs-it:not(.off)')), i = items.indexOf(document.activeElement);
    if (e.key === 'Escape') { e.preventDefault(); closeMenu(true); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); (items[Math.min(items.length - 1, i + 1)] || items[0]).focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); (items[Math.max(0, i - 1)] || items[0]).focus(); }
    else if (e.key === 'Tab') { closeMenu(false); }
  }, true);
  document.addEventListener('mousedown', function (e) {
    if (opened && !opened.pop.contains(e.target) && !opened.btn.contains(e.target)) closeMenu(false);
  }, true);
  window.addEventListener('resize', function () { closeMenu(false); });
  window.addEventListener('scroll', function (e) { if (opened && !opened.pop.contains(e.target)) closeMenu(false); }, true);

  // Программная смена значения (sel.value = …) тоже обновляет кнопку
  Object.defineProperty(HTMLSelectElement.prototype, 'value', { get: valDesc.get, configurable: true,
    set: function (v) { valDesc.set.call(this, v); if (this.__cs) this.__cs.sync(); } });
  Object.defineProperty(HTMLSelectElement.prototype, 'selectedIndex', { get: idxDesc.get, configurable: true,
    set: function (v) { idxDesc.set.call(this, v); if (this.__cs) this.__cs.sync(); } });

  function scan(root) { [].forEach.call((root.querySelectorAll ? root : document).querySelectorAll('select'), enhance); }
  function start() {
    scan(document);
    new MutationObserver(function (list) {
      list.forEach(function (m) { [].forEach.call(m.addedNodes, function (n) {
        if (n.nodeType !== 1) return;
        if (n.tagName === 'SELECT') enhance(n); else scan(n);
      }); });
    }).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
