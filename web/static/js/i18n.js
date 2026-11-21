/* Язык панели: RU / EN. Тексты в разметке и скриптах остаются русскими (это исходник), английский подставляется поверх:
   по словарю window.KIT_EN (точное совпадение строки) и по шаблонам со вставками (%s, %d, {0}). Что в словаре не нашлось,
   остаётся по-русски. Работает и для динамически созданного содержимого (наблюдатель за DOM). */
(function () {
  var KEY = 'kitsune_lang';
  var EN = window.KIT_EN || {};
  var ATTRS = ['placeholder', 'title', 'aria-label', 'alt'];
  var CYR = /[А-Яа-яЁё]/;
  var SKIP = {SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 0};

  function norm(s) { return s.replace(/[\s ]+/g, ' ').trim(); }

  var lang = (function () {
    try { var v = localStorage.getItem(KEY); if (v === 'ru' || v === 'en') return v; } catch (e) {}
    return /^ru/i.test(navigator.language || '') ? 'ru' : 'en';
  })();

  // шаблоны: ключи словаря со вставками превращаются в регулярные выражения
  var PH = /%[-+# 0]*\d*(?:\.\d+)?[sdvqwxXfgt]|\{\d+\}/g;
  var pats = [];
  Object.keys(EN).forEach(function (k) {
    var kk = k.replace(/%%/g, '\u0001'); // %% в строках из Go – обычный знак процента
    PH.lastIndex = 0;
    if (!PH.test(kk)) { PH.lastIndex = 0; return; }
    PH.lastIndex = 0;
    var re = '', last = 0, m;
    while ((m = PH.exec(kk))) { re += esc(kk.slice(last, m.index)) + '(.+?)'; last = m.index + m[0].length; }
    re += esc(kk.slice(last));
    pats.push({re: new RegExp('^' + re.replace(/\u0001/g, '%') + '$'), en: EN[k], n: k.length});
  });
  pats.sort(function (a, b) { return b.n - a.n; }); // длинные шаблоны первыми
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function fill(tpl, caps) {
    var i = 0;
    return tpl.replace(/%%/g, '\u0001').replace(/\{(\d+)\}|%[-+# 0]*\d*(?:\.\d+)?[sdvqwxXfgt]/g, function (m, idx) {
      var v = idx !== undefined ? caps[+idx] : caps[i++];
      return v === undefined ? m : kitT(v);
    }).replace(/\u0001/g, '%');
  }

  function kitT(s) {
    if (lang !== 'en' || typeof s !== 'string' || !CYR.test(s)) return s;
    var lead = /^[\s ]*/.exec(s)[0], tail = /[\s ]*$/.exec(s)[0];
    var core = norm(s);
    if (!core) return s;
    var r = EN[core];
    if (r === undefined) {
      // среди подходящих шаблонов берём тот, после которого осталось меньше непереведённого русского текста
      var best, bestLeft = 1e9;
      for (var i = 0; i < pats.length; i++) {
        var m = pats[i].re.exec(core);
        if (!m) continue;
        var cand = fill(pats[i].en, m.slice(1));
        var left = (cand.match(/[А-Яа-яЁё]/g) || []).length;
        if (left < bestLeft) { best = cand; bestLeft = left; if (!left) break; }
      }
      r = best;
    }
    return r === undefined ? s : lead + r + tail;
  }
  window.kitT = kitT;
  window.kitLang = function () { return lang; };

  /* ---------- DOM ---------- */
  function applyText(n) {
    var cur = n.nodeValue;
    if (n.__en !== undefined && cur === n.__en) { if (lang === 'ru') { n.nodeValue = n.__ru; n.__en = undefined; } return; }
    if (n.__ru === undefined || cur !== n.__ru) n.__ru = cur; // содержимое сменило приложение
    if (!CYR.test(n.__ru)) return;
    var want = lang === 'en' ? kitT(n.__ru) : n.__ru;
    if (want !== cur) { n.__en = want; n.nodeValue = want; } else n.__en = undefined;
  }
  function applyAttrs(el) {
    if (el.nodeType !== 1) return;
    var st = el.__ra || (el.__ra = {});
    for (var i = 0; i < ATTRS.length; i++) {
      var a = ATTRS[i], cur = el.getAttribute(a);
      if (cur === null) { st[a] = null; continue; }
      var rec = st[a];
      if (rec && cur === rec.en) { // это наш перевод
        if (lang === 'ru') { el.setAttribute(a, rec.ru); st[a] = null; }
        continue;
      }
      // атрибут задало приложение (или он сменился): запоминаем только если подставляем перевод.
      // В русском режиме ничего не пишем: лишняя запись атрибута сама вызывает наблюдатель и может зациклить страницу.
      st[a] = null;
      if (lang !== 'en' || !CYR.test(cur)) continue;
      var want = kitT(cur);
      if (want !== cur) { st[a] = {ru: cur, en: want}; el.setAttribute(a, want); }
    }
  }
  function walk(root) {
    if (root.nodeType === 3) { applyText(root); return; }
    if (root.nodeType !== 1) return;
    if (SKIP[root.tagName]) { if (root.tagName === 'TEXTAREA') applyAttrs(root); return; } // у поля ввода переводим подсказку, но не его содержимое
    applyAttrs(root);
    for (var c = root.firstChild; c; c = c.nextSibling) walk(c);
  }

  var storm = {t: 0, n: 0};
  var mo = new MutationObserver(function (list) {
    // защита от зацикливания: если правки сыплются непрерывно, наблюдатель отключается и страница остаётся рабочей
    var now = Date.now();
    if (now - storm.t > 1000) { storm.t = now; storm.n = 0; }
    storm.n += list.length;
    if (storm.n > 3000) {
      mo.disconnect();
      window.__i18nStorm = list.slice(0, 5).map(function (m) { return m.type + ':' + (m.target.nodeName || '') + ':' + (m.attributeName || '') + ':' + String(m.target.nodeValue || m.target.className || '').slice(0, 60); });
      return;
    }
    for (var i = 0; i < list.length; i++) {
      var m = list[i];
      if (m.type === 'characterData') applyText(m.target);
      else if (m.type === 'attributes') applyAttrs(m.target);
      else for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]);
    }
  });
  function observe() { mo.observe(document.documentElement, {childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS}); }

  var origTitle = null;
  function setTitle() {
    if (origTitle === null) origTitle = document.title;
    document.title = lang === 'en' ? kitT(origTitle) : origTitle;
  }

  function markButtons() {
    document.querySelectorAll('.lang-sw button[data-lang]').forEach(function (b) {
      var on = b.getAttribute('data-lang') === lang;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }

  window.setLang = function (l) {
    if (l !== 'ru' && l !== 'en') return;
    lang = l;
    try { localStorage.setItem(KEY, l); } catch (e) {}
    document.documentElement.lang = l;
    mo.disconnect();
    walk(document.documentElement);
    setTitle();
    observe();
    markButtons();
    document.dispatchEvent(new CustomEvent('langchange', {detail: l}));
  };

  function init() {
    document.documentElement.lang = lang;
    mo.disconnect();
    walk(document.documentElement);
    setTitle();
    observe();
    markButtons();
    document.querySelectorAll('.lang-sw button[data-lang]').forEach(function (b) {
      b.addEventListener('click', function () { window.setLang(b.getAttribute('data-lang')); });
    });
  }
  init();
})();
