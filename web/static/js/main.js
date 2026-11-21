// Сессия закончилась, пока вкладка была открыта (простой дольше срока, 12 часов, вход с другого места): сразу форма входа,
// без перезагрузки; открытые окна и данные на экране убираем. До первого входа 401 – обычное дело и сообщения не вызывает.
let appShown = false;
const nativeFetch = window.fetch.bind(window);
window.fetch = async function (...args) {
  const res = await nativeFetch(...args);
  const url = String((args[0] && args[0].url) || args[0] || '');
  if (res.status === 401 && appShown && !url.includes('/api/v1/login')) sessionEnded();
  return res;
};
function sessionEnded() {
  appShown = false;
  document.querySelectorAll('.modal-overlay').forEach(m => { m.style.display = 'none'; });
  try { if (drawerIsOpen()) closeDrawer(); } catch (e) {}
  document.getElementById('app-panel').style.display = 'none';
  document.getElementById('auth-panel').style.display = 'block';
  // введённые ранее пароль и код не должны оставаться в форме после выхода по сроку
  ['login-password', 'login-code'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  loginMessage('Сессия истекла, войдите снова');
}

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (drawerIsOpen()) { closeDrawer(); return; }
  document.querySelectorAll('.modal-overlay').forEach(m => { if (m.style.display === 'flex') closeModal(m.id); });
});

function openModal(id) {
  const m = document.getElementById(id);
  clearTimeout(m._closeT); m.classList.remove('closing');
  m.style.display = 'flex';
}
function closeModal(id) {
  const m = document.getElementById(id);
  if (!m || m.style.display === 'none' || m.classList.contains('closing')) return;
  // окно уходит с анимацией; при сниженной анимации (или если она не запустится) прячем сразу по таймеру
  m.classList.add('closing');
  const hide = () => { m.style.display = 'none'; m.classList.remove('closing'); };
  clearTimeout(m._closeT); m._closeT = setTimeout(hide, 210);
}

// Окна: заголовок получает крестик, ряд кнопок внизу – подвал справа (разметка остаётся прежней)
function enhanceModals() {
  document.querySelectorAll('.modal-overlay').forEach(ov => {
    // клик мимо карточки закрывает окно, только если и нажали, и отпустили на фоне:
    // выделение текста с выходом за карточку (в обе стороны) окно не закрывает
    if (!ov.dataset.bd) {
      ov.dataset.bd = '1';
      let downOnBg = false, upOnBg = false;
      const down = e => { downOnBg = e.target === ov; upOnBg = false; };
      const up = e => { upOnBg = e.target === ov; };
      ov.addEventListener('pointerdown', down);
      ov.addEventListener('mousedown', down);
      ov.addEventListener('pointerup', up);
      ov.addEventListener('mouseup', up);
      ov.addEventListener('click', e => { if (e.target === ov && downOnBg && upOnBg) closeModal(ov.id); downOnBg = upOnBg = false; });
    }
    const card = ov.querySelector('.modal-card');
    if (!card || card.dataset.enhanced) return;
    card.dataset.enhanced = '1';
    const h = card.querySelector(':scope > h3');
    if (h) {
      const head = document.createElement('div'); head.className = 'modal-head';
      const x = document.createElement('button'); x.type = 'button'; x.className = 'modal-x'; x.setAttribute('aria-label', 'Закрыть'); x.textContent = '×';
      x.onclick = () => closeModal(ov.id);
      card.insertBefore(head, h); head.appendChild(h); head.appendChild(x);
      h.removeAttribute('style');
    }
    // последний ряд из кнопок (Сохранить / Отмена) превращаем в подвал
    const last = card.lastElementChild;
    if (last && last.tagName === 'DIV' && last.querySelector('button.btn-banner') && !last.querySelector('input,select,textarea')) {
      last.className = 'modal-foot'; last.removeAttribute('style');
      last.querySelectorAll('button.btn-banner').forEach(b => b.removeAttribute('style'));
      const cancel = [...last.querySelectorAll('button')].find(b => /closeModal/.test(b.getAttribute('onclick') || ''));
      if (cancel) { cancel.style.cssText = 'background: var(--surface-inset); color: var(--text-main); box-shadow: none;'; last.insertBefore(cancel, last.firstChild); }
    } else if (last && last.tagName === 'BUTTON' && /closeModal/.test(last.getAttribute('onclick') || '')) {
      const foot = document.createElement('div'); foot.className = 'modal-foot';
      last.removeAttribute('style'); last.style.cssText = 'background: var(--surface-inset); color: var(--text-main); box-shadow: none;';
      card.insertBefore(foot, last); foot.appendChild(last);
    }
  });
}
document.addEventListener('DOMContentLoaded', enhanceModals);

async function checkAuthAndLoad() {
  try {
    const res = await fetch('/api/v1/inbounds');
    if (res.status === 401) {
      appShown = false;
      document.getElementById('auth-panel').style.display = 'block';
      document.getElementById('app-panel').style.display = 'none';
    } else {
      appShown = true;
      document.getElementById('auth-panel').style.display = 'none';
      document.getElementById('app-panel').style.display = 'flex';
      await loadSystemStatus();
      await loadInbounds();
      await loadUsers();
      loadMetrics();
      silentHealthBadge();
    }
  } catch (e) {
    console.error(e);
  }
}

async function loadSystemStatus() {
  const res = await fetch('/api/v1/system/status');
  if (!res.ok) return;
  const d = await res.json();
  document.getElementById('stat-clients').textContent = d.active_clients;
  document.getElementById('stat-ram').textContent = d.ram_usage;
}

function loginMessage(text) {
  const el = document.getElementById('login-msg');
  el.textContent = text || '';
  el.style.display = text ? 'block' : 'none';
}

async function handleLoginSubmit() {
  const u = document.getElementById('login-username').value;
  const p = document.getElementById('login-password').value;
  const code = document.getElementById('login-code').value;
  loginMessage('');
  const res = await fetch('/api/v1/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: u, password: p, code})
  });
  if (res.ok) { checkAuthAndLoad(); return; }
  const d = await res.json().catch(() => ({}));
  if (d.needs_totp && !code) {
    // пароль верный: просто открываем поле для кода, без всплывающих окон
    document.getElementById('login-2fa').style.display = 'flex';
    document.getElementById('login-code').focus();
    return;
  }
  loginMessage(d.error || 'Неверный логин или пароль');
  if (d.needs_totp) { const f = document.getElementById('login-code'); f.select(); f.focus(); }
}

// Enter в полях входа
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target && /^login-(username|password|code)$/.test(e.target.id)) handleLoginSubmit();
});

async function handleLogoutSubmit() {
  await fetch('/api/v1/logout', {method: 'POST'});
  location.reload();
}

async function submitChangePassword() {
  const old_password = document.getElementById('settings-old-pwd').value;
  const new_password = document.getElementById('settings-new-pwd').value;

  if (!new_password || new_password.length < 8) {
    return uiAlert('Пароль', 'Длина нового пароля должна быть не менее 8 символов');
  }

  const res = await fetch('/api/v1/admin/password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({old_password, new_password})
  });

  if (res.ok) {
    toast('Пароль обновлён');
    document.getElementById('settings-old-pwd').value = '';
    document.getElementById('settings-new-pwd').value = '';
  } else {
    uiAlert('Пароль', 'Неверный текущий пароль');
  }
}


// Выдвижное меню на узких экранах: то же боковое меню, но поверх страницы
const drawerMQ = window.matchMedia('(max-width: 900px)');
const DRAWER_FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';
function drawerIsOpen() { return document.body.classList.contains('drawer-open'); }
function setDrawerState(open) {
  document.body.classList.toggle('drawer-open', open);
  document.documentElement.classList.toggle('drawer-open', open);
  document.getElementById('drawer-toggle').setAttribute('aria-expanded', String(open));
}
function openDrawer() {
  if (!drawerMQ.matches || drawerIsOpen()) return;
  setDrawerState(true);
  const sb = document.getElementById('main-sidebar');
  const visible = [...sb.querySelectorAll(DRAWER_FOCUSABLE)].filter(el => el.offsetParent !== null);
  const first = sb.querySelector('.nav-item.active') || visible[0];
  if (first) {
    first.focus({preventScroll: true});
    first.scrollIntoView({block: 'center'});
  }
}
function closeDrawer() {
  if (!drawerIsOpen()) return;
  setDrawerState(false);
  document.getElementById('drawer-toggle').focus({preventScroll: true});
}
function toggleDrawer() { drawerIsOpen() ? closeDrawer() : openDrawer(); }

function initDrawer() {
  const sb = document.getElementById('main-sidebar');
  const bd = document.getElementById('drawer-backdrop');
  const title = document.getElementById('page-title');
  const bar = document.getElementById('appbar-title');
  const syncTitle = () => { bar.textContent = title.textContent; };
  new MutationObserver(syncTitle).observe(title, {childList: true, characterData: true, subtree: true});
  syncTitle();

  // как у окон: закрываем, только если и нажали, и отпустили на подложке
  let downOnBd = false, upOnBd = false;
  const down = e => { downOnBd = e.target === bd; upOnBd = false; };
  const up = e => { upOnBd = e.target === bd; };
  bd.addEventListener('pointerdown', down);
  bd.addEventListener('mousedown', down);
  bd.addEventListener('pointerup', up);
  bd.addEventListener('mouseup', up);
  bd.addEventListener('click', e => { if (e.target === bd && downOnBd && upOnBd) closeDrawer(); downOnBd = upOnBd = false; });

  // логотип при открытом меню только закрывает его, без перехода на главную
  sb.addEventListener('click', e => {
    if (drawerIsOpen() && e.target.closest('.sb-logo')) { e.stopPropagation(); closeDrawer(); }
  }, true);

  // выбор страницы закрывает меню
  sb.addEventListener('click', e => {
    if (!drawerIsOpen()) return;
    const it = e.target.closest('.nav-item, .sb-logo');
    if (!it || it.classList.contains('sb-logout')) return;
    closeDrawer();
  });

  // свайп влево по меню
  let sx = 0, sy = 0;
  sb.addEventListener('touchstart', e => { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, {passive: true});
  sb.addEventListener('touchend', e => {
    const t = e.changedTouches[0];
    const dx = t.clientX - sx, dy = t.clientY - sy;
    if (dx < -60 && Math.abs(dx) > Math.abs(dy) * 1.5) closeDrawer();
  }, {passive: true});

  // ловушка фокуса
  sb.addEventListener('keydown', e => {
    if (e.key !== 'Tab' || !drawerIsOpen()) return;
    const items = [...sb.querySelectorAll(DRAWER_FOCUSABLE)].filter(el => el.offsetParent !== null);
    if (!items.length) return;
    const a = items[0], z = items[items.length - 1];
    if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
    else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
  });

  const apply = () => {
    if (drawerMQ.matches) {
      sb.setAttribute('role', 'dialog'); sb.setAttribute('aria-modal', 'true'); sb.setAttribute('aria-label', 'Меню');
    } else {
      sb.removeAttribute('role'); sb.removeAttribute('aria-modal'); sb.removeAttribute('aria-label');
      setDrawerState(false);
    }
  };
  drawerMQ.addEventListener('change', apply);
  apply();
}

loadExtensions();
initSidebar();
initDrawer();
checkAuthAndLoad();
setInterval(loadSystemStatus, 10000);
setInterval(loadMetrics, 10000);

// Необязательные расширения: если в сборке есть дополнительный раздел, его скрипт отдаётся с сервера, иначе запрос даёт 404
async function loadExtensions() {
  try {
    const r = await fetch('/api/v1/pro/ui/pro.js');
    if (!r.ok) return;
    const s = document.createElement('script');
    s.text = await r.text() + '\ninitPro();';
    document.body.appendChild(s);
  } catch (e) {}
}
