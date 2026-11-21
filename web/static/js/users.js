/* ---------- Подключение одним нажатием ---------- */
const APPS = [
  {name: 'Happ', url: (u, n) => `happ://add/${u}`},
  {name: 'Hiddify', url: (u, n) => `hiddify://import/${u}#${encodeURIComponent(n)}`},
  {name: 'v2rayNG', url: (u, n) => `v2rayng://install-sub/?url=${encodeURIComponent(u)}#${encodeURIComponent(n)}`},
  {name: 'Streisand', url: (u, n) => `streisand://import/${u}#${encodeURIComponent(n)}`},
  {name: 'Karing', url: (u, n) => `karing://install-config?url=${encodeURIComponent(u)}&name=${encodeURIComponent(n)}`},
  {name: 'Clash Verge', url: (u, n) => `clash://install-config?url=${encodeURIComponent(u)}&name=${encodeURIComponent(n)}`},
  {name: 'FlClash', url: (u, n) => `clash://install-config?url=${encodeURIComponent(u)}&name=${encodeURIComponent(n)}`},
  {name: 'sing-box', url: (u, n) => `sing-box://import-remote-profile?url=${encodeURIComponent(u)}#${encodeURIComponent(n)}`},
  {name: 'Shadowrocket', url: (u, n) => `shadowrocket://add/sub://${btoa(u)}?remark=${encodeURIComponent(n)}`},
  {name: 'V2Box', url: (u, n) => `v2box://install-sub?url=${encodeURIComponent(u)}&name=${encodeURIComponent(n)}`},
  {name: 'Stash', url: (u, n) => `stash://install-config?url=${encodeURIComponent(u)}`},
  {name: 'NekoBox', url: (u, n) => `sn://subscription?url=${encodeURIComponent(u)}&name=${encodeURIComponent(n)}`}
];

function renderAppButtons(subUrl, name) {
  document.getElementById('app-grid').innerHTML = APPS.map((a, i) =>
    `<button class="app-btn" onclick="openInApp(${i})">${a.name}</button>`).join('');
  window.__appCtx = {subUrl, name: 'Kitsune'};
}

function openInApp(i) {
  const c = window.__appCtx;
  if (!c) return;
  window.location.href = APPS[i].url(c.subUrl, c.name);
}

/* ---------- Пользователи ---------- */
let usersCache = [];

let userFilter = 'all';
const USER_FILTERS = [['all', 'Все'], ['active', 'Активные'], ['expiring', 'Скоро истекут'], ['over', 'Лимит исчерпан'], ['off', 'Отключены']];

function userBucket(u) {
  if (!u.enable) return 'off';
  if (!u.active) return 'over';
  if (u.expiry_time && u.expiry_time - Date.now() < 7 * 86400000) return 'expiring';
  return 'active';
}

async function loadUsers() {
  if (!gtData.groups.length) await loadGroups();
  const res = await fetch('/api/v1/users');
  if (!res.ok) return;
  const d = await res.json();
  usersCache = d.users || [];
  const known = new Set(usersCache.map(u => u.id));
  [...userSel].forEach(id => { if (!known.has(id)) userSel.delete(id); });
  const callout = document.getElementById('no-inbounds-callout');
  if (callout) callout.style.display = (window.__inbounds && window.__inbounds.length === 0) ? 'flex' : 'none';
  const cnt = document.getElementById('nb-clients');
  if (cnt) cnt.textContent = usersCache.length || '';
  renderUsers();
}

function setUserFilter(f) { userFilter = f; renderUsers(); }

/* ---------- Выбор нескольких пользователей и групповые действия ---------- */
const userSel = new Set();

function toggleUserSel(id, on) {
  if (on) userSel.add(id); else userSel.delete(id);
  renderBulkBar();
  const card = document.querySelector(`.user-card[data-id="${id}"]`);
  if (card) card.classList.toggle('sel', on);
  syncSelectAll();
}

function visibleUserIds() { return [...document.querySelectorAll('#clients-container .user-card')].map(c => Number(c.dataset.id)); }

function syncSelectAll() {
  const all = document.getElementById('u-select-all'), ids = visibleUserIds();
  if (!all) return;
  const n = ids.filter(id => userSel.has(id)).length;
  all.checked = ids.length > 0 && n === ids.length;
  all.indeterminate = n > 0 && n < ids.length;
}

function selectAllUsers(on) {
  visibleUserIds().forEach(id => on ? userSel.add(id) : userSel.delete(id));
  document.querySelectorAll('#clients-container .user-card').forEach(c => {
    c.classList.toggle('sel', on); const cb = c.querySelector('.user-check'); if (cb) cb.checked = on;
  });
  renderBulkBar();
}

function clearUserSel() {
  userSel.clear();
  document.querySelectorAll('#clients-container .user-card').forEach(c => { c.classList.remove('sel'); const cb = c.querySelector('.user-check'); if (cb) cb.checked = false; });
  syncSelectAll(); renderBulkBar();
}

function renderBulkBar() {
  const bar = document.getElementById('bulk-bar');
  if (!bar) return;
  bar.hidden = userSel.size === 0;
  document.getElementById('bulk-count').textContent = userSel.size;
}

async function bulkAction(action, days) {
  const ids = [...userSel];
  if (!ids.length) return;
  const n = ids.length;
  if (action === 'delete' && !await uiConfirm(`Удалить пользователей: ${n}?`, 'Их подписки перестанут работать. Это действие нельзя отменить.', 'Удалить', true)) return;
  if (action === 'reset_traffic' && !await uiConfirm(`Сбросить трафик у пользователей: ${n}?`, '', 'Сбросить')) return;
  const r = await api('POST', '/api/v1/users/bulk', {ids, action, days: days || 0});
  // часть действий могла пройти даже при ошибке пересборки ядер: список обновляем в любом случае
  if (r.ok && !r.data.failed) toast(r.data.message);
  else if (r.ok) uiAlert('Готово не для всех', r.data.message);
  else if (r.data.done > 0) uiAlert('Изменения сохранены, но ядра не пересобраны', String(r.data.error || 'Ошибка'));
  else uiAlert('Ошибка', String(r.data.error || 'Ошибка'));
  clearUserSel();
  await loadUsers(); loadSystemStatus();
}

let userSort = 'new';
try { userSort = localStorage.getItem('kitsune-user-sort') || 'new'; } catch (e) {}
const USER_SORTS = {
  new: (a, b) => (b.id || 0) - (a.id || 0),
  name: (a, b) => String(a.name).localeCompare(String(b.name), 'ru'),
  traffic: (a, b) => (b.used_traffic || 0) - (a.used_traffic || 0),
  expiry: (a, b) => (a.expiry_time || Infinity) - (b.expiry_time || Infinity)
};
function setUserSort(v) {
  userSort = USER_SORTS[v] ? v : 'new';
  try { localStorage.setItem('kitsune-user-sort', userSort); } catch (e) {}
  renderUsers();
}

// Меню «⋯» у пользователя: открыто не больше одного, закрывается кликом мимо и по Esc
function toggleUserMenu(btn) {
  const menu = btn.nextElementSibling, open = menu.classList.contains('open');
  closeUserMenus();
  if (!open) { menu.classList.add('open'); btn.setAttribute('aria-expanded', 'true'); }
}
function closeUserMenus() {
  document.querySelectorAll('.u-menu.open').forEach(m => { m.classList.remove('open'); if (m.previousElementSibling) m.previousElementSibling.setAttribute('aria-expanded', 'false'); });
}
document.addEventListener('click', e => { if (!e.target.closest('.u-menu-wrap')) closeUserMenus(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeUserMenus(); });

function renderUsers() {
  const box = document.getElementById('clients-container');
  const q = (document.getElementById('u-search').value || '').trim().toLowerCase();
  const counts = {all: usersCache.length, active: 0, expiring: 0, over: 0, off: 0};
  usersCache.forEach(u => { const k = userBucket(u); counts[k]++; if (k === 'expiring') counts.active++; });
  document.getElementById('u-filters').innerHTML = USER_FILTERS
    .filter(([k]) => k === 'all' || k === 'active' || counts[k] > 0)
    .map(([k, t]) => `<button class="chip${userFilter === k ? ' on' : ''}" onclick="setUserFilter('${k}')">${t}<small>${counts[k]}</small></button>`).join('');
  if (!usersCache.length) {
    box.innerHTML = `<div class="empty-state"><h4>Пользователей пока нет</h4><p>Один пользователь – одна ссылка-подписка на все подключения. Создайте первого и отправьте ему ссылку.</p><button class="btn" onclick="openAddUserModal()">Добавить пользователя</button></div>`;
    return;
  }
  const sel = document.getElementById('u-sort'); if (sel && sel.value !== userSort) sel.value = userSort;
  const list = usersCache.filter(u => {
    const k = userBucket(u);
    if (userFilter === 'active' && !(k === 'active' || k === 'expiring')) return false;
    if (userFilter !== 'all' && userFilter !== 'active' && k !== userFilter) return false;
    return !q || (u.name + ' ' + (u.note || '')).toLowerCase().includes(q);
  }).sort(USER_SORTS[userSort]);
  if (!list.length) { box.innerHTML = '<div class="empty-state"><h4>Ничего не найдено</h4><p>Измените запрос или фильтр.</p></div>'; return; }
  box.innerHTML = list.map(u => {
    const used = u.used_traffic || 0, limit = u.traffic_limit || 0;
    const pct = limit > 0 ? Math.min(100, Math.round(used / limit * 100)) : 0;
    const k = userBucket(u);
    const state = {off: ['chip-inactive', 'Отключён'], over: ['chip-inactive', 'Лимит или срок'], expiring: ['chip-active', 'Скоро истечёт'], active: ['chip-active', 'Активен']}[k];
    return `
      <div class="user-card${u.enable ? '' : ' off'}${userSel.has(u.id) ? ' sel' : ''}" data-id="${u.id}">
        <div class="user-identity">
          <input type="checkbox" class="user-check" aria-label="Выбрать ${esc(u.name)}" ${userSel.has(u.id) ? 'checked' : ''} onchange="toggleUserSel(${u.id}, this.checked)">
          <div class="user-avatar">${esc((u.name || 'U').charAt(0).toUpperCase())}</div>
          <div class="user-titles">
            <span class="user-name">${esc(u.name)}${u.group_id ? `<span class="proto-badge">${esc((gtData.groups.find(g => g.id === u.group_id) || {name: 'группа'}).name)}</span>` : ''}</span>
            <span class="user-uuid">${esc(u.note || (u.protocols + ' подключ.'))}</span>
          </div>
        </div>
        <div class="metric-col">
          <div class="metric-label-row"><span>Трафик</span><span>${formatBytes(used)} / ${limit === 0 ? '∞' : formatBytes(limit)}</span></div>
          ${limit > 0 ? `<div class="bar-track"><div class="bar-fill ${pct >= 90 ? 'bad' : (pct >= 75 ? 'warn' : '')}" style="width: ${pct}%;"></div></div>` : '<div class="metric-note">без лимита</div>'}
        </div>
        <div class="user-expiry-box">
          <div>Срок: <strong>${formatDays(u.expiry_time)}</strong>${u.ip_limit ? ` · ${u.ip_limit} устр.` : ''}</div>
          <div><span class="status-chip ${state[0]}">${state[1]}</span></div>
        </div>
        <div class="user-actions">
          <button class="btn-primary-action" onclick="showUserLinks(${u.id})" title="Ссылка подписки и QR-код">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            Ссылка</button>
          <button class="btn soft u-edit" onclick="openEditUser(${u.id})">Изменить</button>
          <div class="u-menu-wrap">
            <button class="btn-icon" aria-label="Ещё действия" aria-haspopup="true" aria-expanded="false" onclick="toggleUserMenu(this)">⋯</button>
            <div class="u-menu" role="menu">
              <button role="menuitem" onclick="closeUserMenus(); toggleUser(${u.id})">${u.enable ? 'Отключить' : 'Включить'}</button>
              <button role="menuitem" onclick="closeUserMenus(); resetUserTraffic(${u.id})">Сбросить трафик</button>
              <button role="menuitem" onclick="closeUserMenus(); regenUserSub(${u.id}, '${escJs(u.name)}')">Новая ссылка подписки…</button>
              <hr>
              <button role="menuitem" class="danger" onclick="closeUserMenus(); deleteUser(${u.id}, '${escJs(u.name)}')">Удалить…</button>
            </div>
          </div>
        </div>
      </div>`;
  }).join('');
  syncSelectAll(); renderBulkBar();
}

// Тарифы-шорткаты в окне нового пользователя
document.addEventListener('click', e => {
  const b = e.target.closest && e.target.closest('#nu-presets .preset');
  if (!b) return;
  document.querySelectorAll('#nu-presets .preset').forEach(x => x.classList.toggle('on', x === b));
  document.getElementById('nu-limit').value = b.dataset.gb;
  document.getElementById('nu-expiry').value = b.dataset.days;
});
document.addEventListener('change', e => {
  if (e.target.id === 'nu-limit' || e.target.id === 'nu-expiry') document.querySelectorAll('#nu-presets .preset').forEach(x => x.classList.remove('on'));
});

async function api(method, url, body) {
  let res;
  try {
    res = await fetch(url, {method, headers: body ? {'Content-Type': 'application/json'} : undefined, body: body ? JSON.stringify(body) : undefined});
  } catch (e) {
    // сети нет или сервер не ответил: результат неизвестен, это не «тихий успех»
    return {ok: false, status: 0, data: {error: 'Нет связи с сервером. Результат неизвестен: обновите страницу и проверьте.'}};
  }
  let data = {};
  try { data = await res.json(); } catch (e) {}
  return {ok: res.ok, status: res.status, data};
}

async function openAddUserModal() { await prepareUserForms(); openModal('add-client-modal'); }

async function submitCreateUser() {
  const gb = parseInt(document.getElementById('nu-limit').value) || 0;
  const body = {
    name: document.getElementById('nu-name').value.trim(),
    traffic_limit: gb * 1024 * 1024 * 1024,
    expiry_days: parseInt(document.getElementById('nu-expiry').value) || 0,
    ip_limit: parseInt(document.getElementById('nu-iplimit').value) || 0,
    note: document.getElementById('nu-note').value.trim(),
    vision: document.getElementById('nu-vision').checked,
    group_id: parseInt(document.getElementById('nu-group').value) || 0
  };
  const r = await api('POST', '/api/v1/users', body);
  if (!r.ok) { uiAlert('Не удалось создать пользователя', r.data.error || 'Ошибка'); return; }
  closeModal('add-client-modal');
  document.getElementById('nu-name').value = '';
  if (r.data.message && r.data.message.includes('не приняло')) uiAlert('Внимание', r.data.message);
  await loadUsers(); loadSystemStatus();
}

let editingUser = null;
async function openEditUser(id) {
  const u = usersCache.find(x => x.id === id);
  if (!u) return;
  await loadGroups();
  document.getElementById('eu-group').innerHTML = groupOptions(u.group_id || 0);
  editingUser = u;
  document.getElementById('eu-title').textContent = u.name;
  document.getElementById('eu-name').value = u.name;
  document.getElementById('eu-limit').value = u.traffic_limit ? Math.round(u.traffic_limit / 1073741824 * 100) / 100 : 0;
  const days = u.expiry_time ? Math.max(0, Math.ceil((u.expiry_time - Date.now()) / 86400000)) : 0;
  document.getElementById('eu-days').value = days;
  document.getElementById('eu-iplimit').value = u.ip_limit || 0;
  document.getElementById('eu-vision').checked = !!u.vision;
  document.getElementById('eu-note').value = u.note || '';
  openModal('edit-user-modal');
}

async function submitEditUser() {
  const u = editingUser;
  if (!u) return;
  const body = {
    name: document.getElementById('eu-name').value.trim(),
    traffic_limit: Math.round((parseFloat(document.getElementById('eu-limit').value) || 0) * 1073741824),
    ip_limit: parseInt(document.getElementById('eu-iplimit').value) || 0,
    vision: document.getElementById('eu-vision').checked,
    note: document.getElementById('eu-note').value.trim(),
    group_id: parseInt(document.getElementById('eu-group').value) || 0
  };
  const days = parseInt(document.getElementById('eu-days').value) || 0;
  // срок меняем, только если значение отличается от текущего остатка
  const cur = u.expiry_time ? Math.max(0, Math.ceil((u.expiry_time - Date.now()) / 86400000)) : 0;
  if (days !== cur) body.expiry_days = days;
  const r = await api('PUT', `/api/v1/users/${u.id}`, body);
  if (!r.ok) { uiAlert('Ошибка сохранения', r.data.error || 'Ошибка'); return; }
  closeModal('edit-user-modal');
  if (r.data.message && r.data.message.includes('не приняло')) uiAlert('Сохранено, но есть замечание', r.data.message);
  await loadUsers();
}

async function resetUserTraffic(id) {
  if (!await uiConfirm('Сбросить трафик пользователя?', '', 'Сбросить')) return;
  const r = await api('POST', `/api/v1/users/${id}/reset-traffic`);
  if (!r.ok) uiAlert('Не удалось сбросить трафик', r.data.error || 'Ошибка'); else toast('Трафик сброшен');
  await loadUsers();
}
async function regenUserSub(id, name) {
  if (!await uiConfirm(`Выпустить новую ссылку для «${name}»?`, 'Старая ссылка и QR-код перестанут работать: пользователю нужно будет добавить новую подписку в приложение. Делайте это, если ссылка попала не в те руки.', 'Выпустить', true)) return;
  const r = await api('POST', `/api/v1/users/${id}/regen-sub`);
  if (!r.ok) uiAlert('Не удалось выпустить ссылку', String((r.data && r.data.error) || 'Ошибка')); else toast('Новая ссылка выпущена');
  await loadUsers();
}
async function toggleUser(id) {
  const r = await api('POST', `/api/v1/users/${id}/toggle`);
  if (!r.ok) uiAlert('Не удалось изменить пользователя', r.data.error || 'Ошибка');
  await loadUsers(); loadSystemStatus();
}
async function deleteUser(id, name) {
  if (!await uiConfirm(`Удалить пользователя «${name}»?`, 'Его подписка перестанет работать.', 'Удалить', true)) return;
  const r = await api('DELETE', `/api/v1/users/${id}`);
  if (!r.ok) uiAlert('Не удалось удалить пользователя', r.data.error || 'Ошибка'); else toast('Пользователь удалён');
  await loadUsers(); loadSystemStatus();
}

// Копирование: через буфер обмена (только в защищённом контексте), иначе через временное поле; если и это не вышло – окно с текстом
function copyText(t) {
  t = String(t == null ? '' : t);
  const done = () => toast('Скопировано');
  const manual = () => uiAlert('Скопируйте вручную', t);
  const legacy = () => {
    try {
      const ta = document.createElement('textarea');
      ta.value = t; ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
      document.body.appendChild(ta); ta.focus(); ta.select(); ta.setSelectionRange(0, t.length);
      const ok = document.execCommand('copy');
      ta.remove();
      ok ? done() : manual();
    } catch (e) { manual(); }
  };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(t).then(done, legacy);
  else legacy();
}

/* Окна подтверждения и сообщений в стиле панели (вместо системных confirm и alert).
   uiConfirm возвращает Promise<boolean>, uiAlert – Promise, который выполнится после закрытия окна. */
function uiDialog({title, text, ok, cancel, danger}) {
  return new Promise(resolve => {
    document.getElementById('ui-dlg')?.remove();
    const prev = document.activeElement;
    const ov = document.createElement('div');
    ov.id = 'ui-dlg'; ov.className = 'dlg-overlay';
    ov.innerHTML = `<div class="dlg-card" role="dialog" aria-modal="true" aria-labelledby="ui-dlg-t">
      <h3 id="ui-dlg-t"></h3><p class="dlg-text"></p>
      <div class="dlg-foot">${cancel ? '<button type="button" class="btn soft" data-r="0"></button>' : ''}<button type="button" class="btn${danger ? ' danger' : ''}" data-r="1"></button></div></div>`;
    ov.querySelector('h3').textContent = title || '';
    ov.querySelector('.dlg-text').textContent = text || '';
    const okb = ov.querySelector('[data-r="1"]'); okb.textContent = ok || 'Понятно';
    if (cancel) ov.querySelector('[data-r="0"]').textContent = cancel;
    const done = r => { ov.classList.add('closing'); ov.style.pointerEvents = 'none'; setTimeout(() => ov.remove(), 180); document.removeEventListener('keydown', onKey, true); try { prev && prev.focus(); } catch (e) {} resolve(r); };
    const onKey = e => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); } };
    document.addEventListener('keydown', onKey, true);
    ov.addEventListener('click', e => { if (e.target === ov) done(false); const b = e.target.closest('[data-r]'); if (b) done(b.dataset.r === '1'); });
    document.body.appendChild(ov);
    okb.focus();
  });
}
const uiConfirm = (title, text, ok, danger) => uiDialog({title, text, ok: ok || 'Да', cancel: 'Отмена', danger});
const uiAlert = (title, text) => uiDialog({title, text, ok: 'Закрыть'}).then(() => undefined);
// встроенные страницы (Роутинг в iframe) берут окна у панели через parent
window.uiConfirm = uiConfirm; window.uiAlert = uiAlert;

// Ответ API: успех – короткая плашка (длинный текст – окно), ошибка – окно
function notify(r, errFallback) {
  if (r.ok) {
    const m = String((r.data && r.data.message) || 'Готово');
    if (m.length > 90 || m.includes('\n')) uiAlert('Готово', m); else toast(m);
  } else uiAlert('Ошибка', String((r.data && r.data.error) || errFallback || 'Ошибка'));
}

function toast(msg) {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.setAttribute('role', 'status'); el.setAttribute('aria-live', 'polite');
    document.body.appendChild(el);
  }
  el.textContent = msg; el.style.opacity = 1;
  clearTimeout(el._t); el._t = setTimeout(() => el.style.opacity = 0, Math.max(1600, msg.length * 55));
}

function drawQR(text, caption) {
  const box = document.getElementById('qrcode');
  box.innerHTML = '';
  // QR не должен блокировать показ ссылки: если библиотека не загрузилась или текст слишком длинный, остаётся ссылка и кнопки
  try {
    new QRCode(box, {text, width: 170, height: 170, colorDark: '#111317', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.L});
    document.getElementById('ul-qr-caption').textContent = caption;
  } catch (e) {
    document.getElementById('ul-qr-caption').textContent = 'QR сейчас недоступен: скопируйте ссылку и вставьте её в приложение';
  }
}

async function showUserLinks(id) {
  const r = await api('GET', `/api/v1/users/${id}/links`);
  if (!r.ok) return;
  const d = r.data;
  document.getElementById('qr-modal-title').textContent = d.user.name;
  document.getElementById('ul-sub').value = d.sub_url;
  renderAppButtons(d.sub_url, 'Kitsune');
  drawQR(d.sub_url, 'QR подписки (все протоколы)');
  document.getElementById('ul-links').innerHTML = d.links.length ? d.links.map((l, i) => `
    <div class="link-row"${(l.configs || []).length ? ' style="flex-wrap:wrap"' : ''}>
      <div class="lt"${(l.configs || []).length ? ' style="flex:1 1 100%"' : ''}>${esc(l.title)} · ${esc(l.tag)}<small>${l.note ? esc(l.note) : (l.uri ? esc(l.uri.slice(0, 64)) + '…' : (l.config ? 'файл настроек .conf' : ((l.configs || []).length ? 'готовый конфиг для приложения: выберите версию ниже' : 'ссылка недоступна для этого протокола')))}</small></div>
      ${l.config ? `<a class="btn-mini" href="/api/v1/users/${d.user.id}/awg/${l.inbound_id}">.conf</a><button onclick="copyText(window.__confs[${i}])">Копировать конфиг</button>` : ''}
      ${(l.configs || []).length ? `<div style="flex-basis:100%;display:flex;gap:6px;flex-wrap:wrap">${l.configs.map((c, j) => `<button onclick="copyText(window.__cfgs[${i}][${j}])">${esc(c.label)}</button>`).join('')}</div>` : ''}
      ${l.uri ? `<button onclick="copyText(window.__links[${i}])">${l.kind === 'awg' || l.kind === 'awg3' ? 'vpn://' : 'Копировать'}</button><button onclick="drawQR(window.__links[${i}], '${escJs(l.title)}')">QR</button>` : ''}
    </div>`).join('') : '<div style="color:var(--text-muted);font-size:13px">Подключений пока нет – создайте их во вкладке «Подключения».</div>';
  window.__confs = d.links.map(l => l.config || '');
  window.__cfgs = d.links.map(l => (l.configs || []).map(c => c.text));
  window.__links = d.links.map(l => l.uri);
  loadUserDevices(d.user.id);
  openModal('qr-modal');
}

// Устройства, которые сами назвались при загрузке подписки (Happ, INCY и похожие приложения).
async function loadUserDevices(id) {
  const box = document.getElementById('ul-devices-box'), list = document.getElementById('ul-devices');
  const r = await api('GET', `/api/v1/users/${id}/devices`);
  const dev = (r.ok && r.data.devices) || [];
  box.style.display = dev.length ? '' : 'none';
  const when = ms => ms ? new Date(ms).toLocaleString('ru-RU', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) : '–';
  list.innerHTML = dev.map(x => `<div class="link-row"><div class="lt">${esc(x.model || x.os || 'Устройство')}${x.os_version ? ' · ' + esc(x.os + ' ' + x.os_version) : ''}<small>был ${when(x.last_seen)} · ${esc(x.hwid.slice(0, 12))}…</small></div><button data-device-id="${Number(x.id)}">Удалить</button></div>`).join('');
  list.dataset.userId = id;
  list.onclick = e => {
    const b = e.target.closest('button[data-device-id]');
    if (b) deleteUserDevice(Number(list.dataset.userId), Number(b.dataset.deviceId));
  };
}

async function deleteUserDevice(id, deviceId) {
  if (!await uiConfirm('Удалить устройство?', 'Оно сможет подключиться заново, если лимит позволяет.', 'Удалить', true)) return;
  const r = await api('DELETE', `/api/v1/users/${id}/devices/${deviceId}`);
  if (!r.ok) uiAlert('Не удалось удалить устройство', r.data.error || 'Ошибка'); else toast('Устройство удалено');
  loadUserDevices(id);
}
