/* ---------- Верхняя пилюля (оформление «Стекло»): статус, поиск, тон, колокольчик ---------- */

// Статус сервера: обновляется каждый раз, когда главная получает метрики
function setTopStatus(level, firstRun) {
  const b = document.getElementById('gtop-status'); if (!b) return;
  b.dataset.level = level;
  document.getElementById('gtop-status-tx').textContent =
    level === 'ok' ? 'Всё работает' : (level === 'bad' ? 'Есть проблема' : (firstRun ? 'Нужна настройка' : 'Нужно внимание'));
}

// Переключатель тона: Рассвет, Ночь
document.addEventListener('click', e => {
  const b = e.target.closest && e.target.closest('#gtop-tone [data-tone]');
  if (b) setTheme('glass', b.dataset.tone);
});
function markTopTone() {
  const d = document.documentElement;
  document.querySelectorAll('#gtop-tone [data-tone]').forEach(b => b.classList.toggle('on', d.dataset.theme === 'glass' && b.dataset.tone === d.dataset.tone));
}

document.addEventListener('DOMContentLoaded', markTopTone);

/* ---------- Поиск: пользователи и подключения ---------- */
let gsData = {users: [], inbounds: [], at: 0}, gsItems = [], gsSel = -1;

async function gSearchLoad() {
  if (Date.now() - gsData.at < 20000) return;
  gsData.at = Date.now();
  try {
    const [u, i] = await Promise.all([fetch('/api/v1/users'), fetch('/api/v1/inbounds')]);
    if (u.ok) gsData.users = (await u.json()).users || [];
    if (i.ok) gsData.inbounds = (await i.json()).inbounds || [];
  } catch (e) { gsData.at = 0; }
}

function gSearchOpen() { gSearchLoad().then(() => gSearch(document.getElementById('gsearch').value)); }

function gSearch(q) {
  const box = document.getElementById('gsearch-res');
  q = (q || '').trim().toLowerCase();
  gsItems = []; gsSel = -1;
  if (!q) { box.hidden = true; box.innerHTML = ''; return; }
  const us = gsData.users.filter(u => (u.name + ' ' + (u.note || '')).toLowerCase().includes(q)).slice(0, 6);
  const ibs = gsData.inbounds.filter(i => [i.tag, i.title, i.kind, i.settings && i.settings.sni].join(' ').toLowerCase().includes(q)).slice(0, 6);
  us.forEach(u => gsItems.push({type: 'user', title: u.name, sub: u.note || (u.protocols + ' подключ.'), run: () => { goTabClients(u.name); }}));
  ibs.forEach(i => gsItems.push({type: 'inbound', title: i.tag, sub: `${i.title || i.kind} · порт ${i.port}`, run: () => goTabInbounds()}));
  const row = (it, n) => `<button type="button" class="gs-item" role="option" data-n="${n}" onmousedown="event.preventDefault(); gSearchPick(${n})"><b>${esc(it.title)}</b><small>${esc(it.sub)}</small></button>`;
  let html = '', n = 0;
  if (us.length) { html += '<div class="gs-h">Пользователи</div>' + us.map(u => row(gsItems[n], n++)).join(''); }
  if (ibs.length) { html += '<div class="gs-h">Подключения</div>' + ibs.map(i => row(gsItems[n], n++)).join(''); }
  box.innerHTML = html || '<div class="gs-empty">Ничего не найдено</div>';
  box.hidden = false;
}

function goTabClients(name) {
  const tab = document.querySelector('#nav-container [data-tab=clients]');
  navigateTo('clients', tab);
  const inp = document.getElementById('u-search'); if (inp) { inp.value = name; if (typeof renderUsers === 'function') renderUsers(); }
}
function goTabInbounds() { navigateTo('inbounds', document.querySelector('#nav-container [data-tab=inbounds]')); }

function gSearchPick(n) {
  const it = gsItems[n]; if (!it) return;
  it.run();
  const inp = document.getElementById('gsearch'); inp.value = ''; inp.blur();
  document.getElementById('gsearch-res').hidden = true;
}
function gSearchKey(e) {
  const box = document.getElementById('gsearch-res');
  if (e.key === 'Escape') { box.hidden = true; e.target.blur(); return; }
  if (!gsItems.length) return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    gsSel = (gsSel + (e.key === 'ArrowDown' ? 1 : -1) + gsItems.length) % gsItems.length;
    box.querySelectorAll('.gs-item').forEach(b => b.classList.toggle('sel', Number(b.dataset.n) === gsSel));
  }
  if (e.key === 'Enter') { e.preventDefault(); gSearchPick(gsSel >= 0 ? gsSel : 0); }
}
document.addEventListener('click', e => {
  if (!e.target.closest || e.target.closest('.gtop-search')) return;
  const box = document.getElementById('gsearch-res'); if (box) box.hidden = true;
});
