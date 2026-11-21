/* ---------- Обновление панели ---------- */
async function loadUpdateSettings() {
  const res = await fetch('/api/v1/system/update/check');
  const d = await res.json().catch(() => ({}));
  const cur = d.current || (d.info && d.info.current);
  if (cur) {
    document.getElementById('settings-version').textContent = 'v' + fmtVer(cur);
    document.getElementById('update-status').textContent = 'Текущая версия: v' + fmtVer(cur);
  }
}

async function checkUpdate() {
  const st = document.getElementById('update-status');
  st.textContent = 'Проверяю…';
  const res = await fetch('/api/v1/system/update/check');
  const d = await res.json();
  const btn = document.getElementById('update-apply-btn');
  btn.style.display = 'none';
  if (!res.ok) { st.textContent = 'Ошибка: ' + (d.error || res.status); return; }
  const i = d.info;
  if (i.available) {
    st.innerHTML = `Доступна версия <b>v${esc(i.latest)}</b> (у вас v${esc(fmtVer(i.current))}).${i.notes ? '<br>' + esc(i.notes) : ''}${i.signed ? '' : '<br>Подпись релиза не проверяется: в этой сборке не задан ключ издателя.'}`;
    btn.style.display = '';
  } else {
    st.textContent = 'Установлена последняя версия v' + fmtVer(i.current);
  }
}

async function applyUpdate() {
  if (!await uiConfirm('Обновить панель?', 'Перед этим будет сделана копия базы, панель перезапустится на несколько секунд.', 'Обновить')) return;
  await doApplyUpdate();
}

// Версия в меню: по клику проверяет, не вышла ли новая, и предлагает обновиться
async function checkVersionClick() {
  const els = [...document.querySelectorAll('.js-ver')], el = els[0];
  if (!el || el.dataset.busy) return;
  els.forEach(e => { e.dataset.busy = '1'; });
  const labels = els.map(e => e.textContent);
  els.forEach(e => { e.textContent = 'Проверяю…'; });
  try {
    const res = await fetch('/api/v1/system/update/check');
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { uiAlert('Не удалось проверить обновления', String(d.error || res.status)); return; }
    const i = d.info || {};
    if (i.available) {
      const text = `У вас v${fmtVer(i.current)}.` + (i.notes ? '\n' + i.notes : '') + '\n\nПеред обновлением будет сделана копия базы, панель перезапустится на несколько секунд.';
      if (await uiConfirm(`Вышла версия v${fmtVer(i.latest)}`, text, 'Обновить')) await doApplyUpdate();
    } else {
      toast('Установлена последняя версия v' + fmtVer(i.current));
    }
  } catch (e) {
    uiAlert('Не удалось проверить обновления', 'Нет связи с панелью');
  } finally {
    els.forEach((e, i) => { e.textContent = labels[i]; delete e.dataset.busy; });
  }
}

// Обновление с видимым ходом: панель на время замены бинарника недоступна, пользователь должен видеть, что происходит.
function updOverlay(title, text, spin) {
  let o = document.getElementById('upd-overlay');
  if (!o) {
    o = document.createElement('div');
    o.id = 'upd-overlay'; o.className = 'upd-overlay'; o.setAttribute('role', 'alertdialog'); o.setAttribute('aria-live', 'polite');
    o.innerHTML = '<div class="upd-box"><div class="upd-spin" aria-hidden="true"></div><h3 id="upd-title"></h3><p id="upd-text"></p><button class="btn" id="upd-close" style="display:none" onclick="document.getElementById(\'upd-overlay\').remove()">Закрыть</button></div>';
    document.body.appendChild(o);
  }
  o.querySelector('#upd-title').textContent = title;
  o.querySelector('#upd-text').textContent = text;
  o.querySelector('.upd-spin').style.display = spin ? '' : 'none';
  o.querySelector('#upd-close').style.display = spin ? 'none' : '';
}
async function doApplyUpdate() {
  let before = '';
  try { const c = await (await fetch('/api/v1/system/update/status')).json(); before = c.current || ''; } catch (e) {}
  updOverlay('Обновляю панель', 'Делаю копию базы, скачиваю и проверяю новую версию…', true);
  let res, d;
  try { res = await fetch('/api/v1/system/update/apply', {method: 'POST'}); d = await res.json().catch(() => ({})); }
  catch (e) { res = null; d = {}; }
  if (res && !res.ok) { document.getElementById('upd-overlay').remove(); uiAlert('Не удалось обновить', String(d.error || res.status)); return; }
  // Панель перезапустится: ждём, пока она сначала пропадёт (или сразу покажет новую версию), а потом снова ответит.
  const t0 = Date.now(); let wentDown = !res;
  const tick = async () => {
    const waited = Math.round((Date.now() - t0) / 1000);
    try {
      const r = await fetch('/api/v1/system/update/status', {cache: 'no-store'});
      const c = await r.json().catch(() => ({}));
      const cur = c.current || '';
      if (r.ok && cur && (cur !== before || wentDown)) {
        updOverlay('Готово', 'Панель обновлена до v' + fmtVer(cur) + '. Страница сейчас перезагрузится.', false);
        setTimeout(() => location.reload(), 1500);
        return;
      }
    } catch (e) {
      if (!wentDown) { wentDown = true; updOverlay('Перезапускаю панель', 'Новая версия установлена, панель включается. Обычно это занимает несколько секунд.', true); }
    }
    if (waited > 120) {
      updOverlay('Панель отвечает слишком долго', 'Подождите ещё немного и обновите страницу. Если не открывается, зайдите на сервер по SSH и выполните kit status (состояние) или kit log (журнал). Копия базы перед обновлением сохранена.', false);
      return;
    }
    setTimeout(tick, 2000);
  };
  setTimeout(tick, 2500);
}

/* ---------- Адрес сервера ---------- */
async function loadServerSettings() {
  const r = await api('GET', '/api/v1/settings/server');
  if (r.ok) document.getElementById('srv-host').value = r.data.public_host || '';
  document.getElementById('srv-host').placeholder = r.ok ? ('сейчас: ' + r.data.effective) : '';
}
async function saveServerHost() {
  const r = await api('PUT', '/api/v1/settings/server', {public_host: document.getElementById('srv-host').value});
  notify(r);
}

/* ---------- Маскировка ---------- */
async function loadMasking() {
  loadCustomStub();
  loadSelfSteal();
  const r = await api('GET', '/api/v1/masking');
  if (!r.ok) return;
  const d = r.data;
  window.__reality = d.reality;
  document.getElementById('mk-current').innerHTML = d.reality.length
    ? 'Сейчас: ' + d.reality.map(x => `<b>${esc(x.tag)}</b> – ${esc(x.sni)}`).join(' · ')
    : 'REALITY-подключений пока нет – создайте их во вкладке «Подключения» или «Быстрой настройкой».';
  const sel = document.getElementById('mk-stub');
  sel.innerHTML = d.stubs.map(t => `<option value="${esc(t.id)}" ${t.id === d.stub ? 'selected' : ''}>${esc(t.title)}</option>`).join('');
}
async function loadSelfSteal() {
  const r = await api('GET', '/api/v1/masking/selfsteal');
  const st = document.getElementById('mk-self-state'), off = document.getElementById('mk-self-off'), inp = document.getElementById('mk-self');
  if (!r.ok || !st) return;
  const d = r.data.domain || '';
  st.textContent = d ? 'Сейчас включён сайт на домене ' + d + '.' : 'Сейчас выключен.';
  if (off) off.style.display = d ? '' : 'none';
  if (inp && d && !inp.value) inp.value = d;
}
async function enableSelfSteal() {
  const dom = document.getElementById('mk-self').value.trim();
  if (!dom) { uiAlert('Сайт на своём домене', 'Введите домен, например vpn.example.com'); return; }
  if (!await uiConfirm('Включить сайт на домене ' + dom + '?', 'Панель выпустит сертификат Let\'s Encrypt (до минуты), поднимет заглушку и переключит REALITY на неё. Прежнее имя сайта ещё неделю принимается сервером, клиентам нужно будет обновить подписку.', 'Включить')) return;
  toast('Выпускаю сертификат, это может занять до минуты…');
  const r = await api('POST', '/api/v1/masking/selfsteal', {domain: dom});
  await uiAlert(r.ok ? 'Готово' : 'Не получилось', r.ok ? r.data.message : ((r.data && r.data.error) || 'Ошибка'));
  loadMasking(); loadSelfSteal();
}
async function disableSelfSteal() {
  if (!await uiConfirm('Выключить сайт на своём домене?', 'REALITY переключится на обычный сайт из списка. Клиентам нужно будет обновить подписку.', 'Выключить', true)) return;
  const r = await api('DELETE', '/api/v1/masking/selfsteal');
  await uiAlert(r.ok ? 'Готово' : 'Не получилось', r.ok ? r.data.message : ((r.data && r.data.error) || 'Ошибка'));
  loadMasking(); loadSelfSteal();
}
async function scanMasking() {
  if (!await uiConfirm('Искать среди соседей по подсети?', 'Панель отправит короткие TLS-запросы (до 253 штук, по 16 одновременно) на соседние адреса вашего хостера, чтобы найти сайт с TLS 1.3 и HTTP/2. Хостер может видеть эти запросы. Если не хотите этого, выберите сайт из списка или укажите свой.', 'Искать')) return;
  const box = document.getElementById('mk-candidates');
  box.innerHTML = '<div style="color:var(--text-muted);font-size:13px">Ищу соседей по подсети (около минуты)…</div>';
  const r = await api('POST', '/api/v1/masking/scan', {confirm: true});
  if (!r.ok) { box.innerHTML = `<div style="color:var(--accent-rose);font-size:13px">${esc(r.data.error || 'Ошибка')}</div>`; return; }
  const c = r.data.candidates || [];
  const others = (window.__reality || []).filter(x => x.kind !== 'vless-reality');
  box.innerHTML = c.length ? c.map(x => `<div class="link-row"><div class="lt">${esc(x.domain)}<small>${esc(x.ip)} · ${x.latency_ms} мс</small></div><button onclick="setMaskingSNI('${escJs(x.domain)}', false)">Для REALITY</button>${others.map(o => `<button onclick="setMaskingSNI('${escJs(x.domain)}', false, false, ${o.id})">Для ${esc(o.tag)}</button>`).join('')}</div>`).join('')
    : '<div style="color:var(--text-muted);font-size:13px">Подходящих соседей не нашлось – воспользуйтесь «Случайный из списка» или укажите свой сайт.</div>';
}
async function setMaskingSNI(sni, random, force, inboundId) {
  const r = await api('POST', '/api/v1/masking/sni' + (force ? '?force=1' : ''), {sni, random, inbound_id: inboundId || 0});
  if (r.status === 409 && r.data.needs_force) {
    if (await uiConfirm('Применить всё равно?', r.data.error, 'Применить')) return setMaskingSNI(sni, random, true, inboundId);
    return;
  }
  notify(r);
  loadMasking();
}
async function setStub(id) {
  const r = await api('PUT', '/api/v1/masking/stub', {id});
  toast(r.ok ? 'Заглушка применена' : (r.data.error || 'Ошибка'));
}

async function randomStub() {
  const r = await api('POST', '/api/v1/masking/stub/random');
  toast(r.ok ? r.data.message : (r.data.error || 'Ошибка'));
  if (r.ok) { loadMasking(); previewCurrentStub(); }
}
async function previewCurrentStub() {
  const r = await api('GET', '/api/v1/masking/stub/page');
  if (!r.ok) { toast(r.data.error || 'Не удалось показать заглушку'); return; }
  const fr = document.getElementById('mk-preview');
  document.getElementById('mk-custom-box').open = true;
  fr.style.display = 'block';
  fr.srcdoc = r.data.html; // iframe с sandbox: скрипты не выполняются
}

/* ---------- Порты ---------- */
async function loadPortMode() {
  const r = await api('GET', '/api/v1/settings/port-mode');
  if (r.ok) document.getElementById('pm-mode').value = r.data.mode;
}
async function savePortMode() {
  const r = await api('PUT', '/api/v1/settings/port-mode', {mode: document.getElementById('pm-mode').value});
  notify(r);
}

/* ---------- Резервная копия ---------- */
async function downloadBackup() {
  const pw = document.getElementById('backup-pass').value;
  if (pw && pw.length < 8) { uiAlert('Копия', 'Пароль копии: не меньше 8 символов'); return; }
  if (!pw && !await uiConfirm('Копия без пароля', 'Файл будет не зашифрован: в нём ключи и пароли. Хранить его надо как секрет. Скачать без пароля?', 'Скачать', true)) return;
  const res = await fetch('/api/v1/backup/export', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password: pw})});
  if (!res.ok) { const d = await res.json().catch(() => ({})); uiAlert('Ошибка', d.error || 'Не удалось сделать копию'); return; }
  const blob = await res.blob();
  const m = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = m ? m[1] : 'kitsune-backup'; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  document.getElementById('backup-pass').value = '';
}

/* ---------- Восстановление ---------- */
async function restoreBackup() {
  const f = document.getElementById('restore-file').files[0];
  if (!f) { uiAlert('Копия', 'Выберите файл копии'); return; }
  if (!await uiConfirm('Заменить данные панели?', 'Текущие данные заменятся данными из копии. Перед заменой сохранится копия нынешней базы (папка backups).', 'Заменить', true)) return;
  const fd = new FormData();
  fd.append('file', f);
  const pw = document.getElementById('restore-pass');
  if (pw && pw.value) fd.append('password', pw.value);
  const res = await fetch('/api/v1/backup/restore', {method: 'POST', body: fd});
  const d = await res.json().catch(() => ({}));
  notify({ok: res.ok, data: d}, 'Ошибка восстановления');
  if (res.ok) location.reload();
}

/* ---------- Ядра ---------- */
function coreBadge(c) {
  if (c.running) return ['chip-active', 'Работает'];
  if (!c.platform) return ['chip-idle', 'Только Linux'];
  if (!c.installed) return ['chip-idle', 'Не установлено'];
  if (!c.needed) return ['chip-idle', 'Не используется'];
  return ['chip-inactive', 'Остановлено'];
}

// Последние выпуски ядер (подсказка): id панели → запись; mtg и telemt – отдельные ядра, mtproto показывает оба
let coreLatest = {};
async function loadCoreLatest() {
  const r = await api('GET', '/api/v1/cores/latest');
  coreLatest = {};
  if (r.ok) (r.data.latest || []).forEach(l => { coreLatest[l.id] = l; });
}
// Подсказка только у Xray: с 26.7.x клиенты Mihomo и sing-box могли не проходить REALITY. У остальных ядер текста нет.
function coreLatestNote(id) {
  const l = coreLatest[id];
  return id === 'xray' && l && l.newer
    ? '<div class="core-warn">⚠ Вышла новая версия Xray' + (l.fresh ? ' (меньше 3 суток, не проверена)' : '') + '. Начиная с 26.9.8 REALITY не принимает клиентов без ключа X25519MLKEM768: Karing, Hiddify и другие приложения на ядре sing-box не подключатся (клиенты на Mihomo и Xray работают). Перед обновлением проверьте своё приложение; вернуться можно кнопкой «Откатить до проверенной».</div>' : '';
}

/* Карточки ядер: клик раскрывает настройки ядра; «Работает» и «Обновить» видны и в свёрнутом, и в раскрытом виде */
let coreOpen = new Set();
try { coreOpen = new Set(JSON.parse(localStorage.getItem('kitsune-cores-open') || '[]')); } catch (e) {}
let coreList = [], coreInbounds = [];

function coreCanRollback(c) { const l = coreLatest[c.id]; return c.id === 'xray' && c.installed && c.platform && l && l.can_rollback && l.verified; }
function coreCanUpdate(c) { return c.installed && c.platform && coreLatest[c.id] && coreLatest[c.id].newer; }
// Значки ядер одноцветные: маска из знака автора (аватар организации на GitHub: xray, sing-box, telemt, AmneziaWG) или наш нейтральный значок (mtg, mita); цвет берётся из темы
const CORE_ICONS = {xray: 'xray.png', singbox: 'singbox.png', masque: 'singbox.png', telemt: 'telemt.png', awg: 'awg.png', mtg: 'mtg.svg', mita: 'mita.svg'};
const coreIcon = id => CORE_ICONS[id] ? `<span class="core-tile" aria-hidden="true"><span class="core-gl" style="--m:url('/static/cores/${CORE_ICONS[id]}')"></span></span>` : '';

function drawCores(cores) {
  coreList = cores;
  const stash = document.getElementById('core-stash'), x = document.getElementById('core-pane-xray');
  if (x && stash && x.parentNode !== stash) stash.appendChild(x);   // не терять форму Xray при перерисовке
  document.getElementById('cores-table').innerHTML = cores.map(c => {
    const b = coreBadge(c), open = coreOpen.has(c.id);
    return `<div class="core-card${open ? ' open' : ''}" id="core-card-${c.id}">
      <div class="core-head" role="button" tabindex="0" aria-expanded="${open}" onclick="toggleCore('${c.id}')" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleCore('${c.id}')}">
        <span class="core-chev">▸</span>
        ${coreIcon(c.id)}
        <div class="lt"><b>${esc(c.title)}</b> ${esc(c.version)}<small>${esc(c.used)}${!c.running && !c.needed && c.installed ? ' – запустится, когда появится подходящее подключение' : ''}</small>${coreLatestNote(c.id)}</div>
        <span class="status-chip ${b[0]}">${b[1]}</span>
        ${!c.installed && c.platform ? `<button class="btn sm" onclick="event.stopPropagation();installCore('${c.id}')">Установить</button>` : ''}
        ${coreCanUpdate(c) ? `<button class="btn sm" onclick="event.stopPropagation();updateCore('${c.id}')">Обновить</button>` : ''}
        ${coreCanRollback(c) ? `<button class="btn sm soft" title="Вернуть версию, которую мы проверяли (${esc(coreLatest[c.id].verified)})" onclick="event.stopPropagation();rollbackCore('${c.id}')">Откатить до проверенной</button>` : ''}
      </div>
      <div class="core-body" id="core-body-${c.id}"${open ? '' : ' hidden'}></div>
    </div>`;
  }).join('');
  cores.forEach(c => { if (coreOpen.has(c.id)) fillCoreBody(c.id); });
}
function toggleCore(id) {
  if (coreOpen.has(id)) coreOpen.delete(id); else coreOpen.add(id);
  try { localStorage.setItem('kitsune-cores-open', JSON.stringify([...coreOpen])); } catch (e) {}
  const card = document.getElementById('core-card-' + id), open = coreOpen.has(id);
  if (!card) return;
  card.classList.toggle('open', open);
  card.querySelector('.core-head').setAttribute('aria-expanded', open);
  card.querySelector('.core-body').hidden = !open;
  if (open) fillCoreBody(id);
}
/* Настройки ядер (кроме Xray): поля по документации ядер; сервер проверяет значения и перезапускает ядро.
   Пустое значение в полях-длительностях и DNS значит «как по умолчанию у ядра». */
const LOG_HINT = 'Подробный журнал помогает при поиске неполадок, но растёт быстрее.';
const CORE_FIELDS = {
  singbox: [
    {k: 'log_level', t: 'select', label: 'Уровень журнала', opts: ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'panic'], hint: LOG_HINT},
    {k: 'log_timestamp', t: 'bool', label: 'Время в строках журнала'},
    {k: 'tcp_fast_open', t: 'bool', label: 'TCP Fast Open для NaiveProxy', hint: 'Ускоряет установку соединения; нужен Linux 3.7 и новее.'},
  ],
  mtg: [
    {k: 'debug', t: 'bool', label: 'Подробный журнал (debug)'},
    {k: 'dns', t: 'text', label: 'DNS для ядра', ph: 'https://1.1.1.1', hint: 'IP, https://… (DoH) или tls://… (DoT). Пусто – системный DNS.'},
    {k: 'timeout_idle', t: 'text', label: 'Простой соединения', ph: '5m', hint: 'Через сколько без данных соединение закрывается. Пусто – 5m.'},
    {k: 'timeout_handshake', t: 'text', label: 'Время на рукопожатие', ph: '10s', hint: 'Пусто – 10s.'},
    {k: 'tolerate_time_skewness', t: 'text', label: 'Допуск расхождения часов клиента', ph: '3s', hint: 'Пусто – 3s. Больше допуск – легче клиентам с неточными часами, но шире окно для повторов.'},
    {k: 'allow_fallback_unknown_dc', t: 'bool', label: 'Неизвестные дата-центры Telegram отправлять в любой'},
    {k: 'anti_replay', t: 'bool', label: 'Защита от повторов', hint: 'Рекомендуется держать включённой.'},
    {k: 'blocklist', t: 'bool', label: 'Чёрный список адресов FireHOL', hint: 'Подключения из этого списка получают страницу маскировки. Список скачивается раз в сутки.'},
  ],
  mita: [
    {k: 'logging_level', t: 'select', label: 'Уровень журнала', opts: ['INFO', 'WARN', 'ERROR', 'DEBUG'], hint: LOG_HINT},
    {k: 'dns_dual_stack', t: 'select', label: 'IPv4 и IPv6 при разрешении имён', opts: [['', 'по умолчанию (USE_FIRST_IP)'], 'PREFER_IPv4', 'PREFER_IPv6', 'ONLY_IPv4', 'ONLY_IPv6'], hint: 'Значение пишется в конфиг только если выбрано.'},
    {k: 'user_hint_mandatory', t: 'bool', label: 'Требовать подсказку пользователя', hint: 'Снижает нагрузку при многих пользователях, но старые клиенты Mieru без подсказки подключаться перестанут.'},
  ],
  telemt: [
    {k: 'log_level', t: 'select', label: 'Уровень журнала', opts: ['debug', 'verbose', 'normal', 'silent'], hint: LOG_HINT},
    {k: 'use_middle_proxy', t: 'bool', label: 'Работать через middle-proxy Telegram', hint: 'Выключите, чтобы ходить к дата-центрам напрямую.'},
    {k: 'ipv6', t: 'bool', label: 'Использовать IPv6'},
    {k: 'prefer', t: 'select', num: true, label: 'Какие адреса предпочитать', opts: [[4, 'IPv4'], [6, 'IPv6']]},
    {k: 'max_connections', t: 'int', label: 'Предел одновременных соединений', hint: '0 – без предела. По умолчанию 10000.'},
  ],
  awg: [
    {k: 'log_level', t: 'select', label: 'Уровень журнала устройства', opts: [['silent', 'silent (ничего)'], ['error', 'error (по умолчанию)'], ['verbose', 'verbose (подробно)']], hint: 'Параметры обфускации (Jc, S1, H1 и другие) задаются в самом подключении.'},
  ],
};
let coreSettingsCache = null;

function coreFieldHtml(id, f, v) {
  const name = `cs-${id}-${f.k}`;
  const hint = f.hint ? `<small style="display:block;color:var(--text-muted);margin-top:4px;">${esc(f.hint)}</small>` : '';
  if (f.t === 'bool') return `<label class="check-row"><input type="checkbox" id="${name}" ${v ? 'checked' : ''}> ${esc(f.label)}</label>${hint}`;
  if (f.t === 'select') {
    const opts = f.opts.map(o => Array.isArray(o) ? o : [o, o]).map(([val, lab]) => `<option value="${esc(val)}" ${String(val) === String(v) ? 'selected' : ''}>${esc(lab)}</option>`).join('');
    return `<div class="form-group"><label>${esc(f.label)}</label><select id="${name}" class="form-control">${opts}</select>${hint}</div>`;
  }
  return `<div class="form-group"><label>${esc(f.label)}</label><input id="${name}" class="form-control" type="${f.t === 'int' ? 'number' : 'text'}" ${f.t === 'int' ? 'min="0"' : ''} placeholder="${esc(f.ph || '')}" value="${esc(v == null ? '' : v)}" spellcheck="false" autocomplete="off">${hint}</div>`;
}
async function loadCoreSettingsCache() {
  const r = await api('GET', '/api/v1/cores/settings');
  coreSettingsCache = r.ok ? r.data : null;
}
function coreSettingsCard(id) {
  const fields = CORE_FIELDS[id];
  if (!fields || !coreSettingsCache) return '';
  const cur = coreSettingsCache.settings[id] || {};
  return `<div class="settings-card"><h3>Настройки</h3>
    <p>Значения проверяются перед сохранением; после сохранения ядро перезапускается и подключения на нём кратко прервутся.</p>
    ${fields.map(f => coreFieldHtml(id, f, cur[f.k])).join('')}
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:6px;">
      <button class="btn-banner" onclick="saveCoreSettings('${id}')">Сохранить и перезапустить</button>
      <button class="btn-banner" onclick="resetCoreSettings('${id}')" style="background: var(--surface-inset); color: var(--text-main); box-shadow: none;">Вернуть по умолчанию</button>
    </div></div>`;
}
async function saveCoreSettings(id) {
  const body = {};
  CORE_FIELDS[id].forEach(f => {
    const el = document.getElementById(`cs-${id}-${f.k}`);
    if (f.t === 'bool') body[f.k] = el.checked;
    else if (f.t === 'int' || f.num) body[f.k] = parseInt(el.value, 10) || 0;
    else body[f.k] = el.value.trim();
  });
  const r = await api('PUT', `/api/v1/cores/settings/${id}`, body);
  await uiAlert(r.ok ? 'Готово' : 'Не сохранилось', r.ok ? r.data.message : (r.data.error || 'Не удалось сохранить'));
  if (r.ok) { await loadCoreSettingsCache(); loadCores(); loadSystemStatus(); }
}
function resetCoreSettings(id) {
  const d = coreSettingsCache && coreSettingsCache.defaults[id];
  if (!d) return;
  CORE_FIELDS[id].forEach(f => {
    const el = document.getElementById(`cs-${id}-${f.k}`), v = d[f.k];
    if (f.t === 'bool') el.checked = !!v; else el.value = v == null ? '' : v;
  });
}

async function fillCoreBody(id) {
  const body = document.getElementById('core-body-' + id);
  if (!body) return;
  if (id === 'xray') { body.appendChild(document.getElementById('core-pane-xray')); return; }
  const [ri] = await Promise.all([api('GET', '/api/v1/inbounds'), loadCoreSettingsCache()]);
  coreInbounds = ri.ok ? (ri.data.inbounds || []) : [];
  const mine = coreInbounds.filter(ib => ib.core === id);
  body.innerHTML = coreSettingsCard(id) + '<div class="settings-card"><h3>Подключения</h3><div style="display:flex;flex-direction:column;gap:6px;">' + (mine.length
    ? mine.map(ib => `<div class="link-row"><div class="lt"><b>${esc(ib.tag)}</b><small>${esc(ib.title || ib.kind)} · порт ${ib.port}</small></div><span class="status-chip ${ib.enable ? 'chip-active' : 'chip-idle'}">${ib.enable ? 'Включено' : 'Выключено'}</span></div>`).join('')
    : '<p>Подключений на этом ядре пока нет. Ядро скачается само, когда вы создадите подходящее подключение.</p>') + '</div></div>';
}
async function loadCores() {
  const r = await api('GET', '/api/v1/cores');
  if (!r.ok) return;
  drawCores(r.data.cores);                    // таблица сразу, без ожидания GitHub
  await loadCoreLatest();
  drawCores(r.data.cores);
}
async function updateCore(id) {
  const l = coreLatest[id] || {}, fresh = !!l.fresh, name = (coreList.find(c => c.id === id) || {}).title || id;
  const ok = fresh
    ? await uiConfirm(`Поставить ${name} ${l.latest}?`, `Версия вышла меньше 3 суток назад, мы её ещё не проверяли: ошибки в свежем выпуске могут сломать подключения.${id === 'xray' ? '\n\nУ Xray с 26.7.x REALITY мог не проходить у клиентов Mihomo и sing-box. После обновления проверьте клиентом (вкладка «Здоровье»).' : ''}\n\nЗагрузка проверяется по SHA-256, ядро перезапустится.`, 'Всё равно поставить')
    : await uiConfirm(`Обновить ${name}${l.latest ? ' до ' + l.latest : ''}?`, 'Загрузка проверяется по SHA-256. Ядро перезапустится, подключения на нём кратко прервутся.', 'Обновить');
  if (ok) installCore(id, fresh);
}
async function rollbackCore(id) {
  const l = coreLatest[id] || {}, name = (coreList.find(c => c.id === id) || {}).title || id;
  if (!await uiConfirm(`Вернуть ${name} к проверенной версии ${l.verified}?`, `Сейчас стоит ${l.pinned}. Откат ставит версию, на которой мы проверяли Kitsune: загрузка сверяется с контрольной суммой, зашитой в панель. Ядро перезапустится, подключения на нём кратко прервутся.`, 'Откатить', true)) return;
  toast('Скачиваю проверенную версию…');
  const r = await api('POST', `/api/v1/cores/${id}/install?pinned=1`);
  await uiAlert(r.ok ? 'Готово' : 'Не получилось', r.ok ? r.data.message : (r.data.error || 'Ошибка'));
  await loadCoreLatest(); loadCores(); loadSystemStatus();
}
async function installCore(id, fresh) {
  toast('Скачиваю ядро…');
  const r = await api('POST', `/api/v1/cores/${id}/install${fresh ? '?fresh=1' : ''}`);
  await uiAlert(r.ok ? 'Готово' : 'Не получилось', r.ok ? r.data.message : (r.data.error || 'Ошибка'));
  loadCores(); loadSystemStatus();
}

/* ---------- HTTPS панели ---------- */
async function loadPanelTLS() {
  const r = await api('GET', '/api/v1/settings/panel-tls');
  if (!r.ok) return;
  const c = r.data.config;
  document.getElementById('tls-mode').value = c.mode || 'off';
  document.getElementById('tls-domain').value = c.domain || '';
  document.getElementById('tls-email').value = c.email || '';
  document.getElementById('tls-cert').value = c.cert_file || '';
  document.getElementById('tls-key').value = c.key_file || '';
  document.getElementById('tls-port').value = c.port || 8443;
  document.getElementById('tls-redirect').checked = !!c.redirect;
  renderTLSMode();
}
function renderTLSMode() {
  const m = document.getElementById('tls-mode').value;
  document.getElementById('tls-acme').style.display = m === 'acme' ? 'flex' : 'none';
  document.getElementById('tls-custom').style.display = m === 'custom' ? 'flex' : 'none';
  document.getElementById('tls-common').style.display = m === 'off' ? 'none' : 'flex';
}
async function savePanelTLS() {
  const body = {
    mode: document.getElementById('tls-mode').value,
    domain: document.getElementById('tls-domain').value.trim(),
    email: document.getElementById('tls-email').value.trim(),
    cert_file: document.getElementById('tls-cert').value.trim(),
    key_file: document.getElementById('tls-key').value.trim(),
    port: parseInt(document.getElementById('tls-port').value) || 8443,
    redirect: document.getElementById('tls-redirect').checked
  };
  const r = await api('PUT', '/api/v1/settings/panel-tls', body);
  if (!r.ok) { uiAlert('Ошибка', r.data.error || 'Ошибка'); return; }
  if (r.data.url) {
    const self = body.mode === 'self' ? '\nСертификат свой, поэтому браузер предупредит о небезопасном сайте: это нормально, продолжайте.' : '';
    uiAlert('HTTPS', 'HTTPS включается. Через несколько секунд панель откроется по адресу:\n' + r.data.url + '\n(для Let\'s Encrypt первый выпуск сертификата может занять до минуты)' + self +
      '\n\nЕсли страница не открылась, старый адрес продолжает работать, пока HTTPS не запустился: при ошибке панель сама вернёт прежние настройки. Выключить HTTPS можно и по SSH командой: kit https off');
    setTimeout(() => { location.href = r.data.url; }, 6000);
  } else notify(r);
}

/* ---------- Оформление подписки ---------- */
const SS_MAP = {title: 'ss-title', announce: 'ss-announce', support_url: 'ss-support', web_url: 'ss-web', provider_id: 'ss-provider',
  expire_link: 'ss-expire-link', info_text: 'ss-info', info_color: 'ss-color', info_button_text: 'ss-btn', info_button_link: 'ss-btn-link'};
const SS_BOOL = {expire_notice: 'ss-expire', hide_settings: 'ss-hide', happ_routing: 'ss-happrt'};

async function loadSubSettings() {
  const r = await api('GET', '/api/v1/settings/subscription');
  if (!r.ok) return;
  for (const [k, id] of Object.entries(SS_MAP)) document.getElementById(id).value = r.data[k] || '';
  for (const [k, id] of Object.entries(SS_BOOL)) document.getElementById(id).checked = !!r.data[k];
  document.getElementById('ss-hours').value = r.data.update_hours || 12;
}
async function saveSubSettings() {
  const body = {update_hours: parseInt(document.getElementById('ss-hours').value) || 12};
  for (const [k, id] of Object.entries(SS_MAP)) body[k] = document.getElementById(id).value.trim();
  for (const [k, id] of Object.entries(SS_BOOL)) body[k] = document.getElementById(id).checked;
  const r = await api('PUT', '/api/v1/settings/subscription', body);
  notify(r);
}

/* ---------- Двухфакторный вход ---------- */
async function loadTOTP() {
  const r = await api('GET', '/api/v1/security/totp');
  if (!r.ok) return;
  const on = r.data.enabled;
  document.getElementById('totp-start').style.display = on ? 'none' : '';
  document.getElementById('totp-off').style.display = on ? 'flex' : 'none';
  document.getElementById('totp-setup').style.display = 'none';
  document.getElementById('totp-state').textContent = on
    ? 'Двухфакторный вход включён: при входе нужен код из приложения. Потеряли телефон – зайдите на сервер по SSH, откройте меню kit и выключите двухфакторный вход.'
    : 'Вход по паролю и одноразовому коду из приложения (Google Authenticator, Aegis, 2FAS…). Даже если пароль утечёт, зайти без телефона не получится.';
}
async function startTOTP() {
  const r = await api('POST', '/api/v1/security/totp/setup');
  if (!r.ok) { uiAlert('Ошибка', r.data.error || 'Ошибка'); return; }
  const box = document.getElementById('totp-qr');
  box.innerHTML = '';
  new QRCode(box, {text: r.data.uri, width: 170, height: 170, colorDark: '#111317', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.M});
  document.getElementById('totp-secret').textContent = r.data.secret;
  document.getElementById('totp-setup').style.display = 'flex';
  document.getElementById('totp-start').style.display = 'none';
}
async function enableTOTP() {
  const r = await api('POST', '/api/v1/security/totp/enable', {code: document.getElementById('totp-code').value});
  notify(r);
  document.getElementById('totp-code').value = '';
  loadTOTP();
}
async function disableTOTP() {
  const r = await api('POST', '/api/v1/security/totp/disable', {password: document.getElementById('totp-pass').value, code: document.getElementById('totp-code2').value});
  notify(r);
  document.getElementById('totp-pass').value = ''; document.getElementById('totp-code2').value = '';
  loadTOTP();
}

/* ---------- Своя страница-заглушка ---------- */
async function loadCustomStub() {
  const r = await api('GET', '/api/v1/masking/custom');
  if (!r.ok) return;
  document.getElementById('mk-html').value = r.data.html || '';
  document.getElementById('mk-del').style.display = r.data.html ? '' : 'none';
}
function loadStubFile(inp) {
  const f = inp.files && inp.files[0];
  if (!f) return;
  if (f.size > 256 * 1024) { uiAlert('Файл', 'Файл больше 256 КБ'); inp.value = ''; return; }
  const rd = new FileReader();
  rd.onload = () => { document.getElementById('mk-html').value = rd.result; previewStub(); };
  rd.readAsText(f);
  inp.value = '';
}
function previewStub() {
  const fr = document.getElementById('mk-preview');
  fr.style.display = 'block';
  fr.srcdoc = document.getElementById('mk-html').value; // iframe с sandbox: скрипты страницы не выполняются
}
async function saveCustomStub() {
  const r = await api('PUT', '/api/v1/masking/custom', { html: document.getElementById('mk-html').value });
  notify(r);
  if (r.ok) { loadMasking(); loadCustomStub(); }
}
async function deleteCustomStub() {
  if (!await uiConfirm('Удалить свою страницу?', 'Вернётся стандартная заглушка.', 'Удалить', true)) return;
  const r = await api('DELETE', '/api/v1/masking/custom');
  notify(r);
  if (r.ok) { document.getElementById('mk-html').value = ''; document.getElementById('mk-preview').style.display = 'none'; loadMasking(); loadCustomStub(); }
}

/* ---------- Всплывающее уведомление о новой версии (панель и ядра) ---------- */
const CORE_NAMES = {xray: 'Xray', singbox: 'sing-box', masque: 'sing-box (MASQUE)', mtg: 'mtg', mita: 'mita', telemt: 'telemt'};
function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

async function checkUpdateBanner() {
  const items = [];
  try {
    const d = await (await fetch('/api/v1/system/update/status')).json();
    if (d && d.available && d.latest) items.push({kind: 'panel', key: lsKeyPanel(), ver: d.latest, text: `Kitsune: доступна версия <b>v${esc(fmtVer(d.latest))}</b> (у вас v${esc(fmtVer(d.current))}).`});
  } catch (e) {}
  try {
    const r = await api('GET', '/api/v1/cores/latest');
    if (r.ok) (r.data.latest || []).forEach(l => {
      if (!l.newer || !l.latest) return;
      const fresh = l.fresh ? ' Выпуску меньше 3 суток, мы его ещё не проверяли.' : '';
      items.push({kind: 'core', key: 'kitsune-core-dismissed-' + l.id, ver: l.latest, text: `${esc(CORE_NAMES[l.id] || l.id)}: вышла версия <b>${esc(l.latest)}</b> (у вас ${esc(l.pinned)}).${fresh}`});
    });
  } catch (e) {}
  const nb = document.getElementById('nb-update');
  if (nb) { nb.hidden = !items.length; if (items.length) { nb.className = 'ni-badge warn'; nb.title = 'Доступны обновления'; } }
  const pending = items.filter(i => lsGet(i.key) !== i.ver);
  const old = document.getElementById('update-banner');
  if (!pending.length) { if (old) old.remove(); return; }
  const sig = pending.map(i => i.key + '=' + i.ver).join('|');
  if (old && old.dataset.sig === sig) return;
  if (old) old.remove();
  const el = document.createElement('div');
  el.id = 'update-banner'; el.dataset.sig = sig;
  const hasPanel = pending.some(i => i.kind === 'panel'), hasCore = pending.some(i => i.kind === 'core');
  el.innerHTML = `<div class="ub-title">${pending.length > 1 ? 'Вышли обновления' : (hasPanel ? 'Вышло обновление Kitsune' : 'Вышло обновление ядра')}</div>
    ${pending.map(i => `<div class="ub-text">${i.text}</div>`).join('')}
    <div class="ub-actions">${hasPanel ? '<button class="btn-banner" onclick="openUpdateSettings()">Обновить панель</button>' : ''}${hasCore ? `<button class="${hasPanel ? 'ub-close' : 'btn-banner'}" onclick="openCoreSettings()">Обновить</button>` : ''}
    <button class="ub-close" title="Скрыть до следующей версии" onclick="dismissUpdateBanner()">Позже</button></div>`;
  el._pending = pending;
  document.body.appendChild(el);
}
function lsKeyPanel() { return 'kitsune-update-dismissed'; }
function dismissUpdateBanner() {
  const el = document.getElementById('update-banner');
  if (el && el._pending) el._pending.forEach(i => lsSet(i.key, i.ver));
  if (el) el.remove();
}
function openUpdateSettings() {
  const el = document.getElementById('update-banner'); if (el) el.remove();
  navigateTo('settings', [...document.querySelectorAll('.nav-item')].find(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes("'settings'")));
  setTimeout(() => { const c = document.getElementById('update-card'); if (c) { c.scrollIntoView({ behavior: 'smooth', block: 'center' }); checkUpdate(); } }, 150);
}
function openCoreSettings() {
  const el = document.getElementById('update-banner'); if (el) el.remove();
  navigateTo('settings', [...document.querySelectorAll('.nav-item')].find(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes("'settings'")));
  setTimeout(() => { if (typeof showSettingsSec === 'function') showSettingsSec('cores'); }, 150);
}
setTimeout(checkUpdateBanner, 2500);
setInterval(checkUpdateBanner, 30 * 60 * 1000);

/* ---------- Настройки: разделы переключаются вкладками вверху страницы ---------- */
let settingsSec = 'security';
function showSettingsSec(sec, fromNav) {
  if (sec === 'ports') sec = 'masking'; // прежний раздел «Порты и режимы» теперь вместе с маскировкой
  settingsSec = sec;
  document.querySelectorAll('#view-settings [data-sec]:not(.tab-btn)').forEach(c => { c.hidden = c.dataset.sec !== sec; });
  document.querySelectorAll('#settings-tabs .tab-btn').forEach(b => { const on = b.dataset.sec === sec; b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on)); });
  try { localStorage.setItem('kitsune-settings-sec', sec); } catch (e) {}
  // ядра подгружаются при открытии раздела
  if (sec === 'cores' && currentTab === 'settings') { loadXraySettings(); loadCores(); }
}
function initSettingsSec() {
  try { settingsSec = localStorage.getItem('kitsune-settings-sec') || settingsSec; } catch (e) {}
  showSettingsSec(settingsSec);
}
document.addEventListener('DOMContentLoaded', initSettingsSec);

/* ---------- Каскад: узлы-мосты ---------- */
let bridgeNodes = [], bridgeInfo = {profiles: [], forwards: [], status: {}}, bridgeIsDirty = false;
function bridgeMark(on) {
  bridgeIsDirty = on !== false;
  const d = document.getElementById('bridge-dirty'); if (d) d.style.display = bridgeIsDirty ? '' : 'none';
  const b = document.getElementById('bridge-save'); if (b) b.classList.toggle('attn', bridgeIsDirty);
  bridgePreview();
}
function bridgeTakes(n, tag) { return n.selection_mode !== 'none' && (n.selection_mode === 'all' || !n.only || !n.only.length || n.only.includes(tag)); }
function bridgeToggleProfile(i, tag, on) {
  const n = bridgeNodes[i], all = (bridgeInfo.profiles || []).filter(p => p.relayed).map(p => p.tag);
  let cur = n.selection_mode === 'none' ? [] : ((n.only && n.only.length) ? n.only.slice() : all.slice());
  cur = on ? [...new Set([...cur, tag])] : cur.filter(t => t !== tag);
  n.selection_mode = !cur.length ? 'none' : (all.every(t => cur.includes(t)) ? 'all' : 'selected');
  n.only = n.selection_mode === 'selected' ? cur : []; // выбраны все – пустой список («все пересылаемые»)
  bridgeMark(); bridgePreview();
}
function bridgeStatusChip(n) {
  const st = (bridgeInfo.status || {})[n.id];
  if (!n.id || !st || st.state === 'unknown') return '<span class="form-hint" style="margin:0">Состояние пока неизвестно: проверка идёт раз в минуту по TCP-портам узла (UDP с сервера не проверить).</span>';
  const t = new Date((st.since || st.checked) * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  return st.state === 'ok'
    ? `<span style="color:var(--g-ok);font-weight:700">● TCP доступен, ${st.ms || 0} мс</span> <span class="form-hint" style="margin:0">с ${t}</span>`
    : `<span style="color:var(--accent-rose);font-weight:700">● не отвечает</span> <span class="form-hint" style="margin:0">с ${t}</span>`;
}
function bridgeRow(n, i) {
  const relayed = (bridgeInfo.profiles || []).filter(p => p.relayed);
  const picks = relayed.length ? `<div style="flex-basis:100%;display:flex;gap:6px 16px;flex-wrap:wrap;align-items:center"><span class="form-hint" style="margin:0">Через этот узел:</span>${relayed.map(p =>
    `<label class="switch-label" style="display:flex;align-items:center;gap:6px"><input type="checkbox" ${bridgeTakes(n, p.tag) ? 'checked' : ''} onchange="bridgeToggleProfile(${i}, '${escJs(p.tag)}', this.checked)" aria-label="${esc(p.tag)} через этот узел"> <span class="form-hint" style="margin:0">${esc(p.tag)} <small>(${esc(p.title)}, ${p.net === 'udp' ? 'UDP' : (p.net === 'both' ? 'TCP/UDP' : 'TCP')} ${p.port})</small></span></label>`).join('')}</div>` : '';
  return `<div class="link-row" style="align-items:center;gap:10px;flex-wrap:wrap">
    <label class="switch-label" style="display:flex;align-items:center;gap:8px"><input type="checkbox" class="check-row-input" ${n.enabled ? 'checked' : ''} onchange="bridgeNodes[${i}].enabled = this.checked; bridgeMark()" aria-label="В подписки"> <span class="form-hint" style="margin:0">В подписки</span></label>
    <input class="form-control" style="flex:1;min-width:140px" placeholder="Название (например, Москва)" maxlength="30" value="${esc(n.name || '')}" oninput="bridgeNodes[${i}].name = this.value; bridgeMark()" aria-label="Название узла">
    <input class="form-control mono" style="flex:1;min-width:180px" placeholder="Адрес узла: IPv4 или домен" value="${esc(n.host || '')}" oninput="bridgeNodes[${i}].host = this.value; bridgeMark()" aria-label="Адрес узла">
    <input class="form-control mono" style="flex:1;min-width:180px" placeholder="SNI для REALITY (необязательно)" title="Имя сайта для REALITY-копий через этот узел. Должно обслуживаться тем же сайтом-маскировкой, что и основное: например, соседний поддомен" value="${esc(n.sni || '')}" oninput="bridgeNodes[${i}].sni = this.value; bridgeMark()" aria-label="SNI для REALITY через этот узел">
    <button class="btn soft" type="button" onclick="bridgeScript(${i})">Скрипт для узла</button>
    <button class="btn soft" type="button" onclick="bridgeCheck(${i})">Проверить с сервера</button>
    <button class="btn soft danger" type="button" onclick="bridgeDel(${i})" aria-label="Удалить узел">✕</button>
    ${picks}
    <label class="switch-label" style="flex-basis:100%;display:flex;align-items:center;gap:8px"><input type="checkbox" ${n.auto_hide ? 'checked' : ''} onchange="bridgeNodes[${i}].auto_hide = this.checked; bridgeMark()" aria-label="Убирать из подписки, пока не отвечает"> <span class="form-hint" style="margin:0">Убирать TCP-копии после трёх отказов; UDP остаётся без проверки</span></label>
    <div style="flex-basis:100%" role="status">${bridgeStatusChip(n)}</div>
    <div id="bridge-check-${i}" class="form-hint" style="flex-basis:100%;margin:0" role="status"></div>
  </div>`;
}
function bridgeRender() {
  const box = document.getElementById('bridge-list');
  if (!box) return;
  box.innerHTML = bridgeNodes.length ? bridgeNodes.map(bridgeRow).join('') : '<span class="form-hint">Узлов пока нет. Нажмите «Добавить узел», введите адрес сервера в другой сети и получите скрипт для него.</span>';
  bridgePreview();
}
// Что окажется в подписке: по копии каждого выбранного пересылаемого подключения на каждый включённый узел; остальные через мост не идут
function bridgePreview() {
  const box = document.getElementById('bridge-preview');
  if (!box) return;
  const nodes = bridgeNodes.filter(n => n.enabled && n.name && n.host);
  const prof = bridgeInfo.profiles || [];
  const relayed = prof.filter(p => p.relayed), notRelayed = prof.filter(p => !p.relayed);
  let h = '', total = 0, lines = '';
  if (!prof.length) h = 'Включённых подключений пока нет: создайте их во вкладке «Подключения».';
  else if (!nodes.length) h = 'Включённых узлов с названием и адресом нет: в подписке только прямые подключения.';
  else {
    nodes.forEach(n => relayed.filter(p => bridgeTakes(n, p.tag)).forEach(p => { total++; lines += `<li>${esc(p.tag)} · ${esc(n.name)}: ${esc(n.host)}:${p.port}/${p.net === 'udp' ? 'UDP' : (p.net === 'both' ? 'TCP/UDP' : 'TCP')} (${esc(p.title)})</li>`; }));
    h = `<div>Кроме прямых подключений, в подписке будет копий: <b>${total}</b>.</div>${lines ? `<ul style="margin:6px 0 0;padding-left:18px">${lines}</ul>` : ''}`;
  }
  if (notRelayed.length) h += `<div style="margin-top:8px">Через мост не идут (только прямое подключение): ${notRelayed.map(p => String(p.title).startsWith(p.tag) ? esc(p.title) : esc(p.tag) + ' (' + esc(p.title) + ')').join(', ')}.</div>`;
  if (bridgeIsDirty) h += '<div style="margin-top:8px"><b>Это предварительный вид: изменения пока не сохранены.</b></div>';
  box.innerHTML = h;
}
async function loadBridges() {
  const r = await api('GET', '/api/v1/bridges');
  if (!r.ok) return;
  bridgeNodes = r.data.nodes || [];
  bridgeInfo = {profiles: r.data.profiles || [], forwards: r.data.forwards || [], status: r.data.status || {}};
  bridgeRender();
  bridgeMark(false);
}
function onCascadeTab() { loadBridges(); }
function bridgeAdd() { bridgeNodes.push({id: '', name: '', host: '', enabled: true, auto_hide: true, only: []}); bridgeRender(); bridgeMark(); }
function bridgeDel(i) { bridgeNodes.splice(i, 1); bridgeRender(); bridgeMark(); document.getElementById('bridge-script').innerHTML = ''; document.getElementById('bridge-script-card').hidden = true; }
async function bridgeSave() {
  const r = await api('PUT', '/api/v1/bridges', {nodes: bridgeNodes});
  notify(r, 'Не удалось сохранить узлы');
  if (r.ok) { bridgeNodes = r.data.nodes; bridgeRender(); bridgeMark(false); }
}
async function bridgeCheck(i) {
  const n = bridgeNodes[i] || {}, box = document.getElementById('bridge-check-' + i);
  if (!box) return;
  if (!n.host) { box.textContent = 'Введите адрес узла.'; return; }
  box.textContent = 'Проверяю…';
  const r = await api('POST', '/api/v1/bridges/check', {host: n.host, only: n.only || [], selection_mode: n.selection_mode || ''});
  if (!r.ok) { box.textContent = (r.data && r.data.error) || 'Ошибка проверки'; return; }
  const res = r.data.results || [];
  box.innerHTML = res.length
    ? res.map(x => x.ok ? `<span style="color:var(--g-ok)">✓ ${x.proto.toUpperCase()} ${x.port}: отвечает, ${x.ms} мс</span>` : `<span>${x.note ? '• ' : '✗ '}${x.proto.toUpperCase()} ${x.port}: ${esc(x.note || 'не отвечает')}</span>`).join('<br>') + '<br><span class="form-hint">Проверка идёт с сервера: она показывает, что порт на узле открыт, но не заменяет проверку из мобильной сети.</span>'
    : 'Нет подключений для пересылки.';
}
async function bridgeScript(i) {
  const r = await api('POST', '/api/v1/bridges/script', {only: (bridgeNodes[i] || {}).only || [], selection_mode: (bridgeNodes[i] || {}).selection_mode || ''});
  const box = document.getElementById('bridge-script'), card = document.getElementById('bridge-script-card');
  if (!r.ok) { box.innerHTML = ''; if (card) card.hidden = true; uiAlert('Скрипт недоступен', (r.data && r.data.error) || 'Ошибка'); return; }
  const n = bridgeNodes[i] || {};
  box.innerHTML = `<div class="form-hint" style="margin-bottom:6px">Скопируйте весь блок и вставьте его в терминал узла «${esc(n.name || n.host || '')}» от root. Блок настроит IPv4-мост через nftables на ${esc(r.data.exit)}. После запуска откройте указанные порты в файрволе узла. Убрать мост: <code>bash /usr/local/sbin/kitsune-bridge-apply remove</code>.</div>
    <textarea id="bridge-script-text" class="form-control mono" rows="12" readonly style="width:100%"></textarea>
    <div style="margin-top:8px"><button class="btn soft" type="button" onclick="copyText(document.getElementById('bridge-script-text').value)">Копировать</button></div>`;
  document.getElementById('bridge-script-text').value = r.data.script;
  if (card) { card.hidden = false; card.scrollIntoView({behavior: 'smooth', block: 'nearest'}); }
}
