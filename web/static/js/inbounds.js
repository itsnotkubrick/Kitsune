/* ---------- Подключения (шлюзы протоколов) ---------- */
let protocols = [];
let editingInbound = null;

async function ensureProtocols() {
  if (protocols.length) return;
  const r = await api('GET', '/api/v1/protocols');
  if (r.ok) protocols = r.data.protocols;
}

async function loadInbounds() {
  await ensureProtocols();
  const r = await api('GET', '/api/v1/inbounds');
  if (!r.ok) return;
  window.__inbounds = r.data.inbounds || [];
  const box = document.getElementById('inbounds-container');
  const acts = document.getElementById('ib-actions');
  if (acts) acts.style.display = window.__inbounds.length ? '' : 'none';
  if (!window.__inbounds.length) {
    box.innerHTML = `<div class="empty-state"><h4>Подключений пока нет</h4>
      <p>Подключение – это протокол на своём порту, через который пользователи выходят в сеть. Рекомендуемый набор (REALITY с Vision и XHTTP на втором имени) создаётся за один шаг, недостающие ядра скачаются сами.</p>
      <div class="empty-actions"><button class="btn" onclick="quickSetup()">Быстрая настройка</button>
      <button class="btn soft" onclick="openInboundModal()">Добавить вручную</button>
      <button class="btn-link" onclick="quickSetup('all')">Все доступные протоколы</button></div></div>`;
    return;
  }
  const coreColor = {xray: '#d4d4da', singbox: '#60a5fa', masque: '#60a5fa', 'sing-box': '#60a5fa', mtg: '#a78bfa', mita: '#34d399', telemt: '#a78bfa', awg: '#f5a524'};
  box.innerHTML = window.__inbounds.map(ib => {
    const ok = ib.enable && (ib.listening || ib.net === 'udp');
    const needDomain = ib.enable && ib.needs_domain;
    const stCls = needDomain ? 'warn' : (ok ? 'ok' : (ib.enable ? 'bad' : ''));
    const color = coreColor[ib.core] || '#9ca3af';
    return `
    <div class="ib-card${ib.enable ? '' : ' off'}">
      <div class="ib-id">
        <div class="ib-ic" style="--c:${color}">${esc((ib.title || ib.kind || '?').charAt(0).toUpperCase())}</div>
        <div><span class="nm">${esc(ib.tag)}</span><span class="sb">${esc(ib.title || ib.kind)}${ib.settings.sni ? ' · ' + esc(ib.settings.sni) : ''}${needDomain ? ' · укажите домен в поле SNI' : ''}</span></div>
      </div>
      <div class="ib-tags"><span class="proto-badge">порт ${ib.port}/${ib.net === 'both' ? 'tcp+udp' : ib.net}</span> <span class="proto-badge">${esc(ib.core)}</span></div>
      <div class="ib-state ${stCls}" ${needDomain ? 'title="Укажите домен в поле SNI (или в адресе для ссылок клиентов) в настройках подключения"' : ''}><span class="dot ${stCls}"></span>${ib.enable ? (needDomain ? 'Требует домен' : (ok ? 'Работает' : 'Не слушает порт')) : 'Выключено'}</div>
      <div class="user-actions">
        <button class="switch${ib.enable ? ' on' : ''}" role="switch" aria-checked="${ib.enable}" title="${ib.enable ? 'Выключить' : 'Включить'}" onclick="toggleInbound(${ib.id})"><i></i></button>
        <button class="btn soft u-edit" onclick="openInboundModal(${ib.id})">Изменить</button>
        <div class="u-menu-wrap">
          <button class="btn-icon" aria-label="Ещё действия" aria-haspopup="true" aria-expanded="false" onclick="toggleUserMenu(this)">⋯</button>
          <div class="u-menu" role="menu">
            <button role="menuitem" class="danger" onclick="closeUserMenus(); deleteInbound(${ib.id}, '${escJs(ib.tag)}')">Удалить…</button>
          </div>
        </div>
      </div>
    </div>`;
  }).join('');
}

async function quickSetup(set) {
  const all = set === 'all';
  const ask = all
    ? 'Создать все доступные протоколы (REALITY, XHTTP, WS, gRPC, VMess, Shadowsocks 2022, Hysteria2, TUIC, MTProto и на Linux – AmneziaWG)? Каждый дополнительный порт делает сервер заметнее, поэтому берите только то, что вам нужно. Недостающие ядра скачаются с проверкой SHA-256.'
    : 'Создать рекомендуемый набор: VLESS + REALITY (с Vision) и дополнительно XHTTP на втором имени сайта? Каждый дополнительный порт делает сервер заметнее, поэтому остальные протоколы лучше добавлять, только когда они нужны. Недостающие ядра скачаются с проверкой SHA-256.';
  if (!await uiConfirm('Быстрая настройка', ask, 'Создать')) return;
  const r = await api('POST', '/api/v1/inbounds/quick-setup', {set: all ? 'all' : 'recommended'});
  if (r.ok) uiAlert('Готово', r.data.message + (r.data.skipped && r.data.skipped.length ? '\nПропущено: ' + r.data.skipped.join('; ') : ''));
  else uiAlert('Ошибка', r.data.error || 'Ошибка');
  await loadInbounds(); loadUsers(); loadSystemStatus();
}

function fieldInput(f, value, idPrefix) {
  const id = idPrefix + f.key;
  const v = value !== undefined && value !== null && value !== '' ? value : '';
  let input;
  if (f.type === 'select') {
    const cur = v !== '' ? v : (f.default || '');
    input = `<select id="${id}" class="form-control">${(f.options || []).map(o => `<option value="${esc(o.value)}" ${o.value === cur ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
  } else if (f.type === 'bool') {
    const cur = (v !== '' ? v : f.default) === 'true' || (v !== '' ? v : f.default) === true;
    return `<label class="check-row" title="${esc(f.help || '')}"><input type="checkbox" id="${id}" ${cur ? 'checked' : ''}> ${esc(f.label)}</label>`;
  } else if (f.type === 'textarea') {
    input = `<textarea id="${id}" class="form-control mono" rows="3" placeholder="${esc(f.default || '')}">${esc(v)}</textarea>`;
  } else {
    input = `<input type="${f.type === 'number' ? 'number' : 'text'}" id="${id}" class="form-control" value="${esc(v)}" placeholder="${esc(f.default || '')}">`;
  }
  return `<div class="form-group"><label>${esc(f.label)}</label>${input}${f.help ? `<p style="font-size:11px;color:var(--text-muted);margin-top:4px">${esc(f.help)}</p>` : ''}</div>`;
}

function renderInboundFields(values) {
  const kind = document.getElementById('ib-kind').value;
  const info = protocols.find(p => p.id === kind);
  if (!info) return;
  document.getElementById('ib-kind-desc').textContent = info.desc;
  const vals = values || {};
  const basic = info.fields.filter(f => !f.adv), adv = info.fields.filter(f => f.adv);
  // основные поля сразу, «тонкая настройка» в раскрывающемся блоке: новичку не нужна длинная форма
  document.getElementById('ib-fields').innerHTML = basic.map(f => fieldInput(f, vals[f.key], 'ibf-')).join('') +
    (adv.length ? `<details class="adv-box"><summary>Дополнительные параметры (${adv.length})</summary><div class="adv-in">${adv.map(f => fieldInput(f, vals[f.key], 'ibf-')).join('')}</div></details>` : '');
  syncCertFields();
}

// Пути к файлам сертификата нужны только в режиме «Свои файлы»: в остальных режимах поля скрыты, чтобы не путать
function syncCertFields() {
  const mode = document.getElementById('ibf-cert_mode');
  if (!mode) return;
  const apply = () => ['cert_file', 'key_file'].forEach(k => {
    const el = document.getElementById('ibf-' + k), g = el && el.closest('.form-group');
    if (g) g.style.display = mode.value === 'custom' ? '' : 'none';
  });
  mode.onchange = apply;
  apply();
}

async function openInboundModal(id) {
  await ensureProtocols();
  const sel = document.getElementById('ib-kind');
  sel.innerHTML = protocols.map(p => `<option value="${p.id}">${esc(p.title)} · ${p.core}</option>`).join('');
  editingInbound = null;
  document.getElementById('ib-tag').value = '';
  document.getElementById('ib-port').value = '';
  document.getElementById('ib-modal-title').textContent = 'Новое подключение';
  document.getElementById('ib-kind-row').querySelector('select').disabled = false;
  let values = {};
  if (id) {
    const ib = (window.__inbounds || []).find(x => x.id === id);
    if (!ib) return;
    editingInbound = ib;
    sel.value = ib.kind;
    sel.disabled = true;
    document.getElementById('ib-tag').value = ib.tag;
    document.getElementById('ib-port').value = ib.port;
    document.getElementById('ib-modal-title').textContent = 'Подключение ' + ib.tag;
    values = ib.settings || {};
  }
  renderInboundFields(values);
  openModal('add-inbound-modal');
}

function collectInboundSettings(info) {
  const out = {};
  info.fields.forEach(f => {
    const el = document.getElementById('ibf-' + f.key);
    if (!el) return;
    if (f.type === 'bool') out[f.key] = el.checked ? 'true' : 'false';
    else out[f.key] = el.value.trim();
  });
  return out;
}

// Кнопка «Сохранить» на время запроса блокируется, вместо слова на ней крутится колёсико: создание подключения может занять минуту
// (докачивается ядро), и повторные нажатия раньше создавали копии подключения. Ширина кнопки не меняется.
let inboundBusy = false;
function buttonBusy(btn, on) {
  if (!btn) return;
  if (on) {
    btn._label = btn.innerHTML;
    btn.style.minWidth = btn.offsetWidth + 'px';
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.innerHTML = '<span class="btn-spin" role="status" aria-label="Сохраняю…"></span>';
  } else {
    btn.innerHTML = btn._label != null ? btn._label : btn.innerHTML;
    btn.style.minWidth = '';
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
  }
}
async function submitInbound() {
  if (inboundBusy) return;
  inboundBusy = true;
  const btn = document.querySelector('#add-inbound-modal button[onclick="submitInbound()"]');
  buttonBusy(btn, true);
  try { await submitInboundNow(); }
  finally { inboundBusy = false; buttonBusy(btn, false); }
}

async function submitInboundNow() {
  const kind = document.getElementById('ib-kind').value;
  const info = protocols.find(p => p.id === kind);
  const body = {
    kind,
    tag: document.getElementById('ib-tag').value.trim(),
    port: parseInt(document.getElementById('ib-port').value) || 0,
    settings: collectInboundSettings(info)
  };
  const r = editingInbound
    ? await api('PUT', `/api/v1/inbounds/${editingInbound.id}`, body)
    : await api('POST', '/api/v1/inbounds', body);
  if (!r.ok) { uiAlert('Ошибка', r.data.error || 'Ошибка'); return; }
  closeModal('add-inbound-modal');
  await loadInbounds(); loadUsers(); loadSystemStatus();
}

async function toggleInbound(id) {
  const ib = window.__inbounds.find(x => x.id === id);
  const r = await api('PUT', `/api/v1/inbounds/${id}`, {enable: !ib.enable});
  if (!r.ok) uiAlert('Ошибка', r.data.error || 'Ошибка');
  await loadInbounds();
}
async function deleteInbound(id, tag) {
  if (!await uiConfirm(`Удалить подключение «${tag}»?`, '', 'Удалить', true)) return;
  const r = await api('DELETE', `/api/v1/inbounds/${id}`);
  if (!r.ok) uiAlert('Ошибка', r.data.error || 'Ошибка');
  await loadInbounds(); loadUsers();
}
