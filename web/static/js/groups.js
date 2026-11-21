/* ---------- Шаблоны и группы ---------- */
let gtData = {groups: [], templates: []};
let editingGroup = 0, editingTemplate = 0;

async function loadGroups() {
  const r = await api('GET', '/api/v1/groups');
  if (r.ok) gtData = r.data;
  return gtData;
}

function groupOptions(selected) {
  return '<option value="0">Все подключения</option>' + gtData.groups.map(g =>
    `<option value="${g.id}" ${g.id === selected ? 'selected' : ''}>${esc(g.name)}</option>`).join('');
}

// Подготовка окон создания и правки пользователя (шаблоны, группы).
async function prepareUserForms() {
  await loadGroups();
  const t = document.getElementById('nu-template');
  if (t) t.innerHTML = '<option value="0">Без шаблона</option>' + gtData.templates.map(x => `<option value="${x.id}">${esc(x.name)}</option>`).join('');
  const g = document.getElementById('nu-group');
  if (g) g.innerHTML = groupOptions(0);
}

function applyTemplate() {
  const id = parseInt(document.getElementById('nu-template').value);
  const t = gtData.templates.find(x => x.id === id);
  if (!t) return;
  const gb = Math.round(t.traffic_limit / 1073741824);
  const lim = document.getElementById('nu-limit');
  if (![...lim.options].some(o => parseInt(o.value) === gb)) lim.add(new Option(gb + ' ГБ', gb));
  lim.value = String(gb);
  const ex = document.getElementById('nu-expiry');
  if (![...ex.options].some(o => parseInt(o.value) === t.days)) ex.add(new Option(t.days + ' дней', t.days));
  ex.value = String(t.days);
  document.getElementById('nu-iplimit').value = t.ip_limit;
  document.getElementById('nu-vision').checked = t.vision;
  document.getElementById('nu-note').value = t.note || '';
  document.getElementById('nu-group').value = String(t.group_id || 0);
}

// Страницы «Шаблоны» и «Группы» (подменю «Пользователи»); окна создания выезжают справа
async function onGroupsTab() { await loadGroups(); if (!window.__inbounds) await loadInbounds(); renderGroupsPage(); }
async function onTemplatesTab() { await loadGroups(); renderTemplatesPage(); }

function renderGroupsPage() {
  const ibs = window.__inbounds || [];
  const users = typeof usersCache !== 'undefined' ? usersCache : [];
  document.getElementById('gt-groups').innerHTML = gtData.groups.length ? gtData.groups.map(g => {
    const names = g.inbound_ids.map(id => (ibs.find(i => i.id === id) || {tag: '#' + id}).tag);
    const n = users.filter(u => u.group_id === g.id).length;
    return `<div class="user-card" style="grid-template-columns: minmax(180px, 1.4fr) minmax(200px, 2fr) auto;">
      <div class="user-identity"><div class="user-avatar">${esc(g.name.charAt(0).toUpperCase())}</div>
        <div class="user-titles"><span class="user-name">${esc(g.name)}</span><span class="user-uuid">${n ? 'пользователей: ' + n : 'пока никого'}</span></div></div>
      <div class="user-expiry-box">${names.length ? names.map(t => `<span class="proto-badge">${esc(t)}</span>`).join(' ') : 'нет подключений'}</div>
      <div class="user-actions"><button class="btn-icon" title="Изменить" onclick="openGroupDrawer(${g.id})">✎</button>
        <button class="btn-icon danger" title="Удалить" onclick="deleteGroup(${g.id})">✕</button></div></div>`;
  }).join('') : '<div class="empty-state"><h4>Групп пока нет</h4><p>Все пользователи видят все включённые подключения. Создайте группу, чтобы выдавать, например, только REALITY.</p><button class="btn" onclick="openGroupDrawer()">Добавить группу</button></div>';
}

function renderTemplatesPage() {
  document.getElementById('gt-templates').innerHTML = gtData.templates.length ? gtData.templates.map(t => {
    const g = gtData.groups.find(x => x.id === t.group_id);
    return `<div class="user-card" style="grid-template-columns: minmax(180px, 1.4fr) minmax(200px, 2fr) auto;">
      <div class="user-identity"><div class="user-avatar">${esc(t.name.charAt(0).toUpperCase())}</div>
        <div class="user-titles"><span class="user-name">${esc(t.name)}</span><span class="user-uuid">${esc(t.note || '')}</span></div></div>
      <div class="user-expiry-box"><div><strong>${t.traffic_limit ? formatBytes(t.traffic_limit) : 'безлимит'}</strong> · ${t.days ? t.days + ' дн.' : 'бессрочно'}${t.ip_limit ? ' · ' + t.ip_limit + ' устр.' : ''}${g ? ' · ' + esc(g.name) : ''}</div></div>
      <div class="user-actions"><button class="btn-icon" title="Изменить" onclick="openTemplateDrawer(${t.id})">✎</button>
        <button class="btn-icon danger" title="Удалить" onclick="deleteTemplate(${t.id})">✕</button></div></div>`;
  }).join('') : '<div class="empty-state"><h4>Шаблонов пока нет</h4><p>Шаблон заполняет форму нового пользователя: трафик, срок, устройства и группу.</p><button class="btn" onclick="openTemplateDrawer()">Добавить шаблон</button></div>';
}

async function openGroupDrawer(id) {
  await loadGroups();
  if (!window.__inbounds) await loadInbounds();
  const ibs = window.__inbounds || [];
  editingGroup = id || 0;
  const g = id ? gtData.groups.find(x => x.id === id) : null;
  document.getElementById('gp-name').value = g ? g.name : '';
  document.getElementById('gp-inbounds').innerHTML = ibs.map(i =>
    `<label class="check-row"><input type="checkbox" class="gp-ib" value="${i.id}" ${g && g.inbound_ids.includes(i.id) ? 'checked' : ''}> ${esc(i.tag)}</label>`).join('') || '<span class="form-hint">Сначала создайте подключения.</span>';
  openModal('group-modal');
}

async function openTemplateDrawer(id) {
  await loadGroups();
  editingTemplate = id || 0;
  const t = id ? gtData.templates.find(x => x.id === id) : null;
  document.getElementById('tp-group').innerHTML = groupOptions(t ? t.group_id : 0);
  document.getElementById('tp-name').value = t ? t.name : '';
  document.getElementById('tp-gb').value = t ? Math.round(t.traffic_limit / 1073741824 * 100) / 100 : 0;
  document.getElementById('tp-days').value = t ? t.days : 30;
  document.getElementById('tp-ip').value = t ? t.ip_limit : 0;
  document.getElementById('tp-note').value = t ? (t.note || '') : '';
  document.getElementById('tp-vision').checked = t ? t.vision : true;
  openModal('template-modal');
}

async function saveGroup() {
  const body = {
    name: document.getElementById('gp-name').value.trim(),
    inbound_ids: [...document.querySelectorAll('.gp-ib:checked')].map(c => parseInt(c.value))
  };
  const r = editingGroup ? await api('PUT', `/api/v1/groups/${editingGroup}`, body) : await api('POST', '/api/v1/groups', body);
  if (!r.ok) { uiAlert('Ошибка', r.data.error || 'Ошибка'); return; }
  editingGroup = 0;
  closeModal('group-modal');
  await loadGroups(); renderGroupsPage(); loadUsers();
}

async function deleteGroup(id) {
  if (!await uiConfirm('Удалить группу?', 'Её пользователи получат доступ ко всем подключениям.', 'Удалить', true)) return;
  const r = await api('DELETE', `/api/v1/groups/${id}`);
  if (!r.ok) uiAlert('Не удалось удалить группу', String((r.data && r.data.error) || 'Ошибка')); else toast('Группа удалена');
  await loadGroups(); renderGroupsPage(); loadUsers();
}

async function saveTemplate() {
  const body = {
    name: document.getElementById('tp-name').value.trim(),
    traffic_limit: Math.round((parseFloat(document.getElementById('tp-gb').value) || 0) * 1073741824),
    days: parseInt(document.getElementById('tp-days').value) || 0,
    ip_limit: parseInt(document.getElementById('tp-ip').value) || 0,
    vision: document.getElementById('tp-vision').checked,
    note: document.getElementById('tp-note').value.trim(),
    group_id: parseInt(document.getElementById('tp-group').value) || 0
  };
  const r = editingTemplate ? await api('PUT', `/api/v1/templates/${editingTemplate}`, body) : await api('POST', '/api/v1/templates', body);
  if (!r.ok) { uiAlert('Ошибка', r.data.error || 'Ошибка'); return; }
  editingTemplate = 0;
  closeModal('template-modal');
  await loadGroups(); renderTemplatesPage();
}

async function deleteTemplate(id) {
  if (!await uiConfirm('Удалить шаблон?', '', 'Удалить', true)) return;
  const r = await api('DELETE', `/api/v1/templates/${id}`);
  if (!r.ok) uiAlert('Не удалось удалить шаблон', String((r.data && r.data.error) || 'Ошибка')); else toast('Шаблон удалён');
  await loadGroups(); renderTemplatesPage();
}
