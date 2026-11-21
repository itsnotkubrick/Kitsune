/* ---------- Импорт config.json Xray ---------- */
const IMP_ACT = {create: 'создать', update: 'обновить', exists: 'уже есть', skip: 'пропуск'};

function impForm(extra) {
  const f = document.getElementById('imp-file').files[0];
  if (!f) { uiAlert('Импорт', 'Выберите файл config.json Xray'); return null; }
  const fd = new FormData();
  fd.append('file', f);
  fd.append('source', 'xray');
  fd.append('mode', document.getElementById('imp-mode').value);
  if (extra) fd.append('confirm', 'yes');
  return fd;
}

function impSection(title, items, s) {
  const head = `${title}: создать ${s.create}, обновить ${s.update}, уже есть ${s.exists}, пропустить ${s.skip}, конфликтов ${s.conflicts}`;
  const rows = items.map(i => `<tr><td>${esc(i.name)}</td><td>${IMP_ACT[i.action] || ''}${i.conflict ? ' (конфликт)' : ''}</td><td>${esc([i.details, i.reason].filter(Boolean).join('. '))}</td></tr>`).join('');
  return `<h4 style="margin-top:14px">${esc(head)}</h4>` + (rows ? `<div style="overflow:auto;max-height:320px"><table class="table"><tbody>${rows}</tbody></table></div>` : '');
}

function impShow(rep, done) {
  impWarnText = (rep.warnings || []).join('\n');
  document.getElementById('imp-warn').innerHTML = (rep.warnings || []).map(n => `<p style="color:var(--accent-fox-orange);font-weight:600;margin:0 0 10px">${esc(n)}</p>`).join('');
  const notes = (rep.notes || []).map(n => `<p>${esc(n)}</p>`).join('');
  const more = (n, what) => n > 0 ? `<p>Ещё ${n} ${what} не показано: первыми выводятся конфликты и пропуски, итоги выше считаются по всем.</p>` : '';
  document.getElementById('imp-report').innerHTML = impSection('Пользователи', rep.users || [], rep.user_sum) + more(rep.users_more, 'строк пользователей') +
    impSection('Подключения', rep.inbounds || [], rep.inbound_sum) + more(rep.inbounds_more, 'строк подключений') + notes;
  document.getElementById('imp-run').style.display = done ? 'none' : '';
}

// Кнопка «Импортировать» относится к тому файлу, источнику и режиму, по которым сделан пробный прогон.
let impBusy = false, impSig = '', impWarnText = '';
function impSignature() {
  const f = document.getElementById('imp-file').files[0];
  return f ? [f.name, f.size, f.lastModified, document.getElementById('imp-mode').value].join('|') : '';
}
function impReset() {
  impSig = '';
  document.getElementById('imp-run').style.display = 'none';
  document.getElementById('imp-report').innerHTML = '';
  document.getElementById('imp-warn').innerHTML = '';
  impWarnText = '';
}
function impLock(on) {
  impBusy = on;
  ['imp-preview', 'imp-run'].forEach(id => { const b = document.getElementById(id); if (b) b.disabled = on; });
}

async function importPreview() {
  if (impBusy) return;
  const fd = impForm(false);
  if (!fd) return;
  const sig = impSignature();
  impLock(true);
  try {
    const res = await fetch('/api/v1/import/preview', {method: 'POST', body: fd});
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { uiAlert('Ошибка', d.error || 'Ошибка чтения файла'); return; }
    impShow(d.report, false);
    impSig = sig;
  } catch (e) {
    uiAlert('Ошибка', 'Не удалось отправить файл');
  } finally {
    impLock(false);
  }
}

async function importRun() {
  if (impBusy) return;
  if (!impSig || impSig !== impSignature()) { impReset(); uiAlert('Импорт', 'Файл или настройки изменились: сначала сделайте пробный прогон.'); return; }
  const fd = impForm(true);
  if (!fd) return;
  if (!await uiConfirm('Выполнить импорт?', (impWarnText ? impWarnText + '\n\n' : '') + 'Перед записью сохранится копия базы Kitsune (папка backups). Запись идёт одной транзакцией: при ошибке ничего не изменится.', 'Импортировать')) return;
  impLock(true);
  try {
    const res = await fetch('/api/v1/import/run', {method: 'POST', body: fd});
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { uiAlert('Ошибка', d.error || 'Ошибка импорта'); return; }
    impSig = '';
    impShow(d.report, true);
    uiAlert('Готово', (d.message || 'Импорт выполнен') + (d.warning ? '\n' + d.warning : ''));
  } catch (e) {
    uiAlert('Ошибка', 'Не удалось отправить файл');
  } finally {
    impLock(false);
  }
}
