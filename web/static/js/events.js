/* ---------- Журнал и уведомления ---------- */
async function loadAudit() {
  const r = await api('GET', '/api/v1/audit?limit=200');
  if (!r.ok) return;
  const rows = r.data.entries || [];
  document.getElementById('audit-table').innerHTML = rows.length ? rows.map(e => `<tr>
    <td style="white-space:nowrap;color:var(--text-secondary)">${new Date(e.time * 1000).toLocaleString('ru-RU')}</td>
    <td>${esc(e.actor || '—')}</td><td>${esc(e.action)}</td><td style="color:var(--text-secondary)">${esc(e.detail || '')}</td></tr>`).join('')
    : '<tr><td colspan="4" style="color:var(--text-muted)">Журнал пока пуст</td></tr>';
}

async function loadTelegram() {
  const r = await api('GET', '/api/v1/settings/telegram');
  if (!r.ok) return;
  const d = r.data;
  document.getElementById('tg-enabled').checked = d.enabled;
  document.getElementById('tg-chat').value = d.chat_id || '';
  document.getElementById('tg-bot').checked = !!d.bot;
  document.getElementById('tg-admins').value = (d.admins || []).join(', ');
  tgBotToggle();
  document.getElementById('tg-token').value = '';
  document.getElementById('tg-token-state').textContent = d.token_set ? '(сохранён)' : '';
  const on = new Set(d.events && d.events.length ? d.events : d.kinds.map(k => k.Key));
  document.getElementById('tg-events').innerHTML = '<div class="field-label">О ЧЁМ УВЕДОМЛЯТЬ</div>' + d.kinds.map(k =>
    `<label class="check-row"><input type="checkbox" class="tg-ev" value="${esc(k.Key)}" ${on.has(k.Key) ? 'checked' : ''}> ${esc(k.Label)}</label>`).join('');
}

// Поле администраторов бота показывается, только когда бот включён.
function tgBotToggle() {
  const box = document.getElementById('tg-bot-box'), on = document.getElementById('tg-bot').checked;
  if (box) box.style.display = on ? '' : 'none';
}
// «123, 456;789» -> [123, 456, 789]; всё, что не число, отбрасывается (сервер проверит ещё раз).
function tgParseAdmins(text) {
  return String(text).split(/[\s,;]+/).filter(Boolean).map(x => parseInt(x, 10)).filter(n => Number.isFinite(n) && n > 0);
}

async function saveTelegram() {
  const evs = [...document.querySelectorAll('.tg-ev')];
  const picked = evs.filter(e => e.checked).map(e => e.value);
  const r = await api('PUT', '/api/v1/settings/telegram', {
    token: document.getElementById('tg-token').value.trim(),
    chat_id: document.getElementById('tg-chat').value.trim(),
    enabled: document.getElementById('tg-enabled').checked,
    events: picked.length === evs.length ? [] : picked,
    bot: document.getElementById('tg-bot').checked,
    admins: tgParseAdmins(document.getElementById('tg-admins').value)
  });
  notify(r);
  loadTelegram();
}

async function testTelegram() {
  const r = await api('POST', '/api/v1/settings/telegram/test');
  notify(r);
}
