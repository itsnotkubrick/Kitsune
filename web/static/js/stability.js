/* ---------- Проверка стабильности соединения: ссылка для проверки из сети человека и результаты ---------- */

const FZ_KIND = {mobile: 'Мобильный', home: 'Домашний', other: 'Другое'};
const fzTime = ms => new Date(ms).toLocaleString('ru-RU', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'});

// Кнопка «Проверка стабильности соединения» в блоке здоровья: открывает раздел, показывает прежние результаты и создаёт ссылку для новой проверки.
async function stabilityOpen() {
  const blk = document.getElementById('stability-block');
  if (blk) blk.style.display = '';
  stabilityLoad();
  await stabilityNew();
  if (blk) blk.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

async function stabilityNew() {
  const r = await api('POST', '/api/v1/system/stability/new');
  if (!r.ok) return uiAlert('Ошибка', (r.data && r.data.error) || 'Не удалось создать ссылку');
  const box = document.getElementById('stability-link');
  box.innerHTML = `<div class="copy-row"><input type="text" id="fz-url" class="form-control mono" readonly value="${esc(r.data.url)}"><button class="btn-icon" title="Копировать" onclick="copyText(document.getElementById('fz-url').value)">⧉</button></div>
    <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-top:14px">
      <div id="fz-qr" style="flex:none;padding:10px;background:#fff;border-radius:16px;line-height:0"></div>
      <div style="flex:1;min-width:220px;color:var(--text-secondary);font-size:13px;line-height:1.5">Откройте ссылку на телефоне в мобильной сети или наведите камеру на QR-код.<br>Ссылка действует 14 дней, ею можно проверить несколько сетей.</div>
    </div>`;
  try { new QRCode(document.getElementById('fz-qr'), {text: r.data.url, width: 140, height: 140, colorDark: '#111317', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.L}); } catch (e) {}
}

async function stabilityLoad() {
  const box = document.getElementById('stability-list');
  if (!box) return;
  const r = await api('GET', '/api/v1/system/stability');
  if (!r.ok) return;
  const d = r.data, rows = d.results || [];
  if (!rows.length) { box.innerHTML = '<span class="form-hint">Результатов пока нет.</span>'; return; }
  let verdict = '';
  if (d.verdict === 'stalled') {
    verdict = `<div class="health-summary warn" style="margin-bottom:10px"><span>В ${d.stalled} из ${d.total} проверок за 14 дней передача останавливалась. TCP-подключения (REALITY, XHTTP) у таких людей могут не пройти.</span></div>`
      + (d.has_udp
        ? `<div class="form-hint" style="margin-bottom:10px">Что можно сделать: поставить UDP-подключения (Hysteria2, TUIC, AmneziaWG) первыми в подписке, использовать мост через другой сервер или перенести сервер к хостеру, у которого остановки передачи нет. ${d.udp_first ? 'UDP-подключения уже стоят первыми.' : ''}</div>
           <button class="btn-banner" onclick="stabilityUDPFirst(${d.udp_first ? 'false' : 'true'})" style="margin-bottom:12px">${d.udp_first ? 'Вернуть прежний порядок в подписках' : 'Поставить UDP первыми в подписках'}</button>`
        : '<div class="form-hint" style="margin-bottom:10px">Что можно сделать: создать UDP-подключения (Hysteria2, TUIC, AmneziaWG), использовать мост через другой сервер или перенести сервер к хостеру, у которого остановки передачи нет.</div>');
  } else if (d.verdict === 'ok') {
    verdict = `<div class="health-summary ok" style="margin-bottom:10px"><span>За 14 дней (${d.total} проверок) соединение не обрывалось.</span></div>`;
  }
  box.innerHTML = verdict + '<div style="display:flex;flex-direction:column;gap:6px">' + rows.slice(0, 10).map(x => {
    const res = x.ok ? `<span style="color:var(--accent-green)">скачалось за ${x.ms} мс</span>`
      : (x.bytes ? `<span style="color:var(--accent-rose)">остановилось после ${Math.round(x.bytes / 1024)} КБ</span>` : '<span style="color:var(--accent-rose)">данные не пришли</span>');
    return `<div class="link-row"><div class="lt">${esc(FZ_KIND[x.kind] || 'Другое')}${x.note ? ' · ' + esc(x.note) : ''}<small>${esc(fzTime(x.at))}</small></div><div>${res}</div></div>`;
  }).join('') + '</div>';
}

async function stabilityUDPFirst(on) {
  const r = await api('PUT', '/api/v1/system/stability/udp-first', {on});
  if (!r.ok) return uiAlert('Ошибка', (r.data && r.data.error) || 'Не удалось изменить порядок');
  toast(on ? 'UDP-подключения теперь первые в подписках' : 'Прежний порядок подключений в подписках');
  stabilityLoad();
}
