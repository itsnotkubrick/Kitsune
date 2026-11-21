/* ---------- Здоровье системы ---------- */
const svg = (inner, size = 18, extra = '') => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" ${extra}>${inner}</svg>`;
const LEVEL_ICONS = {
  ok:   svg('<circle cx="12" cy="12" r="10"/><path d="M8 12.5l2.7 2.7L16 9.5"/>', 18, 'style="color:var(--accent-green)"'),
  warn: svg('<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r=".6" fill="currentColor"/>', 18, 'style="color:#f5a524"'),
  bad:  svg('<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>', 18, 'style="color:var(--accent-rose)"'),
  info: svg('<circle cx="12" cy="12" r="10"/><line x1="12" y1="11" x2="12" y2="16"/><circle cx="12" cy="7.8" r=".6" fill="currentColor"/>', 18, 'style="color:#60a5fa"')
};
const GROUP_ICONS = {
  'Службы': '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  'Конфигурация': '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M9 14l2 2 4-4"/>',
  'Подключения': '<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1" fill="currentColor"/>',
  'Файрвол': '<path d="M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z"/><path d="M4 11h16M12 5v6"/>',
  'База данных': '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  'Клиенты': '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  'Ресурсы сервера': '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
  'Сеть': '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
  'Сетевой путь': '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><path d="M7 12h10"/>',
  'Безопасность': '<path d="M17.9 17.9A10.9 10.9 0 0 1 12 20C5 20 1 12 1 12a18.5 18.5 0 0 1 5.1-5.9"/><path d="M9.9 4.2A9.1 9.1 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2"/><path d="M1 1l22 22"/>',
  'Безопасность': '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  'Система': '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  'Резервные копии': '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>',
  'Обновления': '<path d="M23 4v6h-6"/><path d="M20.5 15a9 9 0 1 1-2.1-9.4L23 10"/>'
};
const groupIcon = name => svg(GROUP_ICONS[name] || '<circle cx="12" cy="12" r="9"/>', 16);

function setHealthBadge(rep) {
  const nb = document.getElementById('nb-health');
  if (!nb) return;
  nb.hidden = !(rep.bad || rep.warn);
  nb.className = 'ni-badge' + (rep.bad ? '' : ' warn');
  nb.title = rep.bad ? `Проблем: ${rep.bad}` : `Предупреждений: ${rep.warn}`;
}

// Тихая проверка при входе: только чтобы зажечь точку у пункта «Здоровье»
async function silentHealthBadge() {
  try { const r = await fetch('/api/v1/system/check'); if (r.ok) setHealthBadge(await r.json()); } catch (e) {}
}

function healthSummary(rep) {
  const lvl = rep.bad ? 'bad' : (rep.warn ? 'warn' : 'ok');
  const text = rep.bad ? `Найдено проблем: ${rep.bad}` + (rep.warn ? `, предупреждений: ${rep.warn}` : '')
             : (rep.warn ? `Есть предупреждения: ${rep.warn}` : 'Всё в порядке');
  return `<div class="health-summary ${lvl}">${svg(lvl === 'ok' ? '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>' : (lvl === 'warn' ? '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/>' : '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'), 26)}<span>${text}</span></div>`;
}

// Исправления, влияющие на адрес панели, ссылки клиентов или порядок подключений, перед применением просят подтверждение
const FIX_CONFIRM = /^(panelpath|sni:|certs|udpfirst)/;
const healthRow = it => `<div class="health-row"><span class="ic">${LEVEL_ICONS[it.level] || ''}</span><div style="flex:1;min-width:0"><div>${esc(it.text)}</div>${it.fix_tip ? `<div class="fixtip">Исправление: ${esc(it.fix_tip)}</div>` : ''}</div>${it.fix && it.level !== 'ok' ? `<button type="button" class="btn soft hfix" data-fix="${esc(it.fix)}" onclick="fixOne(this)">Исправить</button>` : ''}</div>`;

function renderCheck(rep, extra) {
  setHealthBadge(rep);
  const groups = [];
  for (const it of rep.items) {
    let g = groups.find(x => x.name === it.group);
    if (!g) { g = {name: it.group, items: []}; groups.push(g); }
    g.items.push(it);
  }
  let html = (extra || '') + healthSummary(rep);
  for (const g of groups) {
    html += `<div class="health-group" ${g.name === 'Безопасность' ? 'data-pass="1" ' : ''}data-level="${worstLevel(g.items)}"><h5>${groupIcon(g.name)}${esc(g.name)}</h5>` + g.items.map(healthRow).join('') + '</div>';
  }
  document.getElementById('check-result').innerHTML = html;
  foldHealth();
}

// Благополучные группы сворачиваются, проблемные идут первыми и раскрыты; клик по заголовку раскрывает любую
function foldHealth() {
  const box = document.getElementById('check-result');
  const pass = box.querySelector('.health-group[data-pass]');
  if (pass) renderPassport(pass);
  const groups = [...box.querySelectorAll('.health-group[data-level]')].filter(g => g !== pass);
  const bad = groups.filter(g => g.dataset.level === 'bad' || g.dataset.level === 'warn');
  const good = groups.filter(g => !bad.includes(g));
  const anchor = box.querySelector('.health-summary') || null;
  const frag = document.createDocumentFragment();
  [...bad, ...good].forEach(g => { g.classList.toggle('fold', good.includes(g)); frag.appendChild(g); });
  const fix = box.querySelector('#hlive-fix');
  if (fix) box.insertBefore(frag, fix); else box.appendChild(frag);
  if (pass) { // паспорт безопасности всегда раскрыт и стоит сразу под итогом
    const sum = box.querySelector('.health-summary, #hlive-summary');
    if (sum && sum.nextSibling) box.insertBefore(pass, sum.nextSibling); else box.insertBefore(pass, box.firstChild);
  }
  box.classList.remove('all-open');
  let btn = document.getElementById('health-expand');
  if (btn) btn.remove();
  if (good.length) {
    btn = document.createElement('button');
    btn.id = 'health-expand'; btn.className = 'btn-link';
    btn.textContent = `Показать все проверки (${good.length} в порядке)`;
    btn.onclick = () => { const open = box.classList.toggle('all-open'); btn.textContent = open ? 'Свернуть благополучные' : `Показать все проверки (${good.length} в порядке)`; };
    const first = (bad[0] || good[0]);
    if (bad.length) box.insertBefore(btn, good[0]); else box.insertBefore(btn, first);
  }
}
// «Паспорт безопасности»: крупная оценка из строки «Оценка безопасности: N из 100 – вывод…», остальные строки ниже
function renderPassport(g) {
  g.classList.add('passport'); g.classList.remove('fold');
  const rows = [...g.querySelectorAll('.health-row')];
  const first = rows[0], m = first && /Оценка безопасности: (\d+) из 100 – ([^.]+)/.exec(first.textContent);
  g.querySelector('.passport-head')?.remove();
  g.querySelector('.passport-hist')?.remove();
  if (!m) return;
  const score = +m[1], lvl = score >= 90 ? 'ok' : score >= 70 ? 'warn' : 'bad';
  first.style.display = 'none';
  g.querySelector('h5').insertAdjacentHTML('afterend', `<div class="passport-head ${lvl}"><b>${score}</b><div><span>из 100</span><div>Паспорт безопасности: ${esc(m[2])}</div><small>Проверка идёт с самого сервера и не показывает состояние сети у вашего провайдера.</small></div></div><div class="passport-hist" id="passport-hist"></div>`);
  loadPassportHistory();
}

const PASS_TIME = ms => new Date(ms).toLocaleString('ru-RU', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'});

// График оценки и лента изменений: что стало лучше или хуже между соседними проверками
async function loadPassportHistory() {
  const box = document.getElementById('passport-hist'); if (!box) return;
  const r = await fetch('/api/v1/system/passport/history');
  if (!r.ok) return;
  const h = (await r.json()).history || [];
  if (h.length < 2) { box.innerHTML = '<small class="passport-note">История копится: после следующих проверок здесь появится график и лента изменений.</small>'; return; }
  const col = sc => sc >= 90 ? 'ok' : sc >= 70 ? 'warn' : 'bad';
  // полоса по дням: цвет дня = худшая оценка за день, как на страницах статуса
  const DAY = 86400000, days = 30, today = new Date(); today.setHours(0, 0, 0, 0);
  const byDay = {};
  h.forEach(p => { const d = new Date(p.at); d.setHours(0, 0, 0, 0); const k = d.getTime(); byDay[k] = Math.min(byDay[k] ?? 100, p.score); });
  let strip = '';
  for (let i = days - 1; i >= 0; i--) {
    const k = today.getTime() - i * DAY, sc = byDay[k];
    const label = new Date(k).toLocaleDateString('ru-RU', {day: '2-digit', month: '2-digit'});
    strip += `<i class="pd ${sc == null ? 'none' : col(sc)}" title="${label}: ${sc == null ? 'нет проверок' : sc + ' из 100'}"></i>`;
  }
  // плавная кривая с заливкой; шкала сужена до реального разброса, чтобы изменения были видны
  const W = Math.max(280, box.clientWidth || 560), H = 96, pl = 8, pr = 8, pt = 10, pb = 8;
  const lo = Math.max(0, Math.min(60, Math.min(...h.map(p => p.score)) - 8)), hi = 100;
  const t0 = h[0].at, t1 = h[h.length - 1].at;
  const px = p => pl + (W - pl - pr) * (t1 === t0 ? 1 : (p.at - t0) / (t1 - t0));
  const py = p => pt + (H - pt - pb) * (1 - (p.score - lo) / (hi - lo));
  const pts = h.map(p => [px(p), py(p)]);
  let d = `M${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) { // ступенчато-плавная: оценка держится до следующей проверки
    const [x0, y0] = pts[i], [x1, y1] = pts[i + 1], mx = (x0 + x1) / 2;
    d += ` C${mx.toFixed(1)} ${y0.toFixed(1)} ${mx.toFixed(1)} ${y1.toFixed(1)} ${x1.toFixed(1)} ${y1.toFixed(1)}`;
  }
  const last = pts[pts.length - 1], first = pts[0], bottom = H - pb;
  const area = `${d} L${last[0].toFixed(1)} ${bottom} L${first[0].toFixed(1)} ${bottom} Z`;
  const guide = v => v > lo && v < hi ? `<line x1="${pl}" x2="${W - pr}" y1="${(pt + (H - pt - pb) * (1 - (v - lo) / (hi - lo))).toFixed(1)}" y2="${(pt + (H - pt - pb) * (1 - (v - lo) / (hi - lo))).toFixed(1)}" class="pg"/>` : '';
  const uid = 'pg' + Date.now();
  const minP = h.reduce((m, p) => p.score < m.score ? p : m, h[0]);
  const mark = (p, cls) => `<circle cx="${px(p).toFixed(1)}" cy="${py(p).toFixed(1)}" r="4" class="${cls}"><title>${esc(PASS_TIME(p.at))}: ${p.score} из 100</title></circle>`;
  const lastP = h[h.length - 1];
  const chart = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="passport-chart ${col(lastP.score)}" role="img" aria-label="Оценка безопасности по времени">`
    + `<defs><linearGradient id="${uid}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="currentColor" stop-opacity=".32"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/></linearGradient></defs>`
    + guide(90) + guide(70)
    + `<path d="${area}" fill="url(#${uid})"/><path d="${d}" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>`
    + (minP !== lastP && minP.score < 90 ? mark(minP, 'pm-low') : '') + mark(lastP, 'pm-now') + '</svg>';
  const events = [];
  for (let i = 1; i < h.length; i++) {
    const a = h[i - 1], b = h[i];
    // строка считается той же, если совпадает её первое предложение: подсказка в хвосте может меняться (например, появилась кнопка «Исправить»)
    const key = t => t.split('. ')[0];
    const was = new Set(a.lines.map(l => key(l.text))), now = new Set(b.lines.map(l => key(l.text)));
    const added = b.lines.filter(l => !was.has(key(l.text))), gone = a.lines.filter(l => !now.has(key(l.text)));
    if (b.score === a.score && !added.length && !gone.length) continue;
    events.push({at: b.at, from: a.score, to: b.score, added, gone});
  }
  const feed = events.slice(-8).reverse().map(e => {
    const dir = e.to > e.from ? 'up' : e.to < e.from ? 'down' : 'same';
    return `<li class="${dir}"><b>${esc(PASS_TIME(e.at))}</b> ${e.from === e.to ? `оценка ${e.to}` : `оценка ${e.from} → ${e.to}`}`
      + e.added.map(l => `<div class="added">появилось: ${esc(l.text)}</div>`).join('')
      + e.gone.map(l => `<div class="gone">исправлено: ${esc(l.text)}</div>`).join('') + '</li>';
  }).join('');
  box.innerHTML = `<div class="passport-strip" aria-label="Последние 30 дней">${strip}</div>`
    + chart
    + `<div class="passport-range"><span>${esc(PASS_TIME(t0))}</span><span>проверок: ${h.length}</span><span>${esc(PASS_TIME(t1))}</span></div>`
    + (feed ? `<ul class="passport-feed">${feed}</ul>` : '<small class="passport-note">Изменений между проверками не было.</small>');
}

document.addEventListener('click', e => { const h = e.target.closest && e.target.closest('.health-group.fold > h5'); if (h) h.parentElement.classList.toggle('open'); });

// ---- Проверка в реальном времени ----
// Каждый запуск заново выполняет все шаги на сервере по одному. Страница опрашивает ход прогона: у ожидающего шага серая точка,
// у идущего крутится индикатор, у готового значок результата и время, которое шаг занял на самом деле.
let healthTimer = null, healthSeq = -1, healthShown = {};

function stopHealthPoll() { if (healthTimer) { clearTimeout(healthTimer); healthTimer = null; } }

const worstLevel = items => items.some(i => i.level === 'bad') ? 'bad' : items.some(i => i.level === 'warn') ? 'warn' : items.some(i => i.level === 'ok') ? 'ok' : 'info';

function liveSkeleton(job) {
  healthShown = {};
  return '<div id="hlive-summary"></div>' + job.steps.map(s =>
    `<div class="health-group" ${s.id === 'posture' ? 'data-pass="1" ' : ''}id="hs-${esc(s.id)}"><h5>${groupIcon(s.group)}${esc(s.group)}<span class="hstate" id="hs-${esc(s.id)}-st"></span></h5><div id="hs-${esc(s.id)}-body"></div></div>`).join('') +
    '<div id="hlive-fix"></div>';
}

// Обновляет только то, что изменилось, чтобы крутящиеся индикаторы не перезапускались при каждом опросе.
function updateLive(job) {
  const steps = job.steps, done = steps.filter(s => s.state === 'done').length;
  const sum = document.getElementById('hlive-summary');
  if (job.running) {
    const pct = steps.length ? Math.round(done * 100 / steps.length) : 0;
    const label = `Проверяю: шаг ${Math.min(done + 1, steps.length)} из ${steps.length}`;
    if (!sum.firstChild || !sum.querySelector('.hbar')) {
      sum.innerHTML = `<div class="health-summary live"><span class="hspin"></span><span id="hlive-label"></span><span class="hbar"><i id="hlive-bar"></i></span><small id="hlive-time" class="mono"></small></div>`;
    }
    document.getElementById('hlive-label').textContent = label;
    document.getElementById('hlive-bar').style.width = pct + '%';
    document.getElementById('hlive-time').textContent = (job.elapsed_ms / 1000).toFixed(1) + ' с';
  } else if (job.report) {
    sum.innerHTML = healthSummary(job.report);
  }
  for (const s of steps) {
    if (healthShown[s.id] === s.state) continue;
    healthShown[s.id] = s.state;
    const st = document.getElementById(`hs-${s.id}-st`), body = document.getElementById(`hs-${s.id}-body`);
    if (!st || !body) continue;
    if (s.state === 'pending') { st.innerHTML = '<i class="hdot"></i>ожидает'; body.innerHTML = ''; }
    else if (s.state === 'running') { st.innerHTML = '<span class="hspin"></span>идёт'; body.innerHTML = '<div class="health-row"><span class="ic"><span class="hspin"></span></span><div style="color:var(--text-muted)">проверяется…</div></div>'; }
    else {
      st.innerHTML = `${LEVEL_ICONS[worstLevel(s.items || [])] || ''}<span class="mono">${s.millis} мс</span>`;
      body.innerHTML = (s.items || []).map(healthRow).join('') || '<div class="health-row"><div style="color:var(--text-muted)">нечего проверять</div></div>';
      const grp = document.getElementById('hs-' + s.id); if (grp) grp.dataset.level = worstLevel(s.items || []);
    }
  }
  if (!job.running && job.report) foldHealth();
}

// Следит за ходом проверки на сервере и рисует шаги по мере готовности. Сама проверку не запускает.
function followJob() {
  const box = document.getElementById('check-result');
  stopHealthPoll();
  let skeletonFor = -1, failures = 0;
  const tick = async () => {
    healthTimer = null;
    if (currentTab !== 'health') return; // ушли со страницы: при возвращении покажем, как идёт проверка
    try {
      const res = await fetch('/api/v1/system/check/job');
      if (!res.ok) throw new Error('http ' + res.status);
      const job = await res.json();
      failures = 0;
      if (job.seq !== skeletonFor) { box.innerHTML = liveSkeleton(job); skeletonFor = job.seq; }
      updateLive(job);
      if (job.running) { healthTimer = setTimeout(tick, 300); return; }
      if (job.report) setHealthBadge(job.report);
    } catch (e) {
      if (++failures > 5) { box.textContent = 'Связь с панелью потеряна: проверка не завершена'; return; }
      healthTimer = setTimeout(tick, 1000);
    }
  };
  tick();
}

// Проверка запускается только вручную (кнопки «Проверить» и «Проверить подключения клиентом»)
async function runCheck(deep) {
  const box = document.getElementById('check-result');
  stopHealthPoll();
  box.innerHTML = '<div style="color:var(--text-muted)">Запускаю проверку…</div>';
  let started;
  try { started = await fetch('/api/v1/system/check/start' + (deep ? '?deep=1' : ''), {method: 'POST'}); } catch (e) { started = null; }
  if (!started || !started.ok) { box.textContent = 'Не удалось запустить проверку'; return; }
  followJob();
}

// Открытие вкладки: ничего не запускаем. Идёт проверка – показываем ход; есть прежний результат – показываем его; иначе подсказка.
async function healthOpen() {
  const box = document.getElementById('check-result');
  if (box.firstElementChild && !box.querySelector('.health-idle')) return; // уже показано (ход или результат): ничего не стираем
  try {
    const r = await fetch('/api/v1/system/check/job');
    if (r.ok) {
      const job = await r.json();
      if (job && job.steps && job.steps.length) {
        if (job.running) { followJob(); return; }
        if (job.report) { renderCheck(job.report, '<div class="form-hint" style="margin-bottom:8px">Показан результат последней проверки. Чтобы обновить, нажмите «Проверить».</div>'); return; }
      }
    }
  } catch (e) {}
  box.innerHTML = '<div class="form-hint health-idle">Проверка ещё не запускалась. Нажмите «Проверить».</div>';
}

// Исправление одного результата. После него идёт повторная проверка, результат показывается обновлённым.
async function fixOne(btn) {
  const code = btn.dataset.fix;
  if (FIX_CONFIRM.test(code)) {
    const tip = (btn.closest('.health-row').querySelector('.fixtip') || {}).textContent || '';
    if (!await uiConfirm('Применить исправление?', tip.replace(/^Исправление:\s*/, ''), 'Исправить')) return;
  }
  btn.disabled = true; btn.textContent = 'Исправляю…';
  const r = await api('POST', '/api/v1/system/fix', {codes: [code]});
  if (!r.ok) { btn.disabled = false; btn.textContent = 'Исправить'; uiAlert('Не удалось исправить', (r.data && r.data.error) || 'Ошибка'); return; }
  let extra = '';
  (r.data.done || []).forEach(m => extra += `<div class="health-row"><span class="ic">${LEVEL_ICONS.ok}</span><div>${esc(m)}</div></div>`);
  (r.data.failed || []).forEach(m => extra += `<div class="health-row"><span class="ic">${LEVEL_ICONS.bad}</span><div>${esc(m)}</div></div>`);
  renderCheck(r.data.report, extra);
  loadSystemStatus();
}


/* ---------- Отчёт для поддержки ---------- */
async function openSupportReport() {
  const box = document.getElementById('report-text');
  box.value = 'Собираю отчёт…';
  openModal('report-modal');
  const r = await api('GET', '/api/v1/system/report');
  box.value = r.ok ? r.data.text : 'Не удалось собрать отчёт: ' + String((r.data && r.data.error) || 'ошибка');
}
function copyReport() { copyText(document.getElementById('report-text').value); toast('Скопировано'); }
function downloadReport() {
  const blob = new Blob([document.getElementById('report-text').value], {type: 'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'kitsune-report.txt';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
