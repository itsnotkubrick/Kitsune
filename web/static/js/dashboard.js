/* ---------- Дашборд: графики ---------- */
// Цвета графиков берутся из CSS-переменных темы (--chart-*)
const chartColor = (n, fb) => (getComputedStyle(document.documentElement).getPropertyValue('--chart-' + n).trim() || fb);

function fmtBps(v) {
  if (!v || v < 1) return '0 Б/с';
  const u = ['Б/с', 'КБ/с', 'МБ/с', 'ГБ/с'];
  const i = Math.min(Math.floor(Math.log(v) / Math.log(1024)), 3);
  return (v / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}

function fmtUptime(sec) {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d} дн. ${h} ч.` : (h ? `${h} ч. ${m} мин.` : `${m} мин.`);
}

function drawChart(svgId, series, maxVal) {
  const svg = document.getElementById(svgId);
  const W = 600, H = 150, pad = 6;
  const n = Math.max(...series.map(s => s.data.length), 2);
  const max = maxVal || Math.max(1, ...series.flatMap(s => s.data)) * 1.15;
  let out = '';
  for (let g = 0; g <= 4; g++) {
    const y = pad + (H - 2 * pad) * g / 4;
    out += `<line x1="0" x2="${W}" y1="${y}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-width="1" vector-effect="non-scaling-stroke"/>`;
  }
  series.forEach((s, idx) => {
    if (s.data.length < 2) return;
    const pts = s.data.map((v, i) => {
      const x = (i / (n - 1)) * W;
      const y = H - pad - (Math.min(v, max) / max) * (H - 2 * pad);
      return [x, y];
    });
    const line = pts.map(p => p.join(',')).join(' ');
    const area = `0,${H - pad} ${line} ${pts[pts.length - 1][0]},${H - pad}`;
    out += `<polygon points="${area}" fill="${s.color}" opacity="0.12"/>`;
    out += `<polyline points="${line}" fill="none" stroke="${s.color}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
  });
  svg.innerHTML = out;
}

// «168.76 ГБ» -> «168.76» крупно и «ГБ» мелко
function numUnit(txt) {
  const m = String(txt).match(/^([\d.,]+)\s*(.*)$/);
  return m ? `${esc(m[1])} <small>${esc(m[2])}</small>` : esc(txt);
}

function barRow(label, valueText, pct) {
  const cls = pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : '';
  return `<div class="bar-row"><div class="bar-head"><span>${esc(label)}</span><span>${esc(valueText)}</span></div><div class="bar-track" role="progressbar" aria-label="${esc(label)}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(Math.min(100, pct))}" aria-valuetext="${esc(valueText)}"><div class="bar-fill ${cls}" style="width:${Math.min(100, pct).toFixed(1)}%"></div></div></div>`;
}


// Метка свежести данных: видно, что главная обновляется, а при сбое – что она перестала.
let metricsOkAt = 0, metricsFail = false;
function showMetricsAge() {
  const el = document.getElementById('metrics-age');
  if (!el) return;
  const stale = metricsFail || (metricsOkAt && Date.now() - metricsOkAt > 35000);
  el.classList.toggle('stale', !!stale);
  if (!metricsOkAt) { el.textContent = ''; return; }
  const t = new Date(metricsOkAt).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
  el.textContent = stale ? 'Нет связи: данные не обновляются с ' + t : 'Обновлено ' + t;
}
setInterval(showMetricsAge, 5000);

async function loadMetrics() {
  if (currentTab !== 'dashboards') return;
  let d;
  try {
    const res = await fetch('/api/v1/system/metrics');
    if (!res.ok) { metricsFail = true; showMetricsAge(); return; }
    d = await res.json();
  } catch (e) { metricsFail = true; showMetricsAge(); return; }
  metricsFail = false; metricsOkAt = Date.now(); showMetricsAge();
  const h = d.host, hist = d.history || [];

  const st = await (await fetch('/api/v1/system/status')).json().catch(() => ({}));
  const total = d.inbounds.filter(i => i.enable).length;
  const live = d.inbounds.filter(i => i.enable && i.listening).length;
  const running = (d.cores || []).filter(c => c.running).map(c => c.name);

  renderHero(d, h, st, total, live, running);

  // График сети
  const memPct = h.mem_total ? h.mem_used / h.mem_total * 100 : 0;
  drawChart('chart-net', [
    {data: hist.map(x => x.rx_bps), color: chartColor('rx', '#10b981')},
    {data: hist.map(x => x.tx_bps), color: chartColor('tx', '#f5a524')}
  ]);
  document.getElementById('lg-rx').textContent = fmtBps(h.rx_bps);
  document.getElementById('lg-tx').textContent = fmtBps(h.tx_bps);

  // Ресурсы
  let bars = '';
  bars += barRow('Процессор', h.cpu.toFixed(1) + '%', h.cpu);
  bars += barRow('Память', `${formatBytes(h.mem_used)} из ${formatBytes(h.mem_total)}`, memPct);
  if (h.disk_total) bars += barRow('Диск', `${formatBytes(h.disk_used)} из ${formatBytes(h.disk_total)}`, h.disk_used / h.disk_total * 100);
  // нагрузка – тоже полоса, как остальные: средняя очередь за минуту относительно числа ядер
  const cpus = h.cpus || 1;
  bars += barRow('Нагрузка', `${h.load1.toFixed(2)} · ${cpus} яд.`, h.load1 / cpus * 100);
  document.getElementById('res-bars').innerHTML = bars;
  document.getElementById('res-up').textContent = 'работает ' + fmtUptime(h.uptime_sec);

  // Трафик по пользователям: пять строк, остальные раскрываются
  window.__topData = {top: d.traffic.top || [], total: d.clients.total || 0};
  renderTop();
}

let topOpen = false;
function renderTop() {
  const {top, total} = window.__topData || {top: [], total: 0};
  const el = document.getElementById('top-traffic'), btn = document.getElementById('top-more');
  if (!el) return;
  const shown = topOpen ? top : top.slice(0, 5);
  const maxUsed = Math.max(1, ...top.map(t => t.used));
  el.innerHTML = shown.length
    ? shown.map(t => barRow(t.email, formatBytes(t.used) + (t.limit ? ' / ' + formatBytes(t.limit) : ''), t.limit ? t.used / t.limit * 100 : t.used / maxUsed * 100)).join('')
    : '<div style="color:var(--text-muted);font-size:13px">Пока нет данных о трафике</div>';
  el.classList.toggle('open', topOpen);
  const rest = Math.max(top.length, total) - 5;
  btn.style.display = rest > 0 ? '' : 'none';
  btn.setAttribute('aria-expanded', topOpen ? 'true' : 'false');
  btn.textContent = topOpen ? 'Свернуть' : `Показать ещё ${rest}`;
}
document.addEventListener('click', e => { if (e.target && e.target.id === 'top-more') { topOpen = !topOpen; renderTop(); } });

// Вердикт на главной: одним взглядом – всё ли работает; если нет, то что именно.
function renderHero(d, h, st, total, live, running) {
  const problems = [];
  let level = 'ok';
  const bump = l => { if (l === 'bad' || level === 'ok') level = l; };
  const memPct = h.mem_total ? h.mem_used / h.mem_total * 100 : 0;
  const diskPct = h.disk_total ? h.disk_used / h.disk_total * 100 : 0;
  const firstRun = total === 0 && !wizGet('hidden');
  if (firstRun) { problems.push('Сервер ещё не настроен: пройдите первую настройку ниже'); bump('warn'); }
  else if (total === 0) { problems.push('Подключений пока нет: создайте первое во вкладке «Подключения»'); bump('warn'); }
  else if (!running.length) { problems.push('Ядра не запущены'); bump('bad'); }
  else if (live < total) { problems.push(`${total - live} из ${total} подключений не слушают свой порт`); bump('bad'); }
  if (d.config.state === 'invalid') { problems.push('Файл настроек ядра с ошибкой'); bump('bad'); }
  if (diskPct >= 90) { problems.push('Почти заполнен диск'); bump('warn'); }
  if (memPct >= 90) { problems.push('Мало свободной памяти'); bump('warn'); }
  const hero = document.getElementById('hero');
  hero.className = 'hero' + (level === 'ok' ? '' : ' ' + level);
  document.getElementById('hero-fix').style.display = (level === 'ok' || firstRun) ? 'none' : '';
  document.getElementById('hero-ic').textContent = level === 'ok' ? '✓' : '!';
  document.getElementById('hero-title').textContent = level === 'ok' ? 'Всё работает' : (level === 'bad' ? 'Есть проблема' : (firstRun ? 'Добро пожаловать в Kitsune' : 'Нужно внимание'));
  document.getElementById('hero-sub').textContent = problems.length ? problems.join(' · ')
    : `${live} из ${total} подключений слушают порт · сервер работает ${fmtUptime(h.uptime_sec)}`;

  if (typeof setTopStatus === 'function') setTopStatus(level, firstRun);

  const usersTotal = d.clients.active + d.clients.disabled + d.clients.expired;
  document.getElementById('k-users').textContent = d.clients.active;
  document.getElementById('k-traffic').innerHTML = numUnit(formatBytes(d.traffic.total_used));
  document.getElementById('k-conn').innerHTML = `${live} <small>из ${total}</small>`;
  document.getElementById('k-exp').textContent = d.clients.expiring || 0;

  renderWizard({inbounds: total, users: usersTotal, traffic: d.traffic.total_used});

  // версия в меню
  document.querySelectorAll('.js-ver').forEach(e => { e.textContent = 'v' + fmtVer(d.version); });
}
