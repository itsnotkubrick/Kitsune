function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b === 0) return '0 МБ';
  const k = 1024;
  const sizes = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDays(ms) {
  if (!ms || ms === 0) return 'Бессрочно';
  const diff = Math.ceil((new Date(ms) - new Date()) / (1000 * 60 * 60 * 24));
  if (diff <= 0) return '<span style="color:var(--accent-rose)">Истек</span>';
  return `${diff} дн.`;
}

function toggleSidebarCollapse(silent) {
  const sb = document.getElementById('main-sidebar');
  const isExpanded = sb.classList.toggle('expanded');
  document.getElementById('collapse-icon').innerHTML = isExpanded
    ? '<polyline points="15 18 9 12 15 6"></polyline>'
    : '<polyline points="9 18 15 12 9 6"></polyline>';
  if (!silent) { try { localStorage.setItem('kitsune-sidebar', isExpanded ? 'expanded' : 'collapsed'); } catch (e) {} }
}

// Оформление: «Стекло», тоны dawn и night
function setTheme(theme, tone) {
  const d = document.documentElement;
  d.dataset.theme = theme;
  if (tone) d.dataset.tone = tone;
  try { localStorage.setItem('kitsune-theme', theme); if (tone) localStorage.setItem('kitsune-tone', tone); } catch (e) {}
  markThemeMenu();
  if (currentTab === 'dashboards' && typeof loadMetrics === 'function') loadMetrics();
}

function markThemeMenu() {
  if (typeof markTopTone === 'function') markTopTone();
  const d = document.documentElement, cur = d.dataset.theme === 'glass' ? 'glass:' + d.dataset.tone : d.dataset.theme;
  document.querySelectorAll('#theme-pop [data-theme-pick]').forEach(b => b.classList.toggle('on', b.dataset.themePick === cur));
}

function toggleThemeMenu(e) {
  if (e) e.stopPropagation();
  const pop = document.getElementById('theme-pop'), btn = document.getElementById('theme-btn');
  const open = pop.hidden;
  pop.hidden = !open; btn.setAttribute('aria-expanded', String(open));
  if (open) markThemeMenu();
}

document.addEventListener('click', e => {
  const pick = e.target.closest && e.target.closest('#theme-pop [data-theme-pick]');
  if (pick) { const [t, n] = pick.dataset.themePick.split(':'); setTheme(t, n); }
  const pop = document.getElementById('theme-pop');
  if (pop && !pop.hidden && !(e.target.closest && e.target.closest('.theme-wrap') && !pick)) { pop.hidden = true; document.getElementById('theme-btn').setAttribute('aria-expanded', 'false'); }
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { const pop = document.getElementById('theme-pop'); if (pop && !pop.hidden) { pop.hidden = true; document.getElementById('theme-btn').focus(); } } });

function initSidebar() {
  // в «Стекле» меню по умолчанию – узкая рейка с подписями под значками
  let st = document.documentElement.dataset.theme === 'glass' ? 'collapsed' : 'expanded';
  try { st = localStorage.getItem('kitsune-sidebar') || st; } catch (e) {}
  if (st === 'collapsed') toggleSidebarCollapse(true);
  if (!document.querySelector('.nav-item.active')) document.querySelector('.nav-item[data-tab="dashboards"]').classList.add('active');
}

const VIEWS = ['clients', 'templates', 'groups', 'dashboards', 'inbounds', 'cascade', 'tools', 'health', 'audit', 'settings'];
const TITLES = {
  dashboards: ['Главная', 'Всё ли работает и что происходит на сервере'],
  clients: ['Пользователи', 'Доступ, лимиты и ссылки подписки'],
  inbounds: ['Подключения', 'Протоколы, по которым пользователи выходят в сеть'],
  templates: ['Шаблоны', 'Готовые наборы лимитов для новых пользователей'],
  groups: ['Группы', 'Какие подключения видит пользователь'],
  cascade: ['Каскад', 'Вход через узел в другой сети: клиент идёт на узел, узел пересылает на этот сервер'],
  tools: ['Роутинг', 'Что идёт через VPN, а что напрямую; при желании – готовый файл для роутера'],
  health: ['Здоровье', 'Проверка сервера и безопасное автоисправление'],
  audit: ['Журнал', 'Кто и что менял в панели, системные события'],
  settings: ['Настройки', 'Безопасность, сеть, подписка, ядра, обновления и копии']
};
let currentTab = 'dashboards';
let dashTimer = null;

function moveSlider() {} // прежний ползунок меню убран: активный пункт подсвечивается классом

function navigateTo(tab, elem) {
  currentTab = tab;
  // «Шаблоны» и «Группы» – вкладки страницы «Пользователи», в меню подсвечен её пункт
  const navTab = (tab === 'templates' || tab === 'groups') ? 'clients' : tab;
  document.querySelectorAll('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.tab === navTab));
  document.querySelectorAll('.tabs-strip .tab-btn[data-tab]').forEach(b => { const on = b.dataset.tab === tab; b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on)); });

  VIEWS.forEach(v => {
    document.getElementById('view-' + v).style.display = (tab === v) ? 'flex' : 'none';
  });
  // Верхние карточки-сводка нужны только на страницах со списками
  document.querySelector('.overview-row').style.display = 'none';

  document.getElementById('page-title').textContent = TITLES[tab][0];
  document.getElementById('page-subtitle').textContent = TITLES[tab][1];

  if (tab === 'clients') loadUsers();
  if (tab === 'inbounds') loadInbounds();
  if (tab === 'health') healthOpen(); // только показываем прежний результат: проверки запускаются кнопками
  if (tab === 'audit') loadAudit();
  if (window['on' + tab[0].toUpperCase() + tab.slice(1) + 'Tab']) window['on' + tab[0].toUpperCase() + tab.slice(1) + 'Tab']();
  if (tab === 'settings') { loadUpdateSettings(); loadServerSettings(); loadMasking(); loadPortMode(); loadTelegram(); loadPanelTLS(); loadSubSettings(); loadTOTP(); }
  if (tab === 'settings') showSettingsSec(settingsSec);
  if (tab === 'tools') {
    const fr = document.getElementById('tools-frame');
    if (!fr.getAttribute('src')) fr.setAttribute('src', fr.dataset.src);
  }
  if (tab === 'dashboards') { loadMetrics(); }
}

// Высота встроенной страницы «Роутинг» приходит от неё самой (только из своего фрейма и своего источника)
window.addEventListener('message', e => {
  const fr = document.getElementById('tools-frame');
  if (!fr || e.origin !== location.origin || e.source !== fr.contentWindow) return;
  const h = e.data && e.data.kitsuneToolsHeight;
  if (Number.isFinite(h) && h > 200 && h < 20000) fr.style.height = Math.ceil(h) + 'px';
});

const fmtVer = v => String(v).replace(/-/g, ' ');
const esc = t => String(t).replace(/[&<>"'\\]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','\\':'&#92;'}[ch]));
// Значение внутри JS-строки в обработчике onclick="...('${escJs(x)}')": спецсимволы становятся \uXXXX, затем HTML-экранирование.
const escJs = t => esc(String(t).replace(/[^\w .,:@\/+\-]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0')));
