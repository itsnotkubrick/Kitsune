/* ---------- Мастер первой настройки (главная) ---------- */
const WIZ_KEY = 'kitsune-wizard';

function wizGet(k) { try { return localStorage.getItem(WIZ_KEY + '-' + k) === '1'; } catch (e) { return false; } }
function wizSet(k) { try { localStorage.setItem(WIZ_KEY + '-' + k, '1'); } catch (e) {} }

function wizardDismiss() {
  wizSet('hidden');
  document.getElementById('wizard').style.display = 'none';
}

// Выдать ссылку первого пользователя и запомнить, что шаг пройден
async function wizardShowLink() {
  if (!usersCache.length) await loadUsers();
  const u = usersCache[0];
  if (!u) return;
  wizSet('linkseen'); // окно открыто, но шаг закрывается только явным «Я передал ссылку»
  await showUserLinks(u.id);
  renderWizardLast();
}
function wizardLinkDone() { wizSet('link'); renderWizardLast(); }

let wizardLast = null;
function renderWizardLast() { if (wizardLast) renderWizard(wizardLast); }

function renderWizard(s) {
  wizardLast = s;
  const box = document.getElementById('wizard');
  if (!box) return;
  const steps = [
    {done: s.inbounds > 0, title: 'Создайте подключения',
     text: 'Скачаем ядро и создадим VLESS + REALITY с резервным XHTTP.',
     btn: 'Быстрая настройка', act: "quickSetup()"},
    {done: s.users > 0, title: 'Добавьте пользователя',
     text: 'Один пользователь на человека или устройство. Лимиты можно задать позже.',
     btn: 'Добавить пользователя', act: "openAddUserModal()"},
    {done: wizGet('link') || s.traffic > 0, title: 'Передайте ссылку',
     text: 'Ссылка подписки или QR-код для приложения (v2rayN, Hiddify, Streisand и др.).',
     btn: wizGet('linkseen') ? 'Я передал ссылку' : 'Показать ссылку', act: wizGet('linkseen') ? "wizardLinkDone()" : "wizardShowLink()",
     btn2: wizGet('linkseen') ? 'Показать снова' : null, act2: "wizardShowLink()"},
    {done: s.traffic > 0, title: 'Дождитесь первого подключения',
     text: 'Как только пользователь выйдет в сеть, здесь появится трафик, а шаг закроется сам.',
     btn: null}
  ];
  const doneN = steps.filter(x => x.done).length;
  // всё пройдено или скрыто вручную: мастер не нужен
  if (doneN === steps.length || wizGet('hidden')) { box.style.display = 'none'; return; }
  box.style.display = '';
  const firstOpen = steps.findIndex(x => !x.done);
  document.getElementById('wizard-fill').style.width = (doneN / steps.length * 100) + '%';
  document.getElementById('wizard-sub').textContent = `Выполнено ${doneN} из ${steps.length}`;
  document.getElementById('wizard-steps').innerHTML = steps.map((x, i) => {
    const cls = x.done ? 'done' : (i === firstOpen ? 'current' : 'todo');
    const dis = !x.done && i !== firstOpen;
    const btn = x.btn && !x.done
      ? `<button class="btn ${i === firstOpen ? '' : 'soft'}" ${dis && i > firstOpen + 0 && !steps[i - 1].done ? 'disabled' : ''} onclick="${x.act}">${x.btn}</button>` + (x.btn2 ? ` <button class="btn soft" onclick="${x.act2}">${x.btn2}</button>` : '') : '';
    return `<li class="wizard-step ${cls}"><span class="wizard-num">${x.done ? '✓' : i + 1}</span>
      <div class="wizard-body"><b>${esc(x.title)}</b><span>${esc(x.text)}</span></div>${btn}</li>`;
  }).join('');
}
