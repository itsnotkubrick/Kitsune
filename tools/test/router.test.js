// Команда для роутера (Keenetic + Mihomo): порядок шагов, права, откат при провале проверки. Выполняется настоящей оболочкой
// с поддельными mihomo и xkeen в подменённом каталоге вместо /opt/etc/mihomo.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { routerCommand } = require(path.join(__dirname, '..', '..', 'web', 'tools', 'lib', 'router.js'));
const BODY = '# kitsune\nsecret: SECRET-VALUE-XYZ\nrules:\n  - MATCH,DIRECT\n';
const cmd = (options) => routerCommand('keenetic', 'mihomo', { 'config.yaml': BODY }, options);

test('команда: порядок шагов – копия, запись в .new, проверка, только потом mv и перезапуск', () => {
  const c = cmd().split('\n').filter((l) => !l.startsWith('#')).join('\n'); // комментарии с подсказкой про откат не в счёт
  const at = (s) => c.indexOf(s);
  assert.ok(at('cp -a "$PM_CF" "$PM_CF.bak-$PM_TS"') > 0);
  assert.ok(at('cp -a') < at('cat > "$PM_CF.new"'));
  assert.ok(at('cat > "$PM_CF.new"') < at('mihomo -d /opt/etc/mihomo -t -f "$PM_CF.new"'));
  assert.ok(at('mihomo -d /opt/etc/mihomo -t -f') < at('mv "$PM_CF.new" "$PM_CF"'));
  assert.ok(at('mv "$PM_CF.new"') < at('xkeen -restart'));
  assert.ok(!/cat > "\$PM_CF"\s/.test(c) && !/> \/opt\/etc\/mihomo\/config\.yaml\s/.test(c), 'рабочий файл напрямую не перезаписывается');
  assert.strictEqual((c.match(/\bmv /g) || []).length, 1);
  assert.ok(/if \[ "\$PM_OK" = 0 \]; then[\s\S]*mv [\s\S]*else/.test(c), 'mv только в ветке успешной проверки');
  assert.ok(!/\bexit\b/.test(c), 'exit закрыл бы SSH-сессию');
  assert.ok(!/\beval\b/.test(c));
});

test('команда: secret встречается только внутри файла, права 600, синтаксис sh корректен', () => {
  const c = cmd();
  assert.strictEqual(c.split('SECRET-VALUE-XYZ').length - 1, 1);
  assert.ok(c.includes('umask 077') && c.includes('chmod 600 "$PM_CF.bak-$PM_TS"') && c.includes('chmod 600 "$PM_CF"'));
  assert.ok(c.includes('Откат:') && c.includes('config.yaml.bak-'));
  const r = spawnSync('sh', ['-n'], { input: c });
  assert.strictEqual(r.status, 0, String(r.stderr));
});

test('Xray и OpenWrt остаются прежними', () => {
  const x = routerCommand('keenetic', 'xray', { '04_outbounds.json': '{}\n', '05_routing.json': '{}\n' });
  assert.ok(x.includes('/opt/etc/xray/configs/04_outbounds.json') && x.includes('xkeen -restart'));
  const o = routerCommand('openwrt', 'mihomo', { 'config.yaml': 'a: 1\n' });
  assert.ok(o.includes('/etc/nikki/profiles/kitsune.yaml') && o.includes('uci commit nikki'));
  assert.throws(() => routerCommand('openwrt', 'xray', {}));
});

// Запуск команды в песочнице: /opt/etc/mihomo заменён временным каталогом, mihomo и xkeen поддельные.
function run({ mihomoExit, withMihomo = true, oldConfig, options }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-router-'));
  const conf = path.join(dir, 'mihomo');
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'xkeen'), '#!/bin/sh\necho restart >> "' + dir + '/events"\n', { mode: 0o755 });
  if (withMihomo) fs.writeFileSync(path.join(bin, 'mihomo'), '#!/bin/sh\necho "mihomo $*" >> "' + dir + '/events"\n[ "' + mihomoExit + '" = 0 ] || echo "ошибка в конфиге"\nexit ' + mihomoExit + '\n', { mode: 0o755 });
  fs.mkdirSync(conf);
  if (oldConfig !== undefined) fs.writeFileSync(path.join(conf, 'config.yaml'), oldConfig, { mode: 0o644 });
  const script = cmd(options).split('/opt/etc/mihomo').join(conf);
  const r = spawnSync(process.env.PM_TEST_SH || '/bin/sh', ['-c', script], { env: { PATH: bin + ':/usr/bin:/bin', HOME: dir }, encoding: 'utf8' });
  const events = fs.existsSync(path.join(dir, 'events')) ? fs.readFileSync(path.join(dir, 'events'), 'utf8') : '';
  const files = fs.readdirSync(conf);
  const mode = (f) => (fs.statSync(path.join(conf, f)).mode & 0o777).toString(8);
  return { r, events, files, conf, mode, read: (f) => fs.readFileSync(path.join(conf, f), 'utf8') };
}

test('выполнение: проверка прошла – старый файл в копии, новый на месте, права 600, перезапуск один раз', () => {
  const x = run({ mihomoExit: 0, oldConfig: 'old: 1\n' });
  assert.strictEqual(x.r.status, 0, x.r.stderr);
  assert.strictEqual(x.read('config.yaml'), BODY);
  const bak = x.files.find((f) => f.startsWith('config.yaml.bak-'));
  assert.ok(bak, 'копия создана');
  assert.strictEqual(x.read(bak), 'old: 1\n');
  assert.strictEqual(x.mode('config.yaml'), '600');
  assert.strictEqual(x.mode(bak), '600');
  assert.ok(!x.files.includes('config.yaml.new'));
  assert.strictEqual(x.events.split('\n').filter((l) => l === 'restart').length, 1);
  assert.match(x.events, /mihomo -d .* -t -f .*config\.yaml\.new/);
});

test('выполнение: проверка не прошла – рабочий файл не тронут, перезапуска нет, ошибка показана', () => {
  const x = run({ mihomoExit: 1, oldConfig: 'old: 1\n' });
  assert.strictEqual(x.read('config.yaml'), 'old: 1\n');
  assert.ok(x.files.includes('config.yaml.new'), 'новый файл остался рядом для разбора');
  assert.ok(!/restart/.test(x.events));
  assert.match(x.r.stdout, /не прошёл проверку/);
  assert.match(x.r.stdout, /ошибка в конфиге/);
});

test('выполнение: первого файла ещё нет – команда не падает, копии нет', () => {
  const x = run({ mihomoExit: 0 });
  assert.strictEqual(x.read('config.yaml'), BODY);
  assert.ok(!x.files.some((f) => f.includes('.bak-')));
});

test('выполнение: mihomo нет в PATH – рабочий файл не заменяется, новый лежит рядом, перезапуска нет', () => {
  const x = run({ mihomoExit: 0, withMihomo: false, oldConfig: 'old: 1\n' });
  assert.match(x.r.stdout, /mihomo не найден в PATH, проверить конфиг нельзя/);
  assert.strictEqual(x.read('config.yaml'), 'old: 1\n');
  assert.strictEqual(x.read('config.yaml.new'), BODY);
  assert.ok(!/xkeen/.test(x.events || ''), 'перезапуска нет');
});

// Блок dns: ведёт XKeen UI. Старый файл – как его оставляет панель DNS: комментарии, списки, nameserver-policy.
const OLD_WITH_DNS = `# мои заметки
log-level: info
dns:
  # включено XKeen UI
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  nameserver-policy:
    "+.ru": [77.88.8.8, 77.88.8.1]
    "+.su": 77.88.8.8
  fallback-filter: {geoip: false}

proxies:
  - name: old-node
rules:
  - MATCH,DIRECT
`;
const DNS_BLOCK = OLD_WITH_DNS.slice(OLD_WITH_DNS.indexOf('dns:\n'), OLD_WITH_DNS.indexOf('proxies:'));

test('dns: блок переносится дословно, остальное из старого файла не попадает в новый', () => {
  const x = run({ mihomoExit: 0, oldConfig: OLD_WITH_DNS });
  const now = x.read('config.yaml');
  assert.ok(now.startsWith(BODY));
  assert.ok(now.includes(DNS_BLOCK.replace(/\n+$/, '')), 'блок dns: переехал без изменений');
  assert.ok(!/old-node|мои заметки|log-level: info/.test(now), 'остальное из старого файла не переносится');
  assert.strictEqual((now.match(/^dns:/gm) || []).length, 1);
  assert.match(x.r.stdout, /Блок dns: перенесён/);
  assert.ok(!x.files.includes('config.yaml.dns') && !x.files.includes('config.yaml.new'), 'временные файлы убраны');
  assert.strictEqual(x.mode('config.yaml'), '600');
});

test('dns: блок в конце файла, с хвостовым комментарием, однострочный', () => {
  for (const old of ['rules:\n  - MATCH,DIRECT\ndns:\n  enable: true\n  nameserver:\n  - 1.1.1.1\n', 'dns: # из XKeen UI\n  enable: true\nrules: []\n', 'dns: {enable: true}\nrules: []\n']) {
    const x = run({ mihomoExit: 0, oldConfig: old });
    const now = x.read('config.yaml');
    const block = old.split('\n').filter((l, i, a) => i >= a.findIndex((s) => s.startsWith('dns:')) && !/^(rules)/.test(l)).join('\n').trim();
    assert.ok(now.includes(block), 'не перенесён: ' + JSON.stringify(old));
    assert.ok(!/rules: \[\]|MATCH,DIRECT\n?$/.test(now.replace(BODY, '')), 'чужие rules не попали');
  }
});

test('dns: нет в старом файле, нет самого файла, похожие ключи – не переносится и не падает', () => {
  for (const old of [undefined, 'rules:\n  - MATCH,DIRECT\n', 'dnsx:\n  a: 1\ndns-extra: 1\n']) {
    const x = run({ mihomoExit: 0, oldConfig: old });
    assert.strictEqual(x.read('config.yaml'), BODY, JSON.stringify(old));
  }
});

test('dns: без галочки блок не переносится', () => {
  const x = run({ mihomoExit: 0, oldConfig: OLD_WITH_DNS, options: { keepDns: false } });
  assert.strictEqual(x.read('config.yaml'), BODY);
  assert.ok(!/while IFS=|PM_TAB=/.test(cmd({ keepDns: false })));
});

test('dns: при провале проверки старый файл с dns: цел, перенесённый блок остаётся только в .new', () => {
  const x = run({ mihomoExit: 1, oldConfig: OLD_WITH_DNS });
  assert.strictEqual(x.read('config.yaml'), OLD_WITH_DNS);
  assert.ok(x.read('config.yaml.new').includes('nameserver-policy'));
});

test('dns: команда обходится без awk и sed (на части роутеров их нет в BusyBox)', () => {
  const c = cmd().split('\n').filter((l) => !l.startsWith('#')).join('\n');
  assert.ok(!/\b(awk|sed|gawk|perl|python)\b/.test(c));
  // внешние программы – только те, что есть в любой оболочке Entware: cp, chmod, mkdir, date, cat, mv, rm, grep, mihomo, xkeen
  const used = new Set((c.match(/(?:^|[;&|(]\s*|\bthen\s+|\belse\s+)([a-z][a-z0-9-]*)(?=\s)/gm) || []).map((s) => s.replace(/^[;&|(]\s*|^(then|else)\s+/, '').trim()));
  const allowed = new Set(['umask', 'mkdir', 'cp', 'chmod', 'date', 'echo', 'cat', 'mv', 'rm', 'grep', 'mihomo', 'xkeen', 'command', 'printf', 'unset', 'export', 'if', 'then', 'else', 'elif', 'fi', 'while', 'do', 'done', 'case', 'esac', 'read']);
  for (const u of used) assert.ok(allowed.has(u) || /^PM_/.test(u), 'неожиданная команда: ' + u);
});

test('dns: последняя строка блока без перевода строки и пробелы/табуляция в отступах переносятся', () => {
  const old = 'rules: []\ndns:\n  enable: true\n\tnameserver: [1.1.1.1]\n  # коммент\n  fallback: x'; // без \n в конце
  const x = run({ mihomoExit: 0, oldConfig: old });
  const now = x.read('config.yaml');
  assert.ok(now.includes('dns:\n  enable: true\n\tnameserver: [1.1.1.1]\n  # коммент\n  fallback: x\n'), JSON.stringify(now));
  assert.ok(!/rules: \[\]/.test(now));
});

test('dns: если блок есть, а перенести его не удалось, рабочий файл не заменяется', () => {
  // grep видит dns:, но перенос сломан: подмена read через функцию в оболочке, как будто чтение файла не вернуло ничего
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-router-'));
  const conf = path.join(dir, 'mihomo'); fs.mkdirSync(conf);
  fs.writeFileSync(path.join(conf, 'config.yaml'), 'dns:\n  enable: true\n');
  const bin = path.join(dir, 'bin'); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'mihomo'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'xkeen'), '#!/bin/sh\necho restart >> "' + dir + '/events"\n', { mode: 0o755 });
  const script = 'read() { return 1; }\n' + cmd().split('/opt/etc/mihomo').join(conf);
  const r = spawnSync('/bin/bash', ['-c', script], { env: { PATH: bin + ':/usr/bin:/bin', HOME: dir }, encoding: 'utf8' });
  assert.strictEqual(fs.readFileSync(path.join(conf, 'config.yaml'), 'utf8'), 'dns:\n  enable: true\n');
  assert.match(r.stdout, /не удалось перенести/);
  assert.ok(!fs.existsSync(path.join(dir, 'events')), 'перезапуска нет');
});

test('PATH: каталоги Entware добавляются в начало команды (запуск файлом по ssh без входа в оболочку)', () => {
  const lines = cmd().split('\n').filter((l) => !l.startsWith('#'));
  assert.strictEqual(lines[0], 'PATH=/opt/bin:/opt/sbin:$PATH; export PATH');
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'web', 'tools', 'index.html'), 'utf8');
  assert.ok(/id="cps">Скачать как скрипт \(\.sh\)/.test(html) && /UI\.download\('kitsune-apply\.sh', '#!\/bin\/sh\\n' \+ cmd\)/.test(html), 'кнопка скрипта берёт реальную команду, имя файла без секретов');
});

test('запуск файлом: скрипт, выполненный как sh файл с урезанным PATH, делает то же самое и ничего не печатает целиком', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-router-'));
  const conf = path.join(dir, 'mihomo'); fs.mkdirSync(conf);
  fs.writeFileSync(path.join(conf, 'config.yaml'), 'old: 1\n');
  const bin = path.join(dir, 'opt-bin'); fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'mihomo'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'xkeen'), '#!/bin/sh\necho restart >> "' + dir + '/events"\n', { mode: 0o755 });
  const script = '#!/bin/sh\n' + cmd().split('/opt/etc/mihomo').join(conf).replace('PATH=/opt/bin:/opt/sbin:$PATH', 'PATH=' + bin + ':$PATH');
  const file = path.join(dir, 'kitsune-apply.sh'); fs.writeFileSync(file, script);
  const r = spawnSync('/bin/sh', [file], { env: { PATH: '/usr/bin:/bin', HOME: dir }, encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual(fs.readFileSync(path.join(conf, 'config.yaml'), 'utf8'), BODY);
  assert.ok(fs.existsSync(path.join(dir, 'events')), 'xkeen найден через PATH из скрипта');
  assert.ok(!r.stdout.includes('SECRET-VALUE-XYZ') && !r.stderr.includes('SECRET-VALUE-XYZ'), 'secret в вывод не попадает');
});
