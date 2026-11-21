// Язык установщика: --lang, переменная KITSUNE_LANG и локаль выбирают русский или английский; неверное значение отклоняется.
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const script = path.join(__dirname, '..', '..', 'scripts', 'install.sh');

function run(args, env = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kit-lang-'));
  const r = spawnSync('bash', [script, 'install', '--dry-run', '--yes', '--port', '9443', ...args], {
    env: { PATH: process.env.PATH, HOME: root, KITSUNE_ROOT: root, KITSUNE_NO_SYSTEMD: '1', NO_COLOR: '1', ...env },
    encoding: 'utf8', timeout: 60000,
  });
  fs.rmSync(root, { recursive: true, force: true });
  return (r.stdout || '') + (r.stderr || '');
}

test('синтаксис установщика', () => {
  assert.strictEqual(spawnSync('bash', ['-n', script]).status, 0);
});

test('--lang ru: шаги по-русски', () => {
  const out = run(['--lang', 'ru']);
  assert.match(out, /\[1\/9\] Проверка системы/);
  assert.match(out, /\[2\/9\] Установка системных пакетов/);
  assert.doesNotMatch(out, /Checking the system/);
});

test('--lang en: шаги по-английски даже при русской локали', () => {
  const out = run(['--lang', 'en'], { LANG: 'ru_RU.UTF-8' });
  assert.match(out, /\[1\/9\] Checking the system/);
  assert.doesNotMatch(out, /Проверка системы/);
});

test('без флага язык берётся из локали: русская – русский, остальные – английский', () => {
  assert.match(run([], { LANG: 'ru_RU.UTF-8' }), /Проверка системы/);
  assert.match(run([], { LANG: 'en_US.UTF-8' }), /Checking the system/);
  assert.match(run([], { LANG: 'de_DE.UTF-8' }), /Checking the system/);
  assert.match(run([], {}), /Checking the system/);
});

test('KITSUNE_LANG главнее локали, а --lang главнее KITSUNE_LANG', () => {
  assert.match(run([], { KITSUNE_LANG: 'ru', LANG: 'en_US.UTF-8' }), /Проверка системы/);
  assert.match(run(['--lang', 'en'], { KITSUNE_LANG: 'ru' }), /Checking the system/);
});

test('неверный язык отклоняется до начала установки', () => {
  const out = run(['--lang', 'de']);
  assert.match(out, /--lang: ru or en/);
  assert.doesNotMatch(out, /\[1\/9\]/);
});

test('русские тексты вопросов есть для всех мест выбора (по числу переводов)', () => {
  const src = fs.readFileSync(script, 'utf8');
  const pairs = (src.match(/\$\(T "/g) || []).length;
  assert.ok(pairs >= 45, 'переводов в установщике: ' + pairs);
  assert.match(src, /Language \/ Язык/);
});
