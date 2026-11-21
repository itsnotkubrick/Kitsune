// Экранирование значений, которые приходят из сети (заголовки устройств, имена), в разметке панели.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..', '..', 'web', 'static', 'js');
const core = fs.readFileSync(path.join(root, 'core.js'), 'utf8');
const pick = name => core.split('\n').find(l => l.startsWith('const ' + name + ' ='));
const ctx = {};
vm.createContext(ctx);
vm.runInContext(pick('esc') + '\n' + pick('escJs') + '\nthis.esc = esc; this.escJs = escJs;', ctx);
const { esc, escJs } = ctx;

// Разбор атрибута так, как это делает браузер: сначала HTML-сущности, потом JS.
const decodeAttr = s => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n))
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

const payloads = ["');alert(1);//", '"><img src=x onerror=alert(1)>', 'a\\', "\\');alert(1);//", "x'\"`${1}", 'тест\u2028'];

test('esc экранирует кавычки и обратную косую', () => {
  for (const p of payloads) {
    const out = esc(p);
    assert.ok(!/['"<>\\]/.test(out), out);
    assert.strictEqual(decodeAttr(out), p);
  }
});

test('escJs: значение в onclick остаётся строкой', () => {
  for (const p of payloads) {
    const attr = escJs(p);
    assert.ok(!/['"<>\\]/.test(attr), attr);
    const src = `f('${decodeAttr(attr)}')`;
    let got;
    vm.runInNewContext(src, { f: v => { got = v; }, alert: () => assert.fail('выполнился чужой код') });
    assert.strictEqual(got, p);
  }
});

test('список устройств не кладёт HWID в обработчики', () => {
  const src = fs.readFileSync(path.join(root, 'users.js'), 'utf8');
  const line = src.split('\n').find(l => l.includes('list.innerHTML = dev.map'));
  assert.ok(line && !/hwid\)?\}?'/.test(line.replace(/esc\(x\.hwid\.slice\(0, 12\)\)/, '')), line);
  assert.ok(line.includes('data-device-id'));
});
