// Предпросмотр config.json в панели не показывает секреты: ключи REALITY и WireGuard, пароли, auth, id пользователей.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'web', 'static', 'js', 'xray.js'), 'utf8');
const line = src.split('\n').find((l) => l.startsWith('const maskConfigSecrets ='));
const ctx = {};
vm.createContext(ctx);
vm.runInContext(line + '\nthis.maskConfigSecrets = maskConfigSecrets;', ctx);
const mask = ctx.maskConfigSecrets;

test('скрываются ключи REALITY, WireGuard, пароли, auth и id', () => {
  const cfg = { inbounds: [{ settings: { clients: [{ id: 'uuid-1111', password: 'pw-2222', auth: 'au-3333' }] }, streamSettings: { realitySettings: { privateKey: 'PRIV-4444' } } }],
    outbounds: [{ settings: { secretKey: 'WGSECRET-5555', peers: [{ preSharedKey: 'PSK-6666', publicKey: 'PUBLIC-7777' }] } }] };
  const out = mask(cfg);
  for (const s of ['uuid-1111', 'pw-2222', 'au-3333', 'PRIV-4444', 'WGSECRET-5555', 'PSK-6666']) assert.ok(!out.includes(s), s + ' виден');
  assert.ok(out.includes('PUBLIC-7777'), 'публичный ключ не секрет');
  assert.ok(out.includes('••••'));
});

test('структура и несекретные поля сохраняются', () => {
  const out = JSON.parse(mask({ log: { loglevel: 'warning' }, a: [{ port: 443 }] }));
  assert.deepStrictEqual(out, { log: { loglevel: 'warning' }, a: [{ port: 443 }] });
});
