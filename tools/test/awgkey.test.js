// Ключ защиты заголовков AmneziaWG 3.1 в генераторе Mihomo: клиенты ждут base64 (32 байта).
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const lib = path.join(__dirname, '..', '..', 'web', 'tools', 'lib');
const { parseWgConf } = require(path.join(lib, 'links.js'));
const { buildMihomo } = require(path.join(lib, 'mihomo.js'));

const HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const B64 = Buffer.from(HEX, 'hex').toString('base64');

const conf = (key) => `[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.8.2.2/32
MTU = 1280
Jc = 4
S1 = 15
S2 = 68
S3 = 20
S4 = 20
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = ${key}

[Peer]
PublicKey = cHVibGlj
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.5:51822
`;

test('hex-ключ из старого конфига переводится в base64', () => {
  assert.strictEqual(parseWgConf(conf(HEX), 'x').awg.headerprotectionkey, B64);
});

test('base64-ключ остаётся как есть', () => {
  assert.strictEqual(parseWgConf(conf(B64), 'x').awg.headerprotectionkey, B64);
});

test('Mihomo: version 3 и header-protection-key в base64', () => {
  const p = parseWgConf(conf(HEX), 'x');
  const yaml = buildMihomo([p], {});
  const text = typeof yaml === 'string' ? yaml : JSON.stringify(yaml);
  assert.ok(text.includes('header-protection-key: ' + B64) || text.includes('"header-protection-key":"' + B64 + '"'), text);
  assert.ok(!text.includes(HEX));
  assert.match(text, /version:? ?3|"version":3/);
});

// Ссылка vpn:// сгенерирована самим Kitsune (qCompress: 4 байта длины + zlib), ключи в ней учебные.
const fs = require('node:fs');
const vpn = fs.readFileSync(path.join(__dirname, 'fixtures', 'awg3.vpn'), 'utf8').trim();
const FIX_B64 = Buffer.from('0123456789012345678901234567890123456789012345678901234567890123', 'hex').toString('base64');

test('vpn:// из Kitsune разбирается в AmneziaWG 3.1', () => {
  const { parseLink } = require(path.join(lib, 'links.js'));
  const p = parseLink(vpn);
  assert.strictEqual(p.type, 'amneziawg');
  assert.strictEqual(p.server, '203.0.113.5');
  assert.strictEqual(p.port, 51822);
  assert.strictEqual(p.awg.headerprotectionkey, FIX_B64);
  assert.strictEqual(p.awg.s4, 20);
});

test('ключ из одних цифр тоже переводится в base64', () => {
  const digits = '1234567890'.repeat(6) + '1234';
  const want = Buffer.from(digits, 'hex').toString('base64');
  assert.strictEqual(parseWgConf(conf(digits), 'x').awg.headerprotectionkey, want);
});

test('Mihomo: random-trailers и disable-cookies только для version 3', () => {
  const v3 = parseWgConf(conf(HEX).replace('H4 = 4', 'H4 = 4\nRandomTrailers = on\nDisableCookies = off'), 'x');
  const t3 = JSON.stringify(buildMihomo([v3], {}));
  assert.ok(/random-trailers:? ?true|"random-trailers":true/.test(t3), t3);
  assert.ok(/disable-cookies:? ?false|"disable-cookies":false/.test(t3), t3);
  const old = parseWgConf(conf(HEX).replace(/HeaderProtectionKey.*\n/, '').replace(/S[34] = .*\n/g, '').replace('H4 = 4', 'H4 = 4\nRandomTrailers = on'), 'x');
  assert.ok(!/random-trailers/.test(JSON.stringify(buildMihomo([old], {}))));
});

test('секции __proto__ и constructor не задевают прототип объектов', () => {
  const evil = conf(HEX) + '\n[__proto__]\nsecret = pwned\nexternalcontroller = 0.0.0.0:1\n[constructor]\nfinal = x\n[Interface]\n__proto__ = x\n';
  const p = parseWgConf(evil, 'x');
  assert.strictEqual(({}).secret, undefined);
  assert.strictEqual(({}).final, undefined);
  assert.strictEqual(p.type, 'amneziawg');
  assert.ok(!JSON.stringify(buildMihomo([p], {})).includes('pwned'));
});

// qCompress-подобная ссылка с заданным заявленным размером
const zlib = require('node:zlib');
const bomb = (declared, size) => {
  const head = Buffer.alloc(4); head.writeUInt32BE(declared);
  return 'vpn://' + Buffer.concat([head, zlib.deflateSync(Buffer.alloc(size))]).toString('base64url');
};

test('vpn:// отвергает «бомбу» и несовпадение длины', () => {
  const { parseLink } = require(path.join(lib, 'links.js'));
  assert.throws(() => parseLink(bomb(50 * 1024 * 1024, 50 * 1024 * 1024)), /слишком большой/);
  assert.throws(() => parseLink(bomb(1000, 50 * 1024 * 1024)), /слишком большой|повреждена/);
  assert.throws(() => parseLink(bomb(500, 1000)), /слишком большой|повреждена/);
  assert.throws(() => parseLink('vpn://' + 'A'.repeat(300 * 1024)), /слишком большая/);
});

test('inflate: битые stored-блок и коды', () => {
  const { parseLink } = require(path.join(lib, 'links.js'));
  const head = Buffer.from([0, 0, 0, 5]);
  // stored-блок: LEN=5, NLEN неверный
  const bad = Buffer.concat([head, Buffer.from([0x78, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 0, 0, 0, 0])]);
  assert.throws(() => parseLink('vpn://' + bad.toString('base64url')), /повреждена/);
  // stored-блок обрывается
  const cut = Buffer.concat([head, Buffer.from([0x78, 0x01, 0x01, 0x05, 0x00, 0xfa, 0xff, 1, 2])]);
  assert.throws(() => parseLink('vpn://' + cut.toString('base64url')), /повреждена/);
});
