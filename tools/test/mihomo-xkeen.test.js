// Схема групп «как в шаблоне XKeen» (groupModel: 'xkeen'): соответствие закреплённой копии шаблона zxc-rv, целостность, якоря, инъекции.
// Копия шаблона: golden/zxc-template-2026-10-22.yaml. Расхождения с шаблоном намеренные и перечислены в тесте.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const lib = path.join(__dirname, '..', '..', 'web', 'tools', 'lib');
const { parseText } = require(path.join(lib, 'links.js'));
const { buildMihomo, MIHOMO_CATALOG } = require(path.join(lib, 'mihomo.js'));

const SECRET = 'test-secret-0123456789ab';
const LINK = 'vless://11111111-2222-4333-8444-555555555555@203.0.113.5:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12cd34&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#node-a';
const proxies = () => parseText(LINK).proxies;
const TEMPLATE = fs.readFileSync(path.join(__dirname, 'golden', 'zxc-template-2026-10-22.yaml'), 'utf8');
const GOLDEN = path.join(__dirname, 'golden', 'xkeen-default.yaml');

const XK = { secret: SECRET, groupModel: 'xkeen', blockAds: true, blockQuic: true, twitchHq: true, customRules: 'DOMAIN-SUFFIX,a.example.com' };
const gen = (o) => buildMihomo(proxies(), Object.assign({}, XK, o));

function templateGroups() {
  const body = TEMPLATE.split(/^proxy-groups:\n/m)[1].split(/^\S/m)[0];
  return body.split(/^  - name: /m).slice(1).map((b) => {
    const name = b.split('\n')[0].trim();
    const list = (/proxies: \[(.*)\]/.exec(b) || [])[1];
    return { name, type: /type: (\S+)/.exec(b)[1], proxies: list ? list.split(',').map((s) => s.trim()) : [], excludeFilter: (/exclude-filter: (\S+)/.exec(b) || [])[1], hidden: /hidden: true/.test(b) };
  });
}
function templateRules() {
  return TEMPLATE.split(/^rules:\n/m)[1].split('\n').filter((l) => /^\s+- /.test(l)).map((l) => l.replace(/^\s+- /, '').replace(/\s+#.*$/, ''));
}

test('xkeen: группы совпадают с шаблоном (имена, порядок, тип, proxies, exclude-filter, hidden)', () => {
  const ours = gen().config['proxy-groups'];
  const tpl = templateGroups();
  const byName = Object.fromEntries(ours.map((g) => [g.name, g]));
  assert.deepStrictEqual(ours.map((g) => g.name).sort(), tpl.map((g) => g.name).sort());
  tpl.forEach((t) => {
    const g = byName[t.name];
    assert.strictEqual(g.type, t.type, t.name);
    // Намеренное отличие: у Google и GitHub PASS не первым, а последним
    const want = ['Google', 'GitHub'].includes(t.name) ? t.proxies.slice(1).concat('PASS') : t.proxies;
    assert.deepStrictEqual(g.proxies || [], want, t.name);
    assert.strictEqual(g['exclude-filter'], t.excludeFilter, t.name);
    assert.strictEqual(!!g.hidden, t.hidden, t.name);
  });
});

test('xkeen: правила идут в порядке шаблона (отличия: no-resolve у не-CDN ipcidr, ads@domain, discord@domain, user и refilter разнесены)', () => {
  const norm = (r) => r.replace(/,no-resolve/g, '').replace('adlist@domain', 'ads@domain').replace('discord@classical', 'discord@domain');
  const want = [];
  templateRules().forEach((r) => {
    if (r.includes('refilter@domain') && r.includes('user@classical')) {
      want.push('RULE-SET,user@classical,Заблок. сервисы', 'OR,((RULE-SET,refilter@domain),(RULE-SET,refilter@ipcidr)),Заблок. сервисы');
    } else want.push(norm(r));
  });
  const got = gen({ refilterIp: true }).config.rules.map(norm);
  assert.deepStrictEqual(got, want);
});

test('xkeen: ipcidr идёт с no-resolve, кроме CDN и Google (там без него, как в шаблоне: иначе домен без адреса не попадает в диапазон)', () => {
  const rules = gen({ refilterIp: true }).config.rules;
  const cdn = /(google|amazon|akamai|cloudflare|digitalocean|fastly|oracle|hetzner|scaleway|ovh|vultr|vodafone|gcore|cdn77)@ipcidr/;
  rules.forEach((r) => (r.match(/RULE-SET,[^,)]+@ipcidr[^)]*/g) || []).forEach((m) => {
    if (cdn.test(m)) assert.ok(!/no-resolve/.test(m), m); else assert.match(m, /,no-resolve$/, m);
   }));
  assert.ok(rules.some((r) => /^OR,.*telegram@ipcidr,no-resolve/.test(r)));
  assert.ok(rules.some((r) => /^RULE-SET,scaleway@ipcidr,CDN$/.test(r)));
});

// Целостность для схемы с OR и PASS: вытаскиваем все RULE-SET и все цели.
function integrity(cfg) {
  const providers = Object.keys(cfg['rule-providers'] || {});
  const groups = new Set((cfg['proxy-groups'] || []).map((g) => g.name).concat(['DIRECT', 'REJECT', 'PASS']));
  const used = new Set();
  const problems = [];
  (cfg.rules || []).forEach((r) => {
    for (const m of r.matchAll(/RULE-SET,([^,)]+)/g)) {
      used.add(m[1]);
      if (!providers.includes(m[1])) problems.push('rule-set не объявлен: ' + m[1]);
    }
    const target = /^OR,/.test(r) ? r.replace(/^OR,\(\(.*\)\),/, '') : r.split(',')[/^RULE-SET/.test(r) || /^MATCH/.test(r) ? (/^MATCH/.test(r) ? 1 : 2) : 1];
    if (!groups.has(target)) problems.push('нет группы: ' + target + ' в ' + r);
  });
  providers.forEach((p) => { if (!used.has(p)) problems.push('объявлен, но не используется: ' + p); });
  (cfg['proxy-groups'] || []).forEach((g) => (g.proxies || []).forEach((n) => { if (!groups.has(n)) problems.push('группа ссылается на несуществующую: ' + n); }));
  return problems;
}

test('xkeen: целостность ссылок в разных наборах', () => {
  [{}, { refilterIp: true }, { services: ['youtube'] }, { services: ['google', 'cdn', 'github'] }, { services: MIHOMO_CATALOG.map((s) => s.id), blockAds: false, blockQuic: false, customRules: '' }, { finalProxy: true }]
    .forEach((o) => assert.deepStrictEqual(integrity(gen(o).config), [], JSON.stringify(o)));
});

test('xkeen: якоря объявлены один раз, провайдеры без path и без повторов полей', () => {
  const y = gen().yaml;
  assert.strictEqual((y.match(/&domain /g) || []).length, 1);
  assert.strictEqual((y.match(/&ipcidr /g) || []).length, 1);
  assert.ok(y.indexOf('anchors:') < y.indexOf('rule-providers:'));
  assert.ok(!/path: /.test(y.split('rule-providers:')[1]));
  assert.match(y, /youtube@domain: \{ <<: \*domain, url: /);
});

test('xkeen: без галочки вывод прежний (groupModel не влияет на старую схему)', () => {
  const o = { secret: SECRET, services: ['youtube', 'telegram'], blockQuic: true };
  assert.strictEqual(buildMihomo(proxies(), o).yaml, buildMihomo(proxies(), Object.assign({ groupModel: undefined }, o)).yaml);
  assert.ok(!buildMihomo(proxies(), o).yaml.includes('Заблок. сервисы'));
});

test('xkeen: Twitch HQ только по галочке, MATCH зависит от finalProxy', () => {
  assert.ok(!gen({ twitchHq: false }).config.rules.some((r) => r.includes('gql.twitch.tv')));
  assert.ok(gen().config.rules.some((r) => r.includes('gql.twitch.tv')));
  assert.strictEqual(gen({ finalProxy: true }).config.rules.slice(-1)[0], 'MATCH,Заблок. сервисы');
  assert.strictEqual(gen().config.rules.slice(-1)[0], 'MATCH,DIRECT');
});

test('xkeen: свои правила с инъекцией не ломают файл и попадают только в classical', () => {
  const r = gen({ customRules: 'DOMAIN-SUFFIX,x.com\nPROCESS-NAME,evil\nDOMAIN,a.com,REJECT\n  - injected: 1' });
  assert.deepStrictEqual(integrity(r.config), []);
  assert.ok(!/^injected/m.test(r.yaml));
});

test('xkeen: golden режима по умолчанию', () => {
  const y = gen({ subscription: 'https://sub.example.com/s/abc123' }).yaml;
  if (process.env.UPDATE_GOLDEN) fs.writeFileSync(GOLDEN, y);
  assert.strictEqual(y, fs.readFileSync(GOLDEN, 'utf8'));
});
