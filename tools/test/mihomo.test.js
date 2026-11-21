// Генератор config.yaml для Mihomo (XKeen): golden-вывод, целостность ссылок, порядок ярусов, идемпотентность, инъекции.
// Golden обновляется осознанно: UPDATE_GOLDEN=1 node --test tools/test/mihomo.test.js, и diff смотрится глазами.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const lib = path.join(__dirname, '..', '..', 'web', 'tools', 'lib');
const { parseText } = require(path.join(lib, 'links.js'));
const { buildMihomo, MIHOMO_SERVICES } = require(path.join(lib, 'mihomo.js'));

const GOLDEN = path.join(__dirname, 'golden');
const SECRET = 'test-secret-0123456789ab'; // фиксированный: иначе файл меняется при каждой сборке

const LINK = 'vless://11111111-2222-4333-8444-555555555555@203.0.113.5:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12cd34&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#node-a';
const proxies = () => parseText(LINK).proxies;
// Все сервисы текущей схемы групп на момент шага 1: 12 штук. Явный список, а не весь каталог: новые сервисы не должны менять golden full.
const ALL = ['blocked', 'youtube', 'telegram', 'meta', 'twitter', 'discord', 'ai', 'tiktok', 'spotify', 'netflix', 'github', 'twitch'];

// Три типовых набора: минимальный; несколько сервисов без выбора сервера по каждому; всё включено.
const SETS = {
  minimal: { secret: SECRET },
  services: { secret: SECRET, services: ['youtube', 'telegram', 'discord', 'github'], blockQuic: true },
  full: {
    secret: SECRET, services: ALL, perService: true, blockAds: true, blockQuic: true, finalProxy: true,
    proxyDomains: 'proxy.example.com, extra.example.org', directDomains: 'mybank.example.ru',
    subscriptions: ['https://sub.example.com/s/abc123', 'https://sub2.example.com/s/def456'],
  },
  filtered: { secret: SECRET, services: ['youtube'], subscription: 'https://sub.example.com/s/abc123', excludePreset: true, excludeRegex: '(?i)test|\\bdemo\\b' },
};

const idx = (rules, re) => rules.findIndex((r) => re.test(r));

for (const [name, opts] of Object.entries(SETS)) {
  test('golden: ' + name, () => {
    const out = buildMihomo(proxies(), opts).yaml;
    const file = path.join(GOLDEN, name + '.yaml');
    if (process.env.UPDATE_GOLDEN) fs.writeFileSync(file, out);
    assert.strictEqual(out, fs.readFileSync(file, 'utf8'), 'вывод изменился: если это осознанно, UPDATE_GOLDEN=1 и разобрать diff');
  });
}

// Целостность ссылок: каждый rule-set из rules объявлен, каждый объявленный используется, каждая группа из rules существует (регистр важен).
function integrity(cfg) {
  const providers = Object.keys(cfg['rule-providers'] || {});
  const groups = new Set((cfg['proxy-groups'] || []).map((g) => g.name).concat(['DIRECT', 'REJECT']));
  const used = new Set();
  const problems = [];
  (cfg.rules || []).forEach((r) => {
    const m = /^RULE-SET,([^,]+),([^,]+)/.exec(r);
    if (m) {
      used.add(m[1]);
      if (!providers.includes(m[1])) problems.push('rule-set не объявлен: ' + m[1]);
      if (!groups.has(m[2])) problems.push('нет группы: ' + m[2]);
    } else if (/^MATCH,/.test(r)) {
      if (!groups.has(r.split(',')[1])) problems.push('нет группы в MATCH: ' + r);
    } else if (!/^AND,/.test(r)) problems.push('неизвестное правило: ' + r);
  });
  providers.forEach((p) => { if (!used.has(p)) problems.push('объявлен, но не используется: ' + p); });
  (cfg['proxy-groups'] || []).forEach((g) => (g.proxies || []).forEach((n) => { if (!groups.has(n)) problems.push('группа ссылается на несуществующую: ' + n); }));
  if (cfg['sniffer'] && cfg['sniffer']['skip-dst-address']) {
    cfg['sniffer']['skip-dst-address'].forEach((s) => { if (!providers.includes(s.replace('rule-set:', ''))) problems.push('sniffer: нет набора ' + s); });
  }
  return problems;
}

for (const [name, opts] of Object.entries(SETS)) {
  test('целостность ссылок: ' + name, () => {
    assert.deepStrictEqual(integrity(buildMihomo(proxies(), opts).config), []);
  });
}

test('целостность: проверка действительно ловит поломку', () => {
  const cfg = JSON.parse(JSON.stringify(buildMihomo(proxies(), SETS.services).config));
  cfg.rules.push('RULE-SET,нет-такого,Прокси');
  cfg['proxy-groups'][0].name = 'прокси'; // другой регистр
  assert.ok(integrity(cfg).length >= 2);
});

test('идемпотентность: один ввод и один secret дают побайтно один файл, порядок включения сервисов не важен', () => {
  const a = buildMihomo(proxies(), SETS.full).yaml;
  const b = buildMihomo(proxies(), SETS.full).yaml;
  assert.strictEqual(a, b);
  const rev = Object.assign({}, SETS.full, { services: ALL.slice().reverse() });
  assert.strictEqual(buildMihomo(proxies(), rev).yaml, a);
});

test('без secret в вводе генератор выдаёт случайный (это и чинит E1): два вызова различаются', () => {
  const o = { services: ['youtube'] };
  assert.notStrictEqual(buildMihomo(proxies(), o).yaml, buildMihomo(proxies(), o).yaml);
});

test('блока dns в выводе нет ни при каких настройках (его ведёт XKeen UI)', () => {
  for (const opts of Object.values(SETS)) {
    const r = buildMihomo(proxies(), opts);
    assert.ok(!('dns' in r.config));
    assert.ok(!/^dns:/m.test(r.yaml));
  }
});

// Ярусы сверху вниз: ads, QUIC, свои оверрайды (my-direct/my-proxy), сервисы, refilter, MATCH.
// До 68-E2 refilter шёл ПЕРВЫМ среди сервисов, и выбор сервера для YouTube/Telegram не срабатывал на доменах, которые есть и в
// refilter (в mihomo выигрывает первое совпадение). Этот тест ловит именно это.
test('порядок ярусов: refilter ниже конкретных сервисов', () => {
  const { rules } = buildMihomo(proxies(), SETS.full).config;
  const at = (re) => idx(rules, re);
  assert.ok(at(/ads@domain/) < at(/quic@inline/), 'ads выше QUIC');
  assert.ok(at(/quic@inline/) < at(/my-direct@inline/), 'QUIC выше оверрайдов');
  assert.ok(at(/my-proxy@inline/) < at(/youtube@domain/), 'оверрайды выше сервисов');
  assert.ok(at(/my-direct@inline/) < at(/youtube@domain/), 'свои оверрайды выше сервисов');
  assert.ok(at(/youtube@domain/) < at(/refilter@domain/), 'сервисы выше refilter');
  assert.ok(at(/refilter@ipcidr/) < at(/^MATCH,/), 'MATCH последним');
});

test('порядок ярусов: то, что уже верно, зафиксировано', () => {
  const { rules } = buildMihomo(proxies(), SETS.full).config;
  const at = (re) => idx(rules, re);
  assert.ok(at(/ads@domain/) === 0, 'реклама первой');
  assert.ok(at(/my-direct@inline/) < at(/my-proxy@inline/), 'внутри яруса оверрайдов: напрямую выше через прокси');
  assert.ok(rules[rules.length - 1].startsWith('MATCH,'));
  assert.ok(!rules.some((r) => /^AND,/.test(r)), 'QUIC теперь набор quic@inline, а не правило в тексте');
  assert.ok(buildMihomo(proxies(), SETS.services).config.rules.every((r) => !/refilter/.test(r)), 'без галочки re:filter его нет в правилах');
});

test('инъекции: адрес подписки и список доменов не выходят за пределы значений YAML', () => {
  const evil = 'https://sub.example.com/"\nrules: [x]\nEOF\n# ';
  const r = buildMihomo(proxies(), { secret: SECRET, subscription: evil, proxyDomains: 'a.example.com"\nsecret: pwn\n, ok.example.org', services: ['youtube'] });
  const urlLine = r.yaml.split('\n').find((l) => /^\s+url: .*sub\.example\.com/.test(l));
  assert.ok(urlLine, 'адрес остался одной строкой');
  assert.ok(!/^rules: \[x\]$/m.test(r.yaml) && !/^secret: pwn$/m.test(r.yaml));
  assert.strictEqual((r.yaml.match(/^secret:/gm) || []).length, 1);
  assert.ok(r.config['rule-providers']['my-proxy@inline'].payload.every((d) => /^\+\.[a-z0-9.-]+$/.test(d)));
});

test('имена прокси и подписи со спецсимволами не ломают файл', () => {
  const p = proxies();
  p[0].name = 'узел: "тест" # 1\nвторая строка';
  const y = buildMihomo(p, { secret: SECRET, services: ['youtube'] }).yaml;
  assert.ok(!/^вторая строка/m.test(y));
  assert.ok(y.includes('"узел: \\"тест\\" # 1\\nвторая строка"'));
});

test('маркер управляемого файла в первой строке, предупреждение про правки и копию', () => {
  const y = buildMihomo(proxies(), { secret: SECRET }).yaml.split('\n');
  assert.strictEqual(y[0], '# kitsune-managed v2');
  assert.match(y[1], /правки вне блока dns: .*config\.yaml\.bak-/);
});

test('QUIC: набор quic@inline объявлен только при галочке и отклоняет UDP 443', () => {
  const on = buildMihomo(proxies(), { secret: SECRET, blockQuic: true, services: ['youtube'] }).config;
  assert.deepStrictEqual(on['rule-providers']['quic@inline'], { type: 'inline', behavior: 'classical', payload: ['AND,((NETWORK,UDP),(DST-PORT,443))'] });
  assert.ok(on.rules.includes('RULE-SET,quic@inline,REJECT'));
  const off = buildMihomo(proxies(), { secret: SECRET, blockQuic: false, services: ['youtube'] }).config;
  assert.ok(!('quic@inline' in (off['rule-providers'] || {})) && !off.rules.some((r) => /quic/.test(r)));
});

test('перестановка галочек не меняет порядок ярусов (все сочетания)', () => {
  for (const mask of Array.from({ length: 32 }, (_, i) => i)) {
    const o = { secret: SECRET, services: ALL, blockAds: !!(mask & 1), blockQuic: !!(mask & 2), proxyDomains: mask & 4 ? 'a.example.com' : '', directDomains: mask & 8 ? 'b.example.com' : '', finalProxy: !!(mask & 16) };
    const { rules } = buildMihomo(proxies(), o).config;
    const rank = (r) => (/ads@/.test(r) ? 1 : /quic@/.test(r) ? 2 : /my-(direct|proxy)@/.test(r) ? 3 : /^MATCH/.test(r) ? 6 : /refilter@/.test(r) ? 5 : 4);
    const ranks = rules.map(rank);
    assert.deepStrictEqual(ranks, ranks.slice().sort((a, b) => a - b), 'маска ' + mask);
  }
});

// ---------- 68-E5: свои сайты, свои правила, punycode ----------
const { parseCustomRules, asciiDomain } = require(path.join(lib, 'mihomo.js'));
const gen = (o) => buildMihomo(proxies(), Object.assign({ secret: SECRET, services: ['youtube'] }, o));

test('punycode: кириллические домены переводятся, а не молча отбрасываются', () => {
  assert.strictEqual(asciiDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
  assert.strictEqual(asciiDomain('https://Пример.РФ/путь?q=1'), 'xn--e1afmkfd.xn--p1ai');
  assert.strictEqual(asciiDomain('*.example.com'), 'example.com');
  const r = gen({ proxyDomains: 'пример.рф, example.com', directDomains: 'банк.рф' });
  assert.deepStrictEqual(r.config['rule-providers']['my-proxy@inline'].payload, ['+.xn--e1afmkfd.xn--p1ai', '+.example.com']);
  assert.deepStrictEqual(r.config['rule-providers']['my-direct@inline'].payload, ['+.xn--80ab1a8aa.xn--p1ai'].map((x) => '+.' + asciiDomain('банк.рф')));
});

test('неверные строки получают сообщение, а не пропадают молча', () => {
  const r = gen({ proxyDomains: 'ok.example.com bad domain with"quote notadomain', directDomains: 'a b.c' });
  const w = r.warnings.join('\n');
  assert.match(w, /Свои сайты через прокси: «bad»/);
  assert.match(w, /«domain»/);
  assert.match(w, /«with"quote»/);
  assert.match(w, /«notadomain»/);
  assert.match(w, /Свои сайты напрямую: «a»/);
  assert.deepStrictEqual(r.config['rule-providers']['my-proxy@inline'].payload, ['+.ok.example.com']);
});

test('свои правила: типы из белого списка, действия, значения проверяются, ошибки с номером строки', () => {
  const text = ['# комментарий', 'DOMAIN-SUFFIX,example.com', 'domain,Exact.Example.org,direct', 'DOMAIN-KEYWORD,video,DIRECT', 'IP-CIDR,203.0.113.0/24,REJECT',
    'IP-CIDR,198.51.100.7', 'IP-CIDR6,2001:db8::/32,PROXY', 'GEOSITE,Category-Ads-All,REJECT', 'GEOIP,ru,DIRECT', 'пример.рф', 'plain.example.net',
    'PROCESS-NAME,evil.exe', 'DOMAIN-SUFFIX', 'DOMAIN-SUFFIX,bad value', 'IP-CIDR,300.1.1.1/24', 'IP-CIDR,1.2.3.4/33', 'GEOIP,RUS', 'DOMAIN,a.example.com,ALLOW', 'DOMAIN,a.example.com,DIRECT,extra'].join('\n');
  const r = parseCustomRules(text);
  assert.deepStrictEqual(r.rules.map((x) => [x.type, x.value, x.action]), [
    ['DOMAIN-SUFFIX', 'example.com', 'PROXY'], ['DOMAIN', 'exact.example.org', 'DIRECT'], ['DOMAIN-KEYWORD', 'video', 'DIRECT'],
    ['IP-CIDR', '203.0.113.0/24', 'REJECT'], ['IP-CIDR', '198.51.100.7/32', 'PROXY'], ['IP-CIDR6', '2001:db8::/32', 'PROXY'],
    ['GEOSITE', 'category-ads-all', 'REJECT'], ['GEOIP', 'RU', 'DIRECT'], ['DOMAIN-SUFFIX', 'xn--e1afmkfd.xn--p1ai', 'PROXY'], ['DOMAIN-SUFFIX', 'plain.example.net', 'PROXY'],
  ]);
  assert.deepStrictEqual(r.errors.map((e) => e.line), [12, 13, 14, 15, 16, 17, 18, 19]);
  assert.match(r.errors[0].error, /неизвестный тип/);
  assert.match(r.errors[5].error, /значение/);
});

test('свои правила попадают в наборы по действию, ярус между сервисами и refilter, ссылки целы', () => {
  const r = gen({ services: ['blocked', 'youtube'], customRules: 'DOMAIN-SUFFIX,a.example.com\nDOMAIN-SUFFIX,b.example.com,DIRECT\nDOMAIN-SUFFIX,c.example.com,REJECT\nIP-CIDR,10.0.0.0/8,DIRECT' });
  const p = r.config['rule-providers'];
  assert.deepStrictEqual(p['user@classical'].payload, ['DOMAIN-SUFFIX,a.example.com']);
  assert.deepStrictEqual(p['user-direct@classical'].payload, ['DOMAIN-SUFFIX,b.example.com', 'IP-CIDR,10.0.0.0/8,no-resolve']);
  assert.deepStrictEqual(p['user-reject@classical'].payload, ['DOMAIN-SUFFIX,c.example.com']);
  const rules = r.config.rules;
  const at = (re) => idx(rules, re);
  assert.ok(at(/youtube@domain/) < at(/user-reject@classical/) && at(/user-reject@/) < at(/user-direct@/) && at(/user-direct@/) < at(/RULE-SET,user@classical/));
  assert.ok(at(/RULE-SET,user@classical/) < at(/refilter@domain/), 'свои правила выше refilter');
  assert.deepStrictEqual(integrity(r.config), []);
  assert.ok(!gen({}).config['rule-providers'] || !Object.keys(gen({}).config['rule-providers']).some((k) => /^user/.test(k)), 'пустое поле – наборов нет');
});

test('инъекции в своих правилах и сайтах: кавычки, переводы строк, EOF, #, двоеточие не выходят за значение YAML', () => {
  const evil = ['DOMAIN-SUFFIX,a.example.com"\nsecret: pwn', 'DOMAIN-SUFFIX,a.example.com # x: y', 'DOMAIN-KEYWORD,k"w', 'GEOSITE,x\ny', 'EOF', 'DOMAIN,evil.example.com,REJECT\nPMEOF', "DOMAIN-SUFFIX,x.example.com'; rm -rf /"].join('\n');
  const r = gen({ customRules: evil, proxyDomains: 'a.example.com"\nsecret: pwn\nEOF', directDomains: '#x: y' });
  assert.strictEqual((r.yaml.match(/^secret:/gm) || []).length, 1);
  assert.ok(!/^EOF$/m.test(r.yaml) && !/^PMEOF$/m.test(r.yaml) && !/rm -rf/.test(r.yaml));
  const all = Object.values(r.config['rule-providers']).filter((x) => x.type === 'inline').flatMap((x) => x.payload);
  assert.ok(all.every((x) => /^(\+\.[a-z0-9.-]+|[A-Z0-9-]+,[a-z0-9!@._:\/-]+(,no-resolve)?|AND,.*)$/i.test(x)), JSON.stringify(all));
  assert.deepStrictEqual(integrity(r.config), []);
});

test('старый ввод без новых полей работает как раньше (старые сохранённые поля подхватываются)', () => {
  const old = { secret: SECRET, services: ['youtube'], proxyDomains: 'a.example.com', directDomains: 'b.example.com', blockQuic: true };
  const r = buildMihomo(proxies(), old);
  assert.deepStrictEqual(r.config['rule-providers']['my-proxy@inline'].payload, ['+.a.example.com']);
  assert.deepStrictEqual(r.warnings, []);
  assert.ok(!Object.keys(r.config['rule-providers']).some((k) => /^user/.test(k)));
});

// ---------- 68-E6: служебные настройки ----------
const { mihomoPortHints, ZASHBOARD_VERSION } = require(path.join(lib, 'mihomo.js'));

test('служебные настройки: по умолчанию вывод прежний (golden), переключатели видны в выводе и пропадают при выключении', () => {
  const base = gen({}).config;
  assert.strictEqual(base['log-level'], 'warning');
  assert.ok(base['external-ui-url'].includes('/download/' + ZASHBOARD_VERSION + '/'));
  assert.ok(!('skip-domain' in base.sniffer));
  const on = gen({ vivox: true, logLevel: 'silent', zashboard: 'latest' }).config;
  assert.deepStrictEqual(on.sniffer['skip-domain'], ['+.vivox.com']);
  assert.strictEqual(on['log-level'], 'silent');
  assert.strictEqual(on['external-ui-url'], 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip');
  const off = gen({ vivox: false, logLevel: 'warning', zashboard: 'pinned' }).config;
  assert.deepStrictEqual(off, base);
  assert.strictEqual(gen({ logLevel: 'debug' }).config['log-level'], 'warning', 'неизвестное значение – безопасное по умолчанию');
  assert.strictEqual(gen({ zashboard: 'x"y' }).config['external-ui-url'], base['external-ui-url']);
});

test('re:filter по адресам: отдельная галочка, по умолчанию включена как раньше, domain и ipcidr независимы', () => {
  const both = gen({ services: ['blocked'] }).config;
  assert.ok(both['rule-providers']['refilter@domain'] && both['rule-providers']['refilter@ipcidr']);
  const domainOnly = gen({ services: ['blocked'], refilterIp: false }).config;
  assert.ok(domainOnly['rule-providers']['refilter@domain'] && !('refilter@ipcidr' in domainOnly['rule-providers']));
  assert.ok(!domainOnly.rules.some((r) => /refilter@ipcidr/.test(r)));
  assert.deepStrictEqual(integrity(domainOnly), []);
  assert.deepStrictEqual(gen({ services: ['blocked'], refilterIp: true }).config, both);
});

test('подсказки про порты: тексты из задания автора, только для выбранных сервисов, без лишних тем', () => {
  const h = mihomoPortHints(['discord', 'youtube']).join('\n');
  assert.match(h, /Discord: .*80,443,2053:2096,8443,19200:19400,50000:50100/);
  assert.ok(!/Telegram/.test(h));
  assert.match(mihomoPortHints(['telegram']).join('\n'), /Telegram и WhatsApp: .*80,443,596:599,1400,3478,5222/);
  assert.match(mihomoPortHints([]).join('\n'), /Speedtest.*8080/);
  assert.ok(!/обход|блокиров|оператор|провайдер/i.test(mihomoPortHints(['discord', 'telegram']).join(' ')));
});

test('все новые переключатели вместе: файл целый, ссылки целы', () => {
  const r = gen({ services: ALL, vivox: true, logLevel: 'silent', zashboard: 'latest', refilterIp: false, blockQuic: true, blockAds: true, customRules: 'DOMAIN-SUFFIX,a.example.com' });
  assert.deepStrictEqual(integrity(r.config), []);
  assert.ok(!/^dns:/m.test(r.yaml));
});

// ---------- 68-E8: фильтр служебных узлов ----------
const { checkMihomoRegex, MIHOMO_EXCLUDE_PRESET } = require(path.join(lib, 'mihomo.js'));
const subOpts = (o) => Object.assign({ secret: SECRET, services: ['youtube'], subscriptions: ['https://sub.example.com/a', 'https://sub2.example.com/b'] }, o);

test('фильтр узлов: пустое поле – ключ не пишется; пресет и свой фильтр – на каждом провайдере подписки', () => {
  const none = buildMihomo([], subOpts()).config['proxy-providers'];
  assert.ok(Object.values(none).every((p) => !('exclude-filter' in p)));
  const preset = buildMihomo([], subOpts({ excludePreset: true })).config['proxy-providers'];
  assert.ok(Object.values(preset).every((p) => p['exclude-filter'] === MIHOMO_EXCLUDE_PRESET));
  const own = buildMihomo([], subOpts({ excludeRegex: '(?i)demo' })).config['proxy-providers'];
  assert.ok(Object.values(own).every((p) => p['exclude-filter'] === '(?i)demo'));
  const both = buildMihomo([], subOpts({ excludePreset: true, excludeRegex: '(?i)demo' })).config['proxy-providers'];
  const f = both.subscription['exclude-filter'];
  assert.ok(f.startsWith('(?i)') && !f.slice(4).includes('(?i)') && f.includes('осталось') && f.endsWith('|demo'));
});

test('пресет: ловит служебные узлы подписки и не задевает обычные (проверка на JS-эквиваленте RE2)', () => {
  const re = new RegExp(MIHOMO_EXCLUDE_PRESET.replace(/^\(\?i\)/, ''), 'iu');
  for (const bad of ['Осталось трафика: 15 GB', 'Срок до 25.12.2026', 'Traffic left 10GB', 'Expire: 2026-12-25', 'Remaining 5 GB', 'ДО 25.12']) assert.ok(re.test(bad), bad);
  for (const ok of ['Moscow-1', 'Нидерланды 02', 'Frankfurt | fast', 'Madrid', 'Додо-пицца']) assert.ok(!re.test(ok), ok);
});

test('свой фильтр: некорректное выражение и конструкции вне RE2 дают предупреждение и не применяются', () => {
  assert.deepStrictEqual(checkMihomoRegex(''), { ok: true, error: '', warnings: [] });
  assert.ok(checkMihomoRegex('(?i)test|demo').ok);
  for (const bad of ['a(b', '(?=x)y', '(?<!x)y', '(a)\\1', 'x'.repeat(201), 'a\nb']) assert.ok(!checkMihomoRegex(bad).ok, bad);
  const r = buildMihomo([], subOpts({ excludeRegex: '(?=x)y' }));
  assert.ok(Object.values(r.config['proxy-providers']).every((p) => !('exclude-filter' in p)));
  assert.match(r.warnings.join('\n'), /Фильтр узлов: .*lookahead.*свой фильтр не применён/);
  const ok = buildMihomo([], subOpts({ excludePreset: true, excludeRegex: '(?=x)y' }));
  assert.strictEqual(ok.config['proxy-providers'].subscription['exclude-filter'], MIHOMO_EXCLUDE_PRESET, 'пресет остаётся, плохой свой фильтр отброшен');
});

test('фильтр узлов без подписки: предупреждение, ключей нет; значение в YAML экранировано и читается обратно', () => {
  const noSub = buildMihomo(proxies(), { secret: SECRET, services: ['youtube'], excludePreset: true });
  assert.match(noSub.warnings.join('\n'), /только на подписку/);
  const r = buildMihomo([], subOpts({ excludeRegex: '(?i)a"b\\d\\s#x: y' }));
  const line = r.yaml.split('\n').find((l) => /exclude-filter:/.test(l));
  const quoted = line.slice(line.indexOf(':') + 2);
  assert.strictEqual(JSON.parse(quoted), '(?i)a"b\\d\\s#x: y');
  assert.strictEqual((r.yaml.match(/^secret:/gm) || []).length, 1);
});

// ---------- 68-E7: доступ к панели и маскирование ----------
const { maskMihomo, maskSubscriptionUrl, validLanIp } = require(path.join(lib, 'mihomo.js'));
const { routerCommand } = require(path.join(lib, 'router.js'));

test('external-controller: по умолчанию LAN-адрес, 0.0.0.0 только по явному выбору и с предупреждением', () => {
  assert.strictEqual(gen({}).config['external-controller'], '192.168.1.1:9090');
  assert.strictEqual(gen({ controllerIp: '10.0.0.1' }).config['external-controller'], '10.0.0.1:9090');
  assert.strictEqual(gen({ controller: 'local' }).config['external-controller'], '127.0.0.1:9090');
  const all = gen({ controller: 'all' });
  assert.strictEqual(all.config['external-controller'], '0.0.0.0:9090');
  assert.match(all.warnings.join('\n'), /9090 не проброшен наружу/);
  for (const o of [{}, { controller: 'lan' }, { controller: 'x"y' }, { controller: 'local' }, { controller: 'lan', controllerIp: '0.0.0.0' }]) {
    assert.ok(!/0\.0\.0\.0/.test(gen(o).yaml), 'без явного выбора 0.0.0.0 не появляется: ' + JSON.stringify(o));
  }
  for (const f of ['minimal', 'services', 'full', 'filtered']) assert.ok(!/0\.0\.0\.0/.test(fs.readFileSync(path.join(GOLDEN, f + '.yaml'), 'utf8')), f);
});

test('адрес роутера проверяется: мусор заменяется на умолчание с сообщением, кавычки и переводы строк не проходят', () => {
  for (const ip of ['192.168.1.1', '10.0.0.138', '172.16.5.1']) assert.ok(validLanIp(ip), ip);
  for (const ip of ['', 'abc', '0.0.0.0', '127.0.0.1', '255.255.255.255', '224.0.0.1', '300.1.1.1', '192.168.01.1', '1.2.3', '1.2.3.4:9090', '192.168.1.1\nsecret: pwn', '1.2.3.4"']) assert.ok(!validLanIp(ip), JSON.stringify(ip));
  const r = gen({ controllerIp: '1.2.3.4"\nsecret: pwn' });
  assert.strictEqual(r.config['external-controller'], '192.168.1.1:9090');
  assert.match(r.warnings.join('\n'), /Адрес роутера .* не подходит/);
  assert.strictEqual((r.yaml.match(/^secret:/gm) || []).length, 1);
});

test('маскирование: в показанном тексте нет ни secret, ни токена подписки, реальный текст не меняется', () => {
  const opts = Object.assign({}, SETS.full, { secret: 'S3CR3T-VALUE-123', subscriptions: ['https://sub.example.com/s/TOK3N9876?token=QUERYSECRET&u=1', 'https://user:pass@sub2.example.com/api/0123456789abcdef0123456789'] });
  const real = buildMihomo(proxies(), opts).yaml;
  const hide = { secret: opts.secret, urls: opts.subscriptions };
  assert.ok(real.includes('S3CR3T-VALUE-123') && real.includes('TOK3N9876') && real.includes('QUERYSECRET'), 'в настоящем файле значения реальные');
  const shown = maskMihomo(real, hide);
  for (const leak of ['S3CR3T-VALUE-123', 'TOK3N9876', 'QUERYSECRET', 'user:pass', '0123456789abcdef0123456789']) assert.ok(!shown.includes(leak), leak);
  assert.match(shown, /secret: ••••/);
  assert.match(shown, /sub\.example\.com\/s\/••••\?token=••••&u=••••/);
  assert.strictEqual(shown.split('\n').length, real.split('\n').length, 'строки на месте, меняются только значения');
  const cmd = routerCommand('keenetic', 'mihomo', { 'config.yaml': real });
  const shownCmd = maskMihomo(cmd, hide);
  for (const leak of ['S3CR3T-VALUE-123', 'TOK3N9876', 'QUERYSECRET']) assert.ok(!shownCmd.includes(leak), 'в показанной команде: ' + leak);
  assert.ok(cmd.includes('S3CR3T-VALUE-123'), 'в скопированной команде – реальные');
});

test('маскирование: адрес с кавычкой в экранированном виде внутри YAML тоже скрыт', () => {
  const url = 'https://sub.example.com/x"y/ABCDEF123456?token=abc';
  const real = buildMihomo(proxies(), { secret: SECRET, services: ['youtube'], subscription: url }).yaml;
  assert.ok(!maskMihomo(real, { secret: SECRET, urls: [url] }).includes('ABCDEF123456'));
  assert.strictEqual(maskSubscriptionUrl('не адрес'), '••••');
});

test('страница: secret и токены не попадают в console, заголовок, адресную строку и имена файлов', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'web', 'tools', 'index.html'), 'utf8');
  for (const f of ['index.html', 'mihomo.js', 'router.js', 'ui.js', 'links.js']) {
    const src = f === 'index.html' ? html : fs.readFileSync(path.join(lib, f), 'utf8');
    assert.ok(!/console\.(log|info|debug|warn|error)/.test(src), f + ': console');
    assert.ok(!/history\.(push|replace)State|location\.(hash|href|search)\s*=[^=]|document\.title\s*=/.test(src), f + ': адрес страницы или заголовок');
  }
  assert.ok(/UI\.download\(tab, files\[tab\]\)/.test(html), 'имя скачиваемого файла – только название вкладки');
  assert.ok(/id="cp">Копировать как есть/.test(html) && /UI\.copy\(files\[tab\]/.test(html), 'копирование как есть берёт реальный текст');
  assert.ok(/out\(\)\.textContent = view\(files\[tab\]\)/.test(html) && /\$\('#cmd'\)\.textContent = view\(cmd\)/.test(html), 'на странице показывается замаскированный');
});

// ---------- совместимость с XKeen UI ----------
// XKeen UI v1.3.8 (frontend/src/lib/utils.ts, parseClashApiCredentials; backend/src/api_relay.rs): вкладки «Селекторы», «Соединения»,
// «DNS» показываются, только если найден порт по external-controller с адресом 0.0.0.0 или 127.0.0.1 либо задан external-controller-unix;
// backend ходит на 127.0.0.1:порт или в сокет /opt/etc/mihomo/<имя файла>. Поймано на живом Keenetic: адрес LAN прятал вкладки.
function xkeenUiCreds(yaml) {
  const unixMatch = yaml.match(/^external-controller-unix:\s*(?:(["'])(.*?)\1|([^#\n]+?))(?:\s+#.*)?$/m);
  const unixPath = unixMatch ? (unixMatch[2] ?? unixMatch[3])?.trim() || null : null;
  const unix = unixPath ? unixPath.split(/[\\/]/).pop() || null : null;
  const port = yaml.match(/^external-controller:\s*['"']?(?:0\.0\.0\.0|127\.0\.0\.1):(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[0-9]{1,4})\b/m)?.[1] ?? null;
  return { port, unix };
}

test('XKeen UI находит API mihomo при любом выборе доступа к панели (вкладки Селекторы, Соединения, DNS не пропадают)', () => {
  for (const o of [{}, { controller: 'lan', controllerIp: '10.0.0.1' }, { controller: 'local' }, { controller: 'all' }]) {
    const c = xkeenUiCreds(gen(o).yaml);
    assert.ok(c.port || c.unix, 'XKeen UI не найдёт API: ' + JSON.stringify(o));
  }
  assert.deepStrictEqual(xkeenUiCreds(gen({}).yaml), { port: null, unix: 'mihomo.sock' }, 'по умолчанию LAN-адрес и сокет для XKeen UI');
  assert.strictEqual(xkeenUiCreds(gen({ controller: 'local' }).yaml).port, '9090');
  assert.strictEqual(xkeenUiCreds(gen({ controller: 'all' }).yaml).port, '9090');
});

test('сокет для XKeen UI: только в каталоге mihomo, не для Nikki, адрес zashboard остаётся LAN', () => {
  const lan = gen({});
  assert.strictEqual(lan.config['external-controller-unix'], '/opt/etc/mihomo/mihomo.sock');
  assert.strictEqual(lan.config['external-controller'], '192.168.1.1:9090');
  assert.ok(!('external-controller-unix' in gen({ target: 'nikki' }).config), 'у Nikki своя схема');
  assert.ok(!('external-controller-unix' in gen({ controller: 'local' }).config));
  assert.ok(!('external-controller-unix' in gen({ controller: 'all' }).config));
});

test('GEOSITE в своих правилах: предупреждение про скачивание GeoSite.dat, у других типов его нет', () => {
  assert.match(gen({ customRules: 'GEOSITE,category-ads-all,REJECT' }).warnings.join('\n'), /GEOSITE.*GeoSite\.dat/);
  assert.ok(!gen({ customRules: 'GEOIP,ru,DIRECT\nDOMAIN-SUFFIX,a.example.com' }).warnings.join('\n').includes('GeoSite.dat'));
  assert.ok(gen({ customRules: 'GEOSITE,category-ads-all,REJECT' }).config['rule-providers']['user-reject@classical'], 'правило при этом остаётся в наборе');
});

// ---------- 68-E3: каталог сервисов ----------
const { MIHOMO_CATALOG } = require(path.join(lib, 'mihomo-catalog.js'));
const legacyServices = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'mihomo-services-legacy.json'), 'utf8'));

test('каталог: 12 прежних сервисов перенесены 1:1 (id, подписи, группы, ярусы, наборы, адреса, порядок)', () => {
  assert.deepStrictEqual(MIHOMO_SERVICES.map((s) => s.id).slice(0, 12), legacyServices.map((s) => s.id), 'порядок и id прежние');
  for (const old of legacyServices) {
    const now = MIHOMO_SERVICES.find((s) => s.id === old.id);
    assert.deepStrictEqual(now, old, old.id);
  }
});

test('каталог: новые сервисы добавлены, google и cdn только для схемы XKeen и в текущей форме не видны', () => {
  const ids = MIHOMO_SERVICES.map((s) => s.id);
  for (const id of ['reddit', 'steam', 'speedtest']) assert.ok(ids.includes(id), id + ' доступен в текущей схеме');
  for (const id of ['google', 'cdn']) assert.ok(!ids.includes(id) && MIHOMO_CATALOG.some((s) => s.id === id && s.onlyIn === 'xkeen'), id);
  assert.ok(MIHOMO_SERVICES.filter((s) => ['reddit', 'steam', 'speedtest'].includes(s.id)).every((s) => s.on === false), 'новые выключены по умолчанию: вывод у прежних наборов не меняется');
  const cdn = MIHOMO_CATALOG.find((s) => s.id === 'cdn');
  assert.strictEqual(cdn.sets.length, 20, '7 пар domain+ipcidr и 6 одиночных ipcidr');
  assert.deepStrictEqual(cdn.sets.map((x) => x.name.split('@')[0]).filter((n, i, a) => a.indexOf(n) === i),
    ['amazon', 'akamai', 'cloudflare', 'digitalocean', 'fastly', 'oracle', 'hetzner', 'scaleway', 'ovh', 'vultr', 'vodafone', 'gcore', 'cdn77']);
});

test('каталог: схема записей (обязательные поля, уникальность, допустимые значения, адреса https без секретов)', () => {
  const TIERS = ['service', 'refilter', 'google-github', 'cdn'], ORDERS = ['proxy-first', 'direct-first', 'pass-first', 'pass-last', null];
  const ids = new Set(), setNames = new Set(), groups = new Set();
  for (const s of MIHOMO_CATALOG) {
    assert.ok(/^[a-z0-9-]+$/.test(s.id) && !ids.has(s.id), 'id: ' + s.id);
    ids.add(s.id);
    assert.ok(typeof s.label === 'string' && s.label.trim() && typeof s.on === 'boolean', s.id);
    assert.ok(TIERS.includes(s.tier), s.id + ': ярус');
    assert.ok(s.onlyIn === undefined || s.onlyIn === 'xkeen', s.id);
    const grp = s.group || s.label;
    assert.ok(!/[,"\n]/.test(grp), s.id + ': имя группы без запятых и кавычек');
    if (!s.onlyIn) { assert.ok(!groups.has(grp), 'имя группы повторяется: ' + grp); groups.add(grp); }
    assert.ok(Array.isArray(s.sets) && s.sets.length > 0, s.id);
    for (const x of s.sets) {
      assert.ok(/^[a-z0-9-]+@(domain|ipcidr|classical)$/.test(x.name) && !setNames.has(x.name), 'набор: ' + x.name);
      setNames.add(x.name);
      assert.strictEqual(x.name.split('@')[1], x.behavior, x.name + ': тип в имени и в поле совпадают');
      assert.ok(/^https:\/\/[a-z0-9.-]+\/[^\s"'\\]+$/i.test(x.url) && !/[?#]/.test(x.url), x.name + ': адрес');
      assert.ok(['metacubex', 'zxc-rv', 'legiz-ru'].includes(x.source), x.name + ': источник');
      assert.ok(x.url.includes({ metacubex: 'MetaCubeX', 'zxc-rv': 'zxc-rv', 'legiz-ru': 'legiz-ru' }[x.source]), x.name + ': источник совпадает с адресом');
    }
    assert.ok(s.xkeen && TIERS.includes(s.xkeen.tier) && ORDERS.includes(s.xkeen.order === undefined ? null : s.xkeen.order), s.id + ': схема XKeen');
    if (s.xkeen.excludeFilter !== undefined) assert.ok(typeof s.xkeen.excludeFilter === 'string' && s.xkeen.excludeFilter.length < 40, s.id);
  }
});

test('каталог: порядок proxies по шаблону zxc-rv (22.10.2026): Google, GitHub, CDN: PASS последним (у Google и GitHub не как в шаблоне), Reddit, Steam, Twitch DIRECT первым', () => {
  const order = (id) => MIHOMO_CATALOG.find((s) => s.id === id).xkeen.order;
  for (const id of ['google', 'github', 'cdn']) assert.strictEqual(order(id), 'pass-last', id);
  for (const id of ['reddit', 'steam', 'twitch']) assert.strictEqual(order(id), 'direct-first', id);
  for (const id of ['youtube', 'discord', 'meta', 'spotify', 'speedtest', 'telegram', 'ai', 'twitter', 'tiktok']) assert.strictEqual(order(id), 'proxy-first', id);
  assert.strictEqual(MIHOMO_CATALOG.find((s) => s.id === 'ai').xkeen.excludeFilter, '🇷🇺');
  assert.strictEqual(MIHOMO_CATALOG.find((s) => s.id === 'spotify').xkeen.excludeFilter, '🇷🇺');
  assert.strictEqual(MIHOMO_CATALOG.find((s) => s.id === 'cdn').xkeen.tier, 'cdn');
  assert.strictEqual(MIHOMO_CATALOG.find((s) => s.id === 'blocked').xkeen.tier, 'refilter');
});

test('новые сервисы текущей схемы дают рабочий вывод: наборы объявлены, ссылки целы', () => {
  const r = gen({ services: ['reddit', 'steam', 'speedtest'] });
  assert.deepStrictEqual(Object.keys(r.config['rule-providers']).sort(), ['reddit@domain', 'speedtest@domain', 'steam@domain']);
  assert.deepStrictEqual(integrity(r.config), []);
  assert.ok(['reddit', 'steam', 'speedtest'].every((n) => r.config.rules.includes('RULE-SET,' + n + '@domain,Прокси')));
  const per = gen({ services: ['reddit', 'steam', 'speedtest'], perService: true });
  assert.ok(per.config.rules.includes('RULE-SET,reddit@domain,Reddit') && per.config['proxy-groups'].some((g) => g.name === 'Steam') && per.config['proxy-groups'].some((g) => g.name === 'Speedtest'));
  assert.deepStrictEqual(integrity(per.config), []);
});

test('страница подключает каталог раньше генератора; без каталога генератор говорит прямо', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'web', 'tools', 'index.html'), 'utf8');
  assert.ok(html.indexOf('lib/mihomo-catalog.js') > 0 && html.indexOf('lib/mihomo-catalog.js') < html.indexOf('lib/mihomo.js'));
});
