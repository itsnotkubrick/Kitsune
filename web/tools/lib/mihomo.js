// Сборка config.yaml для Mihomo (XKeen) из разобранных ссылок.
(function (root) {
  'use strict';

  const META = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/';
  const REFILTER = 'https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/';

  // Панель zashboard: версия закреплена – «latest» поставил бы на роутер то, что мы не проверяли.
  const ZASHBOARD = 'v3.29.1';
  const ZASH_URL = { pinned: 'https://github.com/Zephyruso/zashboard/releases/download/' + ZASHBOARD + '/dist.zip', latest: 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip' };

  // Подсказки про порты XKeen (команда xkeen -cp): список портов, которые XKeen пропускает через ядро. Тексты из задания автора.
  const PORT_HINTS = {
    discord: 'Discord: добавьте порты 80,443,2053:2096,8443,19200:19400,50000:50100 (команда xkeen -cp)',
    telegram: 'Telegram и WhatsApp: добавьте порты 80,443,596:599,1400,3478,5222 (команда xkeen -cp)',
  };
  const portHints = (ids, refilterOn) => ids.filter((id) => PORT_HINTS[id]).map((id) => PORT_HINTS[id]).concat(['Для Speedtest нужен порт 8080 (команда xkeen -cp)']);

  // Служебные «узлы» подписки (остаток трафика, срок действия) попадают в автовыбор и портят его. Фильтр задаётся один раз на провайдере.
  // Регулярные выражения Mihomo – Go (RE2): без lookahead/lookbehind и обратных ссылок. Слова пресета подтверждены с автором.
  const EXCLUDE_PRESET = '(?i)осталось|срок|трафик|traffic|expire|remaining|до\\s+\\d';

  // Проверка своего регулярного выражения: компиляция в JS и поиск конструкций, которых нет в RE2.
  function checkRegex(src) {
    const out = { ok: true, error: '', warnings: [] };
    if (!src) return out;
    if (src.length > 200 || /[\u0000-\u001f\u007f]/.test(src)) return { ok: false, error: 'регулярное выражение длиннее 200 знаков или содержит управляющие символы', warnings: [] };
    let js = src;
    if (/^\(\?i\)/.test(js)) js = js.slice(4); // (?i) есть в Go, а в JS его нет: флаг отдельно
    try { new RegExp(js, 'iu'); } catch (e) { return { ok: false, error: 'не компилируется: ' + e.message.replace(/^Invalid regular expression: /, ''), warnings: [] }; }
    if (/\(\?<?[=!]/.test(src)) out.warnings.push('в Mihomo (Go, RE2) не работают lookahead и lookbehind: (?=…), (?!…), (?<=…), (?<!…)');
    if (/\\[1-9]|\\k</.test(src)) out.warnings.push('в Mihomo (Go, RE2) не работают обратные ссылки (\\1, \\k<имя>)');
    if (out.warnings.length) out.ok = false, out.error = out.warnings[0];
    return out;
  }

  // Сервисы берутся из каталога (mihomo-catalog.js): данные, а не код. Для текущей схемы групп сервисы только для схемы XKeen
  // (onlyIn) не показываются; форма записи прежняя: sets – массивы [имя, адрес, тип].
  const CATALOG = (typeof module === 'object' && module.exports) ? require('./mihomo-catalog.js').MIHOMO_CATALOG : (root.PM && root.PM.MIHOMO_CATALOG);
  if (!CATALOG) throw new Error('Не загружен каталог сервисов (mihomo-catalog.js)');
  const SERVICES = CATALOG.filter((s) => !s.onlyIn).map((s) => {
    const o = { id: s.id, label: s.label, on: s.on, sets: s.sets.map((x) => [x.name, x.url, x.behavior]) };
    if (s.hint) o.hint = s.hint;
    if (s.group) o.group = s.group;
    if (s.tier && s.tier !== 'service') o.tier = s.tier;
    return o;
  });

  // ---------- YAML ----------

  const PLAIN = /^[A-Za-z0-9_][A-Za-z0-9_.\/@:+-]*$/;
  const RESERVED = /^(true|false|yes|no|on|off|null|~|y|n|[-+]?[0-9][0-9_.eE+-]*|0x[0-9a-f]+)$/i;

  function scalar(v) {
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    const s = String(v);
    return PLAIN.test(s) && !RESERVED.test(s) && !s.includes(': ') ? s : JSON.stringify(s);
  }

  function flow(v) {
    if (Array.isArray(v)) return '[' + v.map(flow).join(', ') + ']';
    if (v && typeof v === 'object') return '{' + Object.keys(v).map((k) => scalar(k) + ': ' + flow(v[k])).join(', ') + '}';
    return scalar(v);
  }

  function yaml(v, ind) {
    ind = ind || '';
    if (Array.isArray(v)) {
      if (!v.length) return ' []\n';
      return '\n' + v.map((x) => {
        if (x && typeof x === 'object' && !Array.isArray(x)) {
          const body = yaml(x, ind + '  ').replace(/^\n/, '');
          return ind + '- ' + body.slice(ind.length + 2);
        }
        return ind + '- ' + scalar(x) + '\n';
      }).join('');
    }
    if (v && typeof v === 'object') {
      return '\n' + Object.keys(v).map((k) => {
        const x = v[k];
        if (x && typeof x === 'object') {
          if (x.__rawText !== undefined) return ind + scalar(k) + ':' + x.__rawText;
          if (x.__flow) { const c = Object.assign({}, x); delete c.__flow; return ind + scalar(k) + ': ' + flow(c) + '\n'; }
          return ind + scalar(k) + ':' + yaml(x, ind + '  ');
        }
        return ind + scalar(k) + ': ' + scalar(x) + '\n';
      }).join('');
    }
    return ' ' + scalar(v) + '\n';
  }

  function clean(o) {
    Object.keys(o).forEach((k) => {
      const v = o[k];
      if (v === undefined || v === '' || v === false && k !== 'tls' && k !== 'udp' || (Array.isArray(v) && !v.length)) delete o[k];
    });
    return o;
  }

  // ---------- прокси ----------

  function transportOpts(p, o) {
    const t = p.transport;
    if (t.network === 'tcp') {
      if (t.headerType === 'http') {
        o.network = 'http';
        o['http-opts'] = clean({ path: [t.path], headers: t.host ? { Host: [t.host] } : undefined });
      } else o.network = 'tcp';
    } else if (t.network === 'ws' || t.network === 'httpupgrade') {
      o.network = 'ws';
      o['ws-opts'] = clean({ path: t.path, headers: t.host ? { Host: t.host } : undefined, 'v2ray-http-upgrade': t.network === 'httpupgrade' || undefined });
    } else if (t.network === 'grpc') {
      o.network = 'grpc';
      o['grpc-opts'] = { 'grpc-service-name': t.serviceName };
    } else if (t.network === 'xhttp') {
      o.network = 'xhttp';
      o['xhttp-opts'] = clean({ path: t.path, host: t.host, mode: t.mode });
    }
  }

  function tlsOpts(p, o, sniKey) {
    const s = p.tls;
    if (s.security === 'none') { o.tls = false; return; }
    o.tls = true;
    o[sniKey] = s.sni;
    o['client-fingerprint'] = s.fp || undefined;
    o.alpn = s.alpn;
    o['skip-cert-verify'] = s.insecure || undefined;
    if (s.security === 'reality') o['reality-opts'] = clean({ 'public-key': s.pbk, 'short-id': s.sid });
  }

  function proxy(p) {
    const o = { name: p.name, type: p.type, server: p.server, port: p.port, udp: true };
    switch (p.type) {
      case 'vless':
        o.uuid = p.uuid; o.flow = p.flow || undefined;
        transportOpts(p, o); tlsOpts(p, o, 'servername');
        break;
      case 'vmess':
        o.uuid = p.uuid; o.alterId = p.alterId; o.cipher = p.cipher;
        transportOpts(p, o); tlsOpts(p, o, 'servername');
        break;
      case 'trojan':
        o.password = p.password;
        transportOpts(p, o); tlsOpts(p, o, 'sni');
        if (o.network === 'tcp') delete o.network;
        delete o.tls;
        break;
      case 'ss':
        o.cipher = p.method; o.password = p.password;
        break;
      case 'tuic':
        o.uuid = p.uuid; o.password = p.password; o.sni = p.sni; o.alpn = p.alpn;
        o['congestion-controller'] = p.congestion; o['udp-relay-mode'] = p.udpRelay;
        o['skip-cert-verify'] = p.insecure || undefined;
        break;
      case 'wireguard':
      case 'amneziawg':
        o.type = 'wireguard';
        o.ip = p.address.find((a) => a.includes('.'));
        o.ipv6 = p.address.find((a) => a.includes(':'));
        o['private-key'] = p.privateKey; o['public-key'] = p.publicKey;
        o['pre-shared-key'] = p.preSharedKey || undefined; o.mtu = p.mtu;
        o.reserved = p.reserved || undefined;
        // Параметры AmneziaWG в именах Mihomo. Для 3.1 (есть ключ защиты заголовков)
        // обязателен version: 3 – без него Mihomo не подключается к такому серверу.
        if (p.awg) {
          const names = { headerprotectionkey: 'header-protection-key', contentpaddingaddition: 'content-padding-addition',
            rekeyaftertime: 'rekey-after-time', rejectaftertime: 'reject-after-time', rekeytimeout: 'rekey-timeout',
            keepalivetimeout: 'keepalive-timeout', maxhandshakeattempts: 'max-handshake-attempts',
            randomtrailers: 'random-trailers', disablecookies: 'disable-cookies' };
          const c = {};
          Object.keys(p.awg).forEach((k) => {
            const v = p.awg[k];
            if (k === 'randomtrailers' || k === 'disablecookies') c[names[k]] = /^(on|true|1|yes)$/i.test(String(v));
            else c[names[k] || k] = /^h[1-4]$/.test(k) ? String(v) : v;
          });
          // версия 3 – по ключу защиты заголовков или любому признаку 3.1 (S3/S4 и новые поля)
          if (['header-protection-key', 's3', 's4', 'content-padding-addition', 'rekey-after-time', 'rekey-timeout', 'reject-after-time',
            'keepalive-timeout', 'max-handshake-attempts'].some((n) => c[n] !== undefined)) c.version = 3;
          // эти два флага есть только в ядре версии 3
          if (c.version !== 3) { delete c['random-trailers']; delete c['disable-cookies']; }
          o['amnezia-wg-option'] = c;
        }
        break;
      case 'hysteria2':
        o.password = p.password; o.sni = p.sni; o.alpn = p.alpn;
        o['skip-cert-verify'] = (p.insecure && !p.pinSHA256) || undefined;
        o.fingerprint = p.pinSHA256 || undefined;
        if (p.obfs) { o.obfs = p.obfs; o['obfs-password'] = p.obfsPassword; }
        break;
    }
    return clean(o);
  }

  function randomSecret() {
    const a = new Uint8Array(12);
    (root.crypto || require('crypto').webcrypto).getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // ---------- свои сайты и правила ----------

  // Домен для набора правил: кириллица и прочие национальные символы переводятся в punycode (пример.рф -> xn--e1afmkfd.xn--p1ai).
  // Возвращает строку или '' – если это не домен (пробелы, кавычки, переводы строк и т.п. сюда не проходят).
  function asciiDomain(raw) {
    let d = String(raw).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/?#].*$/, '').replace(/^\*\./, '').replace(/^\./, '').replace(/\.$/, '');
    if (!d || /[\s"'\\,;<>@:]/.test(d)) return '';
    if (/[^\x00-\x7f]/.test(d)) {
      try { d = new URL('http://' + d).hostname; } catch (e) { return ''; }
    }
    return /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z0-9-]{2,}$/.test(d) && !/(^|\.)-|-(\.|$)/.test(d) ? d : '';
  }

  // Списки доменов (через пробел, запятую или с новой строки): годные и отброшенные – чтобы ничего не пропадало молча.
  function domainList(text) {
    const list = [], bad = [];
    String(text || '').split(/[\s,]+/).filter(Boolean).forEach((x) => {
      const d = asciiDomain(x);
      if (d) { if (!list.includes(d)) list.push(d); } else bad.push(x.length > 40 ? x.slice(0, 37) + '…' : x);
    });
    return { list, bad };
  }

  // Свои правила: «ТИП,значение[,действие]», по одной в строке, как в клиентских профилях Kitsune. Тип – из белого списка, действие
  // PROXY (по умолчанию), DIRECT или REJECT. Голая строка-домен считается DOMAIN-SUFFIX. Строки с ошибкой не пропадают молча.
  const RULE_TYPES = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOSITE', 'GEOIP'];
  const RULE_ACTIONS = ['PROXY', 'DIRECT', 'REJECT'];

  function ruleValue(type, v) {
    if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') return asciiDomain(v);
    if (type === 'DOMAIN-KEYWORD') return /^[a-z0-9._-]{1,63}$/.test(v.toLowerCase()) ? v.toLowerCase() : '';
    if (type === 'IP-CIDR') {
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(v);
      return m && m.slice(1, 5).every((o) => +o <= 255) && (m[5] === undefined || +m[5] <= 32) ? (m[5] === undefined ? v + '/32' : v) : '';
    }
    if (type === 'IP-CIDR6') {
      const m = /^([0-9a-f:]{2,39})(?:\/(\d{1,3}))?$/i.exec(v);
      return m && m[1].includes(':') && !/:::/.test(m[1]) && (m[2] === undefined || +m[2] <= 128) ? (m[2] === undefined ? v.toLowerCase() + '/128' : v.toLowerCase()) : '';
    }
    if (type === 'GEOSITE') return /^[a-z0-9!@._-]{1,60}$/i.test(v) ? v.toLowerCase() : '';
    if (type === 'GEOIP') return /^[A-Za-z]{2}$/.test(v) ? v.toUpperCase() : '';
    return '';
  }

  function parseRules(text) {
    const rules = [], errors = [];
    String(text || '').split(/\r?\n/).forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith('#')) return;
      const err = (why) => errors.push({ line: i + 1, text: line.length > 50 ? line.slice(0, 47) + '…' : line, error: why });
      let p = line.split(',').map((s) => s.trim());
      if (p.length === 1 && asciiDomain(p[0])) p = ['DOMAIN-SUFFIX', p[0]];
      const type = p[0].toUpperCase();
      if (!RULE_TYPES.includes(type)) return err('неизвестный тип «' + (p[0].length > 20 ? p[0].slice(0, 17) + '…' : p[0]) + '» (можно: ' + RULE_TYPES.join(', ') + ')');
      if (p.length < 2 || p.length > 3) return err('нужен вид «ТИП,значение» или «ТИП,значение,действие»');
      const value = ruleValue(type, p[1]);
      if (!value) return err('недопустимое значение для ' + type);
      const action = (p[2] || 'PROXY').toUpperCase();
      if (!RULE_ACTIONS.includes(action)) return err('недопустимое действие (можно: PROXY, DIRECT, REJECT)');
      rules.push({ type, value, action });
    });
    return { rules, errors };
  }

  function domains(text) { return domainList(text).list; }

  const DEFAULT_LAN_IP = '192.168.1.1';
  function validIp(ip) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || '').trim());
    return !!m && m.slice(1).every((o) => +o <= 255 && String(+o) === o) && !/^(0\.|127\.|255\.|2(2[4-9]|[3-5]\d)\.)/.test(ip.trim());
  }
  function controllerOf(opts) {
    const mode = ['lan', 'local', 'all'].includes(opts.controller) ? opts.controller : 'lan';
    const warnings = [];
    if (mode === 'local') return { mode, address: '127.0.0.1:9090', host: '127.0.0.1', warnings };
    if (mode === 'all') {
      warnings.push('Панель управления слушает все интерфейсы (0.0.0.0:9090): проверьте, что порт 9090 не проброшен наружу');
      return { mode, address: '0.0.0.0:9090', host: 'IP-роутера', warnings };
    }
    let ip = String(opts.controllerIp || DEFAULT_LAN_IP).trim();
    if (!validIp(ip)) { warnings.push('Адрес роутера «' + ip.replace(/[^\x20-\x7e]/g, ' ').slice(0, 40) + '» не подходит, взят ' + DEFAULT_LAN_IP); ip = DEFAULT_LAN_IP; }
    return { mode, address: ip + ':9090', host: ip, warnings };
  }

  // ---------- маскирование для показа на странице ----------
  const DOTS = '••••••••••••';
  // Токен подписки может лежать в пути или в параметрах: маскируем длинные и содержащие цифры сегменты пути, все значения параметров и логин.
  function maskUrl(u) {
    try {
      const x = new URL(u);
      const path = x.pathname.split('/').map((s) => (s.length >= 16 || (s.length >= 6 && /\d/.test(s)) ? '••••' : s)).join('/');
      const q = Array.from(x.searchParams.keys()).map((k) => k + '=••••').join('&');
      return x.protocol + '//' + (x.username || x.password ? '••••@' : '') + x.host + path + (q ? '?' + q : '');
    } catch (e) { return '••••'; }
  }
  // text – файл или команда; hide – { secret, urls }. Реальный текст остаётся только в буфере «копировать как есть» и в скачанном файле.
  function maskSecrets(text, hide) {
    let s = String(text);
    const rep = (needle, to) => { if (needle) s = s.split(needle).join(to); };
    (hide.urls || []).slice().sort((a, b) => b.length - a.length).forEach((u) => { const m = maskUrl(u); rep(u, m); rep(JSON.stringify(u).slice(1, -1), m); });
    rep(hide.secret, DOTS);
    return s;
  }

  // ---------- схема групп «как в шаблоне XKeen» (opts.groupModel === 'xkeen'; шаблон zxc-rv от 22.10.2026) ----------
  const XK_BASE = 'Заблок. сервисы';
  const XK_GROUP_ORDER = ['YouTube', 'Discord', 'Twitch', 'Reddit', 'Meta', 'Spotify', 'Speedtest', 'Telegram', 'Steam', 'CDN', 'Google', 'GitHub', 'AI', 'Twitter', 'TikTok'];
  const XK_RULE_ORDER = ['ai', 'steam', 'spotify', 'reddit', 'youtube', 'twitch', 'twitter', 'tiktok', 'netflix', 'discord', 'speedtest', 'meta', 'telegram'];
  const XK_ORDERS = {
    'proxy-first': [XK_BASE, 'Fallback', 'Fastest', 'DIRECT'],
    'direct-first': ['DIRECT', XK_BASE, 'Fallback', 'Fastest'],
    'pass-first': ['PASS', XK_BASE, 'Fallback', 'Fastest'],
    'pass-last': [XK_BASE, 'Fallback', 'Fastest', 'PASS'],
  };
  const XK_CHECK = 'https://www.gstatic.com/generate_204';

  // Сервисы схемы XKeen из каталога: ярус, порядок proxies и наборы берутся из блока xkeen записи.
  function xkeenServices(opts) {
    const ids = opts.services || CATALOG.filter((s) => s.xkeen && s.xkeen.on).map((s) => s.id);
    return CATALOG.filter((s) => ids.includes(s.id)).map((s) => {
      let sets = s.xkeen.sets || s.sets;
      if (s.id === 'blocked' && opts.refilterIp === false) sets = sets.filter((x) => x.behavior !== 'ipcidr');
      return { id: s.id, group: (s.xkeen.group || s.group || s.label).replace(/,/g, ''), tier: s.xkeen.tier, order: s.xkeen.order, excludeFilter: s.xkeen.excludeFilter, sets };
    });
  }

  // Правила сервиса: пара domain+ipcidr с одним именем склеивается в OR (no-resolve у каждого ipcidr), остальное по одному.
  function xkeenSetRules(s, target) {
    const rules = [], done = new Set();
    // У CDN и Google без no-resolve, как в шаблоне: домен без адреса в соединении иначе не попадёт в диапазон
    const nr = s.tier === 'cdn' || s.tier === 'google-github' ? '' : ',no-resolve';
    s.sets.forEach((x) => {
      if (done.has(x.name)) return;
      const base = x.name.split('@')[0];
      const dom = s.sets.find((y) => y.name === base + '@domain'), ip = s.sets.find((y) => y.name === base + '@ipcidr');
      if (dom && ip) {
        rules.push('OR,((RULE-SET,' + dom.name + '),(RULE-SET,' + ip.name + nr + ')),' + target);
        done.add(dom.name); done.add(ip.name);
      } else {
        rules.push('RULE-SET,' + x.name + ',' + target + (x.behavior === 'ipcidr' ? nr : ''));
        done.add(x.name);
      }
    });
    return rules;
  }

  function xkeenGroups(services) {
    const groups = [
      { name: XK_BASE, type: 'select', 'include-all': true, proxies: ['Fallback', 'Fastest'] },
      { name: 'Fallback', type: 'fallback', url: XK_CHECK, interval: 300, 'max-failed-times': 3, hidden: true, 'include-all': true },
      { name: 'Fastest', type: 'url-test', url: XK_CHECK, interval: 300, 'max-failed-times': 3, hidden: true, 'include-all': true },
    ];
    const rank = (g) => { const i = XK_GROUP_ORDER.indexOf(g); return i < 0 ? 1000 : i; };
    services.filter((s) => s.tier !== 'refilter').map((s, i) => [s, i]).sort((a, b) => rank(a[0].group) - rank(b[0].group) || a[1] - b[1]).forEach(([s]) => {
      const g = { name: s.group, type: 'select', 'include-all': true };
      if (s.excludeFilter) g['exclude-filter'] = s.excludeFilter;
      g.proxies = XK_ORDERS[s.order] || XK_ORDERS['proxy-first'];
      groups.push(g);
    });
    return groups;
  }

  // Провайдеры с якорями (&domain, &ipcidr, &inline) как в шаблоне, без явного path: имя файла mihomo выводит из адреса, и уже
  // скачанные наборы пользователя переиспользуются. Возвращает описания, настоящий объект для config и текст для файла.
  function xkeenProviders(specs) {
    const anchors = {
      a1: { type: 'http', format: 'mrs', behavior: 'domain', interval: 86400 },
      a2: { type: 'http', format: 'mrs', behavior: 'ipcidr', interval: 86400 },
      a4: { type: 'inline', behavior: 'classical' },
    };
    const anchorsText = '\n  a1: &domain { type: http, format: mrs, behavior: domain, interval: 86400 }\n' +
      '  a2: &ipcidr { type: http, format: mrs, behavior: ipcidr, interval: 86400 }\n' +
      '  a4: &inline { type: inline, behavior: classical }\n';
    const real = {};
    let text = '\n';
    specs.forEach((s) => {
      if (s.kind === 'http') {
        real[s.name] = Object.assign({}, anchors[s.behavior === 'ipcidr' ? 'a2' : 'a1'], { url: s.url });
        text += '  ' + scalar(s.name) + ': { <<: *' + (s.behavior === 'ipcidr' ? 'ipcidr' : 'domain') + ', url: ' + scalar(s.url) + ' }\n';
      } else {
        real[s.name] = Object.assign({}, anchors.a4, { behavior: s.behavior, payload: s.payload });
        text += '  ' + scalar(s.name) + ':\n    <<: *inline\n' + (s.behavior !== 'classical' ? '    behavior: ' + s.behavior + '\n' : '') + '    payload:\n' +
          s.payload.map((x) => '      - ' + scalar(x) + '\n').join('');
      }
    });
    return { anchors, anchorsText, real, text };
  }

  // opts: services[], subscriptions[] (или subscription), perService, finalProxy, blockAds, blockQuic, proxyDomains, directDomains
  function build(proxies, opts) {
    opts = opts || {};
    const xk = opts.groupModel === 'xkeen'; // схема групп «как в шаблоне XKeen»; по умолчанию прежняя (Прокси и Авто)
    const services = xk ? xkeenServices(opts) : SERVICES.filter((s) => (opts.services || SERVICES.filter((x) => x.on).map((x) => x.id)).includes(s.id))
      // re:filter по адресам (refilter@ipcidr) – отдельная галочка; по умолчанию включена, как и раньше, чтобы поведение у прежних наборов не менялось
      .map((s) => (s.id === 'blocked' && opts.refilterIp === false ? Object.assign({}, s, { sets: s.sets.filter((x) => x[2] !== 'ipcidr') }) : s));
    const subs = opts.subscriptions || (opts.subscription ? [opts.subscription] : []);
    if (!proxies.length && !subs.length) throw new Error('Добавьте хотя бы одну ссылку или подписку.');

    // Адрес панели управления: по умолчанию LAN-адрес роутера, а не все интерфейсы. 0.0.0.0 – только по явному выбору.
    const controller = controllerOf(opts);
    const cfg = {
      'log-level': opts.logLevel === 'silent' ? 'silent' : 'warning',
      'allow-lan': true,
      'redir-port': 5000,
      'tproxy-port': 5001,
      'routing-mark': 255,
      'find-process-mode': 'off',
      'unified-delay': true,
      'external-controller': controller.address,
      // XKeen UI (v1.3.8) находит API mihomo только по external-controller с адресом 0.0.0.0 или 127.0.0.1, иначе вкладки «Селекторы»,
      // «Соединения» и «DNS» в нём пропадают. При адресе LAN его панели ходят через unix-сокет в каталоге mihomo; zashboard остаётся на LAN.
      ...(controller.mode === 'lan' && opts.target !== 'nikki' ? { 'external-controller-unix': '/opt/etc/mihomo/mihomo.sock' } : {}),
      secret: opts.secret || randomSecret(),
      'external-ui': 'zashboard',
      'external-ui-url': opts.zashboard === 'latest' ? ZASH_URL.latest : ZASH_URL.pinned,
      sniffer: {
        enable: true,
        sniff: { HTTP: { __flow: 1, ports: [80, 8080] }, TLS: { __flow: 1, ports: [443, 8443] }, QUIC: { __flow: 1, ports: [443, 8443] } },
      },
    };
    if (services.some((s) => s.id === 'telegram')) cfg.sniffer['skip-dst-address'] = ['rule-set:telegram@ipcidr'];
    // Голосовой чат в играх (vivox) ломается, если разбирать его трафик: домен исключается из sniffer.
    if (opts.vivox) cfg.sniffer['skip-domain'] = ['+.vivox.com'];

    proxies = proxies.filter((p) => p.type !== 'mtproto');
    if (proxies.length) cfg.proxies = proxies.map(proxy);
    const warnings0 = [];
    let exclude = '';
    if (opts.excludePreset || opts.excludeRegex) {
      const mine = String(opts.excludeRegex || '').trim();
      const chk = checkRegex(mine);
      if (!chk.ok) warnings0.push('Фильтр узлов: ' + chk.error + '; свой фильтр не применён');
      const parts = [];
      if (opts.excludePreset) parts.push(EXCLUDE_PRESET);
      if (mine && chk.ok) parts.push(mine);
      // (?i) допустим только в начале выражения: при объединении убираем его у частей и ставим один раз
      exclude = parts.length > 1 ? '(?i)' + parts.map((x) => x.replace(/^\(\?i\)/, '')).join('|') : parts[0] || '';
      if (exclude && !subs.length) warnings0.push('Фильтр узлов действует только на подписку: добавьте ссылку на подписку');
    }
    if (subs.length) {
      // Несколько подписок – несколько провайдеров; группы «Прокси» и «Авто» берут узлы из всех (include-all).
      cfg['proxy-providers'] = {};
      subs.forEach((url, i) => {
        const name = i === 0 ? 'subscription' : 'subscription' + (i + 1);
        cfg['proxy-providers'][name] = {
          type: 'http', url, interval: 3600, path: './providers/' + name + '.yaml',
          'health-check': { enable: true, url: 'https://www.gstatic.com/generate_204', interval: 300 },
        };
        if (exclude) cfg['proxy-providers'][name]['exclude-filter'] = exclude;
      });
    }

    const PROXY = xk ? XK_BASE : 'Прокси';
    const target = {};
    if (xk) {
      cfg['proxy-groups'] = xkeenGroups(services);
    } else {
      const groups = [
        { name: PROXY, type: 'select', proxies: ['Авто'], 'include-all': true },
        { name: 'Авто', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, 'include-all': true },
      ];
      services.forEach((s) => {
        if (opts.perService) {
          // В правилах запятая – разделитель, поэтому имя группы без запятых.
          const g = (s.group || s.label).replace(/,/g, '');
          groups.push({ name: g, type: 'select', proxies: [PROXY, 'DIRECT'], 'include-all': true });
          target[s.id] = g;
        } else target[s.id] = PROXY;
      });
      cfg['proxy-groups'] = groups;
    }

    const providers = {};
    const addSet = (name, url, behavior) => {
      providers[name] = { __flow: 1, type: 'http', format: 'mrs', behavior, url, path: './rules/' + name.replace('@', '-') + '.mrs', interval: 86400 };
    };
    if (!xk) {
      services.forEach((s) => s.sets.forEach((x) => addSet(x[0], x[1], x[2])));
      if (opts.blockAds) addSet('ads@domain', META + 'geosite/category-ads-all.mrs', 'domain');
    }
    const warnings = warnings0.concat(controller.warnings);
    const pdl = domainList(opts.proxyDomains), ddl = domainList(opts.directDomains);
    const pd = pdl.list, dd = ddl.list;
    pdl.bad.forEach((b) => warnings.push('Свои сайты через прокси: «' + b + '» не похоже на домен, пропущено'));
    ddl.bad.forEach((b) => warnings.push('Свои сайты напрямую: «' + b + '» не похоже на домен, пропущено'));
    const custom = parseRules(opts.customRules);
    // Правило GEOSITE заставляет mihomo скачать GeoSite.dat (несколько МБ) и загрузить его при каждом старте
    if (custom.rules.some((r) => r.type === 'GEOSITE')) warnings.push('Свои правила: GEOSITE при первом запуске скачает файл GeoSite.dat (несколько МБ) и замедлит загрузку mihomo; для сайтов лучше DOMAIN-SUFFIX');
    custom.errors.forEach((e) => warnings.push('Свои правила, строка ' + e.line + ' («' + e.text + '»): ' + e.error + ', пропущено'));
    // Набор в mihomo имеет одно действие на весь набор, поэтому свои правила раскладываются по действию. Порядок внутри яруса:
    // запретить, напрямую, через прокси (запрет сильнее разрешения).
    const userSets = [['REJECT', 'user-reject@classical', 'REJECT'], ['DIRECT', 'user-direct@classical', 'DIRECT'], ['PROXY', 'user@classical', PROXY]];
    userSets.forEach(([action, name]) => {
      const payload = custom.rules.filter((r) => r.action === action).map((r) => r.type + ',' + r.value + (/^IP-CIDR/.test(r.type) ? ',no-resolve' : ''));
      if (payload.length) providers[name] = { type: 'inline', behavior: 'classical', payload };
    });
    // UDP 443 (QUIC) отклоняется: видео через прокси грузится стабильнее по TCP.
    if (opts.blockQuic) providers['quic@inline'] = { type: 'inline', behavior: 'classical', payload: ['AND,((NETWORK,UDP),(DST-PORT,443))'] };
    if (pd.length) providers['my-proxy@inline'] = { type: 'inline', behavior: 'domain', payload: pd.map((d) => '+.' + d) };
    if (dd.length) providers['my-direct@inline'] = { type: 'inline', behavior: 'domain', payload: dd.map((d) => '+.' + d) };
    let xkP = null;
    if (xk) {
      // http-наборы сервисов и рекламы, затем inline-наборы (свои правила, QUIC, свои сайты) в порядке появления
      const specs = [];
      services.forEach((s) => s.sets.forEach((x) => specs.push({ kind: 'http', name: x.name, behavior: x.behavior, url: x.url })));
      if (opts.blockAds) specs.push({ kind: 'http', name: 'ads@domain', behavior: 'domain', url: META + 'geosite/category-ads-all.mrs' });
      Object.keys(providers).forEach((n) => specs.push({ kind: 'inline', name: n, behavior: providers[n].behavior, payload: providers[n].payload }));
      xkP = xkeenProviders(specs);
      cfg.anchors = xkP.anchors;
      cfg['rule-providers'] = xkP.real;
    } else if (Object.keys(providers).length) cfg['rule-providers'] = providers;

    // Ярусы правил сверху вниз; в mihomo срабатывает первое совпадение, поэтому порядок задан здесь, а не вводом пользователя:
    // реклама, QUIC, свои оверрайды (my-direct, my-proxy), сервисы, refilter, остальное. refilter всегда ниже конкретных сервисов,
    // иначе выбор сервера для YouTube или Telegram не сработает на доменах, которые есть и в refilter. Внутри яруса порядок – как в каталоге.
    if (xk) {
      // Ярусы схемы XKeen: реклама, QUIC, (Twitch в высоком качестве по галочке), свои оверрайды, сервисы в порядке шаблона, свои правила,
      // refilter, GitHub и Google, CDN, остальное. Группа сервиса – его имя; всё «через прокси» идёт в «Заблок. сервисы».
      const tr = { ads: [], quic: [], twitch: [], override: [], service: [], user: [], refilter: [], gg: [], cdn: [] };
      if (opts.blockAds) tr.ads.push('RULE-SET,ads@domain,REJECT');
      if (opts.blockQuic) tr.quic.push('RULE-SET,quic@inline,REJECT');
      if (opts.twitchHq && services.some((s) => s.id === 'twitch')) tr.twitch.push('OR,((DOMAIN-SUFFIX,gql.twitch.tv),(DOMAIN-SUFFIX,usher.ttvnw.net)),' + XK_BASE);
      if (dd.length) tr.override.push('RULE-SET,my-direct@inline,DIRECT');
      if (pd.length) tr.override.push('RULE-SET,my-proxy@inline,' + XK_BASE);
      const idx = (list, id) => { const i = list.indexOf(id); return i < 0 ? 1000 : i; };
      services.filter((s) => s.tier === 'service').map((s, i) => [s, i]).sort((a, b) => idx(XK_RULE_ORDER, a[0].id) - idx(XK_RULE_ORDER, b[0].id) || a[1] - b[1])
        .forEach(([s]) => tr.service.push(...xkeenSetRules(s, s.group)));
      userSets.forEach(([, name, tgt]) => { if (providers[name]) tr.user.push('RULE-SET,' + name + ',' + tgt); });
      services.filter((s) => s.tier === 'refilter').forEach((s) => tr.refilter.push(...xkeenSetRules(s, XK_BASE)));
      services.filter((s) => s.tier === 'google-github').sort((a, b) => idx(['github', 'google'], a.id) - idx(['github', 'google'], b.id)).forEach((s) => tr.gg.push(...xkeenSetRules(s, s.group)));
      services.filter((s) => s.tier === 'cdn').forEach((s) => tr.cdn.push(...xkeenSetRules(s, s.group)));
      const rules = [].concat(tr.ads, tr.quic, tr.twitch, tr.override, tr.service, tr.user, tr.refilter, tr.gg, tr.cdn);
      rules.push('MATCH,' + (opts.finalProxy ? XK_BASE : 'DIRECT'));
      cfg.rules = rules;
    } else {
      const tier = { ads: [], quic: [], override: [], service: [], user: [], refilter: [] };
      if (opts.blockAds) tier.ads.push('RULE-SET,ads@domain,REJECT');
      if (opts.blockQuic) tier.quic.push('RULE-SET,quic@inline,REJECT');
      if (dd.length) tier.override.push('RULE-SET,my-direct@inline,DIRECT');
      if (pd.length) tier.override.push('RULE-SET,my-proxy@inline,' + PROXY);
      services.forEach((s) => s.sets.forEach((x) => {
        tier[s.tier || 'service'].push('RULE-SET,' + x[0] + ',' + target[s.id] + (x[2] === 'ipcidr' ? ',no-resolve' : ''));
      }));
      userSets.forEach(([, name, target]) => { if (providers[name]) tier.user.push('RULE-SET,' + name + ',' + target); });
      const rules = [].concat(tier.ads, tier.quic, tier.override, tier.service, tier.user, tier.refilter);
      rules.push('MATCH,' + (opts.finalProxy ? PROXY : 'DIRECT'));
      cfg.rules = rules;
    }

    // Куда класть файл: XKeen на Keenetic или профиль Nikki на OpenWrt (порты и DNS Nikki подставляет сам).
    const where = opts.target === 'nikki'
      ? '# Для Nikki (OpenWrt): профиль /etc/nikki/profiles/kitsune.yaml, порты и DNS Nikki подставит сам\n'
      : '# Файл для XKeen: /opt/etc/mihomo/config.yaml, затем xkeen -restart\n';
    // Маркер нужен проверке идемпотентности и будущему импорту. dns: в файле нет: его ведёт XKeen UI, команда для роутера переносит его сама.
    const headHost = controller.host;
    const head = '# kitsune-managed v2\n' +
      '# Файл создан панелью Kitsune: правки вне блока dns: при следующей генерации будут потеряны (копия прежнего файла лежит рядом: config.yaml.bak-*)\n' +
      '# Сгенерировано в панели Kitsune\n' + where +
      '# Панель управления: http://' + headHost + ':9090/ui (секрет – поле secret ниже)\n';
    let emit = cfg;
    if (xkP) {
      // anchors идёт перед rule-providers; оба блока пишутся готовым текстом (якоря и merge-key обычным сериализатором не выразить)
      emit = {};
      Object.keys(cfg).forEach((k) => {
        if (k === 'anchors') return;
        if (k === 'rule-providers') { emit.anchors = { __rawText: xkP.anchorsText }; emit[k] = { __rawText: xkP.text }; } else emit[k] = cfg[k];
      });
    }
    return { yaml: head + yaml(emit).replace(/^\n/, ''), config: cfg, count: proxies.length, warnings };
  }

  const api = { buildMihomo: build, MIHOMO_SERVICES: SERVICES, MIHOMO_CATALOG: CATALOG, mihomoPortHints: portHints, maskMihomo: maskSecrets, maskSubscriptionUrl: maskUrl, validLanIp: validIp, MIHOMO_DEFAULT_LAN_IP: DEFAULT_LAN_IP, checkMihomoRegex: checkRegex, MIHOMO_EXCLUDE_PRESET: EXCLUDE_PRESET, ZASHBOARD_VERSION: ZASHBOARD, parseCustomRules: parseRules, asciiDomain, toYaml: (v) => yaml(v).replace(/^\n/, '') };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PM = Object.assign(root.PM || {}, api);
})(typeof window !== 'undefined' ? window : globalThis);
