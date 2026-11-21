// Разбор ссылок vless:// vmess:// trojan:// ss:// hy2:// в общий формат.
// Работает в браузере (window.PM) и в Node (module.exports). Всё локально –
// ссылки никуда не отправляются.
(function (root) {
  'use strict';

  function b64decode(s) {
    s = s.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    while (s.length % 4) s += '=';
    const bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
    // UTF-8 из бинарной строки
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }

  function looksBase64(s) {
    return /^[A-Za-z0-9+/=_\-\s]+$/.test(s) && s.replace(/\s/g, '').length >= 16;
  }

  function dec(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  function int(v, what) {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error('неверный ' + what + ': ' + v);
    return n;
  }

  function splitList(v) {
    return v ? dec(v).split(',').map((x) => x.trim()).filter(Boolean) : [];
  }

  function truthy(v) {
    return v === '1' || v === 'true' || v === 'True';
  }

  // Разбор адреса «хост:порт» из URL: поддерживает IPv6 в квадратных скобках.
  function hostPort(u) {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) throw new Error('нет адреса сервера');
    return { server: host, port: int(u.port || '443', 'порт') };
  }

  // Общие параметры транспорта и шифрования из query (формат Xray share link).
  function transportFromQuery(q, fallbackHost) {
    let network = (q.get('type') || 'tcp').toLowerCase();
    if (network === 'raw') network = 'tcp';
    if (network === 'http' && q.get('headerType') !== 'http') network = 'xhttp';
    const t = { network };
    const path = q.get('path') ? dec(q.get('path')) : '';
    const host = q.get('host') ? dec(q.get('host')) : '';
    if (network === 'ws' || network === 'httpupgrade') {
      t.path = path || '/';
      if (host) t.host = host;
    } else if (network === 'grpc') {
      t.serviceName = dec(q.get('serviceName') || q.get('path') || '');
      t.multiMode = q.get('mode') === 'multi';
    } else if (network === 'xhttp' || network === 'splithttp') {
      t.network = 'xhttp';
      t.path = path || '/';
      if (host) t.host = host;
      t.mode = q.get('mode') || 'auto';
    } else if (network === 'tcp') {
      if (q.get('headerType') === 'http') {
        t.headerType = 'http';
        t.path = path || '/';
        if (host) t.host = host;
      }
    } else {
      throw new Error('транспорт «' + network + '» не поддерживается');
    }

    const security = (q.get('security') || 'none').toLowerCase();
    const s = { security };
    if (security === 'tls' || security === 'reality') {
      s.sni = dec(q.get('sni') || q.get('peer') || '') || host || fallbackHost;
      s.fp = q.get('fp') || (security === 'reality' ? 'chrome' : '');
      s.alpn = splitList(q.get('alpn'));
      s.insecure = truthy(q.get('allowInsecure')) || truthy(q.get('insecure'));
      // Отпечаток сертификата: pcs – имя параметра в ссылках Xray 26, pinSHA256 – в ссылках Hysteria.
      s.pin = (q.get('pcs') || q.get('pinSHA256') || '').replace(/:/g, '').toLowerCase();
    }
    if (security === 'reality') {
      s.pbk = q.get('pbk') || '';
      if (!s.pbk) throw new Error('в ссылке REALITY нет публичного ключа (pbk)');
      s.sid = q.get('sid') || '';
      s.spx = q.get('spx') ? dec(q.get('spx')) : '';
    } else if (security !== 'tls' && security !== 'none') {
      throw new Error('шифрование «' + security + '» не поддерживается');
    }
    return { transport: t, tls: s };
  }

  function parseVless(link) {
    const u = new URL(link);
    const id = dec(u.username);
    if (!id) throw new Error('нет UUID');
    const hp = hostPort(u);
    const q = u.searchParams;
    const enc = q.get('encryption');
    if (enc && enc !== 'none') throw new Error('шифрование VLESS «' + enc + '» не поддерживается');
    return Object.assign({
      type: 'vless', name: dec(u.hash.slice(1)), uuid: id, flow: q.get('flow') || '',
    }, hp, transportFromQuery(q, hp.server));
  }

  function parseTrojan(link) {
    const u = new URL(link);
    const pw = dec(u.username);
    if (!pw) throw new Error('нет пароля');
    const hp = hostPort(u);
    const q = u.searchParams;
    if (!q.get('security')) q.set('security', 'tls');
    return Object.assign({ type: 'trojan', name: dec(u.hash.slice(1)), password: pw }, hp, transportFromQuery(q, hp.server));
  }

  function parseVmess(link) {
    const raw = b64decode(link.slice('vmess://'.length).split('#')[0]);
    let j;
    try { j = JSON.parse(raw); } catch (e) { throw new Error('ссылка vmess повреждена'); }
    if (!j.id || !j.add) throw new Error('в ссылке vmess нет адреса или UUID');
    const q = new URLSearchParams();
    q.set('type', j.net || 'tcp');
    if (j.type && j.type !== 'none') q.set(j.net === 'grpc' ? 'mode' : 'headerType', j.type);
    if (j.path) q.set(j.net === 'grpc' ? 'serviceName' : 'path', j.path);
    if (j.host) q.set('host', j.host);
    q.set('security', j.tls === 'tls' || j.tls === 'reality' ? j.tls : 'none');
    if (j.sni) q.set('sni', j.sni);
    if (j.alpn) q.set('alpn', j.alpn);
    if (j.fp) q.set('fp', j.fp);
    if (j.pbk) q.set('pbk', j.pbk);
    if (j.sid) q.set('sid', j.sid);
    return Object.assign({
      type: 'vmess', name: j.ps || '', uuid: j.id, alterId: Number(j.aid || 0),
      cipher: j.scy || 'auto', server: String(j.add), port: int(j.port, 'порт'),
    }, transportFromQuery(q, String(j.add)));
  }

  const SS_METHODS = [
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
  ];

  function parseSs(link) {
    let body = link.slice('ss://'.length);
    let name = '';
    const h = body.indexOf('#');
    if (h >= 0) { name = dec(body.slice(h + 1)); body = body.slice(0, h); }
    const qi = body.indexOf('?');
    let query = '';
    if (qi >= 0) { query = body.slice(qi + 1); body = body.slice(0, qi); }
    body = body.replace(/\/$/, '');
    if (new URLSearchParams(query).get('plugin')) throw new Error('плагины Shadowsocks не поддерживаются');
    let userinfo, hostport;
    const at = body.lastIndexOf('@');
    if (at >= 0) {
      userinfo = body.slice(0, at);
      hostport = body.slice(at + 1);
      userinfo = userinfo.includes(':') ? dec(userinfo) : b64decode(dec(userinfo));
    } else {
      const d = b64decode(body);
      const a = d.lastIndexOf('@');
      if (a < 0) throw new Error('ссылка ss повреждена');
      userinfo = d.slice(0, a);
      hostport = d.slice(a + 1);
    }
    const c = userinfo.indexOf(':');
    if (c < 0) throw new Error('в ссылке ss нет метода или пароля');
    const method = userinfo.slice(0, c).toLowerCase();
    const password = userinfo.slice(c + 1);
    if (!SS_METHODS.includes(method)) throw new Error('метод Shadowsocks «' + method + '» не поддерживается');
    const u = new URL('ss://x@' + hostport);
    return Object.assign({ type: 'ss', name, method, password }, hostPort(u));
  }

  function parseHy2(link) {
    const authority = link.replace(/^[a-z0-9]+:\/\//i, '').split(/[/?#]/)[0];
    if (/:\d+[-,]/.test(authority)) throw new Error('диапазоны портов Hysteria2 не поддерживаются');
    const u = new URL(link.replace(/^hysteria2:/, 'hy2:'));
    let auth = dec(u.username);
    if (u.password) auth += ':' + dec(u.password);
    if (!auth) throw new Error('нет пароля');
    const q = u.searchParams;
    const hp = hostPort(u);
    const obfs = q.get('obfs') || '';
    if (obfs && obfs !== 'salamander') throw new Error('обфускация «' + obfs + '» не поддерживается');
    return Object.assign({
      type: 'hysteria2', name: dec(u.hash.slice(1)), password: auth,
      sni: dec(q.get('sni') || '') || hp.server,
      insecure: truthy(q.get('insecure')),
      pinSHA256: (q.get('pinSHA256') || '').replace(/:/g, '').toLowerCase(),
      obfs, obfsPassword: dec(q.get('obfs-password') || ''),
      alpn: splitList(q.get('alpn')),
    }, hp);
  }

  function parseTuic(link) {
    const u = new URL(link);
    const uuid = dec(u.username), password = dec(u.password);
    if (!uuid || !password) throw new Error('в ссылке TUIC нет UUID или пароля');
    const q = u.searchParams, hp = hostPort(u);
    return Object.assign({
      type: 'tuic', name: dec(u.hash.slice(1)), uuid, password,
      sni: dec(q.get('sni') || '') || hp.server,
      alpn: splitList(q.get('alpn')).length ? splitList(q.get('alpn')) : ['h3'],
      congestion: q.get('congestion_control') || 'bbr',
      udpRelay: q.get('udp_relay_mode') || 'native',
      insecure: truthy(q.get('allow_insecure')) || truthy(q.get('insecure')),
    }, hp);
  }

  function wgAddr(v) {
    return splitList(v).map((a) => a.replace(/\/\d+$/, ''));
  }

  function parseWireguard(link) {
    const u = new URL(link.replace(/^wg:/, 'wireguard:'));
    const q = u.searchParams, hp = hostPort(u);
    const priv = dec(u.username);
    const pub = dec(q.get('publickey') || q.get('publicKey') || '');
    if (!priv || !pub) throw new Error('в ссылке WireGuard нет ключей');
    return Object.assign({
      type: 'wireguard', name: dec(u.hash.slice(1)), privateKey: priv, publicKey: pub,
      preSharedKey: dec(q.get('presharedkey') || ''), address: wgAddr(q.get('address') || q.get('ip') || ''),
      mtu: Number(q.get('mtu') || 1420), reserved: q.get('reserved') ? splitList(q.get('reserved')).map(Number) : null,
    }, hp);
  }

  // Конфиг wg-quick / AmneziaWG: [Interface] + [Peer]. Параметры Jc…H4 – обфускация AmneziaWG.
  function parseWgConf(text, name) {
    // Объекты без прототипа и только две известные секции: имя из конфига не должно задевать Object.prototype.
    const sec = { interface: Object.create(null), peer: Object.create(null) };
    let cur = null;
    text.split(/\r?\n/).forEach((line) => {
      const l = line.trim();
      const m = /^\[(\w+)\]$/.exec(l);
      if (m) { const n = m[1].toLowerCase(); cur = n === 'interface' || n === 'peer' ? n : null; return; }
      const kv = /^([A-Za-z0-9]+)\s*=\s*(.*)$/.exec(l);
      const key = kv && kv[1].toLowerCase();
      if (kv && cur && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') sec[cur][key] = kv[2].trim();
      const c = /^#\s*(.+)$/.exec(l);
      if (c && !name) name = c[1];
    });
    const i = sec.interface, p = sec.peer;
    if (!i.privatekey || !p.publickey || !p.endpoint) throw new Error('конфиг WireGuard неполный');
    const ep = /^\[?([^\]]+?)\]?:(\d+)$/.exec(p.endpoint);
    if (!ep) throw new Error('в конфиге WireGuard неверный Endpoint');
    const awgKeys = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5',
      'headerprotectionkey', 'contentpaddingaddition', 'rekeyaftertime', 'rejectaftertime', 'rekeytimeout', 'keepalivetimeout', 'maxhandshakeattempts', 'randomtrailers', 'disablecookies'];
    const awg = {};
    awgKeys.forEach((k) => { if (i[k] !== undefined && i[k] !== '') awg[k] = k !== 'headerprotectionkey' && /^\d+$/.test(i[k]) ? Number(i[k]) : i[k]; });
    // Ключ защиты заголовков клиенты ждут в base64; старые конфиги Kitsune отдавали его в hex (64 символа).
    if (typeof awg.headerprotectionkey === 'string' && /^[0-9a-fA-F]{64}$/.test(awg.headerprotectionkey)) {
      const hex = awg.headerprotectionkey;
      const bytes = Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
      awg.headerprotectionkey = typeof btoa === 'function' ? btoa(String.fromCharCode.apply(null, bytes)) : Buffer.from(bytes).toString('base64');
    }
    const isAwg = Object.keys(awg).length > 0;
    return {
      type: isAwg ? 'amneziawg' : 'wireguard', name: name || (isAwg ? 'amneziawg' : 'wireguard') + '-' + ep[1],
      server: ep[1], port: int(ep[2], 'порт'), privateKey: i.privatekey, publicKey: p.publickey,
      preSharedKey: p.presharedkey || '', address: wgAddr(i.address || ''), mtu: Number(i.mtu || 1420),
      dns: splitList(i.dns || ''), awg: isAwg ? awg : null, reserved: null,
    };
  }

  // Распаковка deflate (RFC 1951) на чистом JS: в браузере нет синхронного inflate, а разбор ссылок синхронный.
  function inflate(src, max) {
    const LB = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const LE = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const DB = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const DE = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    const out = [];
    let pos = 0, bit = 0, cnt = 0;
    const bits = (n) => {
      while (cnt < n) {
        if (pos >= src.length) throw new Error('конец данных');
        bit |= src[pos++] << cnt; cnt += 8;
      }
      const v = bit & ((1 << n) - 1);
      bit >>>= n; cnt -= n;
      return v;
    };
    // таблица Хаффмана: число кодов каждой длины и символы по порядку
    const build = (lens) => {
      const count = new Array(16).fill(0), syms = [];
      lens.forEach((l) => { count[l]++; });
      count[0] = 0;
      const offs = [0];
      for (let i = 1; i < 16; i++) offs[i] = offs[i - 1] + count[i - 1];
      lens.forEach((l, s) => { if (l) syms[offs[l]++] = s; });
      return { count, syms };
    };
    const decode = (h) => {
      let code = 0, first = 0, index = 0;
      for (let len = 1; len < 16; len++) {
        code |= bits(1);
        const c = h.count[len];
        if (code - c < first) return h.syms[index + (code - first)];
        index += c; first += c; first <<= 1; code <<= 1;
      }
      throw new Error('неверный код');
    };
    const codes = (lh, dh) => {
      for (;;) {
        let s = decode(lh);
        if (s < 256) out.push(s);
        else if (s === 256) return;
        else {
          if (s > 285) throw new Error('неверный код длины');
          s -= 257;
          const len = LB[s] + bits(LE[s]);
          const d = decode(dh);
          if (d > 29) throw new Error('неверный код расстояния');
          const dist = DB[d] + bits(DE[d]);
          if (dist > out.length) throw new Error('неверное расстояние');
          if (out.length + len > max) throw new Error('слишком большой объём');
          for (let i = 0; i < len; i++) out.push(out[out.length - dist]);
        }
        if (out.length > max) throw new Error('слишком большой объём');
      }
    };
    let last;
    do {
      last = bits(1);
      const type = bits(2);
      if (type === 0) {
        bit = 0; cnt = 0;
        if (pos + 4 > src.length) throw new Error('конец данных');
        const n = src[pos] | (src[pos + 1] << 8), nn = src[pos + 2] | (src[pos + 3] << 8);
        if ((n ^ 0xffff) !== nn) throw new Error('неверная длина блока');
        pos += 4;
        if (pos + n > src.length || out.length + n > max) throw new Error('неверная длина блока');
        for (let i = 0; i < n; i++) out.push(src[pos++]);
      } else if (type === 1) {
        const l = [];
        for (let i = 0; i < 288; i++) l.push(i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8);
        codes(build(l), build(new Array(30).fill(5)));
      } else if (type === 2) {
        const nl = bits(5) + 257, nd = bits(5) + 1, nc = bits(4) + 4;
        const ORD = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        const cl = new Array(19).fill(0);
        for (let i = 0; i < nc; i++) cl[ORD[i]] = bits(3);
        const ch = build(cl), lens = [];
        while (lens.length < nl + nd) {
          const s = decode(ch);
          if (s < 16) lens.push(s);
          else {
            let rep, v = 0;
            if (s === 16) { v = lens[lens.length - 1]; rep = 3 + bits(2); } else if (s === 17) rep = 3 + bits(3); else rep = 11 + bits(7);
            while (rep--) lens.push(v);
          }
        }
        codes(build(lens.slice(0, nl)), build(lens.slice(nl)));
      } else throw new Error('неверный блок');
    } while (!last);
    return Uint8Array.from(out);
  }

  // vpn:// приложения AmneziaVPN: base64url от qCompress (4 байта длины + zlib) с JSON; клиентский .conf лежит
  // в containers[0].<протокол>.last_config.config. Простой base64 с текстом .conf тоже понимаем.
  function parseVpn(link) {
    const body = link.slice('vpn://'.length).split('#')[0];
    if (body.length > 256 * 1024) throw new Error('ссылка vpn:// слишком большая');
    const name = dec(link.split('#')[1] || '');
    let text = '';
    try {
      let s = body.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
      while (s.length % 4) s += '=';
      const bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      if (bytes.length > 6 && (bytes[4] & 0x0f) === 8) {
        // первые 4 байта qCompress – длина распакованных данных; больше 1 МБ не берём
        const want = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
        if (want > 1024 * 1024) throw new Error('слишком большой объём');
        const raw = inflate(bytes.subarray(6, bytes.length - 4), want);
        if (raw.length !== want) throw new Error('длина не совпадает');
        const json = JSON.parse(new TextDecoder().decode(raw));
        const c = (json.containers || []).find((x) => x && (x.awg || x.wireguard));
        const blk = c && (c.awg || c.wireguard);
        const last = blk && JSON.parse(blk.last_config || '{}');
        text = (last && last.config) || '';
      } else {
        text = new TextDecoder().decode(bytes);
      }
    } catch (e) { throw /объём|большая/.test(e.message) ? e : new Error('ссылка vpn:// повреждена'); }
    if (!/\[Interface\]/.test(text)) throw new Error('формат vpn:// не поддерживается – нужен конфиг AmneziaWG');
    return parseWgConf(text, name);
  }

  function parseTg(link) {
    const u = new URL(link.replace(/^https:\/\/t\.me\/proxy/, 'tg://proxy'));
    const q = u.searchParams;
    if (!q.get('server') || !q.get('secret')) throw new Error('в ссылке MTProto нет сервера или секрета');
    return { type: 'mtproto', name: 'mtproto-' + q.get('server'), server: q.get('server'), port: int(q.get('port') || '443', 'порт'), secret: q.get('secret') };
  }

  const PARSERS = {
    'vless': parseVless, 'vmess': parseVmess, 'trojan': parseTrojan, 'ss': parseSs, 'hy2': parseHy2, 'hysteria2': parseHy2,
    'tuic': parseTuic, 'wireguard': parseWireguard, 'wg': parseWireguard, 'vpn': parseVpn, 'tg': parseTg,
  };

  function parseLink(line) {
    if (/^https:\/\/t\.me\/proxy\?/.test(line)) line = line.replace(/^https:\/\/t\.me\/proxy/, 'tg://proxy');
    const m = /^([a-z0-9]+):\/\//i.exec(line);
    if (!m) throw new Error('это не ссылка на подключение');
    const p = PARSERS[m[1].toLowerCase()];
    if (!p) throw new Error('протокол «' + m[1] + '» не поддерживается');
    const r = p(line);
    if (!r.name) r.name = r.type + '-' + r.server;
    return r;
  }

  // Разбирает текст: ссылки по одной на строку или base64-подписку целиком.
  function parseText(text) {
    let t = (text || '').trim();
    if (t && !/:\/\//.test(t) && looksBase64(t)) {
      try { t = b64decode(t); } catch (e) { /* не base64 – разберём как есть */ }
    }
    const ok = [];
    const errors = [];
    t.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')).forEach((line, i) => {
      try {
        ok.push(parseLink(line));
      } catch (e) {
        errors.push({ line: i + 1, text: line.length > 60 ? line.slice(0, 57) + '…' : line, error: e.message });
      }
    });
    // Уникальные имена – клиенты требуют.
    const seen = {};
    ok.forEach((p) => {
      const base = p.name;
      let n = base, k = 2;
      while (seen[n]) n = base + ' ' + k++;
      seen[n] = true;
      p.name = n;
    });
    return { proxies: ok, errors };
  }

  const api = { parseLink, parseText, parseWgConf, b64decode };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PM = Object.assign(root.PM || {}, api);
})(typeof window !== 'undefined' ? window : globalThis);
