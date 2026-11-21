// Проверка доступности адресов наборов из каталога генератора mihomo (по сети, вручную: перед релизом, аналитик).
// Запуск: node tools/check-catalog-urls.js. Ничего не скачивает целиком: запрос HEAD, код ответа и источник; не 200 – код выхода 1.
const path = require('node:path');
const { MIHOMO_CATALOG } = require(path.join(__dirname, '..', 'web', 'tools', 'lib', 'mihomo-catalog.js'));

(async () => {
  // Наборы обеих схем (sets и xkeen.sets) и реклама схемы XKeen
  const ads = { name: 'ads@domain', url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs', source: 'MetaCubeX' };
  const all = MIHOMO_CATALOG.flatMap((s) => s.sets.concat((s.xkeen && s.xkeen.sets) || [])).concat([ads]);
  const urls = [...new Map(all.map((x) => [x.url, x])).values()];
  let bad = 0;
  for (const x of urls) {
    let code = 'ошибка';
    try { code = (await fetch(x.url, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(20000) })).status; } catch (e) { /* сеть */ }
    if (code !== 200) { bad++; console.log(code, x.source, x.name, x.url); }
  }
  console.log(`проверено ${urls.length}, не отвечают 200: ${bad}`);
  process.exit(bad ? 1 : 0);
})();
