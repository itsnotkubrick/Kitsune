// Каталог сервисов для генератора mihomo: данные, а не код. Запись описывает сервис, его наборы правил и, отдельно, как он выглядит
// в схеме групп «как в шаблоне XKeen» (поле xkeen: ярус, порядок proxies в группе, exclude-filter; шаблон zxc-rv от 22.10.2026).
// Поле onlyIn: 'xkeen' – сервис есть только в схеме XKeen. Поле source: откуда набор (metacubex, zxc-rv, legiz-ru): для проверки доступности
// и учёта сторонних источников. Формат: литерал, совместимый с JSON по структуре; подключается скриптом, запросов по сети страница не делает.
(function (root) {
  'use strict';

  const CATALOG = [
  {
    id: "blocked",
    label: "Сайты из списка re:filter",
    hint: "список re:filter – основные сайты",
    group: "Re:filter",
    tier: "refilter",
    on: true,
    sets: [
      { name: "refilter@domain", url: "https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/domain-rule.mrs", behavior: "domain", source: "legiz-ru" },
      { name: "refilter@ipcidr", url: "https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/ip-rule.mrs", behavior: "ipcidr", source: "legiz-ru" },
    ],
    xkeen: {
      group: null,
      tier: "refilter",
      order: null,
      on: true,
    },
  },
  {
    id: "youtube",
    label: "YouTube",
    tier: "service",
    on: true,
    sets: [
      { name: "youtube@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
    },
  },
  {
    id: "telegram",
    label: "Telegram",
    tier: "service",
    on: true,
    sets: [
      { name: "telegram@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs", behavior: "domain", source: "metacubex" },
      { name: "telegram@ipcidr", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs", behavior: "ipcidr", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
      sets: [
        { name: "telegram@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs", behavior: "domain", source: "metacubex" },
        { name: "telegram@ipcidr", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs", behavior: "ipcidr", source: "metacubex" },
      ],
    },
    portHint: "telegram",
  },
  {
    id: "meta",
    label: "Instagram, Facebook, WhatsApp",
    group: "Meta",
    tier: "service",
    on: true,
    sets: [
      { name: "meta@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/meta.mrs", behavior: "domain", source: "metacubex" },
      { name: "facebook@ipcidr", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/facebook.mrs", behavior: "ipcidr", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
      sets: [
        { name: "meta@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/meta.mrs", behavior: "domain", source: "metacubex" },
        { name: "meta@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/meta@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      ],
    },
  },
  {
    id: "twitter",
    label: "X (Twitter)",
    group: "X",
    tier: "service",
    on: true,
    sets: [
      { name: "twitter@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs", behavior: "domain", source: "metacubex" },
      { name: "twitter@ipcidr", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/twitter.mrs", behavior: "ipcidr", source: "metacubex" },
    ],
    xkeen: {
      group: "Twitter",
      tier: "service",
      order: "proxy-first",
      on: true,
      sets: [
        { name: "twitter@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs", behavior: "domain", source: "metacubex" },
      ],
    },
  },
  {
    id: "discord",
    label: "Discord",
    tier: "service",
    on: true,
    sets: [
      { name: "discord@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
    },
    portHint: "discord",
  },
  {
    id: "ai",
    label: "ChatGPT, Claude и другие ИИ",
    group: "ИИ",
    tier: "service",
    on: true,
    sets: [
      { name: "ai@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      group: "AI",
      tier: "service",
      order: "proxy-first",
      excludeFilter: "🇷🇺",
      on: true,
      sets: [
        { name: "category-ai@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs", behavior: "domain", source: "metacubex" },
      ],
    },
  },
  {
    id: "tiktok",
    label: "TikTok",
    tier: "service",
    on: false,
    sets: [
      { name: "tiktok@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
    },
  },
  {
    id: "spotify",
    label: "Spotify",
    tier: "service",
    on: false,
    sets: [
      { name: "spotify@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      excludeFilter: "🇷🇺",
      on: true,
    },
  },
  {
    id: "netflix",
    label: "Netflix",
    tier: "service",
    on: false,
    sets: [
      { name: "netflix@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs", behavior: "domain", source: "metacubex" },
      { name: "netflix@ipcidr", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/netflix.mrs", behavior: "ipcidr", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: false,
    },
  },
  {
    id: "github",
    label: "GitHub",
    tier: "service",
    on: false,
    sets: [
      { name: "github@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "google-github",
      order: "pass-last",
      on: true,
    },
  },
  {
    id: "twitch",
    label: "Twitch",
    tier: "service",
    on: false,
    sets: [
      { name: "twitch@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitch.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "direct-first",
      on: true,
    },
  },
  {
    id: "reddit",
    label: "Reddit",
    tier: "service",
    on: false,
    sets: [
      { name: "reddit@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/reddit.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "direct-first",
      on: true,
    },
  },
  {
    id: "steam",
    label: "Steam",
    tier: "service",
    on: false,
    sets: [
      { name: "steam@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "direct-first",
      on: true,
    },
  },
  {
    id: "speedtest",
    label: "Speedtest",
    tier: "service",
    on: false,
    sets: [
      { name: "speedtest@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/speedtest.mrs", behavior: "domain", source: "metacubex" },
    ],
    xkeen: {
      tier: "service",
      order: "proxy-first",
      on: true,
    },
    portHint: "speedtest",
  },
  {
    id: "google",
    label: "Google",
    tier: "service",
    on: false,
    onlyIn: "xkeen",
    sets: [
      { name: "google@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs", behavior: "domain", source: "metacubex" },
      { name: "google@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/google@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
    ],
    xkeen: {
      tier: "google-github",
      order: "pass-last",
      on: true,
    },
  },
  {
    id: "cdn",
    label: "CDN-списки",
    hint: "Cloudflare, Fastly, Amazon, Akamai и другие: сайты на этих сетях",
    tier: "service",
    on: false,
    onlyIn: "xkeen",
    sets: [
      { name: "amazon@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/amazon.mrs", behavior: "domain", source: "metacubex" },
      { name: "amazon@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/amazon@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "akamai@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/akamai.mrs", behavior: "domain", source: "metacubex" },
      { name: "akamai@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/akamai@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "cloudflare@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cloudflare.mrs", behavior: "domain", source: "metacubex" },
      { name: "cloudflare@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/cloudflare@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "digitalocean@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/digitalocean.mrs", behavior: "domain", source: "metacubex" },
      { name: "digitalocean@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/digitalocean@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "fastly@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/fastly.mrs", behavior: "domain", source: "metacubex" },
      { name: "fastly@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/fastly@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "oracle@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/oracle.mrs", behavior: "domain", source: "metacubex" },
      { name: "oracle@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/oracle@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "hetzner@domain", url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hetzner.mrs", behavior: "domain", source: "metacubex" },
      { name: "hetzner@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/hetzner@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "scaleway@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/scaleway@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "ovh@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/ovh@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "vultr@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/vultr@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "vodafone@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/vodafone@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "gcore@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/gcore@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
      { name: "cdn77@ipcidr", url: "https://github.com/zxc-rv/zkeenip-rulesets/releases/latest/download/cdn77@ipcidr.mrs", behavior: "ipcidr", source: "zxc-rv" },
    ],
    xkeen: {
      tier: "cdn",
      order: "pass-last",
      on: true,
      group: "CDN",
    },
  },
  ];

  if (typeof module === 'object' && module.exports) module.exports = { MIHOMO_CATALOG: CATALOG };
  root.PM = Object.assign(root.PM || {}, { MIHOMO_CATALOG: CATALOG });
})(typeof window !== 'undefined' ? window : globalThis);
