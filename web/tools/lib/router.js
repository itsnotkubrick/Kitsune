// Роутеры и команды для SSH: куда положить готовые файлы и как перезапустить прокси.
(function (root) {
  'use strict';

  // Что умеет каждый роутер: на Keenetic работает XKeen (Xray или Mihomo), на OpenWrt – Nikki (только Mihomo).
  const ROUTERS = {
    keenetic: { label: 'Keenetic', hint: 'через XKeen', cores: ['xray', 'mihomo'], ssh: 'ssh root@192.168.x.x -p 222' },
    openwrt: { label: 'OpenWrt', hint: 'через Nikki, только Mihomo (бета)', cores: ['mihomo'], ssh: 'ssh root@192.168.x.x' },
  };
  const CORES = {
    xray: { label: 'Xray', hint: '04_outbounds.json и 05_routing.json' },
    mihomo: { label: 'Mihomo', hint: 'config.yaml: автовыбор сервера, Hysteria2, TUIC, AmneziaWG, веб-панель' },
  };
  const NIKKI_PROFILE = 'kitsune.yaml';
  const NIKKI_DIR = '/etc/nikki/profiles';

  // Файл целиком через heredoc: если метка встретилась внутри файла, удлиняем её.
  function heredoc(path, body) {
    let tag = 'PMEOF';
    while (body.includes(tag)) tag += 'X';
    return 'cat > ' + path + " <<'" + tag + "'\n" + body.replace(/\n?$/, '\n') + tag;
  }

  // Mihomo на Keenetic: конфиг никогда не пишется поверх рабочего вслепую. Порядок: копия старого файла (права 600) ->
  // запись в config.yaml.new -> проверка mihomo -t -> только при успехе mv и перезапуск. Если проверка не прошла, рабочий файл
  // не тронут. Команду вставляют в интерактивный SSH, поэтому exit не используется (он закрыл бы сессию).
  // dns: ведёт XKeen UI, генератор его не пишет. Если на роутере уже есть блок dns: верхнего уровня, он дословно переносится из
  // прежнего файла в новый (от строки dns: до следующей строки верхнего уровня). Если блок есть, а перенести его не удалось,
  // рабочий файл не заменяется. Без галочки не переносится.
  function keeneticMihomo(files, options) {
    const keepDns = !options || options.keepDns !== false;
    const dir = '/opt/etc/mihomo';
    return [
      '# Keenetic: вставьте целиком в SSH-консоль роутера (Entware)',
      '# xkeen -mihomo   – раскомментируйте, если сейчас работает другое ядро',
      '# Откат: cp ' + dir + '/config.yaml.bak-<метка> ' + dir + '/config.yaml && xkeen -restart',
      '# Копии содержат secret и ссылку на подписку: храните с правами 600, старые удаляйте (ls ' + dir + '/config.yaml.bak-*)',
      // Entware: при запуске файлом по ssh без входа в оболочку каталоги /opt/bin и /opt/sbin могут не быть в PATH
      'PATH=/opt/bin:/opt/sbin:$PATH; export PATH',
      'umask 077',
      'mkdir -p ' + dir,
      'PM_CF=' + dir + '/config.yaml',
      'PM_TS=$(date +%Y%m%d-%H%M%S)',
      '[ -f "$PM_CF" ] && cp -a "$PM_CF" "$PM_CF.bak-$PM_TS" && chmod 600 "$PM_CF.bak-$PM_TS" && echo "Копия старого конфига: $PM_CF.bak-$PM_TS"',
      heredoc('"$PM_CF.new"', files['config.yaml']),
    ].concat(keepDns ? [
      // Без awk и sed: на части роутеров их нет в BusyBox. Читаем старый файл построчно: от строки dns: до следующей строки верхнего уровня.
      'PM_DNS_OK=1',
      'if [ -f "$PM_CF" ]; then',
      '  PM_IN=0; PM_TAB=$(printf \'\\t\')',
      '  while IFS= read -r PM_L || [ -n "$PM_L" ]; do',
      '    PM_C=${PM_L%"${PM_L#?}"}',
      '    case "$PM_L" in dns:*) PM_IN=1;; *) case "$PM_C" in ""|" "|"$PM_TAB"|"#") ;; *) PM_IN=0;; esac;; esac',
      '    [ "$PM_IN" = 1 ] && printf \'%s\\n\' "$PM_L"',
      '  done < "$PM_CF" > "$PM_CF.dns"',
      '  grep -q \'^dns:\' "$PM_CF" && [ ! -s "$PM_CF.dns" ] && PM_DNS_OK=0',
      'fi',
      '[ -s "$PM_CF.dns" ] && { printf \'\\n# dns: перенесён из прежнего файла (ведётся в XKeen UI)\\n\'; cat "$PM_CF.dns"; } >> "$PM_CF.new" && echo "Блок dns: перенесён из прежнего файла"',
      'rm -f "$PM_CF.dns"',
    ] : ['PM_DNS_OK=1']).concat([
      'if command -v mihomo >/dev/null 2>&1; then PM_OUT=$(mihomo -d ' + dir + ' -t -f "$PM_CF.new" 2>&1); PM_OK=$?; else PM_OUT="mihomo не найден в PATH, проверить конфиг нельзя. Новый файл лежит рядом: $PM_CF.new"; PM_OK=127; fi',
      'if [ "$PM_DNS_OK" = 0 ]; then',
      '  echo "Блок dns: не удалось перенести из прежнего файла, рабочий файл не тронут. Новый лежит рядом: $PM_CF.new"',
      'elif [ "$PM_OK" = 0 ]; then',
      '  [ -n "$PM_OUT" ] && echo "$PM_OUT"',
      '  mv "$PM_CF.new" "$PM_CF" && chmod 600 "$PM_CF" && xkeen -restart',
      'else',
      '  echo "Конфиг не прошёл проверку, рабочий файл не тронут. Новый лежит рядом: $PM_CF.new"',
      '  echo "$PM_OUT"',
      'fi',
      'unset PM_CF PM_TS PM_OUT PM_OK PM_DNS_OK PM_IN PM_TAB PM_L PM_C',
    ]).join('\n') + '\n';
  }

  function command(router, core, files, options) {
    if (!ROUTERS[router] || !ROUTERS[router].cores.includes(core)) throw new Error('Это сочетание роутера и ядра не поддерживается');
    const names = Object.keys(files);
    if (router === 'openwrt') {
      const parts = ['# OpenWrt: вставьте целиком в SSH-консоль роутера (нужен установленный Nikki)', 'mkdir -p ' + NIKKI_DIR];
      parts.push(heredoc(NIKKI_DIR + '/' + NIKKI_PROFILE, files['config.yaml']));
      parts.push("uci set nikki.config.profile='file:" + NIKKI_PROFILE + "'", "uci set nikki.config.enabled='1'", 'uci commit nikki', '/etc/init.d/nikki restart');
      return parts.join('\n') + '\n';
    }
    if (core === 'mihomo') return keeneticMihomo(files, options);
    const dir = '/opt/etc/xray/configs';
    const parts = ['# Keenetic: вставьте целиком в SSH-консоль роутера (Entware)',
      '# xkeen -' + core + '   – раскомментируйте, если сейчас работает другое ядро', 'mkdir -p ' + dir];
    names.forEach((n) => parts.push(heredoc(dir + '/' + n, files[n])));
    parts.push('xkeen -restart');
    return parts.join('\n') + '\n';
  }

  // Подписи для шага «Команда для роутера».
  function describe(router, core) {
    if (router === 'openwrt') return 'Запишет профиль в Nikki, включит его и перезапустит Nikki.';
    if (core === 'mihomo') return 'Сохранит копию текущего конфига, проверит новый через mihomo -t и только тогда заменит файл и перезапустит XKeen.';
    return 'Запишет файлы и перезапустит XKeen.';
  }

  const api = { ROUTERS, CORES, NIKKI_PROFILE, NIKKI_DIR, routerCommand: command, routerDescribe: describe };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.PM = Object.assign(root.PM || {}, api);
})(typeof window !== 'undefined' ? window : globalThis);
