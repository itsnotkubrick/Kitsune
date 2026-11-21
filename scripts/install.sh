#!/usr/bin/env bash
# Kitsune installer for Linux (systemd).
#
#   bash <(curl -fsSL <release-url>/install.sh)          – one-command install (the binary is downloaded for you)
#   sudo bash install.sh install   --binary ./kitsune-linux-amd64 [--domain vpn.example.com] [--port 8080]
#   sudo bash install.sh update    --binary ./kitsune-linux-amd64
#   sudo bash install.sh status
#   sudo bash install.sh uninstall [--keep-data] [--yes]    (removes everything by default)
#
# Default: GitHub Latest Release with signed SHA256SUMS. KITSUNE_BASE_URL or --base-url sets a mirror.
# Manual options: --binary file (scp) or --url together with --sha256 (without a hash it will not install).
# Cores (Xray, sing-box, mtg, mita) are downloaded during the install and checked by SHA-256:
# pick the set with --cores xray,singbox, turn off with --no-cores.
# Panel HTTPS: --domain vpn.example.com [--email you@mail] – a trusted Let's Encrypt certificate
# (the domain's A record must point to this server, port 80 free); without a domain – a self-signed certificate
# (encrypted, but the browser warns). Choice: --cert domain|ip (asks if omitted). Turn off: --no-https.
# Connections: --protocols reality,xhttp,ws,trojan,vmess,ss,hy2,tuic,mtproto,awg,awg3,naive,mieru | all (all 13) | none,
# --sni auto|site.com (REALITY masking), --user name of the first user, --host address used in links.
# With no options the installer asks; the default answer is the recommended set: REALITY with Vision plus XHTTP on a second site name.
# Without a terminal (or with --yes) nothing is created unless --protocols is given (the panel stays empty).
# BBR (faster TCP): --bbr turns it on without asking, --no-bbr leaves it alone; the flags work before or after the command.
# Other: --yes (no questions), --dir /opt/kitsune, --dry-run (only show the steps).
# Check without root and systemd: KITSUNE_ROOT=/tmp/x KITSUNE_NO_SYSTEMD=1.

# Running through sh (dash) breaks with a confusing syntax error – so we hint right away.
[ -n "${BASH_VERSION:-}" ] || { echo "Run it with bash, not sh:  bash install.sh …" >&2; exit 1; }

set -Eeuo pipefail

DIR=/opt/kitsune
PORT=8080; PORT_SET=0
BIN_SRC=""; URL=""; SHA=""
# Resolve GitHub Latest once per operation; explicit mirrors keep their original layout.
DEFAULT_BASE_URL="https://github.com/itsnotkubrick/Kitsune/releases/latest/download"
RELEASE_API="https://api.github.com/repos/itsnotkubrick/Kitsune/releases/latest"
# Public key for verifying the signed release checksums.
RELEASE_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINhjplaosSN+PdupdxtPp2cO0fHtFta9PMzdSH8F4oZm"
BASE_URL=${KITSUNE_BASE_URL:-}
BASE_URL=${BASE_URL%/}
TOKEN_FILE=/etc/kitsune/github-token
TOKEN=${KITSUNE_TOKEN:-}
RELEASE_ASSETS=
RELEASE_TAG=
github_release_get() {
  local accept=$1 url=$2
  shift 2
  if [[ -n $TOKEN ]]; then
    curl -fsSL --proto '=https' --header "Accept: $accept" \
      --header @<(printf 'Authorization: Bearer %s\n' "$TOKEN") "$url" "$@"
  else
    curl -fsSL --proto '=https' --header "Accept: $accept" "$url" "$@"
  fi
}
resolve_release() {
  [[ -z $BASE_URL && -z $RELEASE_ASSETS ]] || return 0
  command -v python3 >/dev/null || die "Python 3 is required to read GitHub release metadata."
  if [[ -z $TOKEN && -r $TOKEN_FILE ]]; then TOKEN=$(<"$TOKEN_FILE"); fi
  [[ $TOKEN != *$'\n'* && $TOKEN != *$'\r'* ]] || die "Invalid GitHub token file."
  local metadata
  metadata=$(github_release_get application/vnd.github+json "$RELEASE_API") ||
    die "Cannot read the latest Kitsune release. Private repositories need a read-only GitHub token in $TOKEN_FILE."
  RELEASE_ASSETS=$(python3 -c '
import json, re, sys
release = json.load(sys.stdin)
tag = release.get("tag_name", "")
if release.get("draft") or release.get("prerelease") or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", tag):
    sys.exit("Expected a published stable release")
print(tag)
for asset in release["assets"]:
    if isinstance(asset.get("id"), int):
        print(asset["id"], asset["name"])
' <<<"$metadata") || die "Invalid release metadata."
  RELEASE_TAG=${RELEASE_ASSETS%%$'\n'*}
}
release_asset() {
  local name=$1
  shift
  if [[ -n $BASE_URL ]]; then
    curl -fsSL "$BASE_URL/$name" "$@"
  else
    local id
    id=$(awk -v n="$name" '$2 == n {print $1}' <<<"$RELEASE_ASSETS")
    [[ $id =~ ^[0-9]+$ ]] || return 1
    if [[ -n $TOKEN ]]; then
      github_release_get application/octet-stream "https://api.github.com/repos/itsnotkubrick/Kitsune/releases/assets/$id" "$@"
    else
      curl -fsSL --proto '=https' "https://github.com/itsnotkubrick/Kitsune/releases/download/$RELEASE_TAG/$name" "$@"
    fi
  fi
}

PURGE=0; KEEP_DATA=0; CORES=""; NO_CORES=0
DOMAIN=""; EMAIL=""; NO_TLS=0; CERT_FOR=""; BBR=ask
PANEL_PATH=""; CONN_PORTS=""; KEPT_DATA=0; SELF_DOMAIN=""; SNI_TARGET=""; PROTOCOLS=""; SNI="auto"; FIRST_USER=""; LINK_HOST=""; SUB_ID=""; CREDS=""
TMP=""; LAST_SUMS=""; YES=0; DRY=0
LANGSEL=${KITSUNE_LANG:-}; LANG_ASKED=0; [[ -n $LANGSEL ]] && LANG_ASKED=1   # interface language: ru or en (asked first; --lang or KITSUNE_LANG skips the question)
SVC=kitsune
ROOT=${KITSUNE_ROOT:-}
NO_SYSTEMD=${KITSUNE_NO_SYSTEMD:-0}
RESULT_FILE=/root/kitsune-install.txt
LOG_FILE=/var/log/kitsune-install.log
WARNINGS=()
STEP=0; TOTAL=9

# Output also goes to a log through tee, after which stdout is no longer a terminal: remember it beforehand.
IS_TTY=0; [[ -t 1 ]] && IS_TTY=1
# Kitsune's signature orange; in terminals without truecolor use the nearest of 256 colours. Colours only in a terminal (or KITSUNE_COLOR=1).
if [[ -t 1 || ${KITSUNE_COLOR:-0} == 1 ]] && [[ -z ${NO_COLOR:-} ]]; then
  if [[ ${COLORTERM:-} == truecolor || ${COLORTERM:-} == 24bit ]]; then O=$'\e[38;2;255;122;61m'; else O=$'\e[38;5;208m'; fi
  G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  O=; G=; Y=; R=; B=; D=; N=
fi
step()  { STEP=$((STEP+1)); printf '\n%s\n' "${O}${B}[$STEP/$TOTAL]${N} ${B}$*${N}"; }
note()  { printf '      %s\n' "${D}$*${N}"; }
q()     { printf '      %s\n' "${B}$*${N}"; }                                   # question: white, bold
opt()   { printf '        %s\n' "$1 $2${3:+  ${D}$3${N}}"; }                       # option: white, explanation grey
cont()  { printf '           %s\n' "${D}$*${N}"; }                                # explanation continued
say()   { printf '%s\n' "$*"; }
ok()    { printf '      %s\n' "${G}✓${N} $*"; }
warn()  { printf '%s\n' "${O}!${N}  $*" >&2; }
later() { WARNINGS+=("$*"); }                       # goes into the "Attention" block at the end of the install
die()   { printf '%s\n' "${R}✗${N}  $*" >&2; exit 1; }
run()   { if [[ $DRY == 1 ]]; then say "      (dry-run) $*"; else "$@"; fi; }
trap 'die "Error on line $LINENO. Fix the cause and run the script again (repeating is safe)."' ERR

# On a fresh VPS automatic updates run in the background and hold the dpkg lock: wait for it instead of failing.
apt-get() { command apt-get -o DPkg::Lock::Timeout=900 "$@"; }
wait_apt_idle() {
  local i
  pgrep -f '/usr/bin/unattended-upgrade$|apt\.systemd\.daily' >/dev/null 2>&1 || return 0
  note "the system is installing updates by itself – waiting for it to finish (up to 15 minutes)"
  for i in $(seq 1 180); do
    pgrep -f '/usr/bin/unattended-upgrade$|apt\.systemd\.daily' >/dev/null 2>&1 || return 0
    sleep 5
  done
}

# Valueless flags are allowed before the command too: install.sh --bbr install
pre=()
while [[ ${1-} == --bbr || ${1-} == --no-bbr || ${1-} == -y || ${1-} == --yes || ${1-} == --dry-run ]]; do pre+=("$1"); shift; done
cmd=${1:-}
[[ -n $cmd ]] && shift || true
case $cmd in -h|--help|help) ;; -*) die "Unknown option: $cmd (see --help)" ;; esac
set -- ${pre[@]+"${pre[@]}"} "$@"
# --port=8443 is understood the same as --port 8443
args=()
for a in "$@"; do
  if [[ $a == --*=* ]]; then args+=("${a%%=*}" "${a#*=}"); else args+=("$a"); fi
done
set -- ${args[@]+"${args[@]}"}
while [[ $# -gt 0 ]]; do
  case $1 in
    --binary|--url|--sha256|--dir|--port|--cores|--domain|--cert|--base-url|--protocols|--sni|--selfsteal|--user|--host)
      [[ -n ${2-} ]] || die "Option $1 has no value (see --help)" ;;
  esac
  case $1 in
    --binary)   BIN_SRC=$2; shift 2 ;;
    --url)      URL=$2; shift 2 ;;
    --base-url) BASE_URL=${2%/}; shift 2 ;;
    --sha256)   SHA=$2; shift 2 ;;
    --dir)      DIR=$2; shift 2 ;;
    --port)     PORT=$2; PORT_SET=1; shift 2 ;;
    --cores)    CORES=$2; shift 2 ;;
    --no-cores) NO_CORES=1; shift ;;
    --domain)   DOMAIN=$2; shift 2 ;;
    --cert)     CERT_FOR=$2; shift 2 ;;
    --protocols) PROTOCOLS=$2; shift 2 ;;
    --sni)      SNI=$2; shift 2 ;;
    --selfsteal) SELF_DOMAIN=$2; shift 2 ;;
    --user)     FIRST_USER=$2; shift 2 ;;
    --host)     LINK_HOST=$2; shift 2 ;;
    --email)    EMAIL=${2:-}; shift 2 ;;
    --no-https) NO_TLS=1; shift ;;
    --bbr)      BBR=yes; shift ;;
    --no-bbr)   BBR=no; shift ;;
    --purge)    PURGE=1; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    --lang)     LANGSEL=$2; LANG_ASKED=1; shift 2 ;;
    -y|--yes)   YES=1; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done

[[ -z $LANGSEL || $LANGSEL == ru || $LANGSEL == en ]] || die "--lang: ru or en"

UNIT="$ROOT/etc/systemd/system/$SVC.service"
TARGET="$ROOT$DIR"

# Case and a trailing dot do not matter: vpn.Example.com. is vpn.example.com.
if [[ -n $DOMAIN ]]; then
  DOMAIN=$(printf %s "$DOMAIN" | tr 'A-Z' 'a-z'); DOMAIN=${DOMAIN%.}
  [[ $DOMAIN != *://* && $DOMAIN != */* ]] || die "Give just the name, without https:// and «/»: for example vpn.example.com"
  [[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$ ]] \
    || die "--domain: use a domain name in Latin letters (for non-Latin names – punycode xn--…), for example vpn.example.com"
fi
[[ -z $CERT_FOR || $CERT_FOR == domain || $CERT_FOR == ip || $CERT_FOR == self ]] || die "--cert: domain (Let's Encrypt for a domain), ip (for an IP address) or self (self-signed)"
[[ $CERT_FOR != ip || -z $DOMAIN ]] || die "--cert ip and --domain together make no sense: pick one"
[[ $PORT =~ ^[0-9]{1,5}$ ]] && ((10#$PORT > 0 && 10#$PORT < 65536)) || die "Invalid port: $PORT"
PORT=$((10#$PORT))
[[ -z $EMAIL || $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "--email: looks like a typo: $EMAIL"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
need_root() { [[ -n $ROOT || $EUID -eq 0 || $DRY == 1 ]] || die "Run as root: sudo -i, then the command again."; }
# The port is taken by someone other than Kitsune itself (the panel holds port 80 to renew its domains' certificates).
port_busy_other() { command -v ss >/dev/null && ss -H -ltnp "sport = :$1" 2>/dev/null | grep -v '"kitsune"' | grep -q .; }
port_busy() { command -v ss >/dev/null && ss -H -ltn "sport = :$1" 2>/dev/null | grep -q .; }

# External address: several sources, then the default route.
public_ip() {
  local ip u
  for u in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
    ip=$(curl -4 -fsS -m 6 "$u" 2>/dev/null | tr -d '[:space:]' || true)
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
  done
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' || true
  return 0
}

# A records of a domain. Public DNS first (DoH): the server's local resolver may have cached "no record".
dns_a() {
  local r
  r=$(curl -fsS -m 6 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$1&type=A" 2>/dev/null \
      | grep -oE '"data":"[0-9]{1,3}(\.[0-9]{1,3}){3}"' | cut -d'"' -f4 | sort -u || true)
  [[ -n $r ]] || r=$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true)
  printf '%s' "$r"
}

# Read the answer from the terminal, not from stdin: works when started through curl | bash.
# Before a question, drop keystrokes typed ahead (an extra Enter etc.): otherwise they would become the "default answer".
ask_tty() {
  local junk
  REPLY=""
  while read -r -t 0.05 -n 1000 junk </dev/tty 2>/dev/null; do :; done
  read -r -p "$1" REPLY </dev/tty || { REPLY=""; return 1; }
}
have_tty() { [[ $YES == 0 && $IS_TTY == 1 ]] && { : </dev/tty; } 2>/dev/null; }

# Interface language. Russian if the system locale is Russian, otherwise English; the user is asked first and can change it.
locale_lang() {
  local v
  for v in "${LC_ALL:-}" "${LC_MESSAGES:-}" "${LANG:-}"; do
    [[ -n $v ]] && { [[ $v == [rR][uU]* ]] && echo ru || echo en; return; }
  done
  echo en
}
# T "English" "Русский": text in the chosen language
T() { if [[ ${LANGSEL:-$(locale_lang)} == ru ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
pick_language() {
  [[ -n $LANGSEL ]] && { export KIT_LANG=$LANGSEL; return 0; }
  local def; def=$(locale_lang)
  LANGSEL=$def
  if have_tty; then
    say ""
    say "  ${B}Language / Язык${N}"
    opt "1)" "English" ""
    opt "2)" "Русский" ""
    ask_tty "      [$([[ $def == ru ]] && echo 2 || echo 1)]: " || REPLY=""
    case ${REPLY//[[:space:]]/} in 1|en|EN) LANGSEL=en; LANG_ASKED=1 ;; 2|ru|RU|р|рус) LANGSEL=ru; LANG_ASKED=1 ;; esac
  fi
  export KIT_LANG=$LANGSEL
}
# The chosen language becomes the default of the kit command (an automatic choice stays "auto": kit follows the system language).
persist_language() {
  [[ $DRY == 1 ]] && return 0
  (cd "$TARGET" && ./kitsune cli lang "$([[ $LANG_ASKED == 1 ]] && echo "$LANGSEL" || echo auto)" >/dev/null 2>&1) || true
}

ssh_ports() {
  { sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
    ss -H -ltnp 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print a[n]}'
    awk '{print $4}' <<<"${SSH_CONNECTION:-}"
  } | grep -E '^[0-9]{1,5}$' | sort -un || true
}

check_os() {
  [[ -n $ROOT || $(uname -s) == Linux ]] || die "The installer works on Linux only."
  if [[ $NO_SYSTEMD != 1 ]]; then command -v systemctl >/dev/null || die "systemd is required."; fi
  case $(uname -m) in x86_64|amd64|aarch64|arm64) ;; *) die "Architecture $(uname -m) is not supported." ;; esac
}

# A random free port for the panel (like 3x-ui does when you do not pick one yourself).
random_free_port() {
  local p i
  for i in $(seq 1 60); do
    p=$((20000 + RANDOM % 40000))
    [[ $p != "$PORT" ]] && ! port_busy "$p" && { echo "$p"; return; }
  done
  echo $((20000 + RANDOM % 40000))
}

# Panel port: random unless --port is given explicitly (no question: a random port is harder to find by scanning, the address is shown at the end).
choose_panel_port() {
  if [[ $PORT_SET == 1 ]]; then check_port; ok "$(T "panel port: $PORT" "порт панели: $PORT")"; return 0; fi
  PORT=$(random_free_port)
  ok "$(T "panel port: $PORT (random; change later: kit port NUMBER)" "порт панели: $PORT (случайный; сменить потом: kit port НОМЕР)")"
}

# update/status/uninstall: the port is whatever the installed service listens on (it may be random).
detect_port() {
  [[ $PORT_SET == 1 || ! -f $UNIT ]] && return 0
  local p; p=$(sed -n 's/^Environment=KITSUNE_ADDR=:\([0-9]\{1,5\}\)$/\1/p' "$UNIT" | head -n 1)
  [[ -n $p ]] && PORT=$p
  return 0
}

check_port() {
  while port_busy "$PORT"; do
    local who; who=$(ss -ltnp "sport = :$PORT" 2>/dev/null | awk 'NR>1 {print $NF}' | head -n 1)
    warn "$(T "Port $PORT/tcp is already in use${who:+ ($who)}." "Порт $PORT/tcp уже занят${who:+ ($who)}.")"
    have_tty || die "$(T "Choose another port for the panel: --port 9000 (or free up $PORT)." "Выберите другой порт для панели: --port 9000 (или освободите $PORT).")"
    q "$(T "What shall we do?" "Что делаем?")"
    opt "1)" "$(T "Another port for the panel" "Другой порт для панели")" "$(T "– enter a number, for example 9000" "– введите число, например 9000")"
    opt "2)" "$(T "Exit" "Выйти")" "$(T "– free up port $PORT and run the install again" "– освободите порт $PORT и запустите установку снова")"
    ask_tty "      $(T "Port number (Enter – exit): " "Номер порта (Enter – выйти): ")" || REPLY=""
    REPLY=${REPLY//[[:space:]]/}
    [[ $REPLY =~ ^[0-9]{1,5}$ ]] && ((10#$REPLY > 0 && 10#$REPLY < 65536)) || die "$(T "Stopped as you chose: port $PORT is in use." "Остановлено по вашему выбору: порт $PORT занят.")"
    PORT=$((10#$REPLY))
  done
}

# Downloads the binary for this architecture from the release: the hash comes from SHA256SUMS, the signature (if a key is set) is checked.
auto_fetch() {
  local out=$1 arch name sums want dir
  case $(uname -m) in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "Architecture $(uname -m) is not supported." ;; esac
  name=kitsune-linux-$arch
  command -v curl >/dev/null || die "curl is required."
  dir=$(mktemp -d); sums=$dir/SHA256SUMS
  resolve_release
  note "downloading $name from the selected release"
  release_asset SHA256SUMS -o "$sums" || die "Release asset SHA256SUMS is missing or inaccessible."
  if [[ -n $RELEASE_PUBKEY ]]; then
    command -v ssh-keygen >/dev/null || die "ssh-keygen is needed to check the signature (package openssh-client)."
    release_asset SHA256SUMS.sig -o "$sums.sig" || die "Release asset SHA256SUMS.sig is missing or inaccessible."
    printf 'kitsune-release %s\n' "$RELEASE_PUBKEY" >"$dir/allowed"
    ssh-keygen -Y verify -f "$dir/allowed" -I kitsune-release -n kitsune-release -s "$sums.sig" <"$sums" >/dev/null 2>&1 \
      || die "The SHA256SUMS signature does not match: the files were tampered with or damaged."
    ok "release signature verified"
  else
    later "The release signature was not checked (no key set): integrity was checked by SHA256SUMS only."
  fi
  LAST_SUMS=$sums
  want=$(awk -v n="$name" '$2 == n {print $1}' "$sums")
  [[ -n $want ]] || die "SHA256SUMS has no entry for $name."
  release_asset "$name" -o "$out" || die "Release asset $name is missing or inaccessible."
  [[ $(sha "$out") == "$want" ]] || die "SHA-256 mismatch: the file was tampered with or damaged."
  ok "SHA-256 matches"
}

fetch_binary() {
  local out=$1
  if [[ -n $BIN_SRC ]]; then
    [[ -f $BIN_SRC ]] || die "No such file: $BIN_SRC"
    cp "$BIN_SRC" "$out"
    note "using file $BIN_SRC ($(du -h "$out" | cut -f1))"
  elif [[ -n $URL ]]; then
    [[ -n $SHA ]] || die "--url needs --sha256: without a hash check the binary will not be installed."
    command -v curl >/dev/null || die "curl is required."
    note "downloading $URL"
    curl -fsSL "$URL" -o "$out"
  else
    auto_fetch "$out"
  fi
  if [[ -n $SHA ]]; then
    [[ $(sha "$out") == "$(printf %s "$SHA" | tr A-F a-f)" ]] || die "SHA-256 mismatch: the file was tampered with or damaged."
    ok "SHA-256 matches"
  fi
  chmod 0755 "$out"
}

write_unit() {
  cat <<UNITEOF
[Unit]
Description=Kitsune
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=KITSUNE_ADDR=:$PORT
ExecStart=$DIR/kitsune
Restart=always
RestartSec=3
LimitNOFILE=65535
# We do not trim root's rights: the panel starts cores and AmneziaWG (ports below 1024, network, iptables), and a reduced set of
# capabilities broke access to the folder on servers with non-standard permissions on /opt (checked on a live server).

[Install]
WantedBy=multi-user.target
UNITEOF
}

sysctl_() { [[ $NO_SYSTEMD == 1 ]] && { note "(no systemd) systemctl $*"; return 0; }; run systemctl "$@"; }

wait_health() {
  [[ $NO_SYSTEMD == 1 || $DRY == 1 ]] && return 0
  local i
  for i in $(seq 1 30); do
    curl -fsS -m 3 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# ufw: add rules only if the server owner has already enabled the firewall; SSH ports are never touched or closed.
open_firewall() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    local p
    for p in $(ssh_ports); do run ufw allow "$p/tcp" >/dev/null || true; done
    run ufw allow "$PORT/tcp" >/dev/null && ok "ufw: opened port $PORT (SSH ports left open)"
    local cp
    for cp in $CONN_PORTS; do run ufw allow "$cp" >/dev/null || true; done
    [[ -n $CONN_PORTS ]] && ok "ufw: opened connection ports: $CONN_PORTS"
  else
    note "ufw is off or not installed – adding no rules"
  fi
}

BBR_CONF=$ROOT/etc/sysctl.d/99-kitsune-bbr.conf
# BBR is a TCP congestion-control algorithm: on long links and with packet loss connections are usually faster and steadier.
# Enabled only with your consent, and only where the kernel supports BBR (cannot be changed in OpenVZ/LXC containers).
setup_bbr() {
  [[ $BBR == no ]] && return 0
  [[ $DRY == 1 ]] && { note "(dry-run) BBR"; return 0; }
  [[ $NO_SYSTEMD == 1 || -n $ROOT ]] && return 0
  local cur prev_q; cur=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
  prev_q=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
  if [[ $cur == bbr ]]; then note "BBR is already on"; return 0; fi
  if [[ -n $(systemd-detect-virt -c 2>/dev/null | grep -v '^none$') ]]; then
    note "BBR skipped: the server runs in a container where kernel network settings cannot be changed"; return 0
  fi
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    note "BBR skipped: this server's kernel does not support it"; return 0
  fi
  if [[ $BBR == ask ]]; then
    have_tty || { later "BBR is not enabled: to speed up connections run the install with --bbr or run: kit bbr on"; return 0; }
    say ""
    q "Enable BBR (TCP speed-up)?"
    cont "Changes a server network setting: the TCP congestion algorithm, file $BBR_CONF."
    cont "Turn it off later: kit bbr off. Uninstalling Kitsune removes the file."
    ask_tty "      [Y/n]: " || REPLY=n
    # Only an empty answer or an explicit yes enables it; anything else ("No", "НЕТ", "nope"…) means no.
    case $(lc "$REPLY") in
      ""|y|yes|д|Д|да|Да|ДА|дА) ;;
      *) note "Okay, leaving BBR alone. Enable later: kit bbr on"; return 0 ;;
    esac
  fi
  run mkdir -p "$(dirname "$BBR_CONF")"
  printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > "$BBR_CONF"
  if sysctl -p "$BBR_CONF" >/dev/null 2>&1; then ok "BBR enabled"; else
    # sysctl -p may have applied only part of the file: remove it and put the previous values back
    rm -f "$BBR_CONF"
    [[ -n $prev_q ]] && sysctl -w "net.core.default_qdisc=$prev_q" >/dev/null 2>&1 || true
    [[ -n $cur ]] && sysctl -w "net.ipv4.tcp_congestion_control=$cur" >/dev/null 2>&1 || true
    later "Could not enable BBR."
  fi
}

install_deps() {
  [[ -n $ROOT ]] && return 0
  local need="" pkg why item
  local -a pk=("curl|downloading cores and checking that the panel responds" "ca-certificates|trusted certificates for HTTPS downloads" "iproute2|the ip command: AmneziaWG networking and diagnostics" "iptables|network rules for AmneziaWG")
  for item in "${pk[@]}"; do
    pkg=${item%%|*}; why=${item#*|}
    case $pkg in
      curl) command -v curl >/dev/null && { note "already present: curl"; continue; } ;;
      ca-certificates) [[ -d /etc/ssl/certs ]] && { note "already present: ca-certificates"; continue; } ;;
      iproute2) command -v ip >/dev/null && { note "already present: iproute2"; continue; } ;;
      iptables) command -v iptables >/dev/null && { note "already present: iptables"; continue; } ;;
    esac
    note "need $pkg – $why"
    need="$need $pkg"
  done
  [[ -z $need ]] && { ok "all system packages are in place"; return 0; }
  note "installing:$need"
  if command -v apt-get >/dev/null; then
    wait_apt_idle
    # Someone else's broken repository must not break the install: warn and move on.
    run env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 update -qq >/dev/null 2>&1 || warn "apt update finished with an error (usually a third-party repository is to blame). Continuing."
    run env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 install -y -qq $need >/dev/null 2>&1 && ok "installed:$need" || later "Could not install:$need – install manually."
  elif command -v dnf >/dev/null; then
    run dnf install -y -q ${need//iproute2/iproute} >/dev/null 2>&1 && ok "installed:$need" || later "Could not install:$need – install manually."
  elif command -v yum >/dev/null; then
    run yum install -y -q ${need//iproute2/iproute} >/dev/null 2>&1 && ok "installed:$need" || later "Could not install:$need – install manually."
  else
    later "No package manager found; install manually:$need"
  fi
}

# Is GitHub reachable? (from some countries and hosting networks it is blocked)
github_ok() { curl -fsS -m 8 -o /dev/null -I https://github.com/ 2>/dev/null; }

# Asks what to do if GitHub does not open. Returns 0 if a source was found (proxy, mirror or folder), 1 – skip.
github_fallback() {
  warn "GitHub does not open from this server. The cores (Xray, sing-box and others) are downloaded from there."
  have_tty || { note "Options: set a proxy (HTTPS_PROXY=http://host:port), a mirror (KITSUNE_GH_MIRROR=https://…/) or a folder with archives (KITSUNE_CORES_DIR=/path) and run the install again."; return 1; }
  while :; do
    say ""
    q "How do we get the cores?"
    opt "1." "Through a proxy" "http://host:port or socks5://host:port"
    opt "2." "Through a GitHub mirror" "a prefix address that goes in front of the GitHub link"
    opt "3." "From a folder on the server" "core archives uploaded by hand (scp)"
    opt "4." "Skip" "the panel is installed without cores; later: kit cores"
    opt "5." "Abort the install"
    cont "Authenticity is not affected: every file is checked against the SHA-256 built into the program."
    ask_tty "      Choose [1-5]: " || return 1
    case ${REPLY//[[:space:]]/} in
      1) ask_tty "      Proxy address: " || continue
         [[ -n ${REPLY//[[:space:]]/} ]] || continue
         export HTTPS_PROXY=${REPLY//[[:space:]]/} ALL_PROXY=${REPLY//[[:space:]]/}
         if github_ok; then ok "GitHub opens through the proxy"; return 0; fi
         warn "GitHub did not open through this proxy either."; unset HTTPS_PROXY ALL_PROXY ;;
      2) ask_tty "      Mirror prefix, for example https://mirror.example/: " || continue
         [[ $REPLY =~ ^https?://[^[:space:]]+$ ]] || { warn "An address like https://… is needed"; continue; }
         export KITSUNE_GH_MIRROR=${REPLY//[[:space:]]/}
         ok "mirror set; files are still checked against SHA-256"; return 0 ;;
      3) ask_tty "      Path to the folder with archives: " || continue
         [[ -d ${REPLY//[[:space:]]/} ]] || { warn "No such folder."; continue; }
         export KITSUNE_CORES_DIR=${REPLY//[[:space:]]/}
         ok "using archives from $KITSUNE_CORES_DIR"; return 0 ;;
      4) return 1 ;;
      5) die "Stopped as you chose: no access to GitHub." ;;
    esac
  done
}

install_cores() {
  [[ $NO_CORES == 1 ]] && { note "cores skipped (--no-cores): the panel will download them on first use"; return 0; }
  [[ $DRY == 1 ]] && { note "(dry-run) downloading cores"; return 0; }
  note "Xray – VLESS, VMess, Trojan, Shadowsocks 2022, Hysteria2"
  note "sing-box – TUIC and NaiveProxy;  mtg – MTProto for Telegram;  mita – Mieru (Linux only)"
  note "every core is checked by SHA-256, a tampered file is not accepted"
  if [[ -z ${KITSUNE_GH_MIRROR:-}${KITSUNE_CORES_DIR:-} ]] && ! github_ok; then
    github_fallback || { later "Cores were not downloaded: GitHub is unreachable. Once you have access (or a proxy): kit cores"; return 0; }
  fi
  local list=()
  [[ -n $CORES ]] && IFS=',' read -r -a list <<<"$CORES"
  if (cd "$TARGET" && "./kitsune" install-cores ${list[@]+"${list[@]}"}); then ok "cores installed"
  else later "Some cores were not downloaded (the server needs access to github.com). Retry: kit cores (through a proxy: HTTPS_PROXY=http://host:port kit cores)"; fi
}

install_kit_cmd() {
  local bin="$ROOT/usr/local/bin/kit"
  if [[ $DRY == 1 ]]; then note "(dry-run) command $bin"; return 0; fi
  mkdir -p "$(dirname "$bin")"
  printf '#!/bin/sh\nKIT_CWD=$(pwd); export KIT_CWD\ncd "%s" && exec ./kitsune cli "$@"\n' "$DIR" >"$bin"
  chmod 0755 "$bin"
  note "kit – the console management menu (run: kit)"
}

# The panel prints the login and password to the journal on first start: show them right away.
show_credentials() {
  local out="" i
  if [[ $NO_SYSTEMD != 1 ]] && command -v journalctl >/dev/null; then
    for i in 1 2 3 4 5 6; do
      out=$(journalctl -u "$SVC" --no-pager -o cat 2>/dev/null | grep -E 'Login|Password' | tail -n 2 | sed 's/^ *//' || true)
      [[ -n $out ]] && break
      sleep 1
    done
  fi
  if [[ -n $out ]]; then printf '%s\n' "$out"
  else say "   Login and password not found in the journal: journalctl -u $SVC | grep -E 'Login|Password'"; fi
}

banner() {
  printf '%s' "$O"
  cat <<'ART'

  _  ___ _
 | |/ (_) |_ ___ _   _ _ __   ___
 | ' /| | __/ __| | | | '_ \ / _ \
 | . \| | |_\__ \ |_| | | | |  __/
 |_|\_\_|\__|___/\__,_|_| |_|\___|

ART
  printf '%s' "$N"
}

# Traces of an earlier failed run: a unit without a binary. Remove them and install fresh.
cleanup_leftovers() {
  if [[ -e $UNIT && ! -x $TARGET/kitsune ]]; then
    warn "Found leftovers of an earlier install (a service without the program) – cleaning up."
    sysctl_ disable --now "$SVC" >/dev/null 2>&1 || true
    run rm -f "$UNIT" "$ROOT/usr/local/bin/kit"
    sysctl_ daemon-reload
  fi
}

PROTO_NAMES=(reality xhttp ws trojan vmess ss hy2 tuic mtproto awg awg3 naive mieru)
PROTO_TITLES=("VLESS + REALITY (TCP 443)|disguised as someone else's site" "VLESS + XHTTP + REALITY|if plain REALITY does not connect for you" "VLESS + WebSocket + TLS|through a CDN" "Trojan + gRPC + TLS|" "VMess + WebSocket + TLS|" "Shadowsocks 2022|" "Hysteria 2 (UDP)|fast on poor links" "TUIC v5 (UDP)|" "MTProto for Telegram|" "AmneziaWG|" "AmneziaWG 3.1|" "NaiveProxy|needs a domain and a trusted certificate: not all clients connect with a self-signed one" "Mieru|a separate daemon, Linux only, not yet tested on a live server")

# Which connections to create right away. By default the recommended set: REALITY with Vision, and XHTTP on a second site name.
# Every extra port makes the server more noticeable, so the rest is created only if you choose it.
choose_protocols() {
  [[ -n $PROTOCOLS ]] && return 0
  have_tty || { PROTOCOLS=none; return 0; }
  say ""
  q "$(T "Which connections should be created right away?" "Какие подключения создать сразу?")"
  opt "1)" "$(T "Recommended" "Рекомендуемые")" "$(T "– REALITY with Vision, plus XHTTP on a second site name  [default]" "– REALITY с Vision и XHTTP на втором имени сайта  [по умолчанию]")"
  cont "$(T "Every extra port makes the server more noticeable: add other protocols only when you need them" "Каждый лишний порт делает сервер заметнее: добавляйте другие протоколы только когда они нужны")"
  opt "2)" "$(T "All (13)" "Все (13)")" "$(T "– REALITY, XHTTP, WS, Trojan, VMess, SS, Hysteria2, TUIC, MTProto, AmneziaWG (2), NaiveProxy, Mieru" "– REALITY, XHTTP, WS, Trojan, VMess, SS, Hysteria2, TUIC, MTProto, AmneziaWG (2), NaiveProxy, Mieru")"
  cont "$(T "NaiveProxy will work after you switch to a domain with a Let's Encrypt certificate, Mieru – on Linux only" "NaiveProxy заработает после перехода на домен с сертификатом Let's Encrypt, Mieru – только на Linux")"
  opt "3)" "$(T "Pick" "Выбрать")" "$(T "– the numbers you need" "– нужные номера")"
  opt "4)" "$(T "None" "Ничего")" "$(T "– the panel stays empty, I will create connections in the browser myself" "– панель останется пустой, подключения я создам в браузере сам")"
  # Enter – recommended; anything unclear is asked again (up to 3 times), then nothing is created
  local tries=0
  while :; do
    ask_tty "      $(T "Choice [1]: " "Выбор [1]: ")" || { PROTOCOLS=none; return 0; }   # end of input (Ctrl+D) is not Enter
    case ${REPLY//[[:space:]]/} in
      ""|1) PROTOCOLS=reality,xhttp; return 0 ;;
      2) PROTOCOLS=all; return 0 ;;
      3) break ;;
      4) PROTOCOLS=none; return 0 ;;
    esac
    tries=$((tries+1))
    if ((tries >= 3)); then
      warn "$(T "No clear choice: no connections will be created (add them later in the panel)." "Выбор не ясен: подключения создаваться не будут (добавите их позже в панели).")"
      PROTOCOLS=none; return 0
    fi
    warn "$(T "Type a number from 1 to 4, or press Enter for the recommended set." "Введите число от 1 до 4 или нажмите Enter для рекомендуемого набора.")"
  done
  say ""
  local i=0 e title n
  for e in "${PROTO_TITLES[@]}"; do
    i=$((i+1)); title=${e%%|*}; n=${e#*|}
    printf '        %2d  %s%s\n' "$i" "$title" "${n:+  ${D}– $n${N}}"
  done
  while :; do
    ask_tty "      $(T "Numbers separated by commas, for example 1,3,7 (Enter – none): " "Номера через запятую, например 1,3,7 (Enter – ничего): ")" || true
    REPLY=$(printf %s "$REPLY" | LC_ALL=C tr -cd '0-9,')   # drop extra and junk terminal characters
    [[ -n $REPLY ]] || { PROTOCOLS=none; return 0; }
    local -a pick=(); local chosen="" bad="" x
    IFS=, read -ra pick <<<"$REPLY"
    for x in "${pick[@]}"; do
      if [[ $x =~ ^[0-9]+$ ]] && ((x >= 1 && x <= ${#PROTO_NAMES[@]})); then chosen="$chosen,${PROTO_NAMES[x-1]}"; else bad=$x; break; fi
    done
    [[ -z $bad ]] || { warn "$(T "«$bad» – no such number. Use numbers from 1 to ${#PROTO_NAMES[@]}." "«$bad» – нет такого номера. Используйте числа от 1 до ${#PROTO_NAMES[@]}.")"; continue; }
    PROTOCOLS=${chosen#,}
    return 0
  done
}

# Which site to disguise REALITY as: a subnet neighbour (picked automatically) or your own site with a TLS 1.3 and HTTP/2 check.
# Which site REALITY shows to an outsider. Options: a subnet neighbour, someone else's site, your own domain with a stub site (self-steal).
# The installer never picks silently: if an option does not fit, it says why and offers the others.
KNOWN_SITES=(dl.google.com www.amazon.com www.samsung.com www.yahoo.com)

# Check the address of someone else's site (TLS 1.3 and HTTP/2). 0 – fits.
site_ok() { (cd "$TARGET" && ./kitsune cli sni check "$1" >/dev/null 2>&1); }
valid_host() { [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; }
lc() { printf %s "$1" | tr 'A-Z' 'a-z' | tr -d '[:space:]'; }

mask_neighbor() {
  local found
  note "$(T "looking for a site among subnet neighbours: up to 253 short TLS requests to neighbouring addresses of your host (up to a minute)…" "ищу сайт среди соседей по подсети: до 253 коротких TLS-запросов на соседние адреса вашего хостера (до минуты)…")"
  found=$(cd "$TARGET" && ./kitsune cli sni find "${LINK_HOST:-}" 2>/dev/null | head -n 1) || found=""
  if [[ -z $found ]]; then
    warn "$(T "No suitable site found among subnet neighbours (some hosting providers are like that)." "Среди соседей по подсети подходящего сайта не нашлось (у некоторых хостеров так бывает).")"
    return 1
  fi
  if have_tty; then
    say ""
    q "$(T "Picked a site: $found" "Выбран сайт: $found")"
    cont "$(T "A subnet neighbour that answers over TLS 1.3 and HTTP/2." "Сосед по подсети, который отвечает по TLS 1.3 и HTTP/2.")"
    ask_tty "      $(T "Enter – use it, or type another address: " "Enter – использовать его или введите другой адрес: ")" || REPLY=""
    local d; d=$(lc "$REPLY")
    if [[ -n $d ]]; then
      valid_host "$d" && site_ok "$d" && { SNI=$d; ok "$d fits"; return 0; }
      warn "$d did not fit (needs the name of a site that answers over TLS 1.3 and HTTP/2). Using the picked one: $found"
    fi
  fi
  SNI=$found; ok "masking site: $found"
}

mask_foreign() {
  local d
  while :; do
    ask_tty "      Site address, for example example.com (Enter – back): " || return 1
    d=$(lc "$REPLY"); [[ -n $d ]] || return 1
    valid_host "$d" || { warn "Give just the site name, without https://. Example: example.com"; continue; }
    if site_ok "$d"; then SNI=$d; ok "$d fits"; return 0; fi
    warn "$d does not answer over TLS 1.3 and HTTP/2: REALITY will not work with it. Type another one, or Enter to go back."
  done
}

# A stub site on your own domain: the panel gets a certificate itself and brings the site up; needs an A record to this server and port 80.
mask_selfsteal() {
  local d=${1:-} out rc
  while :; do
    if [[ -z $d ]]; then
      ask_tty "      Your domain, for example vpn.example.com (Enter – back): " || return 1
      d=$(lc "$REPLY"); [[ -n $d ]] || return 1
    fi
    note "checking the domain and getting a Let's Encrypt certificate (up to a minute)…"
    out=$(cd "$TARGET" && { KITSUNE_NO_RESTART=1 ./kitsune cli selfsteal "$d" 2>&1 && echo "RC=0" || echo "RC=$?"; })
    rc=${out##*RC=}; out=${out%RC=*}
    printf '%s\n' "$out" | grep -E '^(✗|   )' | sed 's/^/      /' >&2 || true
    if ((rc == 0)); then SNI=$d; SNI_TARGET=127.0.0.1:10399; SELF_DOMAIN=$d; ok "stub site on $d is ready: certificate issued"; return 0; fi
    have_tty || return 1
    say ""
    q "What shall we do next?"
    opt "1)" "Check again" "– if you have just fixed the cause"
    opt "2)" "Another domain" ""
    opt "3)" "Pick another masking method" "– subnet neighbour or someone else's site"
    ask_tty "      Choice [1]: " || return 1
    case ${REPLY//[[:space:]]/} in 2) d="" ;; 3) return 1 ;; esac
  done
}

choose_masking() {
  [[ ",$PROTOCOLS," == *",reality,"* || ",$PROTOCOLS," == *",xhttp,"* || $PROTOCOLS == all ]] || return 0
  [[ $KEPT_DATA == 1 ]] && return 0
  # set by options
  if [[ -n $SELF_DOMAIN ]]; then
    mask_selfsteal "$(lc "$SELF_DOMAIN")" || die "The stub site on $SELF_DOMAIN did not work out (the reason is above). Options: --sni site.com (someone else's site), --sni auto (subnet neighbour), or fix the domain and run again."
    return 0
  fi
  if [[ $SNI != auto ]]; then
    valid_host "$(lc "$SNI")" && site_ok "$(lc "$SNI")" || warn "Site $SNI does not answer over TLS 1.3 and HTTP/2: REALITY may not work with it."
    return 0
  fi
  if ! have_tty; then
    mask_neighbor || die "Could not find a masking site among the neighbours. Give your own: --sni dl.google.com (someone else's site) or --selfsteal vpn.example.com (your own domain)."
    return 0
  fi
  while :; do
    say ""
    q "$(T "Which site should REALITY be disguised as?" "Под какой сайт маскировать REALITY?")"
    cont "$(T "From outside the server looks like an ordinary website." "Снаружи сервер выглядит как обычный сайт.")"
    opt "1)" "$(T "Subnet neighbour" "Сосед по подсети")" "$(T "– I pick it, no domain needed  [default]" "– подберу сам, домен не нужен  [по умолчанию]")"
    opt "2)" "$(T "Someone else's site" "Чужой сайт")" "$(T "– you type the address (must answer over TLS 1.3 and HTTP/2)" "– вы вводите адрес (должен отвечать по TLS 1.3 и HTTP/2)")"
    opt "3)" "$(T "Your own domain" "Свой домен")" "$(T "– a stub site with a Let's Encrypt certificate is brought up on the server" "– на сервере поднимается сайт-заглушка с сертификатом Let's Encrypt")"
    cont "$(T "Needs a domain with an A record to this server and a free port 80." "Нужен домен с A-записью на этот сервер и свободный порт 80.")"
    ask_tty "      $(T "Choice [1]: " "Выбор [1]: ")" || REPLY=1
    case ${REPLY//[[:space:]]/} in
      2) mask_foreign && return 0 ;;
      3) mask_selfsteal && return 0 ;;
      *) mask_neighbor && return 0
         say ""; q "What shall we do next?"
         opt "1)" "Enter someone else's site" "– any well-known one, for example dl.google.com"
         opt "2)" "Your own domain" "– a stub site on your domain"
         opt "3)" "Choose from the ready list" "– ${KNOWN_SITES[*]}"
         ask_tty "      Choice [1]: " || REPLY=1
         case ${REPLY//[[:space:]]/} in
           2) mask_selfsteal && return 0 ;;
           3) local k=0 w
              for w in "${KNOWN_SITES[@]}"; do k=$((k+1)); opt "$k)" "$w" ""; done
              ask_tty "      Number: " || REPLY=1
              w=${KNOWN_SITES[$(( ${REPLY//[^0-9]/} - 1 ))]:-}
              [[ -n $w ]] && { SNI=$w; ok "masking site: $w"; return 0; } ;;
           *) mask_foreign && return 0 ;;
         esac ;;
    esac
  done
}

# Creates the database, the random admin login and password, and the secret panel path.
init_panel() {
  local out
  if [[ $KEPT_DATA == 1 ]]; then note "keeping the previous login, password and secret path"; return 0; fi
  if [[ $DRY == 1 ]]; then note "(dry-run) creating the database and the admin login"; return 0; fi
  out=$(cd "$TARGET" && ./kitsune cli init 2>&1) || { printf '%s\n' "$out" >&2; die "Could not create the database (see the output above)."; }
  CREDS=$(printf '%s\n' "$out" | grep -E 'Login|Password' | sed -E 's/^[0-9\/: ]+//; s/^ *//' || true)
  PANEL_PATH=$(cd "$TARGET" && ./kitsune cli path raw 2>/dev/null || true)
  ok "database created; a random login and password were generated"
  [[ -n $PANEL_PATH ]] && ok "secret panel path: $PANEL_PATH (any other address answers 404)"
  return 0
}

# Creates the chosen connections and the first user.
setup_connections() {
  local out line
  if [[ $KEPT_DATA == 1 ]]; then note "using the previous data: connections and users are kept"; return 0; fi
  choose_protocols
  choose_masking
  if [[ $PROTOCOLS != none && -z $FIRST_USER ]]; then
    FIRST_USER=user
    if have_tty; then ask_tty "      First user's name [user]: " && [[ -n ${REPLY//[[:space:]]/} ]] && FIRST_USER=${REPLY//[[:space:]]/}; fi
  fi
  if [[ $DRY == 1 ]]; then note "(dry-run) creating connections: ${PROTOCOLS:-none}"; return 0; fi
  [[ $PROTOCOLS == none ]] && note "no connections chosen: the panel will be empty"
  out=$(cd "$TARGET" && ./kitsune cli setup --protocols "${PROTOCOLS/none/}" --sni "$SNI" ${SNI_TARGET:+--target "$SNI_TARGET"} --user "${FIRST_USER:-user}" ${LINK_HOST:+--host "$LINK_HOST"} 2>&1) || { printf '%s\n' "$out" >&2; die "Could not create the connections (see the output above)."; }
  CONN_PORTS=$(printf '%s\n' "$out" | sed -n 's/^KITSUNE_PORT=//p' | sort -u | tr '\n' ' ')
  local c2; c2=$(printf '%s\n' "$out" | grep -E 'Login|Password' | sed -E 's/^[0-9\/: ]+//; s/^ *//' || true)
  [[ -n $c2 ]] && CREDS=$c2
  SUB_ID=$(printf '%s\n' "$out" | sed -n 's/^KITSUNE_SUB=//p' | head -n 1)
  while IFS= read -r line; do
    case $line in
      ✓*|!*|…*) note "$line" ;;
    esac
  done <<<"$(printf '%s\n' "$out" | grep -E '^(✓|!|…)' || true)"
}

# Data from an earlier install (the database with users, connections and password) is left in the folder: ask what to do with it.
handle_old_data() {
  [[ -f $TARGET/kitsune.db ]] || return 0
  local choice=1
  if [[ $KEEP_DATA == 1 ]]; then choice=2
  elif have_tty; then
    say ""
    q "Found data from an earlier install in $DIR (users, connections, password)."
    opt "1)" "Start from scratch" "– the old data is saved next to it in a dated folder  [default]"
    opt "2)" "Keep it" "– users and connections are kept, the password stays the same"
    ask_tty "      Choice [1]: " || true
    [[ ${REPLY//[[:space:]]/} == 2 ]] && choice=2
  fi
  if [[ $choice == 2 ]]; then
    KEPT_DATA=1; PROTOCOLS=none
    ok "keeping the previous data: users and connections in place, same password"
  else
    local bak="$TARGET.backup-$(date +%Y%m%d-%H%M%S)"
    run mv "$TARGET" "$bak" && ok "old data moved to $bak"
  fi
}

# Address in links: can be corrected if the server is behind NAT or the wrong one was detected.
confirm_host() {
  [[ -n $LINK_HOST ]] && return 0
  LINK_HOST=$1
  have_tty || return 0
  ask_tty "      $(T "Address in links: $LINK_HOST. Correct? Enter – yes, or type another IPv4: " "Адрес в ссылках: $LINK_HOST. Верно? Enter – да, или введите другой IPv4: ")" || return 0
  REPLY=${REPLY//[[:space:]]/}
  [[ -z $REPLY ]] && return 0
  if [[ $REPLY =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then LINK_HOST=$REPLY; else warn "$(T "«$REPLY» is not an IPv4, keeping $LINK_HOST" "«$REPLY» не похоже на IPv4, оставляю $LINK_HOST")"; fi
}

os_name() {
  local n=""
  [[ -r /etc/os-release ]] && n=$(. /etc/os-release; echo "${PRETTY_NAME:-${NAME:-}}")
  echo "${n:-$(uname -s)}"
}

do_install() {
  [[ $DRY == 0 && -z $ROOT ]] && { : >"$LOG_FILE" 2>/dev/null && chmod 600 "$LOG_FILE" && exec > >(tee -a "$LOG_FILE") 2>&1 || true; }
  pick_language
  banner
  step "$(T "Checking the system" "Проверка системы")"
  need_root; check_os
  note "OS: $(os_name) · architecture: $(uname -m) · systemd: $([[ $NO_SYSTEMD == 1 ]] && echo no || echo yes)"
  cleanup_leftovers
  if [[ -e $UNIT ]]; then
    die "Kitsune is already installed. Manage it with the kit command; update: bash install.sh update --binary …; reinstall: first run bash install.sh uninstall."
  fi
  ok "the system fits"
  step "$(T "Installing system packages" "Установка системных пакетов")"
  install_deps
  setup_bbr
  step "$(T "Downloading Kitsune" "Скачивание Kitsune")"
  TMP=$(mktemp)
  trap 'rm -f "$TMP"' EXIT
  fetch_binary "$TMP"
  step "$(T "Installing Kitsune into $DIR" "Установка Kitsune в $DIR")"
  handle_old_data
  run mkdir -p "$TARGET"
  run install -m 0755 "$TMP" "$TARGET/kitsune"
  note "kitsune – the panel itself (a single file, the web interface is inside)"
  if [[ -f $0 && -r $0 ]]; then run install -m 0755 "$0" "$TARGET/install.sh"; note "install.sh – for updating and uninstalling with the kit command"
  elif [[ -n ${LAST_SUMS:-} ]]; then refresh_installer
  else later "The installer was not saved to $DIR: copy install.sh there by hand for updating and uninstalling."; fi
  install_kit_cmd
  ok "files are in place"
  step "$(T "Downloading the cores that serve the protocols" "Скачивание ядер, которые обслуживают протоколы")"
  install_cores
  step "$(T "Panel settings" "Настройки панели")"
  choose_panel_port
  export KITSUNE_ADDR=":$PORT"
  init_panel
  persist_language
  step "$(T "Connections and the first user" "Подключения и первый пользователь")"
  local pip; pip=$(public_ip); pip=${pip:-SERVER-IP}
  confirm_host "$pip"
  setup_connections
  step "$(T "Starting the service: the panel starts by itself and comes back after a reboot" "Запуск службы: панель стартует сама и возвращается после перезагрузки")"
  if [[ $DRY == 1 ]]; then note "(dry-run) writing unit $UNIT"; else mkdir -p "$(dirname "$UNIT")"; write_unit >"$UNIT"; fi
  sysctl_ daemon-reload
  sysctl_ enable --now "$SVC"
  open_firewall
  if wait_health; then ok "the panel responds on port $PORT"
  else
    warn "The panel did not respond within 30 seconds. Last lines of the journal:"
    journalctl -u "$SVC" --no-pager -n 12 -o cat 2>/dev/null | sed 's/^/      /' >&2 || true
    later "The panel is not responding: journalctl -u $SVC -n 50"
  fi
  [[ $KEPT_DATA == 1 ]] || [[ -n $CREDS ]] || CREDS=$(show_credentials)
  [[ -n $PANEL_PATH ]] || PANEL_PATH=$(cd "$TARGET" && ./kitsune cli path raw 2>/dev/null || true)
  step "$(T "HTTPS certificate" "HTTPS-сертификат")"
  local url="http://$pip:$PORT$PANEL_PATH"
  if setup_https "$pip"; then url=$HTTPS_URL; fi
  save_result "$url" "$CREDS"
  say ""
  banner
  print_summary "$url"
  setup_2fa
  usage_box
}

# 3x-ui style closing block: everything you need to sign in, in one place.
print_summary() {
  local url=$1 login pass bar row
  login=$(sed -n 's/^ *Login *: *//p' <<<"$CREDS" | head -n 1)
  pass=$(sed -n 's/^ *Password *: *//p' <<<"$CREDS" | head -n 1)
  [[ $KEPT_DATA == 1 ]] && { login="(unchanged)"; pass="(unchanged – forgot it? reset with: kit password)"; }
  bar="${O}═══════════════════════════════════════════════════${N}"
  row() { printf ' %s%-13s%s %s\n' "$B" "$1" "$N" "$2"; }
  say "$bar"
  say "${O}${B}     Kitsune installation complete${N}"
  say "$bar"
  row "Login:" "${login:-see: journalctl -u $SVC}"
  row "Password:" "${pass:-see: journalctl -u $SVC}"
  row "Port:" "$PORT"
  row "Secret path:" "${PANEL_PATH:-(none)}"
  row "Database:" "SQLite ($DIR/kitsune.db)"
  [[ -n $SUB_ID ]] && row "First user:" "${FIRST_USER:-user}"
  row "Access URL:" "${O}${B}$url${N}"
  say "$bar"
  say " ${O}!${N} Save these details somewhere safe (a copy is in $RESULT_FILE, mode 600)."
  say " ${O}!${N} $(T "After signing in, change the administrator password in Settings → Security." "После входа смените пароль администратора в разделе «Настройки → Безопасность».")"
  if ((${#WARNINGS[@]})); then
    say ""
    say " ${O}${B}Attention:${N}"
    local w; for w in "${WARNINGS[@]}"; do say "   – $w"; done
  fi
  say "$bar"
}

usage_box() {
  local l="${O}│${N}"
  say ""
  say "${O}┌───────────────────────────────────────────────────────┐${N}"
  printf '%s  %s%-53s%s%s\n' "$l" "$B" "kit control menu usages (subcommands):" "$N" "$l"
  say "$l                                                       $l"
  local c d
  while IFS='|' read -r c d; do
    printf '%s  %s%-16s%s- %-35s%s\n' "$l" "$B" "$c" "$N" "$d" "$l"
  done <<'USAGE'
kit|Admin menu (update and more)
kit status|Current status
kit url|Panel address
kit restart|Restart the panel
kit log|Check logs
kit password|Set a new random password
kit 2fa on|Two-factor sign-in
kit https|HTTPS certificate
kit path|Secret panel path
kit private on|Panel only via SSH tunnel
kit bbr on|Faster TCP (BBR)
kit uninstall|Remove Kitsune completely
USAGE
  say "${O}└───────────────────────────────────────────────────────┘${N}"
}

# Two-factor sign-in is no longer asked about during the install: the panel's Health tab lowers the score and suggests turning it on.
setup_2fa() {
  say ""
  note "$(T "Two-factor sign-in is off: the Health tab will suggest turning it on (Settings → Security, or kit 2fa on)." "Двухфакторный вход выключен: вкладка «Здоровье» предложит его включить (Настройки → Безопасность или kit 2fa on).")"
}

HTTPS_URL=""
# Runs kit https …, shows progress and picks up the final address (the HTTPS port may differ from 8443).
run_https() {
  local out
  out=$(cd "$TARGET" && KITSUNE_NO_RESTART=1 ./kitsune cli https "$@" 2>&1) || { printf '%s\n' "$out" | grep -E '^(✗|!)' | sed 's/^/      /' >&2; return 1; }
  printf '%s\n' "$out" | grep -E '^(…|!)' | sed 's/^/      /' || true
  HTTPS_URL=$(printf '%s\n' "$out" | grep -oE 'https://[^ ]+' | tail -n 1)
  [[ -n $HTTPS_URL ]]
}
# What to do if the chosen way of getting a certificate failed: say why and offer options.
# The result goes to CERT_FOR (domain|ip|self|none); retry – repeat the same way.
cert_alternatives() {
  local why=$1
  warn "$why"
  have_tty || return 1
  say ""
  q "What shall we do next?"
  opt "1)" "Check again" "– if you have just fixed the cause"
  opt "2)" "Certificate for the IP address" "– Let's Encrypt for the IP, no domain needed (port 80 must be open)"
  opt "3)" "Self-signed certificate" "– encrypted, the browser warns once"
  opt "4)" "No HTTPS" "– the panel over HTTP, the password will travel in plain text"
  ask_tty "      Choice [1]: " || REPLY=3
  case ${REPLY//[[:space:]]/} in
    2) CERT_FOR=ip ;;
    3) CERT_FOR=self ;;
    4) CERT_FOR=none ;;
    *) CERT_FOR=${CERT_FOR:-domain} ;;   # retry
  esac
  return 0
}

# Certificate for a domain: first check what most often makes Let's Encrypt refuse (A record, port 80).
try_domain() {
  local ip=$1 ips
  ips=$(dns_a "$DOMAIN")
  if [[ -z $ips ]]; then PROBLEM="The domain $DOMAIN has no A record. Create one pointing to IP $ip and wait a few minutes."; return 1
  elif ! grep -qx "$ip" <<<"$ips"; then PROBLEM="The domain $DOMAIN points to $(tr '\n' ' ' <<<"$ips")– and that is not your server ($ip). Fix the A record; if the domain is behind a proxy (Cloudflare), turn proxying off."; return 1
  elif port_busy_other 80; then PROBLEM="Port 80/tcp is used by another program: Let's Encrypt will not be able to verify the domain."; return 1
  fi
  ok "domain $DOMAIN points to this server, port 80 is free"
  note "requesting a Let's Encrypt certificate for $DOMAIN"
  run_https acme "$DOMAIN" ${EMAIL:+"$EMAIL"} || { PROBLEM="Let's Encrypt did not issue a certificate for $DOMAIN (most often port 80 is closed at the hosting provider or in the firewall)."; return 1; }
}

try_ip() {
  local ip=$1
  if port_busy_other 80; then PROBLEM="Port 80/tcp is used by another program: Let's Encrypt will not be able to verify the IP address."; return 1; fi
  note "requesting a Let's Encrypt certificate for the IP address $ip (about 6 days, renews itself; port 80 must be open from outside)"
  # the check on port 80 is done by a separate command, and the port may be held by the panel itself: stop it for a minute
  sysctl_ stop "$SVC" >/dev/null 2>&1 || true
  if ! run_https ip "$ip"; then
    sysctl_ start "$SVC" >/dev/null 2>&1 || true
    PROBLEM="Let's Encrypt did not issue a certificate for IP $ip (most often port 80 is closed at the hosting provider or in the firewall)."; return 1
  fi
}

setup_https() {
  local ip=$1 tries=0
  if [[ $NO_TLS == 1 || $NO_SYSTEMD == 1 || $DRY == 1 ]]; then note "HTTPS skipped"; return 1; fi
  [[ -n $DOMAIN ]] && CERT_FOR=domain
  [[ -n ${KITSUNE_HTTPS_PORT:-} ]] || export KITSUNE_HTTPS_PORT=$(random_free_port)
  if [[ -z $CERT_FOR ]] && have_tty; then
    say ""
    q "Choose how the panel gets HTTPS"
    cont "HTTPS keeps the password from travelling over the network in plain text. Options 1 and 2 need port 80 open from outside."
    opt "1)" "Let's Encrypt for a domain" "– 90 days, renews itself, no browser warning"
    cont "Needs a domain whose A record points to this server ($ip)."
    opt "2)" "Let's Encrypt for the IP address" "– about 6 days, renews itself, no domain needed  [default]"
    opt "3)" "Self-signed certificate" "– encrypted, the browser warns once"
    opt "4)" "Your own certificate" "– paths to existing certificate and key files"
    opt "5)" "Skip HTTPS" "– only safe behind an SSH tunnel (kit private on) or a reverse proxy"
    ask_tty "      Choose [1-5] (Enter – 2): " || true
    case ${REPLY//[[:space:]]/} in 1|d|д|domain) CERT_FOR=domain ;; 3) CERT_FOR=self ;; 4) CERT_FOR=custom ;; 5) CERT_FOR=none ;; *) CERT_FOR=ip ;; esac
  fi
  if [[ -z $CERT_FOR ]]; then
    CERT_FOR=ip; note "asking no questions: certificate for the IP address (the --cert domain|ip|self option changes this)"
  fi
  while :; do
    PROBLEM=""
    tries=$((tries+1)); ((tries > 12)) && { warn "Too many attempts – leaving the panel without HTTPS."; CERT_FOR=none; }
    if [[ $CERT_FOR == domain && -z $DOMAIN ]]; then
      if have_tty; then
        ask_tty "      Domain (for example vpn.example.com): " || true
        DOMAIN=$(printf %s "$REPLY" | tr 'A-Z' 'a-z'); DOMAIN=${DOMAIN//[[:space:]]/}; DOMAIN=${DOMAIN%.}
        [[ -z $DOMAIN || $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$ ]] || { warn "«${DOMAIN}» does not look like a domain."; DOMAIN=""; }
      fi
      [[ -n $DOMAIN ]] || { cert_alternatives "No domain given." || { CERT_FOR=ip; later "No domain given: a certificate for the IP is enabled. Later: kit https acme vpn.example.com"; }; continue; }
    fi
    case $CERT_FOR in
      domain) try_domain "$ip" && break ;;
      ip)     try_ip "$ip" && break ;;
      self)   note "enabling a self-signed certificate for IP $ip (traffic is encrypted, the browser will warn)"
              run_https self && break
              PROBLEM="Could not enable HTTPS." ;;
      custom) local cf kf
              ask_tty "      Path to the certificate (fullchain, PEM): " || true; cf=${REPLY//[[:space:]]/}
              ask_tty "      Path to the private key (PEM): " || true; kf=${REPLY//[[:space:]]/}
              if [[ -r $cf && -r $kf ]]; then run_https custom "$cf" "$kf" && break; PROBLEM="The certificate and key do not match or cannot be loaded."
              else PROBLEM="Could not read the certificate or key file."; fi ;;
      none)   note "the panel stays on HTTP (as you chose)"; later "The panel runs over plain HTTP: the password travels unprotected. Enable HTTPS later: kit https ip (or: kit private on to close the panel from the internet)."; return 1 ;;
    esac
    # it failed: in a dialogue ask, without one – say plainly what was done instead
    if ! cert_alternatives "$PROBLEM"; then
      case $CERT_FOR in
        domain) CERT_FOR=ip; later "$PROBLEM Trying a certificate for the IP address instead. For the domain later: kit https acme $DOMAIN" ;;
        ip)     CERT_FOR=self; later "$PROBLEM A self-signed certificate was enabled instead (the browser will warn). Retry: kit https ip" ;;
        *)      CERT_FOR=none ;;
      esac
    fi
  done
  [[ -n $HTTPS_URL ]] || return 1
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then ok "ufw: the HTTPS port was opened by kit https"; fi
  sysctl_ restart "$SVC"
  wait_health || later "The panel did not respond after enabling HTTPS: journalctl -u $SVC -n 50"
  return 0
}

save_result() {
  [[ $DRY == 1 || -n $ROOT ]] && return 0
  ( umask 077; { echo "Kitsune: install details ($(date '+%F %T'))"; echo "Panel: $1"; echo "$2"; } >"$RESULT_FILE" ) 2>/dev/null || true
}

# Also refreshes the installer itself in the Kitsune folder (the kit menu calls it: update and uninstall); the hash comes from the verified SHA256SUMS.
refresh_installer() {
  [[ -n ${LAST_SUMS:-} && -f $LAST_SUMS ]] || return 0
  local tmp want; tmp=$(mktemp)
  if release_asset install.sh -o "$tmp" 2>/dev/null; then
    want=$(awk '$2 == "install.sh" {print $1}' "$LAST_SUMS")
    if [[ -n $want && $(sha "$tmp") == "$want" ]]; then
      run install -m 0755 "$tmp" "$TARGET/install.sh" && ok "installer updated"
    else
      warn "the install.sh hash does not match SHA256SUMS – installer not updated"
    fi
  fi
  rm -f "$tmp"
}

do_update() {
  need_root; check_os; detect_port
  [[ -e $UNIT || -x $TARGET/kitsune ]] || die "Kitsune is not installed. First: bash install.sh install --binary …"
  step_total=4
  TOTAL=4; STEP=0
  step "$(T "Getting the new binary" "Получение нового бинарника")"
  TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
  fetch_binary "$TMP"
  step "$(T "Backing up the database and the previous version (for rollback)" "Копия базы и прежней версии (для отката)")"
  if [[ -f $TARGET/kitsune.db ]]; then run cp -p "$TARGET/kitsune.db" "$TARGET/kitsune.db.bak" && ok "database copy: kitsune.db.bak"; fi
  run cp -p "$TARGET/kitsune" "$TARGET/kitsune.old"
  step "$(T "Replacing the program and restarting the service" "Замена программы и перезапуск службы")"
  run install -m 0755 "$TMP" "$TARGET/kitsune"
  sysctl_ restart "$SVC"
  step "$(T "Checking that the new version responds" "Проверка, что новая версия отвечает")"
  if wait_health; then refresh_installer; ok "updated, the panel responds"; else
    warn "The new version did not respond – restoring the previous one."
    run cp -p "$TARGET/kitsune.old" "$TARGET/kitsune"; sysctl_ restart "$SVC"
    die "Update rolled back."
  fi
}

do_status() {
  detect_port
  [[ -e $UNIT ]] || { say "Kitsune is not installed"; exit 1; }
  if [[ $NO_SYSTEMD == 1 ]]; then say "installed in $DIR (no systemd)"; exit 0; fi
  systemctl is-active "$SVC" || true
  curl -fsS "http://127.0.0.1:$PORT/api/health" 2>/dev/null || say "the panel is not responding on port $PORT"
}

# Closes ports and removes network rules that appeared because of Kitsune. Other people's things are not touched: a port that
# is still being listened on by someone after the stop stays open; SSH ports were never opened by us and are never closed.
cleanup_network() {
  local info=$1 p iface sub rule closed="" kept="" rules=0
  [[ -n $info ]] && [[ -z $ROOT || ${KITSUNE_TEST_NET:-0} == 1 ]] || return 0
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    local sshp; sshp=" $(ssh_ports | tr '\n' ' ') "
    while read -r _ p; do
      [[ -n $p ]] || continue
      [[ $sshp == *" ${p%/*} "* ]] && continue   # never touch SSH ports
      if port_busy "${p%/*}"; then kept="$kept $p"; continue; fi
      if ufw status 2>/dev/null | grep -qE "^${p}[[:space:]]"; then
        run ufw delete allow "$p" >/dev/null 2>&1 && closed="$closed $p"
      fi
    done < <(grep '^PORT ' <<<"$info")
  fi
  # AmneziaWG: iptables rules and the interface itself (stopping the service usually removes them; here we pick up the leftovers)
  while read -r _ iface; do
    [[ -n $iface ]] || continue
    while iptables -C FORWARD -i "$iface" -j ACCEPT 2>/dev/null; do run iptables -D FORWARD -i "$iface" -j ACCEPT && rules=1; done
    if ip link show "$iface" >/dev/null 2>&1; then run ip link delete "$iface" >/dev/null 2>&1 && rules=1; fi
  done < <(grep '^AWG_IFACE ' <<<"$info")
  while read -r _ sub; do
    [[ -n $sub ]] || continue
    while read -r rule; do
      [[ -n $rule ]] || continue
      read -r -a rule_arr <<<"${rule/-A/-D}"
      run iptables -t nat "${rule_arr[@]}" >/dev/null 2>&1 && rules=1
    done < <(iptables -t nat -S POSTROUTING 2>/dev/null | grep -- "-s $sub " | grep MASQUERADE || true)
  done < <(grep '^AWG_SUBNET ' <<<"$info")
  [[ -n $closed ]] && ok "closed ufw ports:$closed"
  [[ -n $kept ]] && note "left open the ports that another program is listening on now:$kept"
  [[ $rules == 1 ]] && ok "removed the AmneziaWG network rules and interfaces"
  return 0
}

do_uninstall() {
  need_root
  if [[ ! -e $UNIT && ! -d $TARGET ]]; then
    # a failed install could leave only the BBR setting behind
    if [[ -f $BBR_CONF ]]; then
      run rm -f "$BBR_CONF"
      [[ $DRY == 1 ]] || ok "removed the leftover BBR setting (after a reboot the server returns to its previous algorithm)"
      return 0
    fi
    die "Kitsune is not installed."
  fi
  if [[ $YES != 1 ]]; then
    [[ -t 0 ]] || die "Without a terminal --yes is required."
    say "${B}Everything${N} will be removed: the service, the program, the cores (Xray, sing-box and others), the database with users and connections,"
    say "certificates, logs and the kit command. This cannot be undone. You can make a backup beforehand in the panel (Settings → Backup)."
    [[ $KEEP_DATA == 1 ]] && say "(Option --keep-data: the database, certificates and cores stay in $DIR.)"
    read -r -p "Type the word \"delete\": " a
    [[ $(lc "$a") == delete || $a == "удалить" ]] || die "Cancelled."
  fi
  # what has to be cleaned up (ports, AmneziaWG network rules): read from the database while it still exists
  local info=""
  [[ -x $TARGET/kitsune ]] && info=$(cd "$TARGET" && ./kitsune cli uninstall-info 2>/dev/null | grep -E '^(PORT|AWG_IFACE|AWG_SUBNET) ' || true)
  sysctl_ disable --now "$SVC" >/dev/null 2>&1 || true
  # cores started by the panel stop with the service; just in case, finish off any left from our folder
  [[ -n $ROOT ]] || pkill -f "$DIR/bin/" >/dev/null 2>&1 || true
  cleanup_network "$info"
  run rm -f "$UNIT" "$ROOT/usr/local/bin/kit"
  if [[ -f $BBR_CONF ]]; then run rm -f "$BBR_CONF"; note "removed the BBR setting (after a reboot the server returns to its previous algorithm)"; fi
  sysctl_ daemon-reload
  if [[ $KEEP_DATA == 1 ]]; then
    run rm -f "$TARGET/kitsune" "$TARGET/kitsune.old" "$TARGET/install.sh"
    ok "The program and service are removed, the data is left in $DIR."
  else
    run rm -rf "$TARGET"
    [[ -n $ROOT ]] || run rm -rf "$RESULT_FILE" "$LOG_FILE"
    ok "Kitsune is removed completely: service, program, cores, database, certificates, logs and the kit command."
  fi
  say ""
  say "  System packages (curl, git, iptables and others) are untouched: other programs may use them."
  say "  If you opened Kitsune ports in your hosting provider's firewall (not ufw), close them there yourself."
  say ""
  say "  ${O}${B}Install again:${N}"
  say "    bash <(curl -fsSL ${DEFAULT_BASE_URL}/install.sh) install"
}

case $cmd in
  install)   do_install ;;
  update)    do_update ;;
  status)    do_status ;;
  uninstall) do_uninstall ;;
  ""|-h|--help|help) sed -n '2,25p' "$0" ;;
  *) die "Unknown command: $cmd" ;;
esac
