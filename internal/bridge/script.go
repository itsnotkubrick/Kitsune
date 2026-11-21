package bridge

import (
	_ "embed"
	"fmt"
	"net"
	"sort"
	"strings"
)

//go:embed bridge.sh.tmpl
var scriptTemplate string

// Script generates an IPv4-only nftables installer for a dedicated bridge. It never
// adopts unowned firewall objects or changes foreign tables.
func Script(exitHost string, fw []Forward) (string, error) {
	ip := net.ParseIP(exitHost)
	if ip == nil || !publicIPv4(ip) {
		return "", fmt.Errorf("для скрипта нужен публичный IPv4 основного сервера")
	}
	if len(fw) == 0 {
		return "", fmt.Errorf("нет подключений для пересылки")
	}
	seen := map[Forward]bool{}
	var pairs []string
	for _, f := range fw {
		if f.Port < 1 || f.Port > 65535 || (f.Proto != "tcp" && f.Proto != "udp") {
			return "", fmt.Errorf("неверное правило пересылки %s/%d", f.Proto, f.Port)
		}
		if !seen[f] {
			pairs = append(pairs, fmt.Sprintf("%s:%d", f.Proto, f.Port))
			seen[f] = true
		}
	}
	sort.Strings(pairs)
	installer := strings.NewReplacer("@@EXIT@@", ip.To4().String(), "@@PORTS@@", strings.Join(pairs, " ")).Replace(scriptTemplate)
	return pasteCommand(installer), nil
}

// pasteCommand runs the installer as a file so its $0 identifies the helper
// to persist for systemd. The outer heredoc collects the entire paste before
// executing anything, and its Bash process isolates shell options and traps.
func pasteCommand(installer string) string {
	return `#!/bin/bash
bash -s -- "$@" <<'KITSUNE_BRIDGE_RUN'
set -eu
umask 077
tmp=$(mktemp "${TMPDIR:-/tmp}/kitsune-bridge.XXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp" <<'KITSUNE_BRIDGE_INSTALLER'
` + strings.TrimSuffix(installer, "\n") + `
KITSUNE_BRIDGE_INSTALLER
bash "$tmp" "$@"
KITSUNE_BRIDGE_RUN
`
}
