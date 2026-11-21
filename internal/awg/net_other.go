//go:build !linux

package awg

import "errors"

// На системах, кроме Linux, сервер AmneziaWG не настраивается: нужен NAT и пересылка пакетов.
func setupNetwork(iface string, cfg Config) (func(), error) {
	return nil, errors.New("сервер AmneziaWG поддерживается только на Linux")
}
