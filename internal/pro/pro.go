//go:build !pro

// Package pro – точки расширения; здесь все они пустые, а Enabled всегда false.
package pro

import "kitsune/internal/proto"

func Enabled() bool  { return false }
func Licensed() bool { return false }

func XrayParts() (outbounds, rules []proto.M, err error) { return nil, nil, nil }
func ExpandRelays(in []*proto.Profile) []*proto.Profile  { return in }
func ExternalLinks() []string                            { return nil }
