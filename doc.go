// Copyright (C) 2018-2022 Matt Layher
// Copyright (C) 2025 Advanced-WG, V. Bantserov
//
// Package wgctrl enables control of WireGuard and AmneziaWG devices on
// multiple platforms.
//
// For more information on WireGuard, please see https://www.wireguard.com/.
// For AmneziaWG, see https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.
//
// This package is a fork of WireGuard/wgctrl-go with full AmneziaWG support:
//   - Reading AWG parameters (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5) via Device()
//   - Writing AWG parameters via ConfigureDevice()
//   - Automatic parameter generation via Config.GenerateAmneziaParams()
//   - Parameter validation via Config.Validate()
//   - Userspace AWG daemon support (amneziawg-go)
package wgctrl // import "github.com/awg-go/awgctrl-go"
