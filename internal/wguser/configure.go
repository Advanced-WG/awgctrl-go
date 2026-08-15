package wguser

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// configureDevice configures a device specified by its path.
func (c *Client) configureDevice(ctx context.Context, device string, cfg wgtypes.Config) error {
	conn, err := c.dial(ctx, device)
	if err != nil {
		return err
	}
	defer conn.Close()

	// If the context carries a deadline, propagate it to the connection
	// so that blocked reads/writes are cancelled.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}

	// Start with set command.
	var buf bytes.Buffer
	buf.WriteString("set=1\n")

	// Add any necessary configuration from cfg, then finish with an empty line.
	writeConfig(&buf, cfg)
	buf.WriteString("\n")

	// Apply configuration for the device and then check the error number.
	if _, err := io.Copy(conn, &buf); err != nil {
		return err
	}

	res := make([]byte, 32)
	n, err := conn.Read(res)
	if err != nil {
		return err
	}

	// errno=0 indicates success, anything else returns an error number that
	// matches definitions from errno.h.
	str := strings.TrimSpace(string(res[:n]))
	if str != "errno=0" {
		// TODO(mdlayher): return actual errno on Linux?
		return os.NewSyscallError("read", fmt.Errorf("wguser: %s", str))
	}

	return nil
}

// writeConfig writes textual configuration to w as specified by cfg.
func writeConfig(w io.Writer, cfg wgtypes.Config) {
	if cfg.PrivateKey != nil {
		fmt.Fprintf(w, "private_key=%s\n", hexKey(*cfg.PrivateKey))
	}

	if cfg.ListenPort != nil {
		fmt.Fprintf(w, "listen_port=%d\n", *cfg.ListenPort)
	}

	if cfg.FirewallMark != nil {
		fmt.Fprintf(w, "fwmark=%d\n", *cfg.FirewallMark)
	}

	// --- AmneziaWG Parameters Start ---

	// Junk Packets
	if cfg.Jc != nil {
		fmt.Fprintf(w, "jc=%d\n", *cfg.Jc)
	}
	if cfg.Jmin != nil {
		fmt.Fprintf(w, "jmin=%d\n", *cfg.Jmin)
	}
	if cfg.Jmax != nil {
		fmt.Fprintf(w, "jmax=%d\n", *cfg.Jmax)
	}

	// Padding
	if cfg.S1 != nil {
		fmt.Fprintf(w, "s1=%d\n", *cfg.S1)
	}
	if cfg.S2 != nil {
		fmt.Fprintf(w, "s2=%d\n", *cfg.S2)
	}
	if cfg.S3 != nil {
		fmt.Fprintf(w, "s3=%d\n", *cfg.S3)
	}
	if cfg.S4 != nil {
		fmt.Fprintf(w, "s4=%d\n", *cfg.S4)
	}

	// Headers (passed as strings because they can be ranges "123-456")
	if cfg.H1 != nil {
		fmt.Fprintf(w, "h1=%s\n", *cfg.H1)
	}
	if cfg.H2 != nil {
		fmt.Fprintf(w, "h2=%s\n", *cfg.H2)
	}
	if cfg.H3 != nil {
		fmt.Fprintf(w, "h3=%s\n", *cfg.H3)
	}
	if cfg.H4 != nil {
		fmt.Fprintf(w, "h4=%s\n", *cfg.H4)
	}

	// Init Custom Packets ("Custom signature packets")
	if cfg.I1 != nil {
		fmt.Fprintf(w, "i1=%s\n", *cfg.I1)
	}
	if cfg.I2 != nil {
		fmt.Fprintf(w, "i2=%s\n", *cfg.I2)
	}
	if cfg.I3 != nil {
		fmt.Fprintf(w, "i3=%s\n", *cfg.I3)
	}
	if cfg.I4 != nil {
		fmt.Fprintf(w, "i4=%s\n", *cfg.I4)
	}
	if cfg.I5 != nil {
		fmt.Fprintf(w, "i5=%s\n", *cfg.I5)
	}

	// --- AmneziaWG 3.0 Configuration ---
	if cfg.HeaderProtectionKey != nil {
		fmt.Fprintf(w, "header_protection_key=%s\n", hexKey(*cfg.HeaderProtectionKey))
	}
	if cfg.ContentPaddingAddition != nil {
		fmt.Fprintf(w, "content_padding_addition=%d\n", *cfg.ContentPaddingAddition)
	}
	if cfg.RekeyAfterTime != nil {
		fmt.Fprintf(w, "rekey_after_time=%d\n", *cfg.RekeyAfterTime)
	}
	if cfg.RekeyTimeout != nil {
		fmt.Fprintf(w, "rekey_timeout=%d\n", *cfg.RekeyTimeout)
	}
	if cfg.RejectAfterTime != nil {
		fmt.Fprintf(w, "reject_after_time=%d\n", *cfg.RejectAfterTime)
	}
	if cfg.KeepaliveTimeout != nil {
		fmt.Fprintf(w, "keepalive_timeout=%d\n", *cfg.KeepaliveTimeout)
	}
	if cfg.MaxHandshakeAttempts != nil {
		fmt.Fprintf(w, "max_handshake_attempts=%d\n", *cfg.MaxHandshakeAttempts)
	}
	if cfg.RandomTrailers != nil {
		fmt.Fprintf(w, "random_trailers=%t\n", *cfg.RandomTrailers)
	}
	if cfg.DisableCookies != nil {
		fmt.Fprintf(w, "disable_cookies=%t\n", *cfg.DisableCookies)
	}

	// --- AmneziaWG Parameters End ---

	if cfg.ReplacePeers {
		fmt.Fprintln(w, "replace_peers=true")
	}

	for _, p := range cfg.Peers {
		fmt.Fprintf(w, "public_key=%s\n", hexKey(p.PublicKey))

		if p.Remove {
			fmt.Fprintln(w, "remove=true")
		}

		if p.UpdateOnly {
			fmt.Fprintln(w, "update_only=true")
		}

		if p.PresharedKey != nil {
			fmt.Fprintf(w, "preshared_key=%s\n", hexKey(*p.PresharedKey))
		}

		if p.Endpoint != nil {
			fmt.Fprintf(w, "endpoint=%s\n", p.Endpoint.String())
		}

		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}

		if p.ReplaceAllowedIPs {
			fmt.Fprintln(w, "replace_allowed_ips=true")
		}

		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(w, "allowed_ip=%s\n", ip.String())
		}
	}
}

// hexKey encodes a wgtypes.Key into a hexadecimal string.
func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}
