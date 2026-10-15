package wgtypes

import (
	"fmt"
	"strings"
	"testing"
)

// LIB-06: no way of printing a device or a configuration shows the private
// or preshared keys; the public keys still show.
func TestPrintingHidesSecretKeys(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	psk, _ := GenerateKey()
	peerPriv, _ := GeneratePrivateKey()
	pub := peerPriv.PublicKey()

	dev := &Device{Name: "awg0", PrivateKey: priv, PublicKey: priv.PublicKey(),
		Peers: []Peer{{PublicKey: pub, PresharedKey: psk}}}
	cfg := Config{PrivateKey: &priv, Peers: []PeerConfig{{PublicKey: pub, PresharedKey: &psk}}}

	secrets := []string{priv.String(), psk.String(), fmt.Sprintf("%#v", [KeyLen]byte(priv)), fmt.Sprintf("%#v", [KeyLen]byte(psk))}
	for _, v := range []any{dev, *dev, dev.Peers[0], cfg, &cfg, cfg.Peers[0], []*Device{dev}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, v)
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Errorf("%s of %T shows a secret key: %s", verb, v, out)
				}
			}
			if verb != "%#v" && !strings.Contains(out, pub.String()) {
				t.Errorf("%s of %T lost the public key: %s", verb, v, out)
			}
		}
	}
}
