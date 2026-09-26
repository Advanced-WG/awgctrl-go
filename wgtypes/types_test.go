package wgtypes_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/curve25519"
)

func TestPreparedKeys(t *testing.T) {
	// Keys generated via "wg genkey" and "wg pubkey" for comparison
	// with this Go implementation.
	const (
		private = "GHuMwljFfqd2a7cs6BaUOmHflK23zME8VNvC5B37S3k="
		public  = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
	)

	priv, err := wgtypes.ParseKey(private)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	if diff := cmp.Diff(private, priv.String()); diff != "" {
		t.Fatalf("unexpected private key (-want +got):\n%s", diff)
	}

	pub := priv.PublicKey()
	if diff := cmp.Diff(public, pub.String()); diff != "" {
		t.Fatalf("unexpected public key (-want +got):\n%s", diff)
	}
}

func TestKeyExchange(t *testing.T) {
	privA, pubA := mustKeyPair()
	privB, pubB := mustKeyPair()

	// Perform ECDH key exchange: https://cr.yp.to/ecdh.html.
	sharedA, err := curve25519.X25519(privA[:], pubB[:])
	if err != nil {
		t.Fatalf("failed to perform X25519 A: %v", err)
	}
	sharedB, err := curve25519.X25519(privB[:], pubA[:])
	if err != nil {
		t.Fatalf("failed to perform X25519 B: %v", err)
	}

	if diff := cmp.Diff(sharedA, sharedB); diff != "" {
		t.Fatalf("unexpected shared secret (-want +got):\n%s", diff)
	}
}

func TestBadKeys(t *testing.T) {
	// Adapt to fit the signature used in the test table.
	parseKey := func(b []byte) (wgtypes.Key, error) {
		return wgtypes.ParseKey(string(b))
	}

	tests := []struct {
		name string
		b    []byte
		fn   func(b []byte) (wgtypes.Key, error)
	}{
		{
			name: "bad base64",
			b:    []byte("xxx"),
			fn:   parseKey,
		},
		{
			name: "short base64",
			b:    []byte("aGVsbG8="),
			fn:   parseKey,
		},
		{
			name: "short key",
			b:    []byte("xxx"),
			fn:   wgtypes.NewKey,
		},
		{
			name: "long base64",
			b:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZg=="),
			fn:   parseKey,
		},
		{
			name: "long bytes",
			b:    bytes.Repeat([]byte{0xff}, 40),
			fn:   wgtypes.NewKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			t.Logf("OK error: %v", err)
		})
	}
}

func mustKeyPair() (private, public *[32]byte) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	return keyPtr(priv), keyPtr(priv.PublicKey())
}

func keyPtr(k wgtypes.Key) *[32]byte {
	b32 := [32]byte(k)
	return &b32
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}

func TestGenerateAmneziaParams(t *testing.T) {
	cfg := &wgtypes.Config{}
	cfg.GenerateAmneziaParams()

	// Validate the generated params.
	if err := cfg.Validate(); err != nil {
		t.Errorf("GenerateAmneziaParams() produced invalid config: %v", err)
	}

	// All fields should be set.
	fields := []struct {
		name string
		val  interface{}
	}{
		{"Jc", cfg.Jc},
		{"Jmin", cfg.Jmin},
		{"Jmax", cfg.Jmax},
		{"S1", cfg.S1},
		{"S2", cfg.S2},
		{"S3", cfg.S3},
		{"S4", cfg.S4},
		{"H1", cfg.H1},
		{"H2", cfg.H2},
		{"H3", cfg.H3},
		{"H4", cfg.H4},
		{"I1", cfg.I1},
		{"I2", cfg.I2},
		{"I3", cfg.I3},
		{"I4", cfg.I4},
		{"I5", cfg.I5},
	}
	for _, f := range fields {
		if f.val == nil {
			t.Errorf("GenerateAmneziaParams() did not set %s", f.name)
		}
	}

	// S1-S4 must all be unique.
	s := []int{*cfg.S1, *cfg.S2, *cfg.S3, *cfg.S4}
	seen := make(map[int]bool)
	for _, v := range s {
		if seen[v] {
			t.Errorf("GenerateAmneziaParams() produced duplicate S value: %d", v)
		}
		seen[v] = true
	}
}
