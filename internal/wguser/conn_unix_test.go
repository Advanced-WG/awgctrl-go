//go:build !windows
// +build !windows

package wguser

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUNIX_findUNIXSockets(t *testing.T) {
	tmp, err := os.MkdirTemp(os.TempDir(), "wireguardcfg-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create a file which is not a device socket.
	f, err := os.CreateTemp(tmp, "notwg")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	_ = f.Close()

	// Create a temporary UNIX socket and leave it open so it is picked up
	// as a socket file.
	path := filepath.Join(tmp, "testwg0.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	defer l.Close()

	files, err := findUNIXSockets([]string{
		tmp,
		// Should gracefully handle non-existent directories and files.
		filepath.Join(tmp, "foo"),
		"/not/exist",
	})
	if err != nil {
		t.Fatalf("failed to find files: %v", err)
	}

	if diff := cmp.Diff([]string{path}, files); diff != "" {
		t.Fatalf("unexpected output files (-want +got):\n%s", diff)
	}
}

// testFind produces a Client.find function for integration tests.
func testFind(dir string) func() ([]string, error) {
	return func() ([]string, error) {
		return findUNIXSockets([]string{dir})
	}
}

// testListen creates a userspace device listener for tests, returning the
// directory where it can be found and a function to clean up its state.
func testListen(t *testing.T, device string) (l net.Listener, dir string, done func()) {
	t.Helper()

	tmp, err := os.MkdirTemp(os.TempDir(), "wguser-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}

	path := filepath.Join(tmp, device)
	path += ".sock"

	l, err = net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create UNIX socket: %v", err)
	}

	done = func() {
		_ = l.Close()
		_ = os.RemoveAll(tmp)
	}

	return l, tmp, done
}

// testDial connects to a UNIX socket without special options, suitable for tests.
var testDial = func(ctx context.Context, device string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", device)
}

// A socket file left behind by an exited daemon (connection refused) is
// skipped by Devices instead of failing it for every device.
func TestUNIX_DevicesSkipsStaleSocket(t *testing.T) {
	c, done := testClient(t, []byte("private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nerrno=0\n\n"))
	defer done()

	devs, err := c.find()
	if err != nil || len(devs) != 1 {
		t.Fatalf("find = %v, %v", devs, err)
	}

	stale := filepath.Join(filepath.Dir(devs[0]), "stale0.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	_ = l.Close()

	ds, err := c.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(ds) != 1 || ds[0].Name != testDevice {
		t.Fatalf("devices = %v, want only %s", ds, testDevice)
	}
}
