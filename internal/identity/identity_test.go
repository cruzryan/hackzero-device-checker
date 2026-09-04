package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDeviceSignsAndPersists(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("immutable report")
	signature, err := d.Sign(message)
	if err != nil || !d.Verify(message, signature) {
		t.Fatal("signature did not verify")
	}
	path := filepath.Join(t.TempDir(), "private", "device.json")
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != d.ID || !loaded.Verify(message, signature) {
		t.Fatal("saved identity changed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("got permissions %o", info.Mode().Perm())
		}
	}
}
