package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPath(t *testing.T) {
	home := "/tmp/konareef-test"
	want := "/tmp/konareef-test/.konareef/identity.json"
	if got := Path(home); got != want {
		t.Errorf("Path(%q) = %q, want %q", home, got, want)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	id, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := id.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(home)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Handle != id.Handle ||
		loaded.PublicKeyHex != id.PublicKeyHex ||
		loaded.PrivateKeyHex != id.PrivateKeyHex ||
		loaded.Version != id.Version ||
		loaded.Scheme != id.Scheme {
		t.Errorf("loaded identity differs from saved\nloaded=%+v\nsaved=%+v", loaded, id)
	}
	if !loaded.CreatedAt.Equal(id.CreatedAt) {
		t.Errorf("CreatedAt differs: loaded=%v, saved=%v", loaded.CreatedAt, id.CreatedAt)
	}
}

func TestSavePermissions(t *testing.T) {
	home := t.TempDir()
	id, _ := Generate("alice")
	if err := id.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(Path(home))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file perms = %o, want 0600", perm)
	}
	dirfi, err := os.Stat(filepath.Dir(Path(home)))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := dirfi.Mode().Perm(); perm != 0o700 {
		t.Errorf("identity dir perms = %o, want 0700", perm)
	}
}

func TestLoadRefusesLoosePermissions(t *testing.T) {
	home := t.TempDir()
	id, _ := Generate("alice")
	if err := id.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(Path(home), 0o644); err != nil {
		t.Fatalf("Chmod to 0644: %v", err)
	}
	if _, err := Load(home); err == nil {
		t.Errorf("Load accepted a file with 0644 perms; expected refusal")
	}
}

func TestLoadMissingFile(t *testing.T) {
	home := t.TempDir()
	if _, err := Load(home); err == nil {
		t.Errorf("Load on missing file returned nil error")
	}
}

func TestSaveOverwritesAtomically(t *testing.T) {
	home := t.TempDir()
	a, _ := Generate("alice")
	if err := a.Save(home); err != nil {
		t.Fatalf("Save (a): %v", err)
	}
	b, _ := Generate("alice")
	if err := b.Save(home); err != nil {
		t.Fatalf("Save (b): %v", err)
	}
	loaded, err := Load(home)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.PrivateKeyHex != b.PrivateKeyHex {
		t.Errorf("second Save did not overwrite first identity")
	}
}
