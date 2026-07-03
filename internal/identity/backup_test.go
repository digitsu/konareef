package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportImportRoundTrip(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id.bak")
	passphrase := []byte("correct horse battery staple")

	if err := id.Export(path, passphrase); err != nil {
		t.Fatalf("Export: %v", err)
	}
	got, err := Import(path, passphrase)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got.Handle != id.Handle ||
		got.PublicKeyHex != id.PublicKeyHex ||
		got.PrivateKeyHex != id.PrivateKeyHex ||
		got.Version != id.Version ||
		got.Scheme != id.Scheme {
		t.Errorf("imported identity differs from exported\nexp=%+v\ngot=%+v", id, got)
	}
}

func TestImportRejectsWrongPassphrase(t *testing.T) {
	id, _ := Generate("alice")
	path := filepath.Join(t.TempDir(), "id.bak")
	if err := id.Export(path, []byte("right")); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := Import(path, []byte("wrong")); err == nil {
		t.Errorf("Import accepted a wrong passphrase")
	}
}

func TestImportRejectsMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.bak")
	if err := os.WriteFile(path, []byte("not a backup"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Import(path, []byte("any")); err == nil {
		t.Errorf("Import accepted a malformed file")
	}
}

func TestExportFileIsAStructuredEnvelope(t *testing.T) {
	id, _ := Generate("alice")
	path := filepath.Join(t.TempDir(), "id.bak")
	if err := id.Export(path, []byte("pw")); err != nil {
		t.Fatalf("Export: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	for _, key := range []string{"version", "kdf", "kdf_salt", "kdf_time", "kdf_memory_kib", "kdf_threads", "cipher", "nonce", "ciphertext"} {
		if _, ok := env[key]; !ok {
			t.Errorf("envelope missing required key %q", key)
		}
	}
}

func TestExportDoesNotLeakPrivateKey(t *testing.T) {
	id, _ := Generate("alice")
	path := filepath.Join(t.TempDir(), "id.bak")
	if err := id.Export(path, []byte("pw")); err != nil {
		t.Fatalf("Export: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(body), id.PrivateKeyHex) {
		t.Errorf("backup file contains the raw private-key hex — encryption isn't happening")
	}
}

func TestExportRefusesEmptyPassphrase(t *testing.T) {
	id, _ := Generate("alice")
	if err := id.Export(filepath.Join(t.TempDir(), "id.bak"), nil); err == nil {
		t.Errorf("Export accepted an empty passphrase")
	}
	if err := id.Export(filepath.Join(t.TempDir(), "id.bak"), []byte{}); err == nil {
		t.Errorf("Export accepted a zero-length passphrase")
	}
}

func TestExportFilePermsAre0600(t *testing.T) {
	id, _ := Generate("alice")
	path := filepath.Join(t.TempDir(), "id.bak")
	if err := id.Export(path, []byte("pw")); err != nil {
		t.Fatalf("Export: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("export file perms = %o, want 0600", perm)
	}
}
