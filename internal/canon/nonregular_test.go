//go:build unix

// nonregular_test.go — R15's rejection of non-regular filesystem
// entries (FIFOs, sockets, devices). Like symlinks, they cannot
// portably appear in committed test fixtures; the rejection is
// exercised by building a real FIFO in t.TempDir() at runtime.
//
// Build-tagged `unix` because syscall.Mkfifo is not available on
// Windows; that is fine — the rule itself applies wherever pods exist
// and CI runs on linux.
package canon

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestNonRegularFileRejected confirms a FIFO in the pod directory is a
// fatal NON_REGULAR_FILE_FORBIDDEN rejection rather than a silent
// skip. A silent skip would let an attacker hide content from the
// signed [_files] manifest by passing it through a named pipe.
//
// Two subtests: a plain FIFO and a hidden-named FIFO. The hidden
// case is the codex regression — the original walk ordered the
// hidden-name skip before the non-regular check, so `.pipe` was
// silently excluded in violation of R15.
func TestNonRegularFileRejected(t *testing.T) {
	cases := []struct {
		name     string
		fifoName string
	}{
		{"plain", "pipe"},
		{"hidden", ".pipe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			podTOML := []byte("[pod]\nname = \"nonregular-" + c.name + "\"\n")
			if err := os.WriteFile(filepath.Join(dir, "pod.toml"), podTOML, 0o644); err != nil {
				t.Fatalf("write pod.toml: %v", err)
			}
			if err := syscall.Mkfifo(filepath.Join(dir, c.fifoName), 0o644); err != nil {
				t.Skipf("mkfifo unsupported on this platform: %v", err)
			}

			out, err := Canonicalize(podTOML, dir)
			if err == nil {
				t.Fatalf("expected NON_REGULAR_FILE_FORBIDDEN, got %d bytes of output", len(out))
			}
			if Code(err) != ErrNonRegularFile {
				t.Fatalf("expected %s, got %s (%v)", ErrNonRegularFile, Code(err), err)
			}
			if out != nil {
				t.Errorf("a rejection must produce no output; got %d bytes", len(out))
			}
		})
	}
}
