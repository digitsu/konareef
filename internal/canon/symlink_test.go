// symlink_test.go — R15 symlink rejection for the pod root itself.
//
// A symlink *inside* the pod directory is covered by the golden-vector
// suite (reject/0015-symlink). The pod root being a symlink cannot be
// a committed fixture cleanly, so it is exercised here with a
// t.TempDir()-built symlink.
package canon

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSymlinkedPodRootRejected confirms a pod directory that is itself
// a symlink is rejected. filepath.WalkDir follows a symlinked root, so
// the rejection must fire before the walk — otherwise an attacker who
// controls the pod path could bind arbitrary host files into a signed
// pod_hash.
func TestSymlinkedPodRootRejected(t *testing.T) {
	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real-pod")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	podTOML := []byte("[pod]\nname = \"symlink-root-test\"\n")
	if err := os.WriteFile(filepath.Join(realDir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	linkDir := filepath.Join(tmp, "link-pod")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	out, err := Canonicalize(podTOML, linkDir)
	if err == nil {
		t.Fatalf("expected SYMLINK_FORBIDDEN for a symlinked pod root, got %d bytes of output", len(out))
	}
	if Code(err) != ErrSymlinkForbidden {
		t.Fatalf("expected %s, got %s (%v)", ErrSymlinkForbidden, Code(err), err)
	}
	if out != nil {
		t.Errorf("a rejection must produce no output; got %d bytes", len(out))
	}
}
