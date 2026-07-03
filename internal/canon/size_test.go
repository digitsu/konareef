// size_test.go — the R15 pod-size cap and pod-size-large warning.
//
// These cases live in code rather than the golden-vector suite on
// purpose: exercising them needs a >100 KiB and a >1 MiB pod, and
// committing fixture files that large would bloat the repository. Each
// test synthesizes its pod in a t.TempDir() instead.
package canon

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// sizeTestPodTOML is a minimal, admissible pod.toml used as the
// document for every size-cap test.
const sizeTestPodTOML = "[pod]\nname = \"size-test\"\n"

// writeSizedPod builds a pod directory containing pod.toml and one
// extra file of extraBytes bytes, and returns the directory path.
func writeSizedPod(t *testing.T, extraBytes int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(sizeTestPodTOML), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), bytes.Repeat([]byte{'x'}, extraBytes), 0o644); err != nil {
		t.Fatalf("write blob.bin: %v", err)
	}
	return dir
}

// TestPodSizeUnderThreshold confirms a small pod produces no warnings.
func TestPodSizeUnderThreshold(t *testing.T) {
	dir := writeSizedPod(t, 1024) // 1 KiB — well under every threshold
	output, warnings, err := CanonicalizeWithWarnings([]byte(sizeTestPodTOML), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output) == 0 {
		t.Fatal("expected canonical output")
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

// TestPodSizeLargeWarning confirms a pod above the 100 KiB advisory
// threshold but within the 1 MiB cap yields a WarnPodSizeLarge
// advisory without suppressing output.
func TestPodSizeLargeWarning(t *testing.T) {
	dir := writeSizedPod(t, 150*1024) // 150 KiB — over the soft threshold
	output, warnings, err := CanonicalizeWithWarnings([]byte(sizeTestPodTOML), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output) == 0 {
		t.Fatal("a soft warning must not suppress canonical output")
	}
	if len(warnings) != 1 || warnings[0].Code != WarnPodSizeLarge {
		t.Fatalf("expected exactly one %s warning, got %v", WarnPodSizeLarge, warnings)
	}
	// The plain Canonicalize entry point must still succeed and simply
	// discard the advisory.
	if _, err := Canonicalize([]byte(sizeTestPodTOML), dir); err != nil {
		t.Fatalf("Canonicalize rejected a soft-warning pod: %v", err)
	}
}

// TestPodSizeHardCap confirms a pod above the 1 MiB hard cap is a fatal
// POD_SIZE_EXCEEDED rejection with neither output nor warnings.
func TestPodSizeHardCap(t *testing.T) {
	dir := writeSizedPod(t, 1<<20+1) // one byte past the 1 MiB cap
	output, warnings, err := CanonicalizeWithWarnings([]byte(sizeTestPodTOML), dir)
	if err == nil {
		t.Fatal("expected POD_SIZE_EXCEEDED, got success")
	}
	if Code(err) != ErrPodSizeExceeded {
		t.Fatalf("expected %s, got %s (%v)", ErrPodSizeExceeded, Code(err), err)
	}
	if output != nil || warnings != nil {
		t.Errorf("a rejection must yield neither output nor warnings; got output=%d warnings=%v",
			len(output), warnings)
	}
}
