// main_test.go — acceptance tests for top-level CLI flows.
//
// TestPodInitCore_PersistsGenesisSalt is the executable B1 contract: a
// successful `konareef pod init` MUST persist a 32-byte salt under the
// lineage_id baked into the scaffolded pod.toml. The test fails loudly
// if init lies about persistence (e.g. a future regression that only
// writes lineage_id without calling Backend.Put).
package main

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/saltstore"
)

func TestPodInitCore_PersistsGenesisSalt(t *testing.T) {
	// Use a tempdir state root so the backend write never pollutes the
	// developer's ~/.konareef. KONAREEF_STATE_DIR also keeps the
	// resolver's encrypted/plain-file backends rooted under this dir.
	stateDir := t.TempDir()
	t.Setenv("KONAREEF_STATE_DIR", stateDir)
	// Allow plaintext fallback in this test so a CI host without a
	// keychain daemon AND without a passphrase source still has a
	// usable backend. Production callers opt in via the same env var.
	t.Setenv("KONAREEF_ALLOW_PLAINTEXT_SALT", "1")

	scratch := t.TempDir()
	podDir := filepath.Join(scratch, "salt-genesis-fixture")

	// Capture stdout/stderr via pipes so the test sees the recovery
	// notice only when Init + Put both succeed.
	stdout, stdoutW, _ := os.Pipe()
	stderr, stderrW, _ := os.Pipe()
	defer stdout.Close()
	defer stderr.Close()

	code := runPodInitCore(stdoutW, stderrW, pod.InitOptions{
		Name: "salt-genesis-fixture",
		Dir:  podDir,
	})
	stdoutW.Close()
	stderrW.Close()
	outBytes, _ := io.ReadAll(stdout)
	errBytes, _ := io.ReadAll(stderr)
	if code != 0 {
		t.Fatalf("runPodInitCore exit=%d stderr=%q", code, string(errBytes))
	}

	// Read back the lineage_id from the scaffolded pod.toml.
	spec, err := pod.ParseFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	lid, err := saltstore.LineageIDFromManifest(&spec)
	if err != nil {
		t.Fatalf("LineageIDFromManifest: %v (lineage_id should be set by init)", err)
	}

	// CRITICAL ASSERTION (B1): the salt MUST be retrievable from the
	// backend that Resolve() picks. If init only wrote lineage_id but
	// skipped the salt, this fails with ErrSaltNotFound.
	backend, err := saltstore.Resolve(saltstore.ResolveOpts{PlainFileOptIn: true})
	if err != nil {
		t.Fatalf("saltstore.Resolve: %v", err)
	}
	salt, err := backend.Get(lid)
	if err != nil {
		// Clean up the lingering keychain entry (if any) so a re-run
		// doesn't trip ErrSaltAlreadyExists. Best effort.
		_ = backend.Delete(lid)
		t.Fatalf("backend.Get(%s): %v — init claimed success but salt is not persisted",
			hex.EncodeToString(lid[:]), err)
	}
	if salt == ([32]byte{}) {
		_ = backend.Delete(lid)
		t.Fatalf("backend.Get returned all-zero salt — CSPRNG path is broken")
	}

	// Cleanup the persisted salt so a repeat run on the same dev
	// machine doesn't accumulate keychain entries.
	t.Cleanup(func() { _ = backend.Delete(lid) })

	// Recovery-notice contract: stdout must mention "persisted via
	// `konareef salt`" once everything succeeded.
	if !strings.Contains(string(outBytes), "is now persisted") {
		t.Errorf("recovery notice missing from stdout: %q", string(outBytes))
	}
}

// failingPutBackend wraps a MockBackend but always returns the
// configured error from Put. Used by the B2 rollback test to inject a
// salt-persist failure into runPodInitCore.
type failingPutBackend struct {
	*saltstore.MockBackend
	err error
}

func (f failingPutBackend) Put(lid [16]byte, salt [32]byte) error { return f.err }

// TestRunPodInit_RollbackOnSaltPersistFailure is the executable B2
// contract: when the salt backend fails to persist the genesis salt,
// runPodInitCore MUST roll back the scaffold so the user is never left
// with a pod.toml whose lineage_id has no salt stored behind it. The
// final pod directory must NOT exist after the failed call.
func TestRunPodInit_RollbackOnSaltPersistFailure(t *testing.T) {
	// Inject a backend whose Put always fails. The hook is restored
	// in t.Cleanup so neighbouring tests are unaffected.
	injected := failingPutBackend{
		MockBackend: saltstore.NewMockBackend(),
		err:         errors.New("injected: salt backend offline"),
	}
	runPodInitTestHook = func() (saltstore.Backend, error) { return injected, nil }
	t.Cleanup(func() { runPodInitTestHook = nil })

	scratch := t.TempDir()
	podDir := filepath.Join(scratch, "rollback-fixture")

	stdout, stdoutW, _ := os.Pipe()
	stderr, stderrW, _ := os.Pipe()
	defer stdout.Close()
	defer stderr.Close()

	code := runPodInitCore(stdoutW, stderrW, pod.InitOptions{
		Name: "rollback-fixture",
		Dir:  podDir,
	})
	stdoutW.Close()
	stderrW.Close()
	outBytes, _ := io.ReadAll(stdout)
	errBytes, _ := io.ReadAll(stderr)

	if code == 0 {
		t.Fatalf("runPodInitCore unexpectedly returned 0; stdout=%q stderr=%q",
			string(outBytes), string(errBytes))
	}

	// CRITICAL ASSERTION (B2): the pod directory MUST NOT exist
	// after a salt-persist failure. A user re-running `konareef pod
	// init <name>` must hit the clean-slate path, not a "directory
	// already exists" error caused by a half-finished previous
	// attempt.
	if _, err := os.Stat(podDir); !os.IsNotExist(err) {
		t.Fatalf("pod directory %s still exists after rollback (stat err=%v) — B2 invariant violated",
			podDir, err)
	}

	// Also assert no .konareef-init-* tempdir is left dangling in
	// the parent. The init helper is responsible for its own
	// rollback; a leak here would mean the scaffold survives
	// despite Put failure.
	parent := filepath.Dir(podDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("ReadDir parent: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".konareef-init-") {
			t.Errorf("leaked tempdir after rollback: %s", e.Name())
		}
	}

	// The recovery notice MUST NOT appear in stdout on the failure
	// path — printing it would lie to the user about salt durability.
	if strings.Contains(string(outBytes), "is now persisted") {
		t.Errorf("recovery notice present on failure path: %q", string(outBytes))
	}
	// And the error path should mention the persist failure.
	if !strings.Contains(string(errBytes), "persist genesis salt") {
		t.Errorf("stderr missing persist-failure diagnostic: %q", string(errBytes))
	}

	// Sanity: the lineage_id from the (rolled-back) scaffold MUST
	// NOT be present in the injected backend's list — the failing
	// Put MUST NOT have left a partial entry.
	list, _ := injected.MockBackend.List()
	if len(list) != 0 {
		t.Errorf("backend has %d entries after Put failure, want 0 — Put left state behind",
			len(list))
	}

	// Silence unused-import nag in the (negative) success-path
	// assertions above.
	_ = hex.EncodeToString
}
