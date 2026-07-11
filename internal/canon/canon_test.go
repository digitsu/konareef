// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// canon_test.go — the konareef-toml/v1 golden-vector conformance suite.
//
// Every directory under testdata/canon/v1/<category>/<case>/ is one
// test vector. A case is either:
//
//   - a positive case — has expected.canon (the exact bytes
//     Canonicalize must produce) and expected.hash (their SHA-256), or
//   - a reject case — has expected.error (the stable §7 error code
//     Canonicalize must fail with).
//
// Every case has an input/ directory; input/pod.toml is the document
// and input/ is the pod directory passed to Canonicalize.
//
// The golden files are bootstrapped with `go test -run Conformance
// -update`, then reviewed by hand against the spec. basic/0001 is the
// spec §5 worked example and its expected.canon is additionally
// cross-checked against the canonical output printed in the spec — an
// implementation-independent anchor for the whole suite.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// updateGolden, when set via `-update`, regenerates expected.canon and
// expected.hash for every positive case from the current
// implementation output instead of comparing against them.
var updateGolden = flag.Bool("update", false, "regenerate golden expected.canon/expected.hash files")

// TestConformance discovers and runs every vector under testdata.
func TestConformance(t *testing.T) {
	root := filepath.Join("testdata", "canon", "v1")
	categories, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read suite root %s: %v", root, err)
	}
	ran := 0
	for _, category := range categories {
		// Skip non-directories and hidden entries — a tool or harness
		// may drop a `.`-prefixed state directory under testdata, and
		// it is not a conformance category.
		if !category.IsDir() || strings.HasPrefix(category.Name(), ".") {
			continue
		}
		categoryDir := filepath.Join(root, category.Name())
		cases, err := os.ReadDir(categoryDir)
		if err != nil {
			t.Fatalf("read category %s: %v", categoryDir, err)
		}
		for _, vector := range cases {
			if !vector.IsDir() || strings.HasPrefix(vector.Name(), ".") {
				continue
			}
			name := category.Name() + "/" + vector.Name()
			caseDir := filepath.Join(categoryDir, vector.Name())
			t.Run(name, func(t *testing.T) { runVector(t, caseDir) })
			ran++
		}
	}
	if ran == 0 {
		t.Fatalf("no conformance vectors found under %s", root)
	}
}

// runVector executes a single test vector directory.
func runVector(t *testing.T, dir string) {
	inputDir := filepath.Join(dir, "input")
	podTOML, err := os.ReadFile(filepath.Join(inputDir, "pod.toml"))
	if err != nil {
		t.Fatalf("read input/pod.toml: %v", err)
	}

	if wantCode, isReject := readReject(t, dir); isReject {
		runRejectVector(t, podTOML, inputDir, wantCode)
		return
	}
	runPositiveVector(t, dir, podTOML, inputDir)
}

// readReject returns the expected error code and true when dir is a
// reject vector (it has an expected.error file).
func readReject(t *testing.T, dir string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "expected.error"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

// runRejectVector asserts that Canonicalize fails with exactly the
// expected stable error code — and produces no output.
func runRejectVector(t *testing.T, podTOML []byte, inputDir, wantCode string) {
	out, err := Canonicalize(podTOML, inputDir)
	if err == nil {
		t.Fatalf("expected rejection %s, got %d bytes of output", wantCode, len(out))
	}
	if out != nil {
		t.Errorf("rejection produced %d bytes of output; canonicalizer must be all-or-nothing", len(out))
	}
	if got := Code(err); got != wantCode {
		t.Fatalf("expected error code %s, got %s (%v)", wantCode, got, err)
	}
}

// runPositiveVector asserts byte-exact canonical output, that the
// recorded hash matches, and that PodHash agrees with sha256(canon).
func runPositiveVector(t *testing.T, dir string, podTOML []byte, inputDir string) {
	got, err := Canonicalize(podTOML, inputDir)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	digest := sha256.Sum256(got)
	gotHash := hex.EncodeToString(digest[:])
	canonPath := filepath.Join(dir, "expected.canon")
	hashPath := filepath.Join(dir, "expected.hash")

	if *updateGolden {
		if err := os.WriteFile(canonPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", canonPath, err)
		}
		if err := os.WriteFile(hashPath, []byte(gotHash+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", hashPath, err)
		}
	}

	wantCanon, err := os.ReadFile(canonPath)
	if err != nil {
		t.Fatalf("read expected.canon (run -update to create it): %v", err)
	}
	if !bytes.Equal(got, wantCanon) {
		t.Errorf("canonical output mismatch\n--- got (%d bytes) ---\n%s\n--- want (%d bytes) ---\n%s",
			len(got), got, len(wantCanon), wantCanon)
	}

	wantHash, err := os.ReadFile(hashPath)
	if err != nil {
		t.Fatalf("read expected.hash (run -update to create it): %v", err)
	}
	if recorded := strings.TrimSpace(string(wantHash)); recorded != gotHash {
		t.Errorf("hash mismatch: sha256(output)=%s recorded expected.hash=%s", gotHash, recorded)
	}

	podHash, err := PodHash(podTOML, inputDir)
	if err != nil {
		t.Fatalf("podhash: %v", err)
	}
	if podHashHex := hex.EncodeToString(podHash[:]); podHashHex != gotHash {
		t.Errorf("PodHash=%s disagrees with sha256(canonical output)=%s", podHashHex, gotHash)
	}

	// §2 contract: canonical output must re-parse under any conforming
	// TOML 1.0 parser. BurntSushi/toml v1.6.0 is TOML 1.1-compatible,
	// so this Decode only proves the bytes are valid TOML at all —
	// it would silently accept a regression to 1.1-only output. The
	// strict 1.0-parseable assertion runs in CI against Python's
	// `tomllib` (Python 3.11+ ships TOML 1.0), not in this Go test:
	// a regex-on-bytes scanner cannot distinguish escape sequences
	// inside string values from real syntactic escapes, so it
	// false-positives on legitimate strings containing `\\e`,
	// `\\x41`, `T13:42Z`, or `\\u{...}`. See .gitlab-ci.yml for the
	// strict 1.0 round-trip step.
	var reparsed map[string]interface{}
	if _, err := toml.Decode(string(got), &reparsed); err != nil {
		t.Errorf("canonical output does not re-parse: %v", err)
	}
}
