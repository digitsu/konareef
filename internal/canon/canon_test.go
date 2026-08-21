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

// openPodPinnedHashes pins the pod_hash of every open pod (no
// `visibility` key) conformance vector to the value it had before the
// visibility field existed. The digests are transcribed by hand from the
// expected.hash files as of the commit that introduced this guard.
//
// These constants are deliberately NOT read from expected.hash: `go test
// -update` rewrites those goldens, so a golden-versus-output comparison
// alone cannot detect a regression that someone has already regenerated
// over. Pinning the digest in source makes the backward-compat promise
// survive a -update run.
var openPodPinnedHashes = map[string]string{
	"arrays/0001-layout":              "c4e0bed43dfa942d4a31368990156ec4708d3aafcc60f70e44983c7766159d6a",
	"arrays/0002-nested":              "d9f72e46b740e94685ee65caa35203dbb186d6f3fb7f1fbefac62aa68a506538",
	"basic/0001-worked-example":       "255bf513eb667546d3a24020f633d0058bc1d0564245bf56acfe73eb09aa75ef",
	"basic/0002-empty-pod":            "f15cdb76b29e727ea8c74f2ce0cc9733eec6dd93c39ff5be3248878560dd73e9",
	"basic/0003-scalars":              "6fe8fcf20eb679259b770c70b7c5a1fc6cfb257cadbae48f70956a988340ddb8",
	"basic/0004-toml11-normalization": "54080136ba0f89f7509437ea61c4a2d8dadf34fd9d1f701f92334b97dba5759d",
	"numbers/0001-floats":             "dee9250fb9c05fe4846ef7c9ca10af97b31fd413480d1839ad00f22e265b9e91",
	"numbers/0002-integers":           "df8263e59f1850aae67398501a3e002b4db822f09bb487eea2fa10463c98210e",
	"strings/0001-escapes":            "7cdb316250ddbe1af577486b0b121abf7ab40c9a6efc0f54977ac947ad81c038",
	"tables/0001-nesting":             "95e91c3f74a6acff836ada829f6c122f1447339e626b9bd6c4bb2a5146732a13",
	"tables/0002-inline-table":        "0c2750411d477502290f4fe2e423c0850c08a8e5bc7c7c53cc4d7f1a900f21eb",
	"tables/0003-dash-sibling":        "d63000847825b5dba03f2a03ad014969ec6ef6f0b4930cfea8925a3054f82965",
}

// TestCanonicalize_OpenPodBytesUnchanged is the load-bearing
// backward-compat guard for the visibility field (spec §9).
//
// A pod that declares no `visibility` key must canonicalize to bytes —
// and therefore a pod_hash — identical to what it produced before the
// field existed. Every already-published open pod's HEAD, signature and
// on-chain anchor depends on that. If this test fails, the change under
// review is a defect: do NOT resolve it by regenerating the golden
// vectors.
func TestCanonicalize_OpenPodBytesUnchanged(t *testing.T) {
	for name, wantHash := range openPodPinnedHashes {
		t.Run(name, func(t *testing.T) {
			caseDir := filepath.Join("testdata", "canon", "v1", filepath.FromSlash(name))
			inputDir := filepath.Join(caseDir, "input")

			podTOML, err := os.ReadFile(filepath.Join(inputDir, "pod.toml"))
			if err != nil {
				t.Fatalf("read input/pod.toml: %v", err)
			}
			if bytes.Contains(podTOML, []byte("visibility")) {
				t.Fatalf("%s is not an open-pod vector: it declares visibility", name)
			}

			got, err := Canonicalize(podTOML, inputDir)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}

			wantCanon, err := os.ReadFile(filepath.Join(caseDir, "expected.canon"))
			if err != nil {
				t.Fatalf("read expected.canon: %v", err)
			}
			if !bytes.Equal(got, wantCanon) {
				t.Fatalf("open-pod canonical bytes changed:\n got %q\nwant %q", got, wantCanon)
			}

			digest := sha256.Sum256(got)
			if gotHash := hex.EncodeToString(digest[:]); gotHash != wantHash {
				t.Fatalf("open-pod pod_hash changed: got %s, want pinned %s", gotHash, wantHash)
			}
		})
	}
}
