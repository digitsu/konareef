// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_feeder_memory_circuit_test.go — black-box CLI tests for the bare
// `konareef feeder --witness` path with a memory-bearing manifest
// (konareef-rinit/v2 R-M31, CL-4-live review round 2). The --circuit-id
// default (v1.1) must never prove a memory-bearing witness:
//
//   - a witness with a memory lane and no --circuit-id resolves to v1.2,
//     which this build refuses until its vkey pin is set; it never reaches
//     PS-1 as v1.1;
//   - an explicit --circuit-id konareef-pod-step-v1.1 on that witness is
//     refused with the memory-circuit error;
//   - a lane-less witness over a memory-bearing manifest is refused as a
//     root that is not committed.
//
// In every case the PS-1 stub is never called.
package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// memoryBearingWitness returns a witness over a memory-bearing
// konareef-rinit/v2 manifest, with the touched cell's lane when withLane.
func memoryBearingWitness(t *testing.T, withLane bool) feeder.Witness {
	t.Helper()
	salt := bytes.Repeat([]byte{0x5a}, 32)
	content := sha256.Sum256([]byte("Prefer primary sources."))
	cells := []membridge.Cell{{CellID: membridge.SourceCellID(membridge.SourceKindInline, content[:]), ContentHash: content[:]}}
	root, derived, err := membridge.RInitV2(salt, cells)
	if err != nil {
		t.Fatal(err)
	}
	models, tools, cMax := []string{"anthropic/claude-sonnet-4-5"}, []string{}, uint64(5000)
	fr, err := canon.FieldsRoot(models, tools, cMax, root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := append([]byte("#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n"),
		canon.CommitTrailerBytes(canon.CommitTrailer{FieldsRoot: fr, RInitScheme: canon.RInitSchemeV2})...)
	sig := make([]byte, 74)
	sig[0] = 70
	for i := 1; i <= 70; i++ {
		sig[i] = 0xab
	}
	w := feeder.Witness{Manifest: manifest, P: []byte("p"), R: []byte("r"), Model: models[0], Models: models,
		Tools: tools, CMax: cMax, SigManifest: sig,
		PkPub: secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x11}, 32)).PubKey().SerializeCompressed()}
	if withLane {
		d := derived[0]
		row := membridge.LeafV2{CellID: d.CellID, ContentHash: d.ContentHash, KeyTag: d.KeyTag, Index: d.Index, ValueHash: d.ValueHash}
		lane, err := feeder.BuildMemoryLane(root, map[uint32][32]byte{d.Index: d.ValueHash}, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Memory = lane
	}
	return w
}

// runBareFeeder writes w and runs `konareef feeder --witness` against a
// PS-1 stub that counts calls. Output: exit code, combined output, calls.
func runBareFeeder(t *testing.T, bin string, w feeder.Witness, extra ...string) (int, string, int64) {
	t.Helper()
	var calls int64
	ps1 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer ps1.Close()
	path := filepath.Join(t.TempDir(), "witness.json")
	raw, _ := json.Marshal(w)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"feeder", "--witness", path, "--paygate-url", ps1.URL,
		"--reef-ingest-url", ps1.URL, "--ingest-token", "tok"}, extra...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out), atomic.LoadInt64(&calls)
}

// TestFeederBareWitnessMemoryBearingNeverProvesOnV1_1 is the round-2 test.
func TestFeederBareWitnessMemoryBearingNeverProvesOnV1_1(t *testing.T) {
	bin := buildKonareef(t)

	// Lane present, no --circuit-id: the default does not win; v1.2 is
	// picked, and refused while unpinned.
	code, out, calls := runBareFeeder(t, bin, memoryBearingWitness(t, true))
	if !vkeystore.IsSupportedCircuitID(vkeystore.CircuitIDPodStepV1_2) {
		if code == 0 || calls != 0 || !strings.Contains(out, `unsupported circuit_id "konareef-pod-step-v1.2"`) ||
			strings.Contains(out, "needs circuit") {
			t.Fatalf("lane, default circuit: exit %d, PS-1 calls %d, output %q; want a v1.2 refusal and no PS-1 call", code, calls, out)
		}
	} else if calls == 0 || strings.Contains(out, "needs circuit") {
		t.Fatalf("lane, default circuit, v1.2 pinned: exit %d, output %q; want a v1.2 request", code, out)
	}

	// Lane present, explicit v1.1: refused.
	code, out, calls = runBareFeeder(t, bin, memoryBearingWitness(t, true), "--circuit-id", vkeystore.CircuitIDPodStepV1_1)
	if code == 0 || calls != 0 || !strings.Contains(out, "needs circuit konareef-pod-step-v1.2") {
		t.Fatalf("lane, explicit v1.1: exit %d, PS-1 calls %d, output %q", code, calls, out)
	}

	// No lane over a memory-bearing manifest, default and explicit v1.1.
	for _, extra := range [][]string{nil, {"--circuit-id", vkeystore.CircuitIDPodStepV1_1}} {
		code, out, calls = runBareFeeder(t, bin, memoryBearingWitness(t, false), extra...)
		if code == 0 || calls != 0 || !strings.Contains(out, "does not reproduce the committed fields_root") {
			t.Fatalf("no lane %v: exit %d, PS-1 calls %d, output %q", extra, code, calls, out)
		}
	}
}

// TestFeederBareWitnessLaneWithoutRInitV2ManifestRefused is the CLI form
// of Hermes konareef!174 note 9472 blocker 1: a self-consistent memory
// lane over a manifest without the konareef-rinit/v2 marker, run with
// --circuit-id konareef-pod-step-v1.2, is refused and PS-1 is never called.
func TestFeederBareWitnessLaneWithoutRInitV2ManifestRefused(t *testing.T) {
	bin := buildKonareef(t)
	base := memoryBearingWitness(t, true)
	v1Marker := bytes.Replace(base.Manifest, []byte(`"konareef-rinit/v2"`), []byte(`"konareef-rinit/v1"`), 1)
	for name, manifest := range map[string][]byte{
		"legacy manifest without commit trailer": []byte("legacy manifest without commit trailer"),
		"konareef-rinit/v1 marker":               v1Marker,
	} {
		w := base
		w.Manifest = manifest
		code, out, calls := runBareFeeder(t, bin, w, "--circuit-id", vkeystore.CircuitIDPodStepV1_2)
		if code == 0 || calls != 0 || !strings.Contains(out, "konareef-rinit/v2") {
			t.Fatalf("%s: exit %d, PS-1 calls %d, output %q; want a refusal and no PS-1 call", name, code, calls, out)
		}
	}
}
