// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_root_v2_test.go — the verifier's memory-root check for a
// memory-bearing konareef-rinit/v2 Type-C bundle (memory_root_v2.go;
// Hermes konareef!174 note 9472 blocker 2).
//
// The bundles start from the canonical-v2 parity fixture, disclose a
// manifest that declares [[context.memory]] and commits
// fields_root(no models, no tools, c_max 1000, r_init) with the
// konareef-rinit/v2 marker, and carry r_init in the r_in and r_out lanes
// of both public-input buffers and in z0[Z_R_MEM], as a
// konareef-pod-step-v1.2 proof from paygate-zk!74 does. r_init is the
// file-inline-file-multi root of the shared rinit_v2 vectors. The SNARK
// itself is accepted by the test verifier, as in every Go verifier test;
// the Rust verifier owns the proof.
package verify

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// Roots from internal/membridge/testdata/rinit_v2/vectors.json,
// source vector file-inline-file-multi: the konareef-rinit/v2 r_init and,
// for a root mismatch, the v1 r_init of the same cells.
const (
	memV2RInitHex = "1542b33f2c40bff45753cfb9440bdd88d5e87da847e4e56529b95746a47c1e08"
	memV1RInitHex = "8f50797705dfd0300c5eafee6a72be93e69c5ea2e4d81ec5c19e6874bfec3430"
)

// memoryBundleBody is a v2 author tree that declares one memory source.
const memoryBundleBody = "[pod]\nid = \"x\"\n[budget]\nmax_sats = 1000\n" +
	"[[context.memory]]\nkind = \"inline\"\ncontent = \"Prefer primary sources.\"\n[_files]\n"

// memoryBundleOpts changes one part of the honest memory-bearing bundle.
type memoryBundleOpts struct {
	scheme     string    // r_init_scheme marker
	circuit    string    // circuit_id
	committed  [32]byte  // r_init the trailer commits
	rIn, rOut  [32]byte  // r_in and r_out in both buffers
	z0RMem     *[32]byte // z0[Z_R_MEM]; nil means rIn
	lastRInOff bool      // last_step r_in differs from first_step
	body       string    // author tree; "" means memoryBundleBody
}

// memoryFreeBody is the reviewer's memory-free probe body (independent
// review of 4ce611a): no [[context.memory]].
const memoryFreeBody = "[pod]\nid = \"x\"\n[budget]\nmax_sats = 1000\n[_files]\n"

// honestMemoryFreeOpts returns the options of a valid memory-free v1.1
// bundle: v1 marker, committed r_init = E20, r_in = z0[Z_R_MEM] = E20, and
// an r_out from the synthetic write (any value; here a populated root).
func honestMemoryFreeOpts(t *testing.T) memoryBundleOpts {
	t.Helper()
	e20 := canon.EmptyMemoryRoot()
	return memoryBundleOpts{scheme: canon.RInitSchemeV1, circuit: vkeystore.CircuitIDPodStepV1_1, committed: e20,
		rIn: e20, rOut: mustHex32(t, memV1RInitHex), body: memoryFreeBody}
}

// honestMemoryOpts returns the options of a valid v1.2 bundle.
func honestMemoryOpts(t *testing.T) memoryBundleOpts {
	t.Helper()
	r := mustHex32(t, memV2RInitHex)
	return memoryBundleOpts{scheme: canon.RInitSchemeV2, circuit: vkeystore.CircuitIDPodStepV1_2, committed: r, rIn: r, rOut: r}
}

// mustHex32 decodes 32-byte hex or fails the test.
func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("hex32 %q: %v", s, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// buildMemoryBundle builds and encodes a memory-bearing Type-C bundle.
func buildMemoryBundle(t *testing.T, o memoryBundleOpts) []byte {
	t.Helper()
	fr, err := canon.FieldsRoot(nil, nil, 1000, o.committed)
	if err != nil {
		t.Fatal(err)
	}
	body := o.body
	if body == "" {
		body = memoryBundleBody
	}
	raw := buildFieldsRootBundleBody(t, "#!konareef-toml/v2\n", body, fr, fr[:], true, false,
		"r_init_scheme = \""+o.scheme+"\"\n")
	b, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	b.CircuitID = o.circuit
	b.SpartanCompressResult.CircuitID = o.circuit
	if pin, ok := vkeystore.KnownVkeySha256For(o.circuit); ok {
		b.SpartanCompressResult.VkeyHash, _ = hex.DecodeString(pin)
	}
	for _, buf := range [][]byte{b.SpartanCompressResult.FirstStepPublicInputs, b.SpartanCompressResult.LastStepPublicInputs} {
		copy(buf[offRIn:], o.rIn[:])
		copy(buf[offROut:], o.rOut[:])
	}
	if o.lastRInOff {
		b.SpartanCompressResult.LastStepPublicInputs[offRIn] ^= 1
	}
	z := o.rIn
	if o.z0RMem != nil {
		z = *o.z0RMem
	}
	copy(b.SpartanCompressResult.Z0[zRMemLane*zLaneBytes:], z[:])
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := enc.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMemoryRootV2_ValidBundleVerifies is the positive regression: a
// populated konareef-rinit/v2 Type-C bundle proved by
// konareef-pod-step-v1.2 verifies, with CommitmentsValid true.
func TestMemoryRootV2_ValidBundleVerifies(t *testing.T) {
	r := VerifyV2(buildMemoryBundle(t, honestMemoryOpts(t)), WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("valid memory-bearing v1.2 bundle refused:\n%v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Fatal("CommitmentsValid=false on a valid memory-bearing bundle")
	}
}

// TestMemoryRootV2_Refusals: each tamper is refused with its named reason
// inside an ErrFieldsRootMismatch divergence.
func TestMemoryRootV2_Refusals(t *testing.T) {
	other := mustHex32(t, memV1RInitHex)
	cases := map[string]struct {
		mutate func(o *memoryBundleOpts)
		reason error
	}{
		"v1-scheme artifact claiming v1.2": {func(o *memoryBundleOpts) { o.scheme = canon.RInitSchemeV1 }, ErrMemoryRInitV1Retired},
		"memory-bearing bundle on v1.1":    {func(o *memoryBundleOpts) { o.circuit = vkeystore.CircuitIDPodStepV1_1 }, ErrMemoryCircuitRequired},
		"root mismatch (r_in tampered)": {func(o *memoryBundleOpts) {
			o.rIn, o.rOut = other, other
		}, ErrMemoryRootNotCommitted},
		"root mismatch (committed root tampered)": {func(o *memoryBundleOpts) { o.committed = other }, ErrMemoryRootNotCommitted},
		"write (r_out != r_in)":                   {func(o *memoryBundleOpts) { o.rOut = other }, ErrMemoryWriteRefused},
		"z0[Z_R_MEM] != r_in":                     {func(o *memoryBundleOpts) { o.z0RMem = &other }, ErrMemoryRootLaneMismatch},
		"last_step r_in != first_step r_in":       {func(o *memoryBundleOpts) { o.lastRInOff = true }, ErrMemoryRootLaneMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := honestMemoryOpts(t)
			c.mutate(&o)
			r := VerifyV2(buildMemoryBundle(t, o), WithAcceptingVerifierForTests())
			assertFieldsRootRejected(t, r)
			found := false
			for _, d := range r.Divergences {
				found = found || (d.Err == ErrFieldsRootMismatch && strings.Contains(d.Msg, c.reason.Error()))
			}
			if !found {
				t.Fatalf("want an ErrFieldsRootMismatch divergence naming %v; got %v", c.reason, divergenceStrings(r))
			}
		})
	}
}

// TestMemoryFreeLanes_ValidBundleVerifies: the memory-free control. A v1.1
// bundle over a memory-free manifest with r_in = z0[Z_R_MEM] = E20
// verifies, and r_out may differ from r_in: v1.1 keeps the synthetic write
// (paygate-zk a3284518 circuit.rs 141-146, verify.rs check_read_only).
func TestMemoryFreeLanes_ValidBundleVerifies(t *testing.T) {
	r := VerifyV2(buildMemoryBundle(t, honestMemoryFreeOpts(t)), WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("valid memory-free v1.1 bundle refused:\n%v", divergenceStrings(r))
	}
}

// TestMemoryFreeLanes_Refusals covers the independent review of 4ce611a
// (finding 1). Each bundle discloses the memory-free probe manifest; each
// verified OK at 4ce611a and is now refused with its named reason.
func TestMemoryFreeLanes_Refusals(t *testing.T) {
	populated := mustHex32(t, memV2RInitHex)
	other := mustHex32(t, memV1RInitHex)
	cases := map[string]struct {
		mutate func(o *memoryBundleOpts)
		reason error
	}{
		"(f) memory-free manifest, v1.2, populated r_in": {func(o *memoryBundleOpts) {
			o.circuit = vkeystore.CircuitIDPodStepV1_2
			o.rIn, o.rOut = populated, populated
		}, ErrMemoryFreeCircuitV1_2},
		"memory-free manifest, v1.1, populated r_in": {func(o *memoryBundleOpts) {
			o.rIn, o.rOut = populated, populated
		}, ErrMemoryRootNotCommitted},
		"memory-free manifest proved by v1.2 at all": {func(o *memoryBundleOpts) {
			o.circuit = vkeystore.CircuitIDPodStepV1_2
		}, ErrMemoryFreeCircuitV1_2},
		"memory-free manifest, z0[Z_R_MEM] != r_in":    {func(o *memoryBundleOpts) { o.z0RMem = &other }, ErrMemoryRootLaneMismatch},
		"memory-free manifest, last_step r_in differs": {func(o *memoryBundleOpts) { o.lastRInOff = true }, ErrMemoryRootLaneMismatch},
		"legacy zero-root manifest, r_in = E20": {func(o *memoryBundleOpts) {
			o.committed, o.scheme = [32]byte{}, canon.RInitSchemeV1
		}, ErrMemoryRootNotCommitted},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := honestMemoryFreeOpts(t)
			c.mutate(&o)
			r := VerifyV2(buildMemoryBundle(t, o), WithAcceptingVerifierForTests())
			assertFieldsRootRejected(t, r)
			found := false
			for _, d := range r.Divergences {
				found = found || (d.Err == ErrFieldsRootMismatch && strings.Contains(d.Msg, c.reason.Error()))
			}
			if !found {
				t.Fatalf("want an ErrFieldsRootMismatch divergence naming %v; got %v", c.reason, divergenceStrings(r))
			}
		})
	}
}
