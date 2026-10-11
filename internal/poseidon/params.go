// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package poseidon implements Poseidon-over-Pallas-Fq, byte-identical to the
// neptune 13.0.0 reference used by the konareef pod-step ZK circuit
// (paygate-zk crates/konareef-circuit). It is the Go verifier-side counterpart
// of scripts/poseidon_pallas.py and the in-circuit gadgets in
// gadgets/memory_poseidon.rs / troot_poseidon.rs.
//
// All parameters (modulus, domain tags, MDS matrices, round constants) are
// loaded from the pinned artifact konareef-pod-step-v1-poseidon-params-v1.json,
// whose SHA-256 is gated against ParamArtifactSHA256 so the Go, Rust, and Python
// implementations cannot silently diverge.
//
// Field arithmetic uses math/big rather than a Montgomery implementation:
// a verifier hashes only a handful of nodes per proof, so constant-time/perf
// concerns do not apply, and mod-p big.Int mirrors the Python oracle exactly,
// removing the principal silent-divergence risk (parameter/field mismatch).
package poseidon

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// embeddedParamsJSON is the pinned Poseidon parameter artifact, copied verbatim
// from paygate-zk docs/prds/. It is the single source of truth for every
// concrete parameter; do not edit by hand.
//
//go:embed params/konareef-pod-step-v1-poseidon-params-v1.json
var embeddedParamsJSON []byte

// ParamArtifactSHA256 is the pinned digest of the parameter artifact. It mirrors
// the Rust circuit's param_drift_gate.rs constant. A drift here means the Go
// hash outputs would diverge from the circuit/verifier contract.
const ParamArtifactSHA256 = "4aeda63ce430b5f0486bb31c0264923acc493e3d0ab45a92e19efe8ffe4bbf9f"

// instance holds the loaded parameters for one Poseidon configuration
// (leaf, node, or sponge): width t, the full/partial round split, the domain
// tag occupying state[0], the t×t MDS matrix, and the flat round-constant
// schedule (t per round, full and partial alike).
type instance struct {
	t             int
	fullRounds    int
	partialRounds int
	domainTag     *big.Int
	mds           [][]*big.Int
	rc            []*big.Int
}

// Params is a loaded, drift-checked set of the three Poseidon instances over
// the Pallas Fq field.
type Params struct {
	p      *big.Int
	leaf   *instance
	node   *instance
	sponge *instance
}

type rawInstance struct {
	Width            int        `json:"width"`
	FullRounds       int        `json:"full_rounds"`
	PartialRounds    int        `json:"partial_rounds"`
	DomainTagLE      string     `json:"domain_tag_le_hex"`
	MDSLE            [][]string `json:"mds_le_hex"`
	RoundConstantsLE []string   `json:"round_constants_le_hex"`
}

type rawDoc struct {
	Modulus   string                 `json:"modulus"`
	Instances map[string]rawInstance `json:"instances"`
}

var (
	defaultParams *Params
	defaultOnce   sync.Once
	defaultErr    error
)

// Default returns the Params loaded from the embedded pinned artifact. It
// panics if the embedded artifact fails its SHA-256 drift gate or cannot be
// parsed — both are build-time invariants, not recoverable runtime conditions.
func Default() *Params {
	defaultOnce.Do(func() {
		defaultParams, defaultErr = load(embeddedParamsJSON)
	})
	if defaultErr != nil {
		panic("poseidon: " + defaultErr.Error())
	}
	return defaultParams
}

// load parses and validates a parameter artifact: it gates the SHA-256, parses
// the modulus and the three instances, and verifies their structural shape
// (round-constant count == t*(RF+RP), square t×t MDS).
func load(raw []byte) (*Params, error) {
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != ParamArtifactSHA256 {
		return nil, fmt.Errorf("param artifact drift: got %s want %s", got, ParamArtifactSHA256)
	}

	var doc rawDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse artifact: %w", err)
	}

	p, ok := new(big.Int).SetString(strings.TrimPrefix(doc.Modulus, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad modulus %q", doc.Modulus)
	}

	out := &Params{p: p}
	for name, dst := range map[string]**instance{
		"leaf": &out.leaf, "node": &out.node, "sponge": &out.sponge,
	} {
		ri, ok := doc.Instances[name]
		if !ok {
			return nil, fmt.Errorf("missing instance %q", name)
		}
		in, err := parseInstance(ri, p)
		if err != nil {
			return nil, fmt.Errorf("instance %q: %w", name, err)
		}
		*dst = in
	}
	return out, nil
}

func parseInstance(ri rawInstance, p *big.Int) (*instance, error) {
	t := ri.Width
	if t < 2 {
		return nil, fmt.Errorf("width %d too small", t)
	}
	dt, err := feFromLEHex(ri.DomainTagLE, p)
	if err != nil {
		return nil, fmt.Errorf("domain tag: %w", err)
	}

	if len(ri.MDSLE) != t {
		return nil, fmt.Errorf("MDS has %d rows, want %d", len(ri.MDSLE), t)
	}
	mds := make([][]*big.Int, t)
	for i, row := range ri.MDSLE {
		if len(row) != t {
			return nil, fmt.Errorf("MDS row %d has %d cols, want %d", i, len(row), t)
		}
		mds[i] = make([]*big.Int, t)
		for j, s := range row {
			v, err := feFromLEHex(s, p)
			if err != nil {
				return nil, fmt.Errorf("MDS[%d][%d]: %w", i, j, err)
			}
			mds[i][j] = v
		}
	}

	wantRC := t * (ri.FullRounds + ri.PartialRounds)
	if len(ri.RoundConstantsLE) != wantRC {
		return nil, fmt.Errorf("round constants: got %d, want t*(RF+RP)=%d", len(ri.RoundConstantsLE), wantRC)
	}
	rc := make([]*big.Int, wantRC)
	for k, s := range ri.RoundConstantsLE {
		v, err := feFromLEHex(s, p)
		if err != nil {
			return nil, fmt.Errorf("rc[%d]: %w", k, err)
		}
		rc[k] = v
	}

	return &instance{
		t:             t,
		fullRounds:    ri.FullRounds,
		partialRounds: ri.PartialRounds,
		domainTag:     dt,
		mds:           mds,
		rc:            rc,
	}, nil
}

// feFromLEHex decodes a 32-byte little-endian hex field element from the trusted
// artifact, reduced mod p. Used for parameters (domain tags, MDS, constants),
// which are trusted, so no canonicality rejection is applied here.
func feFromLEHex(s string, p *big.Int) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad hex %q: %w", s, err)
	}
	return new(big.Int).Mod(leBytesToInt(b), p), nil
}
