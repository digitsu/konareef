// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package verify — P1.2 SNARK verification phase + first-byte
// dispatch ladder per PRD 3 §§ 5-12 + § 10.1.
//
// The v2 path lands on `verifySnarkPhase`, which runs the disclosure
// matrix, commitments, memory-tree authentication, T_log root check,
// attestation cross-checks, vkey resolution, chain-policy evaluation,
// and finally the SNARK verify itself. All checks fire (no
// short-circuit) so the divergence list is exhaustive; the all-or-none
// invariant is enforced by the final OK = AND of every structured-
// verdict bool.
//
// The default `SpartanVerifier` (when not wired in `VerifyOptions`) is
// `failClosedVerifier{}` — it returns
// `(false, ErrSnarkVerifierNotConfigured)` so production paths cannot
// accept a v2 bundle without an explicit verifier injection. Tests opt
// in via `WithAcceptingVerifierForTests()`.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/poseidon"
	"github.com/digitsu/konareef/internal/vkeystore"
	"github.com/fxamacker/cbor/v2"
)

// Verdict is the v2 structured-verdict shape (PRD 3 § 11.1).
type Verdict struct {
	ProofValid       bool   `json:"proof_valid"`
	DisclosureValid  bool   `json:"disclosure_valid"`
	ChainPolicyMode  string `json:"chain_policy_mode"`
	ChainPolicyValid bool   `json:"chain_policy_valid"`
	// ChainTruncated is true when the first chain link carries a
	// prev_hash, so the bundle starts mid-chain and does not reach the
	// genesis link (PRD 3 § 8.1 amendment, R2b D2). It does not fail
	// the chain policy. A verifier cannot tell how many links are
	// missing.
	ChainTruncated bool `json:"chain_truncated"`
	// ChainHeadAnchored is true only when the bundle's chain_head_anchor
	// passed every check (anchor.go): the head hash is in a BSV
	// transaction whose merkle path reaches a header with enough work and
	// enough confirmations, and a trusted node's attestation binds that
	// transaction to this chain head and this proof. Without it a sender
	// that rewrites the chain can re-hash it and it still verifies, so
	// chain_policy_valid alone is not tamper evidence (R2b D1).
	ChainHeadAnchored bool `json:"chain_head_anchored"`
	// ChainHeadAnchor is the anchor check outcome in detail.
	ChainHeadAnchor         *ChainHeadAnchorVerdict `json:"chain_head_anchor"`
	CommitmentsValid        bool                    `json:"commitments_valid"`
	SignatureValid          bool                    `json:"signature_valid"`
	PublisherIdentityStatus PublisherIdentityStatus `json:"publisher_identity_status"`
}

// SpartanVerifier abstracts the actual Spartan SNARK verification
// call. P1.2 ships with two impls:
//
//   - failClosedVerifier (production default) returns
//     (false, ErrSnarkVerifierNotConfigured).
//   - acceptingVerifier returns (true, nil). Test-only; gated behind
//     WithAcceptingVerifierForTests().
type SpartanVerifier interface {
	Verify(snark, firstStepPublicInputs, lastStepPublicInputs, vkey []byte) (bool, error)
}

type failClosedVerifier struct{}

func (failClosedVerifier) Verify(_, _, _, _ []byte) (bool, error) {
	return false, ErrSnarkVerifierNotConfigured
}

type acceptingVerifier struct{}

func (acceptingVerifier) Verify(_, _, _, _ []byte) (bool, error) { return true, nil }

// WithAcceptingVerifierForTests returns a VerifyOptions populated with
// the accepting Spartan stub. THIS IS A TEST-ONLY ENTRY POINT.
// Production code MUST NOT call this helper.
func WithAcceptingVerifierForTests() VerifyOptions {
	return VerifyOptions{Spartan: acceptingVerifier{}}
}

// VerifyOptions carries the dispatcher's runtime knobs. Zero-value is
// the production default: fail-closed (no SpartanVerifier wired) +
// non-durable mode.
type VerifyOptions struct {
	Spartan SpartanVerifier
	Durable bool
	// Anchor configures the chain-head anchor check (anchor.go). The zero
	// value has no header source and no trusted keys, so an anchor can
	// never read as verified with it.
	Anchor AnchorOptions
	// Circuit is the circuit-binding policy (circuit_policy.go): the
	// publisher's pinned circuit id and the v1 cutoff. The zero value has
	// neither.
	Circuit CircuitPolicy
}

// VerifyV2 is the public entry point for verifying konareef-bundle/v2
// bytes. It dispatches on the first byte:
//
//   - 0x7B ('{')           → legacy v1 JSON; caller should use Verify
//   - 0xA0..0xBB           → konareef-bundle/v2 CBOR
//   - anything else        → ErrMalformedCBOR
func VerifyV2(input []byte, opts VerifyOptions) *ResultV2 {
	r := &ResultV2{OK: true, Custody: CustodyAssessment{Assurance: BrokerAssuranceNotVerified},
		CustodyBinding: CustodyBindingBundleClaim}
	if len(input) == 0 {
		r.diverge(ErrMalformedCBOR, "empty input")
		return r
	}

	first := input[0]
	switch {
	case first >= 0xA0 && first <= 0xBB:
		b, err := decodeBundleV2(input)
		if err != nil {
			r.OK = false
			r.Divergences = append(r.Divergences, Divergence{
				Err: err,
				Msg: err.Error(),
			})
			return r
		}
		r.ChainLength = len(b.Chain)
		verifySnarkPhase(b, opts, r)
		r.Custody = assessCustodyV2(b, r)
		r.CustodyBinding = custodyBindingV2(b, r)
		return r
	case first == 0x7B:
		r.diverge(ErrMalformedCBOR, "v1 JSON bundle on V2 entry; use legacy Verify(b *Bundle)")
	default:
		r.diverge(ErrMalformedCBOR, fmt.Sprintf("unrecognized first byte 0x%02X", first))
	}
	return r
}

// ResultV2 is the v2 verifier's structured output. ResultV2 carries
// typed Divergences (PRD 3 § 11.1) so test code can match against the
// stable taxonomy.
//
// Custody is the MCP broker assurance of the chain's custody record
// (MCP-K04), for display only. See assessCustodyV2.
type ResultV2 struct {
	OK          bool
	ChainLength int
	Divergences []Divergence
	V2Verdict   *Verdict
	Custody     CustodyAssessment
	// CTotalChecked is true only when the whole bundle verified (OK) and
	// the real (subprocess) Spartan verifier confirmed the c check against
	// the bundle's custody TOTAL_SATS, so the proven cost `c` equals that
	// total (MCP-Z00 §7, O1-B). False means the binding was not
	// established: no bound custody total (for example a Type-D bundle),
	// no real verifier, or a failed verification. A display must not
	// claim `c == TOTAL_SATS` when it is false.
	//
	// True does NOT mean the total is the server's record. It means `c`
	// equals the TOTAL_SATS this bundle states. What that total is bound
	// to is CustodyBinding: in bundle-only verification it is
	// "bundle-claim", the bundle's own unanchored claim. A display shows
	// it with CTotalLabel, never as a bare "checked".
	CTotalChecked bool
	// CTotalAnchored is CTotalChecked on a Type-C bundle whose chain head
	// anchor verified (V2Verdict.ChainHeadAnchored). The custody link is
	// then the one the attested node wrote, so the checked total is
	// anchored, not only the bundle's own claim (reef-core#76 § 11).
	CTotalAnchored bool
	// CustodyBinding says what the custody fields of this verdict (the
	// custody total behind CTotalChecked, TOOL_LOG_ROOT, the broker
	// marker) are bound to (custody_binding.go). Every result starts as
	// "bundle-claim"; only a passing Type-C bundle with a verified
	// chain-head anchor reads "chain-anchored" (konareef#37).
	CustodyBinding CustodyBinding
}

// Divergence is a single failure with both the canonical error code
// and a human-readable message.
//
// Err holds the canonical sentinel error (e.g. ErrFieldsRootMismatch) so
// errors.Is() works uniformly on the stable taxonomy. The full wrapped
// TOML/decode detail (the chain that includes the underlying error text)
// lives only in Msg — it is NOT preserved in Err. This is intentional:
// callers should match on the sentinel via errors.Is; human-readable
// context is in Msg.
type Divergence struct {
	Err error
	Msg string
}

func (r *ResultV2) diverge(err error, msg string) {
	r.OK = false
	r.Divergences = append(r.Divergences, Divergence{Err: err, Msg: msg})
}

// verifySnarkPhase runs the version-gated v2 verification ladder per
// PRD 3 §§ 5-12. All checks fire (no short-circuit) so the divergence
// list is exhaustive; the all-or-none invariant is enforced by the
// final OK = AND of every structured-verdict bool.
func verifySnarkPhase(b *BundleV2, opts VerifyOptions, r *ResultV2) {
	v := &Verdict{}
	r.V2Verdict = v

	// § 5.1 vkey_hash length floor.
	scr := b.SpartanCompressResult
	if len(scr.VkeyHash) != 32 {
		r.diverge(ErrProofFieldRenamed, fmt.Sprintf("vkey_hash length=%d, want 32", len(scr.VkeyHash)))
	}

	// § 5.2 circuit_id cross-check.
	if scr.CircuitID != b.CircuitID {
		r.diverge(ErrCircuitIDMismatch, fmt.Sprintf("top=%q inner=%q", b.CircuitID, scr.CircuitID))
		r.OK = false
		return
	}
	// VHASH (paygate-zk#12, O2-A): konareef-pod-step-v1 and
	// konareef-pod-step-v1.1 are both accepted until v1 retires (O5-A).
	if !vkeystore.IsSupportedCircuitID(b.CircuitID) {
		r.diverge(ErrUnsupportedCircuit, fmt.Sprintf("circuit_id=%q not supported", b.CircuitID))
		r.OK = false
		return
	}
	// VHASH-M1 (paygate-zk#14): the id must be the publisher's choice, and
	// v1 ends at the configured cutoff.
	if !checkCircuitPolicy(b, opts.Circuit, r) {
		return
	}
	// v1.1 has no legacy artifacts, so its vkey_hash must be the pinned
	// one. v1 keeps its pre-VHASH behaviour (no pin check here); the Rust
	// verifier binds the vkey to the circuit shape for both ids.
	if b.CircuitID == vkeystore.CircuitIDPodStepV1_1 {
		pin, _ := vkeystore.KnownVkeySha256For(b.CircuitID)
		if hex.EncodeToString(scr.VkeyHash) != pin {
			r.diverge(ErrVkeyMismatch, "vkey_hash != the pinned konareef-pod-step-v1.1 vkey")
		}
	}

	// § 7.1 disclosure consistency matrix.
	checkDisclosureMatrix(b, v, r)

	// § 7.3 commitments — disclosure-disjoint.
	switch b.Disclosure {
	case "C":
		checkTypeCCommitments(b, v, r)
	case "D":
		checkTypeDCommitments(b, v, r)
	}

	// § 9.2 T_log root (Type-C only).
	if b.Disclosure == "C" && b.WitnessDisclosure != nil {
		checkTLogRoot(b, v, r)
	}

	// The first_step lanes read above and by Check 4 must equal the
	// last_step lanes. Runs after the commitment checks so it can clear
	// CommitmentsValid.
	lanesAgree := checkStepLaneAgreement(b, v, r)

	// § 11.2 Check 4 — public-input signature verify (sole authority for
	// v.SignatureValid). Must run before checkAttestationV2.
	v.SignatureValid = false
	checkPublicInputSignature(b, v, r)
	// § 11.2 attestation envelope cross-checks (Task 5 will fully rewrite).
	// Does NOT touch v.SignatureValid.
	checkAttestationV2(b, v, r)
	// Check 4 and the envelope checks read first_step. When the step
	// buffers fail checkStepLaneAgreement, those lanes are not the
	// proof-bound ones, so the signature and the publisher identity must
	// not read as verified. An envelope mismatch status is kept.
	if !lanesAgree {
		v.SignatureValid = false
		if v.PublisherIdentityStatus != PISMismatch {
			v.PublisherIdentityStatus = PISSignatureInvalid
		}
	}

	// § 6 vkey resolution.
	checkVkey(b, opts, v, r)

	// § 7.2 / § 7.3 chain-policy evaluation, then the § 8.4 anchor
	// cross-reference.
	checkChainPolicy(b, v, r)
	checkChainAnchors(b, v, r)
	// Type-C links carry their data, so each link hash must recompute.
	if b.Disclosure == "C" {
		checkTypeCLinkHashes(b, v, r)
	}
	// The chain-head anchor (reef-core#76). Runs after the chain checks
	// so it reads a head link the chain rules have already looked at.
	checkChainHeadAnchor(b, opts.Anchor, lanesAgree, v, r)

	// SNARK verify (fail-closed default).
	spartan := opts.Spartan
	if spartan == nil {
		spartan = failClosedVerifier{}
	}
	ok, err := spartan.Verify(scr.SpartanSnark, scr.FirstStepPublicInputs, scr.LastStepPublicInputs, b.Vkey)
	if err != nil || !ok {
		if errors.Is(err, ErrSnarkVerifierNotConfigured) {
			r.diverge(ErrSnarkVerifierNotConfigured,
				"no Spartan verifier wired into VerifyOptions; production paths must inject one")
		} else if errors.Is(err, ErrCTotalMismatch) {
			// MCP-Z00 §7 (O1-B): the proof's c is not the custody total.
			r.diverge(ErrCTotalMismatch, err.Error())
		} else {
			r.diverge(ErrProofRejected, fmt.Sprintf("spartan verify err=%v ok=%v", err, ok))
		}
		v.ProofValid = false
	} else {
		v.ProofValid = true
	}

	// All-or-none gate: AND every structured-verdict bool.
	r.OK = r.OK && v.ProofValid && v.DisclosureValid && v.CommitmentsValid &&
		v.SignatureValid && v.ChainPolicyValid
	// A head is reported anchored only on a bundle that passed: an
	// anchored head next to a failed proof or chain would read as a
	// stronger claim than the bundle supports. The anchor status keeps
	// what the anchor check itself found.
	v.ChainHeadAnchored = v.ChainHeadAnchored && r.OK
}

func checkDisclosureMatrix(b *BundleV2, v *Verdict, r *ResultV2) {
	switch b.Disclosure {
	case "C":
		for i, link := range b.Chain {
			if link.Scrubbed {
				r.diverge(ErrDisclosureInconsistent, fmt.Sprintf("chain[%d].scrubbed=true under disclosure=C", i))
				return
			}
			if len(link.Data) == 0 {
				r.diverge(ErrDisclosureInconsistent, fmt.Sprintf("chain[%d].data absent under disclosure=C", i))
				return
			}
		}
		if b.WitnessDisclosure == nil {
			r.diverge(ErrDisclosureInconsistent, "witness_disclosure absent under disclosure=C")
			return
		}
	case "D":
		for i, link := range b.Chain {
			if !link.Scrubbed {
				r.diverge(ErrDisclosureInconsistent, fmt.Sprintf("chain[%d].scrubbed=false under disclosure=D", i))
				return
			}
			if len(link.Data) > 0 {
				r.diverge(ErrDisclosureInconsistent, fmt.Sprintf("chain[%d].data present under disclosure=D", i))
				return
			}
		}
		if b.WitnessDisclosure != nil {
			r.diverge(ErrDisclosureInconsistent, "witness_disclosure present under disclosure=D")
			return
		}
	default:
		r.diverge(ErrMalformedCBOR, fmt.Sprintf("disclosure=%q not in {C,D}", b.Disclosure))
		return
	}
	v.DisclosureValid = true
}

// checkTypeCCommitments runs the Type-C commitment matrix per PRD 4
// § B.1. The flag is set to true ONLY at the end, after every
// applicable check has passed (Round-4 B1 fix).
func checkTypeCCommitments(b *BundleV2, v *Verdict, r *ResultV2) {
	ok := true
	scr := b.SpartanCompressResult
	if !checkTypeCWitnessHashes(b, v, r) {
		ok = false
	}
	// The custody record states the same h_p / h_r (reef-core#76 A8).
	if !checkCustodyLaneBinding(b, v, r) {
		ok = false
	}
	// A v3 manifest's disclosed records reproduce the bound v4/v5
	// custody link's TOOL_LOG_ROOT (konareef#37, D7-XCHK).
	if !checkCustodyToolLogRoot(b, v, r) {
		ok = false
	}

	// SHA-256(manifest) == pod_hash, when manifest present.
	if len(b.Manifest) > 0 && len(b.PodHash) == 32 {
		h := sha256.Sum256(b.Manifest)
		if !bytes.Equal(h[:], b.PodHash) {
			r.diverge(ErrCommitmentMismatch, "SHA-256(manifest) != pod_hash")
			ok = false
		}
	}

	// CL-5(a) fields_root genesis-lane binding — gated on a trailer
	// version. The block fires for canonical konareef-toml/v2 AND v3
	// manifests (canon.ClaimsCommitTrailer; v3 carries the same [_commit]
	// trailer, with brokered MCP tool ids in declared_tools). A v3 manifest
	// that skipped this block would have no fields_root binding at all, so
	// the gate is a prefix test. A near-miss magic line never reaches it:
	// canon.CheckMagicLine refuses it first (below). v1 (konareef-manifest-v1) manifests
	// keep the legacy posture untouched (the existing parity corpus carries
	// a zero-h_manifest v1 manifest). The manifest binding invariant is
	// enforced here.
	//
	// A manifest that opens with a konareef-toml magic line this build does
	// not implement (for example `#!konareef-toml/v4`, or `/v1x`) is
	// refused outright. Treating it as v1 would skip both the h_manifest
	// and the fields_root bindings for a version whose commitment rules
	// are unknown here.
	//
	// A first line that is a near miss of a magic line (KR-MAGIC,
	// canon.CheckMagicLine: `#!KONAREEF-TOML/V3`, ` #!konareef-toml/v3`, a
	// BOM or blank line before the magic, ...) is refused the same way.
	// Most such lines have no exact prefix, so both tests below miss them
	// and the manifest would otherwise be verified as a legacy manifest
	// with nothing to bind.
	magicErr := canon.CheckMagicLine(b.Manifest)
	if magicErr != nil {
		r.diverge(ErrManifestMagicNearMiss, fmt.Sprintf("manifest magic line: %v", magicErr))
		ok = false
	} else if canon.HasVersionMagic(b.Manifest) && !canon.HasSupportedVersionMagic(b.Manifest) && !canon.ClaimsCommitTrailer(b.Manifest) {
		version, _ := canon.VersionIdentifier(b.Manifest)
		r.diverge(ErrFieldsRootMismatch, fmt.Sprintf("manifest version %q is not supported by this verifier", version))
		ok = false
	}
	// A near miss is already refused above; its trailer is not read.
	if magicErr == nil && canon.ClaimsCommitTrailer(b.Manifest) {
		// (a) Bind the disclosed manifest to the proof's h_manifest
		// public input: SHA-256(manifest) == h_manifest @ offset 160.
		// This ties the disclosed bytes to the proven computation (step 1
		// of the soundness chain).
		hmExpected, err := extractPublicInputStrict(scr, "h_manifest", 32)
		if err != nil {
			r.diverge(ErrCommitmentMismatch, fmt.Sprintf("h_manifest public-input carrier: %v", err))
			ok = false
		} else {
			hmActual := sha256.Sum256(b.Manifest)
			if !bytes.Equal(hmActual[:], hmExpected) {
				r.diverge(ErrCommitmentMismatch, "SHA-256(manifest) != h_manifest (public input)")
				ok = false
			}
		}

		// (b) Bind [_commit].fields_root to the carried genesis lane:
		// ParseCommitFieldsRoot(manifest) == genesis_fields_root (step 2).
		// Without this a Type-C proof is forgeable (a prover could attest
		// any fields_root).
		fr, perr := canon.ParseCommitFieldsRoot(b.Manifest)
		if perr != nil {
			r.diverge(ErrFieldsRootMismatch, fmt.Sprintf("[_commit].fields_root parse: %v", perr))
			ok = false
		} else if len(scr.GenesisFieldsRoot) != 32 {
			r.diverge(ErrFieldsRootMismatch,
				fmt.Sprintf("genesis_fields_root width=%d, want 32", len(scr.GenesisFieldsRoot)))
			ok = false
		} else if !bytes.Equal(fr[:], scr.GenesisFieldsRoot) {
			r.diverge(ErrFieldsRootMismatch, "[_commit].fields_root != genesis_fields_root")
			ok = false
		}

		// (b') Bind [_commit].fields_root to the manifest's own declared
		// fields. (b) and (c) tie the proof to the TRAILER; without this a
		// signed trailer committing a tool the manifest never declares (for
		// v3, a brokered id no grant allows) would let the circuit accept
		// records for it. A memory-bearing root cannot be recomputed without
		// the salt and is refused (commission.ErrManifestCommitmentUnverifiable).
		if perr == nil {
			if cerr := commission.CheckManifestCommitment(b.Manifest); cerr != nil {
				r.diverge(ErrFieldsRootMismatch, fmt.Sprintf("[_commit].fields_root is not reproduced by the manifest's declared fields: %v", cerr))
				ok = false
			}
		}

		// (c) Bind genesis_fields_root to the SNARK-proven z0 lane:
		// genesis_fields_root == z0[Z_FIELDS_ROOT] (step 3, MR !41
		// blocker-3 hybrid fix). The Rust verify binary absorbs the full
		// 22-lane z0 into CompressedSNARK::verify's RO hash, so z0 is
		// SNARK-proven; but the 298-byte X-assembly does NOT expose the
		// fields_root lane, so the Rust binary cannot — and explicitly does
		// not — bind genesis_fields_root to z0. That binding is owned here.
		//
		// Lane index Z_FIELDS_ROOT == 21 (PRD 1 §5.1 fold-IO lane table),
		// so the lane bytes are z0[21*32 : 22*32] == z0[672:704] (32-byte LE
		// Fq, same orientation as genesis_fields_root = fq_to_le_bytes).
		// This closes the soundness chain end-to-end:
		//   [_commit].fields_root == genesis_fields_root == z0[Z_FIELDS_ROOT]
		// where the last link is SNARK-proven. Without it a prover could
		// carry a genesis_fields_root that agrees with the disclosed manifest
		// but disagrees with what the proof actually folded over.
		//
		// z0 is MANDATORY on the canonical-v2/v3 (C0) surface: a canonical-v2
		// Type-C bundle MUST carry a present, exactly-736-byte z0 whose
		// lane 21 (Z_FIELDS_ROOT) equals genesis_fields_root. Without an
		// enforced z0 the advertised
		//   [_commit].fields_root == genesis_fields_root == z0[Z_FIELDS_ROOT]
		// chain (whose last link is SNARK-proven) is not actually mandatory:
		// a canonical-v2 bundle that simply omits z0 would otherwise still
		// pass step (b) and slip through. So we fail closed when z0 is not
		// EXACTLY 736 bytes (absent, short, or oversized — the C1 contract is
		// an exact 23-lane fold-IO vector (Z_ARITY = 23 post-CL-6); trailing
		// bytes are malformed, and the production Spartan subprocess likewise
		// requires len(z0)==736). This gate is scoped to the
		// `#!konareef-toml/v2` manifest prefix (same gate as CL-5a), so legacy
		// (`konareef-manifest-v1`) and parity fixtures that legitimately omit
		// z0 are unaffected — the gate never fires for them.
		// Z_FIELDS_ROOT is lane 21 in BOTH the 22- and 23-lane layouts
		// (paygate-zk circuit.rs), so z0[672:704] is unchanged; only the total
		// width moved 704 -> 736.
		const zFieldsRootLane = 21 // Z_FIELDS_ROOT (PRD 1 §5.1)
		const zLaneWidth = 32
		const z0FullWidth = 23 * zLaneWidth // 736
		if len(scr.Z0) != z0FullWidth {
			r.diverge(ErrFieldsRootMismatch,
				fmt.Sprintf("canonical-v2 bundle requires an exactly-%d-byte z0; got width=%d", z0FullWidth, len(scr.Z0)))
			ok = false
		} else if len(scr.GenesisFieldsRoot) == 32 {
			laneLo := zFieldsRootLane * zLaneWidth // 672
			laneHi := laneLo + zLaneWidth          // 704
			if !bytes.Equal(scr.GenesisFieldsRoot, scr.Z0[laneLo:laneHi]) {
				r.diverge(ErrFieldsRootMismatch, "genesis_fields_root != z0[Z_FIELDS_ROOT]")
				ok = false
			}
		}
		// (len(GenesisFieldsRoot) != 32 already diverged in (b) above.)
	}

	if ok {
		v.CommitmentsValid = true
	}
}

// checkTypeCWitnessHashes authenticates the disclosed P/R bytes
// against the h_p/h_r commitments in the Spartan public-input vector.
// The carriers are MANDATORY at 32-byte width (Round-4 B1 fix).
func checkTypeCWitnessHashes(b *BundleV2, v *Verdict, r *ResultV2) bool {
	if b.WitnessDisclosure == nil {
		return false
	}

	ok := true

	hpExpected, err := extractPublicInputStrict(b.SpartanCompressResult, "h_p", 32)
	if err != nil {
		r.diverge(ErrCommitmentMismatch, fmt.Sprintf("h_p public-input carrier: %v", err))
		v.CommitmentsValid = false
		ok = false
	} else {
		hpActual := sha256.Sum256(b.WitnessDisclosure.P)
		if !bytes.Equal(hpActual[:], hpExpected) {
			r.diverge(ErrCommitmentMismatch, "SHA-256(witness_disclosure.P) != h_p (public input)")
			v.CommitmentsValid = false
			ok = false
		}
	}

	hrExpected, err := extractPublicInputStrict(b.SpartanCompressResult, "h_r", 32)
	if err != nil {
		r.diverge(ErrCommitmentMismatch, fmt.Sprintf("h_r public-input carrier: %v", err))
		v.CommitmentsValid = false
		ok = false
	} else {
		hrActual := sha256.Sum256(b.WitnessDisclosure.R)
		if !bytes.Equal(hrActual[:], hrExpected) {
			r.diverge(ErrCommitmentMismatch, "SHA-256(witness_disclosure.R) != h_r (public input)")
			v.CommitmentsValid = false
			ok = false
		}
	}

	return ok
}

// publicInputsWidth is the exact width of each public-input buffer
// (PRD 1 § 4.2: sig_manifest@224 + 74 = 298).
const publicInputsWidth = 298

// agreedStepLanes lists the public-input lanes that first_step and
// last_step must carry identically, as {name, offset, width}. They are
// the lanes the Go checks read (t_root, h_p, h_r, h_manifest,
// sig_manifest) plus chain_head_hash, which sits between them. r_in and
// r_out are bound per buffer by the Rust verifier and are not read here.
var agreedStepLanes = []struct {
	name  string
	off   int
	width int
}{
	{"t_root", 64, 32},
	{"h_p", 96, 32},
	{"h_r", 128, 32},
	{"h_manifest", 160, 32},
	{"chain_head_hash", 192, 32},
	{"sig_manifest", 224, 74},
}

// checkStepLaneAgreement requires first_step_public_inputs and
// last_step_public_inputs to carry identical bytes in every lane of
// agreedStepLanes, so each lane the v2 checks read is a lane the proof
// check covers. Both buffers must be exactly publicInputsWidth bytes. A
// genuine producer builds both buffers from the same fold state, so they
// agree.
//
// Inputs: b, the decoded bundle; v, its verdict; r, its result.
// Output: true when both widths are exact and every lane agrees.
// Otherwise false: adds an ErrPublicInputLaneMismatch divergence for the
// width fault or for each differing lane (naming it), and sets
// v.CommitmentsValid=false.
func checkStepLaneAgreement(b *BundleV2, v *Verdict, r *ResultV2) bool {
	first := b.SpartanCompressResult.FirstStepPublicInputs
	last := b.SpartanCompressResult.LastStepPublicInputs
	if len(first) != publicInputsWidth || len(last) != publicInputsWidth {
		r.diverge(ErrPublicInputLaneMismatch, fmt.Sprintf(
			"public-input buffers must be %d bytes: first_step=%d last_step=%d",
			publicInputsWidth, len(first), len(last)))
		v.CommitmentsValid = false
		return false
	}
	agree := true
	for _, lane := range agreedStepLanes {
		end := lane.off + lane.width
		if !bytes.Equal(first[lane.off:end], last[lane.off:end]) {
			r.diverge(ErrPublicInputLaneMismatch, fmt.Sprintf(
				"%s lane differs between first_step and last_step", lane.name))
			v.CommitmentsValid = false
			agree = false
		}
	}
	return agree
}

// extractPublicInputStrict reads a named 32-byte commitment from the
// Spartan first-step public-input vector per PRD 1 § 4.2's offset
// table. checkStepLaneAgreement requires the lanes read here to equal
// the last_step lanes. Returns ErrCommitmentMismatch (wrapped) when the field is
// unknown OR the buffer is too short OR the read window's length is
// not exactly `requiredWidth`.
func extractPublicInputStrict(scr SpartanCompressResult, name string, requiredWidth int) ([]byte, error) {
	offsets := map[string]int{
		"r_in":            0,
		"r_out":           32,
		"t_root":          64,
		"h_p":             96,
		"h_r":             128,
		"h_manifest":      160,
		"chain_head_hash": 192,
		"sig_manifest":    224,
	}
	off, known := offsets[name]
	if !known {
		return nil, fmt.Errorf("%w: unknown public-input field %q", ErrCommitmentMismatch, name)
	}
	if len(scr.FirstStepPublicInputs) < off+requiredWidth {
		return nil, fmt.Errorf("%w: missing %s: buffer len=%d, need offset+%d=%d",
			ErrCommitmentMismatch, name, len(scr.FirstStepPublicInputs), requiredWidth, off+requiredWidth)
	}
	field := scr.FirstStepPublicInputs[off : off+requiredWidth]
	if len(field) != requiredWidth {
		return nil, fmt.Errorf("%w: short %s: width=%d, required=%d",
			ErrCommitmentMismatch, name, len(field), requiredWidth)
	}
	return field, nil
}

// checkTypeDCommitments implements the Type-D commitment matrix per
// PRD 4 § B.2. Manifest MUST be non-empty (the salt commitment is
// otherwise unsignable), pod_hash MUST be present at the canonical
// 32-byte SHA-256 width, and SHA-256(manifest) MUST equal pod_hash
// unconditionally once the length check has passed (Round-1 B1 fix).
//
// The previous implementation pre-set CommitmentsValid=true and only
// compared SHA-256(manifest) when len(pod_hash) == 32, which let bundles
// with missing/short/long pod_hash leak through with CommitmentsValid
// still true. The refactored gate is structured fail-by-default and
// only flips CommitmentsValid=true at the very end, after every check
// has passed.
func checkTypeDCommitments(b *BundleV2, v *Verdict, r *ResultV2) {
	if len(b.Manifest) == 0 {
		r.diverge(ErrCommitmentMismatch, "Type-D bundle missing manifest (pod_salt commitment unsignable)")
		v.CommitmentsValid = false
		return
	}
	if len(b.PodHash) != 32 {
		r.diverge(ErrCommitmentMismatch,
			fmt.Sprintf("Type-D pod_hash length=%d, want 32", len(b.PodHash)))
		v.CommitmentsValid = false
		return
	}
	expected := sha256.Sum256(b.Manifest)
	if !bytes.Equal(expected[:], b.PodHash) {
		r.diverge(ErrCommitmentMismatch, "SHA-256(manifest) != pod_hash (Type-D salt binding)")
		v.CommitmentsValid = false
		return
	}
	v.CommitmentsValid = true
}

// checkTLogRoot compares the recomputed T_log root against the
// `t_root` carried at PRD 1 § 4.2's pinned offset (Round-3 B2 + R4 B1).
func checkTLogRoot(b *BundleV2, v *Verdict, r *ResultV2) {
	wd := b.WitnessDisclosure
	if wd == nil {
		return
	}
	root, err := tlogRootFromRecords(wd.TLogRecords)
	if err != nil {
		r.diverge(ErrCommitmentMismatch, fmt.Sprintf("T_log root: %v", err))
		v.CommitmentsValid = false
		return
	}
	expected, err := extractPublicInputStrict(b.SpartanCompressResult, "t_root", 32)
	if err != nil {
		r.diverge(ErrCommitmentMismatch, fmt.Sprintf("t_root public-input carrier: %v", err))
		v.CommitmentsValid = false
		return
	}
	if !bytes.Equal(root, expected) {
		r.diverge(ErrCommitmentMismatch, "T_log root != t_root (public input)")
		v.CommitmentsValid = false
	}
}

// tlogRootFromRecords reconstructs the Poseidon t_root from raw
// record_bytes (PRD 1 § 5.4, post Lever-1). The records are the wire-form
// per-record encodings; poseidon.TRoot folds each into a leaf, builds the
// Z-padded balanced Poseidon tree, and binds the count via the 0x03 length
// element — identical to internal/tlog.TRootFromRows over the same bytes.
// Records or counts beyond the pinned circuit caps return an error (the
// caller diverges fail-closed; such a log could not have been proven).
func tlogRootFromRecords(records [][]byte) ([]byte, error) {
	root, err := poseidon.Default().TRoot(records)
	if err != nil {
		return nil, err
	}
	return root[:], nil
}

// checkPublicInputSignature implements PRD 3 §11.2 Check 4: verify the
// public-input sig_manifest over the PROOF-BOUND h_manifest (CL-6) under
// the carried pk_pub, out-of-circuit. Runs for konareef-pod-step-v1
// regardless of attestation-envelope presence (the §4 erratum).
//
// CL-6 manifest-binding precondition (disclosure-mode-agnostic, MR !30):
// a valid ECDSA over h_manifest is necessary but NOT sufficient. When a
// manifest is disclosed, the signed h_manifest lane
// (first_step_public_inputs[160:192]) MUST equal SHA-256(b.Manifest);
// otherwise the signature attests an h_manifest detachable from the
// disclosed bytes. Previously this binding lived only in the v2-gated
// CL-5a block of checkTypeCCommitments (Type-C #!konareef-toml/v2 only),
// leaving Type-D and non-v2 Type-C paths unprotected. It is now enforced
// HERE, in the sole signature-validity authority, for every disclosure
// mode — so it cannot be bypassed via disclosure mode or manifest dialect.
//
// pk_pub MUST be present: konareef-pod-step-v1 always carries sig_manifest
// in the public-input vector, so an absent pk_pub leaves the mandatory
// signature claim unverifiable. signature_valid is NEVER n/a for this
// circuit (PRD 1 §4 erratum / PRD 3 §11.2). A bundle that omits pk_pub
// falls through to the len != 33 check below, diverges ErrSignatureInvalid,
// and leaves SignatureValid=false (fail-closed).
//
// Normative reasons: padding_invalid, strict_der_invalid, high_s, rs_out_of_range,
// signature_mismatch, manifest_unbound.
func checkPublicInputSignature(b *BundleV2, v *Verdict, r *ResultV2) {
	scr := b.SpartanCompressResult

	hManifest, err := extractPublicInputStrict(scr, "h_manifest", 32)
	if err != nil {
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("h_manifest carrier: %v", err))
		return
	}

	// CL-6 manifest-binding precondition (MR !30) — disclosure-mode- AND
	// dialect-agnostic. Whenever a manifest is disclosed, the proof-bound
	// h_manifest MUST be its SHA-256; otherwise the verified signature attests
	// an h_manifest detachable from the disclosed bytes. This is the sole
	// signature-validity authority and runs for every disclosure mode and every
	// manifest dialect (Type-C/Type-D, v2 or non-v2) — NOT gated on the
	// `#!konareef-toml/v2` prefix. A non-v2 / envelope-absent bundle that
	// discloses a manifest whose SHA-256 ≠ the signed h_manifest MUST fail
	// closed here (Hermes !33 blocker 2). The v2-gated CL-5a commitments block
	// is a separate, additional binding; this one does not depend on it.
	if len(b.Manifest) > 0 {
		hmActual := sha256.Sum256(b.Manifest)
		if !bytes.Equal(hmActual[:], hManifest) {
			r.diverge(ErrSignatureInvalid,
				"reason=manifest_unbound: signed h_manifest != SHA-256(disclosed manifest)")
			return
		}
	}
	padded, err := extractPublicInputStrict(scr, "sig_manifest", 74)
	if err != nil {
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("sig_manifest carrier: %v", err))
		return
	}

	// Decode the 74-byte padded envelope: [derLen byte][DER bytes][zero pad].
	// Accept any nonzero DER length that fits the lane; do NOT impose a [70,73]
	// window — a minimally-encoded secp256k1 strict-DER signature can be < 70
	// bytes (e.g. 69 when one of r/s is a 31-byte minimal INTEGER). The strict
	// structural/low-S/range validation is identity.ParseStrict's job below.
	derLen := int(padded[0])
	if derLen == 0 || 1+derLen > len(padded) {
		r.diverge(ErrSignatureInvalid, "reason=padding_invalid: bad sig_manifest length prefix")
		return
	}
	for _, pb := range padded[1+derLen:] {
		if pb != 0 {
			r.diverge(ErrSignatureInvalid, "reason=padding_invalid: non-zero padding in sig_manifest")
			return
		}
	}
	der := padded[1 : 1+derLen]

	if len(scr.PkPub) != 33 {
		r.diverge(ErrSignatureInvalid,
			fmt.Sprintf("reason=signature_mismatch: pk_pub len=%d, want 33", len(scr.PkPub)))
		return
	}

	// Check 4 strict-DER + low-S + range gate — UNCONDITIONAL per PRD 1 §4 /
	// PRD 3 §11.2. This is a NEW MANDATORY check and must NOT be gated on
	// identity.StrictDerGateEnabled, which is scoped to the legacy Verify /
	// VerifyRotationSignature rotation path only. Every conforming verifier
	// MUST enforce strict-DER, low-S, and r,s ∈ [1,n-1] for Check 4
	// regardless of runtime configuration.
	if _, _, strictErr := identity.ParseStrict(der); strictErr != nil {
		reason := identity.ClassifyStrictError(der)
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("reason=%s: %v", reason, strictErr))
		return
	}

	// VerifyDigest verifies directly over the raw hManifest digest — no
	// re-hash. ParseStrict above has already enforced strict-DER + low-S;
	// VerifyDigest checks the ECDSA relation. StrictDerGateEnabled may
	// cause VerifyDigest to re-run ParseStrict on the same bytes, which is
	// harmless (idempotent and fast).
	ok, err := identity.VerifyDigest(hex.EncodeToString(scr.PkPub), hManifest, der)
	if err != nil {
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("reason=strict_der_invalid: %v", err))
		return
	}
	if !ok {
		r.diverge(ErrSignatureInvalid, "reason=signature_mismatch: ECDSA relation failed over h_manifest")
		return
	}

	v.SignatureValid = true
	v.PublisherIdentityStatus = PISSelfSigned
}

// checkAttestationV2 runs the PRD 3 §11.2 envelope cross-checks. The
// signature VALIDITY itself is established by checkPublicInputSignature
// (Check 4) — the envelope publisher_signature is the SAME ECDSA signature
// as the public-input sig_manifest (one signature, two encodings; PRD 3
// §11.2), over pod_hash == h_manifest. This function only cross-checks the
// envelope fields against the public-input vector and assigns the publisher
// identity status.
//
// SignatureValid ownership: checkPublicInputSignature (Check 4) is the SOLE
// authority for v.SignatureValid and must run before this function. This
// function does NOT touch v.SignatureValid.
//
// Behaviour:
//   - no envelope + Check 4 passed → status=PISUnbound (no envelope identity
//     claim, but the bare public-input signature is valid).
//   - no envelope + Check 4 failed → status=PISSignatureInvalid. Per PRD 3
//     §11.3, signature_invalid takes precedence over unbound and applies
//     whether or not the envelope is present (unbound REQUIRES signature_valid).
//   - envelope present, all cross-checks pass, SignatureValid=true → PISBound
//     (the envelope confirms identity; upgrades PISSelfSigned from Check 4).
//   - envelope present, all cross-checks pass, SignatureValid=false →
//     PISSignatureInvalid (Check 4 failed; identity claim is unverifiable).
//   - envelope present, any byte cross-check mismatch → diverge
//     ErrAttestationMismatch, status=PISMismatch (PRD 3 §11.2/§12.3:
//     envelope byte mismatches are ERR_ATTESTATION_MISMATCH, NOT
//     ERR_SIGNATURE_INVALID — the latter is reserved for Check 4 failures).
func checkAttestationV2(b *BundleV2, v *Verdict, r *ResultV2) {
	envelopePresent := len(b.PublisherSignature) > 0 || len(b.PublisherPubkey) > 0
	if !envelopePresent {
		// No envelope. Per PRD 3 §11.3, unbound REQUIRES a valid Check 4 and
		// signature_invalid takes precedence regardless of envelope presence:
		// a failed Check 4 (SignatureValid=false) is reported as
		// signature_invalid, not unbound. A passing Check 4 with no envelope is
		// validly self-signed but envelope-unbound.
		if v.SignatureValid {
			v.PublisherIdentityStatus = PISUnbound
		} else {
			v.PublisherIdentityStatus = PISSignatureInvalid
		}
		return
	}

	scr := b.SpartanCompressResult
	pkPub := scr.PkPub

	// A malformed public-input carrier is a Check-4-domain failure (the same
	// carrier checkPublicInputSignature classifies as ERR_SIGNATURE_INVALID, and
	// it has already diverged on it). It is NOT an envelope BYTE mismatch, so the
	// status is signature_invalid (which §11.3 gives precedence over mismatch),
	// keeping the error code and status internally consistent.
	hManifest, err := extractPublicInputStrict(scr, "h_manifest", 32)
	if err != nil {
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("envelope: h_manifest carrier: %v", err))
		v.PublisherIdentityStatus = PISSignatureInvalid
		return
	}
	padded, err := extractPublicInputStrict(scr, "sig_manifest", 74)
	if err != nil {
		r.diverge(ErrSignatureInvalid, fmt.Sprintf("envelope: sig_manifest carrier: %v", err))
		v.PublisherIdentityStatus = PISSignatureInvalid
		return
	}

	// Cross-check 1: publisher_pubkey == pk_pub (byte-equal, 33 B, §11.2 :600-603).
	// A byte mismatch is ERR_ATTESTATION_MISMATCH / mismatch (PRD 3 §11.2/§12.3),
	// NOT ERR_SIGNATURE_INVALID (reserved for Check 4 crypto/pk_pub failures).
	if len(b.PublisherPubkey) == 0 || !bytes.Equal(b.PublisherPubkey, pkPub) {
		r.diverge(ErrAttestationMismatch, "envelope publisher_pubkey != pk_pub")
		v.PublisherIdentityStatus = PISMismatch
		return
	}

	// Cross-check 2: pod_hash == h_manifest (byte-equal, 32 B, §11.2 :611).
	if len(b.PodHash) != 32 || !bytes.Equal(b.PodHash, hManifest) {
		r.diverge(ErrAttestationMismatch, "envelope pod_hash != public-input h_manifest")
		v.PublisherIdentityStatus = PISMismatch
		return
	}

	// Cross-check 3: publisher_signature == DER(sig_manifest) (byte-equal
	// after unpadding the 74-byte form, §11.2 :616-621).
	// padded layout: [derLen byte][DER bytes][zero pad to 74]. Accept any
	// nonzero DER length that fits the lane (a valid strict-DER secp256k1
	// signature can be < 70 bytes); the length itself is validated in Check 4.
	derLen := int(padded[0])
	if derLen > 0 && 1+derLen <= len(padded) {
		der := padded[1 : 1+derLen]
		if !bytes.Equal(b.PublisherSignature, der) {
			r.diverge(ErrAttestationMismatch, "envelope publisher_signature != DER(sig_manifest)")
			v.PublisherIdentityStatus = PISMismatch
			return
		}
	}

	// All cross-checks passed. Identity is PISBound ONLY when Check 4 also
	// validated the signature (v.SignatureValid=true). If Check 4 failed,
	// the envelope fields are consistent but the proof-bound sig is invalid —
	// report PISSignatureInvalid.
	if v.SignatureValid {
		v.PublisherIdentityStatus = PISBound
	} else {
		v.PublisherIdentityStatus = PISSignatureInvalid
	}
}

// checkVkey runs the § 6 vkey resolution.
func checkVkey(b *BundleV2, opts VerifyOptions, _ *Verdict, r *ResultV2) {
	switch {
	case len(b.Vkey) > 0:
		h := sha256.Sum256(b.Vkey)
		if !bytes.Equal(h[:], b.SpartanCompressResult.VkeyHash) {
			r.diverge(ErrVkeyMismatch, "SHA-256(vkey) != vkey_hash")
		}
	case b.VkeyAnchor != nil:
		// Anchor resolution out of scope for P1.2 unit tests.
	default:
		if opts.Durable {
			r.diverge(ErrVkeyUnavailable, "no vkey or vkey_anchor under --durable")
		}
	}
}

// Chain-policy modes. PRD 3 fixes the chain rule by the disclosure tag:
// Type C gets the full hash chain (§ 7.3 rule 1) and Type D gets the
// adjacency/anchor rule (§ 7.2). § 11.1 requires the verdict to report
// the two modes distinctly.
const (
	chainModeFullHashChain   = "full_hash_chain"
	chainModeAdjacencyAnchor = "adjacency_anchor"
)

// requiredChainPolicyMode returns the chain-policy mode that PRD 3
// requires for a disclosure tag.
//
// Input: the bundle's disclosure tag.
// Output: "full_hash_chain" for "C", "adjacency_anchor" for "D", and ""
// for any other value (checkDisclosureMatrix refuses those bundles).
func requiredChainPolicyMode(disclosure string) string {
	switch disclosure {
	case "C":
		return chainModeFullHashChain
	case "D":
		return chainModeAdjacencyAnchor
	}
	return ""
}

// checkChainPolicy evaluates the chain-continuity constraints of PRD 3
// § 7.2 (Type D) and § 7.3 rule 1 (Type C) and sets v.ChainPolicyValid.
//
// The disclosure tag selects the mode. The bundle's own
// `chain_policy_mode` key is not a PRD 3 wire field: it is accepted only
// when it names the mode the disclosure requires. A bundle that declares
// any other mode is refused with ErrChainBroken (R2b). Otherwise a Type-C
// bundle could declare adjacency_anchor and report a weaker rule than
// its disclosure promises, and a Type-D bundle could claim a full hash
// chain that it cannot show. The required mode still runs after a
// mismatch, so the divergence list stays complete.
//
// Both modes check adjacency: for every non-genesis link i,
// chain[i].prev_hash MUST equal chain[i-1].hash (§ 7.2 rule 1, § 7.3
// rule 1). adjacency_anchor also requires a chain head hash. The Type-C
// per-link hash recompute is checkTypeCLinkHashes, and the bsv_txids
// cross-reference is checkChainAnchors.
//
// A chain whose first link carries a prev_hash starts mid-chain (reef-core
// walks back at most 32 links). It is valid, and v.ChainTruncated reports
// it (PRD 3 § 8.1 amendment, R2b D2).
//
// Nothing here binds the chain head to a value outside the bundle. PRD 1
// § 5.1 has no chain-head public input, and the chain_head_hash slot of
// the public-input buffer is zero-filled and not proof-bound. A sender
// that rewrites the chain and re-hashes it still passes, so
// chain_policy_valid means "self-consistent", not "tamper-evident". The
// separate chain-head anchor check (checkChainHeadAnchor, reef-core#76)
// is what can set v.ChainHeadAnchored.
//
// Inputs: b, the decoded bundle; v, its verdict; r, its result.
// Output: none. Sets v.ChainPolicyMode and v.ChainPolicyValid, and adds
// an ErrChainBroken divergence for each fault found. For an unknown
// disclosure it sets ChainPolicyValid to false and adds nothing:
// checkDisclosureMatrix reports that fault.
func checkChainPolicy(b *BundleV2, v *Verdict, r *ResultV2) {
	mode := requiredChainPolicyMode(b.Disclosure)
	if mode == "" {
		// Unknown disclosure: checkDisclosureMatrix has already failed the
		// bundle. No chain rule applies, so the chain policy cannot pass;
		// a sender-chosen mode must not show as a passed check.
		v.ChainPolicyMode = b.ChainPolicyMode
		v.ChainPolicyValid = false
		return
	}
	v.ChainPolicyMode = mode
	v.ChainPolicyValid = true

	if b.ChainPolicyMode != "" && b.ChainPolicyMode != mode {
		r.diverge(ErrChainBroken, fmt.Sprintf(
			"chain_policy_mode=%q but disclosure=%q requires %q", b.ChainPolicyMode, b.Disclosure, mode))
		v.ChainPolicyValid = false
	}

	if len(b.Chain) == 0 {
		r.diverge(ErrChainBroken, "chain is empty")
		v.ChainPolicyValid = false
		return
	}
	// A first link with a prev_hash means the bundle starts mid-chain.
	// That is valid but is reported (PRD 3 § 8.1 amendment, R2b D2).
	v.ChainTruncated = len(b.Chain[0].PrevHash) != 0

	switch mode {
	case chainModeFullHashChain, chainModeAdjacencyAnchor:
		if mode == chainModeAdjacencyAnchor && len(b.Chain[len(b.Chain)-1].Hash) == 0 {
			r.diverge(ErrChainBroken, "chain head hash missing under adjacency_anchor")
			v.ChainPolicyValid = false
			return
		}
		for i := 1; i < len(b.Chain); i++ {
			prev := b.Chain[i-1]
			cur := b.Chain[i]
			if len(cur.PrevHash) == 0 {
				r.diverge(ErrChainBroken, fmt.Sprintf("chain[%d].prev_hash missing under %s", i, mode))
				v.ChainPolicyValid = false
				return
			}
			if !bytes.Equal(cur.PrevHash, prev.Hash) {
				r.diverge(ErrChainBroken, fmt.Sprintf("chain[%d].prev_hash != chain[%d].hash", i, i-1))
				v.ChainPolicyValid = false
				return
			}
		}
	default:
		r.diverge(ErrChainBroken, fmt.Sprintf("unknown chain_policy_mode=%q", mode))
		v.ChainPolicyValid = false
	}
}

// checkChainAnchors cross-references the bundle's BSV anchors against its
// chain, per PRD 3 § 7.2 rule 2 and § 8.4. The anchors are not
// recomputed: the check does not look up a transaction.
//
// Rules:
//   - every bsv_txids key MUST be the lowercase hex of some chain link's
//     hash;
//   - a link whose txid is set and whose hash has a bsv_txids entry MUST
//     carry the same txid as that entry.
//
// This only proves that the two anchor records in the bundle agree with
// each other. Both are optional, so a sender can drop them, and a
// matching pair still says nothing about what the transaction holds.
//
// Inputs: b, the decoded bundle; v, its verdict; r, its result.
// Output: none. On a fault it adds an ErrChainBroken divergence and sets
// v.ChainPolicyValid to false.
func checkChainAnchors(b *BundleV2, v *Verdict, r *ResultV2) {
	// A hash can repeat in a malformed chain, so keep every link for it.
	linksByHash := make(map[string][]*ChainLinkV2, len(b.Chain))
	for i := range b.Chain {
		k := hex.EncodeToString(b.Chain[i].Hash)
		linksByHash[k] = append(linksByHash[k], &b.Chain[i])
	}
	keys := make([]string, 0, len(b.BsvTxids))
	for k := range b.BsvTxids {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		links, ok := linksByHash[k]
		if !ok {
			r.diverge(ErrChainBroken, fmt.Sprintf(
				"bsv_txids key %q references no chain link (keys are lowercase hex)", k))
			v.ChainPolicyValid = false
			continue
		}
		for _, link := range links {
			if link.Txid != "" && link.Txid != b.BsvTxids[k] {
				r.diverge(ErrChainBroken, fmt.Sprintf(
					"chain link %s (%s): txid %q != bsv_txids entry %q", k, link.ProofType, link.Txid, b.BsvTxids[k]))
				v.ChainPolicyValid = false
			}
		}
	}
}

// checkTypeCLinkHashes recomputes the hash of every link in a Type-C
// chain and reports a divergence for each link whose stored hash differs.
//
// A Type-C bundle carries each link's data verbatim, and reef-core hashes
// a link as SHA-256(prev_hash || data || timestamp) (ReefCore.Proofs.Hash,
// the same rule as v1). The chain policy checks only prev_hash continuity,
// so without this check a link whose data was changed after the chain was
// written verified with no divergence (MCP-K04 residual R2).
//
// A link with no data is skipped: checkDisclosureMatrix already refuses it
// (ErrDisclosureInconsistent), so a second divergence would add nothing.
//
// Inputs: b, the decoded Type-C bundle; v, its verdict; r, its result.
// Output: none. On a mismatch it adds an ErrChainBroken divergence and
// sets v.ChainPolicyValid to false.
func checkTypeCLinkHashes(b *BundleV2, v *Verdict, r *ResultV2) {
	for i := range b.Chain {
		link := &b.Chain[i]
		if len(link.Data) == 0 {
			continue
		}
		// reef-core's prev_hash is always a 32-byte stored hash or absent.
		// ComputeChainHash drops any other width, so without this a genesis
		// link's prev_hash could be changed freely and still recompute.
		if len(link.PrevHash) != 0 && len(link.PrevHash) != 32 {
			r.diverge(ErrChainBroken, fmt.Sprintf(
				"chain[%d] (%s): prev_hash length %d, want 32 or absent", i, link.ProofType, len(link.PrevHash)))
			v.ChainPolicyValid = false
			continue
		}
		got := ComputeChainHash(hex.EncodeToString(link.PrevHash), string(link.Data), link.Timestamp)
		if !bytes.Equal(got[:], link.Hash) {
			r.diverge(ErrChainBroken, fmt.Sprintf(
				"chain[%d] (%s): recomputed hash %s != stored %s",
				i, link.ProofType, hex.EncodeToString(got[:]), hex.EncodeToString(link.Hash)))
			v.ChainPolicyValid = false
		}
	}
}

// assessCustodyV2 returns the broker assurance of a v2 bundle's custody
// record.
//
// The v2 chain policy checks prev_hash continuity, checkTypeCLinkHashes
// recomputes Type-C link hashes, and a Type-D bundle carries no link data
// to recompute. Nothing in a v2
// bundle anchors the chain either (the chain-head public input is not
// bound). So the best a v2 bundle can show is an unanchored claim, and
// only when:
//
//   - the chain has exactly one custody link and it is the tail, as in
//     v1 and reef-core; otherwise not_verified;
//   - the link carries data and its hash recomputes from it
//     (SHA-256(prev_hash || data || timestamp), as in v1); otherwise
//     not_verified. The custody rules are not applied to data that is not
//     bound to the link, so no ErrCustodyRecordInvalid is added. For a
//     Type-C bundle, checkTypeCLinkHashes has already reported the
//     mismatch as ErrChainBroken;
//   - the whole bundle verified; otherwise not_verified.
//
// Data whose hash recomputes and that fails a custody rule is refused,
// with an ErrCustodyRecordInvalid divergence and CommitmentsValid=false.
// VerifyV2 and VerifyV2ProductionWithAnchor both call this function, so
// the two paths report the same assessment for the same bundle
// (LIVE-CUSTODY, konareef#38). For a konareef-toml/v3 Type-C bundle,
// checkCustodyToolLogRoot has run before it and may already have refused
// the record with ErrCustodyLinkUnbound; the rules then add their own
// ErrCustodyRecordInvalid, as separate divergences.
// A v5 record reaches at most BrokerAssuranceContainedRootUnchecked. For
// a konareef-toml/v3 manifest, checkCustodyToolLogRoot has already
// recomputed the SHA-256 custody root over the disclosed T_log_records
// and refused a mismatch, but a bundle-only check does not anchor the
// link it compared against, so the level is not raised. The SHA-256
// custody root and the Poseidon t_root are never compared.
//
// Inputs: b, the decoded bundle; r, its result after every check ran.
// Output: the assessment.
func assessCustodyV2(b *BundleV2, r *ResultV2) CustodyAssessment {
	notVerified := CustodyAssessment{Assurance: BrokerAssuranceNotVerified}
	custodyLinks := 0
	for i := range b.Chain {
		if b.Chain[i].ProofType == "custody" {
			custodyLinks++
		}
	}
	if custodyLinks != 1 || b.Chain[len(b.Chain)-1].ProofType != "custody" {
		return notVerified
	}
	link := &b.Chain[len(b.Chain)-1]
	if len(link.Data) == 0 {
		return notVerified
	}
	got := ComputeChainHash(hex.EncodeToString(link.PrevHash), string(link.Data), link.Timestamp)
	if len(link.Hash) != 32 || !bytes.Equal(got[:], link.Hash) {
		return notVerified
	}
	a := AssessCustodyBlob(string(link.Data), r.OK)
	if a.Assurance == BrokerAssuranceRefused {
		if r.V2Verdict != nil {
			r.V2Verdict.CommitmentsValid = false
		}
		r.diverge(ErrCustodyRecordInvalid, fmt.Sprintf("custody commitment: %s", CustodyRuleCode(a.RuleErr)))
	}
	return a
}

// errorsIsCommitmentMismatch returns true iff any of the result's
// recorded divergences wraps ErrCommitmentMismatch.
func errorsIsCommitmentMismatch(r *ResultV2) bool {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrCommitmentMismatch) {
			return true
		}
	}
	return false
}

// _ keeps cbor import live (used by Marshal in tests).
var _ = cbor.Marshal
