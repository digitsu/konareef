// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// admission_v1_reference_test.go — a TEST-ONLY reference for the proposed
// server-enforced commission admission contract,
// docs/design/commission-admission-contract.md (IB-00, konareef#20).
//
// Nothing here is production code and nothing here is approved. The file
// exists so that the contract's decision order and refusal codes are
// executable, and so that IB-04 (reef-core#51, the Elixir strict decoder
// and verifier) and IB-06 (konareef#22, CLI submit) have one shared set of
// vectors to reproduce: testdata/admission_v1/vectors.json.
//
// The reference has four parts:
//
//   - a strict, bounded CBOR reader for the two byte formats the contract
//     defines (the wire envelope and the signed canonical proposal);
//   - admitV1Reference, which applies the contract's checks in the
//     normative order and returns the first refusal code, or an admit
//     verdict with the per-dimension status;
//   - claimLedger, a model of the single-use claim and idempotent-replay
//     rules, driven by the fixture's "sequences";
//   - buildAdmissionVectors, which regenerates the fixture from fixed
//     inputs. TestAdmissionV1VectorsAreCurrent fails when the committed
//     fixture differs from what the generator produces, and
//     KONAREEF_UPDATE_ADMISSION_VECTORS=1 rewrites it.
//
// The private keys in the fixture are derived from fixed public labels.
// They are test keys, they protect nothing, and they must never be
// registered on any server.
package commission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/text/unicode/norm"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
)

// ── Contract constants (proposed; see the design doc §5 and §6) ──────────

const (
	// admissionContractID names this contract in requests and receipts.
	admissionContractID = "konareef-commission-admission/v1"
	// limitedModeID is the only assurance mode v1 defines (design doc §10).
	limitedModeID = "memory_free_limited/v1"
	// wireVersionV1 is the value of wire key 1.
	wireVersionV1 = 1

	maxWireBytes     = 32768
	maxProseBytes    = 16384
	maxPodRefBytes   = 256
	maxElementBytes  = 256
	maxModelElements = 64
	maxToolElements  = 256
	maxLabelElements = 256
	maxSigBytes      = 72
	minSigBytes      = 8
)

// rInitV1Hex is E20, the Poseidon empty-tree root that konareef-rinit/v1
// (docs/reference/konareef-memory-root-v1-spec.md §7.1, owner decision D1 = A)
// makes the memory-free r_init. Copied from
// internal/membridge/testdata/rinit_v1/fixtures.json "memory_free".
const rInitV1Hex = "c5a959b0cf2043a38c6c75e8f05b0f809bbfdc2ce2e2bbf1f7821d7d1de9d727"

// ── Strict CBOR reader ───────────────────────────────────────────────────

// errMalformed marks a structural CBOR fault. Every such fault maps to the
// single refusal code commission_malformed.
type errMalformed struct{ why string }

func (e errMalformed) Error() string { return "malformed: " + e.why }

// errTooLarge marks a value that decodes but exceeds a contract limit.
type errTooLarge struct{ why string }

func (e errTooLarge) Error() string { return "too large: " + e.why }

// strictReader reads the deterministic CBOR subset this contract allows:
// unsigned integers, byte strings, text strings, arrays, maps and the
// simple value null, all with definite lengths and minimal-length heads.
// Input: the bytes to read. It never allocates more than the remaining
// input length for any string, so a hostile length cannot exhaust memory.
type strictReader struct {
	b   []byte
	pos int
}

// head reads one initial byte plus argument. It refuses indefinite
// lengths, reserved additional-information values and non-minimal
// arguments. Output: major type (0..7) and argument.
func (r *strictReader) head() (byte, uint64, error) {
	if r.pos >= len(r.b) {
		return 0, 0, errMalformed{"unexpected end of input"}
	}
	ib := r.b[r.pos]
	r.pos++
	major, ai := ib>>5, ib&0x1f
	var n int
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	default:
		return 0, 0, errMalformed{fmt.Sprintf("additional information %d (indefinite or reserved)", ai)}
	}
	if r.pos+n > len(r.b) {
		return 0, 0, errMalformed{"truncated argument"}
	}
	var v uint64
	for _, c := range r.b[r.pos : r.pos+n] {
		v = v<<8 | uint64(c)
	}
	r.pos += n
	minimal := (n == 1 && v >= 24) || (n == 2 && v > 0xff) || (n == 4 && v > 0xffff) || (n == 8 && v > 0xffffffff)
	if !minimal {
		return 0, 0, errMalformed{"non-minimal integer or length head"}
	}
	return major, v, nil
}

// expect reads a head and refuses any major type other than want.
func (r *strictReader) expect(want byte) (uint64, error) {
	major, arg, err := r.head()
	if err != nil {
		return 0, err
	}
	if major != want {
		return 0, errMalformed{fmt.Sprintf("major type %d, want %d", major, want)}
	}
	return arg, nil
}

// uint reads an unsigned integer (major type 0). A bignum tag or a
// negative integer is refused as malformed.
func (r *strictReader) uint() (uint64, error) { return r.expect(0) }

// bytesN reads a byte string whose length is at most limit.
func (r *strictReader) bytesN(limit int) ([]byte, error) {
	n, err := r.expect(2)
	if err != nil {
		return nil, err
	}
	return r.take(n, limit)
}

// bytesExact reads a byte string that must be exactly n bytes long. A
// wrong length is a structural fault (malformed), never "too large".
func (r *strictReader) bytesExact(n int) ([]byte, error) {
	got, err := r.expect(2)
	if err != nil {
		return nil, err
	}
	if got != uint64(n) {
		return nil, errMalformed{fmt.Sprintf("fixed-size byte string of %d bytes, want %d", got, n)}
	}
	return r.take(got, n)
}

// text reads a UTF-8 text string whose length is at most limit bytes.
func (r *strictReader) text(limit int) (string, error) {
	n, err := r.expect(3)
	if err != nil {
		return "", err
	}
	raw, err := r.take(n, limit)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", errMalformed{"text string is not valid UTF-8"}
	}
	return string(raw), nil
}

// take returns the next n bytes. A declared length beyond the remaining
// input is malformed; one within the input but beyond limit is too large.
func (r *strictReader) take(n uint64, limit int) ([]byte, error) {
	if n > uint64(len(r.b)-r.pos) {
		return nil, errMalformed{"string length exceeds input"}
	}
	if n > uint64(limit) {
		return nil, errTooLarge{fmt.Sprintf("string of %d bytes exceeds limit %d", n, limit)}
	}
	out := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

// mapOf reads a map head of exactly n entries. The caller then reads each
// key with key(); keys must appear in ascending order, which also refuses
// duplicate and unknown keys.
func (r *strictReader) mapOf(n int) error {
	got, err := r.expect(5)
	if err != nil {
		return err
	}
	if got != uint64(n) {
		return errMalformed{fmt.Sprintf("map has %d entries, want %d", got, n)}
	}
	return nil
}

// key reads one integer map key and refuses any value other than want.
func (r *strictReader) key(want uint64) error {
	k, err := r.uint()
	if err != nil {
		return err
	}
	if k != want {
		return errMalformed{fmt.Sprintf("map key %d, want %d (unknown, duplicate or out of order)", k, want)}
	}
	return nil
}

// stringSet reads a set dimension: null (the stated-empty set) or a
// non-empty array of text strings, at most maxElems of them. Ordering,
// duplicates and the empty-array spelling are left to the re-encode check
// in decodeCanonicalV1, which is what makes them "noncanonical" rather
// than "malformed".
func (r *strictReader) stringSet(maxElems int) ([]string, error) {
	if r.pos < len(r.b) && r.b[r.pos] == 0xf6 {
		r.pos++
		return nil, nil
	}
	n, err := r.expect(4)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)-r.pos) {
		return nil, errMalformed{"array length exceeds input"}
	}
	if n > uint64(maxElems) {
		return nil, errTooLarge{fmt.Sprintf("set of %d elements exceeds limit %d", n, maxElems)}
	}
	out := make([]string, 0, n)
	for i := uint64(0); i < n; i++ {
		s, err := r.text(maxElementBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	// A present-but-empty array decodes to a non-nil empty slice, so the
	// re-encode check sees it differ from Go's null spelling.
	return out, nil
}

// wireV1 is the decoded wire envelope (design doc §5.2).
type wireV1 struct {
	canonical []byte
	pubKey    []byte
	sig       []byte
}

// decodeWireV1 decodes the wire envelope strictly. Output: the three
// parts, or a refusal code.
func decodeWireV1(b []byte) (wireV1, string) {
	if len(b) > maxWireBytes {
		return wireV1{}, "commission_too_large"
	}
	r := &strictReader{b: b}
	var w wireV1
	err := func() error {
		// The version is read before the entry count is enforced, so a
		// future envelope with a different shape is reported as an
		// unsupported version rather than as malformed.
		n, err := r.expect(5)
		if err != nil {
			return err
		}
		if err := r.key(1); err != nil {
			return err
		}
		v, err := r.uint()
		if err != nil {
			return err
		}
		if v != wireVersionV1 {
			return errVersion{}
		}
		if n != 4 {
			return errMalformed{fmt.Sprintf("wire map has %d entries, want 4", n)}
		}
		if err := r.key(2); err != nil {
			return err
		}
		if w.canonical, err = r.bytesN(maxWireBytes); err != nil {
			return err
		}
		if err := r.key(3); err != nil {
			return err
		}
		if w.pubKey, err = r.bytesExact(33); err != nil {
			return err
		}
		if w.pubKey[0] != 0x02 && w.pubKey[0] != 0x03 {
			return errMalformed{"public key is not a 33-byte compressed point encoding"}
		}
		if err := r.key(4); err != nil {
			return err
		}
		if w.sig, err = r.bytesN(maxSigBytes); err != nil {
			return err
		}
		if len(w.sig) < minSigBytes {
			return errMalformed{"signature too short"}
		}
		if r.pos != len(b) {
			return errMalformed{"trailing bytes after the wire map"}
		}
		return nil
	}()
	if err != nil {
		return wireV1{}, codeFor(err)
	}
	return w, ""
}

// errVersion marks an unsupported wire version.
type errVersion struct{}

func (errVersion) Error() string { return "unsupported wire version" }

// codeFor maps a decode error to its refusal code.
func codeFor(err error) string {
	switch err.(type) {
	case errTooLarge:
		return "commission_too_large"
	case errVersion:
		return "commission_version_unsupported"
	default:
		return "commission_malformed"
	}
}

// decodeCanonicalV1 decodes the signed canonical proposal strictly, then
// re-encodes it with Proposal.Canonical and requires byte equality.
// Output: the proposal (all four presence flags set, because the canonical
// form carries every dimension and null means "stated empty"), or a
// refusal code.
func decodeCanonicalV1(b []byte) (Proposal, string) {
	r := &strictReader{b: b}
	var p Proposal
	err := func() error {
		var err error
		if err = r.mapOf(6); err != nil {
			return err
		}
		if err = r.key(1); err != nil {
			return err
		}
		if p.Envelope.Models, err = r.stringSet(maxModelElements); err != nil {
			return err
		}
		if err = r.key(2); err != nil {
			return err
		}
		if p.Envelope.Tools, err = r.stringSet(maxToolElements); err != nil {
			return err
		}
		if err = r.key(3); err != nil {
			return err
		}
		if p.Envelope.Labels, err = r.stringSet(maxLabelElements); err != nil {
			return err
		}
		if err = r.key(4); err != nil {
			return err
		}
		if p.Envelope.CMax, err = r.uint(); err != nil {
			return err
		}
		if err = r.key(5); err != nil {
			return err
		}
		n, err := r.expect(5)
		if err != nil {
			return err
		}
		if n != 2 && n != 3 {
			return errMalformed{"binding map must have 2 or 3 entries"}
		}
		if err = r.key(1); err != nil {
			return err
		}
		if p.Binding.PodRef, err = r.text(maxPodRefBytes); err != nil {
			return err
		}
		if err = r.key(2); err != nil {
			return err
		}
		hm, err := r.bytesExact(32)
		if err != nil {
			return err
		}
		copy(p.Binding.HManifest[:], hm)
		if n == 3 {
			if err = r.key(3); err != nil {
				return err
			}
			fr, err := r.bytesExact(32)
			if err != nil {
				return err
			}
			var pin [32]byte
			copy(pin[:], fr)
			p.Binding.FieldsRoot = &pin
		}
		if err = r.key(6); err != nil {
			return err
		}
		if p.Prose, err = r.text(maxProseBytes); err != nil {
			return err
		}
		if r.pos != len(b) {
			return errMalformed{"trailing bytes after the canonical map"}
		}
		return nil
	}()
	if err != nil {
		return Proposal{}, codeFor(err)
	}
	p.Envelope.ModelsSet, p.Envelope.ToolsSet, p.Envelope.LabelsSet, p.Envelope.CMaxSet = true, true, true, true
	again, err := p.Canonical()
	if err != nil || !bytes.Equal(again, b) {
		return Proposal{}, "commission_noncanonical"
	}
	return p, ""
}

// ── The reference admission function ─────────────────────────────────────

// fixtureKey is a registered (or deliberately unregistered) buyer key.
type fixtureKey struct {
	Name          string `json:"name"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	Account       string `json:"account,omitempty"`
	State         string `json:"state"` // "active", "retired" or "unregistered"
}

// fixturePod is one stored published_pods row, reduced to what admission
// reads. Rows are looked up by (handle, pod_name, pod_version), because
// pod_hash is not unique across handles in reef-core.
type fixturePod struct {
	Name        string `json:"name"`
	Why         string `json:"why"`
	Handle      string `json:"handle"`
	PodName     string `json:"pod_name"`
	PodVersion  string `json:"pod_version"`
	Visibility  string `json:"visibility"`
	Withdrawn   bool   `json:"withdrawn"`
	Manifest    string `json:"manifest"`
	PodHash     string `json:"pod_hash"`
	ExpectClass string `json:"expect_memory_class,omitempty"`
}

// admissionRequest is the part of the HTTP request (design doc §5.3) that
// the reference models besides the wire bytes.
type admissionRequest struct {
	Account       string   `json:"account"`
	Contract      string   `json:"contract"`
	AssuranceMode string   `json:"assurance_mode"`
	ExtraKeys     []string `json:"extra_request_keys,omitempty"`
	InputsDigest  string   `json:"inputs_digest,omitempty"`
}

// admissionVerdict is the reference outcome for one request.
type admissionVerdict struct {
	Verdict        string            `json:"verdict"` // "admit" or "refuse"
	Code           string            `json:"code,omitempty"`
	FailedDims     []string          `json:"failed_dimensions,omitempty"`
	HCommission    string            `json:"h_commission,omitempty"`
	PodRef         string            `json:"pod_ref,omitempty"`
	PodHash        string            `json:"pod_hash,omitempty"`
	MemoryClass    string            `json:"memory_class,omitempty"`
	DerivedModels  []string          `json:"derived_models,omitempty"`
	DerivedTools   []string          `json:"derived_tools,omitempty"`
	DerivedCMax    *uint64           `json:"derived_c_max,omitempty"`
	AuthorFeeSats  *uint64           `json:"author_fee_sats,omitempty"`
	DimensionState map[string]string `json:"dimensions,omitempty"`
}

// admissionWorld is the server state one request is judged against.
type admissionWorld struct {
	keys    map[string]fixtureKey // by public key hex
	pods    map[string]fixturePod // by "handle/pod_name@pod_version"
	revoked map[string]bool       // h_commission hex → revoked
}

// refuse builds a refusal verdict.
func refuse(code string) admissionVerdict { return admissionVerdict{Verdict: "refuse", Code: code} }

// verifiedCommission is what the stateless steps Q1–Q4 produce.
type verifiedCommission struct {
	p      Proposal
	pubHex string
	h      [32]byte
}

// checkRequestAndSignature runs Q1–Q4 of design doc §8.1: request shape,
// strict wire and canonical decoding, and the signature. It reads no
// server state. Output: the verified commission, or a refusal code.
func checkRequestAndSignature(req admissionRequest, wire []byte) (verifiedCommission, string) {
	// Q1 request shape, in the order of design doc §5.3.
	if len(req.ExtraKeys) > 0 {
		return verifiedCommission{}, "commission_request_invalid"
	}
	if req.Contract != admissionContractID {
		return verifiedCommission{}, "commission_contract_unsupported"
	}
	if req.AssuranceMode == "" {
		return verifiedCommission{}, "assurance_mode_required"
	}
	if req.AssuranceMode != limitedModeID {
		return verifiedCommission{}, "assurance_mode_unsupported"
	}
	// Q2, Q3 wire and canonical decode.
	env, code := decodeWireV1(wire)
	if code != "" {
		return verifiedCommission{}, code
	}
	p, code := decodeCanonicalV1(env.canonical)
	if code != "" {
		return verifiedCommission{}, code
	}
	// Q4 signature: strict DER + low-S, over SHA-256(canonical), no double
	// hash. A 0x02/0x03 key that is not on the curve fails here too.
	if _, _, err := identity.ParseStrict(env.sig); err != nil {
		return verifiedCommission{}, "commission_signature_invalid"
	}
	h := sha256.Sum256(env.canonical)
	pubHex := hex.EncodeToString(env.pubKey)
	if ok, err := identity.VerifyDigest(pubHex, h[:], env.sig); err != nil || !ok {
		return verifiedCommission{}, "commission_signature_invalid"
	}
	return verifiedCommission{p: p, pubHex: pubHex, h: h}, ""
}

// admitAfterSignature runs Q5–P1i of design doc §8.1 for a commission that
// passed Q1–Q4 (the replay lookup, when there is one, runs between the
// two). Inputs: the verified commission, the authenticated account and the
// server state. It performs no I/O.
func admitAfterSignature(vc verifiedCommission, account string, w admissionWorld) admissionVerdict {
	p := vc.p
	// Q5 semantic validity that the canonical bytes can carry.
	if err := p.Binding.Validate(); err != nil {
		return refuse("commission_invalid")
	}
	for _, set := range [][]string{p.Envelope.Models, p.Envelope.Tools, p.Envelope.Labels} {
		for _, v := range set {
			if v == "" {
				return refuse("commission_invalid")
			}
		}
	}
	// Q6 signer authorization for the authenticated account.
	k, ok := w.keys[vc.pubHex]
	switch {
	case !ok || k.State == "unregistered":
		return refuse("commission_signer_unregistered")
	case k.Account != account:
		return refuse("commission_signer_not_authorized")
	case k.State == "retired":
		return refuse("commission_signer_retired")
	}
	// Q7 revocation.
	hHex := hex.EncodeToString(vc.h[:])
	if w.revoked[hHex] {
		return refuse("commission_revoked")
	}
	// P1a resolve the row the signed pod_ref names; P1b require its hash.
	row, ok := w.pods[p.Binding.PodRef]
	if !ok || row.Withdrawn {
		return refuse("commission_pod_not_found")
	}
	if row.PodHash != hex.EncodeToString(p.Binding.HManifest[:]) {
		return refuse("commission_binding_mismatch")
	}
	manifest := []byte(row.Manifest)
	// P1d manifest version, P1e commitment presence.
	if v, _ := canon.VersionIdentifier(manifest); v != "v2" {
		return refuse("commission_manifest_version_unsupported")
	}
	committed, ok := trailerFieldsRoot(manifest)
	if !ok {
		return refuse("commission_manifest_commitment_unreadable")
	}
	// P1f derive the manifest envelope under the limited mode.
	d, code := deriveLimitedV1(manifest)
	if code != "" {
		return refuse(code)
	}
	// P1g binding pin, P1h independent recomputation of fields_root.
	if p.Binding.FieldsRoot == nil {
		return refuse("commission_fields_root_unpinned")
	}
	if *p.Binding.FieldsRoot != committed {
		return refuse("commission_fields_root_mismatch")
	}
	class, code := classifyFieldsRoot(d, committed)
	if code != "" {
		return refuse(code)
	}
	// P1i containment. Labels are not evaluated in the limited mode; they
	// are never read as empty. Spend is checked twice: the committed
	// compute cap, and (owner decision D17, recommended option b) the
	// total of compute cap plus the public author fee. The server adds its
	// configured ZK fee to the total; the fixture has no ZK fee.
	var failed []string
	res := p.Envelope.Contains(envelope.Envelope{Models: d.models, Tools: d.tools, CMax: d.cMax})
	for _, f := range res.Failures {
		failed = append(failed, f.Dimension)
	}
	spendFailed := d.cMax > p.Envelope.CMax
	if !spendFailed && (d.authorFee > p.Envelope.CMax || d.cMax > p.Envelope.CMax-d.authorFee) {
		failed = append(failed, "spend_total")
	}
	if len(failed) > 0 {
		v := refuse("commission_not_contained")
		v.FailedDims = failed
		return v
	}
	cMax, fee := d.cMax, d.authorFee
	return admissionVerdict{
		Verdict:       "admit",
		HCommission:   hHex,
		PodRef:        p.Binding.PodRef,
		PodHash:       row.PodHash,
		MemoryClass:   class,
		DerivedModels: d.models,
		DerivedTools:  d.tools,
		DerivedCMax:   &cMax,
		AuthorFeeSats: &fee,
		DimensionState: map[string]string{
			"models": "admission_checked",
			"tools":  "admission_checked_declared_only",
			"spend":  "admission_checked",
			"labels": "not_evaluated",
			"memory": memoryClaim(class),
		},
	}
}

// admitV1Reference applies every stateless and state-reading check for a
// single request with no replay history: Q1–Q4, then Q5–P1i.
func admitV1Reference(req admissionRequest, wire []byte, w admissionWorld) admissionVerdict {
	vc, code := checkRequestAndSignature(req, wire)
	if code != "" {
		return refuse(code)
	}
	return admitAfterSignature(vc, req.Account, w)
}

// memoryClaim is the limited-mode memory statement for a class (MEM-00 §10).
func memoryClaim(class string) string {
	if class == "rinit_v1" {
		return "declares_no_initial_memory_and_commits_empty_root"
	}
	return "declares_no_initial_memory_legacy_zero_root_not_proof_eligible"
}

// derivedV1 is the envelope the server derives from the exact manifest,
// plus the public author fee that the spend-total check reads.
type derivedV1 struct {
	models    []string
	tools     []string
	cMax      uint64
	authorFee uint64
}

// exactTrailer is the only [_commit] trailer form reef-core P1e accepts
// (ManifestDerivation.trailer_fields_root/1): the canonicalizer's exact
// bytes at the very end of the manifest, with no extra whitespace, no
// other key and one final LF. canon.ParseCommitFieldsRoot is more lenient
// (IB-07 parity, konareef!135 security review M1).
var exactTrailer = regexp.MustCompile(`\n\[_commit\]\nfields_root = "poseidon:([0-9a-f]{64})"\n\z`)

// trailerFieldsRoot is step P1e: the committed fields_root, read only from
// a v2 manifest that ends in exactTrailer. Input: the manifest bytes.
// Output: the root, and false when the trailer is not in the exact form.
func trailerFieldsRoot(manifest []byte) ([32]byte, bool) {
	var root [32]byte
	if !bytes.HasPrefix(manifest, []byte("#!konareef-toml/v2\n")) {
		return root, false
	}
	m := exactTrailer.FindSubmatch(manifest)
	if m == nil {
		return root, false
	}
	if _, err := hex.Decode(root[:], m[1]); err != nil {
		return root, false
	}
	return root, true
}

// authorTree returns the decoded manifest without its synthesized tables
// ([_files] and [_commit]), re-encoded as TOML for pod.Validate. It
// mirrors reef-core SchemaCheck.strip_synthesized/2, which removes the two
// keys from the decoded tree: a table placed anywhere, including after
// [_files], is still validated (IB-07 parity). A text cut at [_files]
// would miss it. Input: the manifest bytes. Output: TOML bytes, or a
// decode error.
func authorTree(manifest []byte) ([]byte, error) {
	var tree map[string]any
	if _, err := toml.Decode(string(manifest), &tree); err != nil {
		return nil, err
	}
	delete(tree, "_files")
	delete(tree, "_commit")
	var out bytes.Buffer
	if err := toml.NewEncoder(&out).Encode(tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// deriveLimitedV1 derives models, tools (S1), c_max and the author fee
// from the manifest and applies the limited-mode refusals, in the P1f
// order of design doc §8.1:
//
//  1. sealed-grants marker present (read from the decoded tables, before
//     schema validation, because today's schemas do not know the marker);
//  2. schema validation of the author tree (the decoded tree without
//     [_files] and [_commit], wherever they are);
//  3. [[context.memory]] present;
//  4. [model] absent, then a malformed model ID or a provider with "/";
//  5. [budget].max_sats absent, then negative;
//  6. the TA-00 tool rules;
//  7. duplicate S1 entries, or more than canon.MaxTools of them.
//
// 0. (checked first, ahead of the list above): a CR byte anywhere in the
// manifest, and any TOML integer outside the int64 range. Both are IB-04
// (reef-core!125) parity follow-ups. The CR check is explicit, below.
// The int64 bound needs no extra code: BurntSushi's own lexer parses an
// integer token with strconv.ParseInt(s, 10, 64), so a literal outside
// int64 anywhere in the document is already a TOML parse error —
// pod.ParseWithMeta's err path below already gives
// commission_manifest_invalid for it. Elixir's toml-elixir accepts
// arbitrary-precision integers, so lib/pod/commission/manifest_derivation.ex
// checks the decoded value tree explicitly (int64_only?/1); Go's parser
// never produces such a tree in the first place. See
// TestDeriveLimitedV1RefusesCRBody and TestDeriveLimitedV1RefusesOutOfInt64Range.
//
// Output: the derived envelope, or a refusal code.
func deriveLimitedV1(manifest []byte) (derivedV1, string) {
	// IB-04 follow-up (reef-core!125): reef-core's Elixir decoder refuses
	// any CR byte (0x0D) in the manifest, checked before it parses the
	// TOML at all. The konareef canonicalizer rewrites every CRLF and
	// lone CR to LF and escapes control characters in strings (R1), so
	// canonical output never contains 0x0D — but Go's TOML decoder does
	// not itself refuse one inside a multi-line string, and BurntSushi
	// and Elixir's toml-elixir could read such a byte differently. A CR
	// on the magic line or in the [_commit] trailer is refused earlier,
	// by trailerFieldsRoot (P1e, admitAfterSignature above),
	// so any CR reaching this point is in the body.
	if bytes.ContainsRune(manifest, '\r') {
		return derivedV1{}, "commission_manifest_invalid"
	}
	spec, meta, err := pod.ParseWithMeta(manifest)
	if err != nil {
		return derivedV1{}, "commission_manifest_invalid"
	}
	if meta.IsDefined("network", "sealed_grants") {
		return derivedV1{}, "commission_sealed_grants_unsupported"
	}
	head, err := authorTree(manifest)
	if err != nil {
		return derivedV1{}, "commission_manifest_invalid"
	}
	issues, err := pod.Validate(head)
	if err != nil {
		return derivedV1{}, "commission_manifest_invalid"
	}
	for _, iss := range issues {
		// Since TA-01 (konareef#19), pod.Validate itself fails a manifest
		// whose tools_allowed/tools_denied overlap (TA-00 D5) — previously
		// a Warning, now an Issue (internal/pod/toolpolicy.go). That is
		// exactly the shape step 6 below (toolPolicyRefusal) independently
		// re-derives from S1/S3/S4 and assigns the more specific
		// commission_tool_policy_invalid the design doc (§8.1) wants for
		// it. Skip this one code here so step 6 gets to classify it,
		// instead of this generic gate pre-empting it with
		// commission_manifest_invalid. Any OTHER schema/cross-field issue
		// still fails fast here, unclassified.
		if iss.Code != "tools-denied-overlap-allowed" {
			return derivedV1{}, "commission_manifest_invalid"
		}
	}
	if spec.Context != nil && len(spec.Context.Memory) > 0 {
		return derivedV1{}, "commission_memory_unsupported"
	}
	if spec.Model == nil {
		return derivedV1{}, "commission_model_undeclared"
	}
	modelID, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
	if err != nil {
		return derivedV1{}, "commission_manifest_invalid"
	}
	// reef-core ModelSelection.qualified_id/2 refuses a provider that
	// contains "/" (model_provider_ambiguous); canon.ModelID allows it
	// (IB-07 parity).
	if strings.Contains(spec.Model.Provider, "/") {
		return derivedV1{}, "commission_manifest_invalid"
	}
	if !meta.IsDefined("budget", "max_sats") {
		return derivedV1{}, "commission_budget_undeclared"
	}
	if spec.Budget.MaxSats < 0 {
		return derivedV1{}, "commission_manifest_invalid"
	}
	var s1 []string
	if spec.Context != nil {
		for _, t := range spec.Context.Tools {
			s1 = append(s1, t.Source)
		}
	}
	var s3, s4 []string
	if spec.Directive != nil {
		s3, s4 = spec.Directive.ToolsAllowed, spec.Directive.ToolsDenied
	}
	if code := toolPolicyRefusal(s1, s3, s4, meta.IsDefined("directive", "tools_allowed")); code != "" {
		return derivedV1{}, code
	}
	if len(s1) > canon.MaxTools {
		return derivedV1{}, "commission_manifest_invalid"
	}
	seen := map[string]bool{}
	for _, t := range s1 {
		if seen[t] {
			return derivedV1{}, "commission_manifest_invalid"
		}
		seen[t] = true
	}
	var fee uint64
	if m := spec.Marketplace; m != nil && m.PriceModel == "per_run" && m.PriceSats > 0 {
		fee = uint64(m.PriceSats)
	}
	return derivedV1{models: []string{modelID}, tools: envelope.Normalise(s1), cMax: uint64(spec.Budget.MaxSats), authorFee: fee}, ""
}

// toolPolicyRefusal applies the accepted TA-00 rules. s3Present is the
// TOML key presence of [directive].tools_allowed (D4 needs presence, not
// length). The D4 refusal at admission is owner decision D18 of the
// design doc; the fixture follows its recommended option.
func toolPolicyRefusal(s1, s3, s4 []string, s3Present bool) string {
	for _, set := range [][]string{s1, s3, s4} {
		for _, v := range set {
			if !norm.NFC.IsNormalString(v) || v == "" {
				return "commission_tool_policy_invalid"
			}
		}
	}
	for _, set := range [][]string{s3, s4} {
		for _, v := range set {
			if strings.ContainsAny(v, "*?[]{}") {
				return "commission_tool_policy_invalid"
			}
		}
	}
	declared := map[string]bool{}
	for _, v := range s1 {
		declared[v] = true
	}
	for _, v := range s3 {
		if !declared[v] {
			return "commission_tool_policy_invalid" // D3: S3 ⊆ S1 per name
		}
	}
	if s3Present && len(s3) == 0 && len(s1) > 0 {
		return "commission_tool_policy_invalid" // D4: [] contradicts a non-empty S1
	}
	allowed := map[string]bool{}
	for _, v := range s3 {
		allowed[v] = true
	}
	for _, v := range s4 {
		if allowed[v] {
			return "commission_tool_policy_invalid" // D5: S3 ∩ S4 overlap
		}
	}
	return ""
}

// classifyFieldsRoot recomputes fields_root from the derived values under
// both memory-free conventions (MEM-00 R-M17) and classifies the committed
// trailer. A trailer that matches neither is refused, which is what stops
// a self-consistent pin and a forged trailer that omit a declared tool.
func classifyFieldsRoot(d derivedV1, committed [32]byte) (string, string) {
	v1, err := canon.FieldsRoot(d.models, d.tools, d.cMax, mustRoot(rInitV1Hex))
	if err != nil {
		return "", "commission_manifest_invalid"
	}
	legacy, err := canon.FieldsRoot(d.models, d.tools, d.cMax, [32]byte{})
	if err != nil {
		return "", "commission_manifest_invalid"
	}
	switch committed {
	case v1:
		return "rinit_v1", ""
	case legacy:
		return "legacy_zero", ""
	}
	return "", "commission_fields_root_unrecognized"
}

// ── Claim, replay and revocation (design doc §7) ─────────────────────────

// claim is one row of the modelled commission_admissions claim table.
type claim struct {
	account string
	inputs  string
	state   string // "claimed", "started" or "released"
	agentID string
}

// claimLedger models the claim rules. Rows are keyed by h_commission.
// Revocations live in the world's separate revocation set, not here.
type claimLedger struct {
	rows   map[string]*claim
	nextID int
}

// replayLookup is the check that runs right after Q4: an exact match on
// (h_commission, account, inputs digest) with a live claim returns the
// earlier run, or in-progress, before any state-reading check can refuse
// a retry of a run that already exists. Output: a result code and agent
// id, or "" when there is no exact live match.
func (l *claimLedger) replayLookup(h, account, inputsDigest string) (string, string) {
	row, ok := l.rows[h]
	if !ok || row.state == "released" || row.account != account || row.inputs != inputsDigest {
		return "", ""
	}
	if row.state == "claimed" {
		return "commission_admission_in_progress", ""
	}
	return "replayed", row.agentID
}

// claimRun inserts the claim after every admission check passed. It
// re-reads revocation inside the same (modelled) transaction. outcome is
// what happens next: "started" (a runtime launched), "released" (a
// failure before any launch) or "in_flight" (left claimed). Output: the
// step result code and the agent id it names.
func (l *claimLedger) claimRun(h, account, inputsDigest, outcome string, revoked bool) (string, string) {
	if revoked {
		return "commission_revoked", ""
	}
	if row, ok := l.rows[h]; ok && row.state != "released" {
		if row.account != account || row.inputs != inputsDigest {
			return "commission_replay_conflict", ""
		}
		return "commission_admission_in_progress", "" // lost a race with the replay lookup
	}
	l.nextID++
	row := &claim{account: account, inputs: inputsDigest, state: "claimed", agentID: fmt.Sprintf("agent-%d", l.nextID)}
	l.rows[h] = row
	switch outcome {
	case "released":
		row.state = "released"
		return "released", row.agentID
	case "started":
		row.state = "started"
		return "admitted", row.agentID
	}
	return "claimed", row.agentID
}

// ── Fixture model ────────────────────────────────────────────────────────

// admissionCase is one single-request vector.
type admissionCase struct {
	ID      string           `json:"id"`
	Why     string           `json:"why"`
	Request admissionRequest `json:"request"`
	WireHex string           `json:"wire_hex"`
	Expect  admissionVerdict `json:"expect"`
}

// sequenceStep is one step of a replay scenario. Action "submit" (the
// default) submits a case's wire bytes; "retire_key" retires the named
// key; "revoke" revokes the named case's h_commission.
type sequenceStep struct {
	Action       string `json:"action"`
	Case         string `json:"case,omitempty"`
	Key          string `json:"key,omitempty"`
	Account      string `json:"account,omitempty"`
	InputsDigest string `json:"inputs_digest,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Expect       string `json:"expect,omitempty"`
	ExpectAgent  string `json:"expect_agent,omitempty"`
}

// admissionSequence is an ordered scenario over the claim table.
type admissionSequence struct {
	ID    string         `json:"id"`
	Why   string         `json:"why"`
	Steps []sequenceStep `json:"steps"`
}

// admissionFixture is the whole of testdata/admission_v1/vectors.json.
type admissionFixture struct {
	Purpose   string              `json:"_purpose"`
	Status    string              `json:"_status"`
	Contract  string              `json:"_contract"`
	Generated string              `json:"_generated"`
	Constants map[string]any      `json:"constants"`
	Keys      []fixtureKey        `json:"keys"`
	Pods      []fixturePod        `json:"published_pods"`
	Cases     []admissionCase     `json:"cases"`
	Sequences []admissionSequence `json:"sequences"`
}

const admissionFixturePath = "testdata/admission_v1/vectors.json"

// newWorld builds the server state a fixture describes.
func newWorld(fx admissionFixture) admissionWorld {
	w := admissionWorld{keys: map[string]fixtureKey{}, pods: map[string]fixturePod{}, revoked: map[string]bool{}}
	for _, k := range fx.Keys {
		w.keys[k.PublicKeyHex] = k
	}
	for _, p := range fx.Pods {
		w.pods[fmt.Sprintf("%s/%s@%s", p.Handle, p.PodName, p.PodVersion)] = p
	}
	return w
}

// runSequence drives one scenario through replay lookup, admission and
// claim, and returns the (result, agent) pair of every step. Steps that
// change state return ("", "").
func runSequence(fx admissionFixture, s admissionSequence) [][2]string {
	w := newWorld(fx)
	l := &claimLedger{rows: map[string]*claim{}}
	cases := map[string]admissionCase{}
	for _, c := range fx.Cases {
		cases[c.ID] = c
	}
	var out [][2]string
	for _, st := range s.Steps {
		switch st.Action {
		case "retire_key":
			for pub, k := range w.keys {
				if k.Name == st.Key {
					k.State = "retired"
					w.keys[pub] = k
				}
			}
			out = append(out, [2]string{"", ""})
			continue
		case "revoke":
			w.revoked[cases[st.Case].Expect.HCommission] = true
			out = append(out, [2]string{"", ""})
			continue
		}
		c := cases[st.Case]
		req := c.Request
		req.Account, req.InputsDigest = st.Account, st.InputsDigest
		wire, _ := hex.DecodeString(c.WireHex)
		vc, code := checkRequestAndSignature(req, wire)
		if code != "" {
			out = append(out, [2]string{code, ""})
			continue
		}
		hHex := hex.EncodeToString(vc.h[:])
		if r, agent := l.replayLookup(hHex, req.Account, req.InputsDigest); r != "" {
			out = append(out, [2]string{r, agent})
			continue
		}
		if v := admitAfterSignature(vc, req.Account, w); v.Verdict != "admit" {
			out = append(out, [2]string{v.Code, ""})
			continue
		}
		r, agent := l.claimRun(hHex, req.Account, req.InputsDigest, st.Outcome, w.revoked[hHex])
		out = append(out, [2]string{r, agent})
	}
	return out
}

// ── Generator ────────────────────────────────────────────────────────────

// testKey derives a deterministic secp256k1 test key from a public label.
func testKey(name, account, state string) (fixtureKey, *identity.Identity) {
	seed := sha256.Sum256([]byte("konareef/ib-00/admission-v1/test-key/" + name))
	priv := secp256k1.PrivKeyFromBytes(seed[:])
	pub := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	k := fixtureKey{Name: name, PrivateKeyHex: hex.EncodeToString(seed[:]), PublicKeyHex: pub, Account: account, State: state}
	return k, &identity.Identity{PrivateKeyHex: k.PrivateKeyHex, PublicKeyHex: pub}
}

// podSource is an authored pod.toml plus the trailer parameters its
// canonical v2 form commits (which may deliberately disagree with it).
type podSource struct {
	name, why, authored, magic string
	params                     canon.CommitParams
	corrupt                    bool
	crBody                     bool // IB-04 parity: inject a raw CR into the body, after canonicalization
	hugeInt                    bool // IB-04 parity: inject an out-of-int64 integer literal into the body
	withdrawn                  bool
	expectClass                string
	handle                     string            // default "dave"
	copyOf                     string            // reuse another source's exact bytes
	files                      map[string]string // extra body files, path → content
	// podNameFallback and podVersionFallback name the row when the
	// mutated bytes (hugeInt) no longer parse at all — pod.Parse can't
	// read [pod].name/version back off them, so the generator needs
	// this out of band. Every other source leaves these empty and gets
	// its [pod].name/version read back from the parsed manifest, which
	// also doubles as a check that authoredPod's own name/version made
	// it through canonicalization unchanged.
	podNameFallback, podVersionFallback string
	// mutate, when set, rewrites the canonical bytes after every other
	// step. The IB-07 server-parity rows (konareef!135 security review
	// M1) use it: each is a manifest that konareef's lenient helpers
	// accept and reef-core admission refuses.
	mutate func([]byte) []byte
}

// authoredPod renders a small authored pod.toml. extra is appended verbatim.
func authoredPod(name, version, extra string) string {
	return "pod_spec_version = \"0.1\"\n\n[pod]\nname = \"" + name + "\"\nversion = \"" + version +
		"\"\nvisibility = \"closed\"\n\n[runtime]\nkind = \"lobster\"\nexecution_class = \"cloud\"\n\n" +
		"[directive]\ntemplate = \"./prompts/system.md\"\n" + extra
}

const (
	anthropicModel = "\n[model]\nprovider = \"anthropic\"\nname = \"claude-sonnet-4-5\"\n"
	budget2500     = "\n[budget]\nmax_sats = 2500\n"
	toolsBashRg    = "\n[[context.tools]]\nsource = \"bash\"\n\n[[context.tools]]\nsource = \"ripgrep\"\n"
	modelID        = "anthropic/claude-sonnet-4-5"
)

// podSources lists the stored rows the cases run against.
func podSources() []podSource {
	e20 := mustRoot(rInitV1Hex)
	ok := canon.CommitParams{Models: []string{modelID}, Tools: []string{"bash", "ripgrep"}, CMax: 2500, RInit: e20}
	legacy := ok
	legacy.RInit = [32]byte{}
	zero := ok
	zero.CMax = 0
	return []podSource{
		{name: "mf-ok", why: "memory-free v2 pod, trailer over E20: the control", authored: authoredPod("admit-fixture", "1.0.0", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok, expectClass: "rinit_v1"},
		{name: "mf-legacy", why: "same declarations, trailer over r_init = 0 (published before the E20 switch)", authored: authoredPod("admit-fixture", "1.0.1", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: legacy, expectClass: "legacy_zero"},
		{name: "mf-zero-budget", why: "explicit [budget].max_sats = 0: a stated zero, not a missing budget", authored: authoredPod("admit-fixture", "1.0.2", anthropicModel+"\n[budget]\nmax_sats = 0\n"+toolsBashRg), magic: "v2", params: zero, expectClass: "rinit_v1"},
		{name: "mf-forged", why: "declares bash, curl, ripgrep; the trailer commits only bash, ripgrep", authored: authoredPod("admit-fixture", "1.0.3", anthropicModel+budget2500+toolsBashRg+"\n[[context.tools]]\nsource = \"curl\"\n"), magic: "v2", params: ok},
		{name: "mf-no-model", why: "no [model]: the server would run its default model", authored: authoredPod("admit-fixture", "1.0.4", budget2500+toolsBashRg), magic: "v2", params: canon.CommitParams{Tools: []string{"bash", "ripgrep"}, CMax: 2500, RInit: e20}},
		{name: "mf-no-budget", why: "no [budget]: the server would run with its default budget", authored: authoredPod("admit-fixture", "1.0.5", anthropicModel+toolsBashRg), magic: "v2", params: canon.CommitParams{Models: []string{modelID}, Tools: []string{"bash", "ripgrep"}, RInit: e20}},
		{name: "mf-memory", why: "declares [[context.memory]]: outside the memory-free mode", authored: authoredPod("admit-fixture", "1.0.6", anthropicModel+budget2500+toolsBashRg+"\n[[context.memory]]\nkind = \"file\"\npath = \"./prompts/system.md\"\n"), magic: "v2", params: ok},
		{name: "mf-allowed-uncommitted", why: "tools_allowed names curl, which is not in [[context.tools]] (TA-00 D3)", authored: authoredPod("admit-fixture", "1.0.7", "tools_allowed = [\"curl\"]\n"+anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok},
		{name: "mf-allowed-empty", why: "tools_allowed = [] with a non-empty [[context.tools]] (TA-00 D4)", authored: authoredPod("admit-fixture", "1.0.8", "tools_allowed = []\n"+anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok},
		{name: "mf-allow-deny-overlap", why: "bash in both tools_allowed and tools_denied (TA-00 D5)", authored: authoredPod("admit-fixture", "1.0.9", "tools_allowed = [\"bash\"]\ntools_denied = [\"bash\"]\n"+anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok},
		{name: "mf-nfd-tool", why: "a [[context.tools]] source in NFD form (TA-00 D5 NFC rule)", authored: authoredPod("admit-fixture", "1.0.10", anthropicModel+budget2500+"\n[[context.tools]]\nsource = \"café\"\n"), magic: "v2", params: canon.CommitParams{Models: []string{modelID}, Tools: []string{"café"}, CMax: 2500, RInit: e20}},
		{name: "mf-sealed", why: "carries the MCP-C00 sealed-grants marker and a sealed grants file (owner decision D16)", authored: authoredPod("admit-fixture", "1.0.11", anthropicModel+budget2500+toolsBashRg+"\n[network]\nsealed_grants = \"konareef-sealed-grants/v1\"\n"), magic: "v2", params: ok, files: map[string]string{"sealed/grants.toml": "grants = []\n"}},
		{name: "mf-corrupt-trailer", why: "claims v2 but its [_commit] trailer will not parse", authored: authoredPod("admit-fixture", "1.0.12", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok, corrupt: true},
		{name: "v1-plain", why: "a konareef-toml/v1 manifest: no fields_root to bind", authored: authoredPod("admit-fixture", "1.0.13", anthropicModel+budget2500+toolsBashRg), magic: "v1"},
		{name: "mf-priced", why: "per-run author fee of 100 sats beside a 2500-sat compute cap (owner decision D17)", authored: authoredPod("admit-fixture", "1.0.15", anthropicModel+budget2500+toolsBashRg+"\n[marketplace]\nlisted = true\nprice_model = \"per_run\"\nprice_sats = 100\n"), magic: "v2", params: ok, expectClass: "rinit_v1"},
		{name: "mf-33-tools", why: "33 declared tools: over the 32-leaf tools_root cap", authored: authoredPod("admit-fixture", "1.0.16", anthropicModel+budget2500+manyTools(33)), magic: "v2", params: ok},
		{name: "mf-schema-invalid", why: "tools_allowed repeats a name, which the schema refuses (uniqueItems)", authored: authoredPod("admit-fixture", "1.0.17", "tools_allowed = [\"bash\", \"bash\"]\n"+anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok},
		{name: "mf-ok-mirror", why: "byte-identical copy of mf-ok published under another handle: pod_hash is not unique", copyOf: "mf-ok", handle: "mallory", expectClass: "rinit_v1"},
		{name: "mf-withdrawn", why: "a valid row the publisher withdrew", authored: authoredPod("admit-fixture", "1.0.14", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok, withdrawn: true, expectClass: "rinit_v1"},
		{name: "mf-cr-body", why: "IB-04 parity (reef-core!125): a raw CR byte in the body, not the magic line or trailer", authored: authoredPod("admit-fixture", "1.0.18", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok, crBody: true},
		{name: "mf-huge-int", why: "IB-04 parity (reef-core!125): [budget].max_sats outside the int64 range, which Elixir's TOML decoder accepts and Go's does not", authored: authoredPod("admit-fixture", "1.0.19", anthropicModel+budget2500+toolsBashRg), magic: "v2", params: ok, hugeInt: true, podNameFallback: "admit-fixture", podVersionFallback: "1.0.19"},
		// IB-07 server parity (konareef!135 security review M1). The P1e
		// trailer must be byte-exact: reef-core matches
		// ~r/\n\[_commit\]\nfields_root = "poseidon:<64 hex>"\n\z/.
		parityOK("mf-trailer-blank-line", "1.0.20", "an empty line after the [_commit] trailer", func(m []byte) []byte { return append(m, '\n') }),
		parityOK("mf-trailer-no-final-lf", "1.0.21", "the [_commit] trailer has no final LF", func(m []byte) []byte { return m[:len(m)-1] }),
		parityOK("mf-trailer-trailing-spaces", "1.0.22", "two spaces after the fields_root value", func(m []byte) []byte { return append(m[:len(m)-1:len(m)-1], "  \n"...) }),
		parityOK("mf-trailer-spaced-assign", "1.0.23", "extra spaces around '=' in the fields_root line", func(m []byte) []byte {
			return bytes.Replace(m, []byte("\nfields_root = \"poseidon:"), []byte("\nfields_root   =   \"poseidon:"), 1)
		}),
		parityOK("mf-trailer-rinit-scheme", "1.0.24", "an r_init_scheme key after fields_root in [_commit]", func(m []byte) []byte {
			return append(m, "r_init_scheme = \"konareef-rinit/v1\"\n"...)
		}),
		{name: "mf-provider-slash", why: "IB-07 parity: [model].provider contains '/' (reef-core ModelSelection.qualified_id/2 refuses it; canon.ModelID allows it), with a trailer over the model ID it gives", authored: authoredPod("admit-fixture", "1.0.25", "\n[model]\nprovider = \"anthropic/x\"\nname = \"claude-sonnet-4-5\"\n"+budget2500+toolsBashRg), magic: "v2", params: canon.CommitParams{Models: []string{"anthropic/x/claude-sonnet-4-5"}, Tools: []string{"bash", "ripgrep"}, CMax: 2500, RInit: e20}},
		parityOK("mf-nfd-denied", "1.0.26", "a [directive].tools_denied name in NFD form (the TA-00 D5 NFC rule covers S4 too)", func(m []byte) []byte {
			return bytes.Replace(m, []byte("template = \"./prompts/system.md\"\n"), []byte("template = \"./prompts/system.md\"\ntools_denied = [\"cafe\u0301\"]\n"), 1)
		}),
		parityOK("mf-table-after-files", "1.0.27", "an unknown top-level table between [_files] and [_commit], which a text cut at [_files] would not validate", func(m []byte) []byte {
			return insertBeforeCommit(m, "[evil]\nx = 1\n")
		}),
		parityOK("mf-subtable-after-files", "1.0.28", "an unknown [runtime] sub-table between [_files] and [_commit]", func(m []byte) []byte {
			return insertBeforeCommit(m, "[runtime.x]\ny = 2\n")
		}),
	}
}

// parityOK is an IB-07 server-parity row: the mf-ok declarations under
// its own version, canonicalized, then rewritten by mutate. Inputs: the
// row name, the pod version, what the mutation does, and the mutation.
// Output: the podSource. The why text names the parity source.
func parityOK(name, version, what string, mutate func([]byte) []byte) podSource {
	e20 := mustRoot(rInitV1Hex)
	return podSource{
		name: name, why: "IB-07 parity (konareef!135 M1): " + what,
		authored: authoredPod("admit-fixture", version, anthropicModel+budget2500+toolsBashRg), magic: "v2",
		params:             canon.CommitParams{Models: []string{modelID}, Tools: []string{"bash", "ripgrep"}, CMax: 2500, RInit: e20},
		mutate:             mutate,
		podNameFallback:    "admit-fixture",
		podVersionFallback: version,
	}
}

// insertBeforeCommit returns manifest with extra inserted just before its
// "[_commit]" line, which is after [_files]. Inputs: canonical v2 bytes
// and the TOML text to insert (ending in LF). Output: new bytes.
func insertBeforeCommit(manifest []byte, extra string) []byte {
	at := bytes.LastIndex(manifest, []byte("\n[_commit]\n")) + 1
	out := append([]byte{}, manifest[:at]...)
	out = append(out, extra...)
	return append(out, manifest[at:]...)
}

// manyTools renders n [[context.tools]] entries named t00, t01, ….
func manyTools(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\n[[context.tools]]\nsource = \"t%02d\"\n", i)
	}
	return b.String()
}

// mustRoot decodes a 64-hex root.
func mustRoot(h string) [32]byte {
	var out [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		panic("bad root hex " + h)
	}
	copy(out[:], raw)
	return out
}

// canonicalizeSource renders one podSource into canonical manifest bytes.
func canonicalizeSource(t *testing.T, s podSource) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "prompts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prompts", "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for path, content := range s.files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out []byte
	var err error
	if s.magic == "v1" {
		out, err = canon.Canonicalize([]byte(s.authored), dir)
	} else {
		out, err = canon.CanonicalizeV2([]byte(s.authored), dir, s.params)
	}
	if err != nil {
		t.Fatalf("canonicalize %s: %v", s.name, err)
	}
	if s.corrupt {
		out = bytes.Replace(out, []byte("fields_root = \"poseidon:"), []byte("fields_root = \"poseidon;"), 1)
	}
	// Both mutations below land in the author tree, well before [_files]
	// and [_commit], so canon.ParseCommitFieldsRoot still reads a clean
	// trailer — only deriveLimitedV1's P1f decode step sees the damage,
	// exactly as the corresponding reef-core cases are positioned
	// (IB-04 follow-up, reef-core!125).
	if s.crBody {
		out = bytes.Replace(out, []byte(`template = "./prompts/system.md"`+"\n"),
			[]byte(`template = "./prompts/system.md"`+"\r\n"), 1)
	}
	if s.hugeInt {
		out = bytes.Replace(out, []byte("max_sats = 2500\n"), []byte("max_sats = 99999999999999999999999999\n"), 1)
	}
	if s.mutate != nil {
		mutated := s.mutate(out)
		if bytes.Equal(mutated, out) {
			t.Fatalf("canonicalize %s: the mutation changed nothing", s.name)
		}
		out = mutated
	}
	return out
}

// cborHead encodes a minimal-length CBOR head.
func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// cborBstr encodes a byte string.
func cborBstr(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

// cborText encodes a text string.
func cborText(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }

// canonicalParts encodes a canonical-shaped proposal map from explicit
// parts, so the generator can produce validly signed but noncanonical
// spellings. A nil set encodes as null; a non-nil empty set encodes as an
// empty array; set elements are written in the order given.
func canonicalParts(models, tools, labels []string, cMax uint64, b Binding, prose string) []byte {
	set := func(v []string) []byte {
		if v == nil {
			return []byte{0xf6}
		}
		out := cborHead(4, uint64(len(v)))
		for _, e := range v {
			out = append(out, cborText(e)...)
		}
		return out
	}
	out := cborHead(5, 6)
	out = append(append(out, cborHead(0, 1)...), set(models)...)
	out = append(append(out, cborHead(0, 2)...), set(tools)...)
	out = append(append(out, cborHead(0, 3)...), set(labels)...)
	out = append(append(out, cborHead(0, 4)...), cborHead(0, cMax)...)
	out = append(out, cborHead(0, 5)...)
	n := uint64(2)
	if b.FieldsRoot != nil {
		n = 3
	}
	out = append(out, cborHead(5, n)...)
	out = append(append(out, cborHead(0, 1)...), cborText(b.PodRef)...)
	out = append(append(out, cborHead(0, 2)...), cborBstr(b.HManifest[:])...)
	if b.FieldsRoot != nil {
		out = append(append(out, cborHead(0, 3)...), cborBstr(b.FieldsRoot[:])...)
	}
	out = append(append(out, cborHead(0, 6)...), cborText(prose)...)
	return out
}

// wireBytes encodes the v1 wire map {1: version, 2: canonical, 3: pub, 4: sig}.
func wireBytes(version uint64, canonical, pub, sig []byte) []byte {
	out := cborHead(5, 4)
	out = append(out, cborHead(0, 1)...)
	out = append(out, cborHead(0, version)...)
	out = append(out, cborHead(0, 2)...)
	out = append(out, cborBstr(canonical)...)
	out = append(out, cborHead(0, 3)...)
	out = append(out, cborBstr(pub)...)
	out = append(out, cborHead(0, 4)...)
	out = append(out, cborBstr(sig)...)
	return out
}

// signedWire signs the canonical form of p with id and returns wire bytes.
func signedWire(t *testing.T, p Proposal, id *identity.Identity) []byte {
	t.Helper()
	c, err := Sign(p, id)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	canonical, _ := p.Canonical()
	pub, _ := hex.DecodeString(c.PubKeyHex)
	return wireBytes(wireVersionV1, canonical, pub, c.Sig)
}

// rawSignedWire signs arbitrary canonical bytes (valid signature over
// possibly non-canonical bytes) and returns wire bytes.
func rawSignedWire(t *testing.T, canonical []byte, id *identity.Identity) []byte {
	t.Helper()
	sig, err := id.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(id.PublicKeyHex)
	return wireBytes(wireVersionV1, canonical, pub, sig)
}

// highS returns the malleated (r, n-s) DER form of a low-S signature.
func highS(t *testing.T, der []byte) []byte {
	t.Helper()
	r, s, err := identity.ParseStrict(der)
	if err != nil {
		t.Fatal(err)
	}
	n := secp256k1.S256().N
	s2 := new(big.Int).Sub(n, s)
	enc := func(v *big.Int) []byte {
		b := v.Bytes()
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(enc(r), enc(s2)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// buildAdmissionVectors regenerates the whole fixture from fixed inputs.
func buildAdmissionVectors(t *testing.T) admissionFixture {
	t.Helper()
	keyA, idA := testKey("buyer-a", "account-1", "active")
	keyB, idB := testKey("buyer-b", "account-2", "active")
	keyR, idR := testKey("buyer-a-retired", "account-1", "retired")
	keyX, idX := testKey("stranger", "", "unregistered")

	fx := admissionFixture{
		Purpose: "Shared vectors for the proposed server-enforced commission admission contract " +
			"(docs/design/commission-admission-contract.md). IB-04 (reef-core#51) must reproduce every " +
			"case verdict and code in Elixir; IB-06 (konareef#22) uses the wire bytes as golden submissions.",
		Status:    "PROPOSED by IB-00 (konareef#20). Not normative until the owner approves the design MR.",
		Contract:  admissionContractID,
		Generated: "internal/commission/admission_v1_reference_test.go (KONAREEF_UPDATE_ADMISSION_VECTORS=1)",
		Constants: map[string]any{
			"assurance_mode":     limitedModeID,
			"wire_version":       wireVersionV1,
			"r_init_v1":          rInitV1Hex,
			"r_init_legacy_zero": strings.Repeat("0", 64),
			"limits": map[string]int{
				"wire_bytes": maxWireBytes, "prose_bytes": maxProseBytes, "pod_ref_bytes": maxPodRefBytes,
				"set_element_bytes": maxElementBytes, "models": maxModelElements, "tools": maxToolElements,
				"labels": maxLabelElements, "signature_bytes_min": minSigBytes, "signature_bytes_max": maxSigBytes,
			},
			"test_keys_warning": "private keys below are derived from public labels; they are test keys and must never be registered on any server",
		},
		Keys: []fixtureKey{keyA, keyB, keyR, keyX},
	}

	manifests := map[string][]byte{}
	for _, s := range podSources() {
		var m []byte
		if s.copyOf != "" {
			m = manifests[s.copyOf]
		} else {
			m = canonicalizeSource(t, s)
		}
		manifests[s.name] = m
		handle := s.handle
		if handle == "" {
			handle = "dave"
		}
		h := sha256.Sum256(m)
		podName, podVersion := s.podNameFallback, s.podVersionFallback
		if podName == "" {
			spec, err := pod.Parse(m)
			if err != nil {
				t.Fatalf("parse %s: %v", s.name, err)
			}
			podName, podVersion = spec.Pod.Name, spec.Pod.Version
		}
		fx.Pods = append(fx.Pods, fixturePod{
			Name: s.name, Why: s.why, Handle: handle, PodName: podName, PodVersion: podVersion,
			Visibility: "closed", Withdrawn: s.withdrawn, Manifest: string(m), PodHash: hex.EncodeToString(h[:]),
			ExpectClass: s.expectClass,
		})
	}
	pin := func(name string) *[32]byte {
		fr, err := canon.ParseCommitFieldsRoot(manifests[name])
		if err != nil {
			// An IB-07 trailer row that even the lenient parser cannot
			// read: pin the control's root. P1e refuses first, so the
			// pin is never compared.
			if fr, err = canon.ParseCommitFieldsRoot(manifests["mf-ok"]); err != nil {
				t.Fatalf("pin %s: %v", name, err)
			}
		}
		return &fr
	}
	ref := func(name string) string {
		for _, p := range fx.Pods {
			if p.Name == name {
				return fmt.Sprintf("%s/%s@%s", p.Handle, p.PodName, p.PodVersion)
			}
		}
		t.Fatalf("no pod %s", name)
		return ""
	}
	prop := func(pod string, models, tools, labels []string, cMax uint64) Proposal {
		return Proposal{
			Envelope: envelope.Envelope{Models: models, Tools: tools, Labels: labels, CMax: cMax,
				ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true},
			Binding: Binding{PodRef: ref(pod), HManifest: sha256.Sum256(manifests[pod]), FieldsRoot: pin(pod)},
			Prose:   "Review the open merge requests and summarise the risky ones.",
		}
	}
	models := []string{modelID}
	tools := []string{"bash", "ripgrep"}
	control := prop("mf-ok", models, tools, nil, 2500)
	controlWire := signedWire(t, control, idA)
	controlCanonical, _ := control.Canonical()

	addReq := func(id, why string, req admissionRequest, wire []byte) {
		fx.Cases = append(fx.Cases, admissionCase{ID: id, Why: why, Request: req, WireHex: hex.EncodeToString(wire)})
	}
	add := func(id, why, account, mode string, wire []byte) {
		addReq(id, why, admissionRequest{Account: account, Contract: admissionContractID, AssuranceMode: mode}, wire)
	}
	addP := func(id, why string, p Proposal, signer *identity.Identity) {
		add(id, why, "account-1", limitedModeID, signedWire(t, p, signer))
	}

	// Controls.
	add("A01", "control: exact envelope, E20 trailer, active key of the submitting account", "account-1", limitedModeID, controlWire)
	addP("A02", "control: a wider commission (extra tool, higher cap, labels) still contains the pod", prop("mf-ok", []string{"anthropic/claude-sonnet-4-5", "openai/gpt-4o"}, []string{"bash", "curl", "ripgrep"}, []string{"public"}, 5000), idA)
	addP("A03", "legacy zero-root manifest is admitted but its memory root is reported as not proof-eligible", prop("mf-legacy", models, tools, nil, 2500), idA)
	addP("A04", "explicit zero budget in the manifest with a zero cap in the commission: admitted", prop("mf-zero-budget", models, tools, nil, 0), idA)
	addP("A05", "c_max at the uint64 maximum decodes and compares without overflow", prop("mf-ok", models, tools, nil, ^uint64(0)), idA)

	// Request shape.
	addReq("M03", "a contract string this server does not implement", admissionRequest{Account: "account-1", Contract: "konareef-commission-admission/v2", AssuranceMode: limitedModeID}, controlWire)
	addReq("M04", "a request that also names a pod: the pod is named only by the signed binding", admissionRequest{Account: "account-1", Contract: admissionContractID, AssuranceMode: limitedModeID, ExtraKeys: []string{"pod_ref"}}, controlWire)
	addP("A06", "per-run author fee 100 plus compute cap 2500 fits a 2600-sat commission cap", prop("mf-priced", models, tools, nil, 2600), idA)
	addP("P05", "identical bytes exist under another handle; the signed pod_ref selects dave's row", control, idA)
	addP("P06", "the same bytes, commissioned under the mirror handle, select mallory's row", Proposal{Envelope: control.Envelope, Binding: Binding{PodRef: ref("mf-ok-mirror"), HManifest: control.Binding.HManifest, FieldsRoot: control.Binding.FieldsRoot}, Prose: control.Prose}, idA)

	// Request mode.
	add("M01", "no assurance mode: the server never picks one for the caller", "account-1", "", controlWire)
	add("M02", "an unknown assurance mode is refused, not mapped to the limited mode", "account-1", "full/v1", controlWire)

	// Wire and canonical decoding.
	pubA, _ := hex.DecodeString(idA.PublicKeyHex)
	c0, _ := Sign(control, idA)
	add("W01", "wire version 2 is not understood by a v1 server", "account-1", limitedModeID, wireBytes(2, controlCanonical, pubA, c0.Sig))
	add("W02", "trailing byte after the wire map", "account-1", limitedModeID, append(append([]byte{}, controlWire...), 0x00))
	withExtra := append(cborHead(5, 5), controlWire[1:]...)
	withExtra = append(withExtra, append(cborHead(0, 5), cborHead(0, 0)...)...)
	add("W03", "wire map with an unknown fifth key", "account-1", limitedModeID, withExtra)
	dup := append([]byte{}, controlWire...)
	dup[3] = 0x01 // key 2 becomes a second key 1
	add("W04", "duplicate wire key 1", "account-1", limitedModeID, dup)
	indef := append([]byte{0xbf}, controlWire[1:]...)
	add("W05", "indefinite-length wire map", "account-1", limitedModeID, append(indef, 0xff))
	nonMinimal := append([]byte{0xa4, 0x18, 0x01}, controlWire[2:]...)
	add("W06", "non-minimal integer head for wire key 1", "account-1", limitedModeID, nonMinimal)
	add("W07", "wire over 32768 bytes is refused before decoding", "account-1", limitedModeID, append(append([]byte{}, controlWire...), make([]byte, maxWireBytes)...))
	uncompressed := append([]byte{0x04}, make([]byte, 32)...)
	add("W08", "33-byte public key with an invalid prefix", "account-1", limitedModeID, wireBytes(1, controlCanonical, uncompressed, c0.Sig))

	if !bytes.Equal(canonicalParts(control.Envelope.Models, control.Envelope.Tools, nil, 2500, control.Binding, control.Prose), controlCanonical) {
		t.Fatal("canonicalParts does not reproduce Proposal.Canonical for the control")
	}
	add("W09", "labels spelled as an empty array instead of null; validly signed but noncanonical", "account-1", limitedModeID,
		rawSignedWire(t, canonicalParts(models, tools, []string{}, 2500, control.Binding, control.Prose), idA))
	add("W10", "tool set out of byte order; validly signed but noncanonical", "account-1", limitedModeID,
		rawSignedWire(t, canonicalParts(models, []string{"ripgrep", "bash"}, nil, 2500, control.Binding, control.Prose), idA))
	add("W11", "tool set with a duplicate element; validly signed but noncanonical", "account-1", limitedModeID,
		rawSignedWire(t, canonicalParts(models, []string{"bash", "bash", "ripgrep"}, nil, 2500, control.Binding, control.Prose), idA))
	extraKey := append(cborHead(5, 7), controlCanonical[1:]...)
	extraKey = append(extraKey, append(cborHead(0, 7), cborHead(0, 1)...)...)
	add("W12", "canonical proposal with an unknown key 7 (a future field); validly signed", "account-1", limitedModeID, rawSignedWire(t, extraKey, idA))
	bignum := bytes.Replace(controlCanonical, []byte{0x04, 0x19, 0x09, 0xc4}, []byte{0x04, 0xc2, 0x42, 0x09, 0xc4}, 1)
	add("W13", "c_max as a CBOR bignum tag; validly signed", "account-1", limitedModeID, rawSignedWire(t, bignum, idA))
	longProse := control
	longProse.Prose = strings.Repeat("x", maxProseBytes+1)
	// Signed over the raw canonical bytes: Sign itself refuses prose over
	// the limit (ValidateAdmissionLimits), and the bytes are the same.
	add("W14", "prose over 16384 bytes", "account-1", limitedModeID, rawSignedWire(t, mustCanon(t, longProse), idA))
	badUTF8 := bytes.Replace(controlCanonical, []byte("Review"), []byte("R\xffview"), 1)
	add("W15", "prose that is not valid UTF-8; validly signed", "account-1", limitedModeID, rawSignedWire(t, badUTF8, idA))

	add("W16", "a 65-byte public key: a fixed-size field of the wrong length is malformed, not too large", "account-1", limitedModeID, wireBytes(1, controlCanonical, append([]byte{0x04}, make([]byte, 64)...), c0.Sig))
	add("W17", "a 0x02-prefixed key whose x coordinate is not on the curve", "account-1", limitedModeID, wireBytes(1, controlCanonical, offCurveKey(t), c0.Sig))
	future := cborHead(5, 5)
	future = append(future, append(cborHead(0, 1), cborHead(0, 2)...)...)
	future = append(future, append(cborHead(0, 2), cborBstr(controlCanonical)...)...)
	add("W18", "a future wire version with a different entry count is 'version unsupported', not 'malformed'", "account-1", limitedModeID, future)

	// Signature.
	tampered := bytes.Replace(controlCanonical, []byte("risky"), []byte("RISKY"), 1)
	add("S01", "prose tamper: every parameter byte-identical, signature no longer verifies", "account-1", limitedModeID, wireBytes(1, tampered, pubA, c0.Sig))
	pubB, _ := hex.DecodeString(idB.PublicKeyHex)
	add("S02", "signed by buyer-a, wire names buyer-b's key", "account-1", limitedModeID, wireBytes(1, controlCanonical, pubB, c0.Sig))
	add("S03", "high-S malleated form of a valid signature", "account-1", limitedModeID, wireBytes(1, controlCanonical, pubA, highS(t, c0.Sig)))
	doubleHash := sha256.Sum256(controlCanonical)
	dh, _ := idA.Sign(doubleHash[:])
	add("S04", "signature over SHA-256(SHA-256(canonical)) (double hash)", "account-1", limitedModeID, wireBytes(1, controlCanonical, pubA, dh))

	// Semantic validity the signature does not provide.
	badRef := control
	badRef.Binding.PodRef = "dave/admit-fixture"
	add("V01", "validly signed, unversioned pod_ref", "account-1", limitedModeID, rawSignedWire(t, mustCanon(t, badRef), idA))
	zeroPin := control
	zeroPin.Binding.HManifest = [32]byte{}
	add("V02", "validly signed, zero h_manifest", "account-1", limitedModeID, rawSignedWire(t, mustCanon(t, zeroPin), idA))

	emptyElem := prop("mf-ok", models, []string{"", "bash", "ripgrep"}, nil, 2500)
	add("V03", "validly signed tool set with an empty-string element", "account-1", limitedModeID, rawSignedWire(t, mustCanon(t, emptyElem), idA))

	// Authorization.
	add("K01", "valid signature by a key no account registered", "account-1", limitedModeID, signedWire(t, control, idX))
	add("K02", "buyer-b's valid commission submitted by account-1", "account-1", limitedModeID, signedWire(t, control, idB))
	add("K03", "valid signature by a key account-1 retired", "account-1", limitedModeID, signedWire(t, control, idR))

	// Pod resolution and binding coherence.
	stale := control
	stale.Binding.HManifest = sha256.Sum256([]byte("a manifest the store does not hold"))
	addP("P01", "pod_ref resolves a row whose pod_hash is not the signed h_manifest", stale, idA)
	addP("P02", "row exists but was withdrawn", prop("mf-withdrawn", models, tools, nil, 2500), idA)
	swapped := control
	swapped.Binding.PodRef = ref("mf-legacy")
	addP("P03", "pod_ref names another version of the pod than h_manifest does", swapped, idA)
	missing := control
	missing.Binding.PodRef = "dave/admit-fixture@9.9.9"
	addP("P04", "pod_ref names a version no row holds", missing, idA)

	// Manifest-side refusals.
	addP("D01", "v1 manifest: no fields_root, not supported by the limited mode", Proposal{
		Envelope: control.Envelope,
		Binding:  Binding{PodRef: ref("v1-plain"), HManifest: sha256.Sum256(manifests["v1-plain"])},
		Prose:    control.Prose,
	}, idA)
	corrupt := control
	corrupt.Binding = Binding{PodRef: ref("mf-corrupt-trailer"), HManifest: sha256.Sum256(manifests["mf-corrupt-trailer"]), FieldsRoot: control.Binding.FieldsRoot}
	addP("D02", "manifest claims v2 but its trailer is corrupt", corrupt, idA)
	addP("D03", "memory-bearing manifest", prop("mf-memory", models, tools, nil, 2500), idA)
	addP("D04", "sealed-grant manifest", prop("mf-sealed", models, tools, nil, 2500), idA)
	addP("D05", "no [model]: the default model is never read as 'no models'", prop("mf-no-model", models, tools, nil, 2500), idA)
	addP("D06", "no [budget]: the default budget is never read as a zero cap", prop("mf-no-budget", models, tools, nil, 2500), idA)
	addP("D07", "tools_allowed names an undeclared tool (TA-00 D3)", prop("mf-allowed-uncommitted", models, tools, nil, 2500), idA)
	addP("D08", "tools_allowed = [] beside declared tools (TA-00 D4)", prop("mf-allowed-empty", models, tools, nil, 2500), idA)
	addP("D09", "tools_allowed and tools_denied overlap (TA-00 D5)", prop("mf-allow-deny-overlap", models, tools, nil, 2500), idA)
	addP("D11", "33 declared tools: over the fields_root tools cap", prop("mf-33-tools", models, tools, nil, 2500), idA)
	addP("D12", "schema-invalid head (duplicate tools_allowed entries)", prop("mf-schema-invalid", models, tools, nil, 2500), idA)
	addP("D10", "non-NFC declared tool (TA-00 D5)", prop("mf-nfd-tool", models, []string{"café"}, nil, 2500), idA)
	addP("D13", "a raw CR byte in the manifest body (IB-04 parity, reef-core!125)", prop("mf-cr-body", models, tools, nil, 2500), idA)
	addP("D14", "[budget].max_sats outside the int64 range (IB-04 parity, reef-core!125)", prop("mf-huge-int", models, tools, nil, 2500), idA)
	// IB-07 server parity (konareef!135 security review M1): manifests the
	// offline replay once admitted and reef-core refuses.
	addP("D15", "an empty line after the [_commit] trailer (IB-07 parity)", prop("mf-trailer-blank-line", models, tools, nil, 2500), idA)
	addP("D16", "the [_commit] trailer has no final LF (IB-07 parity)", prop("mf-trailer-no-final-lf", models, tools, nil, 2500), idA)
	addP("D17", "trailing spaces after the fields_root value (IB-07 parity)", prop("mf-trailer-trailing-spaces", models, tools, nil, 2500), idA)
	addP("D18", "extra spaces around '=' in the fields_root line (IB-07 parity)", prop("mf-trailer-spaced-assign", models, tools, nil, 2500), idA)
	addP("D19", "an r_init_scheme key in the [_commit] trailer (IB-07 parity)", prop("mf-trailer-rinit-scheme", models, tools, nil, 2500), idA)
	addP("D20", "[model].provider contains '/' (IB-07 parity)", prop("mf-provider-slash", []string{"anthropic/x/claude-sonnet-4-5"}, tools, nil, 2500), idA)
	addP("D21", "an NFD name in [directive].tools_denied (IB-07 parity)", prop("mf-nfd-denied", models, tools, nil, 2500), idA)
	addP("D22", "an unknown table after [_files] (IB-07 parity)", prop("mf-table-after-files", models, tools, nil, 2500), idA)
	addP("D23", "an unknown [runtime] sub-table after [_files] (IB-07 parity)", prop("mf-subtable-after-files", models, tools, nil, 2500), idA)

	// Binding pin and recomputation.
	unpinned := control
	unpinned.Binding.FieldsRoot = nil
	addP("F01", "v2 manifest, binding pins no fields_root", unpinned, idA)
	wrong := control
	other := sha256.Sum256([]byte("not the trailer"))
	wrong.Binding.FieldsRoot = &other
	addP("F02", "binding pins a fields_root the trailer does not carry", wrong, idA)
	addP("F03", "self-consistent pin and forged trailer that omit the declared tool curl", prop("mf-forged", models, []string{"bash", "curl", "ripgrep"}, nil, 2500), idA)

	// Containment.
	addP("C01", "commission permits bash only; pod declares bash and ripgrep", prop("mf-ok", models, []string{"bash"}, nil, 2500), idA)
	addP("C02", "commission permits no models (null = stated empty); pod declares one", prop("mf-ok", nil, tools, nil, 2500), idA)
	addP("C03", "commission cap one satoshi below the manifest cap", prop("mf-ok", models, tools, nil, 2499), idA)
	addP("C04", "all three dimensions fail at once; every failure is reported", prop("mf-ok", nil, nil, nil, 0), idA)
	addP("C05", "explicit zero cap against a 2500-sat manifest", prop("mf-ok", models, tools, nil, 0), idA)
	addP("C06", "compute cap fits but compute plus the 100-sat author fee does not (owner decision D17)", prop("mf-priced", models, tools, nil, 2500), idA)

	// Replay sequences over the control case.
	fx.Sequences = []admissionSequence{
		{ID: "R01", Why: "a timeout retry of the same request returns the same run, not a second run", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "admitted", ExpectAgent: "agent-1"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "replayed", ExpectAgent: "agent-1"},
		}},
		{ID: "R02", Why: "the same commission with different inputs is a conflict, never a second run", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "admitted", ExpectAgent: "agent-1"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-2", Outcome: "started", Expect: "commission_replay_conflict"},
		}},
		{ID: "R03", Why: "a concurrent duplicate while the first request holds the claim", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "in_flight", Expect: "claimed", ExpectAgent: "agent-1"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "commission_admission_in_progress"},
		}},
		{ID: "R04", Why: "a failure before any runtime launch releases the claim; a retry gets a new run id", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "released", Expect: "released", ExpectAgent: "agent-1"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "admitted", ExpectAgent: "agent-2"},
		}},
		{ID: "R05", Why: "a timeout retry after the key was retired still returns the running run, not signer_retired", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "admitted", ExpectAgent: "agent-1"},
			{Action: "retire_key", Key: "buyer-a"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "replayed", ExpectAgent: "agent-1"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-2", Outcome: "started", Expect: "commission_signer_retired"},
		}},
		{ID: "R06", Why: "a revoked commission is never claimed, and a released claim does not bypass revocation", Steps: []sequenceStep{
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "released", Expect: "released", ExpectAgent: "agent-1"},
			{Action: "revoke", Case: "A01"},
			{Case: "A01", Account: "account-1", InputsDigest: "inputs-1", Outcome: "started", Expect: "commission_revoked"},
		}},
	}

	// Compute every expected verdict with the reference.
	world := newWorld(fx)
	for i := range fx.Cases {
		c := &fx.Cases[i]
		wire, _ := hex.DecodeString(c.WireHex)
		c.Expect = admitV1Reference(c.Request, wire, world)
	}
	return fx
}

// offCurveKey returns a 0x02-prefixed 33-byte key whose x coordinate has
// no point on secp256k1: the smallest such x, found deterministically.
func offCurveKey(t *testing.T) []byte {
	t.Helper()
	for x := 1; x < 1000; x++ {
		k := make([]byte, 33)
		k[0] = 0x02
		k[31], k[32] = byte(x>>8), byte(x)
		if _, err := secp256k1.ParsePubKey(k); err != nil {
			return k
		}
	}
	t.Fatal("no off-curve x below 1000")
	return nil
}

// mustCanon returns p's canonical bytes.
func mustCanon(t *testing.T, p Proposal) []byte {
	t.Helper()
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ── Tests ────────────────────────────────────────────────────────────────

// TestAdmissionV1VectorsAreCurrent regenerates the fixture and requires it
// to equal the committed file byte for byte. Set
// KONAREEF_UPDATE_ADMISSION_VECTORS=1 to rewrite the file after a reviewed
// change to the reference or the contract.
func TestAdmissionV1VectorsAreCurrent(t *testing.T) {
	fx := buildAdmissionVectors(t)
	got, err := json.MarshalIndent(fx, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("KONAREEF_UPDATE_ADMISSION_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(admissionFixturePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(admissionFixturePath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s", admissionFixturePath)
	}
	want, err := os.ReadFile(admissionFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: regenerate with KONAREEF_UPDATE_ADMISSION_VECTORS=1 and review the diff", admissionFixturePath)
	}
}

// TestAdmissionV1ExpectedCodes pins the verdict the contract requires for
// each case. It is independent of the committed JSON, so a change to the
// reference that silently changes a verdict fails here even if the fixture
// is regenerated in the same commit.
func TestAdmissionV1ExpectedCodes(t *testing.T) {
	want := map[string]string{
		"A01": "admit", "A02": "admit", "A03": "admit", "A04": "admit", "A05": "admit", "A06": "admit",
		"M01": "assurance_mode_required", "M02": "assurance_mode_unsupported",
		"M03": "commission_contract_unsupported", "M04": "commission_request_invalid",
		"W01": "commission_version_unsupported", "W02": "commission_malformed", "W03": "commission_malformed",
		"W04": "commission_malformed", "W05": "commission_malformed", "W06": "commission_malformed",
		"W07": "commission_too_large", "W08": "commission_malformed", "W09": "commission_noncanonical",
		"W10": "commission_noncanonical", "W11": "commission_noncanonical", "W12": "commission_malformed",
		"W13": "commission_malformed", "W14": "commission_too_large", "W15": "commission_malformed",
		"W16": "commission_malformed", "W17": "commission_signature_invalid", "W18": "commission_version_unsupported",
		"S01": "commission_signature_invalid", "S02": "commission_signature_invalid",
		"S03": "commission_signature_invalid", "S04": "commission_signature_invalid",
		"V01": "commission_invalid", "V02": "commission_invalid", "V03": "commission_invalid",
		"K01": "commission_signer_unregistered", "K02": "commission_signer_not_authorized", "K03": "commission_signer_retired",
		"P01": "commission_binding_mismatch", "P02": "commission_pod_not_found", "P03": "commission_binding_mismatch",
		"P04": "commission_pod_not_found", "P05": "admit", "P06": "admit",
		"D01": "commission_manifest_version_unsupported", "D02": "commission_manifest_commitment_unreadable",
		"D03": "commission_memory_unsupported", "D04": "commission_sealed_grants_unsupported",
		"D05": "commission_model_undeclared", "D06": "commission_budget_undeclared",
		"D07": "commission_tool_policy_invalid", "D08": "commission_tool_policy_invalid",
		"D09": "commission_tool_policy_invalid", "D10": "commission_tool_policy_invalid",
		"D11": "commission_manifest_invalid", "D12": "commission_manifest_invalid",
		"D13": "commission_manifest_invalid", "D14": "commission_manifest_invalid",
		"D15": "commission_manifest_commitment_unreadable", "D16": "commission_manifest_commitment_unreadable",
		"D17": "commission_manifest_commitment_unreadable", "D18": "commission_manifest_commitment_unreadable",
		"D19": "commission_manifest_commitment_unreadable", "D20": "commission_manifest_invalid",
		"D21": "commission_tool_policy_invalid", "D22": "commission_manifest_invalid",
		"D23": "commission_manifest_invalid",
		"F01": "commission_fields_root_unpinned", "F02": "commission_fields_root_mismatch", "F03": "commission_fields_root_unrecognized",
		"C01": "commission_not_contained", "C02": "commission_not_contained", "C03": "commission_not_contained",
		"C04": "commission_not_contained", "C05": "commission_not_contained", "C06": "commission_not_contained",
	}
	fx := buildAdmissionVectors(t)
	if len(fx.Cases) != len(want) {
		t.Fatalf("fixture has %d cases, test pins %d", len(fx.Cases), len(want))
	}
	for _, c := range fx.Cases {
		got := c.Expect.Code
		if c.Expect.Verdict == "admit" {
			got = "admit"
		}
		if got != want[c.ID] {
			t.Errorf("%s (%s): got %q, want %q", c.ID, c.Why, got, want[c.ID])
		}
	}
	byID := map[string]admissionCase{}
	for _, c := range fx.Cases {
		byID[c.ID] = c
	}
	if got := byID["C04"].Expect.FailedDims; strings.Join(got, ",") != "models,tools,spend" {
		t.Errorf("C04 must report every failing dimension, got %v", got)
	}
	if got := byID["A03"].Expect.MemoryClass; got != "legacy_zero" {
		t.Errorf("A03 memory class = %q, want legacy_zero", got)
	}
	if got := byID["C06"].Expect.FailedDims; strings.Join(got, ",") != "spend_total" {
		t.Errorf("C06 must fail on spend_total only, got %v", got)
	}
	if byID["P05"].Expect.PodRef != "dave/admit-fixture@1.0.0" || byID["P06"].Expect.PodRef != "mallory/admit-fixture@1.0.0" {
		t.Errorf("P05/P06 must select the row the signed pod_ref names, got %q and %q", byID["P05"].Expect.PodRef, byID["P06"].Expect.PodRef)
	}
	if got := byID["A01"].Expect.DimensionState["labels"]; got != "not_evaluated" {
		t.Errorf("A01 labels state = %q, want not_evaluated (never 'contained')", got)
	}
}

// TestAdmissionV1ControlIsCompatibleWithShippedVerify ties the reference to
// the shipped Go path: the control commission must pass
// Commission.VerifyAgainstManifest against its manifest, so the contract
// is a strict superset of what konareef already checks, not a different
// rule set.
func TestAdmissionV1ControlIsCompatibleWithShippedVerify(t *testing.T) {
	fx := buildAdmissionVectors(t)
	var control admissionCase
	for _, c := range fx.Cases {
		if c.ID == "A01" {
			control = c
		}
	}
	wire, _ := hex.DecodeString(control.WireHex)
	env, code := decodeWireV1(wire)
	if code != "" {
		t.Fatal(code)
	}
	p, code := decodeCanonicalV1(env.canonical)
	if code != "" {
		t.Fatal(code)
	}
	var manifest []byte
	for _, pd := range fx.Pods {
		if pd.Name == "mf-ok" {
			manifest = []byte(pd.Manifest)
		}
	}
	spec, err := pod.Parse(manifest)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	c := Reconstruct(p, hex.EncodeToString(env.pubKey), env.sig)
	if err := c.VerifyAgainstManifest(manifest, declared); err != nil {
		t.Fatalf("shipped VerifyAgainstManifest refuses the control: %v", err)
	}
}

// TestAdmissionV1E20MatchesMemoryRootFixture guards the copied E20 constant
// against the MEM-00 anchor: fields_root of the empty manifest under E20.
func TestAdmissionV1E20MatchesMemoryRootFixture(t *testing.T) {
	got, err := canon.FieldsRoot(nil, nil, 0, mustRoot(rInitV1Hex))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != "3003b812d8dba16d640505f0bacf48386b98d25a69b267a6d3d90ac209c2fb3e" {
		t.Fatalf("E20 constant does not reproduce the MEM-00 memory_free anchor: %x", got)
	}
}

// TestAdmissionV1PodClasses checks each stored row's expected memory class
// against an independent recomputation, so a mislabelled row cannot make
// a case pass for the wrong reason.
func TestAdmissionV1PodClasses(t *testing.T) {
	for _, p := range buildAdmissionVectors(t).Pods {
		if p.ExpectClass == "" {
			continue
		}
		d, code := deriveLimitedV1([]byte(p.Manifest))
		if code != "" {
			t.Fatalf("%s: derive: %s", p.Name, code)
		}
		fr, err := canon.ParseCommitFieldsRoot([]byte(p.Manifest))
		if err != nil {
			t.Fatal(err)
		}
		class, code := classifyFieldsRoot(d, fr)
		if code != "" || class != p.ExpectClass {
			t.Errorf("%s: class %q code %q, want %q", p.Name, class, code, p.ExpectClass)
		}
	}
}

// TestAdmissionV1ReplaySequences drives each scenario through the replay
// lookup, admission and claim model and checks every submit step.
func TestAdmissionV1ReplaySequences(t *testing.T) {
	fx := buildAdmissionVectors(t)
	for _, s := range fx.Sequences {
		got := runSequence(fx, s)
		for i, st := range s.Steps {
			if st.Action != "" {
				continue
			}
			if got[i][0] != st.Expect || (st.ExpectAgent != "" && got[i][1] != st.ExpectAgent) {
				t.Errorf("%s step %d: got (%s, %s), want (%s, %s)", s.ID, i, got[i][0], got[i][1], st.Expect, st.ExpectAgent)
			}
		}
	}
}

// TestAdmissionV1DecoderRejectsEveryTruncation is a bounded robustness
// check: every strict prefix of the control wire is refused, and none
// panics or admits.
func TestAdmissionV1DecoderRejectsEveryTruncation(t *testing.T) {
	fx := buildAdmissionVectors(t)
	wire, _ := hex.DecodeString(fx.Cases[0].WireHex)
	for n := 0; n < len(wire); n++ {
		if _, code := decodeWireV1(wire[:n]); code == "" {
			t.Fatalf("prefix of %d bytes decoded", n)
		}
	}
	keys := make([]string, 0)
	for _, k := range fx.Keys {
		keys = append(keys, k.Name)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "buyer-a,buyer-a-retired,buyer-b,stranger" {
		t.Fatalf("unexpected key set %v", keys)
	}
}
