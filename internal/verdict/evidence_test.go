package verdict

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// manifestWithBash is a minimal valid pod manifest declaring a single `bash`
// context tool, so declaredToolDigests can resolve SHA-256("bash").
const manifestWithBash = `
pod_spec_version = "0.1"

[pod]
name    = "voice-forge"
version = "0.1.4"

[runtime]
kind = "lobster"

[directive]
task = "x"

[[context.tools]]
source = "bash"
`

// makeToolRecord builds a canonical 113-byte tool-log record.
func makeToolRecord(toolID string, args, result [32]byte, ts, sats uint64) []byte {
	rec := make([]byte, toolRecordLn)
	rec[0] = 0x20
	d := sha256.Sum256([]byte(toolID))
	copy(rec[1:33], d[:])
	copy(rec[33:65], args[:])
	copy(rec[65:97], result[:])
	binary.BigEndian.PutUint64(rec[97:105], ts)
	binary.BigEndian.PutUint64(rec[105:113], sats)
	return rec
}

func TestDecodeToolRecordResolvesName(t *testing.T) {
	var args, result [32]byte
	for i := range args {
		args[i] = byte(i)
		result[i] = byte(255 - i)
	}
	rec := makeToolRecord("bash", args, result, 1783593330453884, 7)
	names := declaredToolDigests([]byte(manifestWithBash))

	tc := decodeToolRecord(rec, names)
	if tc.Name != "bash" {
		t.Fatalf("Name = %q, want bash (digest→manifest resolution)", tc.Name)
	}
	if tc.ArgsHash != hex.EncodeToString(args[:]) {
		t.Errorf("ArgsHash = %s", tc.ArgsHash)
	}
	if tc.ResultHash != hex.EncodeToString(result[:]) {
		t.Errorf("ResultHash = %s", tc.ResultHash)
	}
	if tc.TsUs != 1783593330453884 {
		t.Errorf("TsUs = %d", tc.TsUs)
	}
	if tc.Sats != 7 {
		t.Errorf("Sats = %d", tc.Sats)
	}
	wantDigest := sha256.Sum256([]byte("bash"))
	if tc.IDDigest != hex.EncodeToString(wantDigest[:]) {
		t.Errorf("IDDigest = %s", tc.IDDigest)
	}
}

func TestDecodeToolRecordUnresolvedFallsBackToTool(t *testing.T) {
	var z [32]byte
	rec := makeToolRecord("mystery", z, z, 1, 0)
	tc := decodeToolRecord(rec, map[string]string{}) // no declared tools
	if tc.Name != "tool" {
		t.Fatalf("unresolved Name = %q, want tool", tc.Name)
	}
}

// A committed tool-log record is fail-closed: anything that is not exactly a
// canonical 113-byte, 0x20-prefixed record must be surfaced as malformed, not
// decoded into fields the evidence card would present as committed facts.
func TestDecodeToolRecordFailsClosedOnMalformed(t *testing.T) {
	var z [32]byte
	good := makeToolRecord("bash", z, z, 1, 0)

	short := good[:112]                             // one byte too short
	long := append(append([]byte{}, good...), 0x00) // one byte too long (114)
	wrongPrefix := append([]byte{}, good...)
	wrongPrefix[0] = 0x21 // valid length, wrong marker

	cases := map[string][]byte{
		"short":        short,
		"long":         long,
		"wrong-prefix": wrongPrefix,
		"empty":        {},
	}
	for name, rec := range cases {
		tc := decodeToolRecord(rec, map[string]string{})
		if tc.Name != "malformed" {
			t.Errorf("%s: Name = %q, want malformed (fail-closed)", name, tc.Name)
		}
	}

	// Sanity: the canonical record is still accepted.
	if tc := decodeToolRecord(good, map[string]string{}); tc.Name == "malformed" {
		t.Fatalf("canonical 113-B record was rejected as malformed")
	}
}

func TestBuildEvidenceMapsBundle(t *testing.T) {
	var args, result [32]byte
	args[0], result[0] = 0xAA, 0xBB
	rec := makeToolRecord("bash", args, result, 42, 0)

	// 298-byte first-step public inputs with distinct lane markers.
	pi := make([]byte, 298)
	pi[piRIn] = 0x11
	pi[piROut] = 0x22
	pi[piTRoot] = 0x33

	b := &verify.BundleV2{
		Version:            "konareef-bundle/v2",
		CircuitID:          "konareef-pod-step-v1",
		Disclosure:         "C",
		PodVersion:         "0.1.4",
		PodHash:            []byte{0x46, 0x0a},
		PublisherID:        "bob",
		PublisherPubkey:    []byte{0x02, 0x14},
		PublisherSignature: []byte{0x30, 0x45},
		Manifest:           []byte(manifestWithBash),
		Chain: []verify.ChainLinkV2{
			{ProofType: "structured_bundle", Hash: []byte{0xeb, 0xdd}, Timestamp: "2026-07-09T10:35:24Z"},
			{ProofType: "custody", Hash: []byte{0xdb, 0x41}, Timestamp: "2026-07-09T10:35:34Z"},
		},
		SpartanCompressResult: verify.SpartanCompressResult{
			SpartanSnark:          make([]byte, 12456),
			Z0:                    make([]byte, 736),
			VkeyHash:              []byte{0x01, 0x66},
			FirstStepPublicInputs: pi,
		},
		WitnessDisclosure: &verify.WitnessDisclosure{
			P:           []byte("do the thing"),
			R:           []byte("done"),
			TLogRecords: [][]byte{rec},
		},
	}
	r := &verify.ResultV2{
		OK:          true,
		ChainLength: 2,
		V2Verdict: &verify.Verdict{
			ProofValid: true, DisclosureValid: true, ChainPolicyValid: true,
			CommitmentsValid: true, SignatureValid: true,
		},
	}

	ev := BuildEvidence(b, r, "deadbeef", "http://reefcore:4000")

	if !ev.OK || ev.Verdict == nil || !ev.Verdict.ProofValid {
		t.Fatalf("verdict not passed through: %+v", ev.Verdict)
	}
	if ev.Pod.Name != "voice-forge" || ev.Pod.Version != "0.1.4" || ev.Pod.Circuit != "konareef-pod-step-v1" {
		t.Errorf("pod = %+v", ev.Pod)
	}
	if ev.Pod.PodHash != "460a" {
		t.Errorf("pod_hash = %s, want 460a", ev.Pod.PodHash)
	}
	if ev.Publisher.ID != "bob" || ev.Publisher.Pubkey != "0214" || ev.Publisher.Signature != "3045" {
		t.Errorf("publisher = %+v", ev.Publisher)
	}
	if ev.Execution.P != "do the thing" || ev.Execution.R != "done" {
		t.Errorf("exec P/R = %q / %q", ev.Execution.P, ev.Execution.R)
	}
	if len(ev.Execution.Tools) != 1 || ev.Execution.Tools[0].Name != "bash" {
		t.Fatalf("tools = %+v", ev.Execution.Tools)
	}
	if ev.Commitments.RIn[:2] != "11" || ev.Commitments.ROut[:2] != "22" || ev.Commitments.TRoot[:2] != "33" {
		t.Errorf("commitments lanes = %+v", ev.Commitments)
	}
	if ev.Proof.SnarkBytes != 12456 || ev.Proof.Z0Bytes != 736 || ev.Proof.ManifestBytes != len(manifestWithBash) {
		t.Errorf("proof = %+v", ev.Proof)
	}
	if len(ev.Chain) != 2 || ev.Chain[1].Type != "custody" || ev.Chain[1].Hash != "db41" {
		t.Errorf("chain = %+v", ev.Chain)
	}
	if ev.Divergences == nil {
		t.Error("Divergences must be non-nil (empty slice) for clean JSON")
	}
}

func TestBuildEvidenceEmptyDisclosureNonNilSlices(t *testing.T) {
	b := &verify.BundleV2{Version: "konareef-bundle/v2"} // no witness, no chain
	r := &verify.ResultV2{OK: true, V2Verdict: &verify.Verdict{}}
	ev := BuildEvidence(b, r, "", "")
	if ev.Execution.Tools == nil {
		t.Error("Tools must be non-nil empty slice")
	}
	if ev.Chain == nil {
		t.Error("Chain must be non-nil empty slice")
	}
}

func TestLaneShortBufferReturnsEmpty(t *testing.T) {
	if got := lane(make([]byte, 10), piTRoot); got != "" {
		t.Errorf("short buffer lane = %q, want empty", got)
	}
}

func TestAsTextHexFallback(t *testing.T) {
	if got := asText([]byte("hello")); got != "hello" {
		t.Errorf("utf8 asText = %q", got)
	}
	bad := []byte{0xff, 0xfe}
	if got := asText(bad); !strings.EqualFold(got, "fffe") {
		t.Errorf("non-utf8 asText = %q, want fffe", got)
	}
}
