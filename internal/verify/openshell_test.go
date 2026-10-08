// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell_test.go — tests of the OpenShell containment grade (US-111;
// reef-core OpenShell adapter, phase 2, design section 8).
//
// The golden inputs are copies of the reef-core fixtures (see the SOURCE
// files):
//
//   - testdata/reef_ocsf_v1: the US-108 reef-ocsf/v1 vectors;
//   - testdata/openshell_custody: the US-109/US-110 bundles (verifiable,
//     public, forged public, unavailable);
//   - testdata/bundle_v1: the US-110 Podman bundles (no OpenShell lines).
//
// Each other golden bundle of these tests is one of those bundles with one
// named change (goldenVariant). A change that touches hash-bound bytes
// recomputes what the change invalidates (the root and count lines, the
// precommit link hash, the chain link hashes), so that each bundle tests
// exactly one rule.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	openShellCustodyDir = "testdata/openshell_custody"
	ocsfVectorDir       = "testdata/reef_ocsf_v1"
)

// ── Helpers ──────────────────────────────────────────────────────

// loadOpenShellGolden loads a bundle file of testdata/openshell_custody.
func loadOpenShellGolden(t *testing.T, name string) *Bundle {
	t.Helper()
	return loadBundleFile(t, filepath.Join(openShellCustodyDir, name))
}

// loadBundleFile loads a konareef-bundle/v1 JSON file.
func loadBundleFile(t *testing.T, path string) *Bundle {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	b, err := LoadFromBytes(raw)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return b
}

// custodyLink returns the bundle's custody link.
func custodyLink(t *testing.T, b *Bundle) *ChainLink {
	t.Helper()
	link := findLink(b, "custody")
	if link == nil {
		t.Fatal("bundle has no custody link")
	}
	return link
}

// setCustodyLine replaces the value of the custody line `key`, then
// recomputes the chain hashes.
func setCustodyLine(t *testing.T, b *Bundle, key, value string) {
	t.Helper()
	link := custodyLink(t, b)
	lines := strings.Split(link.Data, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+": ") {
			lines[i] = key + ": " + value
			found = true
		}
	}
	if !found {
		t.Fatalf("custody blob has no %s line", key)
	}
	link.Data = strings.Join(lines, "\n")
	rechain(b)
}

// editOpenShellCustody applies edit to the custody blob's lines, then
// recomputes the chain hashes.
func editOpenShellCustody(t *testing.T, b *Bundle, edit func([]string) []string) {
	t.Helper()
	link := custodyLink(t, b)
	link.Data = strings.Join(edit(strings.Split(link.Data, "\n")), "\n")
	rechain(b)
}

// rechain recomputes every link hash in order and points each prev_hash
// at the link before it.
func rechain(b *Bundle) {
	for i := range b.Chain {
		if i > 0 {
			prev := b.Chain[i-1].Hash
			b.Chain[i].PrevHash = &prev
		}
		prevHex := ""
		if b.Chain[i].PrevHash != nil {
			prevHex = *b.Chain[i].PrevHash
		}
		hash := ComputeChainHash(prevHex, b.Chain[i].Data, b.Chain[i].Timestamp)
		b.Chain[i].Hash = hex.EncodeToString(hash[:])
	}
}

// editPrecommit changes a line of the precommit blob, then makes the
// custody record name the new precommit hash.
func editPrecommit(t *testing.T, b *Bundle, key, value string) {
	t.Helper()
	link := findLink(b, "openshell_precommit")
	if link == nil {
		t.Fatal("bundle has no openshell_precommit link")
	}
	lines := strings.Split(link.Data, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, key+": ") {
			lines[i] = key + ": " + value
		}
	}
	link.Data = strings.Join(lines, "\n")
	rechain(b)
	setCustodyLine(t, b, "OPENSHELL_PRECOMMIT", "sha256:"+findLink(b, "openshell_precommit").Hash)
}

// evidenceRecords returns the records of a bundle whose leaves are all
// real records.
func evidenceRecords(t *testing.T, b *Bundle) [][]byte {
	t.Helper()
	var records [][]byte
	for i, leaf := range b.OpenShellEvidence.Leaves {
		if leaf.Record == nil {
			t.Fatalf("leaf %d is withheld", i)
		}
		record, err := base64.StdEncoding.DecodeString(*leaf.Record)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

// setRecords replaces the leaves with records and sets the OCSF_LOG_ROOT
// and OCSF_LOG_RECORDS lines to match them.
func setRecords(t *testing.T, b *Bundle, records [][]byte) {
	t.Helper()
	leaves := make([]OCSFLeaf, len(records))
	for i, record := range records {
		encoded := base64.StdEncoding.EncodeToString(record)
		leaves[i] = OCSFLeaf{Record: &encoded}
	}
	b.OpenShellEvidence.Leaves = leaves
	root := OCSFRoot(records)
	setCustodyLine(t, b, "OCSF_LOG_ROOT", "sha256:"+hex.EncodeToString(root[:]))
	setCustodyLine(t, b, "OCSF_LOG_RECORDS", strconv.Itoa(len(records)))
}

// recordFields decodes the JSON object of a record (tag || JCS).
func recordFields(t *testing.T, record []byte) map[string]any {
	t.Helper()
	value, err := jcsDecode(record[1:])
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)
}

// makeRecord encodes tag || JCS(fields).
func makeRecord(t *testing.T, tag byte, fields map[string]any) []byte {
	t.Helper()
	body, err := jcsMarshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{tag}, body...)
}

// supervisorRecord is a SUPERVISOR:WARN record with msg at seq.
func supervisorRecord(t *testing.T, seq int, msg string) []byte {
	return makeRecord(t, ocsfEventTag, map[string]any{
		"v": ocsfRule, "seq": seq, "src": "sandbox", "trust": "supervisor_report",
		"class": "SUPERVISOR:WARN", "sev": "WARN", "msg": msg, "t_ms": 1791459259900, "msg_truncated": false,
	})
}

// setHeaderField changes one field of the header record.
func setHeaderField(t *testing.T, records [][]byte, key string, value any) {
	t.Helper()
	fields := recordFields(t, records[0])
	fields[key] = value
	records[0] = makeRecord(t, ocsfHeaderTag, fields)
}

// appendBeforeEnd inserts record before the last record (STREAM:END) and
// sets the header's last_seq to lastSeq.
func appendBeforeEnd(t *testing.T, records [][]byte, record []byte, lastSeq int) [][]byte {
	t.Helper()
	out := append(append(append([][]byte{}, records[:len(records)-1]...), record), records[len(records)-1])
	setHeaderField(t, out, "last_seq", lastSeq)
	return out
}

// setStreamEnd replaces the STREAM:END record.
func setStreamEnd(t *testing.T, records [][]byte, reason, code string) {
	t.Helper()
	records[len(records)-1] = makeRecord(t, ocsfEventTag, map[string]any{
		"v": ocsfRule, "seq": nil, "class": "STREAM:END", "reason": reason, "code": code, "message": "",
	})
}

// setGatewayField changes one field of the evidence's gateway object.
func setGatewayField(t *testing.T, b *Bundle, key string, value any) {
	t.Helper()
	var gateway map[string]any
	if err := json.Unmarshal(b.OpenShellEvidence.Gateway, &gateway); err != nil {
		t.Fatal(err)
	}
	gateway[key] = value
	raw, err := json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	b.OpenShellEvidence.Gateway = raw
}

// signBundle attaches a valid publisher attestation (attestation_test.go),
// so that --strict tests only the containment rule.
func signBundle(t *testing.T, b *Bundle) {
	t.Helper()
	manifest, podHashHex, sigB64, pubB64 := signedAttestation(t)
	manifestB64 := base64.StdEncoding.EncodeToString([]byte(manifest))
	version, publisher := "1.0.0", "alice"
	b.PodHash, b.PodVersion, b.PublisherID = &podHashHex, &version, &publisher
	b.PublisherSignature, b.PublisherPubkey, b.Manifest = &sigB64, &pubB64, &manifestB64
}

// readRecordsFile splits a launcher records file (<u32 BE length><record>).
func readRecordsFile(t *testing.T, path string) [][]byte {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for len(blob) > 0 {
		if len(blob) < 4 {
			t.Fatalf("%s: truncated frame", path)
		}
		size := binary.BigEndian.Uint32(blob[:4])
		records = append(records, blob[4:4+size])
		blob = blob[4+size:]
	}
	return records
}

// leavesOf wraps records as real leaves.
func leavesOf(records [][]byte) []OCSFLeaf {
	leaves := make([]OCSFLeaf, len(records))
	for i, record := range records {
		encoded := base64.StdEncoding.EncodeToString(record)
		leaves[i] = OCSFLeaf{Record: &encoded}
	}
	return leaves
}

// mustAssess runs AssessContainment and fails on a hard failure.
func mustAssess(t *testing.T, b *Bundle) ContainmentAssessment {
	t.Helper()
	a, err := AssessContainment(b)
	if err != nil {
		t.Fatalf("AssessContainment: unexpected hard failure: %v", err)
	}
	return a
}

// ── Golden variants ──────────────────────────────────────────────

// goldenVariant builds a golden bundle: base is a file of
// testdata/openshell_custody, change is the one named change.
type goldenVariant struct {
	name   string
	base   string
	change func(t *testing.T, b *Bundle)
}

// build loads the base bundle and applies the change.
func (v goldenVariant) build(t *testing.T) *Bundle {
	t.Helper()
	b := loadOpenShellGolden(t, v.base)
	if v.change != nil {
		v.change(t, b)
	}
	return b
}

// TestOpenShellGolden_UnavailableVerifiesDirectly: the copied
// unavailable.bundle.json (reef-core 41f96217, which gave its snapshot two
// real leaves) verifies with no change. Its snapshot root recomputes from
// snapshot_leaves, and its containment grade is claimed.
func TestOpenShellGolden_UnavailableVerifiesDirectly(t *testing.T) {
	b := loadOpenShellGolden(t, "unavailable.bundle.json")
	if len(b.SnapshotLeaves) == 0 {
		t.Fatal("the unavailable bundle has no snapshot leaves")
	}
	r := Verify(b)
	if !r.OK {
		t.Fatalf("divergences %v", r.Divergences)
	}
	if r.Containment.Grade != GradeClaimed || r.Containment.Form != "unavailable" {
		t.Errorf("containment %s %q, want claimed unavailable", r.Containment.Grade, r.Containment.Form)
	}
	if !slices.Contains(r.Containment.Reasons, "evidence unavailable: records_missing") {
		t.Errorf("reasons %v", r.Containment.Reasons)
	}
	for _, name := range []string{"full.bundle.json", "full.public.bundle.json", "full.public.forged.bundle.json", "unavailable.bundle.json"} {
		if r := Verify(loadOpenShellGolden(t, name)); !r.OK {
			t.Errorf("%s: %v", name, r.Divergences)
		}
	}
}

// ── reef-ocsf/v1 vectors (US-108) ────────────────────────────────

// TestOCSFVectors_RootsAndSummaries: each vector's root equals the
// manifest root, and the derived checks of the vectors hold (gapless,
// supervisor markers, listener lines, control character).
func TestOCSFVectors_RootsAndSummaries(t *testing.T) {
	var manifest struct {
		Rule    string `json:"rule"`
		Vectors []struct {
			Name        string `json:"name"`
			File        string `json:"file"`
			RecordCount int    `json:"record_count"`
			Root        string `json:"root"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile(filepath.Join(ocsfVectorDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Rule != ocsfRule || len(manifest.Vectors) != 4 {
		t.Fatalf("manifest: rule %q, %d vectors", manifest.Rule, len(manifest.Vectors))
	}
	gatewayRaw, err := os.ReadFile(filepath.Join(ocsfVectorDir, "real_run.gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := readOCSFGateway(gatewayRaw)
	if err != nil {
		t.Fatalf("real_run.gateway.json: %v", err)
	}

	summaries := map[string]ocsfSummary{}
	for _, vector := range manifest.Vectors {
		records := readRecordsFile(t, filepath.Join(ocsfVectorDir, vector.File))
		if len(records) != vector.RecordCount {
			t.Errorf("%s: %d records, manifest says %d", vector.Name, len(records), vector.RecordCount)
		}
		root := OCSFRoot(records)
		if hex.EncodeToString(root[:]) != vector.Root {
			t.Errorf("%s: root %x, manifest says %s", vector.Name, root, vector.Root)
		}
		leaves, err := readOCSFLeaves(leavesOf(records))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if got := ocsfRootFromLeafHashes(leaves.hashes); got != root {
			t.Errorf("%s: root from leaf hashes differs", vector.Name)
		}
		summaries[vector.Name] = summarizeOCSF(leaves.header, leaves.events, gateway,
			leaves.header.sandboxID, "192.0.2.10:4100", true)
	}

	real := summaries["real_run"]
	if len(real.gaplessReasons) != 0 || len(real.policyChangedReasons) != 0 {
		t.Errorf("real_run: gapless reasons %v, policy_changed reasons %v; want none", real.gaplessReasons, real.policyChangedReasons)
	}
	if want := []SupervisorMarker{{Seq: 57, Class: "informational"}}; !slices.Equal(real.markers, want) {
		t.Errorf("real_run markers %v, want %v", real.markers, want)
	}
	if real.listenerSeen == nil || *real.listenerSeen != 4 {
		t.Errorf("real_run listener_seen %v, want 4", real.listenerSeen)
	}
	before := summaries["real_run_marker_before_drain"]
	if want := []SupervisorMarker{{Seq: 57, Class: "possible_loss"}}; !slices.Equal(before.markers, want) {
		t.Errorf("real_run_marker_before_drain markers %v, want %v", before.markers, want)
	}
	if len(before.gaplessReasons) != 0 {
		t.Errorf("real_run_marker_before_drain: gapless reasons %v; a marker alone keeps the stream gapless", before.gaplessReasons)
	}
	if reasons := summaries["non_ascii"].gaplessReasons; len(reasons) != 0 {
		t.Errorf("non_ascii: gapless reasons %v, want none", reasons)
	}
	if reasons := summaries["control_character"].gaplessReasons; !slices.Contains(reasons, "control_character") {
		t.Errorf("control_character: gapless reasons %v, want control_character", reasons)
	}
}

// ── JCS (RFC 8785) ───────────────────────────────────────────────

// TestJCS_RFC8785NumberVectors: the IEEE 754 vectors of RFC 8785
// appendix B.
func TestJCS_RFC8785NumberVectors(t *testing.T) {
	vectors := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, vector := range vectors {
		got, err := jcsNumber(math.Float64frombits(vector.bits))
		if err != nil || got != vector.want {
			t.Errorf("0x%016x: got %q (%v), want %q", vector.bits, got, err, vector.want)
		}
	}
	for _, bits := range []uint64{0x7fffffffffffffff, 0x7ff0000000000000} {
		if _, err := jcsNumber(math.Float64frombits(bits)); err == nil {
			t.Errorf("0x%016x: want an error (NaN or Infinity)", bits)
		}
	}
}

// TestJCS_RFC8785Examples: the canonicalization examples of RFC 8785
// sections 3.2.2 and 3.2.3 (value forms and the UTF-16 member order).
func TestJCS_RFC8785Examples(t *testing.T) {
	cases := []struct{ name, input, want string }{
		{
			"section 3.2.2",
			`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`,
			`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			"section 3.2.3",
			`{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
	}
	for _, c := range cases {
		got, err := jcsCanonicalize([]byte(c.input))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, c.want)
		}
	}
	if _, err := jcsCanonicalize([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("two JSON values: want an error")
	}
}

// TestJCS_VectorRecordsAreCanonical: every record of every vector is
// canonical, and a re-spaced record is not.
func TestJCS_VectorRecordsAreCanonical(t *testing.T) {
	for _, file := range []string{"real_run.records", "non_ascii.records", "control_character.records"} {
		for i, record := range readRecordsFile(t, filepath.Join(ocsfVectorDir, file)) {
			canonical, err := jcsCanonicalize(record[1:])
			if err != nil || !bytes.Equal(canonical, record[1:]) {
				t.Errorf("%s record %d is not canonical (%v)", file, i, err)
			}
		}
	}
	spaced := []byte(`{"v": "reef-ocsf/v1"}`)
	if canonical, _ := jcsCanonicalize(spaced); bytes.Equal(canonical, spaced) {
		t.Error("a record with white space compared equal to its canonical form")
	}
}

// ── Grades (design 8.3, 8.4) ─────────────────────────────────────

// TestContainment_GoldenGrades: one golden bundle per grade and per
// derived check.
func TestContainment_GoldenGrades(t *testing.T) {
	cases := []struct {
		variant  goldenVariant
		grade    ContainmentGrade
		form     string
		reasons  []string // each must be an entry of Reasons
		info     []string // each must be an entry of Informational
		check    func(t *testing.T, a ContainmentAssessment)
		redacted bool
	}{
		{
			variant: goldenVariant{name: "verifiable bundle", base: "full.bundle.json"},
			grade:   GradeOperatorAttested, form: "full",
			info: []string{infoMarkerAtStop, infoPolicyFileToRevision1},
			check: func(t *testing.T, a ContainmentAssessment) {
				if a.Gapless == nil || !*a.Gapless || a.PolicyChanged == nil || *a.PolicyChanged {
					t.Errorf("gapless %v, policy_changed %v; want true, false", a.Gapless, a.PolicyChanged)
				}
				if a.ListenerServed == nil || *a.ListenerServed != 4 || a.ListenerSeen == nil || *a.ListenerSeen != 4 {
					t.Errorf("listener served %v seen %v; want 4 and 4", a.ListenerServed, a.ListenerSeen)
				}
				if a.DrainEndSeq == nil || *a.DrainEndSeq != 56 {
					t.Errorf("drain_end_seq %v, want 56", a.DrainEndSeq)
				}
				if want := []SupervisorMarker{{57, "informational"}}; !slices.Equal(a.SupervisorMarkers, want) {
					t.Errorf("markers %v, want %v", a.SupervisorMarkers, want)
				}
				if a.PolicyV1Source != "end" || a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "no_tool_log" {
					t.Errorf("policy_v1_source %q, cross_check %+v", a.PolicyV1Source, a.CrossCheck)
				}
			},
		},
		{
			variant: goldenVariant{name: "public bundle", base: "full.public.bundle.json"},
			grade:   GradeClaimed, form: "full", redacted: true,
			reasons: []string{reasonRedacted, reasonDisplayBundle},
			check: func(t *testing.T, a ContainmentAssessment) {
				if a.Gapless != nil || a.ListenerSeen != nil {
					t.Errorf("gapless %v, listener_seen %v; want not computed", a.Gapless, a.ListenerSeen)
				}
				if a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "redacted" {
					t.Errorf("cross_check %+v, want not_checked (redacted)", a.CrossCheck)
				}
			},
		},
		{
			variant: goldenVariant{name: "forged public bundle", base: "full.public.forged.bundle.json"},
			grade:   GradeClaimed, form: "full", redacted: true,
			reasons: []string{reasonRedacted, reasonDisplayBundle,
				"redaction metadata of leaf 64: seq 1000 is outside [1, 60]",
				`redaction metadata of leaf 65: class "NET:OPEN" is not HTTP:*`},
			check: func(t *testing.T, a ContainmentAssessment) {
				// Exactly the two forgeries: the forged seq 1000 does not
				// flag the later, true seq values.
				if len(a.Reasons) != 4 {
					t.Errorf("reasons %q, want the two bundle reasons and the two forgeries", a.Reasons)
				}
			},
		},
		{
			variant: goldenVariant{name: "unavailable bundle", base: "unavailable.bundle.json"},
			grade:   GradeClaimed, form: "unavailable",
			reasons: []string{"evidence unavailable: records_missing"},
			check: func(t *testing.T, a ContainmentAssessment) {
				if a.Gapless != nil || a.PolicyChanged != nil || a.ListenerServed != nil || a.ListenerSeen != nil || a.DrainEndSeq != nil {
					t.Errorf("unavailable form computed evidence fields: %+v", a)
				}
			},
		},
		{
			variant: goldenVariant{name: "unavailable storage_failed", base: "unavailable.bundle.json", change: func(t *testing.T, b *Bundle) {
				setCustodyLine(t, b, "OPENSHELL_EVIDENCE", "unavailable storage_failed")
			}},
			grade: GradeClaimed, form: "unavailable",
			reasons: []string{"evidence unavailable: storage_failed"},
		},
		{
			variant: goldenVariant{name: "full form without the key", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				b.OpenShellEvidence = nil
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{reasonNoKey},
		},
		{
			variant: goldenVariant{name: "verifiable false with every record", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				f := false
				b.Verifiable = &f
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{reasonDisplayBundle},
		},
		{
			variant: goldenVariant{name: "marker before the drain end", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setRecords(t, b, readRecordsFile(t, filepath.Join(ocsfVectorDir, "real_run_marker_before_drain.records")))
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{reasonPossibleLoss},
			check: func(t *testing.T, a ContainmentAssessment) {
				if want := []SupervisorMarker{{57, "possible_loss"}}; !slices.Equal(a.SupervisorMarkers, want) {
					t.Errorf("markers %v, want %v", a.SupervisorMarkers, want)
				}
				if slices.Contains(a.Informational, infoMarkerAtStop) {
					t.Error("a possible-loss marker is listed as informational")
				}
				if a.Gapless == nil || !*a.Gapless {
					t.Error("gapless should stay true")
				}
			},
		},
		{
			variant: goldenVariant{name: "supervisor Failed to flush", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), supervisorRecord(t, 61, "Failed to flush log batch: channel closed"), 61))
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"OCSF stream not gapless: supervisor_drop"},
			check:   wantGapless(false),
		},
		{
			variant: goldenVariant{name: "supervisor log push drop", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), supervisorRecord(t, 61, "Log push queue full; Dropping 12 lines"), 61))
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"OCSF stream not gapless: supervisor_drop"},
			check:   wantGapless(false),
		},
		{
			variant: goldenVariant{name: "supervisor warning without drop text", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), supervisorRecord(t, 61, "log push slow: 3 retries"), 61))
			}},
			grade: GradeOperatorAttested, form: "full",
			check: wantGapless(true),
		},
		{
			variant: goldenVariant{name: "server_end_before_stop", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				setStreamEnd(t, records, "server_end_before_stop", "OK")
				setRecords(t, b, records)
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"OCSF stream not gapless: server_end_before_stop"},
			check:   wantGapless(false),
		},
		{
			variant: goldenVariant{name: "closed_after_stop", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				setStreamEnd(t, records, "closed_after_stop", "CANCELLED")
				setRecords(t, b, records)
			}},
			grade: GradeOperatorAttested, form: "full",
			check: wantGapless(true),
		},
		{
			variant: goldenVariant{name: "server_end UNAVAILABLE", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				setStreamEnd(t, records, "server_end", "UNAVAILABLE")
				setRecords(t, b, records)
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"OCSF stream not gapless: server_end_code"},
		},
		{
			variant: goldenVariant{name: "drain_end_seq above last_seq", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				setHeaderField(t, records, "drain_end_seq", 61)
				setRecords(t, b, records)
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			// The marker (seq 57) is now before the drain end too.
			reasons: []string{"OCSF stream not gapless: drain_end_seq_above_last_seq", reasonPossibleLoss},
		},
		{
			variant: goldenVariant{name: "seq gap", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				// Drop the GATEWAY record with seq 58 ("supervisor session: ended").
				var kept [][]byte
				for _, record := range records {
					if fields := recordFields(t, record); fields["seq"] == json.Number("58") {
						continue
					}
					kept = append(kept, record)
				}
				setRecords(t, b, kept)
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"OCSF stream not gapless: seq_not_dense"},
		},
		{
			variant: goldenVariant{name: "listener lines missing", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "5")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"listener lines missing: 5 served, 4 in OCSF"},
		},
		{
			variant: goldenVariant{name: "listener lines without a served request", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "3")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"cross-check inconsistent"},
			check: func(t *testing.T, a ContainmentAssessment) {
				want := CrossCheck{Outcome: "inconsistent", Rows: []string{"X4: listener lines without a served request: 4 in OCSF, 3 served"}}
				if a.CrossCheck.Outcome != want.Outcome || !slices.Equal(a.CrossCheck.Rows, want.Rows) {
					t.Errorf("cross_check %+v, want %+v", a.CrossCheck, want)
				}
			},
		},
		{
			variant: goldenVariant{name: "policy_v1_source create", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setGatewayField(t, b, "policy_v1_source", "create")
			}},
			grade: GradeOperatorAttested, form: "full",
			info: []string{infoPolicyV1FromCreate},
			check: func(t *testing.T, a ContainmentAssessment) {
				if a.PolicyV1Source != "create" {
					t.Errorf("policy_v1_source %q, want create", a.PolicyV1Source)
				}
			},
		},
		{
			variant: goldenVariant{name: "policy changed (revision 3)", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setGatewayField(t, b, "policy_revision", map[string]any{"create": 1, "end": 3})
				setCustodyLine(t, b, "OPENSHELL_POLICY_REVISION", "create=1 end=3")
				setCustodyLine(t, b, "POLICY_CHANGED", "true")
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"policy changed during the run: rule_1, rule_2"},
			check: func(t *testing.T, a ContainmentAssessment) {
				if a.PolicyChanged == nil || !*a.PolicyChanged {
					t.Error("policy_changed should be true")
				}
			},
		},
		{
			variant: goldenVariant{name: "listener endpoint missing from policy_yaml", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				ev := b.OpenShellEvidence
				ev.PolicyYAML = strings.Replace(ev.PolicyYAML, "reef_run_listener:", "other_policy:", 1)
				sum := sha256.Sum256([]byte(ev.PolicyYAML))
				setCustodyLine(t, b, "OPENSHELL_POLICY_SUBMITTED_SHA256", "sha256:"+hex.EncodeToString(sum[:]))
				setGatewayField(t, b, "policy_submitted_sha256", hex.EncodeToString(sum[:]))
				editPrecommit(t, b, "POLICY_SHA256", "sha256:"+hex.EncodeToString(sum[:]))
			}},
			grade: GradeClaimed, form: "full",
			reasons: []string{"listener lines not checked: no reef_run_listener endpoint in policy_yaml"},
		},
	}

	for _, c := range cases {
		t.Run(c.variant.name, func(t *testing.T) {
			b := c.variant.build(t)
			a := mustAssess(t, b)
			if a.Grade != c.grade || a.Form != c.form || a.Redacted != c.redacted {
				t.Errorf("grade %s form %q redacted %t; want %s %q %t (reasons %v)",
					a.Grade, a.Form, a.Redacted, c.grade, c.form, c.redacted, a.Reasons)
			}
			for _, reason := range c.reasons {
				if !slices.Contains(a.Reasons, reason) {
					t.Errorf("reasons %q lack %q", a.Reasons, reason)
				}
			}
			if c.grade == GradeOperatorAttested && len(a.Reasons) != 0 {
				t.Errorf("operator_attested with reasons %v", a.Reasons)
			}
			for _, line := range c.info {
				if !slices.Contains(a.Informational, line) {
					t.Errorf("informational %q lacks %q", a.Informational, line)
				}
			}
			if c.check != nil {
				c.check(t, a)
			}
			// The whole verify: a grade is never a divergence.
			if r := Verify(b); !r.OK {
				t.Errorf("Verify failed: %v", r.Divergences)
			} else if r.Containment.Grade != a.Grade {
				t.Errorf("Verify grade %s, AssessContainment grade %s", r.Containment.Grade, a.Grade)
			}
		})
	}
}

// wantGapless returns a check that the assessment's gapless is want.
func wantGapless(want bool) func(t *testing.T, a ContainmentAssessment) {
	return func(t *testing.T, a ContainmentAssessment) {
		t.Helper()
		if a.Gapless == nil || *a.Gapless != want {
			t.Errorf("gapless %v, want %t", a.Gapless, want)
		}
	}
}

// TestContainment_RedactionMetadataNeverRaisesTheGrade: forged seq or
// class values on withheld leaves (filling a gap, an in-range seq, a
// non-HTTP class) leave the grade at claimed with redacted true, as in the
// public bundle.
func TestContainment_RedactionMetadataNeverRaisesTheGrade(t *testing.T) {
	public := mustAssess(t, loadOpenShellGolden(t, "full.public.bundle.json"))
	forgeries := map[string]func(leaf *OCSFLeaf){
		"seq 1000":         func(leaf *OCSFLeaf) { leaf.Seq = json.RawMessage("1000") },
		"seq null":         func(leaf *OCSFLeaf) { leaf.Seq = nil },
		"class NET:OPEN":   func(leaf *OCSFLeaf) { class := "NET:OPEN"; leaf.Class = &class },
		"class HTTP:GET":   func(leaf *OCSFLeaf) { class := "HTTP:GET"; leaf.Class = &class },
		"class GATEWAY":    func(leaf *OCSFLeaf) { class := "GATEWAY"; leaf.Class = &class },
		"seq 1 (in range)": func(leaf *OCSFLeaf) { leaf.Seq = json.RawMessage("1") },
	}
	for name, forge := range forgeries {
		t.Run(name, func(t *testing.T) {
			b := loadOpenShellGolden(t, "full.public.bundle.json")
			for i := range b.OpenShellEvidence.Leaves {
				if b.OpenShellEvidence.Leaves[i].Withheld != nil {
					forge(&b.OpenShellEvidence.Leaves[i])
				}
			}
			// The public bundle claims verifiable: true here, so only the
			// withheld leaves cap the grade.
			truth := true
			b.Verifiable = &truth
			a := mustAssess(t, b)
			if a.Grade != GradeClaimed || !a.Redacted || public.Grade != GradeClaimed {
				t.Errorf("grade %s redacted %t; want claimed, redacted (public: %s)", a.Grade, a.Redacted, public.Grade)
			}
			if !slices.Contains(a.Reasons, reasonRedacted) || a.Gapless != nil {
				t.Errorf("reasons %v gapless %v", a.Reasons, a.Gapless)
			}
		})
	}
}

// ── Hard failures (design 8.2) ───────────────────────────────────

// TestContainment_HardFailures: each rule of design 8.2, in each form it
// applies to, plus the precommit carry-forward rules. A hard failure fails
// the verify.
func TestContainment_HardFailures(t *testing.T) {
	cases := []struct {
		variant goldenVariant
		rule    int
	}{
		// Rule 1: malformed, out of order, duplicated, or not the line set.
		{goldenVariant{"full: lines out of order", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editOpenShellCustody(t, b, func(lines []string) []string {
				i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "OCSF_LOG_ROOT:") })
				lines[i], lines[i+1] = lines[i+1], lines[i]
				return lines
			})
		}}, 1},
		{goldenVariant{"full: duplicated line", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editOpenShellCustody(t, b, func(lines []string) []string {
				i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "POLICY_CHANGED:") })
				return slices.Insert(lines, i, lines[i])
			})
		}}, 1},
		{goldenVariant{"full: sandbox id unknown", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_SANDBOX_ID", "unknown")
		}}, 1},
		{goldenVariant{"full: malformed count", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "04")
		}}, 1},
		{goldenVariant{"full: line after the block", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editOpenShellCustody(t, b, func(lines []string) []string { return append(lines, "TOTAL_SATS: 0") })
		}}, 1},
		{goldenVariant{"unavailable: malformed sandbox id", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_SANDBOX_ID", "sandbox-1")
		}}, 1},
		{goldenVariant{"unavailable: missing line", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			editOpenShellCustody(t, b, func(lines []string) []string {
				return slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "OPENSHELL_SANDBOX_ID:") })
			})
		}}, 1},
		{goldenVariant{"precommit link without OpenShell lines", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			editOpenShellCustody(t, b, func(lines []string) []string {
				return slices.DeleteFunc(lines, func(l string) bool { return openShellAllKeys[custodyLineKey(l)] })
			})
		}}, 1},
		// Rule 2: unknown reason code.
		{goldenVariant{"unavailable: unknown reason code", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_EVIDENCE", "unavailable disk_full")
		}}, 2},
		// Rule 3: OPENSHELL_PRECOMMIT names no precommit link.
		{goldenVariant{"full: precommit hash names no link", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_PRECOMMIT", "sha256:"+strings.Repeat("ab", 32))
		}}, 3},
		{goldenVariant{"unavailable: precommit hash names no link", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_PRECOMMIT", "sha256:"+strings.Repeat("ab", 32))
		}}, 3},
		{goldenVariant{"full: OpenShell lines without a precommit link", "full.bundle.json", func(t *testing.T, b *Bundle) {
			b.Chain = slices.DeleteFunc(b.Chain, func(l ChainLink) bool { return l.ProofType == "openshell_precommit" })
			rechain(b)
		}}, 3},
		// Rule 4: precommit POLICY_SHA256 differs.
		{goldenVariant{"full: precommit policy hash differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "POLICY_SHA256", "sha256:"+strings.Repeat("cd", 32))
		}}, 4},
		{goldenVariant{"unavailable: precommit policy hash differs", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "POLICY_SHA256", "sha256:"+strings.Repeat("cd", 32))
		}}, 4},
		// Rule 5: TASK_ID or POD_ID differs.
		{goldenVariant{"full: precommit task id differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "TASK_ID", "task-other")
		}}, 5},
		{goldenVariant{"unavailable: precommit task id differs", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "TASK_ID", "task-other")
		}}, 5},
		{goldenVariant{"full: precommit pod id differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "POD_ID", "pod-other")
		}}, 5},
		{goldenVariant{"unavailable: precommit pod id differs", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			editPrecommit(t, b, "POD_ID", "pod-other")
		}}, 5},
		// Rule 6: unavailable form with the key.
		{goldenVariant{"unavailable: openshell_evidence key present", "unavailable.bundle.json", func(t *testing.T, b *Bundle) {
			b.OpenShellEvidence = loadOpenShellGolden(t, "full.bundle.json").OpenShellEvidence
		}}, 6},
		// Rule 7: run id.
		{goldenVariant{"full: key run_id differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			b.OpenShellEvidence.RunID = strings.Repeat("0", 32)
		}}, 7},
		{goldenVariant{"full: header run_id differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			records := evidenceRecords(t, b)
			setHeaderField(t, records, "run_id", strings.Repeat("0", 32))
			setRecords(t, b, records)
		}}, 7},
		// Rule 8: root and count.
		{goldenVariant{"full: root differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OCSF_LOG_ROOT", "sha256:"+strings.Repeat("00", 32))
		}}, 8},
		{goldenVariant{"full: record changed", "full.bundle.json", func(t *testing.T, b *Bundle) {
			records := evidenceRecords(t, b)
			setStreamEnd(t, records, "server_end", "CANCELLED")
			b.OpenShellEvidence.Leaves = leavesOf(records)
		}}, 8},
		{goldenVariant{"full: count differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OCSF_LOG_RECORDS", "81")
		}}, 8},
		{goldenVariant{"public: withheld leaf hash changed", "full.public.bundle.json", func(t *testing.T, b *Bundle) {
			for i := range b.OpenShellEvidence.Leaves {
				if b.OpenShellEvidence.Leaves[i].Withheld != nil {
					forged := strings.Repeat("11", 32)
					b.OpenShellEvidence.Leaves[i].Withheld = &forged
					break
				}
			}
		}}, 8},
		// Rule 9: JCS and tags.
		{goldenVariant{"full: record not canonical", "full.bundle.json", func(t *testing.T, b *Bundle) {
			records := evidenceRecords(t, b)
			records[5] = append([]byte{ocsfEventTag}, bytes.Replace(records[5][1:], []byte(`,`), []byte(`, `), 1)...)
			setRecords(t, b, records)
		}}, 9},
		{goldenVariant{"full: header tag wrong", "full.bundle.json", func(t *testing.T, b *Bundle) {
			records := evidenceRecords(t, b)
			records[0] = append([]byte{ocsfEventTag}, records[0][1:]...)
			setRecords(t, b, records)
		}}, 9},
		{goldenVariant{"full: event tag wrong", "full.bundle.json", func(t *testing.T, b *Bundle) {
			records := evidenceRecords(t, b)
			records[3] = append([]byte{ocsfHeaderTag}, records[3][1:]...)
			setRecords(t, b, records)
		}}, 9},
		// Rule 10: cached lines.
		{goldenVariant{"full: gapless line differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), supervisorRecord(t, 61, "Failed to flush"), 61))
		}}, 10},
		{goldenVariant{"full: policy_changed line differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "POLICY_CHANGED", "true")
		}}, 10},
		{goldenVariant{"public: policy_changed line differs", "full.public.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "POLICY_CHANGED", "true")
		}}, 10},
		{goldenVariant{"full: revision line differs from the gateway object", "full.bundle.json", func(t *testing.T, b *Bundle) {
			// The hash-bound line says the policy changed (create=1 end=4);
			// the unbound gateway object says it did not.
			setCustodyLine(t, b, "OPENSHELL_POLICY_REVISION", "create=1 end=4")
		}}, 10},
		{goldenVariant{"full: settings line differs from the gateway object", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_SETTINGS_DIGEST", "create=sha256:"+strings.Repeat("ee", 32)+" end=sha256:"+strings.Repeat("ee", 32))
		}}, 10},
		{goldenVariant{"full: enriched hash line differs from the gateway object", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setCustodyLine(t, b, "OPENSHELL_POLICY_ENRICHED_HASH", "none")
		}}, 10},
		{goldenVariant{"full: gateway object malformed", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setGatewayField(t, b, "policy_revision", "2")
		}}, 10},
		{goldenVariant{"full: gateway run_id differs", "full.bundle.json", func(t *testing.T, b *Bundle) {
			setGatewayField(t, b, "run_id", strings.Repeat("0", 32))
		}}, 7},
		// Rule 11: policy file hash.
		{goldenVariant{"full: policy_yaml changed", "full.bundle.json", func(t *testing.T, b *Bundle) {
			b.OpenShellEvidence.PolicyYAML += "# changed\n"
		}}, 11},
		// Rule 12: tool-log root.
		{goldenVariant{"full: tool_log_records do not match TOOL_LOG_ROOT", "full.bundle.json", func(t *testing.T, b *Bundle) {
			b.OpenShellEvidence.ToolLogRecords = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, custodyRecordSize))
		}}, 12},
		{goldenVariant{"full: tool_log_records not whole records", "full.bundle.json", func(t *testing.T, b *Bundle) {
			b.OpenShellEvidence.ToolLogRecords = base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
		}}, 12},
	}
	for _, c := range cases {
		t.Run(c.variant.name, func(t *testing.T) {
			b := c.variant.build(t)
			a, err := AssessContainment(b)
			var hard *ContainmentError
			if err == nil || !errorAs(err, &hard) {
				t.Fatalf("want a hard failure (rule %d), got grade %s, err %v", c.rule, a.Grade, err)
			}
			if hard.Rule != c.rule {
				t.Errorf("rule %d (%s), want rule %d", hard.Rule, hard.Msg, c.rule)
			}
			if a.Grade == GradeOperatorAttested || a.Grade == GradeClaimed {
				t.Errorf("hard failure graded %s", a.Grade)
			}
			r := Verify(b)
			if r.OK || !containsAny(r.Divergences, "openshell containment (rule") {
				t.Errorf("Verify did not fail on the hard failure: ok %t, %v", r.OK, r.Divergences)
			}
		})
	}
}

// errorAs is errors.As for *ContainmentError.
func errorAs(err error, target **ContainmentError) bool {
	hard, ok := err.(*ContainmentError)
	if ok {
		*target = hard
	}
	return ok
}

// TestContainment_UnavailablePathSkipsEvidenceChecks: an unavailable
// bundle runs rules 1 to 6 only: a bundle whose TOOL_LOG_ROOT has no
// tool_log_records and whose evidence is absent still grades claimed.
func TestContainment_UnavailablePathSkipsEvidenceChecks(t *testing.T) {
	b := goldenVariant{base: "unavailable.bundle.json"}.build(t)
	// No evidence check may run: put a TOOL_LOG_ROOT that no records give.
	setCustodyLine(t, b, "TOOL_LOG_ROOT", "sha256:"+strings.Repeat("99", 32))
	a := mustAssess(t, b)
	if a.Grade != GradeClaimed || !slices.Equal(a.Reasons, []string{"evidence unavailable: records_missing"}) {
		t.Errorf("grade %s reasons %v", a.Grade, a.Reasons)
	}
	if a.Gapless != nil || a.PolicyChanged != nil || a.ListenerSeen != nil || a.CrossCheck.Outcome != "not_checked" {
		t.Errorf("unavailable path computed evidence: %+v", a)
	}
}

// ── --strict (owner decision 2026-10-08) ─────────────────────────

// TestContainment_Strict: with a valid publisher attestation, --strict
// passes the verifiable OpenShell bundle and fails the public, the
// unavailable and the no-key bundles on their grade.
func TestContainment_Strict(t *testing.T) {
	cases := []struct {
		name string
		base string
		edit func(t *testing.T, b *Bundle)
		pass bool
	}{
		{"verifiable", "full.bundle.json", nil, true},
		{"public", "full.public.bundle.json", nil, false},
		{"forged public", "full.public.forged.bundle.json", nil, false},
		{"unavailable", "unavailable.bundle.json", nil, false},
		{"full form without the key", "full.bundle.json", func(t *testing.T, b *Bundle) { b.OpenShellEvidence = nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := goldenVariant{name: c.name, base: c.base, change: c.edit}.build(t)
			signBundle(t, b)
			if r := Verify(b); !r.OK {
				t.Fatalf("default mode failed: %v", r.Divergences)
			}
			r := VerifyStrict(b)
			if r.OK != c.pass {
				t.Errorf("--strict ok %t, want %t: %v", r.OK, c.pass, r.Divergences)
			}
			if !c.pass && !containsAny(r.Divergences, "--strict requires containment grade operator_attested") {
				t.Errorf("--strict divergences lack the containment rule: %v", r.Divergences)
			}
		})
	}
}

// TestContainment_BundlesWithoutOpenShellLinesUnchanged: bundles with no
// ISOLATION_ENGINE line grade not_claimed, verify as before, and keep
// today's --strict result (only the attestation divergence for an unsigned
// bundle; a pass when signed). The bundles are the konareef golden
// parity-real-1.bundle.json and the verifiable OpenShell golden with its
// precommit link, its OpenShell lines and its key removed (the chain of a
// Podman run).
func TestContainment_BundlesWithoutOpenShellLinesUnchanged(t *testing.T) {
	podmanLike := func(t *testing.T) *Bundle {
		b := loadOpenShellGolden(t, "full.bundle.json")
		b.OpenShellEvidence = nil
		b.Chain = slices.DeleteFunc(b.Chain, func(l ChainLink) bool { return l.ProofType == "openshell_precommit" })
		editOpenShellCustody(t, b, func(lines []string) []string {
			return slices.DeleteFunc(lines, func(l string) bool { return openShellAllKeys[custodyLineKey(l)] })
		})
		return b
	}
	cases := map[string]func(t *testing.T) *Bundle{
		"parity-real-1": func(t *testing.T) *Bundle { return loadBundleFile(t, "testdata/parity-real-1.bundle.json") },
		"podman-like":   podmanLike,
	}
	for name, load := range cases {
		t.Run(name, func(t *testing.T) {
			b := load(t)
			r := Verify(b)
			if !r.OK {
				t.Fatalf("Verify: %v", r.Divergences)
			}
			if r.Containment.Grade != GradeNotClaimed || r.Containment.Form != "" || len(r.Containment.Reasons) != 0 {
				t.Errorf("containment %+v, want not_claimed with no form", r.Containment)
			}
			strict := VerifyStrict(b)
			if want := []string{"publisher attestation envelope is absent; --strict requires it"}; !slices.Equal(strict.Divergences, want) {
				t.Errorf("--strict divergences %v, want %v", strict.Divergences, want)
			}
			signed := load(t)
			signBundle(t, signed)
			if r := VerifyStrict(signed); !r.OK {
				t.Errorf("--strict on the signed bundle: %v", r.Divergences)
			}
		})
	}
}

// TestContainment_JSONFieldNames: the JSON form has the field names of
// design section 8.1.
func TestContainment_JSONFieldNames(t *testing.T) {
	a := mustAssess(t, loadOpenShellGolden(t, "full.bundle.json"))
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	want := []string{"grade", "form", "reasons", "redacted", "gapless", "policy_changed", "drain_end_seq",
		"supervisor_markers", "listener_served", "listener_seen", "policy_v1_source", "cross_check", "informational"}
	got := make([]string, 0, len(fields))
	for key := range fields {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("JSON fields %v, want %v", got, want)
	}
	if fields["grade"] != "operator_attested" {
		t.Errorf("grade %v", fields["grade"])
	}
	empty, _ := json.Marshal(newContainmentAssessment())
	if !strings.Contains(string(empty), `"reasons":[]`) || !strings.Contains(string(empty), `"grade":"not_claimed"`) {
		t.Errorf("not_claimed JSON: %s", empty)
	}
}

// TestContainment_BundleNotVerifiedCapsTheGrade: a bundle that fails
// another check is never operator_attested.
func TestContainment_BundleNotVerifiedCapsTheGrade(t *testing.T) {
	b := loadOpenShellGolden(t, "full.bundle.json")
	b.Chain[0].Data += "x" // breaks the chain hash of the genesis link
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify passed a broken chain")
	}
	if r.Containment.Grade != GradeClaimed || !slices.Contains(r.Containment.Reasons, reasonBundleNotVerified) {
		t.Errorf("containment %+v", r.Containment)
	}
}

// TestPolicyChanged_Rule3FirstLoadedWithoutHash: a first CONFIG:LOADED
// record with no [hash:...] fires rule 3, also when the enriched hash is
// empty (reef-core compares {:ok, nil} with {:ok, enriched}).
func TestPolicyChanged_Rule3FirstLoadedWithoutHash(t *testing.T) {
	loaded := ocsfEvent{class: "CONFIG:LOADED", fields: map[string]any{"msg": "Acknowledged initial policy revision as loaded"}}
	gw := ocsfGateway{revisionCreate: 1, revisionEnd: 1, enrichedHash: ""}
	if got := policyChangedReasons(gw, []ocsfEvent{loaded}); !slices.Equal(got, []string{"rule_3"}) {
		t.Errorf("reasons %v, want [rule_3]", got)
	}
}

// TestURLAuthority: the listener authority of an HTTP:* record, as
// reef-core derives it with URI.parse/1.
func TestURLAuthority(t *testing.T) {
	cases := map[string]string{
		"http://192.0.2.10:4100/mcp/open_brain": "192.0.2.10:4100",
		"http://192.0.2.10:4100/bad%zzpath?x=1": "192.0.2.10:4100",
		"http://192.0.2.10/x":                   "192.0.2.10:80",
		"https://192.0.2.10/x":                  "192.0.2.10:443",
		"ws://192.0.2.10#frag":                  "192.0.2.10:80",
		"http://user:pw@192.0.2.10:4100/":       "192.0.2.10:4100",
		"http://[2001:db8::1]:4100/mcp":         "[2001:db8::1]:4100",
		"http://[2001:db8::1]/mcp":              "[2001:db8::1]:80",
		"192.0.2.10:4100/mcp":                   "",
		"gopher://192.0.2.10/":                  "",
		"http://192.0.2.10:port/":               "",
	}
	for input, want := range cases {
		if got := urlAuthority(input); got != want {
			t.Errorf("urlAuthority(%q) = %q, want %q", input, got, want)
		}
	}
}
