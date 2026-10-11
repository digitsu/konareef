// openshell_admitted_test.go tests rule 3 of the policy_changed rule with
// the gateway object's policy_admitted_hash (reef-core#155). With the W20
// setting on, the supervisor loads the policy the gateway admitted
// (revision 1 or 2 plus the run provider), so the CONFIG:LOADED hash is
// policy_admitted_hash and not policy_enriched_hash. The vectors and the
// goldens come from reef-core (testdata/*/SOURCE).

package verify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// admittedVectors is the expected listener count of each #155 vector.
var admittedVectors = map[string]uint64{"w20_admitted_rev2": 2, "w20_admitted_rev1": 2}

// admittedGoldens are the #155 custody goldens.
var admittedGoldens = []string{"w20_admitted.bundle.json", "w20_admitted_rev1.bundle.json"}

// containmentRule returns the rule of a hard failure, or 0 for none.
func containmentRule(err error) int {
	var failure *ContainmentError
	if errors.As(err, &failure) {
		return failure.Rule
	}
	return 0
}

// deleteGatewayField removes one key of the evidence's gateway object.
func deleteGatewayField(t *testing.T, b *Bundle, key string) {
	t.Helper()
	var gateway map[string]any
	if err := json.Unmarshal(b.OpenShellEvidence.Gateway, &gateway); err != nil {
		t.Fatal(err)
	}
	delete(gateway, key)
	raw, err := json.Marshal(gateway)
	if err != nil {
		t.Fatal(err)
	}
	b.OpenShellEvidence.Gateway = raw
}

// TestOCSFVectors_W20AdmittedManifest: the roots of the #155 vectors match
// the manifest; with policy_admitted_hash no policy_changed rule fires;
// without it (the phase-2 rule) rule 3 fires.
func TestOCSFVectors_W20AdmittedManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(ocsfVectorDir, "manifest.w20_admitted.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Rule    string `json:"rule"`
		Vectors []struct {
			Name        string `json:"name"`
			File        string `json:"file"`
			RecordCount int    `json:"record_count"`
			Root        string `json:"root"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Rule != ocsfRule || len(manifest.Vectors) != len(admittedVectors) {
		t.Fatalf("manifest.w20_admitted.json: rule %q, %d vectors", manifest.Rule, len(manifest.Vectors))
	}
	endpoints := []string{"192.0.2.10:4100", "192.0.2.10:4102"}
	for _, vector := range manifest.Vectors {
		records := readRecordsFile(t, filepath.Join(ocsfVectorDir, vector.File))
		if len(records) != vector.RecordCount {
			t.Errorf("%s: %d records, manifest says %d", vector.Name, len(records), vector.RecordCount)
		}
		root := OCSFRoot(records)
		if hex.EncodeToString(root[:]) != vector.Root {
			t.Errorf("%s: root %x, manifest says %s", vector.Name, root, vector.Root)
		}
		gatewayRaw, err := os.ReadFile(filepath.Join(ocsfVectorDir, vector.Name+".gateway.json"))
		if err != nil {
			t.Fatal(err)
		}
		gateway, err := readOCSFGateway(gatewayRaw)
		if err != nil {
			t.Fatalf("%s.gateway.json: %v", vector.Name, err)
		}
		if gateway.admittedHash == "" || gateway.admittedHash == gateway.enrichedHash {
			t.Fatalf("%s: admitted hash %q, enriched %q", vector.Name, gateway.admittedHash, gateway.enrichedHash)
		}
		leaves, err := readOCSFLeaves(leavesOf(records))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		summary := summarizeOCSF(leaves.header, leaves.events, gateway, leaves.header.sandboxID, endpoints, true)
		if len(summary.gaplessReasons) != 0 || len(summary.policyChangedReasons) != 0 {
			t.Errorf("%s: gapless %v, policy_changed %v", vector.Name, summary.gaplessReasons, summary.policyChangedReasons)
		}
		if summary.listenerSeen == nil || *summary.listenerSeen != admittedVectors[vector.Name] {
			t.Errorf("%s: listener_seen %v, want %d", vector.Name, summary.listenerSeen, admittedVectors[vector.Name])
		}
		gateway.admittedHash = ""
		if got := policyChangedReasons(gateway, leaves.events); !slices.Equal(got, []string{"rule_3"}) {
			t.Errorf("%s without policy_admitted_hash: reasons %v, want [rule_3]", vector.Name, got)
		}
	}
}

// TestAdmittedGoldens_Grades: the #155 goldens verify with
// POLICY_CHANGED false and grade operator_attested.
func TestAdmittedGoldens_Grades(t *testing.T) {
	for _, name := range admittedGoldens {
		t.Run(name, func(t *testing.T) {
			b := loadOpenShellGolden(t, name)
			if line := custodyLines(t, b)["POLICY_CHANGED"]; line != "false" {
				t.Fatalf("POLICY_CHANGED %s", line)
			}
			r := Verify(b)
			if !r.OK {
				t.Fatalf("divergences %v", r.Divergences)
			}
			a := r.Containment
			if a.Grade != GradeOperatorAttested || len(a.Reasons) != 0 {
				t.Errorf("grade %s reasons %v, want operator_attested and no reason", a.Grade, a.Reasons)
			}
			if a.PolicyChanged == nil || *a.PolicyChanged {
				t.Errorf("policy_changed %v, want false", a.PolicyChanged)
			}
		})
	}
}

// TestAdmittedGoldens_KeyIsBoundByPolicyChanged: the key is under no hash,
// but POLICY_CHANGED binds the result. Removing the key (what a reader
// that ignores it computes, as konareef v0.6.0 does) or changing it makes
// the recomputed rule 3 fire, which differs from the line: rule 10.
func TestAdmittedGoldens_KeyIsBoundByPolicyChanged(t *testing.T) {
	for _, name := range admittedGoldens {
		for label, edit := range map[string]func(t *testing.T, b *Bundle){
			"key removed": func(t *testing.T, b *Bundle) { deleteGatewayField(t, b, "policy_admitted_hash") },
			"key changed": func(t *testing.T, b *Bundle) {
				setGatewayField(t, b, "policy_admitted_hash", "cc"+hex.EncodeToString(make([]byte, 31)))
			},
		} {
			t.Run(name+"/"+label, func(t *testing.T) {
				b := loadOpenShellGolden(t, name)
				edit(t, b)
				if _, err := AssessContainment(b); containmentRule(err) != 10 {
					t.Fatalf("error %v, want a rule-10 failure", err)
				}
			})
		}
	}
}

// TestAdmittedHash_BadShapeFailsRule10: a policy_admitted_hash that is
// present but not 64 lower-case hex digits is a rule-10 failure, as in
// reef-core ({:bad_gateway, :policy_admitted_hash}).
func TestAdmittedHash_BadShapeFailsRule10(t *testing.T) {
	upper := "C735367637AB40E5C735367637AB40E5C735367637AB40E5C735367637AB40E5"
	for _, bad := range []any{nil, "", upper, "abc", 7} {
		b := loadOpenShellGolden(t, "w20_admitted.bundle.json")
		setGatewayField(t, b, "policy_admitted_hash", bad)
		if _, err := AssessContainment(b); containmentRule(err) != 10 {
			t.Errorf("policy_admitted_hash %v: error %v, want a rule-10 failure", bad, err)
		}
	}
}

// TestAdmittedHash_OlderGoldensHaveNoKey: the phase-2 and US-205 goldens
// have no policy_admitted_hash, so they keep the phase-2 rule and grade.
func TestAdmittedHash_OlderGoldensHaveNoKey(t *testing.T) {
	for _, name := range []string{"full.bundle.json", "full.public.bundle.json", "w20.bundle.json", "w20_cut.bundle.json", "w20.public.bundle.json"} {
		var gateway map[string]any
		if err := json.Unmarshal(loadOpenShellGolden(t, name).OpenShellEvidence.Gateway, &gateway); err != nil {
			t.Fatal(err)
		}
		if _, present := gateway["policy_admitted_hash"]; present {
			t.Errorf("%s has policy_admitted_hash", name)
		}
	}
}

// TestPolicyChanged_Rule3AdmittedHash: with the key, rule 3 compares the
// first CONFIG:LOADED hash with the admitted hash at revision 2 and at
// revision 1, and the key wins over the enriched hash. A first
// CONFIG:LOADED with no hash still fires.
func TestPolicyChanged_Rule3AdmittedHash(t *testing.T) {
	admitted, enriched := "ad"+hex.EncodeToString(make([]byte, 31)), "e1"+hex.EncodeToString(make([]byte, 31))
	loaded := func(hash string) ocsfEvent {
		msg := "Acknowledged initial policy revision as loaded [version:2]"
		if hash != "" {
			msg += " [hash:" + hash + "]"
		}
		return ocsfEvent{class: "CONFIG:LOADED", fields: map[string]any{"msg": msg}}
	}
	rev2 := ocsfGateway{revisionCreate: 1, revisionEnd: 2, enrichedHash: enriched, admittedHash: admitted}
	rev1 := ocsfGateway{revisionCreate: 1, revisionEnd: 1, enrichedHash: "", admittedHash: admitted}
	phase2 := ocsfGateway{revisionCreate: 1, revisionEnd: 2, enrichedHash: enriched}
	cases := []struct {
		name  string
		gw    ocsfGateway
		event ocsfEvent
		want  []string
	}{
		{"rev 2, loaded the admitted policy", rev2, loaded(admitted), nil},
		{"rev 2, loaded the bare revision 2", rev2, loaded(enriched), []string{"rule_3"}},
		{"rev 1, loaded the admitted policy", rev1, loaded(admitted), nil},
		{"rev 1, no key (phase 2)", ocsfGateway{revisionCreate: 1, revisionEnd: 1}, loaded(admitted), []string{"rule_3"}},
		{"no key, loaded revision 2 (phase 2)", phase2, loaded(enriched), nil},
		{"no key, loaded the admitted policy", phase2, loaded(admitted), []string{"rule_3"}},
		{"key, first CONFIG:LOADED without a hash", rev2, loaded(""), []string{"rule_3"}},
	}
	for _, c := range cases {
		if got := policyChangedReasons(c.gw, []ocsfEvent{c.event}); !slices.Equal(got, c.want) {
			t.Errorf("%s: reasons %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAdmittedHash_CannotClearRule3 is the negative test of Hermes !188
// note 10062. The node writes a bundle whose custody says
// POLICY_CHANGED: true because rule 3 fired (the first CONFIG:LOADED hash
// is neither policy_enriched_hash nor the node's policy_admitted_hash).
// The bundle verifies and grades with the reason rule_3. An editor then
// sets only gateway.policy_admitted_hash to the CONFIG:LOADED hash, which
// is under no hash. The recomputed rule 3 no longer fires, so the
// recomputed policy_changed (false) differs from the hash-bound
// POLICY_CHANGED line (true): rule 10 fails, and the edit gives no clean
// grade. Two node-written cases: a bundle without the key (phase 2, or a
// node before reef-core#155), and a bundle with a key that differs from
// CONFIG:LOADED. The reverse direction (a POLICY_CHANGED: false bundle with
// the key removed or changed) is TestAdmittedGoldens_KeyIsBoundByPolicyChanged.
func TestAdmittedHash_CannotClearRule3(t *testing.T) {
	var golden map[string]any
	if err := json.Unmarshal(loadOpenShellGolden(t, "w20_admitted.bundle.json").OpenShellEvidence.Gateway, &golden); err != nil {
		t.Fatal(err)
	}
	// The CONFIG:LOADED hash of the vector is the golden's admitted hash.
	loadedHash, _ := golden["policy_admitted_hash"].(string)
	if len(loadedHash) != 64 {
		t.Fatalf("golden policy_admitted_hash %q", loadedHash)
	}

	for name, nodeKey := range map[string]func(t *testing.T, b *Bundle){
		"node wrote no key": func(t *testing.T, b *Bundle) { deleteGatewayField(t, b, "policy_admitted_hash") },
		"node wrote another admitted hash": func(t *testing.T, b *Bundle) {
			setGatewayField(t, b, "policy_admitted_hash", "ab"+hex.EncodeToString(make([]byte, 31)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The node-written bundle: rule 3 fires, and the node wrote
			// POLICY_CHANGED: true under the custody hash (rechain).
			nodeBundle := func() *Bundle {
				b := loadOpenShellGolden(t, "w20_admitted.bundle.json")
				nodeKey(t, b)
				setCustodyLine(t, b, "POLICY_CHANGED", "true")
				return b
			}
			r := Verify(nodeBundle())
			if !r.OK {
				t.Fatalf("the node-written bundle does not verify: %v", r.Divergences)
			}
			a := r.Containment
			if a.PolicyChanged == nil || !*a.PolicyChanged || a.Grade == GradeOperatorAttested ||
				!slices.Contains(a.Reasons, "policy changed during the run: rule_3") {
				t.Fatalf("node-written bundle: grade %s policy_changed %v reasons %v", a.Grade, a.PolicyChanged, a.Reasons)
			}

			// The edit: only the unbound gateway key, set to CONFIG:LOADED.
			edited := nodeBundle()
			setGatewayField(t, edited, "policy_admitted_hash", loadedHash)
			if _, err := AssessContainment(edited); containmentRule(err) != 10 {
				t.Fatalf("edited bundle: error %v, want a rule-10 failure", err)
			}
			if r := Verify(edited); r.OK {
				t.Fatalf("edited bundle verifies: grade %s", r.Containment.Grade)
			}
		})
	}
}
