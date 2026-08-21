package feeder

import "testing"

func TestAssemblePodRecord(t *testing.T) {
	w := Witness{
		Manifest: []byte("#!konareef-toml/v2\n..."),
		P:        []byte("prompt"),
		R:        []byte("response"),
		Index:    0, C: 10, CMax: 100,
		Model:       "claude-opus-4-8",
		Models:      []string{"claude-opus-4-8"},
		Tools:       []string{"search"},
		ToolLog:     []ToolCallRecord{{Tool: "search", InHash: make([]byte, 32), OutHash: make([]byte, 32), Ts: 1719200000}},
		SigManifest: validSigLane(),
		PkPub:       validPubKeyBytes(),
	}
	pr, err := AssemblePodRecord(w)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if pr.Model != "claude-opus-4-8" || pr.CMax != 100 || len(pr.ToolLog) != 1 {
		t.Fatalf("unexpected PodRecord: %+v", pr)
	}
	if len(pr.SigManifest) != 74 || len(pr.PkPub) != 33 {
		t.Fatalf("sig/pk wrong size: %d/%d", len(pr.SigManifest), len(pr.PkPub))
	}
}

func TestAssembleRejectsBadSig(t *testing.T) {
	// Short lane fails the strict 74-byte contract even with a valid pubkey.
	w := Witness{SigManifest: make([]byte, 10), PkPub: validPubKeyBytes()}
	if _, err := AssemblePodRecord(w); err == nil {
		t.Fatal("expected error on short sig_manifest")
	}
}

func TestAssembleRejectsBadPkPub(t *testing.T) {
	// Valid sig lane, wrong-size pubkey → the pk_pub gate must reject.
	w := Witness{SigManifest: validSigLane(), PkPub: make([]byte, 32)}
	if _, err := AssemblePodRecord(w); err == nil {
		t.Fatal("expected error on wrong-size pk_pub")
	}
}
