package verify

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestSpartanCompressResult_DecodesPkPub(t *testing.T) {
	pk := append([]byte{0x02}, bytes.Repeat([]byte{0x11}, 32)...)
	enc, err := cbor.Marshal(map[string]any{
		"spartan_snark":            []byte{1, 2, 3},
		"first_step_public_inputs": bytes.Repeat([]byte{7}, 298),
		"last_step_public_inputs":  bytes.Repeat([]byte{7}, 298),
		"vkey_hash":                bytes.Repeat([]byte{9}, 32),
		"pk_pub":                   pk,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var scr SpartanCompressResult
	if err := cbor.Unmarshal(enc, &scr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(scr.PkPub, pk) {
		t.Fatalf("PkPub = %x, want %x", scr.PkPub, pk)
	}
}
