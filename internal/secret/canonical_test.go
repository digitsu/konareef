// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"strings"
	"testing"
	"time"
)

// The exact bytes reef-core rebuilds from the JSON body. The same literal
// appears in reef-core test/pod/pod_secrets/canonical_test.exs. If one
// side changes, both tests change together.
const wantSetPreimage = "op\tset\n" +
	"handle\talice\n" +
	"pod_name\tresearch-bot\n" +
	"name\tELEVENLABS_API_KEY\n" +
	"value_sha256\t2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\n" +
	"nonce\t000102030405060708090a0b0c0d0e0f\n" +
	"ts\t1757404800"

func fixedEnvelope() Envelope {
	return Envelope{
		Handle:      "alice",
		PodName:     "research-bot",
		Name:        "ELEVENLABS_API_KEY",
		ValueSHA256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", // sha256("foo")
		Nonce:       "000102030405060708090a0b0c0d0e0f",
		TS:          1757404800,
	}
}

func TestCanonical_Set(t *testing.T) {
	got, err := Canonical(fixedEnvelope(), OpSet)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if string(got) != wantSetPreimage {
		t.Fatalf("preimage mismatch:\n got %q\nwant %q", got, wantSetPreimage)
	}
}

func TestCanonical_RmAndLsBlankTheValueFields(t *testing.T) {
	envelope := fixedEnvelope()
	rm, err := Canonical(envelope, OpRm)
	if err != nil {
		t.Fatalf("Canonical rm: %v", err)
	}
	if !strings.HasPrefix(string(rm), "op\trm\n") || !strings.Contains(string(rm), "\nvalue_sha256\t\n") {
		t.Fatalf("rm preimage = %q", rm)
	}
	ls, err := Canonical(envelope, OpLs)
	if err != nil {
		t.Fatalf("Canonical ls: %v", err)
	}
	if !strings.Contains(string(ls), "\nname\t\n") || !strings.Contains(string(ls), "\nvalue_sha256\t\n") {
		t.Fatalf("ls preimage = %q", ls)
	}
}

func TestCanonical_RefusesDelimitersAndBadOp(t *testing.T) {
	envelope := fixedEnvelope()
	envelope.PodName = "bad\tname"
	if _, err := Canonical(envelope, OpSet); err == nil {
		t.Fatal("tab in pod_name accepted")
	}
	if _, err := Canonical(fixedEnvelope(), Operation("drop")); err == nil {
		t.Fatal("unknown op accepted")
	}
}

func TestNewEnvelope(t *testing.T) {
	now := time.Unix(1757404800, 0)
	envelope, err := NewEnvelope("alice", "research-bot", "ELEVENLABS_API_KEY", []byte("foo"), now)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if envelope.ValueSHA256 != fixedEnvelope().ValueSHA256 || envelope.TS != 1757404800 || len(envelope.Nonce) != 32 {
		t.Fatalf("envelope = %+v", envelope)
	}
	if _, err := NewEnvelope("alice", "research-bot", "lowercase", []byte("x"), now); err == nil {
		t.Fatal("invalid name accepted")
	}
	if _, err := NewEnvelope("alice", "research-bot", "ANTHROPIC_API_KEY", []byte("x"), now); err == nil {
		t.Fatal("reserved name accepted")
	}
}
