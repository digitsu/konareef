// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package listing

import (
	"bytes"
	"strings"
	"testing"
)

// The delimiter-injection collision this validation exists to close.
//
// The preimage frames fields as "key\tvalue" joined by "\n". If a value
// may itself contain \t or \n, a publisher can move the frame boundary:
// these two DIFFERENT field-sets rendered to IDENTICAL bytes, so one
// signature authenticated both splits. A signed preimage that does not
// uniquely commit to its field values is unsound, so both sides must now
// be rejected outright.
func TestCanonicalRejectsDelimiterInjectionCollision(t *testing.T) {
	a := Fields{
		Revision: Revision(1),
		Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 500,
		ExecutionClass: "cloud",
		Category:       "research\ndisplay_description\tEVIL",
		Description:    "Good",
	}
	b := Fields{
		Revision: Revision(1),
		Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 500,
		ExecutionClass: "cloud",
		Category:       "research",
		Description:    "EVIL\ndisplay_description\tGood",
	}

	gotA, errA := Canonical(a, OpUpsert)
	if errA == nil {
		t.Errorf("Canonical(a) accepted a category containing \\n and \\t: %q", gotA)
	}
	gotB, errB := Canonical(b, OpUpsert)
	if errB == nil {
		t.Errorf("Canonical(b) accepted a description containing \\n and \\t: %q", gotB)
	}

	// The collision itself: neither may yield usable bytes, and the two
	// field-sets must never render to the same thing.
	if errA == nil && errB == nil && bytes.Equal(gotA, gotB) {
		t.Errorf("COLLISION: two different Fields produced identical bytes: %q", gotA)
	}
}

// Every string field in the preimage is validated — not just the two
// that happened to collide above. A gap in any one of them reopens the
// same class of attack.
func TestCanonicalRejectsControlCharactersInEveryStringField(t *testing.T) {
	bad := map[string]string{
		"tab":             "x\ty",
		"newline":         "x\ny",
		"carriage return": "x\ry",
		"nul":             "x\x00y",
		"del":             "x\x7fy",
		"vertical tab":    "x\vy",
		"form feed":       "x\fy",
		"escape":          "x\x1by",
		"bare leading":    "\x01x",
		"bare trailing":   "x\x1f",
	}
	fields := map[string]func(string) Fields{
		"Handle":         func(v string) Fields { return Fields{Revision: Revision(1), Handle: v} },
		"PodName":        func(v string) Fields { return Fields{Revision: Revision(1), PodName: v} },
		"ExecutionClass": func(v string) Fields { return Fields{Revision: Revision(1), ExecutionClass: v} },
		"Category":       func(v string) Fields { return Fields{Revision: Revision(1), Category: v} },
		"Description":    func(v string) Fields { return Fields{Revision: Revision(1), Description: v} },
	}

	for fieldName, mk := range fields {
		for charName, value := range bad {
			t.Run(fieldName+"/"+charName, func(t *testing.T) {
				_, err := Canonical(mk(value), OpUpsert)
				if err == nil {
					t.Fatalf("Canonical accepted %s containing a %s", fieldName, charName)
				}
				// The error must name the offending field so a
				// publisher can actually act on it.
				if !strings.Contains(err.Error(), fieldName) {
					t.Errorf("error %q does not name the offending field %q", err, fieldName)
				}
			})
		}
	}
}

// Rejection must be narrow. This is user-facing display metadata: real
// listings carry spaces, punctuation, currency symbols, accented Latin,
// CJK, and emoji. Over-rejecting here would be a bug in its own right.
func TestCanonicalAcceptsRealWorldText(t *testing.T) {
	good := []string{
		"",
		"research",
		"Summarizes a research question.",
		"Data & analytics — fast, cheap, 100% automated!",
		"Résumé analyseur (français)",
		"日本語のリサーチボット",
		"简体中文 / 繁體中文",
		"Привет, мир",
		"emoji ok 🦞🐙",
		"tilde~ and del-adjacent }|{",
		"quotes \"double\" and 'single' and `back`",
	}
	for _, v := range good {
		t.Run(v, func(t *testing.T) {
			if _, err := Canonical(Fields{
				Revision: Revision(1),
				Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 1,
				ExecutionClass: "cloud", Category: v, Description: v,
			}, OpUpsert); err != nil {
				t.Errorf("Canonical rejected valid text %q: %v", v, err)
			}
		})
	}
}

// A multi-byte UTF-8 rune must never be rejected because one of its
// bytes looks like something else. Continuation bytes are 0x80-0xBF and
// lead bytes 0xC2-0xF4, so none can fall in the rejected C0/DEL range —
// this pins that reasoning as an executable claim.
func TestCanonicalAcceptsEveryMultibyteRune(t *testing.T) {
	var sb strings.Builder
	for r := rune(0x20); r < rune(0x3000); r++ {
		if r == 0x7f {
			continue
		}
		sb.WriteRune(r)
	}
	if _, err := Canonical(Fields{Revision: Revision(1), Category: sb.String()}, OpUpsert); err != nil {
		t.Errorf("Canonical rejected a printable-rune sweep: %v", err)
	}
}
