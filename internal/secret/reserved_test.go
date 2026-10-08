// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Reserved-name parity with reef-core. testdata/reserved_names.json is a
// copy of reef-core's @reserved_exact and @reserved_prefix
// (lib/pod/secrets_vault.ex), with probe names on each side of the rule.
// The tests pin konareef's list to that vector in both directions, so a
// name added on one side only fails here. When
// KONAREEF_REEF_CORE_SECRETS_VAULT names a reef-core secrets_vault.ex, the
// vector itself is also checked against that source file.
package secret

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// reservedVector is the shape of testdata/reserved_names.json.
type reservedVector struct {
	Source         string   `json:"source"`
	Code           string   `json:"code"`
	ReservedExact  []string `json:"reserved_exact"`
	ReservedPrefix string   `json:"reserved_prefix"`
	Refused        []string `json:"refused"`
	Accepted       []string `json:"accepted"`
}

// loadReservedVector reads and decodes testdata/reserved_names.json.
// Input: the test. Output: the decoded vector; the test fails on any
// read or decode error.
func loadReservedVector(t *testing.T) reservedVector {
	t.Helper()
	data, err := os.ReadFile("testdata/reserved_names.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector reservedVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return vector
}

// TestReservedListMatchesReefCoreVector checks that konareef reserves
// exactly reef-core's names and prefix: no fewer (a name reef-core
// refuses at spawn would pass here) and no more (konareef would refuse a
// name reef-core accepts).
func TestReservedListMatchesReefCoreVector(t *testing.T) {
	vector := loadReservedVector(t)
	local := make([]string, 0, len(reservedExact))
	for name := range reservedExact {
		local = append(local, name)
	}
	sort.Strings(local)
	want := append([]string(nil), vector.ReservedExact...)
	sort.Strings(want)
	if strings.Join(local, ",") != strings.Join(want, ",") {
		t.Fatalf("reservedExact = %v, reef-core vector = %v", local, want)
	}
	if reservedPrefix != vector.ReservedPrefix {
		t.Fatalf("reservedPrefix = %q, reef-core vector = %q", reservedPrefix, vector.ReservedPrefix)
	}
	if CodeReserved != vector.Code {
		t.Fatalf("CodeReserved = %q, reef-core code = %q", CodeReserved, vector.Code)
	}
}

// TestValidateNameRefusesEveryReservedName runs every reserved and probe
// name through ValidateName and NewEnvelope, the two paths `pod secret`
// uses, and checks the refusal carries the secret_reserved code. The
// accepted probes are the control: near-miss names still pass.
func TestValidateNameRefusesEveryReservedName(t *testing.T) {
	vector := loadReservedVector(t)
	now := time.Unix(1757404800, 0)
	refused := append(append([]string(nil), vector.ReservedExact...), vector.Refused...)
	for _, name := range refused {
		err := ValidateName(name)
		if !errors.Is(err, ErrReserved) {
			t.Errorf("ValidateName(%q) = %v, want ErrReserved", name, err)
			continue
		}
		if !strings.Contains(err.Error(), "secret_reserved") {
			t.Errorf("ValidateName(%q) error %q does not name the code", name, err)
		}
		if _, err := NewEnvelope("alice", "research-bot", name, []byte("x"), now); !errors.Is(err, ErrReserved) {
			t.Errorf("NewEnvelope(%q) = %v, want ErrReserved", name, err)
		}
	}
	for _, name := range vector.Accepted {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
		if IsReserved(name) {
			t.Errorf("IsReserved(%q) = true, want false", name)
		}
	}
}

// TestReservedVectorMatchesReefCoreSource compares the vector with a
// reef-core checkout's secrets_vault.ex. It runs only when
// KONAREEF_REEF_CORE_SECRETS_VAULT holds that file's path, because
// konareef's CI has no reef-core checkout.
func TestReservedVectorMatchesReefCoreSource(t *testing.T) {
	path := os.Getenv("KONAREEF_REEF_CORE_SECRETS_VAULT")
	if path == "" {
		t.Skip("set KONAREEF_REEF_CORE_SECRETS_VAULT to a reef-core lib/pod/secrets_vault.ex")
	}
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reef-core source: %v", err)
	}
	exact := regexp.MustCompile(`(?s)@reserved_exact ~w\((.*?)\)`).FindSubmatch(source)
	prefix := regexp.MustCompile(`@reserved_prefix "([^"]*)"`).FindSubmatch(source)
	if exact == nil || prefix == nil {
		t.Fatalf("%s has no @reserved_exact ~w(...) or @reserved_prefix", path)
	}
	names := strings.Fields(string(exact[1]))
	sort.Strings(names)
	vector := loadReservedVector(t)
	want := append([]string(nil), vector.ReservedExact...)
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("reef-core @reserved_exact = %v, vector = %v", names, want)
	}
	if string(prefix[1]) != vector.ReservedPrefix {
		t.Fatalf("reef-core @reserved_prefix = %q, vector = %q", prefix[1], vector.ReservedPrefix)
	}
}
