// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package secret is the client half of author-bound pod secrets.
//
// An author binds an API key to a published pod with a signed envelope.
// The publisher key signs Canonical(envelope, op); reef-core rebuilds the
// same bytes from the JSON body and verifies against the pubkey bound to
// the handle. The signature is the credential: there is no session token.
//
// The operation is the first line of the preimage, so a captured `set`
// body can never verify as `rm` (the same replay shape internal/listing
// closes with its op-first rule).
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Operation names the action the envelope authorises.
type Operation string

// The closed set of operations. Anything else is refused by Canonical.
const (
	OpSet Operation = "set"
	OpRm  Operation = "rm"
	OpLs  Operation = "ls"
)

// Envelope is the signed statement "this publisher sets/removes/lists
// secret Name on Handle/PodName at TS". ValueSHA256 binds the uploaded
// value on set; it is empty for rm and ls. Name is empty for ls.
type Envelope struct {
	Handle      string
	PodName     string
	Name        string
	ValueSHA256 string
	Nonce       string
	TS          int64
}

// namePattern mirrors $defs.dependencies.secrets.items.pattern in
// internal/pod/spec_v0_1.schema.json and the reef-core vault pattern.
var namePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// reservedExact and reservedPrefix mirror @reserved_exact and
// @reserved_prefix in reef-core lib/pod/secrets_vault.ex: an author
// cannot bind a harness credential name. reef-core P3-07 (reef-core!169)
// added ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN and REEF_RUN_CREDENTIAL,
// because each one could route or authenticate the harness's model calls.
// The prefix already covers OPENCODE_DISABLE_MODELS_FETCH and
// OPENCODE_DISABLE_PROJECT_CONFIG, the two flags P3-07 sets on the
// harness. testdata/reserved_names.json pins this list to reef-core's.
var reservedExact = map[string]bool{
	"ANTHROPIC_API_KEY":    true,
	"ANTHROPIC_BASE_URL":   true,
	"ANTHROPIC_AUTH_TOKEN": true,
	"OPENAI_API_KEY":       true,
	"OPENAI_BASE_URL":      true,
	"REEF_RUN_CREDENTIAL":  true,
}

const reservedPrefix = "OPENCODE_"

// CodeReserved is the refusal code for a reserved name. It is the same
// bytes as the `secret_reserved` code reef-core returns when it refuses
// the name (pod secret set/rm and spawn).
const CodeReserved = "secret_reserved"

// ErrReserved is wrapped by the error ValidateName returns for a
// reserved name, so a caller can tell it apart with errors.Is.
var ErrReserved = errors.New(CodeReserved)

// IsReserved reports whether name is a reserved harness name: one of
// reservedExact, or any name that starts with reservedPrefix. Input: a
// secret name. Output: true when reef-core refuses the name in every mode.
func IsReserved(name string) bool {
	return reservedExact[name] || strings.HasPrefix(name, reservedPrefix)
}

// ValidateName reports whether name is an acceptable secret name: it
// matches the schema pattern and is not a reserved harness name. Input: a
// secret name. Output: nil, or an error. The error for a reserved name
// wraps ErrReserved and carries the secret_reserved code.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("secret name %q must match %s", name, namePattern.String())
	}
	if IsReserved(name) {
		return fmt.Errorf("%w: secret name %q is reserved for the runtime harness", ErrReserved, name)
	}
	return nil
}

// NewEnvelope builds a set-envelope for value with a fresh 16-byte nonce
// and TS = now in unix seconds. The value itself is never stored on the
// envelope; only its SHA-256 is. It returns an error for an invalid or
// reserved name.
func NewEnvelope(handle, podName, name string, value []byte, now time.Time) (Envelope, error) {
	if err := ValidateName(name); err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("nonce: %w", err)
	}
	digest := sha256.Sum256(value)
	return Envelope{
		Handle:      handle,
		PodName:     podName,
		Name:        name,
		ValueSHA256: hex.EncodeToString(digest[:]),
		Nonce:       hex.EncodeToString(nonce),
		TS:          now.Unix(),
	}, nil
}

// Canonical renders the signed preimage: seven `key<TAB>value` lines
// joined by "\n", op first, no trailing newline. For OpRm the
// value_sha256 line is blank; for OpLs both name and value_sha256 are
// blank. It refuses an unknown op and any field carrying a tab or a
// newline, so no ambiguous bytes can ever be signed.
func Canonical(envelope Envelope, op Operation) ([]byte, error) {
	if op != OpSet && op != OpRm && op != OpLs {
		return nil, fmt.Errorf("secret operation %q is not one of set, rm, ls", string(op))
	}
	name := envelope.Name
	valueSHA := envelope.ValueSHA256
	switch op {
	case OpRm:
		valueSHA = ""
	case OpLs:
		name = ""
		valueSHA = ""
	}
	fields := []struct{ key, value string }{
		{"op", string(op)},
		{"handle", envelope.Handle},
		{"pod_name", envelope.PodName},
		{"name", name},
		{"value_sha256", valueSHA},
		{"nonce", envelope.Nonce},
		{"ts", strconv.FormatInt(envelope.TS, 10)},
	}
	lines := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.ContainsAny(field.value, "\t\n") {
			return nil, fmt.Errorf("secret envelope field %s contains a delimiter", field.key)
		}
		lines = append(lines, field.key+"\t"+field.value)
	}
	if envelope.Handle == "" || envelope.PodName == "" {
		return nil, errors.New("secret envelope needs a handle and a pod_name")
	}
	return []byte(strings.Join(lines, "\n")), nil
}
