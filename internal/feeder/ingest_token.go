// ingest_token.go — a CONFORMANCE implementation of reef-core's ingest-token
// wire contract (HMAC-SHA256(REEF_INGEST_SECRET, task_id), lowercase hex),
// kept here so this repo's tests can pin the normative vector and catch a
// unilateral change on either side of the seam.
//
// The feeder does NOT mint tokens in production: reef-core mints one per run
// and hands it to the sidecar on `--ingest-token` (see runFeeder in main.go),
// which is why nothing outside _test.go calls MintIngestToken. Do not
// provision REEF_INGEST_SECRET on the sidecar host — the secret belongs to
// reef-core alone, and copying it to the feeder would turn a one-way token
// handoff into a shared minting key.

package feeder

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// MintIngestToken returns HMAC-SHA256(secret, utf8(taskID)) as lowercase hex.
// taskID is MAC'd as its raw UTF-8 bytes exactly as it appears in the ingest
// URL path — no prefix, domain separator, length framing, or normalization.
func MintIngestToken(secret []byte, taskID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(taskID))
	return hex.EncodeToString(mac.Sum(nil))
}

// DecodeSecret32 accepts whichever encoding the operator provisioned: hex,
// then base64, then raw bytes — the first yielding exactly 32 bytes wins.
//
// The stated precedence (hex, then base64, then raw) matches the wire
// contract, but no test can falsify a mutant that swaps the hex and base64
// branches: decoding to exactly 32 bytes requires exactly 64 characters of
// hex (32 bytes * 2 hex digits/byte) versus exactly 44 characters of
// standard-padded base64 (ceil(32/3)*4). Those two required input lengths
// are different (64 != 44), so no single string can ever decode to 32
// bytes under both encodings at once — the branches are mutually exclusive
// by construction, and reordering them cannot change the outcome for any
// input. (A 64-hex-char string *is* valid base64, but decodes to 48 bytes,
// not 32 — it loses on the length check regardless of which branch runs
// first.) This is a structural property of the encodings, not something a
// test asserts; it is documented here so a future reviewer doesn't spend
// time trying to write an adversarial-ordering test that cannot exist.
func DecodeSecret32(raw string) ([]byte, error) {
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, errors.New("ingest secret must decode to exactly 32 bytes as hex, standard base64, or raw bytes")
}
