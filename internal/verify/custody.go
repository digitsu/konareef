// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody.go — custody-record rules (versions v3, v4 and v5) and the
// MCP broker assurance that a custody record can support.
//
// The custody commitment's `data` blob is newline-separated `KEY: value`
// lines, and the chain hash covers all of it. Three lines in it matter
// here:
//
//   - `CUSTODY_PROOF: vN` — the record version. It must be the first line
//     and it must appear once.
//   - `TOOL_LOG_ROOT: sha256:<hex>` — the server's SHA-256 custody root
//     over the stored tool-log records. v4 and v5 require it; v3 must not
//     have it.
//   - `MCP_BROKER: <value>` — the broker marker. `contained` appears only
//     with v5, and v5 appears only with `contained`. `proof_incomplete`
//     appears only with v3 or v4. A run with no broker grant has no
//     marker.
//
// The rules below mirror reef-core's `Verifier.check_custody_record/1`
// exactly, including the order in which they are checked, so that each
// refusal carries the same code (for example `custody_v5_without_contained`)
// on both sides. reef-core's custody compatibility fixture pins that; its
// test is kept out of the public export.
//
// A bundle without a verified chain-head anchor cannot anchor its custody
// record. The chain hash shows that the record's data is consistent with
// its link, but anyone can build a consistent chain. So a bundle can show
// at most an UNANCHORED v5 claim (BrokerAssuranceContainedRootUnchecked).
// Only a check against the stored server record (AssessCustodyRecord) can
// give BrokerAssuranceContained. A verified chain-head anchor
// (reef-core#76) makes the record authentic but still does not recompute
// its TOOL_LOG_ROOT, so it does not change these labels.
//
// Two different tool-log roots exist and they are never compared with each
// other:
//
//   - the SHA-256 custody root (this file, CustodyToolLogRoot), which the
//     server hashes into the custody blob; and
//   - the Poseidon t_root (package tlog), which the ZK proof binds.
//
// A custody record, even a verified v5 record, is server custody evidence.
// It is not a ZK spend guarantee and it says nothing about circuit
// coverage. BrokerAssurance and its labels exist so that a display never
// claims more than the record proves.
//
// Public surface:
//
//   - CustodyVersion, BrokerMarker, CustodyClaim — the parsed claims
//   - CustodyRuleError and the ErrCustody* sentinels — refusal codes
//   - ParseCustodyBlob — the rules that read only the blob
//   - CustodyColumns, CheckCustodyRecord — the full record rules
//   - CustodyToolLogRoot, SplitCustodyToolLogRecords — the SHA-256 root
//   - BrokerAssurance, CustodyAssessment, AssessCustodyBlob,
//     AssessCustodyRecord, BrokerAssuranceLabel — display classification

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CustodyVersion is the value of the `CUSTODY_PROOF:` line.
type CustodyVersion string

// The custody versions a verifier accepts. Every other value is refused
// with ErrCustodyVersionUnknown.
const (
	CustodyV3 CustodyVersion = "v3"
	CustodyV4 CustodyVersion = "v4"
	CustodyV5 CustodyVersion = "v5"
)

// BrokerMarker is the value of the `MCP_BROKER:` line. The empty value
// means the line is absent.
type BrokerMarker string

// The accepted broker markers.
const (
	BrokerMarkerAbsent          BrokerMarker = ""
	BrokerMarkerProofIncomplete BrokerMarker = "proof_incomplete"
	BrokerMarkerContained       BrokerMarker = "contained"
)

// CustodyClaim is what a custody blob states, after the blob rules pass.
//
//   - Version: the `CUSTODY_PROOF:` value.
//   - Marker: the `MCP_BROKER:` value, or BrokerMarkerAbsent.
//   - ToolLogRoot: the decoded `TOOL_LOG_ROOT:` bytes, or nil for v3.
type CustodyClaim struct {
	Version     CustodyVersion
	Marker      BrokerMarker
	ToolLogRoot []byte
}

// CustodyRuleError is a custody-record refusal. Code is the reef-core
// verifier's error name, so that both verifiers report the same code for
// the same record.
type CustodyRuleError struct {
	Code string
}

// Error returns the refusal code with a package prefix.
func (e *CustodyRuleError) Error() string { return "custody record: " + e.Code }

// The custody-record refusals. Compare with errors.Is. Each Code equals
// the reef-core error atom of the same name, with one exception:
// ErrToolLogRecordsNotMultiple is reef-core's `{:not_a_record_multiple, n}`
// tuple. reef-core's `custody_data_missing` (a NULL data column) has no
// counterpart here, because a Go string is never NULL; empty data is
// refused with ErrCustodyVersionMissing.
var (
	ErrCustodyVersionMissing       = &CustodyRuleError{"custody_version_missing"}
	ErrCustodyVersionMultipleLines = &CustodyRuleError{"custody_version_multiple_lines"}
	ErrCustodyVersionUnknown       = &CustodyRuleError{"custody_version_unknown"}
	ErrMCPBrokerMultipleLines      = &CustodyRuleError{"mcp_broker_multiple_lines"}
	ErrMCPBrokerLineUnknown        = &CustodyRuleError{"mcp_broker_line_unknown"}
	ErrCustodyV5WithoutContained   = &CustodyRuleError{"custody_v5_without_contained"}
	ErrMCPBrokerContainedBelowV5   = &CustodyRuleError{"mcp_broker_contained_below_v5"}
	ErrCustodyV3WithToolLogRoot    = &CustodyRuleError{"custody_v3_with_tool_log_root"}
	ErrToolLogRootMissing          = &CustodyRuleError{"tool_log_root_missing"}
	ErrToolLogRootMultipleLines    = &CustodyRuleError{"tool_log_root_multiple_lines"}
	ErrToolLogRootMalformed        = &CustodyRuleError{"tool_log_root_malformed"}
	ErrToolLogRootUndecodable      = &CustodyRuleError{"tool_log_root_undecodable"}
	ErrToolLogRecordsMissing       = &CustodyRuleError{"tool_log_records_missing"}
	ErrToolLogRecordsNotMultiple   = &CustodyRuleError{"tool_log_records_not_a_record_multiple"}
	ErrToolLogRootMismatch         = &CustodyRuleError{"tool_log_root_mismatch"}
)

// CustodyRuleCode returns the refusal code of err, or "" when err is not
// a CustodyRuleError.
func CustodyRuleCode(err error) string {
	var ce *CustodyRuleError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

const (
	custodyVersionPrefix = "CUSTODY_PROOF:"
	mcpBrokerPrefix      = "MCP_BROKER:"
	toolLogRootPrefix    = "TOOL_LOG_ROOT:"
)

// toolLogRootLine is the only accepted shape of the root line. It matches
// reef-core's `~r/^TOOL_LOG_ROOT: sha256:([0-9a-f]+)$/` on one line.
var toolLogRootLine = regexp.MustCompile(`^TOOL_LOG_ROOT: sha256:([0-9a-f]+)$`)

// ParseCustodyBlob applies the custody rules that read only the blob
// (rules 1 to 5 of the custody-v5 wire contract), in reef-core's order:
//
//  1. exactly one `CUSTODY_PROOF:` line, and it is the first line;
//  2. the version is v3, v4 or v5;
//  3. at most one `MCP_BROKER:` line, with value `proof_incomplete` or
//     `contained`;
//  4. v5 requires `contained`, and v3 and v4 must not carry it;
//  5. v4 and v5 require exactly one well-formed `TOOL_LOG_ROOT:` line, and
//     v3 must not have one.
//
// It does not check the root against the tool-log records; see
// CheckCustodyRecord.
//
// Input: data, the custody commitment's `data` blob as stored.
// Output: the parsed claim, or a *CustodyRuleError naming the first rule
// that failed.
func ParseCustodyBlob(data string) (CustodyClaim, error) {
	lines := strings.Split(data, "\n")

	version, err := custodyVersion(lines)
	if err != nil {
		return CustodyClaim{}, err
	}
	marker, err := mcpBrokerLine(lines)
	if err != nil {
		return CustodyClaim{}, err
	}
	if err := checkMarker(version, marker); err != nil {
		return CustodyClaim{}, err
	}
	root, rootPresent, rootErr := blobToolLogRoot(lines)
	switch {
	case version == CustodyV3 && rootErr == nil && !rootPresent:
		// Genuine v3: no root line.
	case version == CustodyV3 && rootErr == nil:
		return CustodyClaim{}, ErrCustodyV3WithToolLogRoot
	case rootErr == nil && !rootPresent:
		return CustodyClaim{}, ErrToolLogRootMissing
	case rootErr != nil:
		return CustodyClaim{}, rootErr
	}
	return CustodyClaim{Version: version, Marker: marker, ToolLogRoot: root}, nil
}

// custodyVersion returns the version from the first line. A
// `CUSTODY_PROOF:` line anywhere after the first line is a duplicate, even
// when the first line is not a version line.
func custodyVersion(lines []string) (CustodyVersion, error) {
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, custodyVersionPrefix) {
			return "", ErrCustodyVersionMultipleLines
		}
	}
	first := lines[0]
	if !strings.HasPrefix(first, custodyVersionPrefix) {
		return "", ErrCustodyVersionMissing
	}
	switch v := CustodyVersion(strings.TrimPrefix(first, custodyVersionPrefix+" ")); v {
	case CustodyV3, CustodyV4, CustodyV5:
		return v, nil
	default:
		return "", ErrCustodyVersionUnknown
	}
}

// mcpBrokerLine returns the broker marker, BrokerMarkerAbsent when there
// is no `MCP_BROKER:` line, or a refusal for an unknown value or a second
// line.
func mcpBrokerLine(lines []string) (BrokerMarker, error) {
	var found []string
	for _, line := range lines {
		if strings.HasPrefix(line, mcpBrokerPrefix) {
			found = append(found, line)
		}
	}
	switch {
	case len(found) == 0:
		return BrokerMarkerAbsent, nil
	case len(found) > 1:
		return "", ErrMCPBrokerMultipleLines
	case found[0] == mcpBrokerPrefix+" "+string(BrokerMarkerProofIncomplete):
		return BrokerMarkerProofIncomplete, nil
	case found[0] == mcpBrokerPrefix+" "+string(BrokerMarkerContained):
		return BrokerMarkerContained, nil
	default:
		return "", ErrMCPBrokerLineUnknown
	}
}

// checkMarker pairs the version with the marker: v5 is exactly the
// contained claim, and v3 and v4 never carry it.
func checkMarker(version CustodyVersion, marker BrokerMarker) error {
	switch {
	case version == CustodyV5 && marker != BrokerMarkerContained:
		return ErrCustodyV5WithoutContained
	case version != CustodyV5 && marker == BrokerMarkerContained:
		return ErrMCPBrokerContainedBelowV5
	default:
		return nil
	}
}

// blobToolLogRoot extracts the single `TOOL_LOG_ROOT:` claim.
//
// Output: (root, true, nil) for one well-formed line; (nil, false, nil)
// when there is no line; or a refusal for a second line, a line of the
// wrong shape, or hex that does not decode (odd length).
func blobToolLogRoot(lines []string) ([]byte, bool, error) {
	var found []string
	for _, line := range lines {
		if strings.HasPrefix(line, toolLogRootPrefix) {
			found = append(found, line)
		}
	}
	switch len(found) {
	case 0:
		return nil, false, nil
	case 1:
	default:
		return nil, false, ErrToolLogRootMultipleLines
	}
	m := toolLogRootLine.FindStringSubmatch(found[0])
	if m == nil {
		return nil, false, ErrToolLogRootMalformed
	}
	root, err := hex.DecodeString(m[1])
	if err != nil {
		return nil, false, ErrToolLogRootUndecodable
	}
	return root, true, nil
}

// CustodyColumns holds the two custody columns that sit outside the chain
// hash: the stored tool-log records and the stored root. A consumer only
// has them when the server hands over the stored record; a bundle does
// not carry them.
//
//   - ToolLogRecords / RecordsPresent: the records end to end. A present
//     but empty value is a genuine empty log. RecordsPresent == false is a
//     NULL column.
//   - ToolLogRoot / RootPresent: the root column. RootPresent == false is
//     a NULL column.
type CustodyColumns struct {
	ToolLogRecords []byte
	RecordsPresent bool
	ToolLogRoot    []byte
	RootPresent    bool
}

// CheckCustodyRecord applies every custody rule, as reef-core's
// `Verifier.check_custody_record/1` does: the blob rules of
// ParseCustodyBlob, then, when the version requires a root (v4, v5):
//
//  6. the records column must not be NULL, it must be a whole number of
//     113-byte records, and the SHA-256 custody root recomputed from the
//     records must equal both the blob's root line and the root column.
//
// A NULL records column is a refusal, never a fallback to v3 behaviour.
//
// Inputs: data, the custody `data` blob; cols, the stored columns.
// Output: the parsed claim, or a *CustodyRuleError.
func CheckCustodyRecord(data string, cols CustodyColumns) (CustodyClaim, error) {
	claim, err := ParseCustodyBlob(data)
	if err != nil {
		return CustodyClaim{}, err
	}
	if claim.ToolLogRoot == nil {
		// Genuine v3 proof: nothing to recompute.
		return claim, nil
	}
	if !cols.RecordsPresent {
		return CustodyClaim{}, ErrToolLogRecordsMissing
	}
	records, err := SplitCustodyToolLogRecords(cols.ToolLogRecords)
	if err != nil {
		return CustodyClaim{}, err
	}
	computed := CustodyToolLogRoot(records)
	if !bytes.Equal(computed[:], claim.ToolLogRoot) {
		return CustodyClaim{}, ErrToolLogRootMismatch
	}
	if !cols.RootPresent || !bytes.Equal(computed[:], cols.ToolLogRoot) {
		return CustodyClaim{}, ErrToolLogRootMismatch
	}
	return claim, nil
}

// custodyRecordSize is the fixed width of one canonical tool-log record
// (the 113-byte digest form; see tlog.RecordBytes).
const custodyRecordSize = 113

// SplitCustodyToolLogRecords splits a stored tool log into its records.
//
// Input: blob, the records end to end.
// Output: the records in stored order, or ErrToolLogRecordsNotMultiple
// when the length is not a whole number of records (a truncated or
// corrupted value, which is reported rather than rounded away).
func SplitCustodyToolLogRecords(blob []byte) ([][]byte, error) {
	if len(blob)%custodyRecordSize != 0 {
		return nil, ErrToolLogRecordsNotMultiple
	}
	out := make([][]byte, 0, len(blob)/custodyRecordSize)
	for i := 0; i < len(blob); i += custodyRecordSize {
		out = append(out, blob[i:i+custodyRecordSize])
	}
	return out, nil
}

// Tags of the SHA-256 custody tree. They are the same tag values that the
// Poseidon t_root uses, but the hash function is different, so the two
// roots of one log are never equal.
const (
	custodyLeafTag       = 0x00
	custodyInternalTag   = 0x01
	custodyLengthBindTag = 0x03
)

// CustodyToolLogRoot computes the server's SHA-256 custody root over
// records that are already encoded and already in call order:
//
//	leaf     = SHA-256(0x00 || record)
//	inner    = SHA-256(0x01 || left || right)
//	Z        = SHA-256(0x00 || 0x00), the right-padding to a power of two
//	top      = Z for no leaves; the leaf itself for one leaf
//	root     = SHA-256(0x03 || ULEB128(len(records)) || top)
//
// This is NOT the Poseidon t_root that the ZK proof binds (package tlog).
//
// Input: records, the 113-byte records in order.
// Output: the 32-byte root.
func CustodyToolLogRoot(records [][]byte) [32]byte {
	leaves := make([][32]byte, len(records))
	for i, rec := range records {
		leaves[i] = sha256.Sum256(append([]byte{custodyLeafTag}, rec...))
	}
	top := custodyTreeTop(leaves)
	pre := append([]byte{custodyLengthBindTag}, custodyULEB128(uint64(len(records)))...)
	pre = append(pre, top[:]...)
	return sha256.Sum256(pre)
}

// custodyTreeTop builds the padded balanced tree over leaves and returns
// its top node.
func custodyTreeTop(leaves [][32]byte) [32]byte {
	z := sha256.Sum256([]byte{custodyLeafTag, 0x00})
	switch len(leaves) {
	case 0:
		return z
	case 1:
		return leaves[0]
	}
	width := 1
	for width < len(leaves) {
		width <<= 1
	}
	level := make([][32]byte, width)
	copy(level, leaves)
	for i := len(leaves); i < width; i++ {
		level[i] = z
	}
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			buf := make([]byte, 0, 65)
			buf = append(buf, custodyInternalTag)
			buf = append(buf, level[2*i][:]...)
			buf = append(buf, level[2*i+1][:]...)
			next[i] = sha256.Sum256(buf)
		}
		level = next
	}
	return level[0]
}

// custodyULEB128 returns the minimal unsigned LEB128 encoding of n.
func custodyULEB128(n uint64) []byte {
	out := []byte{}
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

// BrokerAssurance is how much a custody record proves about MCP brokering.
// Each level has one display label (BrokerAssuranceLabel). A level is
// never raised by what a record leaves out: a missing marker is not
// evidence of anything.
type BrokerAssurance string

// The assurance levels, from least to most.
const (
	// BrokerAssuranceNotVerified: the custody record was not verified
	// (the chain did not verify, the bundle is a sanitized display copy,
	// the record data is not consistent with its link hash, or the
	// claimed root is not 32 bytes). No claim in it is shown.
	BrokerAssuranceNotVerified BrokerAssurance = "not_verified"
	// BrokerAssuranceRefused: the record failed a custody rule.
	BrokerAssuranceRefused BrokerAssurance = "refused"
	// BrokerAssuranceNoMarker: a valid v3 or v4 record with no broker
	// marker. It makes no broker claim.
	BrokerAssuranceNoMarker BrokerAssurance = "no_marker"
	// BrokerAssuranceProofIncomplete: a valid v3 or v4 record with
	// `MCP_BROKER: proof_incomplete`.
	BrokerAssuranceProofIncomplete BrokerAssurance = "proof_incomplete"
	// BrokerAssuranceContainedRootUnchecked: an UNANCHORED v5 claim. The
	// v5 blob passes the blob rules and is consistent with a chain that
	// verified, but a bundle does not anchor that chain and does not carry
	// the tool-log records, so the tool-log root was not recomputed. The
	// full reef-core predicate was not checked.
	BrokerAssuranceContainedRootUnchecked BrokerAssurance = "contained_root_not_recomputed"
	// BrokerAssuranceContained: a v5 record that passes every rule,
	// including the recomputed tool-log root.
	BrokerAssuranceContained BrokerAssurance = "contained"
)

// BrokerAssuranceLabel returns the display text for an assurance level.
// The text states only what the level proves. For v5 it says "server
// custody" and says that it is not a ZK spend guarantee.
//
// Input: a, an assurance level.
// Output: one line of display text.
func BrokerAssuranceLabel(a BrokerAssurance) string {
	switch a {
	case BrokerAssuranceContained:
		return "MCP calls to granted upstream authorities were brokered and recorded, under accepted containment " +
			"(server custody record; not a ZK spend guarantee)"
	case BrokerAssuranceContainedRootUnchecked:
		return "unanchored claim of contained MCP brokering (v5): the bundle does not anchor this record " +
			"and does not carry its tool-log records, so the tool-log root was not recomputed; not verified"
	case BrokerAssuranceProofIncomplete:
		return "MCP broker proof incomplete: this record does not show that MCP calls were contained"
	case BrokerAssuranceNoMarker:
		return "no MCP broker marker: this record makes no broker claim " +
			"(a missing marker does not show that a firewall was installed)"
	case BrokerAssuranceRefused:
		return "custody record refused; no broker assurance"
	default:
		return "custody record not verified; no broker assurance"
	}
}

// CustodyAssessment is the broker assurance of one custody record, for
// display.
//
//   - Assurance: the level.
//   - Claim: the parsed claim; zero unless the rules passed and the
//     record is chain-consistent. Below BrokerAssuranceContained it is an
//     unanchored claim, not a verified fact.
//   - RuleErr: the custody-rule refusal, when Assurance is refused.
type CustodyAssessment struct {
	Assurance BrokerAssurance
	Claim     CustodyClaim
	RuleErr   error
}

// Label returns the display text for the assessment. A refusal names its
// rule code.
func (a CustodyAssessment) Label() string {
	if a.Assurance == BrokerAssuranceRefused && a.RuleErr != nil {
		return fmt.Sprintf("custody record refused (%s); no broker assurance", CustodyRuleCode(a.RuleErr))
	}
	return BrokerAssuranceLabel(a.Assurance)
}

// AssessCustodyBlob classifies a custody blob when the stored tool-log
// records are NOT available (the bundle case). A v5 blob can reach at
// most BrokerAssuranceContainedRootUnchecked this way.
//
// Inputs:
//   - data: the custody `data` blob.
//   - chainConsistent: true only when the caller has checked that data
//     is the preimage of a link in a chain that verified. This is chain
//     consistency, not an anchor. When false, the result is not_verified
//     (or refused, if a rule fails) and no claim is kept.
//
// Output: the assessment.
func AssessCustodyBlob(data string, chainConsistent bool) CustodyAssessment {
	claim, err := ParseCustodyBlob(data)
	if err != nil {
		return CustodyAssessment{Assurance: BrokerAssuranceRefused, RuleErr: err}
	}
	// A root that is not 32 bytes passes the blob rules (reef-core refuses
	// it only when it recomputes the root), but it can never match. Show
	// no claim for it.
	if !chainConsistent || (claim.ToolLogRoot != nil && len(claim.ToolLogRoot) != sha256.Size) {
		return CustodyAssessment{Assurance: BrokerAssuranceNotVerified}
	}
	a := CustodyAssessment{Claim: claim, Assurance: assuranceForClaim(claim)}
	if a.Assurance == BrokerAssuranceContained {
		a.Assurance = BrokerAssuranceContainedRootUnchecked
	}
	return a
}

// AssessCustodyRecord classifies a custody record when the stored columns
// ARE available. Only this path can return BrokerAssuranceContained, and
// only when every rule of CheckCustodyRecord passes.
//
// Inputs: data and cols as for CheckCustodyRecord; chainConsistent as
// for AssessCustodyBlob.
// Output: the assessment.
func AssessCustodyRecord(data string, cols CustodyColumns, chainConsistent bool) CustodyAssessment {
	claim, err := CheckCustodyRecord(data, cols)
	if err != nil {
		return CustodyAssessment{Assurance: BrokerAssuranceRefused, RuleErr: err}
	}
	if !chainConsistent {
		return CustodyAssessment{Assurance: BrokerAssuranceNotVerified}
	}
	return CustodyAssessment{Claim: claim, Assurance: assuranceForClaim(claim)}
}

// assuranceForClaim maps a claim that passed the rules to its level.
func assuranceForClaim(c CustodyClaim) BrokerAssurance {
	switch c.Marker {
	case BrokerMarkerContained:
		return BrokerAssuranceContained
	case BrokerMarkerProofIncomplete:
		return BrokerAssuranceProofIncomplete
	default:
		return BrokerAssuranceNoMarker
	}
}
