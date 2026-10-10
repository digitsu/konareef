// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants.go — the sealed closed-pod grants carrier (MCP-C00, v1).
//
// A closed pod keeps its brokered MCP grants out of the public head. The
// grants live in the reserved body file sealed/grants.toml, which the
// closed-pod body encryption already protects and which [_files] binds to
// the signed head. The head carries one content-free marker:
//
//	[network]
//	sealed_grants = "konareef-sealed-grants/v1"
//
// The file format is:
//
//	format = "konareef-sealed-grants/v1"
//	salt   = "<64 lowercase hex characters>"
//	[[grant]]            # zero or more; each is a network_gateway entry
//	protocol = "mcp"     # required, and must be "mcp"
//	...
//
// This file implements the shared rules G1–G16 of the sealed closed-pod
// grants design (MCP-C00, reef-core#42, section 5), and G17 (a closed head
// must not reference sealed/grants.toml, reef-core#63), with the same
// codes reef-core returns. The shared fixtures in
// testdata/sealed_grants/v1 (vendored byte for byte from reef-core) pin the
// verdicts.
//
// Privacy rule for this file: an Issue about the sealed file never quotes a
// sealed value. Messages name the rule and the field path only. No host,
// tool, namespace, secret name or salt from sealed/grants.toml appears in a
// message, because CLI output ends up in terminals, CI logs and bug
// reports. The rules reused from gateway.go and mcp_broker.go quote
// values, so their messages are replaced for every issue that involves a
// sealed entry.
//
// Contents:
//   - the carrier constants and the SEALED_GRANTS_* codes;
//   - SealedGrantsInput and ValidateSealedGrants: the G1–G17 check;
//   - ParseSealedGrantsFile: decode a file that passed validation;
//   - NewSealedGrantsFile and RotateSealedGrantsSalt: salt handling (D4, D14);
//   - AddSealedGrantsMarker: add the head marker to pod.toml text (D3).
package pod

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/secret"
)

// Carrier constants. They are part of the shared contract with reef-core;
// cases.json in the fixtures carries the same values.
const (
	// SealedGrantsFormatV1 is both the head marker value and the file's
	// `format` value for carrier version 1.
	SealedGrantsFormatV1 = "konareef-sealed-grants/v1"
	// SealedGrantsBodyPath is the reserved body path of the grants file,
	// relative to the pod root, with forward slashes (the [_files] form).
	SealedGrantsBodyPath = "sealed/grants.toml"
	// SealedGrantsMaxGrants is the grant cap (owner decision D6 = a).
	SealedGrantsMaxGrants = 16
	// SealedGrantsMaxTools is the cap on mcp_tools entries summed over
	// every sealed grant (owner decision D6 = a).
	SealedGrantsMaxTools = 128
)

// Stable codes for the sealed-grants rules. reef-core returns the same
// bytes from its publish gate. The reused gateway codes (G9, G10, G12,
// G13, G14) are the constants in gateway.go and mcp_broker.go.
const (
	CodeSealedGrantsFileMissing        = "SEALED_GRANTS_FILE_MISSING"
	CodeSealedGrantsFileReferenced     = "SEALED_GRANTS_FILE_REFERENCED"
	CodeSealedGrantsRequiresClosed     = "SEALED_GRANTS_REQUIRES_CLOSED"
	CodeSealedGrantsPublicMCPMixed     = "SEALED_GRANTS_PUBLIC_MCP_MIXED"
	CodeSealedGrantsMarkerMissing      = "SEALED_GRANTS_MARKER_MISSING"
	CodeSealedGrantsVersionUnsupported = "SEALED_GRANTS_VERSION_UNSUPPORTED"
	CodeSealedGrantsTOML               = "SEALED_GRANTS_TOML"
	CodeSealedGrantsSchema             = "SEALED_GRANTS_SCHEMA"
	CodeSealedGrantsSaltInvalid        = "SEALED_GRANTS_SALT_INVALID"
	CodeSealedGrantSecretPublic        = "SEALED_GRANT_SECRET_PUBLIC"
	CodeSealedGrantsZKUnsupported      = "SEALED_GRANTS_ZK_UNSUPPORTED"
	CodeSealedGrantsOverCap            = "SEALED_GRANTS_OVER_CAP"
)

// sealedPathPrefix starts the Path of every Issue inside the grants file,
// so an author can tell a sealed issue from a pod.toml issue at a glance.
const sealedPathPrefix = SealedGrantsBodyPath + ":"

// Strict re-checks of the network_gateway string patterns, anchored with
// \A...\z so a trailing newline can never pass (the PCRE `$` vs RE2 parity
// trap, fixture R20). Go's `$` is already end-of-text without the m flag;
// these exist so the guarantee does not rest on that detail of the schema
// engine.
var (
	sealedSaltPattern    = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
	sealedMCPNamePattern = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,31}\z`)
	sealedMCPToolPattern = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,128}\z`)
	sealedMCPPathPattern = regexp.MustCompile(`\A/[^\s?#]*\z`)
	sealedSecretPattern  = regexp.MustCompile(`\A[A-Z][A-Z0-9_]*\z`)
	sealedAuthPattern    = regexp.MustCompile(`\A(bearer|header:[A-Za-z0-9-]+|query:[A-Za-z0-9_.-]+)\z`)
	sealedHostPattern    = regexp.MustCompile(`\A(?:(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*\])(:[0-9]{1,5})?\z`)
)

// gatewayIndexPath matches a path the gateway rules emit, such as
// "network.gateway[3].mcp_tools[1]", so a merged-list index can be mapped
// back to a sealed grant.
var gatewayIndexPath = regexp.MustCompile(`\Anetwork\.gateway\[(\d+)\](.*)\z`)

// SealedGrantsInput is what ValidateSealedGrants reads.
type SealedGrantsInput struct {
	// Head is the author-tree pod.toml (not the canonical bytes).
	Head []byte
	// Grants is the content of sealed/grants.toml. It is read only when
	// GrantsPresent is true.
	Grants []byte
	// GrantsPresent reports whether sealed/grants.toml is in the body
	// file set (the [_files] paths).
	GrantsPresent bool
	// ZK reports whether the publish asks for zk_enabled (G15).
	ZK bool
}

// sealedGrantsDoc is the typed form of a grants file that passed the
// schema checks.
type sealedGrantsDoc struct {
	Format string    `toml:"format"`
	Salt   string    `toml:"salt"`
	Grant  []Gateway `toml:"grant"`
}

// SealedGrantsFile is a decoded, validated sealed/grants.toml.
//
// It holds sealed values. Never print it, log it or put it in an error.
type SealedGrantsFile struct {
	// Format is the carrier version, SealedGrantsFormatV1.
	Format string
	// Salt is the 64-hex-character salt.
	Salt string
	// Grants are the brokered MCP grants, in file order.
	Grants []Gateway
}

// HasSealedGrantsMarker reports whether spec carries the head marker,
// whatever its value.
//
// Input: a parsed spec. Output: true when [network].sealed_grants is set.
func HasSealedGrantsMarker(spec Spec) bool {
	return spec.Network != nil && spec.Network.SealedGrants != ""
}

// ValidateSealedGrants runs the shared rules G1–G17 over a head and its
// optional grants file.
//
// Input: see SealedGrantsInput. The head should already pass
// ValidateWithWarnings; this function reports only the sealed-grants
// rules, so a caller wanting every issue concatenates both.
//
// Output: every violation found (not only the first), each with a code
// from the shared list, or nil. The error is non-nil only when the head
// is not TOML or the embedded schema does not compile. A problem in the
// grants file is an Issue, never an error, and no Issue quotes a sealed
// value.
func ValidateSealedGrants(input SealedGrantsInput) ([]Issue, error) {
	spec, _, err := ParseWithMeta(input.Head)
	if err != nil {
		return nil, err
	}
	marker := HasSealedGrantsMarker(*spec)
	closed := spec.Pod.Visibility == "closed"

	var issues []Issue
	if marker && !closed {
		issues = append(issues, Issue{
			Path: "network.sealed_grants", Code: CodeSealedGrantsRequiresClosed,
			Message: "the sealed-grants marker is valid only on a closed pod (pod.visibility = \"closed\"); on an open pod, " + SealedGrantsBodyPath + " would be published in the clear",
		})
	}
	if marker && spec.Network != nil {
		for index, entry := range spec.Network.Gateway {
			if entry.Protocol == "mcp" {
				issues = append(issues, Issue{
					Path: fmt.Sprintf("network.gateway[%d].protocol", index), Code: CodeSealedGrantsPublicMCPMixed,
					Message: "a head with the sealed-grants marker must not carry a public protocol = \"mcp\" gateway entry; move it into " + SealedGrantsBodyPath,
				})
			}
		}
	}
	if marker && closed && !input.GrantsPresent {
		issues = append(issues, Issue{
			Path: "network.sealed_grants", Code: CodeSealedGrantsFileMissing,
			Message: "the head carries the sealed-grants marker but the pod has no " + SealedGrantsBodyPath + "; run `konareef pod grants init <pod-dir>`",
		})
	}
	if !marker && closed && input.GrantsPresent {
		issues = append(issues, Issue{
			Path: "network.sealed_grants", Code: CodeSealedGrantsMarkerMissing,
			Message: "the closed pod has " + SealedGrantsBodyPath + " but its head has no [network].sealed_grants marker",
		})
	}
	if closed {
		issues = append(issues, sealedGrantsFileReferences(*spec)...)
	}
	if !marker || !input.GrantsPresent {
		return issues, nil
	}

	fileIssues, err := validateSealedGrantsFile(*spec, input.Grants, input.ZK)
	if err != nil {
		return nil, err
	}
	return append(issues, fileIssues...), nil
}

// sealedGrantsFileReferences is rule G17 (reef-core#63, the MCP-C02 review
// finding L3). reef-core never writes sealed/grants.toml into a closed
// pod's body directory, and its egress review skips the file, so a closed
// head that names the file as a context source or the directive template
// publishes but can never spawn. A directory reference such as ./sealed is
// not refused: reef-core drops only the grants file, so other files under
// sealed/ still resolve.
//
// Input: the parsed closed head. Output: one SEALED_GRANTS_FILE_REFERENCED
// issue per referencing field, in the order memory, skills, tools,
// prompts, directive template. The message names the field only; the
// referenced path is the public reserved path, not a sealed value.
func sealedGrantsFileReferences(spec Spec) []Issue {
	var refs []string
	if spec.Context != nil {
		for index, entry := range spec.Context.Memory {
			if reachesSealedGrantsFile(entry.Path) {
				refs = append(refs, fmt.Sprintf("context.memory[%d].path", index))
			}
		}
		for index, entry := range spec.Context.Skills {
			if reachesSealedGrantsFile(entry.Source) {
				refs = append(refs, fmt.Sprintf("context.skills[%d].source", index))
			}
		}
		for index, entry := range spec.Context.Tools {
			if reachesSealedGrantsFile(entry.Source) {
				refs = append(refs, fmt.Sprintf("context.tools[%d].source", index))
			}
		}
		for index, entry := range spec.Context.Prompts {
			if reachesSealedGrantsFile(entry.Path) {
				refs = append(refs, fmt.Sprintf("context.prompts[%d].path", index))
			}
		}
	}
	if spec.Directive != nil && reachesSealedGrantsFile(spec.Directive.Template) {
		refs = append(refs, "directive.template")
	}

	issues := make([]Issue, 0, len(refs))
	for _, path := range refs {
		issues = append(issues, Issue{
			Path: path, Code: CodeSealedGrantsFileReferenced,
			Message: "a closed pod must not reference " + SealedGrantsBodyPath + "; reef-core never writes that file into the pod's working directory, so the pod could never start",
		})
	}
	return issues
}

// reachesSealedGrantsFile reports whether a pod-relative reference names
// sealed/grants.toml. It normalizes the way
// reef-core Pod.Spec.SafeRelativePath.normalize/1 does: one leading "./"
// is removed and the rest must pass canon.SafeRelativePath. It then folds
// ASCII letters to lower case, because authors work on case-insensitive
// filesystems where ./Sealed/Grants.toml opens the grants file. Only ASCII
// is folded (reef-core String.downcase(rel, :ascii)); strings.EqualFold
// would also fold letters such as U+017F and break verdict parity. A
// reference that does not normalize is left to the other checks.
//
// Input: the reference as written in pod.toml. Output: true or false.
func reachesSealedGrantsFile(ref string) bool {
	rel := strings.TrimPrefix(ref, "./")
	if ref == "" || canon.SafeRelativePath(rel) != nil {
		return false
	}
	return asciiLower(rel) == SealedGrantsBodyPath
}

// asciiLower folds the ASCII letters A–Z in s to a–z and leaves every
// other byte, including all non-ASCII UTF-8, unchanged.
//
// Input: any string. Output: the folded string.
func asciiLower(s string) string {
	folded := []byte(s)
	for index, char := range folded {
		if char >= 'A' && char <= 'Z' {
			folded[index] = char + ('a' - 'A')
		}
	}
	return string(folded)
}

// validateSealedGrantsFile runs G5–G16 over the grants file against the
// parsed head.
//
// Inputs: the head spec, the file bytes, and the publish's ZK choice.
// Output: the issues, or an error when the embedded schema fails to
// compile.
func validateSealedGrantsFile(spec Spec, grantsBytes []byte, zk bool) ([]Issue, error) {
	var raw map[string]interface{}
	if _, err := toml.Decode(string(grantsBytes), &raw); err != nil {
		// The TOML error text can quote the offending line, which may
		// hold a sealed value. Report the line number only.
		message := SealedGrantsBodyPath + " is not valid TOML"
		var parseErr toml.ParseError
		if errors.As(err, &parseErr) {
			message += fmt.Sprintf(" (line %d)", parseErr.Position.Line)
		}
		return []Issue{{Path: SealedGrantsBodyPath, Code: CodeSealedGrantsTOML, Message: message}}, nil
	}
	document, err := jsonNormalize(raw)
	if err != nil {
		return []Issue{{Path: SealedGrantsBodyPath, Code: CodeSealedGrantsTOML, Message: SealedGrantsBodyPath + " cannot be read as a table"}}, nil
	}
	top, _ := document.(map[string]interface{})

	var issues []Issue
	for key := range top {
		if key != "format" && key != "salt" && key != "grant" {
			issues = append(issues, Issue{
				Path: SealedGrantsBodyPath, Code: CodeSealedGrantsSchema,
				Message: "the top level must hold only format, salt and grant; an unknown key is present",
			})
			break
		}
	}

	// G5: an unknown carrier version has unknown rules, so nothing else
	// in the file is judged.
	if format, ok := top["format"].(string); !ok || format != SealedGrantsFormatV1 {
		issues = append(issues, Issue{
			Path: sealedPathPrefix + "format", Code: CodeSealedGrantsVersionUnsupported,
			Message: fmt.Sprintf("format must be %q", SealedGrantsFormatV1),
		})
		return issues, nil
	}

	// G7.
	if salt, ok := top["salt"].(string); !ok || !sealedSaltPattern.MatchString(salt) {
		issues = append(issues, Issue{
			Path: sealedPathPrefix + "salt", Code: CodeSealedGrantsSaltInvalid,
			Message: "salt must be 64 lowercase hex characters (32 random bytes)",
		})
	}

	// G6/G8: shape of each grant.
	var grantItems []interface{}
	if value, present := top["grant"]; present {
		list, ok := value.([]interface{})
		if !ok {
			issues = append(issues, Issue{
				Path: sealedPathPrefix + "grant", Code: CodeSealedGrantsSchema,
				Message: "grant must be an array of tables ([[grant]])",
			})
		}
		grantItems = list
	}
	schemaIssues, err := sealedGrantSchemaIssues(grantItems)
	if err != nil {
		return nil, err
	}
	issues = append(issues, schemaIssues...)

	// G16: counted on the raw items, so an over-cap file is reported even
	// when an entry is also malformed.
	toolCount := 0
	for _, item := range grantItems {
		if grant, ok := item.(map[string]interface{}); ok {
			if tools, ok := grant["mcp_tools"].([]interface{}); ok {
				toolCount += len(tools)
			}
		}
	}
	if len(grantItems) > SealedGrantsMaxGrants || toolCount > SealedGrantsMaxTools {
		issues = append(issues, Issue{
			Path: sealedPathPrefix + "grant", Code: CodeSealedGrantsOverCap,
			Message: fmt.Sprintf("at most %d sealed grants and %d mcp_tools entries in total are allowed", SealedGrantsMaxGrants, SealedGrantsMaxTools),
		})
	}

	// G15.
	if zk && len(grantItems) > 0 {
		issues = append(issues, Issue{
			Path: SealedGrantsBodyPath, Code: CodeSealedGrantsZKUnsupported,
			Message: "a pod with sealed grants cannot be published with --zk",
		})
	}

	// G11: read from the raw items so it runs even when another field of
	// the entry is malformed.
	declared := map[string]bool{}
	if spec.Dependencies != nil {
		for _, name := range spec.Dependencies.Secrets {
			declared[name] = true
		}
	}
	for index, item := range grantItems {
		grant, _ := item.(map[string]interface{})
		if secret, ok := grant["secret"].(string); ok && declared[secret] {
			issues = append(issues, Issue{
				Path: fmt.Sprintf("%sgrant[%d].secret", sealedPathPrefix, index), Code: CodeSealedGrantSecretPublic,
				Message: "a sealed grant's secret must not be listed in the public [dependencies].secrets, which would publish its name; reef-core resolves it from the author's pod secrets",
			})
		}
	}

	// The cross-field rules decode the grants into typed entries. That
	// is safe only when every grant passed the schema, so a malformed
	// file stops here, as ValidateWithWarnings does for a head.
	if len(schemaIssues) > 0 || len(grantItems) == 0 {
		return dedupeIssues(issues), nil
	}
	var typed sealedGrantsDoc
	if _, err := toml.Decode(string(grantsBytes), &typed); err != nil {
		issues = append(issues, Issue{Path: SealedGrantsBodyPath, Code: CodeSealedGrantsSchema, Message: "a grant field has the wrong type"})
		return dedupeIssues(issues), nil
	}
	issues = append(issues, sealedCrossFieldIssues(spec, typed.Grant)...)
	return dedupeIssues(issues), nil
}

// sealedGrantSchemaIssues checks each grant against the network_gateway
// schema definition, then requires protocol = "mcp" and re-checks every
// string pattern with \A...\z anchors (G6, G8).
//
// Input: the JSON-normalized grant items. Output: one SEALED_GRANTS_SCHEMA
// issue per failing field, or an error when the schema fails to compile.
func sealedGrantSchemaIssues(items []interface{}) ([]Issue, error) {
	if len(items) == 0 {
		return nil, nil
	}
	gatewaySchema, err := compileGatewaySchema()
	if err != nil {
		return nil, err
	}
	var issues []Issue
	for index, item := range items {
		prefix := fmt.Sprintf("%sgrant[%d]", sealedPathPrefix, index)
		grant, ok := item.(map[string]interface{})
		if !ok {
			issues = append(issues, Issue{Path: prefix, Code: CodeSealedGrantsSchema, Message: "a grant must be a table"})
			continue
		}
		if err := gatewaySchema.Validate(grant); err != nil {
			var validationErr *jsonschema.ValidationError
			if !errors.As(err, &validationErr) {
				return nil, fmt.Errorf("sealed grant schema validation: %w", err)
			}
			for _, leaf := range flattenIssuesValueFree(validationErr) {
				path := prefix
				if leaf.location != "" {
					path += "." + leaf.location
				}
				issues = append(issues, Issue{
					Path: path, Code: CodeSealedGrantsSchema,
					Message: "the grant does not fit the network_gateway schema (" + leaf.keyword + ")",
				})
			}
		}
		protocol, present := grant["protocol"]
		if !present {
			issues = append(issues, Issue{Path: prefix + ".protocol", Code: CodeSealedGrantsSchema, Message: "protocol is required in a sealed grant and must be \"mcp\""})
		} else if protocol != "mcp" {
			issues = append(issues, Issue{Path: prefix + ".protocol", Code: CodeSealedGrantsSchema, Message: "a sealed grant must have protocol = \"mcp\"; plain HTTP gateway entries stay in pod.toml"})
		}
		strictChecks := []struct {
			field   string
			pattern *regexp.Regexp
		}{
			{"host", sealedHostPattern},
			{"secret", sealedSecretPattern},
			{"auth", sealedAuthPattern},
			{"mcp_name", sealedMCPNamePattern},
			{"mcp_path", sealedMCPPathPattern},
		}
		for _, check := range strictChecks {
			if value, ok := grant[check.field].(string); ok && !check.pattern.MatchString(value) {
				issues = append(issues, Issue{Path: prefix + "." + check.field, Code: CodeSealedGrantsSchema, Message: "the value does not match the required pattern"})
			}
		}
		// A reserved harness name (secret_reserved). reef-core resolves a
		// sealed grant's secret through SecretsVault.check_name, which
		// refuses a reserved name in every mode, self-host included, so the
		// pod could never spawn. This rule is konareef's only: reef-core's
		// publish-time G rules do not check it. The message does not quote
		// the name.
		if name, ok := grant["secret"].(string); ok && secret.IsReserved(name) {
			issues = append(issues, Issue{Path: prefix + ".secret", Code: CodeSecretReserved, Message: "a sealed grant's secret must not be a name reserved for the runtime harness; reef-core refuses it at every spawn"})
		}
		if tools, ok := grant["mcp_tools"].([]interface{}); ok {
			for toolIndex, tool := range tools {
				if name, ok := tool.(string); ok && !sealedMCPToolPattern.MatchString(name) {
					issues = append(issues, Issue{Path: fmt.Sprintf("%s.mcp_tools[%d]", prefix, toolIndex), Code: CodeSealedGrantsSchema, Message: "the value does not match the required pattern"})
				}
			}
		}
	}
	return dedupeIssues(issues), nil
}

// sealedCrossFieldIssues runs the gateway and brokered-MCP rules over the
// merged list (public gateway entries, then the sealed grants), which
// covers G9, G10, G12, G13 and G14 with the codes those rules already
// emit.
//
// It keeps only the issues the sealed grants cause: an issue at a sealed
// index, or a public-path issue the head alone does not produce. It drops
// GATEWAY_SECRET_UNDECLARED for sealed entries (G11 requires the opposite)
// and replaces every kept message with a value-free one.
//
// Inputs: the head spec and the typed sealed grants. Output: the issues.
func sealedCrossFieldIssues(spec Spec, grants []Gateway) []Issue {
	var public []Gateway
	if spec.Network != nil {
		public = spec.Network.Gateway
	}
	headIssues, _ := gatewayRules(spec)
	headIssues = append(headIssues, mcpBrokerRules(spec)...)
	inHead := map[string]bool{}
	for _, issue := range headIssues {
		inHead[issue.Path+"\x00"+issue.Code] = true
	}

	merged := spec
	mergedNetwork := Network{}
	if spec.Network != nil {
		mergedNetwork = *spec.Network
	}
	mergedNetwork.Gateway = append(append([]Gateway(nil), public...), grants...)
	merged.Network = &mergedNetwork
	mergedIssues, _ := gatewayRules(merged)
	mergedIssues = append(mergedIssues, mcpBrokerRules(merged)...)

	var issues []Issue
	for _, issue := range mergedIssues {
		if match := gatewayIndexPath.FindStringSubmatch(issue.Path); match != nil {
			index, _ := strconv.Atoi(match[1])
			if index >= len(public) {
				if issue.Code == CodeGatewaySecretUndeclared {
					continue
				}
				issues = append(issues, Issue{
					Path:    fmt.Sprintf("%sgrant[%d]%s", sealedPathPrefix, index-len(public), match[2]),
					Code:    issue.Code,
					Message: sealedRuleMessage(issue.Code),
				})
				continue
			}
		}
		if inHead[issue.Path+"\x00"+issue.Code] {
			continue
		}
		issues = append(issues, Issue{Path: issue.Path, Code: issue.Code, Message: sealedRuleMessage(issue.Code)})
	}
	return issues
}

// sealedRuleMessage returns the value-free message for a reused gateway
// rule that a sealed grant triggered.
//
// Input: the rule code. Output: a message that names no sealed value.
func sealedRuleMessage(code string) string {
	switch code {
	case CodeGatewayHostWildcard:
		return "a sealed grant host must be exact, not a wildcard"
	case CodeGatewayHostDuplicate:
		return "this host:port authority is already used by another gateway entry or sealed grant"
	case CodeGatewayNoAdapter:
		return "provider-unit caps need a platform adapter, and none exists for this host; use max_calls"
	case CodeGatewayMCPNameReserved:
		return "mcp_name is a built-in reef-core tool namespace"
	case CodeGatewayMCPNameDuplicate:
		return "mcp_name is used by an earlier grant"
	case CodeGatewayMCPHostAlsoEgress:
		return "this sealed grant's authority is also reachable through [network].egress; a brokered host is reached only through the broker, so remove or narrow that egress entry"
	case CodeGatewayMCPToolNameCollision:
		return "a granted tool reaches the runtime under the same name as another granted or built-in tool; rename or drop one of them"
	case CodeGatewayMCPRuntimeUnsupported:
		return "this runtime does not support brokered MCP grants; reef-core serves them only to the orca and lobster runtimes"
	}
	return "a sealed grant breaks rule " + code
}

// valueFreeLeaf is one schema failure, reduced to its instance location
// and the failing keyword. The validator's own message is dropped because
// it quotes the offending value.
type valueFreeLeaf struct {
	location string
	keyword  string
}

// flattenIssuesValueFree walks a validation error tree like
// flattenIssues, but keeps only the location and the keyword of each leaf.
//
// Input: the root validation error. Output: the leaves, in tree order.
func flattenIssuesValueFree(node *jsonschema.ValidationError) []valueFreeLeaf {
	if len(node.Causes) == 0 {
		keyword := "schema"
		if node.ErrorKind != nil {
			if path := node.ErrorKind.KeywordPath(); len(path) > 0 {
				keyword = path[len(path)-1]
			}
		}
		return []valueFreeLeaf{{location: formatInstancePath(node.InstanceLocation), keyword: keyword}}
	}
	var leaves []valueFreeLeaf
	for _, cause := range node.Causes {
		leaves = append(leaves, flattenIssuesValueFree(cause)...)
	}
	return leaves
}

// compileGatewaySchema compiles the network_gateway definition of the
// embedded pod schema, so a sealed grant is checked by the one definition
// a public entry is checked by.
//
// Output: the compiled sub-schema, or an error when the embedded schema
// does not compile (a build bug).
func compileGatewaySchema() (*jsonschema.Schema, error) {
	var schemaDocument interface{}
	if err := json.Unmarshal(schemaJSON, &schemaDocument); err != nil {
		return nil, fmt.Errorf("embedded schema unmarshal: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaID, schemaDocument); err != nil {
		return nil, fmt.Errorf("embedded schema add: %w", err)
	}
	schema, err := compiler.Compile(schemaID + "#/definitions/network_gateway")
	if err != nil {
		return nil, fmt.Errorf("embedded schema compile: %w", err)
	}
	return schema, nil
}

// jsonNormalize turns a TOML-decoded value into the plain JSON value
// types the schema validator expects ([]interface{} for arrays of
// tables, float64 for numbers).
//
// Input: the decoded value. Output: the normalized value, or an error.
func jsonNormalize(value interface{}) (interface{}, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var document interface{}
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, err
	}
	return document, nil
}

// dedupeIssues drops repeated (path, code) pairs, keeping the first
// message, so one field is not reported twice by the schema and by the
// strict pattern re-check.
//
// Input: the issues in report order. Output: the issues without repeats.
func dedupeIssues(issues []Issue) []Issue {
	seen := map[string]bool{}
	var out []Issue
	for _, issue := range issues {
		key := issue.Path + "\x00" + issue.Code
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, issue)
	}
	return out
}

// ParseSealedGrantsFile decodes a grants file that passed
// ValidateSealedGrants.
//
// Input: the file bytes. Output: the decoded file, or an error that names
// no sealed value.
func ParseSealedGrantsFile(grantsBytes []byte) (*SealedGrantsFile, error) {
	var typed sealedGrantsDoc
	if _, err := toml.Decode(string(grantsBytes), &typed); err != nil {
		return nil, errors.New(SealedGrantsBodyPath + " is not a valid sealed grants file")
	}
	return &SealedGrantsFile{Format: typed.Format, Salt: typed.Salt, Grants: typed.Grant}, nil
}

// newSealedSalt returns 32 bytes from the system CSPRNG as 64 lowercase
// hex characters.
//
// Output: the salt, or the error from crypto/rand.
func newSealedSalt() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate sealed-grants salt: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// NewSealedGrantsFile returns the content of an empty grants file with a
// fresh salt: the file `konareef pod grants init` writes and the file the
// always-emit publish (D3 = a) adds.
//
// Output: the file bytes, or an error when the CSPRNG fails.
func NewSealedGrantsFile() ([]byte, error) {
	salt, err := newSealedSalt()
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`# Sealed brokered MCP grants for this closed pod (konareef-sealed-grants/v1).
# This file is encrypted with the pod body and never published in the clear.
# Add one [[grant]] table per brokered MCP server, for example:
#
# [[grant]]
# host      = "mcp.example.com"
# secret    = "EXAMPLE_TOKEN"   # a secret NAME; upload the value with konareef pod secret
# auth      = "bearer"
# max_calls = 50
# protocol  = "mcp"
# mcp_path  = "/mcp"
# mcp_name  = "example"
# mcp_tools = ["search"]
#
# Do not list a sealed grant's secret in [dependencies].secrets.
# konareef pod publish replaces the salt on every publish.
format = %q
salt = %q
`, SealedGrantsFormatV1, salt)), nil
}

// grantTableHeaderPattern matches the first [[grant]] header that is not
// inside a comment.
var grantTableHeaderPattern = regexp.MustCompile(`(?m)^[ \t]*\[\[grant\]\]`)

// saltLinePattern matches the one top-level salt line RotateSealedGrantsSalt
// may rewrite.
var saltLinePattern = regexp.MustCompile(`(?m)^salt[ \t]*=[ \t]*"[0-9a-f]{64}"[ \t]*$`)

// RotateSealedGrantsSalt replaces the salt of a valid grants file with a
// fresh one (owner decision D14 = a) and changes no other byte.
//
// The salt exists only to make the public [_files] hash of the file
// unguessable; a new salt per publish also stops two versions, or two
// pods that copy the file, from sharing one public hash.
//
// Input: the file bytes, which must hold exactly one line of the form
// `salt = "<64 hex>"` before the first [[grant]] table. Output: the new
// bytes, or an error when the line is not found exactly once or the
// CSPRNG fails. The error names no sealed value.
func RotateSealedGrantsSalt(grantsBytes []byte) ([]byte, error) {
	header := grantsBytes
	if cut := grantTableHeaderPattern.FindIndex(grantsBytes); cut != nil {
		header = grantsBytes[:cut[0]]
	}
	locations := saltLinePattern.FindAllIndex(grantsBytes, -1)
	if len(locations) != 1 || locations[0][1] > len(header) {
		return nil, errors.New("cannot rotate the salt: " + SealedGrantsBodyPath + ` must hold exactly one top-level line salt = "<64 lowercase hex>"`)
	}
	salt, err := newSealedSalt()
	if err != nil {
		return nil, err
	}
	start, end := locations[0][0], locations[0][1]
	var out bytes.Buffer
	out.Write(grantsBytes[:start])
	fmt.Fprintf(&out, "salt = %q", salt)
	out.Write(grantsBytes[end:])
	return out.Bytes(), nil
}

// networkHeaderPattern matches a `[network]` table header line.
var networkHeaderPattern = regexp.MustCompile(`(?m)^[ \t]*\[network\][ \t]*(#.*)?$`)

// AddSealedGrantsMarker returns pod.toml text with the v1 marker added to
// the [network] table, creating the table when it is absent.
//
// The edit is textual, so the author's comments and layout survive. It is
// then verified: the result must parse, carry the marker, and decode to
// the same spec as the input in every other field. When that check fails
// (for example, a [network] table written in dotted-key form), the
// function returns an error and the author adds the line by hand.
//
// Input: the pod.toml bytes, without a marker. Output: the new bytes, or
// an error.
func AddSealedGrantsMarker(podTOML []byte) ([]byte, error) {
	before, err := Parse(podTOML)
	if err != nil {
		return nil, err
	}
	if HasSealedGrantsMarker(before) {
		return nil, errors.New("pod.toml already carries [network].sealed_grants")
	}
	markerLine := fmt.Sprintf("sealed_grants = %q\n", SealedGrantsFormatV1)
	var edited []byte
	headers := networkHeaderPattern.FindAllIndex(podTOML, -1)
	switch len(headers) {
	case 0:
		edited = append([]byte(nil), podTOML...)
		if len(edited) > 0 && edited[len(edited)-1] != '\n' {
			edited = append(edited, '\n')
		}
		edited = append(edited, []byte("\n[network]\n"+markerLine)...)
	case 1:
		// Insert on the line after the header. A header on the last line
		// with no newline gets one first.
		lineEnd := headers[0][1]
		insert := markerLine
		if lineEnd < len(podTOML) && podTOML[lineEnd] == '\n' {
			lineEnd++
		} else {
			insert = "\n" + markerLine
		}
		edited = append(append(append([]byte(nil), podTOML[:lineEnd]...), insert...), podTOML[lineEnd:]...)
	default:
		return nil, errors.New("pod.toml has more than one [network] header")
	}
	after, err := Parse(edited)
	if err != nil || !HasSealedGrantsMarker(after) || after.Network.SealedGrants != SealedGrantsFormatV1 {
		return nil, fmt.Errorf("could not add the marker automatically; add %q under [network] by hand", strings.TrimSpace(markerLine))
	}
	after.Network.SealedGrants = ""
	if before.Network == nil && after.Network != nil && len(after.Network.Egress) == 0 && len(after.Network.Gateway) == 0 {
		after.Network = nil
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if !bytes.Equal(beforeJSON, afterJSON) {
		return nil, fmt.Errorf("could not add the marker automatically; add %q under [network] by hand", strings.TrimSpace(markerLine))
	}
	return edited, nil
}

// SortedIssueCodes returns the distinct codes of issues, sorted. The
// fixture tests and the CLI's summary line use it.
//
// Input: issues. Output: the sorted distinct non-empty codes.
func SortedIssueCodes(issues []Issue) []string {
	seen := map[string]bool{}
	var codes []string
	for _, issue := range issues {
		if issue.Code != "" && !seen[issue.Code] {
			seen[issue.Code] = true
			codes = append(codes, issue.Code)
		}
	}
	sort.Strings(codes)
	return codes
}
