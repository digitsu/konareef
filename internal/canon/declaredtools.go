// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// declaredtools.go — the declared_tools list that a canonical manifest
// commits into fields_root, per konareef-toml version.
//
// konareef-toml/v2 commits only the [[context.tools]].source names.
// konareef-toml/v3 (docs/reference/konareef-toml-v3-spec.md; paygate-zk
// MCP-Z00 §10.2, decision D3 option A) also commits the id of every tool a
// brokered MCP grant ([[network.gateway]] with protocol = "mcp") allows:
//
//	declared_tools = sort_bytes( context_tools_sources
//	                             ∪ { g.mcp_name + "." + t | g ∈ mcp grants, t ∈ g.mcp_tools } )
//
// The tools_root algorithm and MaxTools are unchanged, so the circuit and
// the vkey are unchanged. Only the input set is larger.
//
// This file is the one derivation. Publish (CanonicalizeV3), the witness
// feeder (install.LoadManifestParams), commission containment
// (commission.FromManifest) and the commitment check that commission and
// the verifier run (commission.CheckManifestCommitment) all call
// CommittedTools or DeclaredToolsV3, so no path can commit one set and
// check another.
//
// Contents:
//   - BrokerGrant: one brokered grant, as the derivation reads it.
//   - BrokerToolID: the canonical id "<mcp_name>.<tool>".
//   - DeclaredToolsV3: the v3 union, with its refusals.
//   - CommittedTools: the declared_tools list for a given manifest version.
package canon

import (
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// BrokerGrant is one brokered MCP grant as the v3 derivation reads it: the
// grant's tool namespace and its closed allowlist of upstream tool names.
// It mirrors pod.Gateway's MCPName and MCPTools for a protocol = "mcp"
// entry; HTTP gateway entries are never BrokerGrants.
type BrokerGrant struct {
	MCPName string
	Tools   []string
}

// brokerMCPNamePattern and brokerToolPattern are the pod schema patterns
// for mcp_name and each mcp_tools entry (internal/pod/spec_v0_1.schema.json,
// the same patterns reef-core's schema applies). Both are ASCII, so NFC is
// the identity, and mcp_name has no "." so the first "." of a broker id
// splits it without ambiguity. The derivation checks them again because a
// canonical manifest read back from an install cache is parsed, not
// schema-validated.
var (
	brokerMCPNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	brokerToolPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// reservedBrokerNamespaces are the built-in reef-core MCP tool namespaces
// (pod.reservedMCPNamespaces, reef-core GatewayRules.reserved_namespaces/0).
// `pod validate` refuses them at publish; the derivation refuses them again
// because a manifest read back from an install cache is not validated, and a
// grant named "proofs" would commit ids that shadow built-in tools.
var reservedBrokerNamespaces = map[string]bool{
	"openbrain": true,
	"proofs":    true,
	"budget":    true,
	"plan":      true,
}

// BrokerToolID returns the canonical id of a brokered tool:
// mcpName + "." + tool. This is the exact string reef-core's broker records
// as the tool-log tool_id (Grants.namespaced/2). The opencode-rendered
// runtime name ("open_brain_<mcp_name>_<tool>") is never a committed id.
//
// Inputs: the grant's mcp_name and one of its mcp_tools. Output: the id.
func BrokerToolID(mcpName, tool string) string {
	return mcpName + "." + tool
}

// DeclaredToolsV3 derives the konareef-toml/v3 declared_tools list.
//
// Inputs: contextTools, the [[context.tools]].source names in manifest
// order; grants, the brokered MCP grants in manifest order.
//
// Output: the union of contextTools and every BrokerToolID of every grant,
// sorted ascending by UTF-8 bytes (the order tools_root uses), as a new
// non-nil slice. With no grants the result is the v2 set, sorted.
//
// Errors (each a coded *Error; nothing is dropped or merged to make the
// list fit):
//   - COMMIT_EMPTY_ID, COMMIT_INVALID_UTF8_ID, COMMIT_NON_NFC_ID: a context
//     tool is empty, not UTF-8, or not NFC.
//   - COMMIT_BROKER_TOOL_ID_INVALID: an mcp_name or tool is outside the pod
//     schema pattern, or the mcp_name is a reserved built-in namespace.
//   - COMMIT_DUPLICATE_ENTRY: a context tool repeats, an mcp_name repeats,
//     or a grant lists one tool twice.
//   - COMMIT_TOOL_ID_COLLISION: a context tool equals a broker id.
//   - COMMIT_OVER_CAP: the combined list has more than MaxTools entries.
func DeclaredToolsV3(contextTools []string, grants []BrokerGrant) ([]string, error) {
	contextSet := make(map[string]struct{}, len(contextTools))
	for _, source := range contextTools {
		switch {
		case source == "":
			return nil, newErr(ErrCommitEmptyID,
				"declared_tools: an empty [[context.tools]].source is not allowed (it collides with the padding leaf)")
		case !utf8.ValidString(source):
			return nil, newErr(ErrCommitInvalidUTF8ID,
				"declared_tools: a [[context.tools]].source is not valid UTF-8")
		case norm.NFC.String(source) != source:
			return nil, newErr(ErrCommitNonNFCID,
				fmt.Sprintf("declared_tools: tool source %q is not NFC-normalized", source))
		}
		if _, dup := contextSet[source]; dup {
			return nil, newErr(ErrCommitDuplicateEntry,
				fmt.Sprintf("declared_tools: [[context.tools]].source %q is declared twice", source))
		}
		contextSet[source] = struct{}{}
	}

	brokerSet := map[string]struct{}{}
	seenNames := map[string]struct{}{}
	for grantIndex, grant := range grants {
		if !brokerMCPNamePattern.MatchString(grant.MCPName) {
			return nil, newErr(ErrCommitBrokerToolIDInvalid,
				fmt.Sprintf("declared_tools: brokered grant %d has mcp_name %q, outside ^[a-z][a-z0-9_]{0,31}$",
					grantIndex, grant.MCPName))
		}
		if reservedBrokerNamespaces[grant.MCPName] {
			return nil, newErr(ErrCommitBrokerToolIDInvalid,
				fmt.Sprintf("declared_tools: brokered grant %d uses mcp_name %q, a built-in reef-core tool namespace",
					grantIndex, grant.MCPName))
		}
		if _, dup := seenNames[grant.MCPName]; dup {
			return nil, newErr(ErrCommitDuplicateEntry,
				fmt.Sprintf("declared_tools: mcp_name %q is used by two brokered grants", grant.MCPName))
		}
		seenNames[grant.MCPName] = struct{}{}
		for _, tool := range grant.Tools {
			if !brokerToolPattern.MatchString(tool) {
				return nil, newErr(ErrCommitBrokerToolIDInvalid,
					fmt.Sprintf("declared_tools: mcp_name %q grants tool %q, outside ^[A-Za-z0-9_.-]{1,128}$",
						grant.MCPName, tool))
			}
			id := BrokerToolID(grant.MCPName, tool)
			if _, dup := brokerSet[id]; dup {
				return nil, newErr(ErrCommitDuplicateEntry,
					fmt.Sprintf("declared_tools: brokered tool %q is granted twice", id))
			}
			if _, clash := contextSet[id]; clash {
				return nil, newErr(ErrCommitToolIDCollision,
					fmt.Sprintf("declared_tools: [[context.tools]].source %q is also the id of a brokered MCP tool; "+
						"rename the context tool or drop it, because one leaf cannot stand for two authorities", id))
			}
			brokerSet[id] = struct{}{}
		}
	}

	total := len(contextSet) + len(brokerSet)
	if total > MaxTools {
		return nil, newErr(ErrCommitOverCap,
			fmt.Sprintf("declared_tools: %d [[context.tools]] plus %d brokered MCP tools is %d, over the cap of %d; "+
				"remove tools until the total is %d or less", len(contextSet), len(brokerSet), total, MaxTools, MaxTools))
	}

	declared := make([]string, 0, total)
	for source := range contextSet {
		declared = append(declared, source)
	}
	for id := range brokerSet {
		declared = append(declared, id)
	}
	sort.Strings(declared)
	return declared, nil
}

// CommittedTools returns the declared_tools list that a manifest of the
// given canonical version commits.
//
// Inputs: version, the token canon.VersionIdentifier returns for the
// manifest ("v1", "v2", "v3"), or "" for bytes with no magic line (an
// author-written pod.toml); contextTools and grants as for DeclaredToolsV3.
//
// Output:
//   - "v3": DeclaredToolsV3(contextTools, grants). A v3 manifest with no
//     grant is refused with COMMIT_V3_REQUIRES_BROKER_GRANT: its root equals
//     the v2 root, and one pod must not have two valid encodings.
//   - "v2", "v1" or "": a copy of contextTools in manifest order. Brokered
//     grants are not part of these versions' commitment, so they are
//     ignored here; a v2 manifest with a grant stays readable, but a proof
//     of a brokered call against it is refused downstream (MCP-Z00 §10.3).
//     v1 and "" commit no fields_root at all; the list is returned for
//     commission containment, which has always read [[context.tools]].
//   - any other version: a coded WRONG_VERSION *Error. A version this
//     build does not implement has no known derivation.
func CommittedTools(version string, contextTools []string, grants []BrokerGrant) ([]string, error) {
	switch version {
	case "v3":
		if len(grants) == 0 {
			return nil, newErr(ErrCommitV3RequiresBrokerGrant,
				"declared_tools: a konareef-toml/v3 manifest must carry at least one brokered MCP grant; "+
					"a pod with none is konareef-toml/v2, so one pod has one canonical encoding")
		}
		return DeclaredToolsV3(contextTools, grants)
	case "v2", "v1", "":
		return append([]string{}, contextTools...), nil
	default:
		return nil, newErr(ErrWrongVersion,
			"declared_tools: manifest claims unsupported konareef-toml version "+version)
	}
}
