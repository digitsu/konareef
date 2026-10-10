// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// mcp_broker.go — the spawn-time brokered-MCP rules, checked at validate time.
//
// reef-core refuses to spawn a pod with a brokered MCP grant
// ([[network.gateway]] with protocol = "mcp") in two cases that the gateway
// namespace rules in gateway.go do not cover:
//
//   - the runtime is not one whose MCP tool naming reef-core knows
//     (Pod.Spec.SpawnerAdapter, @mcp_broker_runtimes), and
//   - two granted tools, or a granted tool and a built-in reef-core tool,
//     render to one name in the runtime after sanitization
//     (ReefCore.Egress.McpBroker.Grants.name_collisions/2).
//
// This file mirrors both, so `pod validate` refuses the same manifests.
// testdata/mcp_broker_vectors.json holds the shared vectors; the Go test
// and scripts/check_mcp_broker_vectors.exs (reef-core side) both check it.
//
// Contents:
//   - mcpBrokerRuntimeKinds: the [runtime].kind values that support grants.
//   - mcpBuiltinToolNames: the built-in reef-core MCP tool names.
//   - opencodeToolName: the name opencode shows the model for a tool.
//   - mcpToolNameCollisions: the server's collision function, for vectors.
//   - mcpBrokerRules: the coded issues ValidateWithWarnings reports.
package pod

import (
	"fmt"
	"sort"
	"strings"
)

// Stable codes for the brokered-MCP spawn rules. A verifier or a UI keys
// off these exact bytes; the messages beside them may change.
const (
	CodeGatewayMCPRuntimeUnsupported = "GATEWAY_MCP_RUNTIME_UNSUPPORTED"
	CodeGatewayMCPToolNameCollision  = "GATEWAY_MCP_TOOL_NAME_COLLISION"
)

// mcpOpencodeServerKey is the key of the reef-core MCP server in the
// opencode config reef-core materializes. It mirrors
// Grants.opencode_server_key/0 in reef-core.
const mcpOpencodeServerKey = "open_brain"

// mcpBrokerRuntimeKinds are the [runtime].kind values whose registry
// adapter is in reef-core's @mcp_broker_runtimes: orca (Runtime.OpenCode)
// and lobster (Runtime.Omo). A kind is matched exactly, as reef-core's
// registry lookup does; a friendly name such as "opencode" or "omo" is not
// a kind. OpenClaw is not supported. The test-only test_null kind is left
// out, because a production reef-core does not register it.
var mcpBrokerRuntimeKinds = map[string]bool{
	"orca":    true,
	"lobster": true,
}

// mcpBuiltinToolNames are the built-in reef-core MCP tools, in the order
// McpTransport.static_tools/0 publishes them.
var mcpBuiltinToolNames = []string{
	"proofs.list",
	"budget.get",
	"plan.get_state",
	"plan.update_task",
	"openbrain.report_usage",
	"openbrain.inspect_memory",
	"openbrain.list_review_queue",
	"openbrain.review_memory",
	"openbrain.get_recall_trace",
	"openbrain.recall",
	"openbrain.writeback",
}

// mcpGrantTools is the part of a brokered grant the collision rule reads:
// the namespace and the granted upstream tools.
type mcpGrantTools struct {
	MCPName string
	Tools   []string
}

// sanitizeMCPName replaces every byte that is not an ASCII letter, digit,
// "_", or "-" with "_". It works on bytes, not runes, because reef-core's
// regex (`~r/[^a-zA-Z0-9_-]/`, no `u` flag) does: a two-byte UTF-8
// character becomes two underscores.
//
// Input: any string. Output: a string of the same byte length.
func sanitizeMCPName(value string) string {
	out := []byte(value)
	for index, char := range out {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9', char == '_', char == '-':
		default:
			out[index] = '_'
		}
	}
	return string(out)
}

// opencodeToolName returns the name opencode shows the model for a tool on
// the reef-core MCP server, mirroring Grants.opencode_tool_name/1.
//
// Input: a tool name as tools/list publishes it, e.g. "jira.get_issue".
// Output: e.g. "open_brain_jira_get_issue".
func opencodeToolName(toolName string) string {
	return sanitizeMCPName(mcpOpencodeServerKey) + "_" + sanitizeMCPName(toolName)
}

// mcpToolNameCollisions mirrors Grants.name_collisions/2.
//
// Inputs: the grants, and the built-in tool names.
// Output: the namespaced names ("<mcp_name>.<tool>") of the granted tools
// whose opencode name equals the opencode name of a built-in tool or of
// another granted tool, sorted by bytes. A name granted twice is listed
// twice. Nil when every name is unique.
func mcpToolNameCollisions(grants []mcpGrantTools, builtinNames []string) []string {
	builtin := map[string]bool{}
	for _, name := range builtinNames {
		builtin[opencodeToolName(name)] = true
	}
	byRendered := map[string][]string{}
	for _, grant := range grants {
		for _, tool := range grant.Tools {
			namespaced := grant.MCPName + "." + tool
			rendered := opencodeToolName(namespaced)
			byRendered[rendered] = append(byRendered[rendered], namespaced)
		}
	}
	var collisions []string
	for rendered, names := range byRendered {
		if len(names) > 1 || builtin[rendered] {
			collisions = append(collisions, names...)
		}
	}
	sort.Strings(collisions)
	return collisions
}

// mcpBrokerRules applies the runtime and tool-name rules to the brokered
// grants in spec.Network.Gateway.
//
// Input: the decoded spec. Output: the coded issues. A spec with no
// protocol = "mcp" entry yields nothing, so an HTTP-only gateway pod is not
// affected by its runtime kind.
//
// A grant whose mcp_name is reserved, or repeats an earlier grant's, is
// left out of the collision check. gatewayRules already refuses it, and
// reef-core refuses it while parsing, before the spawn-time collision
// check runs; including it would report one mistake twice.
func mcpBrokerRules(spec Spec) []Issue {
	if spec.Network == nil {
		return nil
	}
	type grantedTool struct {
		path, namespaced, rendered string
	}
	var granted []grantedTool
	hasGrant := false
	seenNames := map[string]bool{}
	for index, entry := range spec.Network.Gateway {
		if entry.Protocol != "mcp" {
			continue
		}
		hasGrant = true
		if reservedMCPNamespaces[entry.MCPName] || seenNames[entry.MCPName] {
			continue
		}
		seenNames[entry.MCPName] = true
		for toolIndex, tool := range entry.MCPTools {
			namespaced := entry.MCPName + "." + tool
			granted = append(granted, grantedTool{
				path:       fmt.Sprintf("network.gateway[%d].mcp_tools[%d]", index, toolIndex),
				namespaced: namespaced,
				rendered:   opencodeToolName(namespaced),
			})
		}
	}
	if !hasGrant {
		return nil
	}

	var issues []Issue
	if !mcpBrokerRuntimeKinds[spec.Runtime.Kind] {
		issues = append(issues, Issue{
			Path: "runtime.kind", Code: CodeGatewayMCPRuntimeUnsupported,
			Message: fmt.Sprintf("runtime %q does not support brokered MCP grants; reef-core serves them only to the orca and lobster runtimes", spec.Runtime.Kind),
		})
	}

	builtinByRendered := map[string]string{}
	for _, name := range mcpBuiltinToolNames {
		builtinByRendered[opencodeToolName(name)] = name
	}
	byRendered := map[string][]string{}
	for _, tool := range granted {
		byRendered[tool.rendered] = append(byRendered[tool.rendered], tool.namespaced)
	}
	for _, tool := range granted {
		var clashes []string
		if builtinName, ok := builtinByRendered[tool.rendered]; ok {
			clashes = append(clashes, "built-in tool "+builtinName)
		}
		for _, other := range byRendered[tool.rendered] {
			if other != tool.namespaced {
				clashes = append(clashes, "granted tool "+other)
			}
		}
		if len(clashes) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Path: tool.path, Code: CodeGatewayMCPToolNameCollision,
			Message: fmt.Sprintf("tool %s reaches the runtime as %s, the same name as %s; rename or drop one of them", tool.namespaced, tool.rendered, strings.Join(clashes, ", ")),
		})
	}
	return issues
}
