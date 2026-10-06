// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// gateway.go — cross-field rules for [[network.gateway]].
//
// The JSON schema checks each entry's shape. These rules read two tables
// at once: the secret must be declared in [dependencies].secrets, the host
// must be exact (no wildcard, because the gateway attaches a secret to
// every request it forwards there), hosts must be unique, and a
// provider-unit cap needs a platform adapter for that host. For a
// brokered MCP grant (protocol = "mcp"), the namespace must not be a
// reef-core built-in, two grants must not share one, and no
// [network].egress entry may also cover the grant's authority
// (mcpEgressConflicts lists each such pair, in the shape reef-core
// sends in its 422 body). The rules
// emit coded Issues so `pod validate` output and reef-core error bodies
// can name the same failure.
//
// An http (non-mcp) gateway entry gets a softer version of the same
// egress-overlap check: reef-core excludes every [[network.gateway]]
// authority, http or mcp, from the runtime's direct CONNECT route
// (MCP-00 owner decision D8(a)), so an [network].egress entry for an http
// gateway host is never actually reachable there. That is redundant, not
// contradictory — an http entry does not claim the exclusive use a
// brokered grant does — so it is WarnGatewayHTTPHostAlsoEgress, not an
// Issue.

package pod

import (
	"fmt"
	"strconv"
	"strings"
)

// Stable codes for the gateway rules. A verifier or a UI keys off these
// exact bytes; the messages beside them may change.
const (
	CodeGatewaySecretUndeclared   = "GATEWAY_SECRET_UNDECLARED"
	CodeGatewayHostWildcard       = "GATEWAY_HOST_WILDCARD"
	CodeGatewayHostDuplicate      = "GATEWAY_HOST_DUPLICATE"
	CodeGatewayMCPHostAlsoEgress  = "GATEWAY_MCP_HOST_ALSO_EGRESS"
	CodeGatewayNoAdapter          = "GATEWAY_NO_ADAPTER"
	WarnGatewaySecretLeavesEnv    = "GATEWAY_SECRET_LEAVES_ENV"
	CodeGatewayMCPNameReserved    = "GATEWAY_MCP_NAME_RESERVED"
	CodeGatewayMCPNameDuplicate   = "GATEWAY_MCP_NAME_DUPLICATE"
	WarnGatewayMCPBrokerPending   = "GATEWAY_MCP_BROKER_PENDING"
	WarnGatewayHTTPHostAlsoEgress = "GATEWAY_HTTP_HOST_ALSO_EGRESS"
)

// gatewayAdapters lists the hosts reef-core can price in provider units.
// Empty in Phase B: reef-core counts calls only, so `max_units` and
// `daily_max_units` are refused for every host. Phase C adds
// "api.elevenlabs.io" when the adapter ships, and the list then mirrors
// `GET /api/egress/adapters` on reef-core (spec open question 3).
var gatewayAdapters = map[string]bool{}

// reservedMCPNamespaces are the tool prefixes of the built-in reef-core MCP
// tools. It mirrors Pod.Spec.GatewayRules.reserved_namespaces/0 in
// reef-core; change both together.
var reservedMCPNamespaces = map[string]bool{
	"openbrain": true,
	"proofs":    true,
	"budget":    true,
	"plan":      true,
}

// gatewayRules applies the cross-field rules to spec.Network.Gateway.
// It returns the coded issues and one WarnGatewaySecretLeavesEnv warning
// per entry. A nil Network or an empty Gateway list yields nothing.
func gatewayRules(spec Spec) ([]Issue, []Warning) {
	if spec.Network == nil || len(spec.Network.Gateway) == 0 {
		return nil, nil
	}
	declared := map[string]bool{}
	if spec.Dependencies != nil {
		for _, name := range spec.Dependencies.Secrets {
			declared[name] = true
		}
	}
	seenHosts := map[string]bool{}
	seenMCPNames := map[string]bool{}
	conflictsByGrant := map[int][]MCPEgressConflict{}
	for _, conflict := range mcpEgressConflicts(spec) {
		conflictsByGrant[conflict.GrantIndex] = append(conflictsByGrant[conflict.GrantIndex], conflict)
	}
	egressRules := egressAuthorities(spec)
	var issues []Issue
	var warnings []Warning
	for index, entry := range spec.Network.Gateway {
		prefix := fmt.Sprintf("network.gateway[%d]", index)

		host, port := splitHostPort(strings.ToLower(strings.TrimSpace(entry.Host)))
		if strings.HasPrefix(host, "*.") {
			issues = append(issues, Issue{
				Path: prefix + ".host", Code: CodeGatewayHostWildcard,
				Message: fmt.Sprintf("gateway host %q must be exact: the gateway attaches a secret to every request it forwards, so a wildcard would send it to an unnamed host", entry.Host),
			})
		}
		// The duplicate key uses the canonical port, so "host", "host:443",
		// "host:0443" and "host:00443" are one authority. That is the key
		// reef-core builds in gateway_duplicate_hosts/1 (spawner_adapter.ex),
		// which parses the port with String.to_integer/1 and defaults it to
		// 443. When the authored port was not already canonical, the message
		// also quotes the authored host, so the author can find the entry.
		hostKey := host + ":" + canonicalPort(port)
		if seenHosts[hostKey] {
			message := fmt.Sprintf("gateway host %s is declared more than once", hostKey)
			if port != canonicalPort(port) {
				message += fmt.Sprintf(" (authored as %q)", entry.Host)
			}
			issues = append(issues, Issue{
				Path: prefix + ".host", Code: CodeGatewayHostDuplicate,
				Message: message,
			})
		}
		seenHosts[hostKey] = true

		if !declared[entry.Secret] {
			issues = append(issues, Issue{
				Path: prefix + ".secret", Code: CodeGatewaySecretUndeclared,
				Message: fmt.Sprintf("gateway secret %q is not in [dependencies].secrets", entry.Secret),
			})
		}

		if entry.MaxUnits != 0 && !gatewayAdapters[host] {
			issues = append(issues, Issue{
				Path: prefix + ".max_units", Code: CodeGatewayNoAdapter,
				Message: fmt.Sprintf("max_units needs a platform adapter for %s, and none exists; use max_calls", host),
			})
		}
		if entry.DailyMaxUnits != 0 && !gatewayAdapters[host] {
			issues = append(issues, Issue{
				Path: prefix + ".daily_max_units", Code: CodeGatewayNoAdapter,
				Message: fmt.Sprintf("daily_max_units needs a platform adapter for %s, and none exists; use max_calls", host),
			})
		}

		leavesEnvMessage := fmt.Sprintf("secret %s is bound to gateway host %s: it will not be in the pod environment; the pod must call $REEF_GATEWAY_URL/%s/<path> with header Reef-Gateway-Token: $REEF_GATEWAY_TOKEN, and only a reef-core with the egress gateway can run it", entry.Secret, entry.Host, entry.Host)
		if entry.Protocol == "mcp" {
			leavesEnvMessage = fmt.Sprintf("secret %s is bound to brokered MCP host %s: it will not be in the pod environment; reef-core attaches it upstream", entry.Secret, entry.Host)
		}
		warnings = append(warnings, Warning{
			Path: prefix + ".secret", Code: WarnGatewaySecretLeavesEnv,
			Message: leavesEnvMessage,
		})

		if entry.Protocol != "mcp" {
			// MCP-00 D8(a): reef-core's runtime CONNECT exclusion covers
			// every gateway authority, not only brokered ones, so an
			// [network].egress entry for this http host is dead weight —
			// worth a warning, not a refusal, because (unlike an mcp
			// grant) an http entry does not claim the host exclusively.
			if hostAllowed(host, canonicalPort(port), egressRules) {
				warnings = append(warnings, Warning{
					Path: prefix + ".host", Code: WarnGatewayHTTPHostAlsoEgress,
					Message: fmt.Sprintf("gateway host %s is also declared in [network].egress: reef-core never lets the runtime reach a gateway authority through direct CONNECT, so requests to this host always go through the gateway and the egress entry has no effect here", hostKey),
				})
			}
			continue
		}
		mcpPath := prefix + ".mcp_name"
		switch {
		case reservedMCPNamespaces[entry.MCPName]:
			issues = append(issues, Issue{
				Path: mcpPath, Code: CodeGatewayMCPNameReserved,
				Message: fmt.Sprintf("mcp_name %q is a built-in reef-core tool namespace", entry.MCPName),
			})
		case seenMCPNames[entry.MCPName]:
			issues = append(issues, Issue{
				Path: mcpPath, Code: CodeGatewayMCPNameDuplicate,
				Message: fmt.Sprintf("mcp_name %q is used by an earlier grant", entry.MCPName),
			})
		}
		seenMCPNames[entry.MCPName] = true

		// A brokered grant asks reef-core to attach the secret, meter the
		// call, and record it in the custody proof. An [network].egress
		// entry for the same authority asks for the host to be reachable
		// with no platform key and no record — one host cannot be both.
		// reef-core refuses this at spawn time (spawner_adapter.ex,
		// mcp_egress_conflicts/1); `pod validate` must refuse it too, or
		// an author sees a clean local check and a spawn-time refusal for
		// the same manifest. There is one issue per matching egress entry,
		// so a wildcard is named as the wildcard, not as a literal host
		// that the egress list never contained. The fix is to change the
		// manifest: the broker does not silently take precedence.
		for _, conflict := range conflictsByGrant[index] {
			issues = append(issues, Issue{
				Path: prefix + ".host", Code: CodeGatewayMCPHostAlsoEgress,
				Message: fmt.Sprintf("mcp grant host %q (%s) is also reachable through network.egress[%d] %q; a brokered host is reached only through the broker, so remove or narrow that egress entry", conflict.Grant, conflict.Authority, conflict.EgressIndex, conflict.Egress),
			})
		}

		warnings = append(warnings, Warning{
			Path: prefix + ".protocol", Code: WarnGatewayMCPBrokerPending,
			Message: fmt.Sprintf("gateway host %s is a brokered MCP grant: reef-core serves these only when the operator has enabled the broker, and never for a closed pod, so a node that has not enabled it refuses to spawn this pod", entry.Host),
		})
	}
	return issues, warnings
}

// MCPEgressConflict is one (brokered MCP grant, [network].egress entry)
// pair that names the same authority. The JSON field names and values are
// the ones reef-core sends in the `conflicts` list of its HTTP 422
// `mcp_grant_host_also_declared_egress` body, so the shared fixture
// (testdata/mcp_egress_conflicts/cases.json) decodes into this type.
type MCPEgressConflict struct {
	// Grant is the grant's host, as authored.
	Grant string `json:"grant"`
	// GrantIndex is the 0-based index into [[network.gateway]], counting
	// every entry (http entries too), as in the network.gateway[N] path.
	GrantIndex int `json:"grant_index"`
	// Authority is the grant as the matcher reads it: lowercased
	// "host:port", with the port defaulted to 443 and without leading
	// zeros. An IPv6 host keeps its brackets, as in reef-core.
	Authority string `json:"authority"`
	// Egress is the matching [network].egress entry, as authored. For a
	// wildcard match it is the wildcard.
	Egress string `json:"egress"`
	// EgressIndex is the 0-based index into [network].egress.
	EgressIndex int `json:"egress_index"`
}

// egressAuthorities parses [network].egress into canonical match rules,
// shared by mcpEgressConflicts (the mcp-grant exclusivity refusal) and the
// http gateway/egress overlap warning in gatewayRules (MCP-00 D8(a)).
// Ports are canonicalized numerically, so "host:0443" and "host:443" are
// one authority — the same rule reef-core's integer port parse gives.
// Output is nil for a nil Network, and is in [network].egress order
// otherwise, so callers may index it by egressIndex.
func egressAuthorities(spec Spec) []egressRule {
	if spec.Network == nil {
		return nil
	}
	rules := make([]egressRule, len(spec.Network.Egress))
	for egressIndex, entry := range spec.Network.Egress {
		host, port := splitHostPort(strings.ToLower(strings.TrimSpace(entry)))
		rule := egressRule{host: host, port: canonicalPort(port)}
		if strings.HasPrefix(rule.host, "*.") {
			rule.wildcard = true
			rule.host = strings.TrimPrefix(rule.host, "*.")
		}
		rules[egressIndex] = rule
	}
	return rules
}

// mcpEgressConflicts returns every (brokered grant, [network].egress entry)
// pair where the egress entry covers the grant's full {host, port}
// authority. Input is the parsed spec; output is sorted by GrantIndex,
// then EgressIndex (manifest order), and is nil when nothing matches.
// Only protocol = "mcp" entries are checked: an http gateway host may also
// be directly reachable.
//
// It reads [network].egress alone. It deliberately does NOT use
// parseEgressRules (egress_review.go): parseEgressRules folds every
// [[network.gateway]] host into the same rule set as [network].egress, on
// the premise that a gateway host is itself a declaration of that host —
// which is exactly right for the static safety scan, but wrong here,
// because it would make every mcp grant match its own gateway entry.
//
// The match is hostAllowed (safety.go) applied to one rule at a time, on
// canonical numeric ports, so "mcp.example.com" (port 443) and
// "mcp.example.com:8443" are different authorities and not a conflict.
// splitHostPort strips IPv6 brackets; Authority puts them back so the
// value equals reef-core's `authority` field byte for byte.
func mcpEgressConflicts(spec Spec) []MCPEgressConflict {
	if spec.Network == nil {
		return nil
	}
	rules := egressAuthorities(spec)
	var conflicts []MCPEgressConflict
	for grantIndex, entry := range spec.Network.Gateway {
		if entry.Protocol != "mcp" {
			continue
		}
		host, port := splitHostPort(strings.ToLower(strings.TrimSpace(entry.Host)))
		port = canonicalPort(port)
		authorityHost := host
		if strings.Contains(host, ":") {
			authorityHost = "[" + host + "]"
		}
		for egressIndex, rule := range rules {
			if rule.host == "" || !hostAllowed(host, port, []egressRule{rule}) {
				continue
			}
			conflicts = append(conflicts, MCPEgressConflict{
				Grant:       entry.Host,
				GrantIndex:  grantIndex,
				Authority:   authorityHost + ":" + port,
				Egress:      spec.Network.Egress[egressIndex],
				EgressIndex: egressIndex,
			})
		}
	}
	return conflicts
}

// canonicalPort normalizes a port string numerically so "0443" and "443"
// compare equal. The GATEWAY_HOST_DUPLICATE key and the mcp-grant/egress
// overlap match both use it. It mirrors reef-core's integer port parse
// (Pod.Spec.SpawnerAdapter.split_host_port/1 uses String.to_integer/1,
// so "0443" and "443" are already the same value there). splitHostPort
// and hostAllowed in safety.go are left untouched: they also serve the
// undeclared-URL safety scan and are not part of this rule. A port of
// six or more digits cannot reach here through the v0.1 schema, whose
// host/egress patterns both end `(:[0-9]{1,5})?$`, so the two parsers
// may still disagree there — that is unreachable, not fixed. Any other
// parse failure returns the original string unchanged, so a non-numeric
// port can never silently become something else.
func canonicalPort(port string) string {
	n, err := strconv.Atoi(port)
	if err != nil {
		return port
	}
	return strconv.Itoa(n)
}
