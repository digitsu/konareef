// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commit_tools.go — the manifest fields that feed the committed
// declared_tools list (konareef-toml/v2 and v3).
//
// canon.CommittedTools and canon.DeclaredToolsV3 do the derivation. This
// file only reads the two inputs out of a Spec, so that publish
// (publish.DeriveCommitParams), the witness feeder
// (install.LoadManifestParams) and commission containment
// (commission.FromManifest) read them the same way.
package pod

import "github.com/digitsu/konareef/internal/canon"

// CommitToolInputs returns the two inputs of the declared_tools
// derivation.
//
// Input: a decoded spec. Output: sources, the [[context.tools]].source
// names in manifest order (an empty, non-nil slice when there are none);
// and grants, one canon.BrokerGrant per [[network.gateway]] entry with
// protocol = "mcp", in manifest order (nil when there are none). HTTP
// gateway entries are never grants, so an HTTP-only or empty [network]
// adds nothing to the commitment. Values are copied as authored; the
// derivation validates them.
func CommitToolInputs(s Spec) (sources []string, grants []canon.BrokerGrant) {
	sources = []string{}
	if s.Context != nil {
		for _, tool := range s.Context.Tools {
			sources = append(sources, tool.Source)
		}
	}
	if s.Network != nil {
		for _, entry := range s.Network.Gateway {
			if entry.Protocol != "mcp" {
				continue
			}
			grants = append(grants, canon.BrokerGrant{
				MCPName: entry.MCPName,
				Tools:   append([]string(nil), entry.MCPTools...),
			})
		}
	}
	return sources, grants
}
