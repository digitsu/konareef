<!--
Vendored into konareef for MCP-K03 (konareef#11).

Source: reef-core, branch mcp-diag-r/matched-egress-diagnostics (MR !108),
commit 82c63122304aa4c866e1cb14bdb0838b0239187a,
path test/support/fixtures/mcp_egress_conflicts/.

cases.json is a byte-for-byte copy. Its git blob id is
53d8ca7fb7feeabd69f3d5bb2b506b46a6236448 in both repos; check with
`git hash-object cases.json`. Do not edit it here. Change it in reef-core
first, then copy it again and update this header.

This README is the upstream README with this header added.
konareef reads the fixture in internal/pod/gateway_conflicts_test.go.
konareef formats `authority` for a bracketed IPv6 grant with the brackets
put back, so it compares equal to reef-core's value (see
mcpEgressConflicts in internal/pod/gateway.go).
-->

# MCP grant / egress conflict fixture

`cases.json` holds the shared cases for one rule: a brokered MCP grant
(`[[network.gateway]]` with `protocol = "mcp"`) must not also be directly
reachable through `[network].egress`. reef-core runs every case in
`test/pod/spec/spawner_adapter_test.exs` ("shared mcp/egress conflict
fixture"). konareef vendors this file for its local validator code
`GATEWAY_MCP_HOST_ALSO_EGRESS` (konareef#11). Change both copies together.

## Case format

| Field | Meaning |
|---|---|
| `egress` | The `[network].egress` list, as authored. |
| `gateway` | The `[[network.gateway]]` entries, in order. Only `host` and `protocol` matter to this rule. |
| `expected.hosts` | The legacy host list: distinct authored grant hosts, sorted. |
| `expected.conflicts` | One object per (grant, matching egress entry) pair, in the order defined below. An empty list means the manifest passes this rule. |

## Matching rule

The fixture pins the rule that `Pod.Spec.SpawnerAdapter.mcp_egress_conflicts/1`
applies. The rule was not changed by MCP-DIAG-R.

- Both sides are trimmed and lowercased, then split into `host` and `port`.
  The port defaults to 443. The port is compared as an integer, so `0443`
  equals `443`.
- A rule matches a grant only when the ports are equal.
- With equal ports, an exact rule matches the same host. A `*.domain` rule
  matches a strict subdomain of `domain`. It does not match the bare
  `domain`.
- Only `protocol = "mcp"` entries are checked. An `http` gateway entry may
  share a host with an egress entry.
- A bracketed IPv6 literal keeps its brackets in reef-core's `authority`.
  konareef's `splitHostPort` removes them. Compare the authored strings, not
  the `authority` value, across the two repos for IPv6.
- A trailing dot (`mcp.example.com.`) is not tested. The v0.1 schema pattern
  refuses it on both fields, so it cannot reach the matcher.

## HTTP wire shape

`POST /api/pods/spawn` (all three modes) returns HTTP 422 with this body when
the rule refuses a manifest:

```json
{
  "error": {
    "kind": "mcp_grant_host_also_declared_egress",
    "hosts": ["mcp.example.com"],
    "conflicts": [
      {
        "grant": "mcp.example.com",
        "grant_index": 1,
        "authority": "mcp.example.com:443",
        "egress": "*.example.com",
        "egress_index": 1
      },
      {
        "grant": "mcp.example.com",
        "grant_index": 1,
        "authority": "mcp.example.com:443",
        "egress": "mcp.example.com",
        "egress_index": 2
      }
    ],
    "conflicts_truncated": false,
    "message": "these hosts are brokered MCP grants and are also reachable through [network].egress; a brokered host is reached only through the broker, so remove or narrow each egress entry listed in conflicts"
  }
}
```

| Field | Type | Since | Meaning |
|---|---|---|---|
| `kind` | string | Phase 4a (!95) | Stable code. Unchanged. |
| `hosts` | string[] | Phase 4a (!95) | Distinct authored grant hosts, sorted. Unchanged and never truncated. |
| `conflicts` | object[] | MCP-DIAG-R | Sorted by `grant_index`, then `egress_index`. Each pair appears once. At most 32 entries. |
| `conflicts[].grant` | string | MCP-DIAG-R | The grant's `host`, as authored. |
| `conflicts[].grant_index` | integer | MCP-DIAG-R | 0-based index into `[[network.gateway]]`, counting every entry (`http` entries too). Matches konareef's `network.gateway[N]` path. |
| `conflicts[].authority` | string | MCP-DIAG-R | The grant as the matcher reads it: lowercased `host:port`, port defaulted to 443 and without leading zeros. |
| `conflicts[].egress` | string | MCP-DIAG-R | The matching `[network].egress` entry, as authored. For a wildcard this is the wildcard. |
| `conflicts[].egress_index` | integer | MCP-DIAG-R | 0-based index into `[network].egress`. |
| `conflicts_truncated` | boolean | MCP-DIAG-R | `true` when more than 32 pairs matched and the list was cut. |
| `message` | string | Phase 4a (!95) | Human text. It names no manifest string. Do not parse it. |

Rules for clients:

- Read `kind` to detect the refusal. Read `conflicts` for detail.
- A server from before MCP-DIAG-R sends `kind`, `hosts` and `message` only.
  Treat a missing `conflicts` field as "no detail", and fall back to `hosts`.
- Authored strings are returned as the author wrote them (case included).
  JSON encoding escapes them. A terminal client must still escape control
  characters before it prints them.
- Every field comes from the manifest's `[network]` table. For a closed pod
  that table is in the public signed manifest today. If grants move into the
  sealed body, a buyer-facing surface must use a redacted code instead of
  these fields.
