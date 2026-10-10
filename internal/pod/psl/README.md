# Vendored Public Suffix List

`public_suffix_list.dat` is the Public Suffix List (PSL), copied byte for
byte from the upstream repository at one pinned commit. The `pod` package
embeds it. `konareef pod validate` uses it to refuse a `[network].egress`
wildcard whose base is a public suffix, or a proper ancestor of any rule
in the list (`egress_wildcard_public_suffix`, reef-core#87, owner decision
D2 and the owner ruling of 2026-10-09).

| Field | Value |
|---|---|
| Upstream | <https://github.com/publicsuffix/list> |
| File | `public_suffix_list.dat` |
| Commit | `3929462652695bad04f0a27afb600974014a3c8b` (2026-10-07) |
| SHA-256 | `2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7` |
| Size | 335389 bytes |
| Sections used | ICANN and PRIVATE (owner decision D2a) |
| License | Mozilla Public License 2.0 (see the header of the file) |

reef-core vendors the same file at the same commit. Both repositories pin
the SHA-256. konareef pins it in `egress_breadth.go` (`PSLSHA256`) and in
the `breadth` section of `../testdata/egress-vectors.json`. A test fails
when the embedded file, the constant and the vectors do not agree.

Do not replace this file with `golang.org/x/net/publicsuffix`. That list
is compiled into the Go module and moves with the `x/net` version, not
with the reef-core pin, so the client and the server would disagree.

## Update procedure

1. Pick an upstream commit. Download the file from
   `https://raw.githubusercontent.com/publicsuffix/list/<commit>/public_suffix_list.dat`.
2. Replace `public_suffix_list.dat`. Do not edit its content.
3. Set `PSLCommit` and `PSLSHA256` in `../egress_breadth.go`, the table
   above, and `breadth.psl` in `../testdata/egress-vectors.json`.
4. Run `go test ./internal/pod`. Fix a vector only if the upstream list
   changed the answer for it.
5. Open a linked reef-core MR that vendors the same file and the new
   vector file, and updates both SHA-256 pins.
