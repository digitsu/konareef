# Sealed closed-pod grant fixtures (v1, proposed)

Shared accept/refuse vectors for the sealed closed-pod grants design
(MCP-C00, reef-core#42).

MCP-C01 (konareef#13) and MCP-C02 (reef-core#43) both run these cases. The
two repos must give the same verdict and the same publisher code for every
`publish` case. MCP-C02 alone runs the `spawn` cases.

Status: **proposed**. The carrier names, the codes and the stages are
frozen only after the owner approves the design. Until then, do not ship a
parser that accepts `network.sealed_grants`.

## Layout

| Path | Contents |
|---|---|
| `cases.json` | The case list, the carrier constants, the canaries and the code lists. |
| `heads/*.toml` | Author-tree `pod.toml` heads, before canonicalization. |
| `grants/*.toml` | Plaintext `sealed/grants.toml` bodies. |
| `MANIFEST.sha256` | SHA-256 of every other file here, for vendoring parity. |

## Rules

- G17 (`SEALED_GRANTS_FILE_REFERENCED`) compares a head reference with
  `sealed/grants.toml` after removing one leading `./` and folding ASCII
  letters to lower case, so `./Sealed/Grants.toml` is refused (case R28).
  Only ASCII is folded. A directory reference such as `./sealed` or `./`
  is not refused.
- The heads contain no canary. A canary in a head is a fixture bug, and
  `test/pod/published_pods/sealed_grants_fixtures_test.exs` fails on it.
- The fixtures contain no secret values. Every `secret` field is a
  secret *name*. The `salt` is a fixed, public test value. A real publish
  uses 32 fresh random bytes.
- konareef vendors this directory byte for byte. After a change here,
  regenerate `MANIFEST.sha256` (`shasum -a 256` over the sorted file
  list, excluding the manifest itself) and copy the whole directory.
- The ciphertext is not a fixture. `K_body` and the nonce are random at
  every seal, so each repo seals these plaintexts in its own test setup.
  MCP-C01 supplies golden head plus ciphertext pairs from its real
  packer.
