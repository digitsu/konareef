# tlog/testdata

The single fixture `tlog_from_db_rows.json` is a verbatim mirror of the
`tlog-from-db-rows` entry from the upstream conformance file:

    ~/work/paygate-zk/docs/prds/konareef-integration-contract-conformance-vectors-v1.json

This Go package's `internal/tlog/conformance_test.go` is the byte-exact
gate for the package: any drift between this file and the upstream
publication => the conformance test fails => release blocked.

## Sync rule

When the upstream `tlog-from-db-rows` entry changes, regenerate this
file by re-extracting the object from the upstream JSON:

    jq '.vectors[] | select(.id == "tlog-from-db-rows")' \
      ~/work/paygate-zk/docs/prds/konareef-integration-contract-conformance-vectors-v1.json \
      > internal/tlog/testdata/tlog_from_db_rows.json

Then run `git diff --exit-code internal/tlog/testdata/` to confirm
byte-identity with whatever upstream now publishes.

## Why a local copy and not a `replace` directive into paygate-zk?

`paygate-zk` is a separate repo with its own release cadence. Pulling
its vectors at test time would introduce a cross-repo dependency
checkout step that breaks offline builds (e.g. release tarballs). The
local mirror keeps the konareef Go build self-contained; the sync rule
documents how to refresh.
