# konareef-rinit/v2 shared vectors

`vectors.json` is the contract for CL-4-live steps 2 and 3 (reef-core#84):
konareef membridge, publish, feeder and verify v2; paygate-zk PS-1 and
`konareef-pod-step-v1.2`; and reef-core. Spec:
`docs/reference/konareef-rinit-v2-spec.md` (§ 10 lists the groups).

The file is generated. Do not edit it by hand. From the repository root:

    go run ./internal/membridge/testdata/rinit_v2/gen -out internal/membridge/testdata/rinit_v2/vectors.json

The generator is deterministic. `TestRInitV2VectorsGenerator` runs it and
fails on any byte difference. The other tests in
`internal/membridge/rinit_v2_vectors_test.go` re-derive every value with a
second implementation.

Other repositories copy the file byte for byte. To change it, change the
spec and the generator here first, then re-copy.
