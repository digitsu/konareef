// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// leaf_table_fetch.go — fetch a run's signed memory leaf table from
// reef-core (seam/2, MEM-SEAM D-SEAM-1a (i)).
//
// reef-core stores the publisher-signed leaf table beside the published
// row and serves it only on its internal per-run seam, authenticated by
// the same per-run ingest token the feeder already uses to post its
// proof:
//
//	GET <reef>/api/internal/tasks/<task_id>/memory-leaf-table
//	Authorization: Bearer <ingest token>
//	200 {"scheme": "konareef-mem-leaves/v1", "table": "<base64>", "signature": "<base64>"}
//
// The response is not trusted for integrity: install.LoadManifestParamsForRun
// checks the signature against the manifest's publisher key, the
// pod_hash, the cell list and the root before any byte of it is used.
package feeder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LeafTableScheme is the only leaf-table response scheme this build reads.
const LeafTableScheme = "konareef-mem-leaves/v1"

// maxLeafTableResponse bounds the response body. A table of 500 cells is
// 38 090 bytes, about 51 KiB as base64; 256 KiB leaves ample room for the
// JSON framing and the signature.
const maxLeafTableResponse = 256 << 10

// leafTableClient is the HTTP client for the fetch. The response is small,
// so a short timeout is enough.
var leafTableClient = &http.Client{Timeout: 30 * time.Second}

// ErrLeafTableFetch means the leaf table could not be fetched: a
// transport error, a non-200 status, an oversized or malformed body, or
// an unknown scheme. The error text never carries the body.
var ErrLeafTableFetch = errors.New("feeder: memory leaf table fetch failed")

// FetchLeafTable fetches the leaf table and its signature.
//
// Inputs: a context, the table URL reef-core passed as
// --memory-leaf-table-url, and the per-run ingest token. Output: the
// canonical table bytes and the DER signature, or an error wrapping
// ErrLeafTableFetch.
func FetchLeafTable(ctx context.Context, url, token string) ([]byte, []byte, error) {
	if url == "" {
		return nil, nil, fmt.Errorf("%w: no --memory-leaf-table-url", ErrLeafTableFetch)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrLeafTableFetch, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := leafTableClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrLeafTableFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: status %d", ErrLeafTableFetch, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLeafTableResponse+1))
	if err != nil || len(raw) > maxLeafTableResponse {
		return nil, nil, fmt.Errorf("%w: body unreadable or too large", ErrLeafTableFetch)
	}
	var body struct {
		Scheme    string `json:"scheme"`
		Table     string `json:"table"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Scheme != LeafTableScheme {
		return nil, nil, fmt.Errorf("%w: malformed body or unknown scheme", ErrLeafTableFetch)
	}
	table, err1 := base64.StdEncoding.Strict().DecodeString(body.Table)
	sig, err2 := base64.StdEncoding.Strict().DecodeString(body.Signature)
	if err1 != nil || err2 != nil || len(table) == 0 || len(sig) == 0 {
		return nil, nil, fmt.Errorf("%w: table or signature is not base64", ErrLeafTableFetch)
	}
	return table, sig, nil
}
