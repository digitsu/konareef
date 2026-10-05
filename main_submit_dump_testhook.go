// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build test_dump_submit_opts

// main_submit_dump_testhook.go — test-only build of the SubmitOpts
// dump hook. Enabled by the `test_dump_submit_opts` build tag; the
// dump path is invoked only when KONAREEF_TEST_DUMP_SUBMIT_OPTS is
// set to a writable file path. Used by TestCLITypeDPublishPasses-
// SealedWitnessToSubmit (round-4 B1) to confirm the sealed Witness
// reaches publish.Submit.
//
// Production builds NEVER include this file (the `!test_dump_submit_
// opts` counterpart in main_submit_dump.go is selected instead), so
// the dump path is unreachable from any release binary.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/digitsu/konareef/internal/publish"
)

// maybeDumpSubmitOpts writes a JSON envelope describing the
// publish.SubmitOpts being passed to publish.Submit. The dump is only
// written when KONAREEF_TEST_DUMP_SUBMIT_OPTS is set to a writable
// path; otherwise the function is a no-op.
//
// Envelope shape (matches the test assertion in
// TestCLITypeDPublishPassesSealedWitnessToSubmit):
//
//	{"circuit_id": "...", "zk_enabled": true, "disclosure_policy": "D",
//	 "witness": {"lineage_id": "<hex>", "salt": "<hex>",
//	              "sealed": true, "disclosure_policy": "D"}}
func maybeDumpSubmitOpts(opts publish.SubmitOpts) {
	path := os.Getenv("KONAREEF_TEST_DUMP_SUBMIT_OPTS")
	if path == "" {
		return
	}
	envelope := struct {
		CircuitID        string `json:"circuit_id"`
		ZkEnabled        bool   `json:"zk_enabled"`
		DisclosurePolicy string `json:"disclosure_policy"`
		Witness          *struct {
			LineageID        string `json:"lineage_id"`
			Salt             string `json:"salt"`
			Sealed           bool   `json:"sealed"`
			DisclosurePolicy string `json:"disclosure_policy"`
		} `json:"witness,omitempty"`
	}{
		CircuitID:        opts.CircuitID,
		ZkEnabled:        opts.ZkEnabled,
		DisclosurePolicy: opts.DisclosurePolicy,
	}
	if opts.Witness != nil {
		envelope.Witness = &struct {
			LineageID        string `json:"lineage_id"`
			Salt             string `json:"salt"`
			Sealed           bool   `json:"sealed"`
			DisclosurePolicy string `json:"disclosure_policy"`
		}{
			LineageID:        hex.EncodeToString(opts.Witness.LineageID[:]),
			Salt:             hex.EncodeToString(opts.Witness.Salt[:]),
			Sealed:           opts.Witness.Sealed,
			DisclosurePolicy: opts.Witness.DisclosurePolicy,
		}
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "test-dump: marshal:", err)
		return
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "test-dump: write:", err)
	}
}
