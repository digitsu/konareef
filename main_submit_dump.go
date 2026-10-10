// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build !test_dump_submit_opts

// main_submit_dump.go — production build of the SubmitOpts dump hook.
// Production builds do NOT carry the test-only instrumentation: this
// file provides a no-op maybeDumpSubmitOpts so production callers see
// no behaviour change. The test-only counterpart in
// main_submit_dump_test_tag.go is selected when the binary is built
// with `-tags test_dump_submit_opts` (round-4 B1 / round-8 B1).

package main

import "github.com/digitsu/konareef/internal/publish"

// maybeDumpSubmitOpts is a no-op in production builds.
func maybeDumpSubmitOpts(_ publish.SubmitOpts) {}
