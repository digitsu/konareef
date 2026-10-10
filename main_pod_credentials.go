// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_credentials.go — the CLI surfaces of the pod-bundle credential
// scan (internal/pod/credentials.go).
//
// Two behaviors, one scan. `pod publish` and `pod listing publish` refuse
// a bundle that holds a credential-shaped string, with the stable code
// BUNDLE_CREDENTIAL_FOUND, and a bundle the scan cannot finish, with
// BUNDLE_CREDENTIAL_SCAN_FAILED. `pod validate` and `pod safety` only warn,
// because an author mid-build must be able to run them; the warning names
// the same file, line and class and never the value.
//
// Like the egress gate in main_pod_safety.go, this runs on the author's
// machine. It is advice to an honest author, not a control a server relies
// on: a client that skips it is not stopped by it. Server-side parity is
// tracked in reef-core#88.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/digitsu/konareef/internal/pod"
)

// bundleCredentialGate is the refusal, for `pod publish` and
// `pod listing publish`.
//
// Input: the pod directory and the command name for the message
// ("publish" or "listing"). Output: 0 to continue, or 1 to stop. Findings
// that the allow file lets through are printed to stderr and do not stop
// the command, so the author can see them. They reach only the author's
// terminal: a server-side listing review sees them after reef-core#88.
//
// It fails closed: a bundle that cannot be read, or an allow file that is
// malformed, stops the command with BUNDLE_CREDENTIAL_SCAN_FAILED, because
// "not scanned" must not read as "clean". That code is not
// BUNDLE_CREDENTIAL_FOUND, so automation can tell a scan failure from a
// finding.
func bundleCredentialGate(podDir, command string) int {
	scan, err := pod.ScanBundleCredentials(podDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s: credential scan could not finish: %v\n",
			command, pod.CodeBundleCredentialScanFailed, err)
		return 1
	}
	if notice := scan.AllowedNotice(); notice != "" {
		fmt.Fprint(os.Stderr, notice)
	}
	if len(scan.Refused) > 0 {
		fmt.Fprint(os.Stderr, scan.RefusalMessage(command))
		return 1
	}
	return 0
}

// warnBundleCredentials is the warning, for `pod validate` and
// `pod safety`. It writes one line per refused finding, with the digest an
// allow entry needs, to w and never
// changes an exit code. A scan that cannot finish is reported as a
// warning too, because these commands run on a half-built pod.
func warnBundleCredentials(w io.Writer, podDir string) {
	scan, err := pod.ScanBundleCredentials(podDir)
	if err != nil {
		fmt.Fprintf(w, " warning: credential scan could not finish: %v\n", err)
		return
	}
	for _, finding := range scan.Refused {
		fmt.Fprintf(w, " warning: %s: %s (sha256 = %q; publish refuses this; use `konareef pod secret set`; the value is not shown)\n",
			pod.CodeBundleCredentialFound, finding, finding.SHA256)
	}
}
