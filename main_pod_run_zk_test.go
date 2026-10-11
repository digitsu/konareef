package main

// Tests for the `konareef pod run --zk` flag (reef-core ZK-002) at the
// CLI layer: the commissioned route has no ZK request, so the flag must
// fail the command there instead of being silently ignored.

import (
	"bytes"
	"strings"
	"testing"
)

// A commissioned run (`pod run --commission ...`) has its own flag set
// with no --zk. The flag must fail the command there, not be dropped.
func TestPodRunCommissionRefusesZKFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runCommissionSubmitCore(&stdout, &stderr, "pod run",
		[]string{"--commission", "commission.cbor", "--zk", "--out", t.TempDir()})

	if code != 2 {
		t.Fatalf("exit %d, want 2 (usage error)\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-zk") {
		t.Fatalf("stderr must name the refused flag, got: %s", stderr.String())
	}
}
