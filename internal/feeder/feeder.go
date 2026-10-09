// Package feeder is the konareef Pod-Trust-Domain sidecar orchestrator.
// It ties the individual feeder stages together: reading the relayed
// witness.json, assembling a PodRecord, calling the PS-1 prover via
// SpartanCompress, and posting the resulting artifact to reef-core via
// PostArtifact.
package feeder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// Opts configures one feeder run inside the PTD workspace.
// All fields are required; the CLI validates them before calling Run.
type Opts struct {
	// WitnessPath is the filesystem path to the witness.json file written
	// by the relayer sidecar.
	WitnessPath string
	// PaygateURL is the base URL of the PS-1 prover (e.g. http://localhost:8080).
	PaygateURL string
	// IngestURL is the reef-core internal ingest endpoint URL.
	IngestURL string
	// IngestToken is the per-pod bearer token for the reef-core ingest seam.
	IngestToken string
	// CircuitID identifies the ZK circuit to use: konareef-pod-step-v1 or
	// konareef-pod-step-v1.1 (VHASH, paygate-zk#12). Empty lets PS-1 decide.
	CircuitID string
}

// Run executes the full feeder pipeline for one step:
//
//  1. Read and parse the witness JSON from o.WitnessPath.
//  2. Assemble a PodRecord from the witness (AssemblePodRecord).
//  3. POST the PodRecord to PS-1 to obtain a SpartanCompressResult (SpartanCompress).
//  4. POST the artifact to reef-core ingest (PostArtifact).
//
// Returns the first error encountered, wrapped with feeder-package context.
//
// The four endpoint/credential fields are required (the doc invariant): an
// empty WitnessPath, PaygateURL, IngestURL, or IngestToken is rejected up
// front rather than surfacing as a confusing downstream I/O/HTTP error.
// CircuitID is allowed to be empty (PS-1 may default it server-side). A
// non-empty CircuitID must be one this build accepts (VHASH: v1 or v1.1).
func Run(ctx context.Context, o Opts) error {
	switch {
	case o.CircuitID != "" && !vkeystore.IsSupportedCircuitID(o.CircuitID):
		return fmt.Errorf("feeder: unsupported circuit_id %q (want one of %v)", o.CircuitID, vkeystore.SupportedCircuitIDs())
	case o.WitnessPath == "":
		return fmt.Errorf("feeder: WitnessPath is required")
	case o.PaygateURL == "":
		return fmt.Errorf("feeder: PaygateURL is required")
	case o.IngestURL == "":
		return fmt.Errorf("feeder: IngestURL is required")
	case o.IngestToken == "":
		return fmt.Errorf("feeder: IngestToken is required")
	}
	raw, err := os.ReadFile(o.WitnessPath)
	if err != nil {
		return fmt.Errorf("feeder: read witness: %w", err)
	}
	var w Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		return fmt.Errorf("feeder: parse witness: %w", err)
	}
	pr, err := AssemblePodRecord(w)
	if err != nil {
		return err
	}
	scr, err := SpartanCompress(ctx, o.PaygateURL, o.CircuitID, pr)
	if err != nil {
		return err
	}
	return PostArtifact(ctx, o.IngestURL, o.IngestToken, scr, w)
}
