// Package feeder is the konareef Pod-Trust-Domain sidecar orchestrator.
// It ties the individual feeder stages together: reading the relayed
// witness.json, assembling a PodRecord, calling the PS-1 prover via
// SpartanCompress, and posting the resulting artifact to reef-core via
// PostArtifact.
package feeder

import (
	"context"
	"encoding/json"
	"errors"
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
	// CircuitID is the requested ZK circuit: konareef-pod-step-v1,
	// konareef-pod-step-v1.1 (VHASH, paygate-zk#12),
	// konareef-pod-step-v1.2 (konareef-rinit/v2 read), or empty. Run
	// passes it through CircuitForWitness, which picks the circuit the
	// witness needs: v1.1 for a memory-free witness (empty or v1.2
	// requested) and v1.2 for a memory-bearing one.
	CircuitID string
}

// CircuitForWitness picks the circuit a pod record is proved with
// (konareef-rinit/v2 R-M28, R-M31; coordinator decision on konareef!173).
//
// Inputs: the assembled pod record and the requested circuit id (may be
// empty). Output: the circuit id to send to PS-1, or an error:
//
//   - memory-bearing record (pod_record.memory present): an empty request
//     or konareef-pod-step-v1.2 gives v1.2; v1.2 must be accepted by this
//     build (its vkey pin is set), else the unsupported-circuit error; any
//     other id is ErrMemoryCircuitRequired.
//   - memory-free record: an empty request or konareef-pod-step-v1.2 gives
//     konareef-pod-step-v1.1, because v1.2 requires the v2 lane and a
//     memory-free run sends no lane; an explicit v1 or v1.1 is kept.
func CircuitForWitness(pr PodRecord, requested string) (string, error) {
	if pr.Memory != nil {
		switch requested {
		case "", vkeystore.CircuitIDPodStepV1_2:
			if !vkeystore.IsSupportedCircuitID(vkeystore.CircuitIDPodStepV1_2) {
				return "", fmt.Errorf("feeder: unsupported circuit_id %q (want one of %v)",
					vkeystore.CircuitIDPodStepV1_2, vkeystore.SupportedCircuitIDs())
			}
			return vkeystore.CircuitIDPodStepV1_2, nil
		default:
			return "", fmt.Errorf("%w (circuit_id %q)", ErrMemoryCircuitRequired, requested)
		}
	}
	if requested == "" || requested == vkeystore.CircuitIDPodStepV1_2 {
		return vkeystore.CircuitIDPodStepV1_1, nil
	}
	return requested, nil
}

// ErrMemoryCircuitRequired means a witness carries a memory lane (a
// memory-bearing konareef-rinit/v2 run) but the run's circuit id is not
// konareef-pod-step-v1.2. Only v1.2 binds the lane's payload and proves a
// read; an older circuit's proof of a memory-bearing manifest is not
// proof-eligible (konareef-rinit/v2 R-M30), and PS-1 refuses a v2 lane
// under v1 or v1.1 (R-M31, memory_lane_circuit_mismatch). The feeder
// refuses first, so nothing is sent to PS-1.
var ErrMemoryCircuitRequired = errors.New(
	"feeder: a memory-bearing witness needs circuit konareef-pod-step-v1.2; no proof is requested")

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
// CircuitID may be empty. A non-empty CircuitID must be one this build
// accepts (vkeystore). The circuit sent to PS-1 is CircuitForWitness's
// pick: v1.1 for a memory-free witness, v1.2 for a memory-bearing one. A
// memory-bearing witness with a v1 or v1.1 request is refused with
// ErrMemoryCircuitRequired before PS-1 is called.
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
	circuitID, err := CircuitForWitness(pr, o.CircuitID)
	if err != nil {
		return err
	}
	scr, err := SpartanCompress(ctx, o.PaygateURL, circuitID, pr)
	if err != nil {
		return err
	}
	return PostArtifact(ctx, o.IngestURL, o.IngestToken, scr, w)
}
