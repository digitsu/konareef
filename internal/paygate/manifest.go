// internal/paygate/manifest.go — discovery manifest (PRD 2 § 3.4).
package paygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Manifest mirrors PRD 2 § 3.4. Unknown fields are preserved as raw
// JSON in RawExtra so a future PRD 2 field bump does not require a
// client recompile to ignore.
type Manifest struct {
	Service                string             `json:"service"`
	Version                string             `json:"version"`
	Operations             []string           `json:"operations"`
	Circuits               map[string]Circuit `json:"circuits"`
	MarginMultiplier       int                `json:"margin_multiplier"`
	ScheduleRevision       int                `json:"schedule_revision"`
	ScheduleEffectiveAfter *time.Time         `json:"schedule_effective_after"`
	Signature              map[string]string  `json:"signature"`
}

// Circuit is the per-circuit block from PRD 2 § 3.4.
type Circuit struct {
	VkeySha256      string                 `json:"vkey_sha256"`
	VkeyURL         string                 `json:"vkey_url"`
	Pricing         map[string]Schedule    `json:"pricing"`
	InputCaps       map[string]interface{} `json:"input_caps"`
	DeprecatedAfter *time.Time             `json:"deprecated_after"`
}

// Schedule is one (compute_usd, retail_usd) pricing row.
type Schedule struct {
	ComputeUSD     float64 `json:"compute_usd"`
	RetailUSD      float64 `json:"retail_usd"`
	AvailableAfter string  `json:"available_after,omitempty"`
}

// ParseManifest parses the JSON body of GET /v1/.well-known/x402-info.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("paygate: parse manifest: %w", err)
	}
	if m.Service != "paygate-zk" {
		return nil, fmt.Errorf("paygate: manifest.service = %q, want paygate-zk", m.Service)
	}
	return &m, nil
}

// IsScheduleStale returns true when ScheduleEffectiveAfter is non-nil
// and now >= ScheduleEffectiveAfter; PRD 2 § 5.3 calls this the
// transition-in-progress condition and PRD P1.8 Obligation 3 makes
// BEEFs built after this point non-refundable.
func (m *Manifest) IsScheduleStale(now time.Time) bool {
	if m.ScheduleEffectiveAfter == nil {
		return false
	}
	return !now.Before(*m.ScheduleEffectiveAfter)
}

// ActiveSchedule returns the pricing row for (circuitID, op). Returns
// an error if either lookup fails.
func (m *Manifest) ActiveSchedule(circuitID, op string) (Schedule, error) {
	c, ok := m.Circuits[circuitID]
	if !ok {
		return Schedule{}, errors.New("paygate: circuit not advertised in manifest")
	}
	s, ok := c.Pricing[op]
	if !ok {
		return Schedule{}, errors.New("paygate: op not priced for circuit")
	}
	return s, nil
}
