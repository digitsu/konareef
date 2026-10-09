// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// limits.go — the size and shape limits of the admission contract
// (docs/design/commission-admission-contract.md §5.6), applied at signing
// time.
//
// reef-core refuses a commission that is over one of these limits with
// commission_too_large (Q2, Q3), and one whose set holds an empty element
// with commission_invalid (Q5). The design (§5.6) asks the CLI to apply the
// same limits in `commission sign`, so a buyer can never sign a commission
// the server must refuse for its size. ValidateSignable calls
// ValidateAdmissionLimits, so `check`, `sign`, `verify`, `show` and the
// wire encoder all apply the same rule.

package commission

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/digitsu/konareef/internal/envelope"
)

// The limits of the admission contract §5.6. They are server rules, so a
// change here must follow a change to the contract and to reef-core.
const (
	// MaxWireBytes is the largest wire envelope the server decodes.
	MaxWireBytes = 32768
	// MaxProseBytes is the largest prose, in bytes.
	MaxProseBytes = 16384
	// MaxPodRefBytes is the largest pod_ref, in bytes.
	MaxPodRefBytes = 256
	// MaxElementBytes is the largest set element, in bytes.
	MaxElementBytes = 256
	// MaxModelElements is the most models a commission may list.
	MaxModelElements = 64
	// MaxToolElements is the most tools a commission may list.
	MaxToolElements = 256
	// MaxLabelElements is the most labels a commission may list.
	MaxLabelElements = 256
)

// ErrOverAdmissionLimit means a proposal is over a size limit of the
// admission contract. reef-core refuses it as commission_too_large.
var ErrOverAdmissionLimit = errors.New("proposal is over an admission contract limit")

// ErrEmptySetElement means a set dimension holds an empty string. reef-core
// refuses it as commission_invalid, and an empty name permits nothing.
var ErrEmptySetElement = errors.New("proposal set holds an empty element")

// ErrNotUTF8 means a text field is not valid UTF-8. reef-core refuses such
// canonical bytes as commission_malformed.
var ErrNotUTF8 = errors.New("proposal text is not valid UTF-8")

// ValidateAdmissionLimits reports whether p fits the admission contract's
// limits (§5.6).
//
// Input: a proposal. Output: nil, or an error that wraps
// ErrOverAdmissionLimit, ErrEmptySetElement or ErrNotUTF8 and names the
// field. The sets are counted after envelope.Normalise, because the
// canonical form (and so the server) sees the normalised set.
//
// The whole wire envelope must also be at most MaxWireBytes. Its exact size
// depends on the signature, so this check adds the largest envelope
// overhead (maxWireOverhead) to the canonical size; EncodeWireV1 checks the
// exact size again.
func ValidateAdmissionLimits(p Proposal) error {
	sets := []struct {
		name  string
		elems []string
		max   int
	}{
		{"models", envelope.Normalise(p.Envelope.Models), MaxModelElements},
		{"tools", envelope.Normalise(p.Envelope.Tools), MaxToolElements},
		{"labels", envelope.Normalise(p.Envelope.Labels), MaxLabelElements},
	}

	// Shape first: text that is not UTF-8 and empty elements are refused
	// before any size rule, so ErrOverAdmissionLimit is only ever reported
	// for a proposal whose shape is valid. `verify` and `show` rely on
	// that when they report an over-limit artifact as a warning.
	if !utf8.ValidString(p.Prose) {
		return fmt.Errorf("%w: prose", ErrNotUTF8)
	}
	if !utf8.ValidString(p.Binding.PodRef) {
		return fmt.Errorf("%w: pod_ref", ErrNotUTF8)
	}
	for _, set := range sets {
		for _, elem := range set.elems {
			switch {
			case elem == "":
				return fmt.Errorf("%w: %s", ErrEmptySetElement, set.name)
			case !utf8.ValidString(elem):
				return fmt.Errorf("%w: a %s element", ErrNotUTF8, set.name)
			}
		}
	}

	// Then size.
	if len(p.Prose) > MaxProseBytes {
		return fmt.Errorf("%w: prose is %d bytes, the limit is %d", ErrOverAdmissionLimit, len(p.Prose), MaxProseBytes)
	}
	if len(p.Binding.PodRef) > MaxPodRefBytes {
		return fmt.Errorf("%w: pod_ref is %d bytes, the limit is %d", ErrOverAdmissionLimit, len(p.Binding.PodRef), MaxPodRefBytes)
	}
	for _, set := range sets {
		if len(set.elems) > set.max {
			return fmt.Errorf("%w: %s has %d elements, the limit is %d", ErrOverAdmissionLimit, set.name, len(set.elems), set.max)
		}
		for _, elem := range set.elems {
			if len(elem) > MaxElementBytes {
				return fmt.Errorf("%w: a %s element is %d bytes, the limit is %d", ErrOverAdmissionLimit, set.name, len(elem), MaxElementBytes)
			}
		}
	}
	canonical, err := p.Canonical()
	if err != nil {
		return err
	}
	if len(canonical)+maxWireOverhead > MaxWireBytes {
		return fmt.Errorf("%w: the signed commission would be over %d bytes on the wire", ErrOverAdmissionLimit, MaxWireBytes)
	}
	return nil
}

// maxWireOverhead is the largest number of bytes the v1 wire envelope adds
// around the canonical bytes: the map head, four keys, the version, the
// three byte-string heads (at most 3 bytes each below 64 KiB), the 33-byte
// key and a signature of at most 72 bytes.
const maxWireOverhead = 1 + 4 + 1 + 3*3 + 33 + maxWireSigBytes
