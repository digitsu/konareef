// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"fmt"
)

// ErrDimensionAbsent is returned when a commission omits a dimension.
//
// An omitted dimension is refused rather than defaulted. Treating an
// omission as unconstrained is fail-open: a commission that forgot to
// mention tools would authorise every tool. Treating it as empty is
// fail-closed but useless, since no manifest could satisfy it. Refusal is
// the only option consistent with the principle main_confirm_gate.go states
// for this codebase: a caller that cannot answer does not get a default yes.
var ErrDimensionAbsent = errors.New("commission omits a constraint dimension")

// ValidateAsCommission returns ErrDimensionAbsent if any dimension was
// omitted rather than stated, naming the dimension in the wrapped message.
//
// The test is the presence FLAG alone. The dimension's value plays no part,
// because the value is not evidence that anyone stated the dimension: values
// and presence come from different sources in every decoder here
// (main.unmarshalProposal reads values from the decoded struct and presence
// from toml metadata; rar.Parse reads presence from JSON key presence), so a
// slice can carry contents its file never declared.
//
// This is deliberately stricter than the condition it replaces,
// `len(e.Models) == 0 && !e.ModelsSet`, which refused only when a dimension
// was BOTH empty AND unstated — i.e. it let an unstated dimension through
// whenever some value happened to survive decoding, exactly the fail-open
// the flags exist to prevent. See
// TestValidateAsCommission_RejectsUnstatedDimensionCarryingAValue, which
// fails against that conjunction and is the reason this is one condition.
func (e Envelope) ValidateAsCommission() error {
	if !e.ModelsSet {
		return fmt.Errorf("%w: models", ErrDimensionAbsent)
	}
	if !e.ToolsSet {
		return fmt.Errorf("%w: tools", ErrDimensionAbsent)
	}
	if !e.LabelsSet {
		return fmt.Errorf("%w: labels", ErrDimensionAbsent)
	}
	if !e.CMaxSet {
		return fmt.Errorf("%w: c_max_sats", ErrDimensionAbsent)
	}
	return nil
}
