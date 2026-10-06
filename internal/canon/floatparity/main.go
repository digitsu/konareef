// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Command floatparity generates a deterministic sweep of IEEE-754
// doubles in the konareef-toml/v1 R8 range [0.0, 1.0e6], formats each
// through the Go canonical float rule, and emits the set as JSON for
// cross-implementation comparison against Erlang.
//
// This harness checks the canonical TOML float formatting contract:
// confirm whether Go's strconv.FormatFloat and Erlang's
// :erlang.float_to_binary/2 [short] agree byte-for-byte across the
// allowed float range. A clean run lets the canonicalizer spec be
// locked; a divergence forces an explicit float-to-string algorithm.
//
// Pipeline:
//
//	go run ./internal/canon/floatparity > samples.json
//	escript internal/canon/floatparity/parity.erl samples.json
//
// Exit 0 from the Erlang script = full parity. Exit 1 = at least one
// divergence, printed with the exact IEEE-754 bit pattern that caused
// it so the failing value can be reproduced bit-identically.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

// sweepSeed fixes the PRNG so a divergence found in one run reproduces
// exactly in the next — essential when chasing a single failing value.
const sweepSeed = 0x6b6f6e61 // "kona"

// sampleCount is the size of the sweep the spec calls for.
const sampleCount = 10000

// floatMax is the inclusive upper bound of the R8 allowed float range.
const floatMax = 1.0e6

// sample is one entry in the sweep: the exact double, transported as
// its raw IEEE-754 bits (hex-encoded) so the Erlang side reconstructs
// it bit-identically rather than re-parsing a lossy decimal string,
// paired with the Go canonical-form string.
type sample struct {
	// Bits is the 16-char big-endian hex of math.Float64bits(value).
	Bits string `json:"bits"`
	// Go is canonicalFloat(value) — what the konareef canonical TOML
	// serializer emits for this value per rule R8.
	Go string `json:"go"`
}

// sweep is the top-level JSON document written to stdout.
type sweep struct {
	Spec    string   `json:"spec"`
	Count   int      `json:"count"`
	Samples []sample `json:"samples"`
}

// canonicalFloat formats x exactly as konareef-toml/v1 rule R8 requires:
// shortest round-trip decimal notation (Ryu, via strconv), never
// exponent form, always with a decimal point and at least one
// fractional digit, with negative zero normalized to "0.0".
//
// strconv.FormatFloat(x, 'f', -1, 64) yields shortest-round-trip
// decimal but drops the fractional part for integer-valued floats
// ("100", not "100.0"), so a ".0" suffix is appended when no decimal
// point is present.
func canonicalFloat(x float64) string {
	if x == 0 {
		// Collapses both +0.0 and -0.0 to the canonical "0.0".
		x = 0
	}
	s := strconv.FormatFloat(x, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// bitsHex returns the 16-character big-endian hex encoding of x's raw
// IEEE-754 representation — the transport form that survives the JSON
// round-trip and the Erlang side with zero precision loss.
func bitsHex(x float64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], math.Float64bits(x))
	return hex.EncodeToString(buf[:])
}

// generateSamples returns the sweep population: exactly sampleCount
// doubles, every one within [0.0, floatMax].
//
// A purely uniform random draw is a weak test — it almost never lands
// on the values where shortest round-trip formatters disagree. So the
// population is bucketed: a deterministic set of edge cases (range
// boundaries and their nearest neighbours, every in-range power of two
// and power of ten, and familiar fractions whose decimal form is not
// exact in binary), then the remaining budget split across uniform
// random, exact integers, sub-unit fractions, and long-mantissa values
// scattered by magnitude. The PRNG is seeded from sweepSeed so the
// whole population is reproducible run to run.
func generateSamples() []float64 {
	rng := rand.New(rand.NewSource(sweepSeed))
	samples := make([]float64, 0, sampleCount)

	// Bucket 1 — deterministic edge cases.
	samples = append(samples,
		0.0,
		floatMax,
		math.Ldexp(1.0, -1022),        // smallest positive normal double (subnormals are R8-rejected)
		math.Nextafter(floatMax, 0.0), // largest in-range value below the cap
	)
	for e := -40; e <= 19; e++ { // every power of two within range
		if v := math.Ldexp(1.0, e); v >= 0.0 && v <= floatMax {
			samples = append(samples, v)
		}
	}
	for e := -10; e <= 6; e++ { // every power of ten within range
		if v := math.Pow(10, float64(e)); v >= 0.0 && v <= floatMax {
			samples = append(samples, v)
		}
	}
	samples = append(samples, // fractions inexact in binary
		0.1, 0.2, 0.3, 0.15, 0.25, 0.125, 1.0/3.0, 2.0/3.0)

	// Buckets 2-5 — random fill of the remaining budget.
	remaining := sampleCount - len(samples)
	uniformN := remaining * 60 / 100
	integerN := remaining * 15 / 100
	fractionN := remaining * 15 / 100
	longMantissaN := remaining - uniformN - integerN - fractionN

	for i := 0; i < uniformN; i++ { // uniform across the whole range
		samples = append(samples, rng.Float64()*floatMax)
	}
	for i := 0; i < integerN; i++ { // exact integer-valued floats
		samples = append(samples, float64(rng.Intn(int(floatMax)+1)))
	}
	for i := 0; i < fractionN; i++ { // sub-unit fractions
		samples = append(samples, rng.Float64())
	}
	for i := 0; i < longMantissaN; i++ {
		// Random magnitude in [1e-3, 1e6) times a full-mantissa
		// fraction — exercises 15-17 significant-digit values across
		// the whole exponent range, where formatters most often
		// disagree. Clamped defensively against floating-point fuzz.
		scale := math.Pow(10, rng.Float64()*9-3)
		samples = append(samples, math.Min(rng.Float64()*scale, floatMax))
	}

	return samples
}

func main() {
	values := generateSamples()
	if len(values) == 0 {
		fmt.Fprintln(os.Stderr,
			"floatparity: generateSamples() returned no samples — implement it (see TODO in main.go)")
		os.Exit(1)
	}

	doc := sweep{
		Spec:    "konareef-toml/v1 R8 float-parity sweep",
		Count:   len(values),
		Samples: make([]sample, 0, len(values)),
	}
	for _, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0.0 || v > floatMax {
			fmt.Fprintf(os.Stderr,
				"floatparity: sample %v is outside the R8 range [0.0, %g]\n", v, floatMax)
			os.Exit(1)
		}
		doc.Samples = append(doc.Samples, sample{
			Bits: bitsHex(v),
			Go:   canonicalFloat(v),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "floatparity: encoding samples: %v\n", err)
		os.Exit(1)
	}
}
