// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// jcs.go — a small in-tree JSON Canonicalization Scheme encoder
// (RFC 8785), used by the OpenShell containment check (openshell.go).
//
// The launcher writes each reef-ocsf/v1 record as `tag || JCS(record)`.
// konareef hashes the bytes it receives, and it also refuses a record
// whose bytes are not canonical (phase-2 design section 4.1, item 1;
// section 8.2, rule 9). The check decodes the bytes, encodes the value
// again with jcsMarshal, and compares the two byte strings.
//
// Functions:
//
//   - jcsCanonicalize: decode one JSON text and return its JCS bytes.
//   - jcsMarshal: the JCS bytes of a decoded Go value.
//   - jcsNumber: the ECMAScript form of one IEEE 754 double.
//
// Rules (RFC 8785 section 3.2): no white space; object members sorted
// by the UTF-16 code units of their names; strings with only the
// escapes \" \\ \b \f \n \r \t and \u00xx (lower-case hex) for the
// other C0 characters, every other character as UTF-8; numbers in the
// ECMAScript Number.prototype.toString form.
package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// jcsCanonicalize decodes one JSON text and returns its canonical form.
//
// Input: raw, one JSON text (white space and member order free).
// Output: the RFC 8785 bytes, or an error for text that is not exactly
// one JSON value, or that holds a number JCS cannot encode.
func jcsCanonicalize(raw []byte) ([]byte, error) {
	value, err := jcsDecode(raw)
	if err != nil {
		return nil, err
	}
	return jcsMarshal(value)
}

// jcsDecode decodes exactly one JSON value, with numbers kept as
// json.Number so that no precision is lost before jcsNumber.
//
// Input: raw JSON text. Output: the value, or an error for invalid
// JSON or for data after the value.
func jcsDecode(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON value")
	}
	return value, nil
}

// jcsMarshal returns the RFC 8785 bytes of a value.
//
// Input: value, made of map[string]any, []any, string, bool, nil,
// json.Number, float64 or the Go integer types.
// Output: the canonical bytes, or an error for another type or for a
// number that is not finite.
func jcsMarshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := jcsWrite(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jcsWrite appends the canonical form of value to buf.
func jcsWrite(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		jcsWriteString(buf, v)
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return fmt.Errorf("number %q: %w", string(v), err)
		}
		return jcsWriteFloat(buf, f)
	case float64:
		return jcsWriteFloat(buf, v)
	case int:
		return jcsWriteFloat(buf, float64(v))
	case int64:
		return jcsWriteFloat(buf, float64(v))
	case uint64:
		return jcsWriteFloat(buf, float64(v))
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(v))
		for name := range v {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return jcsLessUTF16(names[i], names[j]) })
		buf.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				buf.WriteByte(',')
			}
			jcsWriteString(buf, name)
			buf.WriteByte(':')
			if err := jcsWrite(buf, v[name]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", value)
	}
	return nil
}

// jcsWriteFloat appends the ECMAScript form of f.
func jcsWriteFloat(buf *bytes.Buffer, f float64) error {
	text, err := jcsNumber(f)
	if err != nil {
		return err
	}
	buf.WriteString(text)
	return nil
}

// jcsLessUTF16 orders two member names by their UTF-16 code units
// (RFC 8785 section 3.2.3).
func jcsLessUTF16(a, b string) bool {
	unitsA := utf16.Encode([]rune(a))
	unitsB := utf16.Encode([]rune(b))
	for i := 0; i < len(unitsA) && i < len(unitsB); i++ {
		if unitsA[i] != unitsB[i] {
			return unitsA[i] < unitsB[i]
		}
	}
	return len(unitsA) < len(unitsB)
}

// jcsWriteString appends a JSON string in the JCS escape form.
func jcsWriteString(buf *bytes.Buffer, text string) {
	buf.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// jcsNumber returns the ECMAScript Number.prototype.toString form of f
// (RFC 8785 section 3.2.2.3): the shortest digits that round-trip,
// fixed notation for exponents from -7 to 20, else "e+N" or "e-N".
//
// Input: f, a finite double. Output: the text, or an error for NaN or
// an infinity (JCS has no form for them).
func jcsNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs: number is not finite")
	}
	if f == 0 {
		return "0", nil // also -0
	}
	text := strconv.FormatFloat(f, 'e', -1, 64) // "-d.ddde+NN"
	negative := strings.HasPrefix(text, "-")
	text = strings.TrimPrefix(text, "-")
	mantissa, exponentText, _ := strings.Cut(text, "e")
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		return "", fmt.Errorf("jcs: exponent %q: %w", exponentText, err)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	n := exponent + 1

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if negative {
		out = "-" + out
	}
	return out, nil
}
