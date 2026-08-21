// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// serialize.go — the deterministic byte emitter (rules R3–R14).
//
// Serialization is a total function on the AST: given an admissible
// tree it produces exactly one byte sequence. Every formatting choice
// the spec leaves to "one canonical form" is resolved here.
//
// Table headers are emitted in one global order: ascending over the
// UTF-8 byte encoding of each table's full dotted key path (R5). The
// emitter flattens the whole plain-table forest into that single sort
// rather than walking it depth-first — the two differ whenever a
// sibling key sorts between a parent and the parent's children (`-`,
// 0x2D, sorts before the `.`, 0x2E, that joins a child path), and the
// global sort is the canonical one.
//
// Array-of-tables are the exception: their entries are positional, and
// a table nested inside an entry stays contiguous with that entry. Each
// entry is therefore its own emission scope with its own local sort.
//
// Within any table, scalar (and array) fields are emitted before any
// sub-table header: TOML attaches every `key = value` line after a
// `[header]` to that header, so scalars must precede the first
// sub-table. A parent's dotted path is always a proper prefix of its
// children's, so the global sort always emits a parent header before
// the children that depend on it.
package canon

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"
)

// serializeTree renders root as canonical TOML body bytes. The
// `#!konareef-toml/v1` magic line and the `[_files]` section are added
// by the caller (canon.go); this function emits only the author tree.
func serializeTree(root *table) []byte {
	var buf bytes.Buffer
	emitScope(&buf, nil, root)
	return buf.Bytes()
}

// section pairs a table-or-array-of-tables value with its full dotted
// key path — the key the global R5 ordering sorts on.
type section struct {
	path []string
	val  *value
}

// emitScope renders one emission scope: the document root, or a single
// array-of-tables entry. It writes base's own scalar fields, then every
// section within the scope — plain sub-tables flattened across depth,
// array-of-tables as indivisible units — in one ascending sort over the
// dotted key path (R5).
//
// basePath is the dotted path of base: nil for the document root, the
// `[[path]]` path for an array-of-tables entry. Recursing into a plain
// sub-table keeps its descendants in this scope's sort; an
// array-of-tables entry opens a fresh scope, so a table nested inside an
// entry stays contiguous with that entry rather than floating into the
// outer sort.
func emitScope(buf *bytes.Buffer, basePath []string, base *table) {
	emitScalars(buf, base.fields)

	var sections []section
	collectSections(basePath, base, &sections)
	sort.Slice(sections, func(i, j int) bool {
		return strings.Join(sections[i].path, ".") < strings.Join(sections[j].path, ".")
	})

	for _, s := range sections {
		joined := strings.Join(s.path, ".")
		switch s.val.kind {
		case kindTable:
			buf.WriteByte('[')
			buf.WriteString(joined)
			buf.WriteString("]\n")
			emitScalars(buf, s.val.tbl.fields)
		case kindArrayTable:
			// R13: one [[path]] header per entry, entries in source
			// (positional) order — never sorted.
			for _, entry := range s.val.aot {
				buf.WriteString("[[")
				buf.WriteString(joined)
				buf.WriteString("]]\n")
				emitScope(buf, s.path, entry)
			}
		}
	}
}

// collectSections gathers every section reachable within one scope.
// Plain sub-tables are recursed into so their descendants join this
// scope's global sort; array-of-tables are appended as indivisible
// units and not descended — each entry forms its own scope via
// emitScope.
func collectSections(basePath []string, t *table, out *[]section) {
	for _, f := range t.fields {
		switch f.val.kind {
		case kindTable:
			p := childPath(basePath, f.key)
			*out = append(*out, section{path: p, val: f.val})
			collectSections(p, f.val.tbl, out)
		case kindArrayTable:
			*out = append(*out, section{path: childPath(basePath, f.key), val: f.val})
		}
	}
}

// emitScalars writes the scalar and array fields of fields as sorted
// `key = value` lines (R5 key order). Table and array-of-tables fields
// are skipped — emitScope renders those as `[header]` blocks.
func emitScalars(buf *bytes.Buffer, fields []field) {
	scalars, _ := partitionFields(fields)
	sort.Slice(scalars, func(i, j int) bool { return scalars[i].key < scalars[j].key })
	for _, f := range scalars {
		buf.WriteString(f.key)
		buf.WriteString(" = ")
		buf.WriteString(serializeScalar(f.val))
		buf.WriteByte('\n')
	}
}

// partitionFields splits a table's fields into scalar/array fields
// (emitted as `key = value` lines) and section fields (tables and
// array-of-tables, emitted as `[header]` blocks).
func partitionFields(fields []field) (scalars, sections []field) {
	for _, f := range fields {
		switch f.val.kind {
		case kindTable, kindArrayTable:
			sections = append(sections, f)
		default:
			scalars = append(scalars, f)
		}
	}
	return scalars, sections
}

// serializeScalar renders a non-section value: string, integer, float,
// bool, datetime, or array.
func serializeScalar(v *value) string {
	switch v.kind {
	case kindString:
		return serializeString(v.str)
	case kindInt:
		return strconv.FormatInt(v.i, 10)
	case kindFloat:
		return serializeFloat(v.f)
	case kindBool:
		if v.b {
			return "true"
		}
		return "false"
	case kindDatetime:
		return serializeDatetime(v.dt)
	case kindArray:
		return serializeArray(v.arr)
	default:
		// Unreachable: section kinds never reach serializeScalar.
		return ""
	}
}

// serializeString renders s as an R6 canonical basic string: a
// double-quoted, pure-ASCII string. Printable ASCII passes through;
// `"` and `\` are backslash-escaped; newline and tab use their short
// escapes; every other codepoint — ASCII control characters and all
// non-ASCII — becomes one of TOML v1.0's two unicode escapes:
// `\uXXXX` (lowercase hex, exactly 4 digits) for codepoints in the
// Basic Multilingual Plane, and `\UXXXXXXXX` (lowercase hex, exactly
// 8 digits) for astral-plane codepoints. The braced `\u{...}` form
// is *not* in TOML v1.0 — using it would break R6's promise that the
// output re-parses under any conforming parser.
func serializeString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r >= 0x20 && r <= 0x7E {
				b.WriteRune(r)
			} else if r <= 0xFFFF {
				b.WriteString(`\u`)
				b.WriteString(hexPad(r, 4))
			} else {
				b.WriteString(`\U`)
				b.WriteString(hexPad(r, 8))
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// hexPad renders a codepoint as lowercase hex, zero-padded to exactly
// width digits. Used for TOML v1.0 `\uXXXX` (width 4) and `\UXXXXXXXX`
// (width 8) escapes.
func hexPad(r rune, width int) string {
	h := strconv.FormatInt(int64(r), 16)
	for len(h) < width {
		h = "0" + h
	}
	return h
}

// serializeFloat renders x per R8: shortest round-trip decimal
// notation, never exponent form, always with a decimal point and at
// least one fractional digit, with negative zero normalized to "0.0".
//
// strconv.FormatFloat(x, 'f', -1, 64) gives the shortest round-trip
// value (Ryu) in plain decimal, but drops the fractional part for
// integer-valued floats ("100", not "100.0"), so a ".0" suffix is
// appended when no decimal point is present.
func serializeFloat(x float64) string {
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

// serializeDatetime renders t per R10: RFC 3339, UTC, with a literal
// trailing `Z` and exactly six fractional-second digits. The value has
// already passed validateDatetime, so it is known to be UTC; the
// explicit .UTC() is a defensive normalization.
func serializeDatetime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000") + "Z"
}

// serializeArray renders an array per R12:
//
//   - empty            → []
//   - single element   → [element]
//   - two or more      → bracket and `]` each on their own line, one
//     element per line, a comma after every element except the last,
//     no indentation.
//
// Nested arrays recurse through serializeScalar; konareef pods use
// flat scalar arrays, so a multi-line nested array — which would let
// a single "element" span lines — does not arise in practice.
func serializeArray(elems []*value) string {
	switch len(elems) {
	case 0:
		return "[]"
	case 1:
		return "[" + serializeScalar(elems[0]) + "]"
	default:
		var b strings.Builder
		b.WriteString("[\n")
		for i, e := range elems {
			b.WriteString(serializeScalar(e))
			if i < len(elems)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteByte(']')
		return b.String()
	}
}
