// ast.go — the internal canonicalization AST and its builder.
//
// The canonicalizer is deliberately schema-agnostic (spec §8: "it
// doesn't care about semantic meaning, just structure"). It therefore
// works on a generic tree mirroring arbitrary TOML structure, NOT on
// the typed pod.Spec — it must, for example, reject hand-authored
// `_`-prefixed keys that no typed struct would even surface.
//
// The tree is built from BurntSushi/toml's decode into a generic
// map. That decode is faithful enough for canonicalization because:
//
//   - integers arrive as int64, floats as float64, datetimes as
//     time.Time — type identity is preserved;
//   - inline tables and `[table]` headers both decode to a map, which
//     is exactly what R11 wants (inline tables are expanded to tables);
//   - array-of-tables (`[[x]]`) decodes to []map[string]interface{},
//     while every other array — including an array of inline-table
//     literals — decodes to []interface{}. That type split is the
//     sole, reliable signal distinguishing R13 array-of-tables from
//     the R-less array-of-inline-tables construct v1 rejects.
package canon

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// valueKind tags which arm of a value is populated.
type valueKind int

const (
	kindString valueKind = iota
	kindInt
	kindFloat
	kindBool
	kindDatetime
	kindArray      // a regular TOML array (R12)
	kindTable      // a table or expanded inline table (R11)
	kindArrayTable // an array-of-tables, `[[x]]` (R13)
)

// value is one node in the canonicalization AST. Exactly one arm is
// meaningful, selected by kind.
type value struct {
	kind valueKind

	str string    // kindString
	i   int64     // kindInt
	f   float64   // kindFloat
	b   bool      // kindBool
	dt  time.Time // kindDatetime
	arr []*value  // kindArray
	tbl *table    // kindTable
	aot []*table  // kindArrayTable — entries in source (positional) order
}

// field is one key/value pair within a table. Insertion order is
// whatever the decoder produced; R5 ordering is applied at serialize
// time, never here, so the AST stays a faithful structural mirror.
type field struct {
	key string
	val *value
}

// table is a TOML table: an ordered list of fields. Order is not
// canonical (R5 sorts at serialize time) but is retained so the AST
// round-trips losslessly for debugging.
type table struct {
	fields []field
}

// buildTree converts a decoded TOML map into the canonicalization AST.
// path is the dotted key path to m, used only for error messages.
//
// Map keys are iterated in sorted byte order so that downstream
// validation walks every node in deterministic sorted-key pre-order
// DFS. That makes the error code returned for an input with multiple
// independent violations the same across implementations: the spec's
// "first violation in sorted-key DFS order" precedence rule (§4).
func buildTree(m map[string]interface{}, path []string) (*table, error) {
	t := &table{}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		child, err := buildValue(m[key], childPath(path, key))
		if err != nil {
			return nil, err
		}
		t.fields = append(t.fields, field{key: key, val: child})
	}
	return t, nil
}

// buildValue converts one decoded TOML value into an AST node.
func buildValue(raw interface{}, path []string) (*value, error) {
	switch x := raw.(type) {
	case string:
		return &value{kind: kindString, str: x}, nil
	case int64:
		return &value{kind: kindInt, i: x}, nil
	case int:
		// Some BurntSushi decode paths yield a plain int; widen it.
		return &value{kind: kindInt, i: int64(x)}, nil
	case float64:
		return &value{kind: kindFloat, f: x}, nil
	case bool:
		return &value{kind: kindBool, b: x}, nil
	case time.Time:
		return &value{kind: kindDatetime, dt: x}, nil

	case map[string]interface{}:
		// A `[table]` header or an inline table — R11 expands both.
		tbl, err := buildTree(x, path)
		if err != nil {
			return nil, err
		}
		return &value{kind: kindTable, tbl: tbl}, nil

	case []map[string]interface{}:
		// Array-of-tables, `[[x]]` (R13). Only AoT decodes to this Go
		// type; element order is positional and preserved.
		aot := make([]*table, 0, len(x))
		for _, entry := range x {
			tbl, err := buildTree(entry, path)
			if err != nil {
				return nil, err
			}
			aot = append(aot, tbl)
		}
		return &value{kind: kindArrayTable, aot: aot}, nil

	case []interface{}:
		// A regular array (R12). An element that is itself a table
		// means the source was an array of inline-table literals —
		// rejected per spec §11 (no canonical form is defined).
		arr := make([]*value, 0, len(x))
		for _, elem := range x {
			if _, isTable := elem.(map[string]interface{}); isTable {
				return nil, newErr(ErrArrayOfInlineTables,
					fmt.Sprintf("key %q is an array of inline tables", strings.Join(path, ".")))
			}
			ev, err := buildValue(elem, path)
			if err != nil {
				return nil, err
			}
			arr = append(arr, ev)
		}
		return &value{kind: kindArray, arr: arr}, nil

	default:
		return nil, newErr(ErrTOMLParseError,
			fmt.Sprintf("unsupported value type %T at key %q", raw, strings.Join(path, ".")))
	}
}

// childPath returns a fresh slice extending parent with key. A fresh
// slice is required: reusing append(parent, key) would alias the
// backing array across sibling recursions and corrupt error messages.
func childPath(parent []string, key string) []string {
	out := make([]string, len(parent)+1)
	copy(out, parent)
	out[len(parent)] = key
	return out
}
