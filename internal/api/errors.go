// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// errors.go — decoding and rendering of reef-core error bodies.
//
// reef-core sends two error shapes. Older endpoints send
// {"error": "<text>"}. The spawn endpoints send a structured map,
// {"error": {"kind": "<stable code>", "message": "<text>", ...}}, with
// extra fields per kind. decodeErrorBody turns either shape into a Go
// error. A structured body becomes a *ServerError, so a caller can use
// errors.As and switch on Kind instead of parsing English text.
//
// Every string in a body came from the server, and some came from a pod
// manifest. Error() escapes control characters before any of it reaches
// a terminal.

package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// KindCommissionNotContained is reef-core's code for a signed commission
// whose pod declares more than the commission permits (admission contract
// §18). Its body also carries failed_dimensions and details.
const KindCommissionNotContained = "commission_not_contained"

// KindMCPGrantHostAlsoDeclaredEgress is reef-core's stable code for a spawn
// refused because a brokered MCP grant host is also reachable through
// [network].egress. The local `konareef pod validate` code for the same
// rule is GATEWAY_MCP_HOST_ALSO_EGRESS.
const KindMCPGrantHostAlsoDeclaredEgress = "mcp_grant_host_also_declared_egress"

// KindZKRequestRefused is reef-core's 422 for a `zk_requested: true`
// spawn the run cannot serve (ZK-002). ServerError.Reason carries the
// refusal code, for example "zk_not_enabled" or "closed_pod".
const KindZKRequestRefused = "zk_request_refused"

// KindInvalidZKRequested is reef-core's 422 for a `zk_requested` value
// that is not a JSON boolean (ZK-002).
const KindInvalidZKRequested = "invalid_zk_requested"

// KindPodRefAmbiguous is reef-core's 422 for a Mode C pod_ref whose
// pod_hash still matches more than one live published-pod row after
// resolve_for_spawn narrows by every field the ref carries (reef-core
// !254, owner decision F2). `konareef pod run` already sends
// handle/pod/version alongside pod_hash (buildSpawnRequest), so this
// means the collision survives naming the publisher — a publishing-side
// state the client cannot resolve by retrying.
const KindPodRefAmbiguous = "pod_ref_ambiguous"

// EgressConflict is one entry of the `conflicts` list in a
// mcp_grant_host_also_declared_egress body: a brokered grant and one
// [network].egress entry that covers its authority. The wire shape is
// documented in internal/pod/testdata/mcp_egress_conflicts/README.md.
type EgressConflict struct {
	// Grant is the grant's host, as authored.
	Grant string `json:"grant"`
	// GrantIndex is the 0-based index into [[network.gateway]], counting
	// every entry, as in the network.gateway[N] path.
	GrantIndex int `json:"grant_index"`
	// Authority is the grant's canonical "host:port". An IPv6 host keeps
	// its brackets.
	Authority string `json:"authority"`
	// Egress is the matching [network].egress entry, as authored. For a
	// wildcard match it is the wildcard.
	Egress string `json:"egress"`
	// EgressIndex is the 0-based index into [network].egress.
	EgressIndex int `json:"egress_index"`
}

// ServerError is a structured reef-core error body plus the HTTP status.
//
// Kind is the stable code. Message is human text; do not parse it. Hosts,
// Conflicts and ConflictsTruncated are set only for
// KindMCPGrantHostAlsoDeclaredEgress. Conflicts is nil when the server
// did not send the field: a reef-core from before MR !108 sends Hosts
// only, and Error() then falls back to naming the hosts.
// Reason is the sub-code some kinds carry (for example the refusal code
// of KindZKRequestRefused); it is empty for every other kind.
// FailedDimensions and Details are set only for
// KindCommissionNotContained: the failing dimensions (models, tools,
// spend, spend_total) and, per dimension, the values that did not fit.
type ServerError struct {
	Status             int                        `json:"-"`
	Kind               string                     `json:"kind"`
	Message            string                     `json:"message"`
	Reason             string                     `json:"reason"`
	Hosts              []string                   `json:"hosts"`
	Conflicts          []EgressConflict           `json:"conflicts"`
	ConflictsTruncated bool                       `json:"conflicts_truncated"`
	FailedDimensions   []string                   `json:"failed_dimensions"`
	Details            map[string]json.RawMessage `json:"details"`
}

// Error renders the error for a terminal. Input is the decoded body; output
// starts with "http <status>: <kind>". For KindMCPGrantHostAlsoDeclaredEgress
// it lists one line per conflict, naming both the grant entry and the
// matching egress entry. Any other kind is followed by the server message.
func (e *ServerError) Error() string {
	head := fmt.Sprintf("http %d: %s", e.Status, terminalSafe(e.Kind))
	if e.Kind == KindMCPGrantHostAlsoDeclaredEgress {
		return head + ": " + e.mcpEgressConflictText()
	}
	if e.Kind == KindCommissionNotContained && len(e.FailedDimensions) > 0 {
		return head + ": " + e.notContainedText()
	}
	if e.Message == "" {
		return head
	}
	return head + ": " + terminalSafe(e.Message)
}

// mcpEgressConflictText builds the body of the
// KindMCPGrantHostAlsoDeclaredEgress message from the structured fields
// only; it never reuses the server's English message. Authored strings are
// quoted with %q, which escapes control characters.
func (e *ServerError) mcpEgressConflictText() string {
	var text strings.Builder
	if len(e.Conflicts) == 0 {
		quoted := make([]string, 0, len(e.Hosts))
		for _, host := range e.Hosts {
			quoted = append(quoted, strconv.Quote(host))
		}
		fmt.Fprintf(&text, "brokered MCP grant hosts %s are also reachable through [network].egress; "+
			"a brokered host is reached only through the broker, so the manifest must remove or narrow "+
			"the egress entries that cover them (this reef-core does not name the entries; "+
			"run `konareef pod validate` on the pod.toml to list them)", strings.Join(quoted, ", "))
		return text.String()
	}
	text.WriteString("each brokered MCP grant below is also reachable through [network].egress; " +
		"a brokered host is reached only through the broker, so the manifest must remove or narrow " +
		"each listed egress entry")
	for _, conflict := range e.Conflicts {
		fmt.Fprintf(&text, "\n  network.gateway[%d].host %q (%s) matches network.egress[%d] %q",
			conflict.GrantIndex, conflict.Grant, terminalSafe(conflict.Authority),
			conflict.EgressIndex, conflict.Egress)
	}
	if e.ConflictsTruncated {
		text.WriteString("\n  (the server truncated this list; run `konareef pod validate` on the pod.toml to list every pair)")
	}
	return text.String()
}

// notContainedText lists each failing dimension of a
// KindCommissionNotContained refusal with the server's detail for it,
// rendered as compact JSON. The values come from the buyer's own
// commission and the public manifest head (contract §13).
func (e *ServerError) notContainedText() string {
	var text strings.Builder
	text.WriteString("the pod's declared envelope is not inside the signed commission")
	for _, dimension := range e.FailedDimensions {
		detail := string(e.Details[dimension])
		if detail == "" {
			detail = "(no detail)"
		}
		fmt.Fprintf(&text, "\n  %s: %s", terminalSafe(dimension), terminalSafe(detail))
	}
	return text.String()
}

// TerminalSafe is terminalSafe for callers outside this package that print
// server or manifest text: it escapes every non-printable rune.
func TerminalSafe(s string) string { return terminalSafe(s) }

// TerminalSafeJSON returns JSON text with every non-printable rune except
// the newline replaced by its \uXXXX escape (a surrogate pair above
// U+FFFF). The result decodes to the same value, and printing it cannot
// move the cursor or recolour the terminal: encoding/json escapes only the
// controls below U+0020, not DEL or the C1 controls such as U+009B (CSI).
//
// Input: JSON text from json.Marshal or json.MarshalIndent with spaces for
// indentation. Any other non-printable rune outside a string (a tab, a CR)
// would be escaped too and make the JSON invalid, so callers must not pass
// other JSON text. Output: the escaped JSON text.
func TerminalSafeJSON(data []byte) []byte {
	var out strings.Builder
	for _, r := range string(data) {
		if r == '\n' || unicode.IsPrint(r) {
			out.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
			continue
		}
		fmt.Fprintf(&out, "\\u%04x", r)
	}
	return []byte(out.String())
}

// terminalSafe returns s unchanged when every rune is printable, and
// otherwise returns it with Go escapes (such as \x1b) in place of the
// non-printable runes, so server text cannot move the cursor or recolor
// the terminal.
func terminalSafe(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
}

// decodeErrorBody turns a 4xx/5xx response into an error. Input is the
// HTTP status and the raw body. Output is "http <status>: <text>" for a
// string-shaped error, a *ServerError for a structured error with a kind,
// and "http <status>" when the body has neither shape. A detail field of
// an unexpected type is left at its zero value; the kind is kept.
func decodeErrorBody(status int, body []byte) error {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Error) == 0 {
		return fmt.Errorf("http %d", status)
	}
	var text string
	if err := json.Unmarshal(envelope.Error, &text); err == nil {
		if text == "" {
			return fmt.Errorf("http %d", status)
		}
		return fmt.Errorf("http %d: %s", status, terminalSafe(text))
	}
	// Each field is decoded on its own, so a detail field of an
	// unexpected type drops only that field and never hides the kind.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Error, &fields); err != nil {
		return fmt.Errorf("http %d", status)
	}
	var serverErr ServerError
	json.Unmarshal(fields["kind"], &serverErr.Kind)
	json.Unmarshal(fields["message"], &serverErr.Message)
	json.Unmarshal(fields["reason"], &serverErr.Reason)
	if json.Unmarshal(fields["hosts"], &serverErr.Hosts) != nil {
		serverErr.Hosts = nil
	}
	json.Unmarshal(fields["conflicts_truncated"], &serverErr.ConflictsTruncated)
	if json.Unmarshal(fields["conflicts"], &serverErr.Conflicts) != nil {
		serverErr.Conflicts = nil
	}
	if json.Unmarshal(fields["failed_dimensions"], &serverErr.FailedDimensions) != nil {
		serverErr.FailedDimensions = nil
	}
	if json.Unmarshal(fields["details"], &serverErr.Details) != nil {
		serverErr.Details = nil
	}
	if serverErr.Kind == "" {
		return fmt.Errorf("http %d", status)
	}
	serverErr.Status = status
	return &serverErr
}
