// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell_crosscheck.go — the cross-check of the tool log against the
// reef-ocsf/v1 records (reef-core OpenShell adapter, phase 2, design
// section 9; story US-112; X2t: phase-3 design section 6.6, story US-206).
//
// The cross-check runs only for a full-form custody record with the
// `openshell_evidence` key, after hard-failure rule 12 has checked the
// tool-log records against TOOL_LOG_ROOT. Its rules:
//
//   - X1: every `NET:OPEN ... ALLOWED` and `HTTP:* ... ALLOWED`
//     destination is an endpoint of `policy_yaml`;
//   - X2: the number of tool-log records whose tool hash is an Open Brain
//     tool-log id is at most the number of `HTTP:POST ... ALLOWED` records
//     to `http://<listener>:<run_port>/mcp/open_brain`. X2 runs only on
//     complete evidence (design 8.3). When the reef_run_listener policy
//     has the W20 mcp endpoint, X2t (below) runs in place of X2;
//   - X3: no `NET:OPEN ... ALLOWED` record names a binary other than the
//     `reef_run_listener` binary of `policy_yaml`;
//   - X4: the listener lines seen in the records are at most the served
//     requests (OPENSHELL_LISTENER_REQUESTS).
//
// The outcome is never a hard failure. "inconsistent" and "not_checked
// (redacted)" cap the grade at claimed. The outcome is chosen in this
// order (the first that applies):
//
//  1. inconsistent: a rule that ran failed (one row per failed rule);
//  2. not_checked (redacted): a leaf is withheld, so X2 and X4 cannot run;
//  3. not_checked (incomplete): the evidence is not complete, so X2 did
//     not run (X1, X3 and X4 ran and held);
//  4. not_checked (no_tool_log): the tool log is empty;
//  5. consistent.
//
// Choices the design text does not fix word for word:
//
//   - A record counts as ALLOWED when its msg starts with "ALLOWED ".
//   - X1 also checks a bare NET:OPEN "<host>:<port>" (no verdict) to an
//     address that is not loopback: it must be a policy endpoint
//     (coordinator decision 2026-10-09). A bare loopback destination
//     (127.0.0.0/8, ::1) is not checked.
//   - A destination is "<host>:<port>"; a policy endpoint matches when the
//     two strings are equal, byte for byte (no case folding, no Unicode
//     normalization, no wildcard hosts). reef-core compares the listener
//     authority in the same way (ReefCore.Proofs.OpenShellEvidence,
//     listener_seen/2).
//   - An ALLOWED record whose destination or binary cannot be read fails
//     X1 or X3, with the row item "seq <n>: no destination" or "seq <n>:
//     no binary" (fail closed).
//   - The X4 row keeps the text that design 8.3 quotes, after "X4: ".
//   - X2 counts only the built-in Open Brain tools. A brokered tool also
//     goes through /mcp/open_brain, but its name is not fixed, so X2 can
//     miss a fault but never reports a false one.
//
// X2t (phase-3 design 6.6) counts per tool. The candidate set C holds two
// kinds of name, each with its tool-log id:
//
//   - a static Open Brain tool (openBrainToolNames): the id is
//     OpenBrainToolLogID(name), the phase-2 mapping;
//   - a brokered tool (a name of the tools/call allow list of the mcp
//     endpoint that is not static; listenerPolicy.brokeredTools): the id
//     is the name, byte for byte, with no prefix.
//
// From OCSF X2t takes the tool names of the ALLOWED HTTP:POST records to
// "http://<mcp endpoint>/mcp/open_brain": the `tools=` field inside the
// "[msg:...]" tag, split on ','. X2t passes when, for each tool-log id in
// C, the tool-log records with that id are at most the OCSF names whose
// id it is. Its other rules:
//
//   - A `tools=` value is complete only when a space follows it inside the
//     tag. A value that runs into the 120-byte cut, a record with no tag or
//     no `tools=` field, and a form with two readings (two tags, two
//     `tools=` fields, an empty or non-strict name) make X2t not_checked
//     (incomplete), never inconsistent. The ellipsis alone is not the test:
//     almost every allowed MCP record ends in it (US-202).
//   - A tool-log record whose hash is not in C (an OpenCode built-in, a
//     runtime record of a brokered call under a rendered name, a static
//     tool under an unexpected rendered name) is not counted: X2t can miss
//     a fault, but it never reports a false one.
//   - Limit: OpenBrainToolLogID maps the static names "a.b" and "a_b" to
//     one id. X2t compares that id with the sum of the OCSF counts of both
//     names, so it cannot tell the two tools apart. Brokered ids have no
//     such change.
//   - A brokered name whose runtime rendering OpenBrainToolLogID(name)
//     equals the id of a static tool (brokered "plan_get.state", static
//     "plan.get_state": both "open_brain_plan_get_state") is also added to
//     that static candidate, so a runtime record of the brokered call
//     counts against the OCSF calls of both names and cannot give a false
//     inconsistent.
//   - With the "any tool" fallback (design 6.3) C has the static tools
//     only, and X2t can miss a fault of a brokered tool. The report then
//     says so in an informational line (infoX2tStaticOnly).
//   - X2t checks one direction only. It finds tool-log records with no
//     inspected call (the bypass direction). It does not find a call that
//     the tool log leaves out: an OCSF call with no tool-log record passes
//     (design 6.6). "X2t consistent" does not mean that the tool log is
//     complete.
//   - Only a tools/call record gives names (mcpToolNames). A record whose
//     `rule_methods=` holds no tools/call (initialize, tools/list, ...) is
//     not counted, so it cannot stand in for a missing call. A batch is
//     counted name by name. The count of "tools/call" in `rule_methods=`
//     must equal the number of names in `tools=`, else X2t is not_checked
//     (incomplete); so a `tools=` value that lost a duplicate name cannot
//     give a false inconsistent. A missing, cut or mixed `rule_methods=`
//     is incomplete too.
//
// Parser differentials. One record must not read as two different things
// to the producer and to konareef. The launcher writes `class` and `msg`
// of NET:* and HTTP:* records from one OpenShell OCSF shorthand line
// "<CLASS> [<SEV>] <msg>" (reef-core launcher/openshell_stream.go,
// ocsfMessagePattern and the OCSF branch of the record builder), so the
// class and the method in msg are two separate tokens. konareef refuses
// (fails X1, fail closed) every form that could be read in two ways:
//
//   - a NET:OPEN or HTTP:* msg that is not ALLOWED, DENIED, or (NET:OPEN
//     only) a bare "<host>:<port>" (the measured forms): "seq <n>: unknown
//     <class> msg form";
//   - an ALLOWED NET:OPEN msg with more than one " -> ": "seq <n>: no
//     destination" and "seq <n>: no binary";
//   - an ALLOWED HTTP:* msg whose method is not the class suffix, byte for
//     byte: "seq <n>: method <m> differs from class <c>".
//
// X2 counts a POST only when its URL is the exact text
// "http://<listener>:<run_port>/mcp/open_brain". Every such URL has the
// listener authority (urlAuthority), so the X2 POSTs are always a subset
// of the listener lines that X4 and reef-core count. Any other spelling
// (a query, a trailing '/', percent-encoding, user info, other case, an
// explicit default port) is not counted, so X2 can only report more.
// JSON forms with two readings (duplicate keys, data after the value, a
// seq such as 1.0 or 1e0, invalid UTF-8) are not canonical JCS and fail
// rule 9 before the cross-check (openshell.go, decodeOCSFRecord).
package verify

import (
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// openBrainMCPServerKey is the key of the Open Brain MCP server in the
// OpenCode configuration that reef-core writes (reef-core
// lib/pod/agent/runtime/opencode/config_materializer.ex).
const openBrainMCPServerKey = "open_brain"

// openBrainToolNames are the names of the built-in Open Brain MCP tools
// (reef-core `Pod.OpenBrain.McpTransport.static_tools/0`), in that order.
// testdata/open_brain_tools.json pins them with the reef-core commit, and
// a test checks that this list and the file agree.
var openBrainToolNames = []string{
	"proofs.list",
	"budget.get",
	"plan.get_state",
	"plan.update_task",
	"openbrain.report_usage",
	"openbrain.inspect_memory",
	"openbrain.list_review_queue",
	"openbrain.review_memory",
	"openbrain.get_recall_trace",
	"openbrain.recall",
	"openbrain.writeback",
}

// OpenBrainToolLogID returns the tool-log id that OpenCode writes for an
// Open Brain MCP tool (design section 14a, D11): "<MCP server key>_<tool
// name with '.' replaced by '_'>".
//
// Input: the MCP tool name, for example "openbrain.recall".
// Output: the tool-log id, for example "open_brain_openbrain_recall".
func OpenBrainToolLogID(toolName string) string {
	return openBrainMCPServerKey + "_" + strings.ReplaceAll(toolName, ".", "_")
}

// openBrainToolHashes is the set of SHA-256 hashes of the Open Brain
// tool-log ids. A tool-log record holds the SHA-256 of its tool id.
var openBrainToolHashes = func() map[[32]byte]bool {
	hashes := map[[32]byte]bool{}
	for _, name := range openBrainToolNames {
		hashes[sha256.Sum256([]byte(OpenBrainToolLogID(name)))] = true
	}
	return hashes
}()

// mcpToolNamePattern is the tool-name rule of strict_tool_names (phase-3
// design 6.3): no ',' and no space, so a `tools=` value splits on ','.
var mcpToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// crossCheckInput holds the inputs of the cross-check besides the records.
type crossCheckInput struct {
	policyYAML string         // the policy file of the key
	listener   listenerPolicy // the reef_run_listener policy (readListenerPolicy)
	toolLog    [][]byte       // the 113-byte tool-log records (rule 12 checked them)
	served     uint64         // OPENSHELL_LISTENER_REQUESTS
	seen       *uint64        // the listener lines in the records; nil when not computed
	redacted   bool           // a leaf is withheld
	complete   bool           // complete evidence (design 8.3)
}

// crossCheck applies rules X1 to X4 and returns the outcome.
//
// Inputs: events, the real event records in order (withheld leaves are
// not among them); input, the other inputs.
// Output: the CrossCheck, chosen in the order of the file comment.
func crossCheck(events []ocsfEvent, input crossCheckInput) CrossCheck {
	policy := readPolicyNetwork(input.policyYAML)
	var rows []string
	if row := crossCheckX1(events, policy); row != "" {
		rows = append(rows, row)
	}
	toolNamesIncomplete := false
	if input.complete && !input.redacted {
		var row string
		if input.listener.mcpEndpoint != "" {
			candidates := x2tCandidates(openBrainToolNames, input.listener.brokeredTools)
			row, toolNamesIncomplete = crossCheckX2t(events, input.toolLog, input.listener.mcpEndpoint, candidates)
		} else {
			endpoint := ""
			if len(input.listener.endpoints) == 1 {
				endpoint = input.listener.endpoints[0]
			}
			row = crossCheckX2(events, input.toolLog, endpoint)
		}
		if row != "" {
			rows = append(rows, row)
		}
	}
	if row := crossCheckX3(events, policy); row != "" {
		rows = append(rows, row)
	}
	if input.seen != nil && *input.seen > input.served {
		rows = append(rows, fmt.Sprintf("X4: listener lines without a served request: %d in OCSF, %d served", *input.seen, input.served))
	}

	switch {
	case len(rows) > 0:
		return CrossCheck{Outcome: "inconsistent", Rows: rows}
	case input.redacted:
		return CrossCheck{Outcome: "not_checked", Reason: "redacted"}
	case !input.complete || toolNamesIncomplete:
		return CrossCheck{Outcome: "not_checked", Reason: "incomplete"}
	case len(input.toolLog) == 0:
		return CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"}
	default:
		return CrossCheck{Outcome: "consistent"}
	}
}

// crossCheckX1 checks that every ALLOWED NET:OPEN and HTTP:* destination
// is an endpoint of the policy file.
//
// Inputs: the event records; the policy's network part.
// Output: "" when the rule holds, else the row that names each failed
// destination once, in record order.
func crossCheckX1(events []ocsfEvent, policy policyNetwork) string {
	var failed []string
	seen := map[string]bool{}
	for _, event := range events {
		var destination string
		var ok bool
		if event.class != "NET:OPEN" && !strings.HasPrefix(event.class, "HTTP:") {
			continue
		}
		if problem := msgFormProblem(event); problem != "" {
			if !seen[problem] {
				seen[problem] = true
				failed = append(failed, problem)
			}
			continue
		}
		switch {
		case event.class == "NET:OPEN":
			allowed, readable := netOpenAllowed(event)
			if !allowed {
				// A bare "<host>:<port>" (no verdict) to a non-loopback
				// address must also be a policy endpoint.
				bare, checked := bareNetOpenDestination(event)
				if !checked {
					continue
				}
				readable.destination = bare
			}
			destination, ok = readable.destination, readable.destination != ""
		default:
			url, allowed := httpAllowedURL(event)
			if !allowed {
				continue
			}
			destination = urlAuthority(url)
			ok = destination != ""
		}
		item := destination
		if !ok {
			item = fmt.Sprintf("seq %s: no destination", eventSeqText(event))
		} else if policy.endpoints[destination] {
			continue
		}
		if !seen[item] {
			seen[item] = true
			failed = append(failed, item)
		}
	}
	if len(failed) == 0 {
		return ""
	}
	return "X1: destination not an endpoint of policy_yaml: " + strings.Join(failed, ", ")
}

// crossCheckX2 checks that the Open Brain tool calls of the tool log are
// at most the HTTP:POST ALLOWED records to the Open Brain MCP URL of the
// listener. One tool call gives several such records (US-102 D10), so the
// rule is an upper bound.
//
// Inputs: the event records; the tool-log records; the listener endpoint
// ("<listener>:<run_port>").
// Output: "" when the rule holds, else the row with both counts.
func crossCheckX2(events []ocsfEvent, toolLog [][]byte, endpoint string) string {
	var toolCalls uint64
	for _, record := range toolLog {
		if len(record) != custodyRecordSize {
			continue // checkToolLogRecords gives 113-byte records only
		}
		var toolHash [32]byte
		copy(toolHash[:], record[1:33]) // 0x20 || SHA-256(tool_id) || ...
		if openBrainToolHashes[toolHash] {
			toolCalls++
		}
	}
	mcpURL := "http://" + endpoint + "/mcp/" + openBrainMCPServerKey
	var posts uint64
	for _, event := range events {
		if event.class != "HTTP:POST" {
			continue
		}
		msg, _ := event.fields["msg"].(string)
		rest, ok := strings.CutPrefix(msg, "ALLOWED POST ")
		if !ok {
			continue
		}
		if url, _, _ := strings.Cut(rest, " "); url == mcpURL {
			posts++
		}
	}
	if toolCalls <= posts {
		return ""
	}
	return fmt.Sprintf("X2: %d Open Brain tool calls in the tool log, %d HTTP:POST ALLOWED records to %s", toolCalls, posts, mcpURL)
}

// x2tCandidate is one tool-log id of the X2t candidate set C: the SHA-256
// of the id, and the OCSF tool names whose id it is (more than one only
// for static names such as "a.b" and "a_b").
type x2tCandidate struct {
	hash      [32]byte
	ocsfNames []string
}

// x2tCandidates builds the candidate set C of X2t (phase-3 design 6.6).
//
// Inputs: static, the static Open Brain tool names; brokered, the brokered
// names of the tools/call allow list (none with the "any tool" fallback).
// Output: one entry per distinct tool-log id, in input order: id
// OpenBrainToolLogID(name) for a static name, the name itself for a
// brokered name. A brokered name whose OpenBrainToolLogID equals the id of
// a static candidate is also added to the OCSF names of that candidate.
func x2tCandidates(static, brokered []string) []x2tCandidate {
	var candidates []x2tCandidate
	index := map[[32]byte]int{}
	add := func(id, ocsfName string) {
		hash := sha256.Sum256([]byte(id))
		if i, seen := index[hash]; seen {
			if !slices.Contains(candidates[i].ocsfNames, ocsfName) {
				candidates[i].ocsfNames = append(candidates[i].ocsfNames, ocsfName)
			}
			return
		}
		index[hash] = len(candidates)
		candidates = append(candidates, x2tCandidate{hash: hash, ocsfNames: []string{ocsfName}})
	}
	for _, name := range static {
		add(OpenBrainToolLogID(name), name)
	}
	staticCount := len(candidates)
	for _, name := range brokered {
		add(name, name)
		// The runtime rendering of a brokered call: merge it with a static
		// candidate that has the same id (never make a new candidate).
		rendered := sha256.Sum256([]byte(OpenBrainToolLogID(name)))
		if i, seen := index[rendered]; seen && i < staticCount && !slices.Contains(candidates[i].ocsfNames, name) {
			candidates[i].ocsfNames = append(candidates[i].ocsfNames, name)
		}
	}
	return candidates
}

// crossCheckX2t checks, per tool, that the tool-log records of each
// candidate in C are at most the allowed tools/call names in the OCSF
// records to the MCP URL of the mcp endpoint (phase-3 design 6.6).
//
// Inputs: the event records; the tool-log records; the mcp endpoint
// ("<listener>:<run_mcp_port>"); the candidate set C (x2tCandidates).
// Output: the row ("" when the rule holds or did not run), and true when a
// `tools=` value could not be read in full, so X2t did not run (the
// outcome is then not_checked (incomplete)).
func crossCheckX2t(events []ocsfEvent, toolLog [][]byte, mcpEndpoint string, candidates []x2tCandidate) (string, bool) {
	mcpURL := "http://" + mcpEndpoint + "/mcp/" + openBrainMCPServerKey
	ocsfCounts := map[string]uint64{}
	for _, event := range events {
		if event.class != "HTTP:POST" {
			continue
		}
		msg, _ := event.fields["msg"].(string)
		rest, ok := strings.CutPrefix(msg, "ALLOWED POST ")
		if !ok {
			continue
		}
		if url, _, _ := strings.Cut(rest, " "); url != mcpURL {
			continue
		}
		names, complete := mcpToolNames(msg)
		if !complete {
			return "", true
		}
		for _, name := range names {
			ocsfCounts[name]++
		}
	}
	logCounts := map[[32]byte]uint64{}
	for _, record := range toolLog {
		if len(record) != custodyRecordSize {
			continue // checkToolLogRecords gives 113-byte records only
		}
		var toolHash [32]byte
		copy(toolHash[:], record[1:33]) // 0x20 || SHA-256(tool_id) || ...
		logCounts[toolHash]++
	}
	var failed []string
	for _, candidate := range candidates {
		var calls uint64
		for _, name := range candidate.ocsfNames {
			calls += ocsfCounts[name]
		}
		if logged := logCounts[candidate.hash]; logged > calls {
			failed = append(failed, fmt.Sprintf("%s %d in the tool log, %d in OCSF", strings.Join(candidate.ocsfNames, "/"), logged, calls))
		}
	}
	if len(failed) == 0 {
		return "", false
	}
	return "X2: tool calls in the tool log above the allowed tools/call records to " + mcpURL + ": " + strings.Join(failed, ", "), false
}

// mcpToolNames reads the tool names of an allowed MCP record: the `tools=`
// field inside its "[msg:...]" tag (the US-202 form "ALLOWED POST <url>
// [policy:... engine:l7-mcp] [msg:JSONRPC_L7_REQUEST decision=allow
// rule_methods=<m> tools=<names> http_method=<h> endpoint=<e>...]").
//
// Only a tools/call record gives names (Hermes !183 note 9927). The
// `rule_methods=` field decides, as the US-202 captures write it: one
// method, or a batch joined with ',' ("tools/call,tools/call"):
//
//   - no `rule_methods=` field, more than one, a value that runs into the
//     cut, or an empty entry: incomplete;
//   - no tools/call entry (initialize, notifications/initialized,
//     tools/list): the record is not a tool call and gives no names,
//     whatever its `tools=` field holds;
//   - tools/call mixed with other methods: incomplete (ambiguous);
//   - only tools/call entries: the `tools=` value must be complete (a
//     space follows it inside the tag), come after `rule_methods=`, hold
//     strict tool names only, and hold exactly one name per tools/call
//     entry, else incomplete.
//
// Input: the record's msg. Output: the names, and whether the record could
// be read (false means X2t is not_checked (incomplete)).
func mcpToolNames(msg string) ([]string, bool) {
	const tagOpen, field, methodsField = " [msg:", " tools=", " rule_methods="
	start := strings.Index(msg, tagOpen)
	if start < 0 || strings.Count(msg, tagOpen) != 1 || !strings.HasSuffix(msg, "]") {
		return nil, false
	}
	tag := msg[start+len(tagOpen) : len(msg)-1]

	if strings.Count(tag, methodsField) != 1 {
		return nil, false
	}
	_, methodsText, _ := strings.Cut(tag, methodsField)
	methods, _, spaced := strings.Cut(methodsText, " ")
	if !spaced {
		return nil, false // rule_methods runs into the cut
	}
	toolCalls, others := 0, 0
	for _, method := range strings.Split(methods, ",") {
		switch method {
		case "":
			return nil, false
		case "tools/call":
			toolCalls++
		default:
			others++
		}
	}
	switch {
	case toolCalls == 0:
		return nil, true // not a tool call: nothing to count
	case others > 0:
		return nil, false // a mixed batch: ambiguous
	}

	if strings.Count(tag, field) != 1 {
		return nil, false
	}
	before, after, _ := strings.Cut(tag, field)
	if !strings.Contains(before, methodsField) {
		return nil, false // tools= before rule_methods: not the US-202 form
	}
	value, _, spaced := strings.Cut(after, " ")
	if !spaced {
		return nil, false // the value runs into the cut
	}
	if value == "-" {
		return nil, false // upstream's "no tool" mark in a tools/call record
	}
	names := strings.Split(value, ",")
	for _, name := range names {
		if !mcpToolNamePattern.MatchString(name) {
			return nil, false
		}
	}
	if len(names) != toolCalls {
		return nil, false
	}
	return names, true
}

// crossCheckX3 checks that every ALLOWED NET:OPEN record names a binary of
// the reef_run_listener network policy.
//
// Inputs: the event records; the policy's network part.
// Output: "" when the rule holds, else the row that names each other
// binary once, in record order.
func crossCheckX3(events []ocsfEvent, policy policyNetwork) string {
	var failed []string
	seen := map[string]bool{}
	for _, event := range events {
		if event.class != "NET:OPEN" {
			continue
		}
		allowed, readable := netOpenAllowed(event)
		if !allowed {
			continue
		}
		item := readable.binary
		if item == "" {
			item = fmt.Sprintf("seq %s: no binary", eventSeqText(event))
		} else if policy.listenerBinaries[item] {
			continue
		}
		if !seen[item] {
			seen[item] = true
			failed = append(failed, item)
		}
	}
	if len(failed) == 0 {
		return ""
	}
	return "X3: NET:OPEN by a binary other than the " + listenerPolicyName + " binary: " + strings.Join(failed, ", ")
}

// netOpenFields are the parts of an ALLOWED NET:OPEN msg; each is "" when
// it cannot be read.
type netOpenFields struct {
	binary      string // the executable path, without the "(<n>)" suffix
	destination string // "<host>:<port>"
}

// netOpenAllowed reads an ALLOWED NET:OPEN msg of the measured form
// "ALLOWED <binary>(<n>) -> <host>:<port> [policy:... engine:...]".
//
// Input: a NET:OPEN record. Output: whether its msg starts with
// "ALLOWED ", and the parts that could be read.
func netOpenAllowed(event ocsfEvent) (bool, netOpenFields) {
	msg, _ := event.fields["msg"].(string)
	rest, ok := strings.CutPrefix(msg, "ALLOWED ")
	if !ok {
		return false, netOpenFields{}
	}
	arrow := strings.Index(rest, " -> ")
	if arrow < 0 || strings.Count(rest, " -> ") != 1 {
		// No arrow, or more than one: the binary and the destination
		// could be split in two ways.
		return true, netOpenFields{}
	}
	fields := netOpenFields{}
	process := rest[:arrow]
	if open := strings.LastIndex(process, "("); open > 0 && strings.HasSuffix(process, ")") {
		if _, err := strconv.ParseUint(process[open+1:len(process)-1], 10, 64); err == nil {
			fields.binary = process[:open]
		}
	}
	destination, _, _ := strings.Cut(rest[arrow+len(" -> "):], " ")
	if host, port, err := net.SplitHostPort(destination); err == nil && host != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err == nil {
			fields.destination = net.JoinHostPort(host, port)
		}
	}
	return true, fields
}

// msgFormProblem checks the msg form of a NET:OPEN or HTTP:* record
// against the measured forms (US-102 P5 and the US-108 vectors):
// "ALLOWED ...", "DENIED ...", and for NET:OPEN also a bare
// "<host>:<port>". An ALLOWED HTTP:* msg must name the method of its
// class, byte for byte.
//
// Input: a NET:OPEN or HTTP:* record. Output: "" for a known form, else
// the X1 row item.
func msgFormProblem(event ocsfEvent) string {
	msg, _ := event.fields["msg"].(string)
	seq := eventSeqText(event)
	switch {
	case strings.HasPrefix(msg, "ALLOWED "):
		if method, isHTTP := strings.CutPrefix(event.class, "HTTP:"); isHTTP {
			rest := strings.TrimPrefix(msg, "ALLOWED ")
			if token, _, _ := strings.Cut(rest, " "); token != method {
				return fmt.Sprintf("seq %s: method %q differs from class %s", seq, token, event.class)
			}
		}
		return ""
	case strings.HasPrefix(msg, "DENIED "):
		return ""
	case event.class == "NET:OPEN" && bareDestination(msg):
		return ""
	}
	return fmt.Sprintf("seq %s: unknown %s msg form", seq, event.class)
}

// bareDestination reports whether msg is only "<host>:<port>", the form
// of a NET:OPEN record with no verdict (US-108 vectors: "127.0.0.1:17670").
func bareDestination(msg string) bool {
	if strings.ContainsAny(msg, " \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(msg)
	if err != nil || host == "" {
		return false
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return err == nil
}

// bareNetOpenDestination reads the destination of a NET:OPEN record in
// the bare "<host>:<port>" form, which has no ALLOWED or DENIED verdict
// (coordinator decision 2026-10-09, after US-112). A loopback address
// (127.0.0.0/8 or ::1, as net.IP.IsLoopback reads an IP literal) stays
// inside the sandbox and is not checked. Any other host, a name such as
// "localhost" included, must be a policy endpoint (X1, fail closed).
//
// Input: a NET:OPEN record. Output: the destination "<host>:<port>" and
// true when X1 must check it; "" and false for a record that is not in
// the bare form or names a loopback address.
func bareNetOpenDestination(event ocsfEvent) (string, bool) {
	msg, _ := event.fields["msg"].(string)
	if !bareDestination(msg) {
		return "", false
	}
	host, port, _ := net.SplitHostPort(msg)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

// httpAllowedURL reads the URL of an ALLOWED HTTP:* msg of the form
// "ALLOWED <METHOD> <url> [...]".
//
// Input: an HTTP:* record. Output: the URL ("" when absent), and whether
// the msg starts with "ALLOWED ".
func httpAllowedURL(event ocsfEvent) (string, bool) {
	msg, _ := event.fields["msg"].(string)
	rest, ok := strings.CutPrefix(msg, "ALLOWED ")
	if !ok {
		return "", false
	}
	parts := strings.SplitN(rest, " ", 3)
	if len(parts) < 2 {
		return "", true
	}
	return parts[1], true
}

// eventSeqText is the seq of a record as text, "null" when it has none.
func eventSeqText(event ocsfEvent) string {
	if !event.hasSeq {
		return "null"
	}
	return strconv.FormatUint(event.seq, 10)
}

// policyNetwork is the network part of the policy file that the
// cross-check reads.
type policyNetwork struct {
	endpoints        map[string]bool // "<host>:<port>" of every endpoint of every network policy, as written
	listenerBinaries map[string]bool // the binary paths of the reef_run_listener network policy
}

// readPolicyNetwork reads the endpoints and the listener binaries of the
// policy file. An endpoint without a host or a port in 1..65535 is not
// read. A file that does not parse gives empty sets, so every ALLOWED
// destination and binary fails X1 and X3 (fail closed).
//
// Input: the policy YAML. Output: the network part.
func readPolicyNetwork(policyYAML string) policyNetwork {
	out := policyNetwork{endpoints: map[string]bool{}, listenerBinaries: map[string]bool{}}
	var policy struct {
		NetworkPolicies map[string]struct {
			Endpoints []struct {
				Host string `yaml:"host"`
				Port int    `yaml:"port"`
			} `yaml:"endpoints"`
			Binaries []struct {
				Path string `yaml:"path"`
			} `yaml:"binaries"`
		} `yaml:"network_policies"`
	}
	if err := yaml.Unmarshal([]byte(policyYAML), &policy); err != nil {
		return out
	}
	for name, networkPolicy := range policy.NetworkPolicies {
		for _, endpoint := range networkPolicy.Endpoints {
			if endpoint.Host == "" || endpoint.Port <= 0 || endpoint.Port > 65535 {
				continue
			}
			out.endpoints[net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))] = true
		}
		if name == listenerPolicyName {
			for _, binary := range networkPolicy.Binaries {
				if binary.Path != "" {
					out.listenerBinaries[binary.Path] = true
				}
			}
		}
	}
	return out
}
