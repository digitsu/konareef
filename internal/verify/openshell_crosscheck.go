// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell_crosscheck.go — the cross-check of the tool log against the
// reef-ocsf/v1 records (reef-core OpenShell adapter, phase 2, design
// section 9; story US-112).
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
//     complete evidence (design 8.3);
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

// crossCheckInput holds the inputs of the cross-check besides the records.
type crossCheckInput struct {
	policyYAML string   // the policy file of the key
	endpoint   string   // "<listener>:<run_port>", "" when unknown
	toolLog    [][]byte // the 113-byte tool-log records (rule 12 checked them)
	served     uint64   // OPENSHELL_LISTENER_REQUESTS
	seen       *uint64  // the listener lines in the records; nil when not computed
	redacted   bool     // a leaf is withheld
	complete   bool     // complete evidence (design 8.3)
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
	if input.complete && !input.redacted {
		if row := crossCheckX2(events, input.toolLog, input.endpoint); row != "" {
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
	case !input.complete:
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
