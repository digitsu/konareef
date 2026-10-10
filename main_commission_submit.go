// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Commission subcommands that talk to reef-core: submit, key, revoke,
// receipt (docs/design/commission-admission-contract.md, IB-06).
//
//   - `commission submit <commission.cbor>` runs a pod under a signed
//     commission on POST /api/commissioned-runs. `pod run --commission`
//     is the same command.
//   - `commission key register|list|retire` manages the buyer keys the
//     server accepts as signers for this account.
//   - `commission revoke <commission.cbor>` stops a commission from
//     admitting any future run.
//   - `commission receipt <receipt-id>` reads an admission receipt.
//
// A commissioned run is enforced or it does not happen. When the server
// refuses, does not have the route, or cannot be reached, the command
// fails and says why. It never falls back to `pod run` without the
// commission. Server refusals, a server without the route, and transport
// failures have separate exit codes so a script can tell them apart.
//
// None of these commands signs a commission. `submit` and `revoke` read an
// artifact that `commission sign` already wrote behind its own
// confirmation gate. `key register` signs only the registration message,
// behind its own gate.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/install"
	"github.com/digitsu/konareef/internal/run"
)

// Confirmation flags of the key registry and revocation. Each is its own
// flag: registering a key, retiring it and revoking a commission are three
// different acts (see main_confirm_gate.go's header).
const (
	confirmFlagKeyRegister = "confirm-key-register"
	confirmFlagKeyRetire   = "confirm-key-retire"
	confirmFlagRevoke      = "confirm-revoke"
)

// Exit codes of the commands that talk to reef-core, beside 1 (a local or
// transport failure), 2 (usage), 3 (exitNotConfirmed) and 4
// (exitNotContained, also used when the local check refuses).
const (
	// exitServerRefused: the server answered with a refusal code.
	exitServerRefused = 5
	// exitServerUnsupported: the server has no commission route.
	exitServerUnsupported = 6
)

// commissionServerFlags are the flags every server-facing commission verb
// takes.
type commissionServerFlags struct {
	server *string
	token  *string
}

// addServerFlags registers --server and --token on fs.
func addServerFlags(fs *flag.FlagSet) commissionServerFlags {
	return commissionServerFlags{
		server: fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)"),
		token:  fs.String("token", "", "session token (default: $KONAREEF_TOKEN)"),
	}
}

// resolve returns the server URL and session token, or a usage error.
func (f commissionServerFlags) resolve() (string, string, error) {
	server, err := resolveServerURL(*f.server)
	if err != nil {
		return "", "", err
	}
	token := *f.token
	if token == "" {
		token = os.Getenv("KONAREEF_TOKEN")
	}
	if token == "" {
		return "", "", fmt.Errorf("session token required (pass --token or KONAREEF_TOKEN env)")
	}
	return server, token, nil
}

// serverErrorExit prints a server-facing failure and returns its exit code.
//
// Inputs: the stderr writer, the verb name, and the error. Output: the exit
// code. The server's refusal code is printed exactly as sent, followed by
// a hint for the codes a buyer can act on.
func serverErrorExit(stderr io.Writer, verb string, err error) int {
	var serverErr *api.ServerError
	var httpRefusal *api.HTTPRefusal
	isRun := verb == "commission submit" || verb == "pod run"
	switch {
	case errors.As(err, &serverErr):
		fmt.Fprintf(stderr, "%s: the server refused: %v\n", verb, serverErr)
		if hint := refusalHints[serverErr.Kind]; hint != "" {
			fmt.Fprintf(stderr, "  %s\n", hint)
		}
		if isRun {
			fmt.Fprintln(stderr, "  The run was not started without the commission, and this command will not retry it on another route.")
		}
		return exitServerRefused
	case errors.As(err, &httpRefusal):
		fmt.Fprintf(stderr, "%s: the server refused (http %d): %v\n", verb, httpRefusal.Status, httpRefusal)
		if httpRefusal.Status == 401 {
			fmt.Fprintln(stderr, "  The session token was not accepted. Get a new session token.")
		}
		if isRun {
			fmt.Fprintln(stderr, "  The run was not started, and this command will not retry it on another route.")
		}
		return exitServerRefused
	case errors.Is(err, api.ErrCommissionRouteMissing):
		fmt.Fprintf(stderr, "%s: %v\n", verb, err)
		fmt.Fprintln(stderr, "  This reef-core predates signed commissions. Nothing was started, and the run is not retried without the commission.")
		return exitServerUnsupported
	case errors.Is(err, run.ErrSubmitCancelled):
		fmt.Fprintf(stderr, "%s: %v\n", verb, err)
		fmt.Fprintln(stderr, "  The request may already have been admitted. Run the same command with the same inputs to get that run back.")
		return 1
	default:
		var transport *api.TransportError
		if errors.As(err, &transport) {
			fmt.Fprintf(stderr, "%s: no usable answer from the server: %s\n", verb, api.TerminalSafe(err.Error()))
			if isRun {
				fmt.Fprintln(stderr, "  The request may or may not have reached it. Run the same command with the same inputs: the server returns the same run, never a second one.")
			}
			return 1
		}
		fmt.Fprintf(stderr, "%s: %s\n", verb, api.TerminalSafe(err.Error()))
		return 1
	}
}

// refusalHints are what a buyer can do about a refusal code. Codes that
// report a server or manifest fault have no hint; the code says it.
var refusalHints = map[string]string{
	"commission_admission_disabled":        "This server does not accept commissioned runs right now.",
	"commission_signer_unregistered":       "Register the signing key for this account: `konareef commission key register`.",
	"commission_signer_not_authorized":     "The signing key is registered to another account. Sign with a key registered to this account.",
	"commission_signer_retired":            "The signing key is retired. Register a new key and sign a new commission.",
	"commission_revoked":                   "This commission was revoked. Sign a new one.",
	"commission_replay_conflict":           "This commission already admitted a run with other inputs or another account. Sign a new commission.",
	"commission_admission_in_progress":     "Another request with this commission is being admitted. Run the same command again later.",
	"commission_claim_lost":                "The server released the claim before the run started. Run the same command again.",
	"commission_binding_mismatch":          "The pod was republished under this version, or the commission was bound by hand. Draft a new commission.",
	"commission_not_contained":             "The pod declares more than the commission permits. Widen the commission and sign it again, or choose another pod.",
	"commission_sealed_grants_unsupported": "Commissions for closed pods that carry sealed grants are not supported yet (IB-00 D16).",
	"commission_route_required":            "Commissions are accepted only on the commissioned-run route; this is a client bug.",
	"commission_key_challenge_invalid":     "The registration challenge expired (5 minutes) or was replaced by a newer one. Run the command again.",
}

// runCommissionSubmit implements `commission submit <commission.cbor>`.
func runCommissionSubmit(args []string) {
	os.Exit(runCommissionSubmitCore(os.Stdout, os.Stderr, "commission submit", args))
}

// hasCommissionFlag reports whether args carry --commission (or
// -commission, with or without =value) ANYWHERE, including after a "--".
// `pod run` uses it to hand the whole command to runCommissionSubmitCore,
// so a commissioned run never passes through the uncommissioned spawn
// path. Scanning past "--" is deliberate: a commission word the flag
// parser would treat as a positional must not be dropped silently.
func hasCommissionFlag(args []string) bool {
	for _, a := range args {
		name := strings.TrimLeft(a, "-")
		if strings.HasPrefix(a, "-") && (name == "commission" || strings.HasPrefix(name, "commission=")) {
			return true
		}
	}
	return false
}

// runCommissionSubmitCore is the testable body of `commission submit` and
// of `pod run --commission`.
//
// Inputs: the output writers, the verb name for messages, and the
// arguments. The artifact is the positional argument, or the --commission
// flag; with the flag, a positional argument (optional) is a pod reference
// that must equal the signed pod_ref. Output: the exit code.
//
// Steps: load the artifact with the verifying loader; refuse a pod
// reference that disagrees with the signed binding; run the advisory local
// check; ask for --confirm-spend; submit; wait for the run.
func runCommissionSubmitCore(stdout, stderr io.Writer, verb string, args []string) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addServerFlags(fs)
	out := fs.String("out", "", "directory to download deliverables into (required)")
	timeout := fs.Duration("timeout", run.DefaultTimeout, "poll timeout waiting for the run to finish")
	var inputs run.InputFlags
	fs.Var(&inputs, "input", "pod input as key=value (repeatable; inputs are NOT covered by the signature)")
	confirmSpend := fs.Bool(confirmFlagSpend, false,
		"the buyer has confirmed this run and its cost (skips the interactive prompt; does not sign anything)")
	commissionFlag := fs.String("commission", "", "the signed commission.cbor; when given, the positional argument (optional) is the pod reference, which must equal the signed pod_ref")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	usage := "usage: konareef commission submit <commission.cbor> --out <dir> [--input k=v ...] [--server URL] [--token TOKEN] [--timeout DURATION] [--confirm-spend]\n" +
		"       konareef pod run [<handle>/<pod>@<version>] --commission <commission.cbor> --out <dir> [...]"

	var podArg, commissionPath string
	switch {
	case *commissionFlag == "" && fs.NArg() == 1:
		commissionPath = fs.Arg(0)
	case *commissionFlag != "" && fs.NArg() <= 1:
		commissionPath, podArg = *commissionFlag, fs.Arg(0)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	// The verifying loader: a signature that checks out AND an artifact
	// `sign` would have produced. An unsigned proposal.toml fails here.
	c, err := loadAndVerifyCommission(commissionPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %s is not a verified signed commission: %v\n", verb, commissionPath, err)
		fmt.Fprintln(stderr, "  (only an artifact written by `konareef commission sign` can be submitted)")
		return 1
	}
	p := c.Proposal()

	// The pod is named only by the signed binding. A pod reference on the
	// command line may repeat it, never replace it.
	if podArg != "" && podArg != p.Binding.PodRef {
		fmt.Fprintf(stderr, "%s: the command names %q, but the commission is signed for %q\n", verb, podArg, p.Binding.PodRef)
		fmt.Fprintln(stderr, "  A signed commission pins its pod; the command line cannot change it.")
		return 2
	}

	parsedInputs, err := run.ParseInputs(inputs)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", verb, err)
		return 2
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", verb, err)
		return 2
	}

	local := run.CheckLocally(c, func(handle, podName, version string) ([]byte, error) {
		fetched, err := install.Fetch(server, handle, podName, version)
		if err != nil {
			return nil, err
		}
		return fetched.ManifestCanonical, nil
	})
	if local.Blocks() {
		fmt.Fprintf(stderr, "%s: the local check refuses this commission, so it was not sent: %s: %s\n", verb, local.State, api.TerminalSafe(local.Detail))
		return exitNotContained
	}

	hCommission, _ := c.HCommissionHex()
	if !confirmedTo(stdout, stderr, *confirmSpend, confirmFlagSpend, fmt.Sprintf(
		"run %s on %s under the signed commission %s — this spends the buyer's sats and cannot be refunded.\n"+
			"  Assurance mode %s: the server checks models, tools (declared tools only) and spend,\n"+
			"  does NOT evaluate labels, and admits memory-free pods only. The run inputs are not signed.",
		p.Binding.PodRef, strings.TrimRight(server, "/"), hCommission, commission.AssuranceModeLimitedV1)) {
		return exitNotConfirmed
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cfg := run.CommissionedConfig{
		BaseURL: server, SessionToken: token, Commission: c, Inputs: parsedInputs,
		OutDir: *out, Timeout: *timeout, Out: stdout,
	}
	outcome, err := run.RunCommissioned(ctx, cfg, local)
	if err != nil {
		if outcome != nil && outcome.Response != nil && !errors.Is(err, run.ErrReceiptMismatch) && !errors.Is(err, run.ErrLaunchFailed) {
			// Admitted and started; the wait or the download failed.
			fmt.Fprintf(stderr, "%s: %s\n", verb, api.TerminalSafe(err.Error()))
			return 1
		}
		if errors.Is(err, run.ErrReceiptMismatch) {
			fmt.Fprintf(stderr, "%s: %s\n", verb, api.TerminalSafe(err.Error()))
			fmt.Fprintln(stderr, "  A run may have started; do not treat it as admitted under this commission.")
			return 1
		}
		if errors.Is(err, run.ErrLaunchFailed) {
			fmt.Fprintf(stderr, "%s: %v\n", verb, err)
			return exitServerRefused
		}
		return serverErrorExit(stderr, verb, err)
	}
	return 0
}

// runCommissionKey dispatches `commission key register|list|retire`.
func runCommissionKey(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission key <register|list|retire> ...")
		os.Exit(2)
	}
	var code int
	switch args[0] {
	case "register":
		code = runCommissionKeyRegister(os.Stdout, os.Stderr, args[1:])
	case "list":
		code = runCommissionKeyList(os.Stdout, os.Stderr, args[1:])
	case "retire":
		code = runCommissionKeyRetire(os.Stdout, os.Stderr, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown commission key subcommand %q\n", args[0])
		code = 2
	}
	os.Exit(code)
}

// runCommissionKeyRegister implements `commission key register [--account
// <user-id>]`: fetch a challenge, pick the account id the §6.1 message
// signs over (resolveKeyRegisterAccount), confirm, sign the message with
// the local identity, and register the key for this account.
//
// At a terminal, the challenge is fetched before the confirmation, so the
// prompt names the account the signature will bind. Fetching a challenge
// replaces the session's earlier one, and the server accepts it for 5
// minutes. Without a terminal and without --confirm-key-register, the
// command refuses before any request, as before. A malformed --account is
// a usage error before any request. The command never signs without an
// account id.
//
// Inputs: the output streams and the arguments after `register`. Output:
// the exit code: 2 usage; 3 not confirmed; 1 a transport failure, a
// malformed challenge, a missing account id or an --account that is not
// the session's account; 5 or 6 as serverErrorExit.
func runCommissionKeyRegister(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("commission key register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addServerFlags(fs)
	account := fs.String("account", "", "the reef-core user id (UUID) of the session's account (optional: the server's challenge names it; if given, it must match)")
	confirm := fs.Bool(confirmFlagKeyRegister, false, "the buyer has confirmed registering this key as a commission signer for the account")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: konareef commission key register [--account <user-id>] [--server URL] [--token TOKEN] [--confirm-key-register]")
		return 2
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintln(stderr, "commission key register:", err)
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "commission key register: locate home directory:", err)
		return 1
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(stderr, "commission key register:", err)
		fmt.Fprintln(stderr, "  (run `konareef pod identity create --handle <h>` first)")
		return 1
	}
	pub := strings.ToLower(id.PublicKeyHex)
	// Validate the local inputs before any request, with a placeholder
	// challenge (and a placeholder account when --account is absent).
	localAccount := *account
	if localAccount == "" {
		localAccount = "00000000-0000-0000-0000-000000000000"
	}
	if _, err := commission.KeyRegistrationMessage(localAccount, pub, strings.Repeat("00", 32)); err != nil {
		fmt.Fprintln(stderr, "commission key register:", err)
		return 2
	}

	// With nobody to ask and no flag, refuse offline: confirmedTo cannot
	// succeed, so do not create a server challenge first.
	if !*confirm && !stdinIsTerminal() {
		named := "the account the server's challenge names"
		if *account != "" {
			named = strings.ToLower(*account)
		}
		confirmedTo(stdout, stderr, false, confirmFlagKeyRegister, fmt.Sprintf(
			"register key %s as a commission signer for account %s on %s",
			pub, named, api.TerminalSafe(strings.TrimRight(server, "/"))))
		return exitNotConfirmed
	}

	ctx := context.Background()
	client := api.NewClient(server).WithToken(token)
	challenge, err := client.GetCommissionKeyChallenge(ctx)
	if err != nil {
		return serverErrorExit(stderr, "commission key register", err)
	}
	userID, err := resolveKeyRegisterAccount(*account, challenge.UserID)
	if err != nil {
		fmt.Fprintln(stderr, "commission key register:", err)
		return 1
	}
	msg, err := commission.KeyRegistrationMessage(userID, pub, challenge.Challenge)
	if err != nil {
		fmt.Fprintln(stderr, "commission key register: the server's challenge:", api.TerminalSafe(err.Error()))
		return 1
	}
	if !confirmedTo(stdout, stderr, *confirm, confirmFlagKeyRegister, fmt.Sprintf(
		"register key %s as a commission signer for account %s on %s — commissions this key signs can then run on this account.\n"+
			"  Check that %s is the user_id printed when your session was issued (pass --account to have this command check it)",
		pub, userID, api.TerminalSafe(strings.TrimRight(server, "/")), userID)) {
		return exitNotConfirmed
	}
	sig, err := id.Sign(msg)
	if err != nil {
		fmt.Fprintln(stderr, "commission key register:", err)
		return 1
	}
	key, err := client.RegisterCommissionKey(ctx, api.CommissionKeyRegistration{
		Pubkey: pub, Challenge: challenge.Challenge, Signature: hex.EncodeToString(sig),
	})
	if err != nil {
		return serverErrorExit(stderr, "commission key register", err)
	}
	fmt.Fprintf(stdout, "✓ registered commission key %s (key_id %s) for account %s\n", api.TerminalSafe(key.Pubkey), api.TerminalSafe(key.KeyID), userID)
	return 0
}

// resolveKeyRegisterAccount picks the account id that the §6.1
// registration message signs over.
//
// Inputs: the --account flag ("" when absent) and the user_id of the
// server's challenge (nil when the server did not send one). Output: the
// account id in canonical lowercase form, or an error; the caller must not
// sign on an error. The rules:
//   - A user_id the server sent must already be a lowercase canonical
//     UUID, which is what reef-core signs over. Anything else is refused,
//     even when --account is given.
//   - With both, they must be the same account (--account may be upper
//     case). A difference is refused: the session is not the account the
//     buyer named.
//   - With only the server's user_id, it is used.
//   - With only --account (a server before reef-core!149), it is used, as
//     before.
//   - With neither, the command refuses: it never signs without an
//     account id.
//
// Server text in an error is escaped with api.TerminalSafe.
func resolveKeyRegisterAccount(flagAccount string, serverUserID *string) (string, error) {
	flagAccount = strings.ToLower(flagAccount)
	if serverUserID == nil {
		if flagAccount == "" {
			return "", fmt.Errorf("the server did not return user_id with the challenge (reef-core before !149); pass --account <user-id>, the user_id printed when the session was issued")
		}
		if !commission.IsCanonicalUserID(flagAccount) {
			return "", fmt.Errorf("--account %s is not a canonical UUID", api.TerminalSafe(flagAccount))
		}
		return flagAccount, nil
	}
	serverAccount := *serverUserID
	if !commission.IsCanonicalUserID(serverAccount) {
		return "", fmt.Errorf("the server's challenge has user_id %s, which is not a canonical UUID; nothing was signed",
			api.TerminalSafe(strconv.Quote(serverAccount)))
	}
	if flagAccount != "" && flagAccount != serverAccount {
		return "", fmt.Errorf("--account %s does not match the session's account %s from the server; nothing was signed",
			api.TerminalSafe(flagAccount), serverAccount)
	}
	return serverAccount, nil
}

// runCommissionKeyList implements `commission key list`. Output: the exit
// code; one line per key.
func runCommissionKeyList(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("commission key list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addServerFlags(fs)
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintln(stderr, "commission key list:", err)
		return 2
	}
	keys, err := api.NewClient(server).WithToken(token).ListCommissionKeys(context.Background())
	if err != nil {
		return serverErrorExit(stderr, "commission key list", err)
	}
	for _, k := range keys {
		state := "active"
		if k.RetiredAt != nil {
			state = "retired " + *k.RetiredAt
		}
		safe := api.TerminalSafe
		fmt.Fprintf(stdout, "%s  %s  registered %s  %s\n", safe(k.KeyID), safe(k.Pubkey), safe(k.RegisteredAt), safe(state))
	}
	return 0
}

// runCommissionKeyRetire implements `commission key retire <key-id>`.
// Retirement is permanent. Output: the exit code.
func runCommissionKeyRetire(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("commission key retire", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addServerFlags(fs)
	confirm := fs.Bool(confirmFlagKeyRetire, false, "the buyer has confirmed retiring this key (permanent)")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: konareef commission key retire <key-id> [--server URL] [--token TOKEN] [--confirm-key-retire]")
		return 2
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintln(stderr, "commission key retire:", err)
		return 2
	}
	if !confirmedTo(stdout, stderr, *confirm, confirmFlagKeyRetire, fmt.Sprintf(
		"retire commission key %s on %s — permanent; every commission it signed that has not started a run is refused from now on",
		fs.Arg(0), strings.TrimRight(server, "/"))) {
		return exitNotConfirmed
	}
	key, err := api.NewClient(server).WithToken(token).RetireCommissionKey(context.Background(), fs.Arg(0))
	if err != nil {
		return serverErrorExit(stderr, "commission key retire", err)
	}
	fmt.Fprintf(stdout, "✓ retired commission key %s\n", api.TerminalSafe(key.KeyID))
	return 0
}

// runCommissionRevoke implements `commission revoke <commission.cbor>`.
func runCommissionRevoke(args []string) {
	os.Exit(runCommissionRevokeCore(os.Stdout, os.Stderr, args))
}

// runCommissionRevokeCore sends the signed wire bytes to
// POST /api/commissions/revoke. Output: the exit code.
func runCommissionRevokeCore(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("commission revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := addServerFlags(fs)
	confirm := fs.Bool(confirmFlagRevoke, false, "the buyer has confirmed revoking this commission (permanent)")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: konareef commission revoke <commission.cbor> [--server URL] [--token TOKEN] [--confirm-revoke]")
		return 2
	}
	c, err := loadAndVerifyCommission(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "commission revoke: %s is not a verified signed commission: %v\n", fs.Arg(0), err)
		return 1
	}
	wire, err := commission.EncodeWireV1(c)
	if err != nil {
		fmt.Fprintln(stderr, "commission revoke:", err)
		return 1
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintln(stderr, "commission revoke:", err)
		return 2
	}
	hCommission, _ := c.HCommissionHex()
	if !confirmedTo(stdout, stderr, *confirm, confirmFlagRevoke, fmt.Sprintf(
		"revoke commission %s for %s on %s — permanent; it does not stop a run that already started",
		hCommission, c.Proposal().Binding.PodRef, strings.TrimRight(server, "/"))) {
		return exitNotConfirmed
	}
	resp, err := api.NewClient(server).WithToken(token).RevokeCommission(context.Background(), api.CommissionRevokeRequest{
		Contract: commission.AdmissionContractV1, Commission: base64.StdEncoding.EncodeToString(wire),
	})
	if err != nil {
		return serverErrorExit(stderr, "commission revoke", err)
	}
	fmt.Fprintf(stdout, "✓ commission %s: %s\n", api.TerminalSafe(resp.HCommission), api.TerminalSafe(resp.State))
	return 0
}

// runCommissionReceipt implements `commission receipt <receipt-id>`: print
// the caller's receipt as the server sent it. With --json it prints the
// receipt as JSON instead, the input `commission replay --receipt` reads.
func runCommissionReceipt(args []string) {
	fs := flag.NewFlagSet("commission receipt", flag.ContinueOnError)
	flags := addServerFlags(fs)
	asJSON := fs.Bool("json", false, "print the receipt as JSON, for `commission replay --receipt`")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission receipt <receipt-id> [--server URL] [--token TOKEN] [--json]")
		os.Exit(2)
	}
	server, token, err := flags.resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission receipt:", err)
		os.Exit(2)
	}
	r, err := api.NewClient(server).WithToken(token).GetCommissionReceipt(context.Background(), fs.Arg(0))
	if err != nil {
		os.Exit(serverErrorExit(os.Stderr, "commission receipt", err))
	}
	if *asJSON {
		// TerminalSafeJSON escapes every non-printable rune, so the JSON
		// is safe to print and still decodes to the same receipt.
		out, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "commission receipt:", err)
			os.Exit(1)
		}
		os.Stdout.Write(append(api.TerminalSafeJSON(out), '\n'))
		return
	}
	safe := api.TerminalSafe
	fmt.Printf("receipt_id:     %s\nrun_state:      %s\nh_commission:   %s\npod:            %s pod_hash=%s\n",
		safe(r.ReceiptID), safe(r.RunState), safe(r.HCommission), safe(r.PodRef), safe(r.PodHash))
	fmt.Printf("effective:      model=%s budget_sats=%d\nauthenticity:   %s (the receipt is not signed)\n",
		safe(r.Effective.ModelID), r.Effective.BudgetSats, safe(r.Authenticity))
	dims := make([]string, 0, len(r.Dimensions))
	for k := range r.Dimensions {
		dims = append(dims, k)
	}
	sort.Strings(dims)
	for _, k := range dims {
		fmt.Printf("  %s: %s\n", safe(k), safe(r.Dimensions[k]))
	}
}
