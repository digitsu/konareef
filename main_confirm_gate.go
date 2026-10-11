// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Confirmation gate for the commands that cannot be taken back.
//
// `konareef pod publish` writes a publisher-signed artifact to the server
// under the developer's identity. `konareef pod run` spends their sats.
// Neither is reversible, and until now neither asked.
//
// The gate exists because prose did not hold. The agent skill that drives
// this CLI stated the rule twice, in two different wordings, and an agent
// told "publish it and run it, don't ask me anything" attempted a live
// publish both times. A rule a caller can reason its way around is not a
// control. This one refuses to act instead.
//
// Two properties matter more than the prompt itself.
//
// It fails closed. With no terminal to ask and no flag, the command aborts.
// A caller that cannot answer does not get a default yes.
//
// Each command has its own flag. `--confirm-publish` does not authorise a
// run, and `--confirm-spend` does not authorise a publish, so one approval
// can never cover both. Publishing and spending are separate decisions and
// the flags keep them separate.

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// confirmFlagPublish and confirmFlagSpend name the per-command bypasses.
// They are deliberately not a shared `--yes`: a single flag would let one
// answer authorise both commands, which is the failure this gate prevents.
const (
	confirmFlagPublish  = "confirm-publish"
	confirmFlagSpend    = "confirm-spend"
	confirmFlagFee      = "confirm-fee"
	confirmFlagSecretRm = "confirm-secret-rm"
)

// exitNotConfirmed is the exit code for a refused command. It is distinct
// from 1 (a pipeline failure) and 2 (a usage error) so a caller can tell
// "nobody approved this" apart from "this went wrong".
const exitNotConfirmed = 3

// stdinIsTerminal reports whether a person can answer a prompt on stdin.
//
// This uses term.IsTerminal rather than the os.ModeCharDevice test that the
// same check is often written with. `/dev/null` is itself a character
// device, so the mode test calls `cmd < /dev/null` a terminal — the exact
// shape of a headless run. Both paths refuse, so the mode test is safe, but
// it sends the caller the wrong message: a prompt it cannot answer instead
// of the explanation that names the flag and says who must approve.
//
// Declared as a variable so tests can replace it. The alternative is to
// exercise the gate only through a real terminal, which no test has.
var stdinIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// confirmOrExit gates an irreversible command.
//
// It returns when the caller may proceed. Otherwise it prints why and exits
// non-zero — callers do not need to handle a refusal.
//
//   - flagSet: the caller passed the command's own confirmation flag. The
//     gate accepts that and returns.
//   - a terminal is attached: print what will happen, then read an answer.
//     Anything other than "y" aborts.
//   - no terminal and no flag: abort, and name the flag that would have
//     worked.
//
// action is the one-line description of what the command is about to do,
// written so a person reading it can tell what it costs.
func confirmOrExit(flagSet bool, flagName, action string) {
	if !confirmed(flagSet, flagName, action) {
		os.Exit(exitNotConfirmed)
	}
}

// confirmed is confirmOrExit for callers that return an exit code rather
// than exiting. It reports whether the caller may proceed, and prints the
// same refusal on the way to false.
func confirmed(flagSet bool, flagName, action string) bool {
	return confirmedTo(os.Stdout, os.Stderr, flagSet, flagName, action)
}

// confirmedTo is confirmed with the prompt written to stdout and the
// refusal to stderr, for callers that return an exit code and write to
// writers a test can capture. Inputs and output are as confirmed's.
func confirmedTo(stdout, stderr io.Writer, flagSet bool, flagName, action string) bool {
	if flagSet {
		return true
	}

	if !stdinIsTerminal() {
		fmt.Fprintf(stderr,
			"konareef: refusing to continue without confirmation.\n"+
				"  About to: %s\n"+
				"  No terminal is attached, so there is nobody to ask.\n"+
				"  Pass --%s only when the developer has told you to run this command.\n",
			action, flagName)
		return false
	}

	fmt.Fprintf(stdout, "About to: %s\nContinue? [y/N] ", action)
	var answer string
	// A read error leaves answer empty, which aborts. Fail closed.
	_, _ = fmt.Scanln(&answer)
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		fmt.Fprintln(stdout, "Aborted.")
		return false
	}
	return true
}
