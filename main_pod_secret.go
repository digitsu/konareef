// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_secret.go — `konareef pod secret set|rm|ls`.
//
// An author binds an API key to a published pod. The value is read from
// stdin (a pipe) or from a hidden terminal prompt, never from an
// argument, so it does not land in shell history. Every operation is a
// signed envelope (internal/secret) verified server-side against the
// pubkey bound to the handle. `rm` needs its own confirmation flag,
// because a removed key stops every run of the pod at its first
// gateway call.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/secret"
	"github.com/digitsu/konareef/internal/serverurl"
	"golang.org/x/term"
)

const podSecretUsage = `usage: konareef pod secret <subcommand>
  set <handle>/<pod> <NAME> [--server URL]                    bind a secret value (read from stdin or a prompt)
  rm  <handle>/<pod> <NAME> [--server URL] [--confirm-secret-rm]  remove a bound secret
  ls  <handle>/<pod> [--server URL]                           list bound secret names`

// runPodSecret is the os.Exit wrapper around runPodSecretImpl.
func runPodSecret(args []string) {
	os.Exit(runPodSecretImpl(args, os.Stdin))
}

// runPodSecretImpl runs one secret subcommand and returns the exit code:
// 0 on success, 1 on a pipeline failure (identity, read, server
// refusal), 2 on a usage error, exitNotConfirmed when `rm` is refused.
// valueSource supplies the secret value for `set`; the CLI passes
// os.Stdin and tests pass a reader.
func runPodSecretImpl(args []string, valueSource io.Reader) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, podSecretUsage)
		return 2
	}
	op := args[0]
	if op != "set" && op != "rm" && op != "ls" {
		fmt.Fprintln(os.Stderr, podSecretUsage)
		return 2
	}

	fs := flag.NewFlagSet("pod secret "+op, flag.ContinueOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	confirmRm := fs.Bool(confirmFlagSecretRm, false,
		"the developer has confirmed this removal (skips the interactive prompt; authorises nothing else)")
	if err := fs.Parse(reorderFlagsFirst(args[1:])); err != nil {
		return 2
	}
	wantArgs := 2
	if op == "ls" {
		wantArgs = 1
	}
	if fs.NArg() != wantArgs {
		fmt.Fprintln(os.Stderr, podSecretUsage)
		return 2
	}
	handle, podName, ok := strings.Cut(fs.Arg(0), "/")
	if !ok || handle == "" || podName == "" || strings.Contains(podName, "/") {
		fmt.Fprintln(os.Stderr, "pod secret: the pod reference must be <handle>/<pod_name>")
		return 2
	}
	name := ""
	if op != "ls" {
		name = fs.Arg(1)
		if err := secret.ValidateName(name); err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 2
		}
	}

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pod secret:", err)
		return 2
	}
	if op == "set" {
		parsed, err := serverurl.Parse(resolvedServer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 2
		}
		if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
			fmt.Fprintf(os.Stderr,
				"pod secret set: refusing to send a secret over http to %s; use an https server URL (plain http is allowed only for localhost, 127.0.0.1, or ::1)\n",
				parsed.Host)
			return 2
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pod secret:", err)
		return 1
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pod secret: load identity:", err)
		return 1
	}
	if id.Handle != handle {
		fmt.Fprintf(os.Stderr, "pod secret: the local identity is bound to handle %q, not %q\n", id.Handle, handle)
		return 1
	}

	switch op {
	case "set":
		value, err := readSecretValue(valueSource, name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		envelope, err := secret.NewEnvelope(handle, podName, name, value, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		response, err := secret.Set(resolvedServer, id, envelope, value)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		fmt.Printf("bound %s to %s/%s (rotated %s)\n", response.Name, handle, podName, response.RotatedAt.UTC().Format(time.RFC3339))
		return 0

	case "rm":
		if !confirmed(*confirmRm, confirmFlagSecretRm,
			fmt.Sprintf("remove secret %s from %s/%s; every run of the pod will fail at its first gateway call until it is set again", name, handle, podName)) {
			return exitNotConfirmed
		}
		envelope, err := secret.NewEnvelope(handle, podName, name, nil, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		if err := secret.Remove(resolvedServer, id, envelope); err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		fmt.Printf("removed %s from %s/%s\n", name, handle, podName)
		return 0

	default: // ls
		envelope := secret.Envelope{Handle: handle, PodName: podName, TS: time.Now().Unix()}
		nonceEnvelope, err := secret.NewEnvelope(handle, podName, "LS_PLACEHOLDER", nil, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		envelope.Nonce = nonceEnvelope.Nonce
		entries, err := secret.List(resolvedServer, id, envelope)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pod secret:", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Printf("no secrets bound to %s/%s\n", handle, podName)
			return 0
		}
		for _, entry := range entries {
			fmt.Printf("%s\t%s\n", entry.Name, entry.RotatedAt.UTC().Format(time.RFC3339))
		}
		return 0
	}
}

// readSecretValue reads the value for name. When source is a terminal it
// prompts on stderr and reads with echo off. Otherwise it reads source to
// EOF and trims exactly one trailing newline, so `printf 'v\n' | ...` and
// `echo -n v | ...` both yield "v". An empty value is an error.
func readSecretValue(source io.Reader, name string) ([]byte, error) {
	if file, isFile := source.(*os.File); isFile && term.IsTerminal(int(file.Fd())) {
		fmt.Fprintf(os.Stderr, "Value for %s (hidden): ", name)
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read value: %w", err)
		}
		if len(value) == 0 {
			return nil, errors.New("empty secret value")
		}
		return value, nil
	}
	raw, err := io.ReadAll(io.LimitReader(source, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read value from stdin: %w", err)
	}
	if len(raw) > 64*1024 {
		return nil, errors.New("secret value exceeds 64 KiB")
	}
	value := bytes.TrimSuffix(raw, []byte("\n"))
	value = bytes.TrimSuffix(value, []byte("\r"))
	if len(value) == 0 {
		return nil, errors.New("empty secret value on stdin")
	}
	return value, nil
}

// isLoopbackHost reports whether host (as returned by url.URL.Hostname,
// so an IPv6 literal arrives without its brackets) names the local
// machine. `pod secret set` allows plain http only to these hosts —
// everywhere else a secret value must travel over https.
func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
