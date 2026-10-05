// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// konareef — a TUI harness for agentic pods.
//
// Connects to a reef-core instance and provides terminal-native
// monitoring and management of orca-pods and lobster-pods.
//
// Usage:
//
//	konareef                                     # start the TUI (default)
//	konareef --server http://host:4000           # override reef-core URL
//	konareef smoke --token <base64>              # non-TUI end-to-end smoke test
//	konareef smoke --lifecycle --token <base64>  # full lifecycle smoke test
//	konareef pod validate <pod.toml>             # local schema validation
//	KONAREEF_TOKEN=... konareef smoke            # same, via env var
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/install"
	"github.com/digitsu/konareef/internal/listing"
	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
	"github.com/digitsu/konareef/internal/run"
	"github.com/digitsu/konareef/internal/saltstore"
	"github.com/digitsu/konareef/internal/serverurl"
	"github.com/digitsu/konareef/internal/smoke"
	"github.com/digitsu/konareef/internal/tui"
	"github.com/digitsu/konareef/internal/verdict"
	"github.com/digitsu/konareef/internal/verify"
	"github.com/digitsu/konareef/internal/version"
	"github.com/digitsu/konareef/internal/vkeystore"
	"github.com/digitsu/konareef/internal/ws"
	"golang.org/x/term"
)

// reorderFlagsFirst rearranges args so flag arguments come before any
// positional arguments. Go's flag.Parse stops at the first non-flag arg,
// which silently drops flags written after a positional (`pod init my-pod
// --dir X`). This helper restores the more-common Unix convention of
// allowing either order.
//
// Conservative behaviour:
//   - Flags are recognised by a leading "-".
//   - A flag's value is only consumed when the flag is in `--foo value`
//     form (no '=') AND the following arg does not itself start with "-".
//   - This is safe for subcommands that take only string-valued flags.
//     Mixing bool flags would risk consuming a positional as the bool's
//     value; runPodInit currently has only string flags.
func reorderFlagsFirst(args []string) []string {
	var flags []string
	var positional []string
	for cursor := 0; cursor < len(args); cursor++ {
		current := args[cursor]
		if strings.HasPrefix(current, "-") {
			flags = append(flags, current)
			if !strings.Contains(current, "=") &&
				cursor+1 < len(args) &&
				!strings.HasPrefix(args[cursor+1], "-") {
				flags = append(flags, args[cursor+1])
				cursor++
			}
			continue
		}
		positional = append(positional, current)
	}
	return append(flags, positional...)
}

func main() {
	// Apply env-var feature flags early so every subcommand path sees
	// the correct gate state. identity.LoadEnv() reads
	// KONAREEF_STRICT_DER_GATE=true → StrictDerGateEnabled (P1.4).
	identity.LoadEnv()

	// Version is handled before any subcommand routing so `konareef version`,
	// `konareef --version`, and `konareef -v` all short-circuit cleanly.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("konareef %s\n", version.String())
			return
		}
	}

	if len(os.Args) >= 2 && os.Args[1] == "smoke" {
		runSmoke(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "pod" {
		runPod(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "install" {
		runInstall(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "verify" {
		runVerify(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "feeder" {
		runFeeder(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "salt" {
		runSalt(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "verdict" {
		runVerdictServer(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "commission" {
		runCommission(os.Args[2:])
		return
	}

	runTUI(os.Args[1:])
}

// runVerdictServer serves the live, public-facing verdict page: it fetches a
// konareef-bundle/v2 from reef-core, runs the REAL verifier (the same
// VerifyV2Production + Rust `verify` subprocess as `konareef verify`), and
// renders the six checks resolving to a verdict. It is an INDEPENDENT verifier
// meant to run on the presenter's machine — reef-core is trusted only to serve
// the bundle bytes.
//
// Flags:
//
//	--serve <addr>    listen address (default :8099)
//	--server <url>    reef-core base URL to fetch bundles from
//	--hash <64-hex>   default proof hash (overridable per request via ?hash=)
//	--verify-bin <p>  path to the Rust verify binary (sets KONAREEF_VERIFY_BIN)
//	--durable         thread the verify --durable knob through
func runVerdictServer(args []string) {
	fs := flag.NewFlagSet("verdict", flag.ExitOnError)
	addr := fs.String("serve", ":8099", "listen address")
	server := fs.String("server", os.Getenv("KONAREEF_SERVER"), "reef-core base URL (bundles fetched from here)")
	hash := fs.String("hash", "", "default proof hash (64 hex); overridable per request via ?hash=")
	verifyBin := fs.String("verify-bin", "", "path to the Rust verify binary (sets KONAREEF_VERIFY_BIN)")
	durable := fs.Bool("durable", false, "thread the verify --durable knob through")
	_ = fs.Parse(args)

	if *verifyBin != "" {
		_ = os.Setenv(verify.VerifyBinEnv, *verifyBin)
	}
	if os.Getenv(verify.VerifyBinEnv) == "" {
		fmt.Fprintf(os.Stderr, "verdict: warning: %s is not set — the verifier will fail closed (proof_valid=false).\n", verify.VerifyBinEnv)
		fmt.Fprintln(os.Stderr, "         pass --verify-bin <path> or export KONAREEF_VERIFY_BIN to get a real PASS.")
	}

	srv := &verdict.Server{ReefcoreURL: *server, DefaultHash: *hash, Durable: *durable}
	fmt.Printf("verdict: serving on http://localhost%s\n", *addr)
	if *server != "" {
		fmt.Printf("verdict: bundles from %s", *server)
		if *hash != "" {
			fmt.Printf(" · default proof %s…", firstN(*hash, 8))
		}
		fmt.Println()
	}
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		fmt.Fprintln(os.Stderr, "verdict:", err)
		os.Exit(1)
	}
}

// firstN returns the first n runes of s (for concise hash display in logs).
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// runSalt dispatches a top-level `konareef salt` subcommand. Type-D
// pod salt management is a TOP-LEVEL command (NOT under `pod`) because
// it manages cross-pod secret state in the OS keyring / state dir, not
// pod-worktree state.
func runSalt(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef salt <subcommand>")
		fmt.Fprintln(os.Stderr, "  export <uuid>          export one lineage salt (passphrase-encrypted blob to stdout)")
		fmt.Fprintln(os.Stderr, "  export --all           export all lineages present in the active backend")
		fmt.Fprintln(os.Stderr, "  import <blob>          import a blob (use '-' for stdin)")
		fmt.Fprintln(os.Stderr, "  status                 list lineages + active backend")
		fmt.Fprintln(os.Stderr, "  delete <uuid> --yes-i-want-to-lose-this-pod")
		os.Exit(2)
	}
	switch args[0] {
	case "export":
		runSaltExport(args[1:])
	case "import":
		runSaltImport(args[1:])
	case "status":
		runSaltStatus(args[1:])
	case "delete":
		runSaltDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown salt subcommand: %q\n", args[0])
		os.Exit(2)
	}
}

// runSaltExport implements `konareef salt export <uuid>|--all`.
func runSaltExport(args []string) {
	fs := flag.NewFlagSet("salt export", flag.ExitOnError)
	all := fs.Bool("all", false, "export every lineage present in the active backend")
	output := fs.String("o", "", "write blob to this file instead of stdout")
	armor := fs.Bool("armor", false, "emit base64-armored output between PEM-style markers")
	fs.Parse(reorderFlagsFirst(args))

	backend, err := saltstore.Resolve(defaultResolveOpts())
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt export:", err)
		printSaltRemediation(os.Stderr, err)
		os.Exit(1)
	}
	var lids [][16]byte
	if *all {
		lids, err = backend.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, "salt export: list:", err)
			os.Exit(1)
		}
	} else if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef salt export <uuid> | --all")
		os.Exit(2)
	} else {
		raw, err := hex.DecodeString(strings.ReplaceAll(fs.Arg(0), "-", ""))
		if err != nil || len(raw) != 16 {
			fmt.Fprintln(os.Stderr, "salt export: lineage id must be 32 hex chars (UUID)")
			os.Exit(2)
		}
		var lid [16]byte
		copy(lid[:], raw)
		lids = [][16]byte{lid}
	}

	entries := make([]saltstore.Entry, 0, len(lids))
	for _, lid := range lids {
		salt, err := backend.Get(lid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "salt export: get %x: %v\n", lid, err)
			os.Exit(1)
		}
		entries = append(entries, saltstore.Entry{LineageID: lid, Salt: salt})
	}

	passphrase, err := readSaltPassphrase(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt export:", err)
		os.Exit(1)
	}
	blob, err := saltstore.ExportBlob(entries, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt export:", err)
		os.Exit(1)
	}
	if *armor {
		blob = saltstore.ArmorBlob(blob)
	}
	if *output != "" {
		if err := os.WriteFile(*output, blob, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "salt export: write:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %d-byte blob to %s (mode 0600)\n", len(blob), *output)
		return
	}
	_, _ = os.Stdout.Write(blob)
}

// runSaltImport implements `konareef salt import <blob-path>`.
func runSaltImport(args []string) {
	fs := flag.NewFlagSet("salt import", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing entries on lineage_id collision")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef salt import <blob-path> [--force]    ('-' reads stdin)")
		os.Exit(2)
	}
	var blob []byte
	if fs.Arg(0) == "-" {
		var err error
		blob, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "salt import: stdin:", err)
			os.Exit(1)
		}
	} else {
		var err error
		blob, err = os.ReadFile(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "salt import: read:", err)
			os.Exit(1)
		}
	}
	passphrase, err := readSaltPassphrase(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt import:", err)
		os.Exit(1)
	}
	entries, err := saltstore.ImportBlob(blob, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt import:", err)
		os.Exit(1)
	}
	backend, err := saltstore.Resolve(defaultResolveOpts())
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt import:", err)
		printSaltRemediation(os.Stderr, err)
		os.Exit(1)
	}
	for _, e := range entries {
		err := backend.Put(e.LineageID, e.Salt)
		if errors.Is(err, saltstore.ErrSaltAlreadyExists) {
			if !*force {
				fmt.Fprintf(os.Stderr, "salt import: lineage %x already exists; --force to overwrite\n", e.LineageID)
				continue
			}
			_ = backend.Delete(e.LineageID)
			if err := backend.Put(e.LineageID, e.Salt); err != nil {
				fmt.Fprintf(os.Stderr, "salt import: force-overwrite %x: %v\n", e.LineageID, err)
				os.Exit(1)
			}
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "salt import: put %x: %v\n", e.LineageID, err)
			os.Exit(1)
		}
	}
	fmt.Printf("imported %d lineage(s) into backend %q\n", len(entries), backend.Name())
}

// runSaltStatus implements `konareef salt status`.
func runSaltStatus(_ []string) {
	backend, err := saltstore.Resolve(defaultResolveOpts())
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt status:", err)
		printSaltRemediation(os.Stderr, err)
		os.Exit(1)
	}
	lids, err := backend.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt status: list:", err)
		os.Exit(1)
	}
	fmt.Printf("Active backend: %s\n", backend.Name())
	fmt.Printf("Lineages present: %d\n", len(lids))
	for _, lid := range lids {
		fmt.Printf("  %s\n", hex.EncodeToString(lid[:]))
	}
}

// runSaltDelete implements `konareef salt delete <uuid> --yes-i-want-to-lose-this-pod`.
func runSaltDelete(args []string) {
	fs := flag.NewFlagSet("salt delete", flag.ExitOnError)
	consent := fs.Bool("yes-i-want-to-lose-this-pod", false, "required to confirm the destructive action")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 || !*consent {
		fmt.Fprintln(os.Stderr, "usage: konareef salt delete <uuid> --yes-i-want-to-lose-this-pod")
		fmt.Fprintln(os.Stderr, "(Removing a Type-D salt is irreversible: the pod's witness becomes unrecoverable.)")
		os.Exit(2)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(fs.Arg(0), "-", ""))
	if err != nil || len(raw) != 16 {
		fmt.Fprintln(os.Stderr, "salt delete: lineage id must be 32 hex chars (UUID)")
		os.Exit(2)
	}
	var lid [16]byte
	copy(lid[:], raw)
	backend, err := saltstore.Resolve(defaultResolveOpts())
	if err != nil {
		fmt.Fprintln(os.Stderr, "salt delete:", err)
		printSaltRemediation(os.Stderr, err)
		os.Exit(1)
	}
	if err := backend.Delete(lid); err != nil {
		fmt.Fprintln(os.Stderr, "salt delete:", err)
		os.Exit(1)
	}
	fmt.Printf("deleted lineage %x from backend %q\n", lid, backend.Name())
}

// defaultResolveOpts builds the saltstore.ResolveOpts the CLI uses for
// every salt-touching subcommand. It wires:
//
//   - EncryptedFilePassphraseProvider → cliPassphraseProvider, so the
//     encrypted-file backend can prompt on first access when no keychain
//     is available. The provider's CanProvideNow() probe lets the
//     resolver skip the encrypted-file tier in non-interactive contexts
//     (no TTY + no KONAREEF_SALT_PASSPHRASE) instead of selecting it
//     and dying at first use — that is what makes the plain-file
//     opt-in fallback actually reachable.
//   - PlainFileOptIn → KONAREEF_ALLOW_PLAINTEXT_SALT=1 (or "true"),
//     gating the plain-file fallback behind an explicit user decision.
//
// SECURITY: without the opt-in env var, a host with no keychain AND no
// usable encrypted-file passphrase source will fail closed with
// ErrSaltStorageUnavailable rather than silently writing salts in
// cleartext to disk.
func defaultResolveOpts() saltstore.ResolveOpts {
	return saltstore.ResolveOpts{
		EncryptedFilePassphraseProvider: cliPassphraseProvider{},
		PlainFileOptIn:                  plaintextSaltOptIn(),
		// KONAREEF_DISABLE_KEYCHAIN_BACKEND lets hermetic CLI tests
		// (and headless CI environments) drop the keychain tier so
		// the resolver never reaches a macOS UI prompt that would
		// block a non-interactive subprocess.
		DisableKeychain: envBoolTruthy("KONAREEF_DISABLE_KEYCHAIN_BACKEND"),
	}
}

// envBoolTruthy returns true when the named env var is set to a
// truthy lower-cased value ("1", "true", "yes"). Empty is false.
func envBoolTruthy(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}

// saltRemediation returns operator-facing guidance for a salt-backend
// failure, or "" when err needs no special explanation.
//
// WHY THIS LIVES IN THE CLI, NOT IN saltstore: the sentinels in
// internal/saltstore are a stable machine-readable error catalog (PRD
// P1.7.1) whose Error() string IS the code — golden vectors and log
// greps depend on that. Human, platform-specific advice belongs at the
// surface the human is actually looking at.
//
// ErrSaltStorageUnavailable is the fail-closed outcome when no backend
// is usable. Failing closed is deliberate and correct: the alternative
// is silently writing salts in cleartext. But `konareef pod init` is
// the FIRST command of the quickstart and it resolves a salt backend,
// so on WSL, headless Linux, or a container — none of which run a
// Secret Service keyring — a new user hits this at step one. Emitting
// the bare code there strands them.
func saltRemediation(err error) string {
	if !errors.Is(err, saltstore.ErrSaltStorageUnavailable) {
		return ""
	}
	return `
konareef needs somewhere safe to keep this pod's genesis salt, and no
storage backend was usable on this host:

  • OS keyring     — unavailable. Common on WSL, headless Linux, and
                     containers, which run no Secret Service/keyring.
  • encrypted file — needs a passphrase, and none was available (no
                     interactive terminal, and KONAREEF_SALT_PASSPHRASE
                     is unset).

konareef will not fall back to storing salts unencrypted unless you ask
for that explicitly. Choose one:

  KONAREEF_SALT_PASSPHRASE=<passphrase>
      Keep salts in an encrypted file. Recommended — works everywhere,
      including WSL and CI.

  KONAREEF_DISABLE_KEYCHAIN_BACKEND=1
      Skip the keyring probe entirely. Pair with a passphrase above.

  KONAREEF_ALLOW_PLAINTEXT_SALT=1
      Last resort: salts stored unencrypted on disk.

Every pod gets a salt at ` + "`konareef pod init`" + `, so this applies to the
Hello World quickstart too. See https://konareef.ai/docs/troubleshooting/`
}

// printSaltRemediation writes salt-backend guidance to w when err has
// any. No-op for errors that need no explanation, so call sites stay
// one line.
func printSaltRemediation(w *os.File, err error) {
	if hint := saltRemediation(err); hint != "" {
		fmt.Fprintln(w, hint)
	}
}

// cliPassphraseProvider implements saltstore.PassphraseProvider for the
// CLI: it reads KONAREEF_SALT_PASSPHRASE when present, otherwise
// prompts on a real TTY. CanProvideNow honestly reports whether either
// source is currently available, so the resolver can skip the
// encrypted-file tier when the host is headless and no env var is
// configured.
type cliPassphraseProvider struct{}

// Get implements saltstore.PassphraseProvider.
func (cliPassphraseProvider) Get() ([]byte, error) {
	return readSaltPassphrase(false)
}

// CanProvideNow implements saltstore.PassphraseProvider. It returns
// true when KONAREEF_SALT_PASSPHRASE is set (non-empty) OR stdin is a
// terminal that can host a passphrase prompt. The check is
// side-effect-free: no prompting, no I/O beyond an env lookup and a
// TTY isatty probe.
func (cliPassphraseProvider) CanProvideNow() bool {
	if os.Getenv("KONAREEF_SALT_PASSPHRASE") != "" {
		return true
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// plaintextSaltOptIn reports whether the user opted into the
// plain-file salt backend via KONAREEF_ALLOW_PLAINTEXT_SALT. The check
// is permissive ("1" or any value that parses as truthy lowercase
// "true") so a curious user can flip it without reading the docs;
// the danger is documented in the salt-storage runbook.
func plaintextSaltOptIn() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("KONAREEF_ALLOW_PLAINTEXT_SALT")))
	return v == "1" || v == "true" || v == "yes"
}

// readSaltPassphrase reads a passphrase from the TTY (or from
// KONAREEF_SALT_PASSPHRASE for non-interactive automation). When
// confirm is true the user must enter the same passphrase twice
// (export path). Returns an error if neither source is available.
func readSaltPassphrase(confirm bool) ([]byte, error) {
	if v := os.Getenv("KONAREEF_SALT_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("no TTY and KONAREEF_SALT_PASSPHRASE unset; refusing to read passphrase from a non-tty stdin")
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read confirm: %w", err)
		}
		if string(pw) != string(pw2) {
			return nil, errors.New("passphrases do not match")
		}
	}
	if len(pw) == 0 {
		return nil, errors.New("empty passphrase")
	}
	return pw, nil
}

// runPod dispatches to a pod-related subcommand. The dispatcher is
// structured so additional subcommands (spawn, install, publish) can be
// slotted in without restructuring main.
func runPod(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod <subcommand>")
		fmt.Fprintln(os.Stderr, "  init <name>            scaffold a new pod directory")
		fmt.Fprintln(os.Stderr, "  validate <path>        validate a pod.toml against the v0.1 schema")
		fmt.Fprintln(os.Stderr, "  schema                 print the v0.1 JSON Schema this binary validates against")
		fmt.Fprintln(os.Stderr, "  safety <dir>           check context files for egress not declared in [network]")
		fmt.Fprintln(os.Stderr, "  identity <subcommand>  manage the publisher signing identity")
		fmt.Fprintln(os.Stderr, "  publish <dir>          sign and submit a pod to reef-core")
		fmt.Fprintln(os.Stderr, "  grants init <dir>      create sealed/grants.toml for a closed pod's brokered MCP grants")
		fmt.Fprintln(os.Stderr, "  listing <subcommand>   manage the pod's marketplace listing")
		fmt.Fprintln(os.Stderr, "  secret <subcommand>    bind, remove, or list author secrets for a published pod")
		fmt.Fprintln(os.Stderr, "  trust <handle>         record a publisher pubkey as locally trusted")
		fmt.Fprintln(os.Stderr, "  run <handle>/<pod>@<version>  spawn an installed pod and download its deliverables")
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		runPodInit(args[1:])
	case "validate":
		runPodValidate(args[1:])
	case "schema":
		runPodSchema(args[1:])
	case "safety":
		runPodSafety(args[1:])
	case "identity":
		runPodIdentity(args[1:])
	case "publish":
		runPodPublish(args[1:])
	case "grants":
		runPodGrants(args[1:])
	case "listing":
		runPodListing(args[1:])
	case "secret":
		runPodSecret(args[1:])
	case "trust":
		runPodTrust(args[1:])
	case "run":
		runPodRun(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown pod subcommand: %q\n", args[0])
		os.Exit(2)
	}
}

// runPodInit scaffolds a new pod directory with a starter pod.toml,
// prompts/system.md placeholder, and README. Exits 0 on success, 1 on
// init errors, 2 on usage errors.
func runPodInit(args []string) {
	fs := flag.NewFlagSet("pod init", flag.ExitOnError)
	runtime := fs.String("runtime", "", "runtime kind written into [runtime].kind (default: lobster)")
	model := fs.String("model", "", "model spec as <provider>/<name> (default: anthropic/claude-sonnet-4-5)")
	dir := fs.String("dir", "", "output directory (default: ./<name>)")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod init <name> [--runtime kind] [--model provider/name] [--dir path]")
		os.Exit(2)
	}
	name := fs.Arg(0)

	code := runPodInitCore(os.Stdout, os.Stderr, pod.InitOptions{
		Name:    name,
		Dir:     *dir,
		Runtime: *runtime,
		Model:   *model,
	})
	if code != 0 {
		os.Exit(code)
	}
}

// runPodInitTestHook, when non-nil, replaces the saltstore.Resolve()
// call inside runPodInitCore so a test can inject a failing backend
// and assert the rollback contract (no pod.toml / no pod directory
// after a salt-persist failure). Production code MUST leave this nil.
var runPodInitTestHook func() (saltstore.Backend, error)

// runPodInitCore is the testable core of `konareef pod init`. It
// enforces the B1+B2 genesis-salt contract atomically:
//
//  1. generate a 32-byte CSPRNG salt in memory,
//  2. scaffold the pod into a TEMPORARY directory next to the final
//     destination,
//  3. read the freshly-baked lineage_id from the temp scaffold,
//  4. persist (lineage_id, salt) via the resolved saltstore backend,
//  5. os.Rename(temp, final) — the pod directory only materialises
//     AFTER the salt is durable,
//  6. print the user-facing recovery notice.
//
// SECURITY: on ANY failure between steps 2 and 4 the temp directory is
// removed; on a step-4 failure the temp directory is also removed so
// the user never sees a pod.toml whose lineage_id has no salt persisted
// behind it (a previous regression that left "valid-looking" pods on
// disk that could not be re-spawned).
//
// Returns 0 on full success, 1 on any failure. Writes diagnostics to
// stderr; writes the success summary + recovery notice to stdout.
func runPodInitCore(stdout, stderr *os.File, opts pod.InitOptions) int {
	finalDir := opts.Dir
	if finalDir == "" {
		finalDir = "./" + opts.Name
	}
	// Pre-flight: refuse early if the final destination already
	// exists. pod.Init would also reject it, but we want a clean error
	// before we even touch the salt backend.
	if _, err := os.Stat(finalDir); err == nil {
		fmt.Fprintf(stderr, "init error: directory %s already exists; pick a different name or remove it first\n", finalDir)
		return 1
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(stderr, "init: stat destination:", err)
		return 1
	}

	// CSPRNG-generate the 32-byte salt in memory before any
	// filesystem work. If the CSPRNG read fails the pod tree is
	// never created.
	var salt [32]byte
	if _, err := cryptorand.Read(salt[:]); err != nil {
		fmt.Fprintln(stderr, "init: generate genesis salt:", err)
		return 1
	}

	// Scaffold into a sibling temp directory so we can atomically
	// rename to finalDir on success, or os.RemoveAll on any failure
	// between here and Backend.Put.
	parent := filepath.Dir(finalDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		fmt.Fprintln(stderr, "init: mkdir parent:", err)
		return 1
	}
	tempDir, err := os.MkdirTemp(parent, ".konareef-init-*")
	if err != nil {
		fmt.Fprintln(stderr, "init: mkdir tempdir:", err)
		return 1
	}
	// Tempdir is now ours; ensure it is removed on any failure path.
	rollback := func() {
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			fmt.Fprintf(stderr, "init: rollback warning: %v\n", rmErr)
		}
	}
	// pod.Init rejects an existing destination — we need to delete the
	// freshly-created tempdir so pod.Init can write into it itself.
	if err := os.Remove(tempDir); err != nil {
		rollback()
		fmt.Fprintln(stderr, "init: clear tempdir:", err)
		return 1
	}
	tempOpts := opts
	tempOpts.Dir = tempDir
	written, err := pod.Init(tempOpts)
	if err != nil {
		rollback()
		fmt.Fprintln(stderr, "init error:", err)
		return 1
	}

	// Read the lineage_id pod.Init baked into the temp scaffold's
	// pod.toml. This is the key we will persist the salt under.
	spec, err := pod.ParseFile(filepath.Join(tempDir, "pod.toml"))
	if err != nil {
		rollback()
		fmt.Fprintln(stderr, "init: re-parse scaffolded pod.toml:", err)
		return 1
	}
	lid, err := saltstore.LineageIDFromManifest(&spec)
	if err != nil {
		rollback()
		fmt.Fprintln(stderr, "init: lineage_id missing from scaffolded pod.toml:", err)
		return 1
	}

	// Resolve the backend and persist BEFORE the pod tree is moved
	// into its final location. INVARIANT: a visible pod.toml at
	// finalDir is only possible AFTER Backend.Put returns nil.
	var backend saltstore.Backend
	if runPodInitTestHook != nil {
		backend, err = runPodInitTestHook()
	} else {
		backend, err = saltstore.Resolve(defaultResolveOpts())
	}
	if err != nil {
		rollback()
		fmt.Fprintln(stderr, "init: resolve salt backend:", err)
		// `pod init` is step one of the quickstart, so this is the
		// most likely place a brand-new user meets a keyring-less
		// host (WSL, headless Linux, containers).
		printSaltRemediation(stderr, err)
		return 1
	}
	if err := backend.Put(lid, salt); err != nil {
		rollback()
		fmt.Fprintf(stderr, "init: persist genesis salt for lineage %x: %v\n", lid, err)
		return 1
	}

	// Salt is durable; finalise the pod tree.
	if err := os.Rename(tempDir, finalDir); err != nil {
		// Salt was persisted but we cannot show the user a pod
		// directory; back out the salt entry so the next attempt
		// can retry cleanly.
		_ = backend.Delete(lid)
		rollback()
		fmt.Fprintln(stderr, "init: finalise pod directory:", err)
		return 1
	}

	// Rewrite the written-file paths from the temp prefix to the
	// final destination so the user-facing output references the
	// real on-disk paths.
	rewritten := make([]string, 0, len(written))
	for _, path := range written {
		rel, relErr := filepath.Rel(tempDir, path)
		if relErr != nil {
			rewritten = append(rewritten, path)
			continue
		}
		rewritten = append(rewritten, filepath.Join(finalDir, rel))
	}

	fmt.Fprintf(stdout, "created pod %q (%d files)\n", opts.Name, len(rewritten))
	for _, path := range rewritten {
		fmt.Fprintln(stdout, "  ", path)
	}
	if len(rewritten) > 0 {
		fmt.Fprintf(stdout, "\nNext: konareef pod validate %s\n", rewritten[0])
		fmt.Fprintln(stdout)
		// INVARIANT: pod.Init + Backend.Put + Rename all succeeded → the
		// salt is now persisted in the resolved backend AND the pod
		// tree is visible. The recovery notice is the user-facing
		// contract that the salt is durable.
		fmt.Fprintln(stdout, "If this is a Type-D (--disclosure-policy D) pod, your 32-byte salt")
		fmt.Fprintln(stdout, "is now persisted via `konareef salt`. Run `konareef salt export`")
		fmt.Fprintln(stdout, "to back up the salt — loss is irrecoverable.")
	}
	return 0
}

// runPodValidate implements `konareef pod validate <path>`. It prints
// "<path>: valid" and exits 0 when the schema and the cross-field rules
// pass, printing any advisory warnings to stderr first. Issues go to
// stderr and exit 1. An unreadable file or a malformed document exits 1.
func runPodValidate(args []string) {
	fs := flag.NewFlagSet("pod validate", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod validate <pod.toml-path>")
		os.Exit(2)
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate error:", err)
		os.Exit(1)
	}
	issues, warnings, err := pod.ValidateWithWarnings(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate error:", err)
		os.Exit(1)
	}
	// Sealed closed-pod grants (G1–G16) need a head that passed the
	// schema, the same precondition the cross-field rules have.
	if len(issues) == 0 {
		sealedIssues, sealedWarnings, err := validateSealedGrantsForCLI(path, data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "validate error:", err)
			os.Exit(1)
		}
		issues = append(issues, sealedIssues...)
		warnings = append(warnings, sealedWarnings...)
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, " warning:", warning)
	}
	// Advisory only: publish is what refuses a credential in the bundle.
	warnBundleCredentials(os.Stderr, filepath.Dir(path))
	if len(issues) == 0 {
		fmt.Printf("%s: valid\n", path)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %d validation issue(s)\n", path, len(issues))
	for _, issue := range issues {
		fmt.Fprintln(os.Stderr, " -", issue)
	}
	os.Exit(1)
}

// runPodSchema implements `konareef pod schema`. It prints the v0.1 JSON
// Schema embedded in this binary to stdout.
//
// The schema is what `konareef pod validate` enforces. Printing it gives
// tooling and coding agents the exact shape to author against, instead of a
// reconstruction from prose that can disagree with the binary silently.
func runPodSchema(args []string) {
	fs := flag.NewFlagSet("pod schema", flag.ExitOnError)
	fs.Parse(args)

	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod schema")
		os.Exit(2)
	}

	out := pod.SchemaJSON()
	os.Stdout.Write(out)
	if len(out) == 0 || out[len(out)-1] != '\n' {
		fmt.Println()
	}
}

// runPodIdentity dispatches to a `pod identity` subcommand. The
// surface today is `create` and `show`; encrypted export/import lands
// in a follow-up commit (the publish path needs only create + show).
func runPodIdentity(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod identity <subcommand>")
		fmt.Fprintln(os.Stderr, "  create [--handle <h>]                       generate a new publisher keypair")
		fmt.Fprintln(os.Stderr, "  show                                        print the current handle and public key")
		fmt.Fprintln(os.Stderr, "  export --output <path>                      passphrase-encrypted backup of the identity (prompts on TTY)")
		fmt.Fprintln(os.Stderr, "  import <path>                               restore the identity from an encrypted backup (prompts on TTY)")
		fmt.Fprintln(os.Stderr, "  rotate [--reason <text>] [--server URL]     generate a new keypair, sign a rotation attestation, submit to reef-core")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		runPodIdentityCreate(args[1:])
	case "show":
		runPodIdentityShow(args[1:])
	case "export":
		runPodIdentityExport(args[1:])
	case "import":
		runPodIdentityImport(args[1:])
	case "rotate":
		runPodIdentityRotate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown identity subcommand: %q\n", args[0])
		os.Exit(2)
	}
}

// runPodIdentityCreate generates a fresh secp256k1 keypair, binds it
// to --handle, and saves it to <home>/.konareef/identity.json (mode
// 0600). An existing identity is preserved unless --force is given —
// losing a key means losing control of the bound handle.
//
// Exits 0 on success, 1 on I/O / key-gen failure, 2 on usage error.
func runPodIdentityCreate(args []string) {
	fs := flag.NewFlagSet("pod identity create", flag.ExitOnError)
	handle := fs.String("handle", "", "publisher handle to bind to the new keypair (required)")
	force := fs.Bool("force", false, "overwrite an existing identity file (destroys the prior key)")
	fs.Parse(args)

	if *handle == "" {
		fmt.Fprintln(os.Stderr, "konareef pod identity create: --handle is required")
		os.Exit(2)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity create: locate home directory:", err)
		os.Exit(1)
	}
	if _, err := os.Stat(identity.Path(home)); err == nil && !*force {
		fmt.Fprintf(os.Stderr,
			"identity create: %s already exists; pass --force to overwrite (this destroys the prior key)\n",
			identity.Path(home),
		)
		os.Exit(1)
	}

	id, err := identity.Generate(*handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity create: generate keypair:", err)
		os.Exit(1)
	}
	if err := id.Save(home); err != nil {
		fmt.Fprintln(os.Stderr, "identity create: save:", err)
		os.Exit(1)
	}

	fmt.Println("✓ Generated secp256k1 keypair")
	fmt.Printf("✓ Saved to %s (mode 0600)\n\n", identity.Path(home))
	fmt.Printf("  Handle:     %s\n", id.Handle)
	fmt.Printf("  Public key: %s\n\n", id.PublicKeyHex)
	fmt.Println("  Back up this file before publishing your first pod.")
	fmt.Printf("  Losing the private key means losing control of the handle %q.\n", id.Handle)
}

// runPodIdentityShow prints the current identity's handle and public
// key. It NEVER prints the private key — that field of identity.json
// is a credential, and a `show` command that leaked it would be a
// foot-gun every shell-history grep waits for.
//
// Exits 0 on success, 1 if no identity exists or perms are wrong.
func runPodIdentityShow(args []string) {
	fs := flag.NewFlagSet("pod identity show", flag.ExitOnError)
	fs.Parse(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity show: locate home directory:", err)
		os.Exit(1)
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity show:", err)
		os.Exit(1)
	}
	fmt.Printf("Handle:     %s\n", id.Handle)
	fmt.Printf("Public key: %s\n", id.PublicKeyHex)
	fmt.Printf("Scheme:     %s\n", id.Scheme)
	fmt.Printf("Created at: %s\n", id.CreatedAt.Format(time.RFC3339))
}

// runPodIdentityExport writes a passphrase-encrypted backup of the
// local identity to --output. The passphrase MUST be supplied via
// --passphrase-file <path> (interactive prompting is a deliberate
// follow-up — file-based input is scriptable and CI-safe).
//
// Exits 0 on success, 1 on I/O / crypto failure, 2 on usage error.
func runPodIdentityExport(args []string) {
	fs := flag.NewFlagSet("pod identity export", flag.ExitOnError)
	output := fs.String("output", "", "destination path for the encrypted backup (required)")
	passFile := fs.String("passphrase-file", "", "file containing the passphrase (required; trailing newlines trimmed)")
	force := fs.Bool("force", false, "overwrite the output file if it exists")
	fs.Parse(reorderFlagsFirst(args))

	if *output == "" {
		fmt.Fprintln(os.Stderr, "konareef pod identity export: --output is required")
		os.Exit(2)
	}

	passphrase, err := resolvePassphrase(*passFile, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity export:", err)
		os.Exit(1)
	}

	if _, err := os.Stat(*output); err == nil && !*force {
		fmt.Fprintf(os.Stderr,
			"identity export: %s already exists; pass --force to overwrite\n", *output)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity export: locate home directory:", err)
		os.Exit(1)
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity export:", err)
		os.Exit(1)
	}
	if err := id.Export(*output, passphrase); err != nil {
		fmt.Fprintln(os.Stderr, "identity export:", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Wrote encrypted backup to %s (mode 0600)\n", *output)
	fmt.Println("  Keep the passphrase separately from the file. Losing")
	fmt.Println("  either makes the backup useless.")
}

// runPodIdentityImport restores an identity from an encrypted backup
// into <home>/.konareef/identity.json. An existing identity at the
// target is preserved unless --force is passed — losing a key means
// losing control of the handle bound to it.
//
// Exits 0 on success, 1 on I/O / crypto / wrong-passphrase failure,
// 2 on usage error.
func runPodIdentityImport(args []string) {
	fs := flag.NewFlagSet("pod identity import", flag.ExitOnError)
	passFile := fs.String("passphrase-file", "", "file containing the passphrase (required; trailing newlines trimmed)")
	force := fs.Bool("force", false, "overwrite an existing identity file at the target")
	fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod identity import <backup-path> --passphrase-file <path> [--force]")
		os.Exit(2)
	}
	backupPath := fs.Arg(0)

	passphrase, err := resolvePassphrase(*passFile, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity import:", err)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity import: locate home directory:", err)
		os.Exit(1)
	}
	if _, err := os.Stat(identity.Path(home)); err == nil && !*force {
		fmt.Fprintf(os.Stderr,
			"identity import: %s already exists; pass --force to overwrite (this destroys the current key)\n",
			identity.Path(home),
		)
		os.Exit(1)
	}

	id, err := identity.Import(backupPath, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity import:", err)
		os.Exit(1)
	}
	if err := id.Save(home); err != nil {
		fmt.Fprintln(os.Stderr, "identity import: save:", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Restored identity to %s (mode 0600)\n\n", identity.Path(home))
	fmt.Printf("  Handle:     %s\n", id.Handle)
	fmt.Printf("  Public key: %s\n", id.PublicKeyHex)
}

// runPodIdentityRotate rotates the local publisher identity to a
// freshly-generated keypair, registering the change with reef-core
// so future installs walk a valid chain (old key → new key) at the
// TrustChange branch of `konareef install`.
//
// Pipeline (atomic enough for a CLI — any failure before the final
// Save leaves the existing identity.json untouched):
//
//  1. Load the current identity (becomes "old key").
//  2. Generate a fresh keypair under the same handle ("new key").
//  3. Build the attestation, sign Canonical(att) with the OLD key.
//  4. POST to /api/publishers/<handle>/rotate — reef-core verifies
//     the signature, records the rotation, and swings the
//     publisher_identities row to the new key atomically.
//  5. Archive the old identity.json to
//     ~/.konareef/identity.<old-fingerprint>.archived.json (mode 0600).
//     Kept around so a misfire is recoverable.
//  6. Save the new identity to ~/.konareef/identity.json (mode 0600).
//
// Exits 0 on success, 1 on any pipeline failure, 2 on usage error.
func runPodIdentityRotate(args []string) {
	fs := flag.NewFlagSet("pod identity rotate", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	reason := fs.String("reason", "", "optional free-text reason recorded in the attestation")
	fs.Parse(reorderFlagsFirst(args))

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate:", err)
		os.Exit(2)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate: locate home directory:", err)
		os.Exit(1)
	}

	oldID, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate:", err)
		fmt.Fprintln(os.Stderr, "  (run `konareef pod identity create --handle <h>` first)")
		os.Exit(1)
	}

	newID, err := identity.Generate(oldID.Handle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate: generate new keypair:", err)
		os.Exit(1)
	}

	att := identity.RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       oldID.Handle,
		OldPubkeyHex: oldID.PublicKeyHex,
		NewPubkeyHex: newID.PublicKeyHex,
		// Microsecond-precision UTC ISO-8601, matching the format
		// reef-core's RotationCanonical emits (and the format the
		// server stores into rotated_at).
		RotatedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		Reason:    *reason,
	}

	sig, err := oldID.SignRotation(att)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate: sign attestation:", err)
		os.Exit(1)
	}

	oldFp, _ := install.Fingerprint(oldID.PublicKeyHex)
	newFp, _ := install.Fingerprint(newID.PublicKeyHex)

	fmt.Printf("Rotating identity for handle %q\n", oldID.Handle)
	fmt.Printf("  old key: %s\n", oldFp)
	fmt.Printf("  new key: %s\n\n", newFp)

	fmt.Printf("POST %s/api/publishers/%s/rotate\n",
		strings.TrimRight(resolvedServer, "/"), oldID.Handle)
	resp, err := identity.SubmitRotation(resolvedServer, oldID.Handle, att, sig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Registered rotation (id=%s) at %s\n\n",
		resp.RotationID, resp.RegisteredAt)

	// Archive the old identity. Use a fingerprint-suffixed name so a
	// publisher who rotates more than once still has every prior key
	// on disk — naming on (pubkey-hash) prevents collision without
	// needing a counter.
	archivePath := filepath.Join(home, ".konareef",
		fmt.Sprintf("identity.%s.archived.json",
			strings.ReplaceAll(oldFp, ":", "")))
	oldBytes, err := os.ReadFile(identity.Path(home))
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"identity rotate: warning: failed to read current identity for archive: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(archivePath, oldBytes, 0o600); err != nil {
		fmt.Fprintf(os.Stderr,
			"identity rotate: failed to archive old identity to %s: %v\n", archivePath, err)
		os.Exit(1)
	}
	fmt.Printf("✓ Archived old identity to %s (mode 0600)\n", archivePath)

	if err := newID.Save(home); err != nil {
		fmt.Fprintln(os.Stderr, "identity rotate: save new identity:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Wrote new identity to %s (mode 0600)\n", identity.Path(home))
}

// readPassphraseFile reads a passphrase from path, trimming a single
// trailing newline (so a passphrase file authored with `echo` works
// as expected) but preserving every other byte.
func readPassphraseFile(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file: %w", err)
	}
	if n := len(body); n > 0 && body[n-1] == '\n' {
		body = body[:n-1]
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("passphrase file %s is empty", path)
	}
	return body, nil
}

// readPassphraseInteractive prompts on the controlling terminal with
// echo disabled and returns the typed passphrase. When confirm is
// true the user must type the passphrase twice (for new-passphrase
// flows like `identity export`); the second prompt's bytes must
// match exactly. Newline is printed after each prompt so the next
// console line starts cleanly.
//
// A non-TTY stdin (piped, redirected) returns an error rather than
// silently reading the passphrase from the pipe — that path is
// already covered by --passphrase-file and reading from a pipe
// invisibly would be a foot-gun in scripts.
func readPassphraseInteractive(confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf(
			"stdin is not a terminal and --passphrase-file was not provided")
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("passphrase is empty")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pw2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read passphrase confirmation: %w", err)
		}
		if string(pw) != string(pw2) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return pw, nil
}

// humanDaysAgo renders a UTC timestamp as a "N days ago"-style
// phrase for the install summary's "last verified" line. Same day
// collapses to "today"; a single 24h interval shows "1 day ago"
// (singular). Negative deltas (clock skew, future timestamps) are
// also treated as "today".
func humanDaysAgo(t time.Time) string {
	days := int(time.Now().UTC().Sub(t).Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", days)
	}
}

// resolvePassphrase routes between --passphrase-file (scriptable,
// CI-safe) and an interactive TTY prompt (the default when a human
// is at the keyboard). confirm gates the "type it twice" flow used
// when the passphrase is being set, not just verified.
func resolvePassphrase(passphraseFile string, confirm bool) ([]byte, error) {
	if passphraseFile != "" {
		return readPassphraseFile(passphraseFile)
	}
	return readPassphraseInteractive(confirm)
}

// runPodPublish signs and submits a pod to reef-core. Composes the
// existing primitives: pod.ParseAndValidate → canon.Canonicalize →
// identity.Sign → publish.Submit. The --dry-run flag stops after
// signing — useful for offline verification and for the period
// before reef-core's POST /api/pods endpoint (P0.6 6d) ships.
//
// Server URL precedence: --server flag → $KONAREEF_SERVER → the
// TUI's default (http://localhost:4000). The winner is validated by
// resolveServerURL BEFORE the identity is loaded and Prepare signs the
// manifest, so a malformed or misleading base URL can never turn into a
// publisher signature addressed to a non-reef-core origin.
//
// Exits 0 on success, 1 on any pipeline failure, 2 on usage error.
//
// The Tier-2 anchor backend (`publishAnchorBackend`) and the default
// vkey resolver (`newDefaultResolver`) used by the `--pin-circuit-vkey`
// and `--zk` flows are defined in build-tag-gated companion files:
//
//   - main_anchor_backend.go        (production, `!testhooks`)
//   - main_anchor_backend_testhook.go (`testhooks` build only)
//   - main_resolver.go              (production, `!testhooks`)
//   - main_resolver_testhook.go     (`testhooks` build only)
//
// Production builds (no `-tags testhooks`) fail closed: anchor lookups
// always return ErrAnchorNotFound (no BSV wallet wiring yet, P1.8) and
// Tier-1 vkey fetches always hit the real `https://paygate-zk.<domain>`
// well-known URL. The test-hook variants add env-var seams
// (KONAREEF_TEST_ANCHOR_HASH_HEX, KONAREEF_TEST_VKEY_BASE_URL) used by
// the e2e CLI tests and are unreachable from release binaries.

// defaultServerURL is the reef-core base URL used when neither
// `--server` nor `$KONAREEF_SERVER` is set — the local dev instance.
const defaultServerURL = "http://localhost:4000"

// resolveServerURL applies the reef-core base URL precedence
// (--server flag → $KONAREEF_SERVER → defaultServerURL) and validates
// the winner with internal/serverurl.
//
// Input: flagValue — the raw `--server` flag value ("" when unset).
// Output: the resolved base URL, or an error wrapping
// serverurl.ErrInvalidServerURL naming the rule that failed.
//
// Callers MUST call this before loading an identity or signing
// anything. On the publish and listing endpoints the publisher's
// signature is the credential, so a misleading or malformed base URL
// would otherwise hand a valid signature plus pubkey to a non-reef-core
// origin; failing here means nothing is signed and no request is sent.
func resolveServerURL(flagValue string) (string, error) {
	resolved := flagValue
	if resolved == "" {
		resolved = os.Getenv("KONAREEF_SERVER")
	}
	if resolved == "" {
		resolved = defaultServerURL
	}
	if _, err := serverurl.Parse(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// parseListingRevision parses the --revision flag as a strictly base-10
// integer in 0..listing.MaxRevision.
//
// Input: s — the raw flag value. Output: the revision, or an error
// naming the rule that failed.
//
// Base 10 and integers only, for the same reason as the fee: "0x10"
// must not silently mean 16, and "1.0" must not be accepted at all —
// reef-core renders the revision into the signed preimage as a base-10
// integer, so "1.0" would be a second preimage for the same logical
// revision and a 400 at its boundary.
func parseListingRevision(s string) (int64, error) {
	rev, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"--revision %q is not a plain decimal integer "+
				"(no 0x/0b/0o prefixes, underscores, decimal points or signs)", s)
	}
	if rev < 0 {
		return 0, fmt.Errorf("--revision must not be negative, got %d", rev)
	}
	if rev > listing.MaxRevision {
		return 0, fmt.Errorf("--revision must be at most %d, got %d", listing.MaxRevision, rev)
	}
	return rev, nil
}

func runPodPublish(args []string) {
	fs := flag.NewFlagSet("pod publish", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	dryRun := fs.Bool("dry-run", false, "validate + canonicalize + sign locally; skip the POST")
	confirmPublish := fs.Bool(confirmFlagPublish, false,
		"the developer has confirmed this publish (skips the interactive prompt; does not authorise `pod run`)")
	publicBundle := fs.Bool("public-bundle", false,
		"opt this publication into the public verifiable bundle endpoint (default off — only the sanitized display bundle is public)")

	// P1.3 — ZK opt-in flags (PRD 4 § 4.3).
	circuitID := fs.String("circuit-id", "",
		"pin the publication to a specific circuit_id (konareef-pod-step-v1 or konareef-pod-step-v1.1); mandatory with --zk")
	pinCircuitVkey := fs.Bool("pin-circuit-vkey", false,
		"trigger on-chain anchor of the active circuit's vkey (no-op if anchor already exists); requires --circuit-id")
	disclosurePolicy := fs.String("disclosure-policy", "",
		"per-session disclosure policy {C|D}; mandatory with --zk (case-insensitive)")
	zk := fs.Bool("zk", false,
		"opt into the ZK publication path (sets published_pods.zk_enabled = true)")

	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr,
			"usage: konareef pod publish <pod-dir> [--server URL] [--dry-run] "+
				"[--public-bundle] [--zk --circuit-id <id> --disclosure-policy {C|D}] "+
				"[--pin-circuit-vkey]")
		os.Exit(2)
	}
	podDir := fs.Arg(0)

	// Normalise --disclosure-policy to upper-case so "c" / "C" / "d" / "D"
	// all reach ValidateZKFlags in canonical form.
	normalisedPolicy := strings.ToUpper(*disclosurePolicy)

	flags := publish.ZKFlags{
		CircuitID:        *circuitID,
		PinCircuitVkey:   *pinCircuitVkey,
		DisclosurePolicy: normalisedPolicy,
		ZK:               *zk,
	}
	if err := publish.ValidateZKFlags(flags); err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(2)
	}

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(2)
	}

	// A credential-shaped string in any bundle file is a refusal, not a
	// warning: a key that is published stays published. It runs before
	// Prepare, which may rewrite files on disk, and before anything is signed.
	if code := bundleCredentialGate(podDir, "publish"); code != 0 {
		os.Exit(code)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish: locate home directory:", err)
		os.Exit(1)
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		fmt.Fprintln(os.Stderr, "  (run `konareef pod identity create --handle <h>` first)")
		os.Exit(1)
	}

	// Advisory at publish time. The hard gate is at `pod listing publish`,
	// which is the step that exposes a pod to strangers — see
	// warnPodSafety for why publishing is deliberately not blocked.
	warnPodSafety(podDir)

	// Sealed closed-pod grants: read the server's capabilities before
	// Prepare, which may add the carrier (always-emit) or rotate its
	// salt on disk.
	sealedPlan, err := planSealedGrantsPublish(podDir, resolvedServer, *dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
	prepOpts := sealedPlan.prepareOptions(flags.ZK, *dryRun)
	prepOpts.DisclosurePolicy = flags.DisclosurePolicy
	// Memory-bearing --zk publish reads the lineage salt before
	// canonicalizing, because r_init is inside the signed bytes
	// (konareef-rinit/v1 R-M12). The gate is off in every build, so this
	// never provisions a salt today; see publish.MemoryPublishEnabled.
	if flags.ZK && publish.MemoryPublishEnabled() {
		prepOpts.MemorySalt = func(spec *pod.Spec) ([32]byte, error) {
			backend, berr := saltstore.Resolve(defaultResolveOpts())
			if berr != nil {
				return [32]byte{}, berr
			}
			_, salt, serr := publish.EnsureSaltForTypeD(flags, spec, backend)
			return salt, serr
		}
	}
	prep, err := publish.Prepare(podDir, id, prepOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
	for _, warning := range prep.Warnings {
		fmt.Fprintln(os.Stderr, " warning:", warning)
	}
	reportSealedGrantsPrepared(prep.SealedGrants)

	fmt.Println("✓ Validated pod.toml against v0.1 schema")
	fmt.Printf("✓ Canonicalized manifest (%d bytes)\n", len(prep.CanonicalBytes))
	fmt.Printf("  pod_hash: sha256:%x\n", prep.PodHash)
	fmt.Printf("✓ Signed manifest with identity %q\n", prep.Handle)
	fmt.Printf("  signature: %x\n\n", prep.Signature)

	// --pin-circuit-vkey: handle BEFORE the publish branch so it can
	// run standalone (PRD 4 § 4.3.2). Fail-closed: this halts the
	// publish on ErrAnchorBroadcastUnsupported (no broadcast path
	// until P1.8) and on ErrCircuitPinMismatch (on-chain anchor hash
	// disagrees with the resolved vkey). The Tier-2 anchor backend is
	// the package-level seam `publishAnchorBackend`.
	if flags.PinCircuitVkey {
		manifest, err := publish.FetchDiscoveryManifest(context.Background(), resolvedServer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish: --pin-circuit-vkey:", err)
			os.Exit(1)
		}
		pin, ok := manifest.VkeySha256For(flags.CircuitID)
		if !ok {
			fmt.Fprintf(os.Stderr,
				"publish: --pin-circuit-vkey: circuit %q not advertised in discovery manifest\n",
				flags.CircuitID)
			os.Exit(1)
		}
		// VHASH versioning review I-2: for v1.1 the verifier gate pins the
		// vkey (vkeystore/known.go). Refuse to anchor a vkey that gate would
		// refuse. v1 is left as before (legacy artifacts carry other pins).
		if flags.CircuitID == vkeystore.CircuitIDPodStepV1_1 {
			if known, _ := vkeystore.KnownVkeySha256For(flags.CircuitID); pin != known {
				fmt.Fprintf(os.Stderr,
					"publish: --pin-circuit-vkey: discovery advertises vkey_sha256 %s for %s, but this build pins %s\n",
					pin, flags.CircuitID, known)
				os.Exit(1)
			}
		}
		resolver, err := newDefaultResolver()
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish: --pin-circuit-vkey:", err)
			os.Exit(1)
		}
		// MR !21 round-2 B2 (note 680): strip the `paygate-zk.` prefix
		// off the discovery `paygate_zk_domain` (service host) before
		// passing to the resolver, which expects the publisher BASE
		// domain and rejects already-prefixed inputs with
		// ErrDomainAlreadyPrefixed.
		baseDomain, err := publish.PublisherBaseDomain(manifest.PaygateZKDomainHost())
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish: --pin-circuit-vkey:", err)
			os.Exit(1)
		}
		vkey, err := resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
			CircuitID:       flags.CircuitID,
			VkeySha256:      pin,
			PublisherDomain: baseDomain,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish: --pin-circuit-vkey:", err)
			os.Exit(1)
		}
		if _, anchorErr := publish.EnsureVkeyAnchor(
			context.Background(), publishAnchorBackend, flags.CircuitID, vkey.Bytes); anchorErr != nil {
			fmt.Fprintln(os.Stderr, "publish: --pin-circuit-vkey:", anchorErr)
			os.Exit(1)
		}
		fmt.Println("✓ --pin-circuit-vkey: existing on-chain anchor verified (no-op)")
		// Standalone --pin-circuit-vkey: exit if no further publish
		// work was requested.
		if !flags.ZK && !*publicBundle {
			return
		}
	}

	if *dryRun {
		fmt.Printf("DRY RUN — skipping POST to %s/api/pods\n",
			strings.TrimRight(resolvedServer, "/"))
		return
	}

	if err := checkSealedGrantsBeforeSubmit(sealedPlan, prep.SealedGrants); err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}

	// Past this point the pod reaches the server. The gate sits after the
	// dry-run return so rehearsal stays free and unprompted, and before the
	// --zk salt provisioning below, so a refusal costs nothing.
	confirmOrExit(*confirmPublish, confirmFlagPublish, fmt.Sprintf(
		"publish %s/%s@%s to %s — a signed artifact under your publisher identity, which you cannot unpublish",
		prep.Handle, prep.PodName, prep.PodVersion, strings.TrimRight(resolvedServer, "/")))

	// --zk: pre-session pin check + Type-D salt provisioning + witness
	// seal. All three fail-closed BEFORE publish.Submit.
	var sealedWitness *publish.Witness
	var sealedLineageID [16]byte
	var sealedSalt [32]byte
	if flags.ZK {
		fmt.Println("✓ ZK opt-in:")
		fmt.Printf("  circuit_id:        %s\n", flags.CircuitID)
		fmt.Printf("  disclosure_policy: %s\n", flags.DisclosurePolicy)

		manifest, err := publish.FetchDiscoveryManifest(context.Background(), resolvedServer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish: discovery manifest:", err)
			os.Exit(1)
		}
		resolver, err := newDefaultResolver()
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish:", err)
			os.Exit(1)
		}
		if err := publish.PreflightPinCheck(
			context.Background(), resolver, flags, manifest); err != nil {
			fmt.Fprintln(os.Stderr, "publish:", err)
			os.Exit(1)
		}

		// Type-D salt provisioning. EnsureSaltForTypeD is a no-op for
		// Type-C; for Type-D it requires a saltstore backend.
		var saltBackend saltstore.Backend
		if flags.DisclosurePolicy == "D" {
			saltBackend, err = saltstore.Resolve(defaultResolveOpts())
			if err != nil {
				fmt.Fprintln(os.Stderr, "publish:", err)
				printSaltRemediation(os.Stderr, err)
				os.Exit(1)
			}
		}
		lineageID, salt, err := publish.EnsureSaltForTypeD(flags, prep.Spec, saltBackend)
		if err != nil {
			fmt.Fprintln(os.Stderr, "publish:", err)
			os.Exit(1)
		}
		sealedLineageID = lineageID
		sealedSalt = salt
		if flags.DisclosurePolicy == "D" {
			fmt.Printf("  lineage_id:        %x\n", sealedLineageID)
			fmt.Println("  ✓ Type-D salt provisioned + persisted via saltstore")
		}

		// Seal the witness disclosure policy. After this point the
		// session's policy is irrevocable.
		sealedWitness = &publish.Witness{
			LineageID: sealedLineageID,
			Salt:      sealedSalt,
		}
		if err := publish.SealDisclosurePolicy(flags, sealedWitness); err != nil {
			fmt.Fprintln(os.Stderr, "publish:", err)
			os.Exit(1)
		}
	}

	submitOpts := publish.SubmitOpts{
		PublicBundle:     *publicBundle,
		CircuitID:        flags.CircuitID,
		ZkEnabled:        flags.ZK,
		DisclosurePolicy: flags.DisclosurePolicy,
		Witness:          sealedWitness,
	}
	maybeDumpSubmitOpts(submitOpts)
	resp, err := publish.Submit(resolvedServer, prep, submitOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
	fmt.Printf("POST %s/api/pods\n", strings.TrimRight(resolvedServer, "/"))
	fmt.Printf("✓ Pod registered as %s/%s v%s\n", prep.Handle, prep.PodName, prep.PodVersion)
	if *publicBundle {
		fmt.Println("  ⚠  publicly verifiable bundle ENABLED — every commitment in every run of this pod will be downloadable verbatim from the public bundle endpoint")
	}
	if flags.ZK {
		fmt.Println("  ⚠  ZK path ENABLED — v2 bundle emission active")
	}
	fmt.Printf("  install URL: %s\n", resp.InstallURL)
	if !resp.RegisteredAt.IsZero() {
		fmt.Printf("  registered at: %s\n", resp.RegisteredAt.Format(time.RFC3339))
	}
}

// podListingUsage is the single usage string every usage-error path in
// the listing handler prints, so the flag set and the error message can
// never drift apart.
const podListingUsage = "usage: konareef pod listing publish <pod-dir> --fee <sats> --revision <n> --category <c> [--description <d>] [--server URL]"

// maxAuthorFeeSats mirrors reef-core's Gates.max_author_fee_sats/0
// (100_000_000). Enforcing it client-side turns a fat-fingered price
// into a local error instead of a round trip and a server rejection.
// If reef-core's ceiling moves, this must move with it.
const maxAuthorFeeSats = 100_000_000

// parseAuthorFeeSats parses the --fee flag as a strictly base-10
// integer in (0, maxAuthorFeeSats].
//
// Base 10 is explicit because this is a price. flag.Int would parse
// with base 0, where a leading zero means octal ("0100" -> 64) and
// "0x1f4" means 500 — an author pasting a zero-padded value from a
// spreadsheet would silently publish at a price they never chose.
// strconv.ParseInt with base 10 also rejects "1_000", " 500" and any
// trailing junk. Note a leading zero is fine and no longer changes the
// value: "0100" is 100 here, which is what the author meant — under
// base-0 parsing it silently became 64.
func parseAuthorFeeSats(s string) (int, error) {
	sats, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"--fee %q is not a plain decimal number of satoshis "+
				"(no 0x/0b/0o prefixes, underscores, spaces or units)", s)
	}
	if sats <= 0 {
		return 0, fmt.Errorf("--fee must be greater than 0, got %d", sats)
	}
	if sats > maxAuthorFeeSats {
		return 0, fmt.Errorf("--fee must be at most %d satoshis, got %d", maxAuthorFeeSats, sats)
	}
	return int(sats), nil
}

// runPodListing implements `konareef pod listing <sub> ...`. Today the
// only sub is `publish` — create or update the marketplace listing for
// an already-published pod. It is a thin os.Exit wrapper over
// runPodListingImpl so the acceptance tests can drive the same code
// path in-process and assert on the exit code.
func runPodListing(args []string) {
	os.Exit(runPodListingImpl(args))
}

// runPodListingImpl runs `pod listing publish` and returns the process
// exit code: 0 on success, 1 on a pipeline failure (unreadable manifest,
// missing identity, server rejection), 2 on a usage error.
//
// The author fee and category come from flags because they are the
// mutable half of a listing — changing a price must not require
// re-signing the pod. The execution_class does NOT come from a flag: it
// is read from the pod's own signed manifest so the listing can never
// claim a class the pod did not declare. reef-core's listing gate
// rejects a mismatch anyway; reading it here keeps the CLI honest up
// front and keeps the two sides of the gate in agreement.
//
// Server URL precedence matches publish: --server → $KONAREEF_SERVER →
// http://localhost:4000, validated by resolveServerURL before the
// identity is loaded and listing.Submit signs anything.
func runPodListingImpl(args []string) int {
	if len(args) < 1 || args[0] != "publish" {
		fmt.Fprintln(os.Stderr, podListingUsage)
		return 2
	}

	fs := flag.NewFlagSet("pod listing publish", flag.ContinueOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	// --fee is taken as a string and parsed base-10 explicitly. flag.Int
	// parses with base 0, so "0100" would silently mean octal 64 and
	// "0x1f4" would mean 500 — a zero-padded price pasted from a
	// spreadsheet would publish at a number the author never chose.
	feeArg := fs.String("fee", "", "per-run author fee in satoshis, decimal (required, 1..100000000)")
	confirmFee := fs.Bool(confirmFlagFee, false,
		"the developer has confirmed this fee and this listing (skips the interactive prompt; does not authorise `pod publish` or `pod run`)")
	// --revision is required and never auto-incremented. It decides
	// whether reef-core accepts the mutation at all (it must strictly
	// exceed the stored revision), and this is a signed, money-carrying
	// write — guessing the next value on the publisher's behalf would
	// mean signing a freshness claim they did not make.
	revisionArg := fs.String("revision", "",
		"listing revision, decimal (required; must exceed the revision reef-core stores — "+
			"read it from GET /api/listings/<handle>/<pod>)")
	category := fs.String("category", "", "marketplace category (required)")
	description := fs.String("description", "", "listing description (defaults to the pod's [pod].description)")
	if err := fs.Parse(reorderFlagsFirst(args[1:])); err != nil {
		return 2
	}
	if fs.NArg() < 1 || *feeArg == "" || *revisionArg == "" || *category == "" {
		fmt.Fprintln(os.Stderr, podListingUsage)
		return 2
	}
	podDir := fs.Arg(0)

	fee, err := parseAuthorFeeSats(*feeArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 2
	}
	revision, err := parseListingRevision(*revisionArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 2
	}

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 2
	}

	// Validate against the v0.1 schema, not just TOML-decode: this is the
	// same bar `konareef pod publish` applies, and it is what constrains
	// the handle / pod-name identifiers that go into the request path.
	podTOML, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 1
	}
	spec, issues, err := pod.ParseAndValidate(podTOML)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 1
	}
	if len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "listing: pod.toml has %d validation issue(s)\n", len(issues))
		for _, issue := range issues {
			fmt.Fprintln(os.Stderr, " -", issue)
		}
		return 1
	}

	// No default here. reef-core's ManifestFields.execution_class/1
	// returns :error when the field is absent and the gate then fails
	// closed with :execution_class_undeclared — so inventing a value
	// client-side could only ever produce a server rejection, after
	// silently choosing a security-relevant setting for the author.
	// Egress gate at the point of exposure: a listed pod is one a
	// stranger can pay to run, so its context files must not name a host
	// it never declared.
	if code := listingSafetyGate(podDir, spec); code != 0 {
		return code
	}
	// Credential gate at the same point: a listed pod is one a stranger
	// runs. This is a pre-check of the LOCAL tree, not of the published
	// revision that the server lists: a key that was published and then
	// removed from the tree is not found here. An allowed finding is
	// printed to the author's stderr only. The scan of the listed revision,
	// and allowed findings in the server's listing diagnostics, are
	// reef-core#88.
	if code := bundleCredentialGate(podDir, "listing"); code != 0 {
		return code
	}

	execClass := spec.Runtime.ExecutionClass
	if execClass == "" {
		fmt.Fprintln(os.Stderr,
			"listing: pod.toml does not declare [runtime].execution_class; add it and republish the pod.")
		return 1
	}
	desc := *description
	if desc == "" {
		desc = spec.Pod.Description
	}
	if desc == "" {
		fmt.Fprintln(os.Stderr, "listing: a description is required (pass --description or set [pod].description)")
		return 1
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing: locate home directory:", err)
		return 1
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		fmt.Fprintln(os.Stderr, "  (run `konareef pod identity create --handle <h>` first)")
		return 1
	}

	f := listing.Fields{
		Revision:       listing.Revision(revision),
		Handle:         id.Handle,
		PodName:        spec.Pod.Name,
		AuthorFeeSats:  fee,
		ExecutionClass: execClass,
		Category:       *category,
		Description:    desc,
	}

	// Validate before asking. Submit validates too, but a command that is
	// going to be rejected must fail as invalid rather than as unconfirmed,
	// and nobody should be asked to approve an action that cannot happen.
	if err := f.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		return 1
	}

	// The fee below is what every other developer pays per run, and this is
	// a signed write under the publisher's identity. The gate sits after the
	// fields are assembled and checked so the prompt names the real price,
	// and before Submit so a refusal costs nothing.
	if !confirmed(*confirmFee, confirmFlagFee, fmt.Sprintf(
		"list %s/%s at %d sats per run on %s — this sets what others pay, signed under your publisher identity",
		id.Handle, spec.Pod.Name, fee, strings.TrimRight(resolvedServer, "/"))) {
		return exitNotConfirmed
	}

	resp, err := listing.Submit(resolvedServer, f, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing:", err)
		reportListingRefusal(resolvedServer, f, spec.Pod.Version, err)
		return 1
	}
	// Report the fee the SERVER stored, not the one we asked for: on a
	// money-carrying write, echoing the request back would hide a
	// disagreement. Submit already errors if the two differ, so reaching
	// here means they agree — printing resp keeps it that way if that
	// check is ever loosened.
	fmt.Printf("✓ Listing published: %s/%s (%s) — %d sats/run [%s]\n",
		resp.Handle, resp.PodName, execClass, resp.AuthorFeeSats, resp.Status)
	if !resp.UpdatedAt.IsZero() {
		fmt.Printf("  updated at: %s\n", resp.UpdatedAt.Format(time.RFC3339))
	}
	return 0
}

// reportListingRefusal prints author guidance when a listing was refused
// at a server egress gate. It looks up the latest published revision,
// which is the one the server checked, so the author knows which version
// and pod_hash the refusal is about.
//
// Inputs: serverURL — the server the listing went to; f — the listing
// fields (handle and pod name); localVersion — the version in the local
// pod.toml; err — the error Submit returned. It prints nothing for any
// other error, or for a server code this CLI does not know: that code is
// already on the "listing:" line above, verbatim.
func reportListingRefusal(serverURL string, f listing.Fields, localVersion string, err error) {
	var refusal *listing.RefusalError
	if !errors.As(err, &refusal) {
		return
	}
	if _, known := listing.Diagnose(refusal.Code); !known {
		return
	}
	latest, lookupErr := listing.LatestRevision(serverURL, f.Handle, f.PodName)
	fmt.Fprintln(os.Stderr, listing.RefusalReport(refusal.Code, latest, localVersion, lookupErr))
}

// runPodRun spawns a previously installed pod on reef-core and
// downloads its deliverables — the demo's buyer-side "Execute" step.
// Composes internal/run.Run with CLI flag parsing and pod-spec
// resolution (parsePodSpec, shared with `konareef install` and
// `smoke --pod`).
//
// run.Run picks the spawn mode from the install cache's meta.json, so
// this command is the same invocation for both kinds of pod: an open
// pod spawns inline from its cached content (Mode A: pod.toml +
// content files, no free-form task string), while a closed pod — which
// has no local body to send — spawns by reference and runs entirely on
// konareef's infrastructure (Mode C). run.Run prints the closed-pod
// disclosure before it commissions such a run.
//
// Argument shape: `<handle>/<pod-name>@<version>`. Unlike `install`,
// an explicit version is required — the install cache is keyed by
// exact version, so there's no "@latest" to resolve locally.
//
// Server URL / session token precedence mirrors `smoke`: --server /
// --token flags fall back to $KONAREEF_SERVER / $KONAREEF_TOKEN.
//
// Exits 0 on success, 1 on any pipeline failure, 2 on usage error.
func runPodRun(args []string) {
	// A commissioned run takes a different route with different rules
	// (main_commission_submit.go). It is handed over whole, before any
	// flag parsing here, so it can never reach the uncommissioned spawn.
	if hasCommissionFlag(args) {
		os.Exit(runCommissionSubmitCore(os.Stdout, os.Stderr, "pod run", args))
	}
	fs := flag.NewFlagSet("pod run", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	token := fs.String("token", "", "session token (default: $KONAREEF_TOKEN)")
	out := fs.String("out", "", "directory to download deliverables into (required)")
	timeout := fs.Duration("timeout", run.DefaultTimeout, "poll timeout waiting for the pod run to finish")
	var inputs run.InputFlags
	fs.Var(&inputs, "input", "pod input as key=value (repeatable)")
	confirmSpend := fs.Bool(confirmFlagSpend, false,
		"the developer has confirmed this run and its cost (skips the interactive prompt; does not authorise `pod publish`)")
	zk := fs.Bool("zk", false,
		"request a ZK attestation of this run (open, published, zk-enabled pods on konareef-pod-step-v1.1 only; "+
			"needs a reef-core with ZK-002, which refuses any other pod; on an older server that does not confirm "+
			"the request, the run is stopped and the command fails)")
	fs.Parse(reorderFlagsFirst(args))

	// Exactly one positional argument, and not a flag spelling: after a
	// "--" the parser stops reading flags, and any word it did not read
	// (for example a --commission) must fail the command, not be ignored.
	if fs.NArg() != 1 || strings.HasPrefix(fs.Arg(0), "-") || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: konareef pod run <handle>/<pod-name>@<version> --out <dir> "+
			"[--input k=v ...] [--zk] [--server URL] [--token TOKEN] [--timeout DURATION]")
		os.Exit(2)
	}

	handle, podName, version, err := parsePodSpec(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(2)
	}
	if version == "" {
		fmt.Fprintln(os.Stderr, "run: explicit @<version> required (no @latest against the install cache)")
		os.Exit(2)
	}

	parsedInputs, err := run.ParseInputs(inputs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(2)
	}

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(2)
	}

	sessionToken := *token
	if sessionToken == "" {
		sessionToken = os.Getenv("KONAREEF_TOKEN")
	}

	// Everything after this spends the developer's sats. The gate sits after
	// argument parsing so a malformed command still fails on its own terms,
	// and before the spawn so a refusal costs nothing.
	confirmOrExit(*confirmSpend, confirmFlagSpend, fmt.Sprintf(
		"run %s/%s@%s on %s — this spends the developer's sats and cannot be refunded",
		handle, podName, version, strings.TrimRight(resolvedServer, "/")))

	cfg := run.Config{
		BaseURL:      resolvedServer,
		SessionToken: sessionToken,
		Handle:       handle,
		PodName:      podName,
		Version:      version,
		Inputs:       parsedInputs,
		OutDir:       *out,
		Timeout:      *timeout,
		ZKRequested:  *zk,
	}

	if err := run.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
}

// runInstall fetches, verifies, and caches a published pod for the
// buyer side of the workflow (P0.6 6e).
//
// Argument shape: `<handle>/<pod-name>[@<version>]`. Without
// @<version>, the server's `/latest` alias is used.
//
// Verification is non-negotiable: a hash mismatch or signature
// failure aborts before any cache write and without a user prompt —
// "Refuse install if anything mismatches" per publisher-signing-
// design v0 §"Stage 4".
//
// Server URL precedence: --server → $KONAREEF_SERVER →
// http://localhost:4000. --yes skips the interactive y/N prompt for
// scripted use.
//
// Exits 0 on success or user-aborted prompt, 1 on any fetch / verify
// / cache failure, 2 on usage error.
// runPodTrust records a publisher's pubkey in
// ~/.konareef/known_publishers.json as locally trusted. The intended
// use is admin recovery after a key change: when `konareef install`
// blocks on a TrustChange divergence, the user out-of-band-confirms
// the new key with the publisher and runs:
//
//	konareef pod trust <handle> --pubkey-hex <new-pubkey> [--yes]
//
// This is deliberately a separate command, not a `--force` flag on
// install — users should never get into the habit of `--force install`.
//
// Exits 0 on success, 1 on I/O failure, 2 on usage error or
// malformed pubkey.
func runPodTrust(args []string) {
	fs := flag.NewFlagSet("pod trust", flag.ExitOnError)
	pubkeyHex := fs.String("pubkey-hex", "", "publisher's compressed-secp256k1 pubkey, 66 hex chars (required)")
	yes := fs.Bool("yes", false, "skip the interactive confirmation prompt")
	fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod trust <handle> --pubkey-hex <hex> [--yes]")
		os.Exit(2)
	}
	handle := fs.Arg(0)
	if *pubkeyHex == "" {
		fmt.Fprintln(os.Stderr, "konareef pod trust: --pubkey-hex is required")
		os.Exit(2)
	}
	if !looksLikeCompressedPubkey(*pubkeyHex) {
		fmt.Fprintln(os.Stderr,
			"konareef pod trust: --pubkey-hex must be 66 hex characters starting with 02 or 03 (compressed secp256k1)")
		os.Exit(2)
	}
	newFp, _ := install.Fingerprint(*pubkeyHex)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pod trust: locate home directory:", err)
		os.Exit(1)
	}
	known, err := install.LoadKnownPublishers(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pod trust:", err)
		os.Exit(1)
	}

	existing := known.Get(handle)
	fmt.Printf("Recording trust for %q:\n", handle)
	if existing != nil {
		fmt.Printf("  previous key: %s (since %s)\n",
			existing.Fingerprint, existing.FirstSeenAt.Format("2006-01-02"))
	} else {
		fmt.Println("  previous key: (none — this is the first record)")
	}
	fmt.Printf("  new key:      %s\n", newFp)
	fmt.Println()

	if !*yes {
		fmt.Print("Confirm? [y/N] ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	known.Record(handle, *pubkeyHex, time.Now().UTC())
	if err := known.Save(home); err != nil {
		fmt.Fprintln(os.Stderr, "pod trust:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Updated %s\n", install.KnownPublishersPath(home))
}

// looksLikeCompressedPubkey checks the hex string is the right
// shape for a compressed secp256k1 pubkey: 66 hex chars (33 bytes)
// starting with the standard 02 or 03 prefix. Doesn't verify the
// point is on the curve — that's the signature verifier's job.
func looksLikeCompressedPubkey(hex string) bool {
	if len(hex) != 66 {
		return false
	}
	if hex[:2] != "02" && hex[:2] != "03" {
		return false
	}
	for _, r := range hex {
		ok := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !ok {
			return false
		}
	}
	return true
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	yes := fs.Bool("yes", false, "skip the interactive confirmation prompt")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef install <handle>/<pod-name>[@<version>] [--server URL] [--yes]")
		os.Exit(2)
	}
	handle, podName, version, err := parsePodSpec(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(2)
	}

	resolvedServer, err := resolveServerURL(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(2)
	}

	fmt.Printf("Fetching pod manifest from %s...\n", strings.TrimRight(resolvedServer, "/"))
	fetched, err := install.Fetch(resolvedServer, handle, podName, version)
	if err != nil {
		if errors.Is(err, install.ErrManifestNotFound) {
			fmt.Fprintf(os.Stderr, "install: MANIFEST_NOT_FOUND: no published pod at %s/%s",
				handle, podName)
			if version != "" {
				fmt.Fprintf(os.Stderr, "@%s", version)
			}
			fmt.Fprintln(os.Stderr)
			os.Exit(4)
		}
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Retrieved: %s/%s v%s\n", fetched.Handle, fetched.PodName, fetched.PodVersion)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "install: locate home directory:", err)
		os.Exit(1)
	}

	lock, err := install.AcquireLock(home, fetched.Handle, fetched.PodName, 60*time.Second)
	if err != nil {
		if errors.Is(err, install.ErrLocalLocked) {
			fmt.Fprintf(os.Stderr, "install: LOCAL_LOCKED: another install of %s/%s is in progress\n",
				fetched.Handle, fetched.PodName)
			os.Exit(5)
		}
		fmt.Fprintln(os.Stderr, "install: acquire lock:", err)
		os.Exit(1)
	}
	defer lock.Release()

	status, err := install.CheckInstalled(home, fetched.Handle, fetched.PodName, fetched.PodVersion, fetched.PodHash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "install: inspect local cache:", err)
		os.Exit(1)
	}
	switch status {
	case install.StatusAlreadyInstalled:
		fmt.Printf("✓ Already installed: %s/%s v%s (sha256:%x)\n",
			fetched.Handle, fetched.PodName, fetched.PodVersion, fetched.PodHash[:6])
		return
	case install.StatusConflict:
		fmt.Fprintf(os.Stderr,
			"install: INSTALL_HASH_MISMATCH: %s/%s@%s already installed with a different hash (remote sha256:%x)\n",
			fetched.Handle, fetched.PodName, fetched.PodVersion, fetched.PodHash[:6])
		os.Exit(5)
	}
	// StatusNotInstalled → fall through to Verify + Cache.

	if err := install.Verify(fetched); err != nil {
		fmt.Fprintln(os.Stderr, "install: refusing — verification failed:", err)
		os.Exit(1)
	}
	fingerprint, _ := install.Fingerprint(fetched.PublisherPubkeyHex)
	fmt.Printf("✓ Publisher signature valid (handle: %s, fingerprint: %s)\n", fetched.Handle, fingerprint)
	fmt.Printf("✓ Pod hash matches: sha256:%x\n\n", fetched.PodHash)

	known, err := install.LoadKnownPublishers(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(1)
	}

	defaultYes := false
	switch m := known.Match(fetched.Handle, fetched.PublisherPubkeyHex); m.Status {
	case install.TrustOK:
		fmt.Printf("✓ Known publisher — last verified %s (trusted since %s)\n\n",
			humanDaysAgo(m.Known.LastVerifiedAt),
			m.Known.FirstSeenAt.Format("2006-01-02"))
		defaultYes = true

	case install.TrustNew:
		fmt.Println("⚠  NEW publisher — first time installing from this handle.")
		fmt.Println("   By installing, you record this public key locally; future")
		fmt.Println("   installs from this handle will be silently verified against it.")
		fmt.Println()

	case install.TrustChange:
		fmt.Println("⚠  Publisher key change detected — checking for rotation attestation...")

		rotations, err := install.FetchRotations(resolvedServer, fetched.Handle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   could not fetch rotation history: %v\n", err)
			blockKeyChange(fetched.Handle, m.Known, fingerprint, fetched.PublisherPubkeyHex)
		}

		chain, err := install.WalkRotationChain(
			rotations, fetched.Handle,
			m.Known.PubkeyHex, fetched.PublisherPubkeyHex,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   no valid rotation chain found: %v\n", err)
			blockKeyChange(fetched.Handle, m.Known, fingerprint, fetched.PublisherPubkeyHex)
		}

		// Chain verified end-to-end. Surface each hop so the user can
		// see the signing trail before consenting.
		fmt.Printf("✓ Found valid rotation chain (%d hop", len(chain))
		if len(chain) != 1 {
			fmt.Print("s")
		}
		fmt.Println("):")
		for i, hop := range chain {
			oldFp, _ := install.Fingerprint(hop.Attestation.OldPubkeyHex)
			newFp, _ := install.Fingerprint(hop.Attestation.NewPubkeyHex)
			fmt.Printf("    %d. %s → %s  rotated %s",
				i+1, oldFp, newFp, hop.Attestation.RotatedAt)
			if hop.Attestation.Reason != "" {
				fmt.Printf(" (%s)", hop.Attestation.Reason)
			}
			fmt.Println()
		}
		fmt.Println()
		fmt.Printf("  This appears to be a legitimate key rotation. The new key\n")
		fmt.Printf("  will replace the old one in your trusted publishers list\n")
		fmt.Printf("  if you proceed.\n\n")
		// Rotation acceptance is never silent — default to N regardless
		// of how `defaultYes` was set above.
		defaultYes = false
	}

	if !*yes {
		prompt := "Install? [y/N] "
		if defaultYes {
			prompt = "Install? [Y/n] "
		}
		fmt.Print(prompt)
		var answer string
		_, _ = fmt.Scanln(&answer)
		a := strings.ToLower(strings.TrimSpace(answer))
		accept := (a == "y" || a == "yes") || (a == "" && defaultYes)
		if !accept {
			fmt.Println("Aborted.")
			return
		}
	}

	cacheDir, err := install.Cache(home, fetched)
	if err != nil {
		fmt.Fprintln(os.Stderr, "install: cache:", err)
		os.Exit(1)
	}

	// Record the trust decision (TrustNew → new entry; TrustOK →
	// LastVerifiedAt refresh; TrustChange already exited above).
	known.Record(fetched.Handle, fetched.PublisherPubkeyHex, time.Now().UTC())
	if err := known.Save(home); err != nil {
		fmt.Fprintf(os.Stderr, "install: warning: failed to update known_publishers.json: %v\n", err)
	}
	fmt.Printf("✓ Installed %s/%s to %s\n", fetched.Handle, fetched.PodName, cacheDir)

	// A closed pod's install looks "incomplete" on disk — a signed HEAD
	// and no content — so say plainly that this is the finished state
	// and how to run it, rather than leaving the user to conclude the
	// download was truncated.
	if fetched.IsClosed() {
		ref := fmt.Sprintf("%s/%s@%s", fetched.Handle, fetched.PodName, fetched.PodVersion)
		fmt.Printf("  %s is a closed pod — HEAD only (manifest + signature verified).\n", ref)
		if line := sealedGrantsInspectLine(fetched.ManifestCanonical); line != "" {
			fmt.Println(line)
		}
		fmt.Println("  This pod's contents are private and run on konareef's infrastructure.")
		fmt.Printf("  Run it with:  konareef pod run %s --out <dir>\n", ref)
	}
}

// blockKeyChange prints the security-critical "publisher key changed
// without valid rotation attestation" message and exits the process
// with code 2 (refusal). Called from runInstall's TrustChange branch
// whenever the rotation fetch fails or the chain cannot be walked
// from the locally-recorded key to the server-supplied one.
//
// Exits the process — never returns to the caller.
func blockKeyChange(handle string, known *install.PublisherRecord, newFingerprint, newPubkeyHex string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "✗ PUBLISHER KEY CHANGE DETECTED — install BLOCKED")
	fmt.Fprintf(os.Stderr, "    handle:       %s\n", handle)
	fmt.Fprintf(os.Stderr, "    recorded key: %s (since %s)\n",
		known.Fingerprint, known.FirstSeenAt.Format("2006-01-02"))
	fmt.Fprintf(os.Stderr, "    new key:      %s\n", newFingerprint)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Out-of-band confirmation required. If %q legitimately rotated their key:\n", handle)
	fmt.Fprintf(os.Stderr, "      konareef pod trust %s --pubkey-hex %s\n", handle, newPubkeyHex)
	fmt.Fprintln(os.Stderr, "  Otherwise: do not install. Report at security@konareef.ai.")
	os.Exit(2)
}

// parsePodSpec parses the `konareef install` argument
// `<handle>/<pod-name>[@<version>]` into its parts. An empty version
// signals "latest" to Fetch. Handle and pod-name are both required;
// an empty either side is a usage error.
func parsePodSpec(spec string) (handle, podName, version string, err error) {
	slash := strings.IndexByte(spec, '/')
	if slash < 0 {
		return "", "", "", fmt.Errorf("pod spec %q is not <handle>/<pod-name>[@<version>]", spec)
	}
	handle = spec[:slash]
	rest := spec[slash+1:]
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		podName = rest[:at]
		version = rest[at+1:]
	} else {
		podName = rest
	}
	if handle == "" || podName == "" {
		return "", "", "", fmt.Errorf("pod spec %q has an empty handle or pod name", spec)
	}
	return handle, podName, version, nil
}

// runVerify re-checks a konareef-bundle/v1 document offline (P0.2).
// Accepts either a filesystem path or an http(s) URL.
//
//   - 0  → bundle verified
//   - 1  → load failure OR at least one divergence
//   - 2  → usage error
//
// --json emits a structured result for piping; the default output
// is a human-friendly checklist with the divergences enumerated.
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the verification result as JSON for piping")
	strict := fs.Bool("strict", false, "require a fully-populated publisher attestation envelope; reject legacy v0 unsigned bundles (WI-P0-002)")
	// P1.3 — optional verify-side disclosure-policy assertion
	// (PRD 4 § 4.3.3). Empty = no-op; non-empty asserts the bundle's
	// `disclosure` field equals the supplied value (case-insensitive).
	disclosurePolicyAssert := fs.String("disclosure-policy", "",
		"assert the bundle's disclosure policy matches {C|D}; mismatch returns ERR_DISCLOSURE_POLICY_VIOLATION")
	asTUI := fs.Bool("tui", false, "render the verification result in an interactive TUI instead of plain text")
	// reef-core#76: chain-head anchor check. With no headers file and no
	// header URL (flag or environment), an anchored bundle is checked
	// against the two default header services (verify.DefaultHeaderServices),
	// which must agree. A headers file or header URL replaces the defaults.
	// --offline keeps the check off the network: the headers file only.
	var anchorCfg verify.AnchorConfig
	fs.StringVar(&anchorCfg.HeadersFile, "headers-file", "",
		"pinned block headers file for the chain-head anchor check; replaces the default header services (env "+verify.HeadersFileEnv+")")
	fs.Func("headers-url", "block header service base URL, WhatsOnChain-style API; give two or more, which must agree; replaces the default header services (env "+verify.HeadersURLsEnv+")",
		func(v string) error { anchorCfg.HeaderURLs = append(anchorCfg.HeaderURLs, v); return nil })
	fs.Uint64Var(&anchorCfg.MinConfirmations, "min-confirmations", 0,
		"confirmations the chain-head anchor needs (default 1; env "+verify.MinConfirmationsEnv+")")
	fs.StringVar(&anchorCfg.MaxTargetBits, "max-target-bits", "",
		"testnet/regtest only: replace the mainnet difficulty floor with this compact target, hex; the verdict reports it")
	fs.Func("trusted-node-key", "reef-core node identity key (compressed hex) whose anchor attestations count; repeatable (env "+verify.TrustedNodeKeysEnv+")",
		func(v string) error { anchorCfg.TrustedNodeKeys = append(anchorCfg.TrustedNodeKeys, v); return nil })
	fs.BoolVar(&anchorCfg.Offline, "offline", false,
		"never ask a network service for block headers; only --headers-file is used, and without it an anchored bundle reports headers_unavailable; a bundle given as a URL is still fetched (env "+verify.OfflineEnv+"=1)")
	fs.Parse(reorderFlagsFirst(args))
	verifyUsage := func() {
		fmt.Fprintln(os.Stderr, "usage: konareef verify <path-or-url> [--json] [--strict] [--disclosure-policy {C|D}] [--tui] [--headers-file F] [--headers-url U]... [--offline] [--min-confirmations N] [--trusted-node-key K]...")
		fmt.Fprintln(os.Stderr, "  chain-head anchor headers: with no --headers-file, no --headers-url and no --offline, konareef asks "+
			verify.WhatsOnChainHeadersURL+" and "+verify.BitailsHeadersURL+" (both must agree)")
	}
	if fs.NArg() < 1 {
		verifyUsage()
		os.Exit(2)
	}
	// A malformed anchor environment variable (for example
	// KONAREEF_OFFLINE or KONAREEF_MIN_CONFIRMATIONS) is a usage error,
	// reported before any source is read, for v1 and v2 bundles alike.
	// --offline with header URLs (flag or environment) is a usage error
	// too, not a silent drop of the URLs.
	envAnchorCfg, envErr := verify.AnchorConfigFromEnv()
	if envErr == nil {
		envErr = envAnchorCfg.Merge(anchorCfg).CheckOffline()
	}
	if envErr != nil {
		fmt.Fprintln(os.Stderr, "verify:", envErr)
		verifyUsage()
		os.Exit(2)
	}
	src := fs.Arg(0)

	// --tui: hand off to the standalone interactive verify screen
	// (Track A.1). It owns format dispatch (v1 JSON / v2 CBOR), the
	// disclosure-policy assertion, and rendering; the headless paths
	// below are unaffected.
	if *asTUI {
		if err := tui.RunVerifyWithAnchor(src, *strict, *disclosurePolicyAssert, anchorCfg); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
		return
	}

	// Headless konareef-bundle/v2 (CBOR) dispatch. The legacy verify.Load
	// path below is v1-JSON only; a v2 CBOR bundle (first byte 0xA0..0xBB)
	// is routed here through VerifyV2Production, which injects the real
	// Rust Spartan verifier subprocess when KONAREEF_VERIFY_BIN is set
	// (fail-closed otherwise). This is the non-TUI DoD entry point for C0
	// end-to-end verify — `konareef verify <path-or-url>.cbor` — that the
	// interactive --tui path cannot serve in a non-TTY context.
	//
	// MR !30 fix: the byte source must cover BOTH local files AND http(s)
	// URLs so the served-bundle C0 flow (/api/public/proofs/:hash/bundle +
	// `konareef verify <url>`) reaches VerifyV2Production.
	//
	// Single-fetch (MR !30 blocker-2): fetch the raw source bytes EXACTLY
	// ONCE, then dispatch on the first byte. A CBOR map (0xA0..0xBB) routes
	// to the v2 verifier; anything else is parsed as v1 JSON from the SAME
	// already-fetched bytes via verify.LoadFromBytes — NOT re-fetched. A
	// previous version fetched once to peek the format and then called
	// verify.Load(src) which fetched the URL AGAIN; for single-use /
	// expiring / mutable URLs the second fetch can fail or return different
	// bytes than were peeked. We now reuse the first read for both the
	// format peek and the v1 parse, so the CLI makes one network request.
	//
	// A failed fetch is reported with the exact v1 error wording (matching
	// the prior verify.Load behavior) for both local paths and URLs.
	raw, readErr := verify.ReadSource(src)
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "verify:", readErr)
		os.Exit(1)
	}
	if len(raw) > 0 && raw[0] >= 0xA0 && raw[0] <= 0xBB {
		runVerifyV2Headless(src, raw, *disclosurePolicyAssert, *asJSON, anchorCfg)
		return
	}

	b, err := verify.LoadFromBytes(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}

	// P1.3 — optional disclosure-policy assertion (PRD 4 § 4.3.3).
	if *disclosurePolicyAssert != "" {
		if err := verify.AssertDisclosurePolicy(b, strings.ToUpper(*disclosurePolicyAssert)); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
	}

	var result *verify.Result
	if *strict {
		result = verify.VerifyStrict(b)
	} else {
		result = verify.Verify(b)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"source":             src,
			"version":            b.Version,
			"ok":                 result.OK,
			"chain_length":       result.ChainLength,
			"divergences":        result.Divergences,
			"attestation_status": result.AttestationStatus,
			"custody":            custodyJSON(result.Custody),
		})
	} else {
		fmt.Printf("Bundle: %s\n", src)
		fmt.Printf("Version: %s\n", b.Version)
		fmt.Printf("Chain length: %d\n\n", result.ChainLength)
		if result.OK {
			// WI-P0-007: distinguish "passed because the bundle is
			// legacy unsigned" from "passed because the publisher
			// signature actually checked". A green check on a
			// legacy bundle is NOT cryptographic proof of authorship.
			switch result.AttestationStatus {
			case "attested":
				fmt.Println("✓ Verification PASSED (publisher attested)")
				fmt.Println("  - chain link hashes recompute")
				fmt.Println("  - snapshot Merkle root matches")
				fmt.Println("  - snapshot-source accesses are in the leaf set")
				fmt.Println("  - access log hash matches the custody claim")
				fmt.Println("  - SHA-256(manifest) == pod_hash")
				fmt.Println("  - publisher signature verifies under publisher_pubkey")
			case "legacy_unsigned":
				fmt.Println("✓ Verification PASSED (legacy unsigned bundle)")
				fmt.Println("  - chain link hashes recompute")
				fmt.Println("  - snapshot Merkle root matches")
				fmt.Println("  - snapshot-source accesses are in the leaf set")
				fmt.Println("  - access log hash matches the custody claim")
				fmt.Println("  ⚠  no publisher attestation; --strict to require one")
			default:
				// Should not happen for OK results, but degrade
				// safely if it does.
				fmt.Println("✓ Verification PASSED")
			}
		} else {
			fmt.Println("✗ Verification FAILED")
			for _, d := range result.Divergences {
				fmt.Printf("  - %s\n", d)
			}
		}
		fmt.Printf("\nMCP broker (server custody): %s\n", result.Custody.Label())
	}

	if !result.OK {
		os.Exit(1)
	}
}

// custodyJSON renders a custody assessment for `konareef verify --json`.
//
// Input: a, the assessment from verify.Result or verify.ResultV2.
// Output: a map with "assurance" (the level), "label" (the display text)
// and "refusal" (the custody-rule code; empty unless the record was
// refused). "version" and "mcp_broker" are set only for a fully verified
// contained record. A bundle cannot anchor its custody record, so any
// other claim goes under "unanchored_claim", never under those two keys.
func custodyJSON(a verify.CustodyAssessment) map[string]any {
	out := map[string]any{
		"assurance":  string(a.Assurance),
		"label":      a.Label(),
		"version":    "",
		"mcp_broker": "",
		"refusal":    verify.CustodyRuleCode(a.RuleErr),
	}
	switch {
	case a.Assurance == verify.BrokerAssuranceContained:
		out["version"] = string(a.Claim.Version)
		out["mcp_broker"] = string(a.Claim.Marker)
	case a.Claim.Version != "":
		out["unanchored_claim"] = map[string]string{
			"version":    string(a.Claim.Version),
			"mcp_broker": string(a.Claim.Marker),
		}
	}
	return out
}

// verifyV2JSONDoc builds the `konareef verify --json` document for a
// konareef-bundle/v2 result.
//
// Inputs: the source name, the bundle's version, circuit id and
// disclosure (from the header), and the result.
// Output: the JSON document. c_total_checked is always next to
// custody_binding and c_total_label, so a reader sees what the custody
// total is bound to (konareef#37).
func verifyV2JSONDoc(src, version, circuitID, disclosure string, r *verify.ResultV2) map[string]any {
	msgs := make([]string, 0, len(r.Divergences))
	for _, d := range r.Divergences {
		msgs = append(msgs, d.Msg)
	}
	return map[string]any{
		"source":       src,
		"version":      version,
		"circuit_id":   circuitID,
		"disclosure":   disclosure,
		"ok":           r.OK,
		"chain_length": r.ChainLength,
		"verdict":      r.V2Verdict,
		"divergences":  msgs,
		"custody":      custodyJSON(r.Custody),
		// reef-core#76: the proven cost equals the custody total, and
		// the custody link is anchored. konareef#37: what the custody
		// fields are bound to ("bundle-claim" in bundle-only
		// verification) and the matching display text.
		"c_total_checked":  r.CTotalChecked,
		"c_total_anchored": r.CTotalAnchored,
		"custody_binding":  string(r.CustodyBinding),
		"c_total_label":    r.CTotalLabel(),
	}
}

// writeVerifyV2Text writes the text form of a konareef-bundle/v2 result.
//
// Inputs: w, the output; the source name, the bundle's version, circuit
// id and disclosure; the result. Output: none. The custody total line
// always names its binding (konareef#37), so an unanchored total is never
// shown as a bare "checked".
func writeVerifyV2Text(w io.Writer, src, version, circuitID, disclosure string, r *verify.ResultV2) {
	fmt.Fprintf(w, "Bundle: %s\n", src)
	fmt.Fprintf(w, "Version: %s\n", version)
	fmt.Fprintf(w, "Circuit: %s  Disclosure: %s\n", circuitID, disclosure)
	fmt.Fprintf(w, "Chain length: %d\n\n", r.ChainLength)
	if v := r.V2Verdict; v != nil {
		fmt.Fprintf(w, "  proof_valid=%v disclosure_valid=%v commitments_valid=%v signature_valid=%v chain_policy_valid=%v\n",
			v.ProofValid, v.DisclosureValid, v.CommitmentsValid, v.SignatureValid, v.ChainPolicyValid)
		fmt.Fprintf(w, "  chain_head_anchored=%v%s\n\n", v.ChainHeadAnchored, anchorStatusSuffix(v))
	}
	if r.OK {
		fmt.Fprintln(w, "✓ Verification PASSED (konareef-bundle/v2)")
	} else {
		fmt.Fprintln(w, "✗ Verification FAILED")
		for _, d := range r.Divergences {
			fmt.Fprintf(w, "  - %s\n", d.Msg)
		}
	}
	fmt.Fprintf(w, "\nMCP broker (server custody): %s\n", r.Custody.Label())
	fmt.Fprintf(w, "Custody total: %s\n", r.CTotalLabel())
	fmt.Fprintf(w, "Custody binding: %s\n", r.CustodyBinding)
}

// runVerifyV2Headless verifies a konareef-bundle/v2 (CBOR) bundle on the
// live production path (real Rust Spartan verifier subprocess when
// KONAREEF_VERIFY_BIN is set; fail-closed otherwise) and prints a non-TUI
// summary. It exits 1 on any divergence, 0 on a full PASS — mirroring the
// headless v1 exit contract.
//
// disclosurePolicy, when non-empty, asserts the bundle's disclosure field
// (case-insensitive) before verification, identical to the v1 path.
// verifyV2ByteSource fetches the raw bytes for src — a local filesystem path
// OR an http(s) URL — via verify.ReadSource, then applies the first-byte
// format gate that decides between the konareef-bundle/v2 CBOR verifier and
// the legacy v1 JSON loader.
//
// Inputs:
//   - src: a local path or http(s) URL (the `konareef verify <src>` argument).
//
// Returns:
//   - raw:  the fetched bytes when src is a v2 CBOR-map bundle, else nil.
//   - isV2: true iff the fetch succeeded AND the first byte is a CBOR map
//     header (0xA0..0xBB), meaning the caller must route to the v2 verifier.
//
// When isV2 is false — a non-CBOR body, an empty body, or a failed fetch —
// the caller falls through to verify.Load(src), preserving the exact v1 JSON
// behavior and v1 error reporting for both local paths and URLs. This is the
// single point of dispatch shared by file and URL sources (MR !30): it is the
// reason the served-bundle C0 flow (/api/public/proofs/:hash/bundle) reaches
// VerifyV2Production instead of falling through to the v1 JSON loader.
func verifyV2ByteSource(src string) (raw []byte, isV2 bool) {
	b, err := verify.ReadSource(src)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	if b[0] >= 0xA0 && b[0] <= 0xBB {
		return b, true
	}
	return nil, false
}

// anchorStatusSuffix returns " (status …)" for the headless verdict line,
// or "" when the verdict has no anchor object.
func anchorStatusSuffix(v *verify.Verdict) string {
	if v.ChainHeadAnchor == nil {
		return ""
	}
	return fmt.Sprintf(" (anchor status %s)", v.ChainHeadAnchor.Status)
}

// runVerifyV2Headless verifies konareef-bundle/v2 bytes on the live path
// and prints the result (JSON with asJSON). Inputs: the source name, the
// raw bytes, the optional disclosure assertion, the output mode, and the
// chain-head anchor configuration from flags. It exits 1 on any failure.
func runVerifyV2Headless(src string, raw []byte, disclosurePolicy string, asJSON bool, anchorCfg verify.AnchorConfig) {
	// Best-effort header decode for the policy assertion + display, then
	// route to the production v2 verifier.
	var hdr struct {
		Version    string `cbor:"version"`
		CircuitID  string `cbor:"circuit_id"`
		Disclosure string `cbor:"disclosure"`
	}
	_ = cbor.Unmarshal(raw, &hdr)

	if disclosurePolicy != "" {
		if err := verify.AssertDisclosurePolicy(
			&verify.Bundle{Disclosure: hdr.Disclosure}, strings.ToUpper(disclosurePolicy)); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
	}

	r := verify.VerifyV2ProductionWithAnchor(raw, false, anchorCfg)

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(verifyV2JSONDoc(src, hdr.Version, hdr.CircuitID, hdr.Disclosure, r))
	} else {
		writeVerifyV2Text(os.Stdout, src, hdr.Version, hdr.CircuitID, hdr.Disclosure, r)
	}

	if !r.OK {
		os.Exit(1)
	}
}

// runFeeder dispatches the `konareef feeder` subcommand. It is the PTD
// sidecar entry point: reads a relayed witness.json, calls the PS-1 prover,
// and posts the resulting artifact to reef-core ingest.
//
// When --step-disclosure is set, the WitnessWriter runs first (spec §3):
// it combines the reef-core-relayed step-disclosure.json with the
// installed pod's manifest fields (looked up via --pod) and (re)writes
// --witness before feeder.Run consumes it. Without --step-disclosure,
// behavior is unchanged: feeder.Run reads a pre-written --witness.
//
// Flag precedence: --witness, --paygate-url, --reef-ingest-url,
// --ingest-token are always required; --circuit-id defaults to
// "konareef-pod-step-v1.1" (VHASH-M1; reef-core always passes the
// publisher's id); --pod is required only when --step-disclosure is
// set. Exits 0 on success, 1 on pipeline error, 2 on usage error.
func runFeeder(args []string) {
	fs := flag.NewFlagSet("feeder", flag.ExitOnError)
	seamVersion := fs.Bool("seam-version", false, "print the step-disclosure seam version this binary reads/writes, then exit (reef-core's version handshake; see internal/version.SeamVersion)")
	witness := fs.String("witness", "", "path to the relayed witness.json")
	paygate := fs.String("paygate-url", "", "PS-1 base URL")
	ingest := fs.String("reef-ingest-url", "", "reef-core ingest endpoint URL")
	token := fs.String("ingest-token", "", "per-pod ingest bearer token")
	circuit := fs.String("circuit-id", vkeystore.CircuitIDPodStepV1_1, "circuit id: konareef-pod-step-v1.1 (default; VHASH, binds value_hash_out) or konareef-pod-step-v1 (pre-VHASH; see paygate-zk#12 and #14 for the migration order)")
	stepDisclosure := fs.String("step-disclosure", "", "path to the reef-core-relayed step-disclosure.json (spec §2); when set, the WitnessWriter runs before feeder.Run and (re)writes --witness")
	podSpec := fs.String("pod", "", "installed pod spec <handle>/<name>@<version> whose install cache supplies the manifest fields for the WitnessWriter (required with --step-disclosure)")
	leafTableURL := fs.String("memory-leaf-table-url", "", "reef-core URL of this run's signed memory leaf table (seam/2); fetched with --ingest-token only for a memory-bearing manifest")
	_ = fs.Parse(args)

	// Handled before any other flag is required: reef-core's version
	// handshake (B1 task 5) invokes `konareef feeder --seam-version` alone
	// to probe compatibility before it ever builds a real feeder
	// invocation. Stdout MUST be exactly the seam version and a newline —
	// reef-core parses it verbatim — so nothing else may print here.
	if *seamVersion {
		fmt.Println(version.SeamVersion)
		return
	}

	if *witness == "" || *paygate == "" || *ingest == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "feeder: --witness, --paygate-url, --reef-ingest-url, --ingest-token are required")
		os.Exit(2)
	}
	if !vkeystore.IsSupportedCircuitID(*circuit) {
		fmt.Fprintf(os.Stderr, "feeder: --circuit-id %q is not supported (want one of %v)\n", *circuit, vkeystore.SupportedCircuitIDs())
		os.Exit(2)
	}

	if *stepDisclosure != "" {
		if *podSpec == "" {
			fmt.Fprintln(os.Stderr, "feeder: --pod is required with --step-disclosure")
			os.Exit(2)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "feeder: locate home directory:", err)
			os.Exit(1)
		}
		leafTable := leafTableSource{URL: *leafTableURL, Token: *token}
		if err := runFeederWitnessWriter(home, *podSpec, *stepDisclosure, *witness, leafTable); err != nil {
			fmt.Fprintln(os.Stderr, "feeder:", err)
			os.Exit(1)
		}
	}

	err := feeder.Run(context.Background(), feeder.Opts{
		WitnessPath: *witness, PaygateURL: *paygate, IngestURL: *ingest,
		IngestToken: *token, CircuitID: *circuit,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "feeder: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("feeder: artifact ingested")
}

// leafTableSource says where the feeder fetches a run's signed memory
// leaf table (seam/2): reef-core's per-run URL and the per-run ingest
// token that authenticates the request. A zero value refuses a
// memory-bearing manifest, since no table can be fetched.
type leafTableSource struct {
	URL   string
	Token string
}

// runFeederWitnessWriter loads the installed pod's manifest params and
// runs feeder.WriteWitness, producing witnessPath from stepDisclosurePath.
// Extracted from runFeeder so the "load params + WriteWitness" step is
// unit-testable without spawning the `feeder` subcommand as a process.
//
// The params come from install.LoadManifestParamsForRun, which checks the
// step disclosure's initial_memory against the signed manifest (seam/2,
// C1 and S-7) and, for a memory-bearing manifest, fetches the signed leaf
// table from leafTable and checks it before it builds the memory lane
// (MEM-SEAM A1). Any mismatch, or a table that cannot be fetched, fails
// before witnessPath is written.
func runFeederWitnessWriter(home, podSpec, stepDisclosurePath, witnessPath string, leafTable leafTableSource) error {
	handle, podName, version, err := parsePodSpec(podSpec)
	if err != nil {
		return fmt.Errorf("--pod: %w", err)
	}
	if version == "" {
		return fmt.Errorf("--pod: explicit @<version> required (no @latest in cache)")
	}
	disclosed, err := feeder.ReadSeamMemory(stepDisclosurePath)
	if err != nil {
		return fmt.Errorf("read step-disclosure initial_memory: %w", err)
	}
	mp, err := install.LoadManifestParamsForRun(home, handle, podName, version, install.RunMemory{
		Disclosed: disclosed,
		FetchLeafTable: func() (*install.LeafTableEvidence, error) {
			table, sig, err := feeder.FetchLeafTable(context.Background(), leafTable.URL, leafTable.Token)
			if err != nil {
				return nil, err
			}
			return &install.LeafTableEvidence{Table: table, Signature: sig}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("load manifest params: %w", err)
	}
	if err := feeder.WriteWitness(stepDisclosurePath, mp, witnessPath); err != nil {
		return fmt.Errorf("write witness: %w", err)
	}
	return nil
}

func runTUI(args []string) {
	fs := flag.NewFlagSet("konareef", flag.ExitOnError)
	server := fs.String("server", "http://localhost:4000", "reef-core base URL")
	token := fs.String("token", "", "session token (default: $KONAREEF_TOKEN) — required for mutating actions")
	fs.Parse(args)

	sessionToken := *token
	if sessionToken == "" {
		sessionToken = os.Getenv("KONAREEF_TOKEN")
	}

	client := api.NewClient(*server).WithToken(sessionToken)

	// Create a WebSocket client when a session token is available; without a
	// token the WS connection would be rejected, so wsClient remains nil.
	var wsClient *ws.Client
	if sessionToken != "" {
		wsClient = ws.New(*server, sessionToken)
	}

	app := tui.NewApp(client, wsClient)

	p := tea.NewProgram(app, tea.WithAltScreen())

	// Start the WS listener in a background goroutine so it can dispatch
	// tea.Msg values into the program's event loop.
	if wsClient != nil {
		go wsClient.Connect(p)
	}

	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// Clean up the WebSocket connection after the program exits.
	if wsClient != nil {
		wsClient.Close()
	}
}

func runSmoke(args []string) {
	fs := flag.NewFlagSet("smoke", flag.ExitOnError)
	server := fs.String("server", "http://localhost:4000", "reef-core base URL")
	token := fs.String("token", "", "session token (default: $KONAREEF_TOKEN)")
	timeout := fs.Duration("timeout", 120*time.Second, "poll timeout for custody proof")
	lifecycle := fs.Bool("lifecycle", false, "run full lifecycle smoke (spawn + stream + cost + kill + exit) instead of the default spawn+proof test")
	memoryRoundtrip := fs.Bool("memory-roundtrip", false, "additionally verify Phase 1.5 Layer 1 memory entries persist after agent_exited (lifecycle mode only; requires reef-core with the matching feature)")
	podSpec := fs.String("pod", "", "spec of a previously installed signed pod (handle/name@version); attaches the cached pod_attestation to the spawn request so the resulting structured_bundle commitment is tied to the signed manifest (P0.3R)")
	fs.Parse(args)

	cfg := smoke.Default()
	cfg.BaseURL = *server
	cfg.Timeout = *timeout
	cfg.MemoryRoundtrip = *memoryRoundtrip

	cfg.SessionToken = *token
	if cfg.SessionToken == "" {
		cfg.SessionToken = smoke.TokenFromEnv()
	}

	// --pod handle/name@version: load the cached attestation from
	// the local install dir and attach it to the spawn. Failing to
	// locate or parse the cache is fatal — the user asked for a
	// signed-pod spawn and got something else would be the worst
	// possible silent fallback.
	if *podSpec != "" {
		handle, podName, version, err := parsePodSpec(*podSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "smoke --pod:", err)
			os.Exit(2)
		}
		if version == "" {
			fmt.Fprintln(os.Stderr, "smoke --pod: explicit @<version> required (no @latest in cache)")
			os.Exit(2)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "smoke --pod: locate home directory:", err)
			os.Exit(1)
		}
		att, err := install.LoadCachedAttestation(home, handle, podName, version)
		if err != nil {
			fmt.Fprintln(os.Stderr, "smoke --pod: load cached attestation:", err)
			os.Exit(1)
		}
		cfg.PodAttestation = att
	}

	var err error
	if *lifecycle {
		err = smoke.RunLifecycle(cfg)
	} else {
		err = smoke.Run(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "smoke failed:", err)
		os.Exit(1)
	}
}
