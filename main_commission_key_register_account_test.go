// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_key_register_account_test.go — tests for the account id
// that `commission key register` signs over (K5-2, konareef#34).
//
// reef-core!149 returns the session's `user_id` in
// GET /api/commission-keys/challenge. It is the exact text of the §6.1
// registration message. These tests cover resolveKeyRegisterAccount, the
// pure rule that picks the account, and the binary against a fake server:
// the control without --account, a matching and a different --account, an
// older server with no user_id, and hostile or malformed server values.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// keyRegAccount is the account id the fake server returns.
const keyRegAccount = "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9"

// strPtr returns a pointer to s, for the optional server user_id.
func strPtr(s string) *string { return &s }

// TestResolveKeyRegisterAccount pins the rule table: which account id is
// signed, and when the command refuses.
func TestResolveKeyRegisterAccount(t *testing.T) {
	cases := []struct {
		name      string
		flag      string
		server    *string
		want      string
		wantError string
	}{
		{"server only", "", strPtr(keyRegAccount), keyRegAccount, ""},
		{"flag equals server", keyRegAccount, strPtr(keyRegAccount), keyRegAccount, ""},
		{"flag upper case equals server", strings.ToUpper(keyRegAccount), strPtr(keyRegAccount), keyRegAccount, ""},
		{"older server, flag given", strings.ToUpper(keyRegAccount), nil, keyRegAccount, ""},
		{"flag differs from server", "11111111-2222-4333-8444-555555555555", strPtr(keyRegAccount), "", "does not match"},
		{"older server, no flag", "", nil, "", "did not return user_id"},
		{"server empty", "", strPtr(""), "", "not a canonical UUID"},
		{"server empty, flag given", keyRegAccount, strPtr(""), "", "not a canonical UUID"},
		{"server upper case", "", strPtr(strings.ToUpper(keyRegAccount)), "", "not a canonical UUID"},
		{"server not a uuid", "", strPtr("alice"), "", "not a canonical UUID"},
		{"server with trailing newline", "", strPtr(keyRegAccount + "\n"), "", "not a canonical UUID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveKeyRegisterAccount(c.flag, c.server)
			if c.wantError == "" {
				if err != nil || got != c.want {
					t.Fatalf("got %q, %v; want %q", got, err, c.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantError) || got != "" {
				t.Fatalf("got %q, %v; want an error containing %q", got, err, c.wantError)
			}
		})
	}
}

// TestResolveKeyRegisterAccountEscapesServerText checks that a hostile
// server user_id reaches the error text only in escaped form.
func TestResolveKeyRegisterAccountEscapesServerText(t *testing.T) {
	hostile := "\x1b]0;pwned\x07\x1b[2J\u009b31m"
	_, err := resolveKeyRegisterAccount("", strPtr(hostile))
	if err == nil {
		t.Fatal("a hostile user_id was accepted")
	}
	for _, raw := range []string{"\x1b", "\x07", "\u009b"} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("error text carries raw %q: %q", raw, err.Error())
		}
	}
}

// keyRegFake is a fake reef-core for key registration. challengeBody is
// the raw JSON of the challenge response; posts counts registrations;
// registerStatus and registerBody, when set, replace the 201 answer to the
// POST; decodeErr records a POST body that is not JSON.
type keyRegFake struct {
	mu             sync.Mutex
	challengeBody  string
	registerStatus int
	registerBody   string
	challenges     int
	posts          int
	decodeErr      error
	registered     struct{ Pubkey, Challenge, Signature string }
}

func (f *keyRegFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/commission-keys/challenge":
		f.challenges++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(f.challengeBody))
	case r.Method == http.MethodPost && r.URL.Path == "/api/commission-keys":
		f.posts++
		if err := json.NewDecoder(r.Body).Decode(&f.registered); err != nil {
			f.decodeErr = err
		}
		if f.registerStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.registerStatus)
			w.Write([]byte(f.registerBody))
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"key_id": "k-1", "pubkey": f.registered.Pubkey, "registered_at": "2026-09-26T00:00:00Z", "retired_at": nil})
	default:
		http.NotFound(w, r)
	}
}

// challengeJSON returns a challenge body; extra is spliced in verbatim
// (for example `,"user_id":"…"`).
func challengeJSON(challenge, extra string) string {
	return `{"challenge":"` + challenge + `","expires_at":"2026-09-26T00:05:00Z"` + extra + `}`
}

// TestCommissionKeyRegisterAccountFromChallenge drives the binary. Every
// accepted case must post a signature over the expected account; every
// refused case must post nothing.
func TestCommissionKeyRegisterAccountFromChallenge(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	id, err := identity.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("cd", 32)
	withUser := challengeJSON(challenge, `,"user_id":"`+keyRegAccount+`"`)
	other := "11111111-2222-4333-8444-555555555555"

	cases := []struct {
		name       string
		body       string
		args       []string
		wantCode   int
		wantSigned string // the account the signature must cover; "" = no post
		wantText   string
	}{
		{"control: no --account, server user_id", withUser, nil, 0, keyRegAccount, "for account " + keyRegAccount},
		{"--account equals server", withUser, []string{"--account", strings.ToUpper(keyRegAccount)}, 0, keyRegAccount, "k-1"},
		{"older server, --account given", challengeJSON(challenge, ""), []string{"--account", other}, 0, other, "for account " + other},
		{"server user_id null, --account given", challengeJSON(challenge, `,"user_id":null`), []string{"--account", other}, 0, other, "for account " + other},
		{"--account differs from server", withUser, []string{"--account", other}, 1, "", "does not match"},
		{"older server, no --account", challengeJSON(challenge, ""), nil, 1, "", "--account"},
		{"server user_id null, no --account", challengeJSON(challenge, `,"user_id":null`), nil, 1, "", "did not return user_id"},
		{"server user_id empty", challengeJSON(challenge, `,"user_id":""`), []string{"--account", keyRegAccount}, 1, "", "not a canonical UUID"},
		{"server user_id not a string", challengeJSON(challenge, `,"user_id":42`), nil, 1, "", "no usable answer from the server"},
		{"server user_id hostile", challengeJSON(challenge, `,"user_id":"\u001b[2J\u009bevil"`), nil, 1, "", "not a canonical UUID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &keyRegFake{challengeBody: c.body}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			args := append([]string{"commission", "key", "register", "--server", srv.URL, "--token", "dG9rZW4=", "--confirm-key-register"}, c.args...)
			res := runCommissionCLI(t, bin, home, args...)
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if res.code != c.wantCode {
				t.Fatalf("exit %d, want %d\n%s", res.code, c.wantCode, res.combined())
			}
			if c.wantText != "" && !strings.Contains(res.combined(), c.wantText) {
				t.Fatalf("output lacks %q:\n%s", c.wantText, res.combined())
			}
			for _, raw := range []string{"\x1b", "\u009b"} {
				if strings.Contains(res.combined(), raw) {
					t.Fatalf("output carries raw %q:\n%q", raw, res.combined())
				}
			}
			if fake.decodeErr != nil {
				t.Fatalf("the CLI posted a body that is not JSON: %v", fake.decodeErr)
			}
			if c.wantSigned == "" {
				if fake.posts != 0 {
					t.Fatalf("a refused registration posted %d time(s)", fake.posts)
				}
				return
			}
			if fake.posts != 1 || fake.registered.Pubkey != id.PublicKeyHex || fake.registered.Challenge != challenge {
				t.Fatalf("posts %d, registered %+v", fake.posts, fake.registered)
			}
			msg := "konareef-commission-key-registration/v1\n" + c.wantSigned + "\n" + id.PublicKeyHex + "\n" + challenge
			digest := sha256.Sum256([]byte(msg))
			sig, _ := hex.DecodeString(fake.registered.Signature)
			if ok, err := identity.VerifyDigest(id.PublicKeyHex, digest[:], sig); !ok || err != nil {
				t.Fatalf("the signature does not cover account %s: %v", c.wantSigned, err)
			}
		})
	}
}

// TestCommissionKeyRegisterNoTerminalRefusesOffline checks that, without
// --confirm-key-register and with no terminal, the command refuses before
// any request: it does not create a server challenge it cannot use.
func TestCommissionKeyRegisterNoTerminalRefusesOffline(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	fake := &keyRegFake{challengeBody: challengeJSON(strings.Repeat("cd", 32), `,"user_id":"`+keyRegAccount+`"`)}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	for _, extra := range [][]string{nil, {"--account", keyRegAccount}} {
		args := append([]string{"commission", "key", "register", "--server", srv.URL, "--token", "dG9rZW4="}, extra...)
		res := runCommissionCLI(t, bin, home, args...)
		if res.code != exitNotConfirmed || !strings.Contains(res.stderr, "refusing to continue without confirmation") {
			t.Fatalf("%v: exit %d\n%s", extra, res.code, res.combined())
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.challenges != 0 || fake.posts != 0 {
		t.Fatalf("an unconfirmed run sent requests: challenges %d, posts %d", fake.challenges, fake.posts)
	}
}

// runKeyRegisterAtTerminal runs runCommissionKeyRegister in process as if
// stdin were a terminal that types answer. Output: stdout, stderr and the
// exit code.
func runKeyRegisterAtTerminal(t *testing.T, home, answer string, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv("HOME", home)
	restoreTerminal := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = restoreTerminal }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(answer)
	w.Close()
	restoreStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = restoreStdin; r.Close() }()
	var stdout, stderr bytes.Buffer
	code := runCommissionKeyRegister(&stdout, &stderr, args)
	return stdout.String(), stderr.String(), code
}

// TestCommissionKeyRegisterPromptNamesServerAccount checks the terminal
// prompt: it names the account from the server's challenge before
// anything is signed. "n" posts nothing; "y" registers over that account.
func TestCommissionKeyRegisterPromptNamesServerAccount(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	fake := &keyRegFake{challengeBody: challengeJSON(strings.Repeat("cd", 32), `,"user_id":"`+keyRegAccount+`"`)}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	args := []string{"--server", srv.URL, "--token", "dG9rZW4="}

	stdout, stderr, code := runKeyRegisterAtTerminal(t, home, "n\n", args...)
	fake.mu.Lock()
	challenges, posts := fake.challenges, fake.posts
	fake.mu.Unlock()
	if code != exitNotConfirmed || challenges != 1 || posts != 0 {
		t.Fatalf("declined: exit %d, challenges %d, posts %d\n%s%s", code, challenges, posts, stdout, stderr)
	}
	if !strings.Contains(stdout, "for account "+keyRegAccount) || !strings.Contains(stdout, "user_id printed when your session was issued") {
		t.Fatalf("the prompt does not name the server's account:\n%s", stdout)
	}

	stdout, stderr, code = runKeyRegisterAtTerminal(t, home, "y\n", args...)
	fake.mu.Lock()
	posts = fake.posts
	fake.mu.Unlock()
	if code != 0 || posts != 1 {
		t.Fatalf("accepted: exit %d, posts %d\n%s%s", code, posts, stdout, stderr)
	}
}

// TestCommissionKeyRegisterExpiredChallengeHint checks that the server's
// commission_key_challenge_invalid refusal (a challenge older than 5
// minutes, or replaced) is exit 5 with a hint to run the command again.
func TestCommissionKeyRegisterExpiredChallengeHint(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	fake := &keyRegFake{
		challengeBody:  challengeJSON(strings.Repeat("cd", 32), `,"user_id":"`+keyRegAccount+`"`),
		registerStatus: http.StatusUnprocessableEntity,
		registerBody:   `{"error":{"kind":"commission_key_challenge_invalid","message":"the challenge is unknown, expired, already used, or was issued to another session"}}`,
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	res := runCommissionCLI(t, bin, home, "commission", "key", "register", "--server", srv.URL, "--token", "dG9rZW4=", "--confirm-key-register")
	if res.code != exitServerRefused || !strings.Contains(res.stderr, "commission_key_challenge_invalid") || !strings.Contains(res.stderr, "Run the command again") {
		t.Fatalf("exit %d\n%s", res.code, res.combined())
	}
}

// TestCommissionKeyRegisterBadAccountFlagSendsNothing checks that a
// malformed --account is a usage error before any request.
func TestCommissionKeyRegisterBadAccountFlagSendsNothing(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	fake := &keyRegFake{challengeBody: challengeJSON(strings.Repeat("cd", 32), `,"user_id":"`+keyRegAccount+`"`)}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	res := runCommissionCLI(t, bin, home, "commission", "key", "register", "--account", "alice", "--server", srv.URL, "--token", "dG9rZW4=", "--confirm-key-register")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if res.code != 2 || fake.challenges != 0 || fake.posts != 0 {
		t.Fatalf("exit %d, challenges %d, posts %d\n%s", res.code, fake.challenges, fake.posts, res.combined())
	}
}
