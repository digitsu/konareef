// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// node_key_file_test.go: tests for the node key file of the chain-head
// anchor check (US-007, ~/.proof_server_node_key). They check that an
// absent file adds no keys, that comments, blank lines and spaces are
// ignored, that a bad line or an unreadable file is an error that names
// the file (and the line), that KONAREEF_NODE_KEY_FILE="" turns the file
// off, and that a key in the file makes an anchor from that key verified
// on the production entry. No test here reads the real file in the home
// directory: TestMain sets DefaultNodeKeyFile and NodeKeyFileEnv to "".
package verify

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// otherCompressedKey is a valid compressed key hex that is not the beta
// node key; only its format matters to the file parser.
const otherCompressedKey = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// writeNodeKeyFile writes content to a node key file in a temporary
// directory. Inputs: t, content. Output: the file path.
func writeNodeKeyFile(t *testing.T, content string) string {
	t.Helper()
	nodeKeyPath := filepath.Join(t.TempDir(), NodeKeyFileName)
	if err := os.WriteFile(nodeKeyPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return nodeKeyPath
}

// unsetNodeKeyFileEnv removes NodeKeyFileEnv for one test and puts back
// the previous value when the test ends. t.Setenv cannot remove a
// variable, and TestMain sets it to "". Input: t.
func unsetNodeKeyFileEnv(t *testing.T) {
	t.Helper()
	previousValue, wasSet := os.LookupEnv(NodeKeyFileEnv)
	if err := os.Unsetenv(NodeKeyFileEnv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv(NodeKeyFileEnv, previousValue)
		} else {
			_ = os.Unsetenv(NodeKeyFileEnv)
		}
	})
}

// useDefaultNodeKeyFile sets DefaultNodeKeyFile for one test and puts
// back the previous value when the test ends. Inputs: t, nodeKeyPath.
func useDefaultNodeKeyFile(t *testing.T, nodeKeyPath string) {
	t.Helper()
	previousPath := DefaultNodeKeyFile
	DefaultNodeKeyFile = nodeKeyPath
	t.Cleanup(func() { DefaultNodeKeyFile = previousPath })
}

// TestNodeKeyFile_AbsentAddsNothing: a path with no file gives no keys
// and no error, through LoadNodeKeyFile and AnchorConfigFromEnv.
func TestNodeKeyFile_AbsentAddsNothing(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "no-such-file")
	keys, err := LoadNodeKeyFile(missingPath)
	if err != nil || len(keys) != 0 {
		t.Fatalf("keys=%v err=%v, want none and no error", keys, err)
	}
	t.Setenv(NodeKeyFileEnv, missingPath)
	t.Setenv(TrustedNodeKeysEnv, "")
	cfg, err := AnchorConfigFromEnv()
	if err != nil || len(cfg.TrustedNodeKeys) != 0 {
		t.Fatalf("config keys=%v err=%v, want none and no error", cfg.TrustedNodeKeys, err)
	}
}

// TestNodeKeyFile_CommentsBlankLinesAndSpaces: comments and blank lines
// are ignored, spaces around a key are removed, and the keys come back in
// file order.
func TestNodeKeyFile_CommentsBlankLinesAndSpaces(t *testing.T) {
	nodeKeyPath := writeNodeKeyFile(t, "# reefcore-beta identity key\n\n  "+
		betaNodeIdentityKey+"  \r\n\t# another node\n"+otherCompressedKey+"\n\n")
	keys, err := LoadNodeKeyFile(nodeKeyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(keys) != 2 || keys[0] != betaNodeIdentityKey || keys[1] != otherCompressedKey {
		t.Fatalf("keys = %v, want [beta, other]", keys)
	}
}

// TestNodeKeyFile_BadLineIsError: each kind of bad line gives an error
// that names the file and the line number, and does not show the line.
func TestNodeKeyFile_BadLineIsError(t *testing.T) {
	badLines := map[string]string{
		"not hex":            strings.Repeat("zz", 33),
		"uncompressed":       "04" + strings.Repeat("ab", 64),
		"bad prefix":         "05" + betaNodeIdentityKey[2:],
		"short":              betaNodeIdentityKey[:64],
		"private key format": strings.Repeat("1f", 32),
		"two keys on a line": betaNodeIdentityKey + " " + otherCompressedKey,
	}
	for name, badLine := range badLines {
		t.Run(name, func(t *testing.T) {
			nodeKeyPath := writeNodeKeyFile(t, "# header\n"+betaNodeIdentityKey+"\n\n"+badLine+"\n")
			_, err := LoadNodeKeyFile(nodeKeyPath)
			if err == nil {
				t.Fatal("bad line accepted")
			}
			message := err.Error()
			if !strings.Contains(message, nodeKeyPath) || !strings.Contains(message, "line 4") {
				t.Fatalf("error %q does not name the file and line 4", message)
			}
			if strings.Contains(message, badLine) {
				t.Fatalf("error %q shows the text of the bad line", message)
			}
		})
	}
}

// TestNodeKeyFile_BadLineFailsConfig: a bad line makes AnchorConfigFromEnv
// fail, and the production entry refuses the bundle with
// ErrAnchorConfigInvalid. The bad line is not skipped.
func TestNodeKeyFile_BadLineFailsConfig(t *testing.T) {
	t.Setenv(NodeKeyFileEnv, writeNodeKeyFile(t, "0211\n"))
	if _, err := AnchorConfigFromEnv(); err == nil {
		t.Fatal("AnchorConfigFromEnv accepted a bad node key file")
	}
	p := newAnchorParts(t, "C")
	t.Setenv(VerifyBinEnv, "")
	r := VerifyV2ProductionWithAnchor(p.encode(t), false, AnchorConfig{})
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrAnchorConfigInvalid) {
			found = true
		}
	}
	if r.OK || !found {
		t.Fatalf("ok=%v, want a refusal with ErrAnchorConfigInvalid: %v", r.OK, divergenceStrings(r))
	}
}

// TestNodeKeyFile_UnreadableIsError: a path that exists but cannot be
// read as a file gives an error that names the path.
func TestNodeKeyFile_UnreadableIsError(t *testing.T) {
	directoryPath := t.TempDir()
	if _, err := LoadNodeKeyFile(directoryPath); err == nil || !strings.Contains(err.Error(), directoryPath) {
		t.Fatalf("directory as node key file: err=%v, want an error that names it", err)
	}
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file modes do not stop this user from reading")
	}
	nodeKeyPath := writeNodeKeyFile(t, betaNodeIdentityKey+"\n")
	if err := os.Chmod(nodeKeyPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeKeyFile(nodeKeyPath); err == nil || !strings.Contains(err.Error(), nodeKeyPath) {
		t.Fatalf("unreadable node key file: err=%v, want an error that names it", err)
	}
}

// TestNodeKeyFile_PathSelection: the environment variable wins, an empty
// value turns the file off (also when the default file has a bad line),
// and with the variable unset the default path is used.
func TestNodeKeyFile_PathSelection(t *testing.T) {
	badDefaultPath := writeNodeKeyFile(t, "not a key\n")
	useDefaultNodeKeyFile(t, badDefaultPath)

	t.Run("empty env turns the file off", func(t *testing.T) {
		t.Setenv(NodeKeyFileEnv, "")
		t.Setenv(TrustedNodeKeysEnv, "")
		if path := NodeKeyFilePath(); path != "" {
			t.Fatalf("path = %q, want none", path)
		}
		cfg, err := AnchorConfigFromEnv()
		if err != nil || len(cfg.TrustedNodeKeys) != 0 {
			t.Fatalf("keys=%v err=%v, want none and no error", cfg.TrustedNodeKeys, err)
		}
	})
	t.Run("env path wins over the default", func(t *testing.T) {
		envPath := writeNodeKeyFile(t, otherCompressedKey+"\n")
		t.Setenv(NodeKeyFileEnv, envPath)
		t.Setenv(TrustedNodeKeysEnv, "")
		cfg, err := AnchorConfigFromEnv()
		if err != nil || len(cfg.TrustedNodeKeys) != 1 || cfg.TrustedNodeKeys[0] != otherCompressedKey {
			t.Fatalf("keys=%v err=%v, want [other]", cfg.TrustedNodeKeys, err)
		}
	})
	t.Run("unset env uses the default", func(t *testing.T) {
		unsetNodeKeyFileEnv(t)
		if path := NodeKeyFilePath(); path != badDefaultPath {
			t.Fatalf("path = %q, want the default %q", path, badDefaultPath)
		}
		if _, err := AnchorConfigFromEnv(); err == nil {
			t.Fatal("bad default node key file accepted")
		}
	})
	t.Run("shipped default is in the home directory", func(t *testing.T) {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home directory")
		}
		if got, want := defaultNodeKeyFilePath(), filepath.Join(home, ".proof_server_node_key"); got != want {
			t.Fatalf("default path = %q, want %q", got, want)
		}
	})
}

// TestNodeKeyFile_KeysAddedToEnvKeys: the file keys are trusted in
// addition to KONAREEF_TRUSTED_NODE_KEYS and the pinned keys.
func TestNodeKeyFile_KeysAddedToEnvKeys(t *testing.T) {
	t.Setenv(NodeKeyFileEnv, writeNodeKeyFile(t, otherCompressedKey+"\n"))
	t.Setenv(TrustedNodeKeysEnv, betaNodeIdentityKey)
	cfg, err := AnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := cfg.Options()
	if err != nil {
		t.Fatal(err)
	}
	if want := len(PinnedTrustedNodeKeys) + 2; len(opts.TrustedNodeKeys) != want {
		t.Fatalf("trusted keys = %d, want %d", len(opts.TrustedNodeKeys), want)
	}
}

// TestNodeKeyFile_KeyMakesAnchorVerified runs the production entry with a
// pinned headers file in offline mode and an accepting stub verifier.
// The test identity key is not
// pinned, so with no node key file the anchor is "unattributed". With the
// key in the node key file the anchor is "verified" and attributed to
// it. With the key both in the file and in --trusted-node-key, the
// verdict does not change.
func TestNodeKeyFile_KeyMakesAnchorVerified(t *testing.T) {
	p := newAnchorParts(t, "C")
	testIdentityHex := hex.EncodeToString(p.identity)
	t.Setenv(OfflineEnv, "1")
	t.Setenv(HeadersFileEnv, writePinnedHeaders(t, p))
	t.Setenv(HeadersURLsEnv, "")
	t.Setenv(TrustedNodeKeysEnv, "")
	// chain_head_anchored needs a valid proof, so use an accepting stub
	// verifier.
	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, filepath.Join(t.TempDir(), "env.json"), acceptingVerifierStderr, 0))
	floorOnly := AnchorConfig{MaxTargetBits: "207fffff"}

	t.Setenv(NodeKeyFileEnv, "")
	r := VerifyV2ProductionWithAnchor(p.encode(t), false, floorOnly)
	if got := anchorStatus(r); got != AnchorUnattributed || r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("no file: status=%s anchored=%v, want unattributed/false: %v",
			got, r.V2Verdict.ChainHeadAnchored, divergenceStrings(r))
	}

	t.Setenv(NodeKeyFileEnv, writeNodeKeyFile(t, "# test node\n"+testIdentityHex+"\n"))
	for name, extra := range map[string]AnchorConfig{
		"file only":         floorOnly,
		"file and flag key": {MaxTargetBits: "207fffff", TrustedNodeKeys: []string{testIdentityHex}},
	} {
		r = VerifyV2ProductionWithAnchor(p.encode(t), false, extra)
		anchorVerdict := r.V2Verdict.ChainHeadAnchor
		if anchorStatus(r) != AnchorVerified || !r.V2Verdict.ChainHeadAnchored || anchorVerdict.AttributedTo != testIdentityHex {
			t.Fatalf("%s: status=%s anchored=%v attributed=%q, want verified/true/test key: %v", name,
				anchorStatus(r), r.V2Verdict.ChainHeadAnchored, anchorVerdict.AttributedTo, divergenceStrings(r))
		}
	}
}
