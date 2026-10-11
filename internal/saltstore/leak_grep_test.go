// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/leak_grep_test.go — invariant: a Type-D session's
// raw salt bytes never appear in any log line, stdout, stderr, written
// file, or build artifact (except the salt.bin file itself, which is
// where the salt is supposed to live). This test runs an end-to-end
// mini-session (Put salt → Get salt → log a few messages that could
// have leaked the salt if the code were sloppy) and then sweeps every
// captured output for the literal salt bytes.
package saltstore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestSaltNeverLeaksToFilesOrLogs(t *testing.T) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	saltHexPattern := []byte(hex.EncodeToString(salt[:]))

	root := t.TempDir()
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})

	// Capture stdout / stderr / log destinations.
	stdout, stderr, lg := captureAll(t)
	defer stdout.Restore()
	defer stderr.Restore()
	defer lg.Restore()

	lid := [16]byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xAA, 0xBB, 0xCC}
	if err := b.Put(lid, salt); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(lid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != salt {
		t.Fatal("round-trip salt mismatch")
	}
	// Simulate session-start work: log a few messages that COULD have
	// leaked the salt if the code were sloppy.
	log.Printf("saltstore: opened lineage %x", lid)
	log.Printf("saltstore: backend=%s", b.Name())

	// The on-disk salt.bin DOES contain the raw bytes (that's its
	// job) — exclude that file from the sweep.
	saltPath := filepath.Join(root, "typed", hex.EncodeToString(lid[:]), "salt.bin")

	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || p == saltPath {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(body, salt[:]) {
			t.Errorf("RAW salt bytes leaked into %s", p)
		}
		if bytes.Contains(body, saltHexPattern) {
			t.Errorf("HEX-encoded salt leaked into %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Sweep captured stdout / stderr / log buffers.
	for name, buf := range map[string][]byte{
		"stdout": stdout.Bytes(),
		"stderr": stderr.Bytes(),
		"log":    lg.Bytes(),
	} {
		if bytes.Contains(buf, salt[:]) {
			t.Errorf("RAW salt bytes leaked into %s", name)
		}
		if bytes.Contains(buf, saltHexPattern) {
			t.Errorf("HEX salt leaked into %s", name)
		}
	}
}

// captured redirects an output stream into an in-memory buffer.
type captured struct {
	buf    *bytes.Buffer
	orig   *os.File
	target **os.File
	logorg io.Writer
}

func (c *captured) Bytes() []byte  { return c.buf.Bytes() }
func (c *captured) String() string { return c.buf.String() }
func (c *captured) Restore() {
	if c.target != nil {
		*c.target = c.orig
	}
	if c.logorg != nil {
		log.SetOutput(c.logorg)
	}
}

func captureAll(t *testing.T) (*captured, *captured, *captured) {
	t.Helper()
	stdout := captureStream(&os.Stdout)
	stderr := captureStream(&os.Stderr)
	lg := &captured{buf: &bytes.Buffer{}, logorg: log.Writer()}
	log.SetOutput(lg.buf)
	return stdout, stderr, lg
}

func captureStream(p **os.File) *captured {
	orig := *p
	r, w, _ := os.Pipe()
	*p = w
	buf := &bytes.Buffer{}
	go func() {
		_, _ = io.Copy(buf, r)
	}()
	return &captured{buf: buf, orig: orig, target: p}
}
