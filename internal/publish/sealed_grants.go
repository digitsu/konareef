// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants.go — the publish side of sealed closed-pod grants
// (MCP-C01, konareef#13; design MCP-C00, reef-core#42).
//
// internal/pod owns the carrier format and the shared rules G1–G17. This
// file connects them to a pod directory and to the server:
//
//   - CheckSealedGrants: run G1–G17 over a pod directory (pod validate,
//     pod publish).
//   - InitSealedGrants: `konareef pod grants init` — write an empty,
//     salted sealed/grants.toml and add the head marker.
//   - rotateSealedGrantsSaltOnDisk: D14, a fresh salt on every publish.
//   - verifySealedGrantsCommitted: the [_files] entry of the grants file
//     equals the bytes that were validated.
//   - Capabilities / FetchCapabilities / CheckSealedGrantsCapability: the
//     server advertisement (GET /api/health "capabilities", agreed with
//     reef-core MCP-C02) the CLI reads before a publish (section 11.2).
//
// No function here prints, logs or returns a sealed value (host, tool,
// namespace, secret name, salt). Errors name paths and rule codes only.
package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/serverurl"
)

// sealedGrantsFileMode is the mode of a grants file konareef writes. The
// file names secrets and upstream hosts, so only the author reads it.
const sealedGrantsFileMode = 0o600

// SealedGrantsState is what Prepare learned about a pod's sealed grants.
// It carries no sealed value: only whether the carrier is present and how
// many grants it holds.
type SealedGrantsState struct {
	// Marker reports whether the head carries [network].sealed_grants.
	Marker bool
	// GrantCount is the number of sealed grants (0 for an empty file or
	// when there is no carrier).
	GrantCount int
	// Emitted reports that this publish added the marker and an empty
	// grants file (always-emit, owner decision D3 = a).
	Emitted bool
	// SaltRotated reports that this publish wrote a fresh salt (D14 = a).
	SaltRotated bool
}

// sealedGrantsPath returns the absolute path of the grants file in podDir.
func sealedGrantsPath(podDir string) string {
	return filepath.Join(podDir, filepath.FromSlash(pod.SealedGrantsBodyPath))
}

// readSealedGrantsFile reports whether podDir holds a grants file and, if
// so, returns its bytes. A non-regular file at the reserved path (a
// symlink, a directory) is an error: the body walk refuses it too.
//
// Input: the pod root. Output: the bytes (nil when absent), whether the
// file is present, and an error.
func readSealedGrantsFile(podDir string) ([]byte, bool, error) {
	path := sealedGrantsPath(podDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stat %s: %w", pod.SealedGrantsBodyPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s must be a regular file", pod.SealedGrantsBodyPath)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", pod.SealedGrantsBodyPath, err)
	}
	return data, true, nil
}

// CheckSealedGrants runs the shared sealed-grants rules G1–G17 over a pod
// directory.
//
// Inputs: podTOML (the author-tree head), podDir (the pod root, where
// sealed/grants.toml is looked up), and zk (the publish's --zk choice,
// for G15). Output: the issues, the grant count (0 when there is no
// carrier or the file does not parse), and an error for an I/O failure or
// an unparseable head.
func CheckSealedGrants(podTOML []byte, podDir string, zk bool) ([]pod.Issue, int, error) {
	grants, present, err := readSealedGrantsFile(podDir)
	if err != nil {
		return nil, 0, err
	}
	issues, err := pod.ValidateSealedGrants(pod.SealedGrantsInput{
		Head: podTOML, Grants: grants, GrantsPresent: present, ZK: zk,
	})
	if err != nil {
		return nil, 0, err
	}
	count := 0
	if present {
		if parsed, parseErr := pod.ParseSealedGrantsFile(grants); parseErr == nil {
			count = len(parsed.Grants)
		}
	}
	return issues, count, nil
}

// InitSealedGrants implements `konareef pod grants init`: it writes an
// empty sealed/grants.toml with a fresh salt and adds the marker to
// pod.toml when it is missing.
//
// It refuses an open pod, an existing grants file, and a head whose
// marker it cannot add safely. The grants file is created first with
// O_EXCL, so a concurrent run cannot overwrite it.
//
// Input: the pod root. Output: whether the marker was added, or an error.
func InitSealedGrants(podDir string) (markerAdded bool, err error) {
	tomlPath := filepath.Join(podDir, "pod.toml")
	head, err := os.ReadFile(tomlPath)
	if err != nil {
		return false, fmt.Errorf("read pod.toml: %w", err)
	}
	spec, err := pod.Parse(head)
	if err != nil {
		return false, fmt.Errorf("parse pod.toml: %w", err)
	}
	if spec.Pod.Visibility != VisibilityClosed {
		return false, errors.New("sealed grants are only for closed pods; set [pod].visibility = \"closed\" first")
	}
	var editedHead []byte
	if !pod.HasSealedGrantsMarker(spec) {
		editedHead, err = pod.AddSealedGrantsMarker(head)
		if err != nil {
			return false, err
		}
	}
	content, err := pod.NewSealedGrantsFile()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(sealedGrantsPath(podDir)), 0o700); err != nil {
		return false, fmt.Errorf("create sealed/: %w", err)
	}
	file, err := os.OpenFile(sealedGrantsPath(podDir), os.O_WRONLY|os.O_CREATE|os.O_EXCL, sealedGrantsFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, fmt.Errorf("%s already exists; it was not changed", pod.SealedGrantsBodyPath)
		}
		return false, fmt.Errorf("create %s: %w", pod.SealedGrantsBodyPath, err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return false, fmt.Errorf("write %s: %w", pod.SealedGrantsBodyPath, err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("write %s: %w", pod.SealedGrantsBodyPath, err)
	}
	if editedHead != nil {
		if err := writeFileKeepMode(tomlPath, editedHead, 0); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// writeFileKeepMode replaces path with data through a temporary file in
// the same directory and a rename. With forceMode 0 it keeps the file's
// current mode; otherwise it sets forceMode.
//
// Inputs: the path, the new bytes and the mode override. Output: an
// error.
func writeFileKeepMode(path string, data []byte, forceMode os.FileMode) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if forceMode != 0 {
		mode = forceMode
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".konareef-tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// rotateSealedGrantsSaltOnDisk gives the grants file in podDir a fresh
// salt (D14 = a), changes no other byte, and sets the mode to 0600.
//
// Input: the pod root. Output: an error that names no sealed value.
func rotateSealedGrantsSaltOnDisk(podDir string) error {
	current, present, err := readSealedGrantsFile(podDir)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("%s is missing", pod.SealedGrantsBodyPath)
	}
	rotated, err := pod.RotateSealedGrantsSalt(current)
	if err != nil {
		return err
	}
	// The file names secrets and hosts: whatever mode an author gave it,
	// the rotated file is readable by the author only.
	return writeFileKeepMode(sealedGrantsPath(podDir), rotated, sealedGrantsFileMode)
}

// verifySealedGrantsCommitted checks that the canonical head's [_files]
// entry for sealed/grants.toml is the SHA-256 of grantsBytes, the bytes
// that were validated. A file changed on disk between validation and
// canonicalization would otherwise ship unvalidated.
//
// Inputs: the canonical manifest bytes and the validated file bytes.
// Output: an error when the entry is missing or differs.
func verifySealedGrantsCommitted(canonical, grantsBytes []byte) error {
	digest := sha256.Sum256(grantsBytes)
	entry := fmt.Sprintf("%q = \"sha256:%s\"\n", pod.SealedGrantsBodyPath, hex.EncodeToString(digest[:]))
	if !bytes.Contains(canonical, []byte(entry)) {
		return fmt.Errorf("%s changed while the pod was being published; publish again", pod.SealedGrantsBodyPath)
	}
	return nil
}

// Capabilities is the slice of reef-core's unauthenticated capability
// advertisement the CLI reads (MCP-C00 section 11.2). reef-core MCP-C02
// serves it inside GET /api/health:
//
//	{"capabilities": {"sealed_grants": ["konareef-sealed-grants/v1"],
//	                  "closed_grants_enabled": true}}
//
// A server that sends no "capabilities" object, or no v1 entry, cannot
// take a marker head.
type Capabilities struct {
	// SealedGrantsCarriers are the carrier versions the publish gate
	// accepts. Empty for an old server.
	SealedGrantsCarriers []string
	// ClosedGrantsEnabled mirrors the operator switch
	// :closed_grants_enabled. While it is false the server accepts
	// marker heads but refuses to spawn a pod that has grants. An absent
	// key reads as false.
	ClosedGrantsEnabled bool
}

// healthResponse is the part of the GET /api/health body the CLI decodes.
type healthResponse struct {
	Capabilities *struct {
		SealedGrants        []string `json:"sealed_grants"`
		ClosedGrantsEnabled bool     `json:"closed_grants_enabled"`
	} `json:"capabilities"`
}

// SupportsSealedGrantsV1 reports whether the server accepts the v1
// carrier.
func (capabilities Capabilities) SupportsSealedGrantsV1() bool {
	for _, carrier := range capabilities.SealedGrantsCarriers {
		if carrier == pod.SealedGrantsFormatV1 {
			return true
		}
	}
	return false
}

// SealedGrantsEnabled reports whether the server supports the v1 carrier
// and has closed grants switched on.
func (capabilities Capabilities) SealedGrantsEnabled() bool {
	return capabilities.SupportsSealedGrantsV1() && capabilities.ClosedGrantsEnabled
}

// capabilitiesBodyLimit bounds the advertisement read, so a hostile server
// cannot make the CLI buffer an unbounded body.
const capabilitiesBodyLimit = 64 << 10

// FetchCapabilities GETs <serverURL>/api/health and decodes its
// "capabilities" object.
//
// A 404, or a body without the object, is an old server and yields empty
// Capabilities with no error, so the caller refuses a marker publish
// instead of failing on transport. Any other failure is an error.
//
// Inputs: a context and the server URL. Output: the capabilities or an
// error.
func FetchCapabilities(ctx context.Context, serverURL string) (Capabilities, error) {
	endpoint, err := serverurl.Endpoint(serverURL, "api", "health")
	if err != nil {
		return Capabilities{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Capabilities{}, fmt.Errorf("capabilities: build request: %w", err)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: sameOriginRedirect}
	response, err := client.Do(request)
	if err != nil {
		return Capabilities{}, fmt.Errorf("capabilities: GET %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return Capabilities{}, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Capabilities{}, fmt.Errorf("capabilities: GET %s: status %d", endpoint, response.StatusCode)
	}
	var health healthResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, capabilitiesBodyLimit)).Decode(&health); err != nil {
		return Capabilities{}, fmt.Errorf("capabilities: decode: %w", err)
	}
	if health.Capabilities == nil {
		return Capabilities{}, nil
	}
	return Capabilities{
		SealedGrantsCarriers: health.Capabilities.SealedGrants,
		ClosedGrantsEnabled:  health.Capabilities.ClosedGrantsEnabled,
	}, nil
}

// sameOriginRedirect refuses a redirect to another scheme or host, so an
// https advertisement cannot be answered from a plain-http or foreign
// origin.
func sameOriginRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("capabilities: too many redirects")
	}
	origin := via[0].URL
	if request.URL.Scheme != origin.Scheme || request.URL.Host != origin.Host {
		return errors.New("capabilities: redirect to another origin refused")
	}
	return nil
}

// OpenPodSealedFileWarning is the advisory code for an open pod that
// contains sealed/grants.toml: the file ships in the clear.
const OpenPodSealedFileWarning = "SEALED_GRANTS_FILE_PUBLIC"

// openPodSealedFileWarnings warns when a pod that is not closed carries a
// file at the reserved path. Design section 4.2 makes that file ordinary
// public content, so it is not refused, but an author who switched a
// closed pod to open would otherwise publish its grants unawares.
//
// Inputs: the parsed head and the pod root. Output: zero or one warning.
func openPodSealedFileWarnings(spec pod.Spec, podDir string) []pod.Warning {
	if spec.Pod.Visibility == VisibilityClosed {
		return nil
	}
	if _, present, err := readSealedGrantsFile(podDir); err != nil || !present {
		return nil
	}
	return []pod.Warning{{
		Path: pod.SealedGrantsBodyPath, Code: OpenPodSealedFileWarning,
		Message: "this pod is not closed, so " + pod.SealedGrantsBodyPath + " is published in the clear with the rest of the pod; remove it, or set [pod].visibility = \"closed\"",
	}}
}

// OpenPodSealedFileWarningsFor is openPodSealedFileWarnings for raw
// pod.toml bytes, for `pod validate`. An unparseable head yields nothing;
// validation reports it.
func OpenPodSealedFileWarningsFor(podTOML []byte, podDir string) []pod.Warning {
	spec, err := pod.Parse(podTOML)
	if err != nil {
		return nil
	}
	return openPodSealedFileWarnings(spec, podDir)
}

// ErrSealedGrantsUnsupported is returned by CheckSealedGrantsCapability
// when the server cannot take a sealed-grants pod.
var ErrSealedGrantsUnsupported = errors.New("SEALED_GRANTS_SERVER_UNSUPPORTED")

// ErrSealedGrantsNotEnabled is returned when the pod has sealed grants and
// the server has not switched closed grants on (rollout step 6).
var ErrSealedGrantsNotEnabled = errors.New("SEALED_GRANTS_SERVER_NOT_ENABLED")

// CheckSealedGrantsCapability decides whether a prepared pod may go to a
// server. It never falls back to public grants or a pod-held MCP config:
// the only outcomes are "publish as prepared" and "refuse".
//
// Inputs: the prepared pod's sealed state and the server capabilities.
// Output: nil, or an error wrapping ErrSealedGrantsUnsupported /
// ErrSealedGrantsNotEnabled.
func CheckSealedGrantsCapability(state SealedGrantsState, capabilities Capabilities) error {
	if !state.Marker {
		return nil
	}
	if !capabilities.SupportsSealedGrantsV1() {
		return fmt.Errorf("%w: the server does not advertise %s, so it cannot keep this pod's grants sealed; publish refused (konareef never moves sealed grants back into the public head)",
			ErrSealedGrantsUnsupported, pod.SealedGrantsFormatV1)
	}
	if state.GrantCount > 0 && !capabilities.SealedGrantsEnabled() {
		return fmt.Errorf("%w: the server has not enabled closed-pod grants yet, so a pod with sealed grants could not run there; publish refused",
			ErrSealedGrantsNotEnabled)
	}
	return nil
}

// formatSealedIssues renders sealed-grants issues for an error message,
// one per line. The issues are value-free by construction (pod package).
func formatSealedIssues(issues []pod.Issue) string {
	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		lines = append(lines, "  - "+issue.String())
	}
	return strings.Join(lines, "\n")
}
