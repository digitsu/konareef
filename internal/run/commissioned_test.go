// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commissioned_test.go — the commissioned-run client against an httptest
// server that answers as reef-core's POST /api/commissioned-runs does
// (reef-core CommissionedRunController, Refusal and Claims.response): the
// accepted control, the replay, every refusal code, a server without the
// route, retries of the same request, cancellation, a receipt that does
// not match, and the advisory local check.

package run

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

// admissionVectorsPath is the shared admission_v1 fixture (IB-00), which
// reef-core vendors byte for byte.
const admissionVectorsPath = "../commission/testdata/admission_v1/vectors.json"

// vectorsFile is the part of vectors.json these tests read.
type vectorsFile struct {
	Keys []struct {
		Name          string `json:"name"`
		PrivateKeyHex string `json:"private_key_hex"`
		PublicKeyHex  string `json:"public_key_hex"`
	} `json:"keys"`
	Pods []struct {
		Name       string `json:"name"`
		Handle     string `json:"handle"`
		PodName    string `json:"pod_name"`
		PodVersion string `json:"pod_version"`
		Manifest   string `json:"manifest"`
	} `json:"published_pods"`
	Cases []struct {
		ID      string `json:"id"`
		WireHex string `json:"wire_hex"`
		Expect  struct {
			HCommission string `json:"h_commission"`
		} `json:"expect"`
	} `json:"cases"`
}

// fixture is the A01 control of the admission vectors: the signed
// commission, the manifest it pins, and the expected wire bytes.
type fixture struct {
	vectors  vectorsFile
	signed   commission.Commission
	manifest []byte
	wire     []byte
	hComm    string
}

// loadFixture rebuilds vector A01 through the production path: a proposal
// signed by commission.Sign with the buyer-a test key.
func loadFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile(admissionVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	fx := fixture{vectors: v, manifest: []byte(podManifest(t, v, "mf-ok"))}
	for _, c := range v.Cases {
		if c.ID == "A01" {
			fx.wire, _ = hex.DecodeString(c.WireHex)
			fx.hComm = c.Expect.HCommission
		}
	}
	fx.signed = signFor(t, v, "buyer-a", fx.manifest, "dave/admit-fixture@1.0.0",
		[]string{"anthropic/claude-sonnet-4-5"}, []string{"bash", "ripgrep"}, 2500)
	return fx
}

// podManifest returns the manifest of the named fixture pod.
func podManifest(t *testing.T, v vectorsFile, name string) string {
	t.Helper()
	for _, p := range v.Pods {
		if p.Name == name {
			return p.Manifest
		}
	}
	t.Fatalf("no fixture pod %s", name)
	return ""
}

// signFor signs a commission over manifest with the named fixture key.
func signFor(t *testing.T, v vectorsFile, key string, manifest []byte, podRef string, models, tools []string, cMax uint64) commission.Commission {
	t.Helper()
	var id *identity.Identity
	for _, k := range v.Keys {
		if k.Name == key {
			id = &identity.Identity{PrivateKeyHex: k.PrivateKeyHex, PublicKeyHex: k.PublicKeyHex}
		}
	}
	pin, err := commission.ManifestFieldsRoot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	p := commission.Proposal{
		Envelope: envelope.Envelope{Models: models, Tools: tools, CMax: cMax,
			ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true},
		Binding: commission.Binding{PodRef: podRef, HManifest: sha256.Sum256(manifest), FieldsRoot: pin},
		Prose:   "Review the open merge requests and summarise the risky ones.",
	}
	c, err := commission.Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeReefCore records every request and answers the commission route
// with a scripted sequence of responses.
type fakeReefCore struct {
	t         *testing.T
	fx        fixture
	mu        sync.Mutex
	requests  []recorded
	responses []func(w http.ResponseWriter, r *http.Request)
}

// recorded is one captured request.
type recorded struct {
	method, path, contentType, auth string
	body                            []byte
}

// newFake starts a fake server. Each POST to the commission route takes the
// next scripted response; when the script is used up, the last one repeats.
func newFake(t *testing.T, fx fixture, responses ...func(w http.ResponseWriter, r *http.Request)) (*fakeReefCore, *httptest.Server) {
	f := &fakeReefCore{t: t, fx: fx, responses: responses}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeReefCore) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, recorded{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), body})
	n := 0
	for _, req := range f.requests {
		if req.path == "/api/commissioned-runs" {
			n++
		}
	}
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/commissioned-runs":
		i := n - 1
		if i >= len(f.responses) {
			i = len(f.responses) - 1
		}
		f.responses[i](w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
		// reef-core#98: collectRun needs a completed run_outcome beside the
		// custody proof, or it fails closed.
		json.NewEncoder(w).Encode(map[string]any{"proofs": []map[string]any{
			{"proof_type": "run_outcome", "hash": "0utc0me", "agent_id": "agent-1", "data": "RUN_OUTCOME: v1\n{\"run_status\":\"completed\"}"},
			{"proof_type": "custody", "hash": "c0ffee", "agent_id": "agent-1"},
		}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
		json.NewEncoder(w).Encode(map[string]any{"deliverables": []any{}})
	default:
		http.NotFound(w, r)
	}
}

// commissionPosts returns the captured commission-route requests.
func (f *fakeReefCore) commissionPosts() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, r := range f.requests {
		if r.path == "/api/commissioned-runs" {
			out = append(out, r)
		}
	}
	return out
}

// assertNoFallback fails if any request reached an uncommissioned spawn
// route.
func (f *fakeReefCore) assertNoFallback() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r.path == "/api/pods/spawn" || (r.method == http.MethodPost && r.path == "/api/agents") {
			f.t.Fatalf("request fell back to %s %s", r.method, r.path)
		}
	}
}

// receiptFor builds the receipt reef-core's Claims.receipt/1 returns for fx.
func receiptFor(fx fixture) map[string]any {
	p := fx.signed.Proposal()
	return map[string]any{
		"receipt_id": "7b0c8f7e-0000-4000-8000-000000000001", "contract": commission.AdmissionContractV1,
		"assurance_mode": commission.AssuranceModeLimitedV1, "h_commission": fx.hComm,
		"signer_pubkey": fx.signed.PubKeyHex, "signer_key_id": "7b0c8f7e-0000-4000-8000-000000000002",
		"pod_hash": hex.EncodeToString(p.Binding.HManifest[:]), "pod_ref": p.Binding.PodRef,
		"fields_root": hex.EncodeToString(p.Binding.FieldsRoot[:]), "memory_class": "rinit_v1",
		"derived":   map[string]any{"models": []string{"anthropic/claude-sonnet-4-5"}, "tools": []string{"bash", "ripgrep"}, "c_max_sats": 2500},
		"fees":      map[string]any{"author_fee_sats": 0, "zk_fee_sats": 0, "bounded_by_commission": true},
		"run_state": "started", "effective": map[string]any{"model_id": "anthropic/claude-sonnet-4-5", "budget_sats": 2500},
		"dimensions": map[string]string{"models": "admission_checked", "tools": "admission_checked_declared_only",
			"spend": "admission_checked", "labels": "not_evaluated", "memory": "declares_no_initial_memory_and_commits_empty_root"},
		"inputs": "not_buyer_signed", "verifier_impl": "reef-core/test", "admitted_at": "2026-09-25T00:00:00Z",
		"authenticity": "api_session_only",
	}
}

// started answers as a 201 (or 200 for a replay) with the spawn fields and
// the receipt, plus an unknown field a newer server might add.
func started(fx fixture, status int, edit func(map[string]any)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		receipt := receiptFor(fx)
		if edit != nil {
			edit(receipt)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-1", "pod_id": "pod-1", "task_id": "task-1", "snapshot_id": "snap-1",
			"bundle_hash": "abcd", "bundle_file_count": 3, "receipt": receipt, "future_field": map[string]any{"x": 1},
		})
	}
}

// refusal answers with reef-core's error body shape.
func refusal(status int, kind string, extra map[string]any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"kind": kind, "message": "commission refused: " + kind}
		for k, v := range extra {
			body[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": body})
	}
}

// config returns a commissioned-run config for srv with fast retries.
func config(srv *httptest.Server, fx fixture) CommissionedConfig {
	return CommissionedConfig{
		BaseURL: srv.URL, SessionToken: "dG9rZW4=", Commission: fx.signed,
		Inputs: map[string]string{"topic": "risky MRs"}, OutDir: "",
		MaxAttempts: 3, RetryDelay: time.Millisecond, Timeout: time.Second, PollInterval: time.Millisecond,
	}
}

// TestCommissionedControlIsVectorA01 pins the fixture: the production
// signing and encoding path reproduces vector A01 byte for byte.
func TestCommissionedControlIsVectorA01(t *testing.T) {
	fx := loadFixture(t)
	wire, err := commission.EncodeWireV1(fx.signed)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(wire) != hex.EncodeToString(fx.wire) {
		t.Fatal("control wire is not vector A01")
	}
	if h, _ := fx.signed.HCommissionHex(); h != fx.hComm {
		t.Fatalf("h_commission %s, want %s", h, fx.hComm)
	}
}

// TestSubmitCommissionedAccepted is the successful control. The wire
// capture proves the server receives exactly the signed bytes, the four
// allowed keys and nothing that names a pod, model or budget.
func TestSubmitCommissionedAccepted(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, started(fx, http.StatusCreated, nil))
	cfg := config(srv, fx)
	var out strings.Builder
	cfg.Out = &out
	cfg.OutDir = t.TempDir()

	outcome, err := RunCommissioned(context.Background(), cfg, LocalCheck{LocalContained, "ok"})
	if err != nil {
		t.Fatalf("RunCommissioned: %v", err)
	}
	if outcome.Replayed || outcome.Attempts != 1 || outcome.Response.Receipt.ReceiptID == "" {
		t.Fatalf("outcome = %+v", outcome)
	}

	posts := fake.commissionPosts()
	if len(posts) != 1 {
		t.Fatalf("%d posts, want 1", len(posts))
	}
	got := posts[0]
	if got.contentType != "application/json" || got.auth != "Bearer dG9rZW4=" {
		t.Fatalf("content-type %q auth %q", got.contentType, got.auth)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(got.body, &body); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range body {
		keys = append(keys, k)
	}
	if len(body) != 4 || body["contract"] == nil || body["assurance_mode"] == nil || body["commission"] == nil || body["inputs"] == nil {
		t.Fatalf("request keys %v, want exactly contract, assurance_mode, commission, inputs", keys)
	}
	var contract, mode, b64 string
	json.Unmarshal(body["contract"], &contract)
	json.Unmarshal(body["assurance_mode"], &mode)
	json.Unmarshal(body["commission"], &b64)
	if contract != "konareef-commission-admission/v1" || mode != "memory_free_limited/v1" {
		t.Fatalf("contract %q mode %q", contract, mode)
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		t.Fatalf("commission is not padded standard base64: %v", err)
	}
	if hex.EncodeToString(wire) != hex.EncodeToString(fx.wire) {
		t.Fatal("the transmitted wire bytes are not the signed vector A01 bytes")
	}
	// Presence survives: the stated-empty labels set is CBOR null (0xf6)
	// under canonical key 3, exactly as signed.
	if !strings.Contains(hex.EncodeToString(wire), "03f604") {
		t.Fatal("stated-empty labels did not survive as null")
	}
	wantDigest := sha256.Sum256([]byte(`{"topic":"risky MRs"}`))
	if outcome.RequestDigest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("request digest %s", outcome.RequestDigest)
	}
	fake.assertNoFallback()

	text := out.String()
	for _, want := range []string{
		"signature valid:   yes, checked locally",
		"locally contained: contained",
		"(advisory; the server checks again)",
		"server admitted:   yes, new run",
		"labels:          not_evaluated",
		"tools:           admission_checked_declared_only",
		"executed:          started: agent_id=agent-1",
		"proof verified:    no",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status output lacks %q:\n%s", want, text)
		}
	}
}

// TestSubmitCommissionedOmitsEmptyInputs: an omitted inputs key is read by
// the server as {}, and the digest is SHA-256("{}").
func TestSubmitCommissionedOmitsEmptyInputs(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, started(fx, http.StatusCreated, nil))
	cfg := config(srv, fx)
	cfg.Inputs = nil
	outcome, err := SubmitCommissioned(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fake.commissionPosts()[0].body), "inputs") {
		t.Fatal("empty inputs were sent")
	}
	empty := sha256.Sum256([]byte("{}"))
	if outcome.RequestDigest != hex.EncodeToString(empty[:]) {
		t.Fatalf("digest %s", outcome.RequestDigest)
	}
}

// TestSubmitCommissionedReplay: a 200 is the same account's earlier run of
// the same request; it is reported as a replay, not a new run.
func TestSubmitCommissionedReplay(t *testing.T) {
	fx := loadFixture(t)
	_, srv := newFake(t, fx, started(fx, http.StatusOK, nil))
	cfg := config(srv, fx)
	var out strings.Builder
	cfg.Out = &out
	cfg.OutDir = t.TempDir()
	outcome, err := RunCommissioned(context.Background(), cfg, LocalCheck{LocalContained, "ok"})
	if err != nil || !outcome.Replayed {
		t.Fatalf("outcome %+v err %v", outcome, err)
	}
	if !strings.Contains(out.String(), "replay; no second run") {
		t.Fatalf("status does not say replay:\n%s", out.String())
	}
}

// refusalCodes are the admission contract §18 codes reef-core returns on
// the commission route, with their HTTP statuses (reef-core Refusal).
// commission_admission_in_progress and commission_claim_lost are retried
// and have their own tests.
var refusalCodes = map[string]int{
	"commission_admission_disabled": 503, "commission_request_too_large": 413,
	"commission_request_invalid": 400, "commission_contract_unsupported": 422,
	"assurance_mode_required": 422, "assurance_mode_unsupported": 422,
	"commission_too_large": 413, "commission_malformed": 422,
	"commission_version_unsupported": 422, "commission_noncanonical": 422,
	"commission_signature_invalid": 422, "commission_invalid": 422,
	"commission_signer_unregistered": 403, "commission_signer_not_authorized": 403,
	"commission_signer_retired": 403, "commission_revoked": 403,
	"commission_pod_not_found": 404, "commission_binding_mismatch": 422,
	"commission_manifest_version_unsupported": 422, "commission_manifest_commitment_unreadable": 422,
	"commission_memory_unsupported": 422, "commission_sealed_grants_unsupported": 422,
	"commission_model_undeclared": 422, "commission_budget_undeclared": 422,
	"commission_tool_policy_invalid": 422, "commission_manifest_invalid": 422,
	"commission_fields_root_unpinned": 422, "commission_fields_root_mismatch": 422,
	"commission_fields_root_unrecognized": 422, "commission_not_contained": 422,
	"commission_replay_conflict": 409, "commission_runtime_unsupported": 422,
	"commission_effective_mismatch": 500, "commission_route_required": 422,
	"commission_admission_not_authentic": 500,
	"pod_not_listed":                     402,
}

// TestSubmitCommissionedRefusalsAreFinal: every coded refusal is returned
// with the server's code unchanged, after exactly one request, with no
// retry and no request to any other spawn route.
func TestSubmitCommissionedRefusalsAreFinal(t *testing.T) {
	fx := loadFixture(t)
	for code, status := range refusalCodes {
		t.Run(code, func(t *testing.T) {
			fake, srv := newFake(t, fx, refusal(status, code, nil))
			cfg := config(srv, fx)
			var out strings.Builder
			cfg.Out = &out
			_, err := RunCommissioned(context.Background(), cfg, LocalCheck{LocalContained, "ok"})
			var serverErr *api.ServerError
			if !errors.As(err, &serverErr) || serverErr.Kind != code || serverErr.Status != status {
				t.Fatalf("err = %v, want *ServerError %d %s", err, status, code)
			}
			if n := len(fake.commissionPosts()); n != 1 {
				t.Fatalf("%d requests, want 1 (no retry)", n)
			}
			fake.assertNoFallback()
			if !strings.Contains(out.String(), "server admitted:   no — http") || !strings.Contains(out.String(), code) {
				t.Fatalf("status does not name the refusal:\n%s", out.String())
			}
			if strings.Contains(out.String(), "executed:          started") {
				t.Fatal("a refused run is shown as executed")
			}
		})
	}
}

// TestSubmitCommissionedNotContainedDetails: a containment refusal names
// every failing dimension with the server's values.
func TestSubmitCommissionedNotContainedDetails(t *testing.T) {
	fx := loadFixture(t)
	_, srv := newFake(t, fx, refusal(422, "commission_not_contained", map[string]any{
		"failed_dimensions": []string{"tools", "spend_total"},
		"details": map[string]any{
			"tools":       map[string]any{"not_permitted": []string{"curl"}},
			"spend_total": map[string]any{"c_max_sats": 2500, "fees_sats": 200, "commission_c_max_sats": 2600},
		},
	}))
	_, err := SubmitCommissioned(context.Background(), config(srv, fx))
	var serverErr *api.ServerError
	if !errors.As(err, &serverErr) || serverErr.Kind != "commission_not_contained" {
		t.Fatalf("err = %v", err)
	}
	text := err.Error()
	for _, want := range []string{"tools: {\"not_permitted\":[\"curl\"]}", "spend_total:", "\"fees_sats\":200"} {
		if !strings.Contains(text, want) {
			t.Errorf("error lacks %q: %s", want, text)
		}
	}
}

// TestSubmitCommissionedLegacyServer: a server without the route answers
// 404 (or 405) with no refusal code. The run fails; nothing falls back.
func TestSubmitCommissionedLegacyServer(t *testing.T) {
	fx := loadFixture(t)
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		fake, srv := newFake(t, fx, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"errors":{"detail":"Not Found"}}`))
		})
		_, err := SubmitCommissioned(context.Background(), config(srv, fx))
		if !errors.Is(err, api.ErrCommissionRouteMissing) {
			t.Fatalf("status %d: err = %v, want ErrCommissionRouteMissing", status, err)
		}
		if n := len(fake.commissionPosts()); n != 1 {
			t.Fatalf("%d requests, want 1", n)
		}
		fake.assertNoFallback()
	}
}

// TestSubmitCommissionedRetriesSameRequest: after a transport timeout and
// after a 409 in progress, the client sends the byte-identical request
// again; the server's replay answer (200) is the same run.
func TestSubmitCommissionedRetriesSameRequest(t *testing.T) {
	fx := loadFixture(t)
	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}
	fake, srv := newFake(t, fx, slow,
		refusal(409, "commission_admission_in_progress", nil),
		started(fx, http.StatusOK, nil))
	cfg := config(srv, fx)
	cfg.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
	outcome, err := SubmitCommissioned(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SubmitCommissioned: %v", err)
	}
	if !outcome.Replayed || outcome.Attempts != 3 {
		t.Fatalf("outcome %+v", outcome)
	}
	posts := fake.commissionPosts()
	for i := range posts {
		if string(posts[i].body) != string(posts[0].body) {
			t.Fatalf("attempt %d sent a different body", i+1)
		}
	}
	fake.assertNoFallback()
}

// TestSubmitCommissionedRetriesAreBounded: transport failures stop after
// MaxAttempts identical requests and are reported as transport errors,
// distinct from a server refusal.
func TestSubmitCommissionedRetriesAreBounded(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>bad gateway</html>"))
	})
	_, err := SubmitCommissioned(context.Background(), config(srv, fx))
	var transport *api.TransportError
	if !errors.As(err, &transport) || transport.Status != http.StatusBadGateway {
		t.Fatalf("err = %v, want *TransportError 502", err)
	}
	var serverErr *api.ServerError
	if errors.As(err, &serverErr) {
		t.Fatal("a transport failure was reported as a server refusal")
	}
	if n := len(fake.commissionPosts()); n != 3 {
		t.Fatalf("%d requests, want 3", n)
	}
	fake.assertNoFallback()
}

// TestSubmitCommissionedDoesNotFollowRedirects: a redirect could point the
// signed request at another route; it is refused, not followed.
func TestSubmitCommissionedDoesNotFollowRedirects(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/pods/spawn", http.StatusTemporaryRedirect)
	})
	cfg := config(srv, fx)
	cfg.MaxAttempts = 1
	_, err := SubmitCommissioned(context.Background(), cfg)
	var transport *api.TransportError
	if !errors.As(err, &transport) || transport.Status != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want a transport error for the redirect", err)
	}
	fake.assertNoFallback()
}

// TestSubmitCommissionedCancellation: cancelling during a request stops at
// once, is not retried, and says a repeat returns the same run.
func TestSubmitCommissionedCancellation(t *testing.T) {
	fx := loadFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fake, srv := newFake(t, fx, func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	})
	_, err := SubmitCommissioned(ctx, config(srv, fx))
	if !errors.Is(err, ErrSubmitCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrSubmitCancelled", err)
	}
	if n := len(fake.commissionPosts()); n != 1 {
		t.Fatalf("%d requests after cancel, want 1", n)
	}
	fake.assertNoFallback()
}

// TestSubmitCommissionedReceiptMismatch: a 201 whose receipt names another
// commission, pod or an effective value outside the commission is not
// reported as admission, and the run is not collected.
func TestSubmitCommissionedReceiptMismatch(t *testing.T) {
	fx := loadFixture(t)
	edits := map[string]func(map[string]any){
		"h_commission": func(r map[string]any) { r["h_commission"] = strings.Repeat("00", 32) },
		"pod_hash":     func(r map[string]any) { r["pod_hash"] = strings.Repeat("11", 32) },
		"pod_ref":      func(r map[string]any) { r["pod_ref"] = "mallory/admit-fixture@1.0.0" },
		"mode":         func(r map[string]any) { r["assurance_mode"] = "full/v1" },
		"fields_root":  func(r map[string]any) { r["fields_root"] = strings.Repeat("22", 32) },
		"model": func(r map[string]any) {
			r["effective"] = map[string]any{"model_id": "anthropic/claude-opus-4", "budget_sats": 2500}
		},
		"budget": func(r map[string]any) {
			r["effective"] = map[string]any{"model_id": "anthropic/claude-sonnet-4-5", "budget_sats": 1000000}
		},
		"derived tool": func(r map[string]any) {
			r["derived"] = map[string]any{"models": []string{"anthropic/claude-sonnet-4-5"}, "tools": []string{"curl"}, "c_max_sats": 2500}
		},
		"signer":        func(r map[string]any) { r["signer_pubkey"] = "02" + strings.Repeat("ab", 32) },
		"missing field": func(r map[string]any) { delete(r, "contract") },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			fake, srv := newFake(t, fx, started(fx, http.StatusCreated, edit))
			cfg := config(srv, fx)
			var out strings.Builder
			cfg.Out = &out
			outcome, err := RunCommissioned(context.Background(), cfg, LocalCheck{LocalContained, "ok"})
			if !errors.Is(err, ErrReceiptMismatch) || outcome == nil {
				t.Fatalf("err = %v, want ErrReceiptMismatch with the outcome", err)
			}
			if !strings.Contains(out.String(), "server admitted:   UNTRUSTED") {
				t.Fatalf("status:\n%s", out.String())
			}
			for _, r := range fake.requests {
				if r.path == "/api/proofs" {
					t.Fatal("the run was collected despite the mismatch")
				}
			}
		})
	}
}

// TestSubmitCommissionedSuccessWithoutReceipt: a 201 with no receipt is
// not evidence of admission.
func TestSubmitCommissionedSuccessWithoutReceipt(t *testing.T) {
	fx := loadFixture(t)
	_, srv := newFake(t, fx, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"agent_id":"agent-1"}`))
	})
	cfg := config(srv, fx)
	cfg.MaxAttempts = 1
	if _, err := SubmitCommissioned(context.Background(), cfg); err == nil {
		t.Fatal("a success with no receipt was accepted")
	}
}

// TestSubmitCommissionedRefusesUnsendableCommission: an artifact whose
// signature does not verify, or whose presence flags were edited, never
// produces a request.
func TestSubmitCommissionedRefusesUnsendableCommission(t *testing.T) {
	fx := loadFixture(t)
	p := fx.signed.Proposal()
	tampered := p
	tampered.Prose = "something else"
	unstated := p
	unstated.Envelope.LabelsSet = false
	for name, c := range map[string]commission.Commission{
		"unsigned":         commission.Reconstruct(p, fx.signed.PubKeyHex, nil),
		"tampered prose":   commission.Reconstruct(tampered, fx.signed.PubKeyHex, fx.signed.Sig),
		"labels unstated":  commission.Reconstruct(unstated, fx.signed.PubKeyHex, fx.signed.Sig),
		"another key sigs": commission.Reconstruct(p, "03"+strings.Repeat("11", 32), fx.signed.Sig),
	} {
		fake, srv := newFake(t, fx, started(fx, http.StatusCreated, nil))
		cfg := config(srv, fx)
		cfg.Commission = c
		if _, err := SubmitCommissioned(context.Background(), cfg); !errors.Is(err, commission.ErrWireEncode) {
			t.Errorf("%s: err = %v, want ErrWireEncode", name, err)
		}
		if len(fake.requests) != 0 {
			t.Errorf("%s: %d requests were sent", name, len(fake.requests))
		}
	}
}

// TestCheckLocally covers the advisory local check: the contained control,
// a narrower commission, a manifest that is not the pinned one, a sealed
// grants pod, and a fetch failure that does not block.
func TestCheckLocally(t *testing.T) {
	fx := loadFixture(t)
	serve := func(manifest []byte) ManifestFetcher {
		return func(handle, podName, version string) ([]byte, error) {
			if handle != "dave" || podName != "admit-fixture" {
				t.Fatalf("fetched %s/%s@%s", handle, podName, version)
			}
			return manifest, nil
		}
	}
	if got := CheckLocally(fx.signed, serve(fx.manifest)); got.State != LocalContained || got.Blocks() {
		t.Fatalf("control: %+v", got)
	}

	narrow := signFor(t, fx.vectors, "buyer-a", fx.manifest, "dave/admit-fixture@1.0.0",
		[]string{"anthropic/claude-sonnet-4-5"}, []string{"bash"}, 2500)
	if got := CheckLocally(narrow, serve(fx.manifest)); got.State != LocalNotContained || !got.Blocks() || !strings.Contains(got.Detail, "ripgrep") {
		t.Fatalf("narrow: %+v", got)
	}

	other := []byte(podManifest(t, fx.vectors, "mf-legacy"))
	if got := CheckLocally(fx.signed, serve(other)); got.State != LocalRefused || !got.Blocks() {
		t.Fatalf("other manifest: %+v", got)
	}

	sealedManifest := []byte(podManifest(t, fx.vectors, "mf-sealed"))
	sealed := signFor(t, fx.vectors, "buyer-a", sealedManifest, "dave/admit-fixture@1.0.11",
		[]string{"anthropic/claude-sonnet-4-5"}, []string{"bash", "ripgrep"}, 2500)
	if got := CheckLocally(sealed, serve(sealedManifest)); got.State != LocalRefused || !strings.Contains(got.Detail, "commission_sealed_grants_unsupported") {
		t.Fatalf("sealed: %+v", got)
	}

	failing := func(string, string, string) ([]byte, error) { return nil, errors.New("connection refused") }
	if got := CheckLocally(fx.signed, failing); got.State != LocalNotChecked || got.Blocks() {
		t.Fatalf("fetch failure: %+v", got)
	}
}

// TestSubmitCommissionedUncodedRefusalIsFinal: reef-core's auth plug
// answers 401 {"error":"invalid_session"} with no code. That is a final
// refusal: one request, an *api.HTTPRefusal, no retry (review M1).
func TestSubmitCommissionedUncodedRefusalIsFinal(t *testing.T) {
	fx := loadFixture(t)
	for _, status := range []int{401, 403, 413} {
		fake, srv := newFake(t, fx, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"invalid_session\u001b[2J"}`))
		})
		_, err := SubmitCommissioned(context.Background(), config(srv, fx))
		var refusal *api.HTTPRefusal
		if !errors.As(err, &refusal) || refusal.Status != status {
			t.Fatalf("%d: err = %v, want *HTTPRefusal", status, err)
		}
		if strings.ContainsRune(err.Error(), 0x1b) {
			t.Fatalf("%d: server text reached the error unescaped: %q", status, err.Error())
		}
		if n := len(fake.commissionPosts()); n != 1 {
			t.Fatalf("%d: %d requests, want 1", status, n)
		}
	}
}

// TestSubmitCommissionedClaimLostIsRetried: the server released the claim
// and asks for a retry; the same bytes are sent again (review m1).
func TestSubmitCommissionedClaimLostIsRetried(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, refusal(500, "commission_claim_lost", nil), started(fx, http.StatusCreated, nil))
	outcome, err := SubmitCommissioned(context.Background(), config(srv, fx))
	if err != nil || outcome.Attempts != 2 {
		t.Fatalf("outcome %+v err %v", outcome, err)
	}
	posts := fake.commissionPosts()
	if string(posts[0].body) != string(posts[1].body) {
		t.Fatal("the retry sent a different body")
	}
}

// TestSubmitCommissionedLaunchFailed: a replay whose receipt says
// launch_failed is not shown as a started run and is not collected
// (review M3).
func TestSubmitCommissionedLaunchFailed(t *testing.T) {
	fx := loadFixture(t)
	fake, srv := newFake(t, fx, started(fx, http.StatusOK, func(r map[string]any) { r["run_state"] = "launch_failed" }))
	cfg := config(srv, fx)
	var out strings.Builder
	cfg.Out = &out
	_, err := RunCommissioned(context.Background(), cfg, LocalCheck{LocalContained, "ok"})
	if !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("err = %v, want ErrLaunchFailed", err)
	}
	if !strings.Contains(out.String(), "commission is consumed and its run failed to launch") || strings.Contains(out.String(), "executed:          started") {
		t.Fatalf("status:\n%s", out.String())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, r := range fake.requests {
		if r.path == "/api/proofs" {
			t.Fatal("a launch_failed run was collected")
		}
	}
}

// TestCheckReceiptOverclaims: receipts that overstate what the limited mode
// checked, or whose fees break the bound they claim, are mismatches.
func TestCheckReceiptOverclaims(t *testing.T) {
	fx := loadFixture(t)
	edits := map[string]func(map[string]any){
		"memory class": func(r map[string]any) { r["memory_class"] = "memory_v1" },
		"labels":       func(r map[string]any) { r["dimensions"] = map[string]string{"labels": "admission_checked"} },
		"authenticity": func(r map[string]any) { r["authenticity"] = "server_signed" },
		"inputs":       func(r map[string]any) { r["inputs"] = "buyer_signed" },
		"no model":     func(r map[string]any) { r["effective"] = map[string]any{"model_id": "", "budget_sats": 2500} },
		"fees over cap": func(r map[string]any) {
			r["fees"] = map[string]any{"author_fee_sats": 100, "zk_fee_sats": 0, "bounded_by_commission": true}
		},
		"fee overflow": func(r map[string]any) {
			r["fees"] = map[string]any{"author_fee_sats": uint64(1) << 63, "zk_fee_sats": uint64(1) << 63, "bounded_by_commission": true}
		},
		"unknown run state": func(r map[string]any) { r["run_state"] = "claimed" },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			_, srv := newFake(t, fx, started(fx, http.StatusCreated, edit))
			if _, err := SubmitCommissioned(context.Background(), config(srv, fx)); !errors.Is(err, ErrReceiptMismatch) {
				t.Fatalf("err = %v, want ErrReceiptMismatch", err)
			}
		})
	}
}

// TestRenderCommissionStatusEscapesServerText: receipt strings with
// terminal control characters are escaped (review M2).
func TestRenderCommissionStatusEscapesServerText(t *testing.T) {
	fx := loadFixture(t)
	_, srv := newFake(t, fx, started(fx, http.StatusCreated, func(r map[string]any) {
		r["receipt_id"] = "r\u001b]0;pwned\u0007"
		r["dimensions"] = map[string]string{"labels": "not_evaluated", "x\u001b[31m": "y\u001b[0m"}
	}))
	outcome, err := SubmitCommissioned(context.Background(), config(srv, fx))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	RenderCommissionStatus(&out, CommissionStatus{Outcome: outcome, Local: LocalCheck{LocalNotChecked, "detail\x1b[2J"}, Executed: "started: agent_id=a\x1b[1m"})
	if strings.ContainsRune(out.String(), 0x1b) || strings.ContainsRune(out.String(), 0x07) {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}

// TestRunCommissionedCancelDuringWait: after admission, cancelling the
// context stops the wait for the custody proof (review M4).
func TestRunCommissionedCancelDuringWait(t *testing.T) {
	fx := loadFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/commissioned-runs":
			started(fx, http.StatusCreated, nil)(w, r)
		case "/api/proofs":
			cancel()
			json.NewEncoder(w).Encode(map[string]any{"proofs": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := config(srv, fx)
	cfg.Timeout = time.Minute
	cfg.PollInterval = 10 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := RunCommissioned(ctx, cfg, LocalCheck{LocalContained, "ok"})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop the wait")
	}
}
