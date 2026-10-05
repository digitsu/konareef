// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package stubserver — handlers + writers for the in-process stub PayGate.
package stubserver

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	profile := "active"
	if s.opts.ManifestProfile != "" {
		profile = s.opts.ManifestProfile
	}
	vkeyHash := "0101010101010101010101010101010101010101010101010101010101010101"
	if s.opts.PinMismatchManifest != "" {
		vkeyHash = s.opts.PinMismatchManifest
	}
	// SHA-256 of the v1.1 vkey, from the pin table (it equals the
	// paygate-zk param_drift_gate pin).
	vkeyHashV1_1, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	// circuitEntry builds one advertised circuit: its vkey pin, vkey URL,
	// pricing and input caps. Input: the circuit id and the vkey_sha256 to
	// advertise. Output: the manifest entry for that id.
	circuitEntry := func(id, vkeySha256 string) map[string]interface{} {
		return map[string]interface{}{
			"vkey_sha256": vkeySha256,
			"vkey_url":    s.srv.URL + "/.well-known/circuits/" + id + "/vkey",
			"pricing": map[string]interface{}{
				"nova-fold":        map[string]float64{"compute_usd": 0.0001, "retail_usd": 0.001},
				"spartan-compress": map[string]float64{"compute_usd": 0.005, "retail_usd": 0.05},
			},
			"input_caps":       map[string]int{"manifest_bytes": 2048, "prompt_bytes": 1024, "response_bytes": 1024, "t_log_max": 16, "touched_memory_leaves_max": 64},
			"deprecated_after": nil,
		}
	}
	body := map[string]interface{}{
		"service":    "paygate-zk",
		"version":    "v1",
		"operations": []string{"nova-fold", "spartan-compress", "groth16-wrap"},
		// PS-1 serves both pod-step ids during the VHASH migration (O5-A
		// step 2). v1 keeps its synthetic pin, which PinMismatchManifest can
		// override. v1.1 advertises the real pinned SHA-256(vkey), because
		// `pod publish --pin-circuit-vkey` refuses any other value for v1.1
		// (VHASH-FU, script-verify/paygate-zk#13).
		"circuits": map[string]interface{}{
			vkeystore.CircuitIDPodStepV1:   circuitEntry(vkeystore.CircuitIDPodStepV1, vkeyHash),
			vkeystore.CircuitIDPodStepV1_1: circuitEntry(vkeystore.CircuitIDPodStepV1_1, vkeyHashV1_1),
		},
		"margin_multiplier": 10,
		"schedule_revision": 1,
		"signature":         map[string]string{"scheme": "BRC-31", "service_pubkey": "deadbeef", "sig": "feedface"},
	}
	if profile == "stale" {
		past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		body["schedule_effective_after"] = past
		body["schedule_revision"] = 2
	} else {
		body["schedule_effective_after"] = nil
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	idemKey := r.Header.Get("Idempotency-Key")
	xpay := r.Header.Get("X-Payment")
	auth := r.Header.Get("Authorization")
	if auth == "" {
		writePRDErr(w, http.StatusUnauthorized, "AUTH_MISSING_BRC31", "auth", "", 0)
		return
	}
	sessID := extractSessionID(auth)
	cacheKey := sessID + "|" + idemKey
	s.mu.Lock()

	// AttemptScript (M-7) takes precedence.
	if len(s.opts.AttemptScript) > 0 {
		next := s.opts.AttemptScript[0]
		s.opts.AttemptScript = s.opts.AttemptScript[1:]
		if s.opts.OnAttempt != nil {
			s.opts.OnAttempt()
		}
		s.mu.Unlock()
		switch next.Status {
		case 503:
			if next.RetryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(next.RetryAfter.Seconds())))
			}
			// Retry-After supplied ONLY via header; JSON body OMITS
			// retry_after_seconds so we prove the client reads the header.
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": map[string]interface{}{
					"code":         "SERVICE_UNAVAILABLE",
					"category":     "service",
					"message":      "SERVICE_UNAVAILABLE",
					"details":      map[string]interface{}{},
					"retryable":    true,
					"credit_token": "",
				},
			})
		case 200, 202:
			body := map[string]interface{}{"job_id": next.JobID}
			if next.AcceptedAtUTC {
				body["submitted_at"] = time.Now().UTC()
			}
			// Track job state so subsequent status+result calls succeed.
			s.mu.Lock()
			s.jobs[next.JobID] = &jobState{
				JobID:       next.JobID,
				Status:      "completed",
				ProofType:   "nova-fold",
				CircuitID:   "konareef-pod-step-v1",
				CreatedAt:   time.Now().UTC(),
				CompletedAt: time.Now().UTC(),
				Accumulator: []byte{0x99, 0x88, 0x77},
			}
			s.beefSubmits++
			s.mu.Unlock()
			writeJSON(w, http.StatusAccepted, body)
		default:
			writePRDErr(w, next.Status, "SCRIPTED_FAILURE", "stub", "", 0)
		}
		return
	}
	if existing, ok := s.idempKeyToJob[cacheKey]; ok && s.opts.IdempotencyReplay {
		s.mu.Unlock()
		// Replay — same job_id, no new BEEF debit.
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"job_id":       existing,
			"submitted_at": time.Now().UTC(),
		})
		return
	}
	// Stale-schedule enforcement.
	if s.opts.StaleScheduleEnforce && s.opts.ManifestProfile == "stale" {
		s.mu.Unlock()
		writePRDErr(w, http.StatusPaymentRequired, "PAYMENT_AMOUNT_INSUFFICIENT", "payment", "", 0)
		return
	}
	if strings.HasPrefix(xpay, "credit_token ") {
		token := strings.TrimPrefix(xpay, "credit_token ")
		if token == "" {
			s.mu.Unlock()
			writePRDErr(w, http.StatusPaymentRequired, "PAYMENT_CREDIT_TOKEN_INVALID", "payment", "", 0)
			return
		}
		// honour credit_token without incrementing BEEF count
	} else {
		// BRC-29 wire contract: the payload after the "Brc29 " scheme
		// tag MUST be hex-encoded. Raw binary in the header is a
		// protocol violation (it would corrupt the HTTP framing); the
		// stub rejects it to keep round-3 B7 enforced from both sides.
		if strings.HasPrefix(xpay, "Brc29 ") {
			payload := strings.TrimPrefix(xpay, "Brc29 ")
			if _, err := hex.DecodeString(payload); err != nil {
				s.mu.Unlock()
				writePRDErr(w, http.StatusPaymentRequired, "PAYMENT_BEEF_INVALID", "payment", "", 0)
				return
			}
		}
		s.beefSubmits++
	}
	if s.opts.NextFailureCode != "" {
		code := s.opts.NextFailureCode
		s.opts.NextFailureCode = ""
		tok := s.opts.CreditTokenInjection
		retryAfter := int(s.opts.RetryAfterDuration.Seconds())
		s.mu.Unlock()
		writePRDErr(w, http.StatusServiceUnavailable, code, "compute", tok, retryAfter)
		return
	}
	s.nextJobID++
	jobID := fmt.Sprintf("stub-job-%d", s.nextJobID)
	s.jobs[jobID] = &jobState{
		JobID:       jobID,
		Status:      "completed", // stub completes instantly
		ProofType:   "nova-fold",
		CircuitID:   "konareef-pod-step-v1",
		CreatedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC(),
		Accumulator: []byte{0x99, 0x88, 0x77},
	}
	s.idempKeyToJob[cacheKey] = jobID
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id":       jobID,
		"submitted_at": time.Now().UTC(),
	})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	if strings.HasSuffix(path, "/result") {
		jobID := strings.TrimSuffix(path, "/result")
		s.serveResult(w, r, jobID)
		return
	}
	jobID := path
	s.serveStatus(w, r, jobID)
}

func (s *Server) serveStatus(w http.ResponseWriter, _ *http.Request, jobID string) {
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	s.mu.Unlock()
	if !ok {
		writePRDErr(w, http.StatusNotFound, "VALIDATION_SCHEMA", "validation", "", 0)
		return
	}
	if s.opts.RetryAfterDuration > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(s.opts.RetryAfterDuration.Seconds())))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"job_id":     j.JobID,
		"status":     j.Status,
		"proof_type": j.ProofType,
		"circuit_id": j.CircuitID,
		"created_at": j.CreatedAt,
		"updated_at": time.Now().UTC(),
		"error":      nil,
	})
}

func (s *Server) serveResult(w http.ResponseWriter, _ *http.Request, jobID string) {
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		writePRDErr(w, http.StatusNotFound, "VALIDATION_SCHEMA", "validation", "", 0)
		return
	}
	// M-6 retention semantics (unconditional expired profile).
	if s.opts.RetentionState == "expired" {
		s.mu.Unlock()
		writePRDErr(w, http.StatusGone, "RESULT_EXPIRED", "service", "", 0)
		return
	}
	// M-6b first-fetch window.
	if s.opts.FirstFetchWindow > 0 {
		if firstAt, ok := s.firstFetchAt[jobID]; ok {
			if time.Since(firstAt) > s.opts.FirstFetchWindow {
				s.mu.Unlock()
				writePRDErr(w, http.StatusGone, "RESULT_EXPIRED", "service", "", 0)
				return
			}
		} else {
			s.firstFetchAt[jobID] = time.Now().UTC()
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"job_id":               j.JobID,
		"accumulator_out":      j.Accumulator,
		"step_proof":           []byte{0xab, 0xcd},
		"public_inputs_echoed": map[string]interface{}{"step_index": j.StepIndex},
		"cost_meta":            map[string]int{"actual_constraints": 1500, "actual_compute_ms": 300},
	})
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writePRDErr(w http.ResponseWriter, status int, code, category, creditToken string, retryAfter int) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	}
	errBody := map[string]interface{}{
		"code":                code,
		"category":            category,
		"message":             code,
		"details":             map[string]interface{}{},
		"retryable":           false,
		"credit_token":        creditToken,
		"retry_after_seconds": retryAfter,
	}
	// PRD P1.8 round-2 B3: whenever the server hands out a credit_token
	// it MUST also declare an issued_at / expires_at window. Clients
	// reject tokens without a declared window (no synthesised TTL).
	if creditToken != "" {
		now := time.Now().UTC()
		errBody["credit_token_issued_at"] = now
		errBody["credit_token_expires_at"] = now.Add(time.Hour)
	}
	writeJSON(w, status, map[string]interface{}{"error": errBody})
}

func extractSessionID(auth string) string {
	// Parse `Brc31 session=<sid>; …` simply.
	for _, p := range strings.Split(strings.TrimPrefix(auth, "Brc31 "), ";") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "session=") {
			return strings.TrimPrefix(p, "session=")
		}
	}
	return ""
}
