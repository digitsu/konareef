package feeder

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// validSigLane returns a structurally valid 74-byte PS-1 sig_manifest lane
// [derLen(1)][DER][zero pad]: derLen=70, a 70-byte non-zero DER region, and a
// zero-padded tail. Shared by the feeder assembly/round-trip tests.
func validSigLane() []byte {
	lane := make([]byte, sigManifestLaneLen)
	lane[0] = 70
	for i := 1; i <= 70; i++ {
		lane[i] = 0xAB
	}
	return lane // bytes 71..73 remain zero (valid padding)
}

// validPubKeyBytes returns a structurally valid 33-byte compressed secp256k1
// public key (derived from a fixed non-zero scalar, so it is genuinely
// on-curve — an all-zero or bad-prefix 33-byte blob would not parse).
func validPubKeyBytes() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x11
	}
	return secp256k1.PrivKeyFromBytes(seed).PubKey().SerializeCompressed()
}

// okSpartanResult is a SpartanCompressResult with every floor field valid
// (z0 exactly 736 bytes), so a test can mutate a single field to assert that
// validateSpartanResult rejects only that divergence.
func okSpartanResult() SpartanCompressResult {
	return SpartanCompressResult{
		CircuitID:             "konareef-pod-step-v1",
		SpartanSnark:          []byte("snark"),
		FirstStepPublicInputs: make([]byte, 298),
		LastStepPublicInputs:  make([]byte, 298),
		VkeyHash:              make([]byte, 32),
		Z0:                    make([]byte, z0FullWidth),
		Vkey:                  make([]byte, 32),
	}
}

func TestValidateSigManifestLane(t *testing.T) {
	tests := []struct {
		name    string
		lane    func() []byte
		wantErr bool
	}{
		{"valid", validSigLane, false},
		{"short lane (73)", func() []byte { return validSigLane()[:73] }, true},
		{"long lane (75)", func() []byte { return append(validSigLane(), 0x00) }, true},
		{"zero derLen", func() []byte { l := validSigLane(); l[0] = 0; return l }, true},
		{"derLen too big (74)", func() []byte { l := validSigLane(); l[0] = 74; return l }, true},
		{"non-zero padding", func() []byte { l := validSigLane(); l[73] = 0x01; return l }, true},
		{"nil", func() []byte { return nil }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSigManifestLane(tc.lane())
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSigManifestLane(%s) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestValidatePkPub(t *testing.T) {
	// A 33-byte value with the valid 0x02 prefix but an x-coordinate of all
	// 0xFF is >= the field prime, so it is not a point on the curve.
	nonCurve := make([]byte, 33)
	nonCurve[0] = 0x02
	for i := 1; i < 33; i++ {
		nonCurve[i] = 0xFF
	}
	badPrefix := make([]byte, 33) // prefix 0x00, not 0x02/0x03

	tests := []struct {
		name    string
		pk      []byte
		wantErr bool
	}{
		{"valid compressed", validPubKeyBytes(), false},
		{"too short (32)", make([]byte, 32), true},
		{"too long (34)", make([]byte, 34), true},
		{"bad prefix (0x00)", badPrefix, true},
		{"non-curve 0xFF x", nonCurve, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePkPub(tc.pk)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePkPub(%s) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSpartanResultZ0(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*SpartanCompressResult)
		wantErr bool
	}{
		{"valid 736", func(*SpartanCompressResult) {}, false},
		{"empty z0", func(r *SpartanCompressResult) { r.Z0 = nil }, true},
		{"short z0 (1)", func(r *SpartanCompressResult) { r.Z0 = make([]byte, 1) }, true},
		{"short z0 (735)", func(r *SpartanCompressResult) { r.Z0 = make([]byte, z0FullWidth-1) }, true},
		{"oversized z0 (737)", func(r *SpartanCompressResult) { r.Z0 = make([]byte, z0FullWidth+1) }, true},
		{"bad vkey (31)", func(r *SpartanCompressResult) { r.Vkey = make([]byte, 31) }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := okSpartanResult()
			tc.mutate(&res)
			err := validateSpartanResult(&res)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSpartanResult(%s) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
			}
		})
	}
}
