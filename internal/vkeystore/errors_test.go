// Package vkeystore_test asserts the sentinel-error contract.
package vkeystore_test

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestErrVkeyUnavailableIsDistinctFromPinMismatch(t *testing.T) {
	if errors.Is(vkeystore.ErrVkeyUnavailable, vkeystore.ErrCircuitPinMismatch) {
		t.Fatal("ErrVkeyUnavailable and ErrCircuitPinMismatch must be distinct sentinels")
	}
}

func TestErrCodesMatchSurfaceStrings(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{vkeystore.ErrVkeyUnavailable, "ERR_VKEY_UNAVAILABLE"},
		{vkeystore.ErrCircuitPinMismatch, "ERR_CIRCUIT_PIN_MISMATCH"},
		{vkeystore.ErrVkeyCorrupt, "ERR_VKEY_CORRUPT"},
		{vkeystore.ErrCircuitIDInvalid, "ERR_CIRCUIT_ID_INVALID"},
		{vkeystore.ErrVkeySha256Invalid, "ERR_VKEY_SHA256_INVALID"},
		{vkeystore.ErrDomainAlreadyPrefixed, "ERR_DOMAIN_ALREADY_PREFIXED"},
		{vkeystore.ErrPublisherDomainInvalid, "ERR_PUBLISHER_DOMAIN_INVALID"},
	}
	for _, c := range cases {
		if c.err.Error() != c.want {
			t.Errorf("err string = %q, want %q", c.err.Error(), c.want)
		}
	}
}
