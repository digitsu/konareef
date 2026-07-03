// discovery_test.go — unit coverage for PublisherBaseDomain, the
// bridge between reef-core's /api/discovery `paygate_zk_domain`
// service host and vkeystore.ResolveRequest.PublisherDomain's base
// domain contract.
//
// MR !21 round-2 B2 (note 680).
package publish

import (
	"errors"
	"testing"
)

func TestPublisherBaseDomainStripsPaygateZKPrefix(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"standard service host", "paygate-zk.example.com", "example.com"},
		{"deeper base domain", "paygate-zk.api.publisher.example", "api.publisher.example"},
		// Round-2 B2 acceptance case from note 680.
		{"hermes-acceptance-vector", "paygate-zk.example.com", "example.com"},
		{"case-insensitive prefix", "PayGate-ZK.example.com", "example.com"},
		{"surrounding whitespace trimmed", "  paygate-zk.example.com  ", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PublisherBaseDomain(tc.input)
			if err != nil {
				t.Fatalf("PublisherBaseDomain(%q) err=%v, want nil", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("PublisherBaseDomain(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestPublisherBaseDomainRejectsBareBaseDomain(t *testing.T) {
	// A bare base domain has no `paygate-zk.` prefix → caller violated
	// the contract; must fail closed with the new sentinel.
	cases := []string{
		"example.com",
		"paygate.example.com", // similar but not exact prefix
		"paygate-zkX.example.com",
		"foo.paygate-zk.example.com", // prefix not at start
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := PublisherBaseDomain(in)
			if !errors.Is(err, ErrPaygateZKDomainMissingPrefix) {
				t.Fatalf("PublisherBaseDomain(%q) err=%v, want ErrPaygateZKDomainMissingPrefix",
					in, err)
			}
		})
	}
}

func TestPublisherBaseDomainRejectsEmptyOrPrefixOnly(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"paygate-zk.",
		"paygate-zk.   ",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := PublisherBaseDomain(in)
			if !errors.Is(err, ErrPaygateZKDomainMissingPrefix) {
				t.Fatalf("PublisherBaseDomain(%q) err=%v, want ErrPaygateZKDomainMissingPrefix",
					in, err)
			}
		})
	}
}
