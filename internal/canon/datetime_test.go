// datetime_test.go — pins the BurntSushi/toml behavior that datetime
// sub-kind detection depends on.
//
// validateDatetime distinguishes the four TOML datetime kinds by the
// name BurntSushi assigns the parsed time.Location. Those names are
// BurntSushi-internal and undocumented. This test fails loudly if a
// dependency upgrade renames them — before the rename can silently
// weaken (or break) a datetime rejection gate. The end-to-end
// conformance vectors would also catch it, but this gives a direct,
// unambiguous CI signal pointing straight at validate.go.
package canon

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// TestBurntSushiDatetimeZoneNames asserts the exact location-name
// strings validateDatetime switches on.
func TestBurntSushiDatetimeZoneNames(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantZone string
	}{
		{"offset-utc", "v = 2026-05-21T13:42:08Z", "UTC"},
		{"local-datetime", "v = 2026-05-21T13:42:08", "datetime-local"},
		{"local-date", "v = 2026-05-21", "date-local"},
		{"local-time", "v = 13:42:08", "time-local"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var root map[string]interface{}
			if _, err := toml.Decode(c.input, &root); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := root["v"].(time.Time).Location().String()
			if got != c.wantZone {
				t.Fatalf("BurntSushi zone name for %s changed: got %q, want %q — "+
					"validateDatetime in validate.go switches on this string and must be updated",
					c.name, got, c.wantZone)
			}
		})
	}
}
