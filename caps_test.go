package firewalld

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		raw             string
		maj, min, patch int
	}{
		{"0.6.3", 0, 6, 3},
		{"1.3.4", 1, 3, 4},
		{"2.4.3", 2, 4, 3},
		{"1", 1, 0, 0},
		{"0.9", 0, 9, 0},
		{"1.2.3-4.el9", 1, 2, 3},
		{"", 0, 0, 0},
		{"garbage", 0, 0, 0},
	}
	for _, tc := range cases {
		v := parseVersion(tc.raw)
		assert.Equal(t, tc.maj, v.Major, "major of %q", tc.raw)
		assert.Equal(t, tc.min, v.Minor, "minor of %q", tc.raw)
		assert.Equal(t, tc.patch, v.Patch, "patch of %q", tc.raw)
	}
}

func TestVersionAtLeast(t *testing.T) {
	assert.True(t, parseVersion("1.3.4").atLeast(0, 9))
	assert.True(t, parseVersion("0.9.0").atLeast(0, 9))
	assert.False(t, parseVersion("0.6.3").atLeast(0, 9))
	assert.True(t, parseVersion("1.0.0").atLeast(1, 0))
	assert.False(t, parseVersion("0.9.9").atLeast(1, 0))
	assert.True(t, parseVersion("2.0.0").atLeast(1, 5))
}

// TestCapsByVersion locks the capability gates to the three real server versions:
// EL7 0.6.3 (no dict, no policies), EL9 1.3.4 and local 2.4.3 (full).
func TestCapsByVersion(t *testing.T) {
	el7 := capsFor(parseVersion("0.6.3"))
	assert.False(t, el7[DictZoneSettings])
	assert.False(t, el7[Policies])
	assert.False(t, el7[ServiceSettings2])
	assert.False(t, el7[ResetToDefaults])

	el9 := capsFor(parseVersion("1.3.4"))
	assert.True(t, el9[DictZoneSettings])
	assert.True(t, el9[Policies])
	assert.True(t, el9[ServiceSettings2])
	assert.True(t, el9[ResetToDefaults])
	assert.True(t, el9[AddZone2])

	// The 0.9 boundary: dict + policies land, the 1.x-only flags do not.
	el09 := capsFor(parseVersion("0.9.0"))
	assert.True(t, el09[DictZoneSettings])
	assert.True(t, el09[Policies])
	assert.False(t, el09[ServiceSettings2])
}
