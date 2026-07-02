package firewalld

import (
	"strconv"
	"strings"
)

// Capability names a version-gated feature of the firewalld D-Bus surface.
// Callers test support with Conn.Supports; internal code version-gates transports
// (tuple vs dict) on these flags.
type Capability int

const (
	// DictZoneSettings gates the a{sv} zone-settings path (getSettings2/update2 on
	// config.zone, getZoneSettings2/setZoneSettings2 on the runtime .zone). Added
	// in firewalld 0.9. Absent on EL7 0.6.3, which uses the v1 tuple only.
	DictZoneSettings Capability = iota
	// Policies gates zone-to-zone policy objects (config listPolicies/addPolicy,
	// runtime getPolicySettings/getActivePolicies). Added in 0.9. Absent on EL7.
	Policies
	// ServiceSettings2 gates getServiceSettings2/addService2 (a{sv} services).
	// Present on 1.3.4, absent on 0.6.3.
	ServiceSettings2
	// AddZone2 gates config.addZone2/addService2 (dict-based creation). Added 0.9.
	AddZone2
	// ResetToDefaults gates the main resetToDefaults method. Present on 1.x.
	ResetToDefaults
)

// Version is a parsed firewalld version. Missing components read as zero, so a
// server reporting "1" compares equal to "1.0.0".
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

// parseVersion parses a "X.Y.Z" firewalld version string. Trailing non-numeric
// suffixes on a component (e.g. a distro tag) are tolerated by reading the leading
// digits. Unparseable components read as zero rather than failing the connection.
func parseVersion(raw string) Version {
	v := Version{Raw: raw}
	parts := strings.SplitN(raw, ".", 3)
	dst := []*int{&v.Major, &v.Minor, &v.Patch}
	for i := 0; i < len(parts) && i < 3; i++ {
		*dst[i] = leadingInt(parts[i])
	}
	return v
}

// leadingInt reads the leading base-10 digits of s, ignoring any suffix.
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

// atLeast reports whether v is >= the given major.minor.
func (v Version) atLeast(major, minor int) bool {
	if v.Major != major {
		return v.Major > major
	}
	return v.Minor >= minor
}

// String returns the raw version string as reported by the server.
func (v Version) String() string { return v.Raw }

// capsFor derives the capability set from a parsed version. Gates follow the
// introspection findings: dict settings and policies land at 0.9; the *2 service
// APIs and resetToDefaults are 1.x.
func capsFor(v Version) map[Capability]bool {
	return map[Capability]bool{
		DictZoneSettings: v.atLeast(0, 9),
		Policies:         v.atLeast(0, 9),
		AddZone2:         v.atLeast(0, 9),
		ServiceSettings2: v.atLeast(1, 0),
		ResetToDefaults:  v.atLeast(1, 0),
	}
}
