package firewalld

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sigOf returns the D-Bus signature godbus would emit for v. This is the exact
// check that catches the []interface{}->"av" regression: a compound value that
// does not encode to firewalld's expected tuple signature would fail here before
// it ever reaches a bus.
func sigOf(v any) string { return dbus.SignatureOf(v).String() }

// TestCompoundSignatures locks every compound type to the signature firewalld
// requires. These are pure encode checks; no bus is involved.
func TestCompoundSignatures(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"Port", Port{}, "(ss)"},
		{"ForwardPort", ForwardPort{}, "(ssss)"},
		{"[]Port", []Port{}, "a(ss)"},
		{"[]ForwardPort", []ForwardPort{}, "a(ssss)"},
		{"zoneTuple", zoneTuple{}, "(sssbsasa(ss)asba(ssss)asasasasa(ss)b)"},
		{"ipsetTuple", ipsetTuple{}, "(ssssa{ss}as)"},
		{"serviceTuple", serviceTuple{}, "(sssa(ss)asa{ss}asa(ss))"},
		{"icmpTuple", icmpTuple{}, "(sssas)"},
		{"helperTuple", helperTuple{}, "(sssssa(ss))"},
		{"directChainTuple", directChainTuple{}, "(sss)"},
		{"directRuleTuple", directRuleTuple{}, "(sssias)"},
		{"directPassthroughTuple", directPassthroughTuple{}, "(sas)"},
		{"directConfigTuple", directConfigTuple{}, "(a(sss)a(sssias)a(sas))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sigOf(tc.val), "signature mismatch for %s", tc.name)
		})
	}
}

// TestZoneDictSignatures verifies the a{sv} dict encodes as a{sv} and that each
// compound value wrapped in a variant carries the tuple signature, not "av".
func TestZoneDictSignatures(t *testing.T) {
	s := ZoneSettings{
		Ports:        []Port{{Port: "80", Protocol: "tcp"}},
		ForwardPorts: []ForwardPort{{Port: "22", Protocol: "tcp", ToPort: "2222"}},
		Services:     []string{"ssh"},
	}
	d := s.toDict()
	assert.Equal(t, "a{sv}", sigOf(d))

	// The variants must carry concrete tuple signatures.
	assert.Equal(t, "a(ss)", d["ports"].Signature().String())
	assert.Equal(t, "a(ssss)", d["forward_ports"].Signature().String())
	assert.Equal(t, "as", d["services"].Signature().String())
	assert.Equal(t, "b", d["masquerade"].Signature().String())
}

// TestZoneTupleRoundTrip encodes settings to the tuple form, then decodes the
// same struct back through the length-tolerant tuple decoder to confirm field
// alignment and value fidelity.
func TestZoneTupleRoundTrip(t *testing.T) {
	in := ZoneSettings{
		Version:            "1",
		Short:              "Test",
		Description:        "a test zone",
		Target:             TargetDROP,
		Services:           []string{"ssh", "http"},
		Ports:              []Port{{Port: "80", Protocol: "tcp"}, {Port: "53", Protocol: "udp"}},
		ICMPBlocks:         []string{"echo-request"},
		Masquerade:         true,
		ForwardPorts:       []ForwardPort{{Port: "22", Protocol: "tcp", ToPort: "2222", ToAddr: "10.0.0.5"}},
		Interfaces:         []string{"eth0"},
		Sources:            []string{"10.0.0.0/8"},
		RichRules:          []string{`rule family="ipv4" reject`},
		Protocols:          []string{"gre"},
		SourcePorts:        []Port{{Port: "1024", Protocol: "udp"}},
		ICMPBlockInversion: true,
	}
	tuple := in.toTuple()

	// Simulate the wire decode: godbus hands a tuple back as []any positionally.
	raw := []any{
		tuple.Version, tuple.Short, tuple.Description, tuple.Unused, tuple.Target,
		tuple.Services, portsToAny(tuple.Ports), tuple.ICMPBlocks, tuple.Masquerade,
		forwardsToAny(tuple.ForwardPorts), tuple.Interfaces, tuple.Sources,
		tuple.RichRules, tuple.Protocols, portsToAny(tuple.SourcePorts),
		tuple.ICMPBlockInversion,
	}
	out := zoneSettingsFromTuple(raw)

	assert.Equal(t, in.Version, out.Version)
	assert.Equal(t, in.Short, out.Short)
	assert.Equal(t, in.Description, out.Description)
	assert.Equal(t, in.Target, out.Target)
	assert.Equal(t, in.Services, out.Services)
	assert.Equal(t, in.Ports, out.Ports)
	assert.Equal(t, in.ICMPBlocks, out.ICMPBlocks)
	assert.Equal(t, in.Masquerade, out.Masquerade)
	assert.Equal(t, in.ForwardPorts, out.ForwardPorts)
	assert.Equal(t, in.Interfaces, out.Interfaces)
	assert.Equal(t, in.Sources, out.Sources)
	assert.Equal(t, in.RichRules, out.RichRules)
	assert.Equal(t, in.Protocols, out.Protocols)
	assert.Equal(t, in.SourcePorts, out.SourcePorts)
	assert.Equal(t, in.ICMPBlockInversion, out.ICMPBlockInversion)
}

// TestZoneTupleShortTolerant proves the decoder never panics or misaligns on a
// truncated tuple from an old firewalld: trailing fields simply read as zero.
func TestZoneTupleShortTolerant(t *testing.T) {
	// Only the first five fields present (version..target).
	raw := []any{"1", "Short", "desc", false, "ACCEPT"}
	require.NotPanics(t, func() {
		out := zoneSettingsFromTuple(raw)
		assert.Equal(t, "1", out.Version)
		assert.Equal(t, Target("ACCEPT"), out.Target)
		assert.Nil(t, out.Services)
		assert.False(t, out.Masquerade)
		assert.False(t, out.ICMPBlockInversion)
	})

	// Empty tuple: everything zero, still no panic.
	require.NotPanics(t, func() {
		out := zoneSettingsFromTuple(nil)
		assert.Equal(t, ZoneSettings{}, out)
	})
}

// TestZoneDictRoundTrip confirms dict encode/decode is lossless for the modelled
// fields, including the v2-only forward flag.
func TestZoneDictRoundTrip(t *testing.T) {
	in := ZoneSettings{
		Short:        "Test",
		Target:       TargetACCEPT,
		Services:     []string{"ssh"},
		Ports:        []Port{{Port: "443", Protocol: "tcp"}},
		Masquerade:   true,
		Forward:      true,
		SourcePorts:  []Port{{Port: "68", Protocol: "udp"}},
		ForwardPorts: []ForwardPort{{Port: "80", Protocol: "tcp", ToPort: "8080"}},
	}
	d := in.toDict()

	// Re-wrap variants the way getSettings2 hands them back (plain values).
	back := make(map[string]dbus.Variant, len(d))
	for k, v := range d {
		back[k] = v
	}
	out := zoneSettingsFromDict(back)

	assert.Equal(t, in.Short, out.Short)
	assert.Equal(t, in.Target, out.Target)
	assert.Equal(t, in.Services, out.Services)
	assert.Equal(t, in.Ports, out.Ports)
	assert.Equal(t, in.Masquerade, out.Masquerade)
	assert.Equal(t, in.Forward, out.Forward)
	assert.Equal(t, in.SourcePorts, out.SourcePorts)
	assert.Equal(t, in.ForwardPorts, out.ForwardPorts)
}

// portsToAny mirrors how godbus decodes a(ss) in raw mode: each element becomes a
// []any pair. Used to feed the tuple decoder realistic input in tests.
func portsToAny(ports []Port) []any {
	out := make([]any, len(ports))
	for i, p := range ports {
		out[i] = []any{p.Port, p.Protocol}
	}
	return out
}

func forwardsToAny(fps []ForwardPort) []any {
	out := make([]any, len(fps))
	for i, f := range fps {
		out[i] = []any{f.Port, f.Protocol, f.ToPort, f.ToAddr}
	}
	return out
}
