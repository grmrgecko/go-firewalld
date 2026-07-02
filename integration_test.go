//go:build firewalld_integration

// Integration tests exercised against a live firewalld over the system bus. They
// are gated behind the firewalld_integration build tag so the default `go test`
// stays bus-free. Run them on each target server (they need firewalld and root):
//
//	go test -c -tags firewalld_integration -o firewalld.itest .
//	scp firewalld.itest root@<host>:/tmp/ && ssh root@<host> /tmp/firewalld.itest -test.v
//
// Safety: every test operates on a throwaway zone/ipset/policy it creates and
// removes. Nothing here touches the default zone, real interfaces, panic mode, or
// lockdown, so a failure cannot cut the SSH session.
package firewalld

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCtx returns a context bounded to keep a hung call from stalling the suite.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// dial connects to the live firewalld or skips the test if unavailable.
func dial(t *testing.T) *Conn {
	t.Helper()
	c, err := Connect(testCtx(t))
	if err != nil {
		t.Skipf("no firewalld on the system bus: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// uniqueName derives a collision-resistant throwaway name.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, os.Getpid())
}

func TestIntegrationConnect(t *testing.T) {
	c := dial(t)
	v := c.Version()
	t.Logf("firewalld version %s (major=%d minor=%d)", v.Raw, v.Major, v.Minor)
	assert.NotEmpty(t, v.Raw)
	t.Logf("caps: dict=%v policies=%v svc2=%v reset=%v",
		c.Supports(DictZoneSettings), c.Supports(Policies),
		c.Supports(ServiceSettings2), c.Supports(ResetToDefaults))
}

func TestIntegrationDefaultZoneAndList(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	dz, err := c.DefaultZone(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, dz)
	t.Logf("default zone: %s", dz)

	names, err := c.Permanent().ZoneNames(ctx)
	require.NoError(t, err)
	assert.Contains(t, names, "public")
}

// TestIntegrationZoneSettingsTransport reads the public zone through whichever
// transport the server supports (tuple on EL7, dict on EL9+) and sanity-checks it.
func TestIntegrationZoneSettingsTransport(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	s, err := c.Permanent().Zone("public").Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, "Public", s.Short)
	assert.Equal(t, TargetDefault, s.Target)
	t.Logf("public services=%v ports=%v forward=%v", s.Services, s.Ports, s.Forward)

	// The runtime read path too.
	rs, err := c.Runtime().Settings(ctx, "public")
	require.NoError(t, err)
	assert.Equal(t, "Public", rs.Short)
}

// TestIntegrationPermanentZoneLifecycle is the core round-trip: create a zone,
// mutate every element kind, read it back through Settings, then remove it.
func TestIntegrationPermanentZoneLifecycle(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	name := uniqueName("gofwz")

	// Clean any leftover from a previous crashed run, then create fresh.
	_ = perm.Zone(name).Remove(ctx)
	_, err := perm.AddZone(ctx, name, ZoneSettings{Short: name, Target: TargetDefault})
	require.NoError(t, err, "addZone")
	t.Cleanup(func() {
		_ = perm.Zone(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	z := perm.Zone(name)
	require.NoError(t, z.SetTarget(ctx, TargetDROP))
	require.NoError(t, z.AddPort(ctx, Port{Port: "4242", Protocol: "udp"}))
	require.NoError(t, z.AddPort(ctx, Port{Port: "8080", Protocol: "tcp"}))
	require.NoError(t, z.AddSourcePort(ctx, Port{Port: "1024", Protocol: "tcp"}))
	require.NoError(t, z.AddSource(ctx, "10.9.8.0/24"))
	require.NoError(t, z.AddService(ctx, "ssh"))
	require.NoError(t, z.AddProtocol(ctx, "gre"))
	require.NoError(t, z.AddMasquerade(ctx))
	require.NoError(t, z.AddForwardPort(ctx, ForwardPort{Port: "80", Protocol: "tcp", ToPort: "8080", ToAddr: "10.9.8.5"}))
	require.NoError(t, z.AddRichRule(ctx, `rule family="ipv4" source address="10.9.8.0/24" reject`))

	// Read everything back through the settings decoder.
	s, err := z.Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetDROP, s.Target)
	assert.Contains(t, s.Ports, Port{Port: "4242", Protocol: "udp"})
	assert.Contains(t, s.Ports, Port{Port: "8080", Protocol: "tcp"})
	assert.Contains(t, s.SourcePorts, Port{Port: "1024", Protocol: "tcp"})
	assert.Contains(t, s.Sources, "10.9.8.0/24")
	assert.Contains(t, s.Services, "ssh")
	assert.Contains(t, s.Protocols, "gre")
	assert.True(t, s.Masquerade)
	assert.Contains(t, s.ForwardPorts, ForwardPort{Port: "80", Protocol: "tcp", ToPort: "8080", ToAddr: "10.9.8.5"})
	assert.Len(t, s.RichRules, 1)

	// Query helpers agree with the settings snapshot.
	ok, err := z.QueryPort(ctx, Port{Port: "4242", Protocol: "udp"})
	require.NoError(t, err)
	assert.True(t, ok)

	// Remove a port and confirm it is gone.
	require.NoError(t, z.RemovePort(ctx, Port{Port: "8080", Protocol: "tcp"}))
	ok, err = z.QueryPort(ctx, Port{Port: "8080", Protocol: "tcp"})
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestIntegrationUpdateWholesale verifies the Update path (tuple or dict) writes a
// full settings struct that reads back intact.
func TestIntegrationUpdateWholesale(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	name := uniqueName("gofwu")

	_ = perm.Zone(name).Remove(ctx)
	_, err := perm.AddZone(ctx, name, ZoneSettings{Short: name})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = perm.Zone(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	want := ZoneSettings{
		Short:       name,
		Description: "wholesale update",
		Target:      TargetACCEPT,
		Services:    []string{"ssh", "http"},
		Ports:       []Port{{Port: "5353", Protocol: "udp"}},
		Masquerade:  true,
	}
	require.NoError(t, perm.Zone(name).Update(ctx, want))

	got, err := perm.Zone(name).Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, got.Target)
	assert.Equal(t, "wholesale update", got.Description)
	assert.ElementsMatch(t, want.Services, got.Services)
	assert.Contains(t, got.Ports, Port{Port: "5353", Protocol: "udp"})
	assert.True(t, got.Masquerade)
}

// TestIntegrationRuntimeZone exercises transient edits with a timeout against a
// throwaway zone that has been reloaded into the runtime.
func TestIntegrationRuntimeZone(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	name := uniqueName("gofwr")

	_ = perm.Zone(name).Remove(ctx)
	_, err := perm.AddZone(ctx, name, ZoneSettings{Short: name})
	require.NoError(t, err)
	require.NoError(t, c.Reload(ctx)) // materialise the zone at runtime
	t.Cleanup(func() {
		_ = perm.Zone(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	rz := c.Runtime().Zone(name)
	require.NoError(t, rz.AddPort(ctx, Port{Port: "7000", Protocol: "tcp"}, 0))
	ports, err := rz.Ports(ctx)
	require.NoError(t, err)
	assert.Contains(t, ports, Port{Port: "7000", Protocol: "tcp"})

	ok, err := rz.QueryPort(ctx, Port{Port: "7000", Protocol: "tcp"})
	require.NoError(t, err)
	assert.True(t, ok)

	require.NoError(t, rz.RemovePort(ctx, Port{Port: "7000", Protocol: "tcp"}))
}

// TestIntegrationIdempotency confirms firewalld's idempotency signals map to the
// sentinels callers rely on.
func TestIntegrationIdempotency(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	name := uniqueName("gofwi")

	_ = perm.Zone(name).Remove(ctx)
	_, err := perm.AddZone(ctx, name, ZoneSettings{Short: name})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = perm.Zone(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	z := perm.Zone(name)
	require.NoError(t, z.AddPort(ctx, Port{Port: "9999", Protocol: "tcp"}))

	// Adding the same port again is ALREADY_ENABLED.
	err = z.AddPort(ctx, Port{Port: "9999", Protocol: "tcp"})
	assert.ErrorIs(t, err, ErrAlreadyEnabled)

	// Removing a port that is not present is NOT_ENABLED.
	err = z.RemovePort(ctx, Port{Port: "1234", Protocol: "tcp"})
	assert.ErrorIs(t, err, ErrNotEnabled)
}

// TestIntegrationErrorMapping checks a precise INVALID_* mapping.
func TestIntegrationErrorMapping(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	_, err := c.Permanent().Zone("definitely-not-a-zone").Settings(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidZone)
}

func TestIntegrationIPSetLifecycle(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	name := uniqueName("gofwset")

	_ = perm.IPSet(name).Remove(ctx)
	_, err := perm.AddIPSet(ctx, name, IPSetSettings{
		Type:    "hash:ip",
		Options: map[string]string{"family": "inet"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = perm.IPSet(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	set := perm.IPSet(name)
	require.NoError(t, set.AddEntry(ctx, "10.7.7.1"))
	require.NoError(t, set.AddEntry(ctx, "10.7.7.2"))

	entries, err := set.Entries(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"10.7.7.1", "10.7.7.2"}, entries)

	s, err := set.Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, "hash:ip", s.Type)
	assert.Equal(t, "inet", s.Options["family"])

	require.NoError(t, set.RemoveEntry(ctx, "10.7.7.1"))
	ok, err := set.QueryEntry(ctx, "10.7.7.1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIntegrationServiceRead(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	s, err := c.ServiceSettings(ctx, "ssh")
	require.NoError(t, err)
	assert.Contains(t, s.Ports, Port{Port: "22", Protocol: "tcp"})
}

func TestIntegrationICMPTypeRead(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	names, err := c.ICMPTypes(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, names)

	s, err := c.ICMPTypeSettings(ctx, "echo-request")
	require.NoError(t, err)
	assert.NotEmpty(t, s.Short)
}

// TestIntegrationPolicyLifecycle is skipped on servers without policy support.
func TestIntegrationPolicyLifecycle(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	if !c.Supports(Policies) {
		t.Skip("server predates zone-to-zone policies")
	}
	perm := c.Permanent()
	name := uniqueName("gofwp")

	_ = perm.Policy(name).Remove(ctx)
	_, err := perm.AddPolicy(ctx, name, PolicySettings{
		Target:       "CONTINUE",
		Priority:     -1,
		IngressZones: []string{"public"},
		EgressZones:  []string{"HOST"},
		Ports:        []Port{{Port: "6000", Protocol: "tcp"}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = perm.Policy(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	s, err := perm.Policy(name).Settings(ctx)
	require.NoError(t, err)
	assert.Equal(t, "CONTINUE", s.Target)
	assert.Equal(t, int32(-1), s.Priority)
	assert.Contains(t, s.IngressZones, "public")
	assert.Contains(t, s.Ports, Port{Port: "6000", Protocol: "tcp"})

	// Reload so the permanent policy appears in the runtime, then exercise the
	// runtime .policy interface. These calls target the .policy interface (not
	// .zone); a regression to the wrong interface would fault here with
	// UnknownMethod rather than returning the policy.
	require.NoError(t, c.Reload(ctx))
	names, err := c.Runtime().Policies(ctx)
	require.NoError(t, err)
	assert.Contains(t, names, name)

	rs, err := c.Runtime().PolicySettings(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "CONTINUE", rs.Target)
	assert.Contains(t, rs.IngressZones, "public")

	_, err = c.Runtime().ActivePolicies(ctx)
	require.NoError(t, err)
}

// TestIntegrationDirect exercises the direct interface with a throwaway custom
// chain and rule, cleaning up after itself.
func TestIntegrationDirect(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	d := c.Direct()
	chain := DirectChain{IPV: "ipv4", Table: "filter", Chain: uniqueName("GOFW")}

	_ = d.RemoveChain(ctx, chain)
	require.NoError(t, d.AddChain(ctx, chain))
	t.Cleanup(func() {
		_ = d.RemoveRules(context.Background(), chain.IPV, chain.Table, chain.Chain)
		_ = d.RemoveChain(context.Background(), chain)
	})

	ok, err := d.QueryChain(ctx, chain)
	require.NoError(t, err)
	assert.True(t, ok)

	chains, err := d.AllChains(ctx)
	require.NoError(t, err)
	assert.Contains(t, chains, chain)

	rule := DirectRule{IPV: "ipv4", Table: "filter", Chain: chain.Chain, Priority: 0, Args: []string{"-j", "ACCEPT"}}
	require.NoError(t, d.AddRule(ctx, rule))

	ok, err = d.QueryRule(ctx, rule)
	require.NoError(t, err)
	assert.True(t, ok)

	rules, err := d.Rules(ctx, chain.IPV, chain.Table, chain.Chain)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, []string{"-j", "ACCEPT"}, rules[0].Args)

	require.NoError(t, d.RemoveRule(ctx, rule))
}

// TestIntegrationSignals subscribes to firewalld signals and confirms a Reloaded
// event arrives after an explicit reload.
func TestIntegrationSignals(t *testing.T) {
	c := dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	reloaded, err := c.WatchReloaded(ctx)
	require.NoError(t, err)

	// Give the match rule a moment to register before triggering.
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, c.Reload(ctx))

	select {
	case <-reloaded:
		// success
	case <-time.After(10 * time.Second):
		t.Fatal("did not receive Reloaded signal within timeout")
	}
}

// TestIntegrationProperties reads the runtime state and daemon config properties.
func TestIntegrationProperties(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)

	state, err := c.State(ctx)
	require.NoError(t, err)
	assert.Equal(t, "RUNNING", state)

	info, err := c.RuntimeInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, "RUNNING", info.State)
	t.Logf("runtime: ipv4=%v ipv6=%v ipset=%v bridge=%v ipsetTypes=%d",
		info.IPv4, info.IPv6, info.IPSet, info.Bridge, len(info.IPSetTypes))

	dc, err := c.Permanent().DaemonConfig(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, dc.DefaultZone)
	t.Logf("daemon: backend=%q defaultZone=%q ipv6rpfilter=%q cleanup=%q",
		dc.FirewallBackend, dc.DefaultZone, dc.IPv6RPFilter, dc.CleanupOnExit)
	t.Logf("daemon 2.x knobs: nftCounters=%q nftFlowtable=%q strictForwardPorts=%q",
		dc.NftablesCounters, dc.NftablesFlowtable, dc.StrictForwardPorts)
}

// TestIntegrationServiceIncludes exercises the service includes editor on a
// throwaway service (firewalld >= 1.0).
func TestIntegrationServiceIncludes(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	if !c.Supports(ServiceSettings2) {
		t.Skip("server predates service includes")
	}
	perm := c.Permanent()
	name := uniqueName("gofwsvc")

	_ = perm.Service(name).Remove(ctx)
	_, err := perm.AddService(ctx, name, ServiceSettings{Short: name})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = perm.Service(name).Remove(context.Background())
		_ = c.Reload(context.Background())
	})

	svc := perm.Service(name)
	require.NoError(t, svc.AddPort(ctx, Port{Port: "1717", Protocol: "tcp"}))
	require.NoError(t, svc.AddInclude(ctx, "ssh"))

	ok, err := svc.QueryInclude(ctx, "ssh")
	require.NoError(t, err)
	assert.True(t, ok)

	incs, err := svc.Includes(ctx)
	require.NoError(t, err)
	assert.Contains(t, incs, "ssh")

	got, err := svc.Settings(ctx)
	require.NoError(t, err)
	assert.Contains(t, got.Ports, Port{Port: "1717", Protocol: "tcp"})
}

// TestIntegrationChangeZoneOfSource confirms a source can be moved between zones
// at runtime without an ALREADY-bound error.
func TestIntegrationChangeZoneOfSource(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	perm := c.Permanent()
	za, zb := uniqueName("gofwca"), uniqueName("gofwcb")
	source := "10.44.44.0/24"

	for _, n := range []string{za, zb} {
		_ = perm.Zone(n).Remove(ctx)
		_, err := perm.AddZone(ctx, n, ZoneSettings{Short: n})
		require.NoError(t, err)
	}
	require.NoError(t, c.Reload(ctx))
	t.Cleanup(func() {
		for _, n := range []string{za, zb} {
			_ = perm.Zone(n).Remove(context.Background())
		}
		_ = c.Reload(context.Background())
	})

	require.NoError(t, c.Runtime().Zone(za).AddSource(ctx, source))
	// Move it to zb; ChangeSource must succeed even though it is bound to za.
	require.NoError(t, c.Runtime().Zone(zb).ChangeSource(ctx, source))

	zone, err := c.Runtime().ZoneOfSource(ctx, source)
	require.NoError(t, err)
	assert.Equal(t, zb, zone)
}

// TestIntegrationUnsupportedGuards ensures the library refuses policy calls on old
// servers rather than emitting an UnknownMethod fault.
func TestIntegrationUnsupportedGuards(t *testing.T) {
	c := dial(t)
	ctx := testCtx(t)
	if c.Supports(Policies) {
		t.Skip("server supports policies; nothing to guard")
	}
	_, err := c.Runtime().Policies(ctx)
	assert.True(t, errors.Is(err, ErrUnsupported))
}
