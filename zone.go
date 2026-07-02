package firewalld

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

// timeoutSeconds converts a Go duration to firewalld's int32 timeout in seconds.
// A zero or negative duration means "no timeout" (the runtime edit persists until
// reload), which firewalld encodes as 0.
func timeoutSeconds(d time.Duration) int32 {
	if d <= 0 {
		return 0
	}
	return int32(d / time.Second)
}

// Runtime is the entry point for transient operations on the running firewall.
// Edits made here last until the next reload unless given a timeout, mirroring
// firewall-cmd without --permanent.
type Runtime struct{ c *Conn }

// Runtime returns the runtime operation namespace.
func (c *Conn) Runtime() *Runtime { return &Runtime{c: c} }

// Zone returns a handle for runtime operations on the named zone.
func (r *Runtime) Zone(name string) *RuntimeZone {
	return &RuntimeZone{c: r.c, name: name}
}

// Zones lists the names of all defined zones (runtime view).
func (r *Runtime) Zones(ctx context.Context) ([]string, error) {
	var zones []string
	err := r.c.call(ctx, basePath, ifaceZone, "getZones", []any{&zones})
	return zones, err
}

// ActiveZone pairs a zone name with the interfaces and sources currently bound to
// it, as reported by getActiveZones.
type ActiveZone struct {
	Name       string
	Interfaces []string
	Sources    []string
}

// ActiveZones returns the zones that currently have interfaces or sources bound.
// getActiveZones returns a{sa{sas}}: zone -> {"interfaces": [...], "sources": [...]}.
func (r *Runtime) ActiveZones(ctx context.Context) ([]ActiveZone, error) {
	var raw map[string]map[string][]string
	if err := r.c.call(ctx, basePath, ifaceZone, "getActiveZones", []any{&raw}); err != nil {
		return nil, err
	}
	out := make([]ActiveZone, 0, len(raw))
	for name, binding := range raw {
		out = append(out, ActiveZone{
			Name:       name,
			Interfaces: binding["interfaces"],
			Sources:    binding["sources"],
		})
	}
	return out, nil
}

// ZoneOfInterface returns the zone an interface is bound to at runtime, or "" if
// none.
func (r *Runtime) ZoneOfInterface(ctx context.Context, iface string) (string, error) {
	var zone string
	err := r.c.call(ctx, basePath, ifaceZone, "getZoneOfInterface", []any{&zone}, iface)
	return zone, err
}

// ZoneOfSource returns the zone a source is bound to at runtime, or "" if none.
func (r *Runtime) ZoneOfSource(ctx context.Context, source string) (string, error) {
	var zone string
	err := r.c.call(ctx, basePath, ifaceZone, "getZoneOfSource", []any{&zone}, source)
	return zone, err
}

// Settings reads the runtime settings of a zone. On dict-capable servers it uses
// getZoneSettings2; otherwise it falls back to the main getZoneSettings tuple.
func (r *Runtime) Settings(ctx context.Context, zone string) (ZoneSettings, error) {
	if r.c.caps[DictZoneSettings] {
		var d map[string]dbus.Variant
		if err := r.c.call(ctx, basePath, ifaceZone, "getZoneSettings2", []any{&d}, zone); err != nil {
			return ZoneSettings{}, err
		}
		return zoneSettingsFromDict(d), nil
	}
	var raw []any
	if err := r.c.call(ctx, basePath, ifaceMain, "getZoneSettings", []any{&raw}, zone); err != nil {
		return ZoneSettings{}, err
	}
	return zoneSettingsFromTuple(raw), nil
}

// SetSettings replaces a zone's runtime settings wholesale via setZoneSettings2.
// This is a dict-only path (firewalld >= 0.9); older servers expose no runtime
// settings writer, so it returns ErrUnsupported there.
func (r *Runtime) SetSettings(ctx context.Context, zone string, settings ZoneSettings) error {
	if !r.c.caps[DictZoneSettings] {
		return ErrUnsupported
	}
	return r.c.call(ctx, basePath, ifaceZone, "setZoneSettings2", nil, zone, settings.toDict())
}

// RuntimeZone is a handle for transient edits to a single zone. Add methods take a
// timeout (zero for none) and return the affected zone name from firewalld.
type RuntimeZone struct {
	c    *Conn
	name string
}

// Name returns the zone name this handle targets.
func (z *RuntimeZone) Name() string { return z.name }

// addElement invokes a runtime add* method: (zone, args..., timeout) -> zone.
func (z *RuntimeZone) addElement(ctx context.Context, method string, timeout time.Duration, args ...any) error {
	full := append([]any{z.name}, args...)
	full = append(full, timeoutSeconds(timeout))
	return z.c.call(ctx, basePath, ifaceZone, method, nil, full...)
}

// removeElement invokes a runtime remove* method: (zone, args...) -> zone.
func (z *RuntimeZone) removeElement(ctx context.Context, method string, args ...any) error {
	full := append([]any{z.name}, args...)
	return z.c.call(ctx, basePath, ifaceZone, method, nil, full...)
}

// queryElement invokes a runtime query* method: (zone, args...) -> bool.
func (z *RuntimeZone) queryElement(ctx context.Context, method string, args ...any) (bool, error) {
	var ok bool
	full := append([]any{z.name}, args...)
	err := z.c.call(ctx, basePath, ifaceZone, method, []any{&ok}, full...)
	return ok, err
}

// getStrings invokes a runtime get* method returning "as": (zone) -> []string.
func (z *RuntimeZone) getStrings(ctx context.Context, method string) ([]string, error) {
	var xs []string
	err := z.c.call(ctx, basePath, ifaceZone, method, []any{&xs}, z.name)
	return xs, err
}

// Port operations.
func (z *RuntimeZone) AddPort(ctx context.Context, p Port, timeout time.Duration) error {
	return z.addElement(ctx, "addPort", timeout, p.Port, p.Protocol)
}
func (z *RuntimeZone) RemovePort(ctx context.Context, p Port) error {
	return z.removeElement(ctx, "removePort", p.Port, p.Protocol)
}
func (z *RuntimeZone) QueryPort(ctx context.Context, p Port) (bool, error) {
	return z.queryElement(ctx, "queryPort", p.Port, p.Protocol)
}

// Protocol operations.
func (z *RuntimeZone) AddProtocol(ctx context.Context, proto string, timeout time.Duration) error {
	return z.addElement(ctx, "addProtocol", timeout, proto)
}
func (z *RuntimeZone) RemoveProtocol(ctx context.Context, proto string) error {
	return z.removeElement(ctx, "removeProtocol", proto)
}
func (z *RuntimeZone) QueryProtocol(ctx context.Context, proto string) (bool, error) {
	return z.queryElement(ctx, "queryProtocol", proto)
}

// SourcePort operations.
func (z *RuntimeZone) AddSourcePort(ctx context.Context, p Port, timeout time.Duration) error {
	return z.addElement(ctx, "addSourcePort", timeout, p.Port, p.Protocol)
}
func (z *RuntimeZone) RemoveSourcePort(ctx context.Context, p Port) error {
	return z.removeElement(ctx, "removeSourcePort", p.Port, p.Protocol)
}
func (z *RuntimeZone) QuerySourcePort(ctx context.Context, p Port) (bool, error) {
	return z.queryElement(ctx, "querySourcePort", p.Port, p.Protocol)
}

// Service operations.
func (z *RuntimeZone) AddService(ctx context.Context, service string, timeout time.Duration) error {
	return z.addElement(ctx, "addService", timeout, service)
}
func (z *RuntimeZone) RemoveService(ctx context.Context, service string) error {
	return z.removeElement(ctx, "removeService", service)
}
func (z *RuntimeZone) QueryService(ctx context.Context, service string) (bool, error) {
	return z.queryElement(ctx, "queryService", service)
}

// Source operations. Unlike ports/services, a source binding is not timed, so
// AddSource takes no timeout (firewalld's addSource has no timeout argument).
func (z *RuntimeZone) AddSource(ctx context.Context, source string) error {
	return z.removeElement(ctx, "addSource", source)
}
func (z *RuntimeZone) RemoveSource(ctx context.Context, source string) error {
	return z.removeElement(ctx, "removeSource", source)
}
func (z *RuntimeZone) QuerySource(ctx context.Context, source string) (bool, error) {
	return z.queryElement(ctx, "querySource", source)
}

// RichRule operations.
func (z *RuntimeZone) AddRichRule(ctx context.Context, rule string, timeout time.Duration) error {
	return z.addElement(ctx, "addRichRule", timeout, rule)
}
func (z *RuntimeZone) RemoveRichRule(ctx context.Context, rule string) error {
	return z.removeElement(ctx, "removeRichRule", rule)
}
func (z *RuntimeZone) QueryRichRule(ctx context.Context, rule string) (bool, error) {
	return z.queryElement(ctx, "queryRichRule", rule)
}

// ForwardPort operations.
func (z *RuntimeZone) AddForwardPort(ctx context.Context, fp ForwardPort, timeout time.Duration) error {
	return z.addElement(ctx, "addForwardPort", timeout, fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}
func (z *RuntimeZone) RemoveForwardPort(ctx context.Context, fp ForwardPort) error {
	return z.removeElement(ctx, "removeForwardPort", fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}
func (z *RuntimeZone) QueryForwardPort(ctx context.Context, fp ForwardPort) (bool, error) {
	return z.queryElement(ctx, "queryForwardPort", fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}

// Masquerade operations. Add takes a timeout; the others do not.
func (z *RuntimeZone) AddMasquerade(ctx context.Context, timeout time.Duration) error {
	return z.addElement(ctx, "addMasquerade", timeout)
}
func (z *RuntimeZone) RemoveMasquerade(ctx context.Context) error {
	return z.removeElement(ctx, "removeMasquerade")
}
func (z *RuntimeZone) QueryMasquerade(ctx context.Context) (bool, error) {
	return z.queryElement(ctx, "queryMasquerade")
}

// IcmpBlock operations.
func (z *RuntimeZone) AddIcmpBlock(ctx context.Context, icmptype string, timeout time.Duration) error {
	return z.addElement(ctx, "addIcmpBlock", timeout, icmptype)
}
func (z *RuntimeZone) RemoveIcmpBlock(ctx context.Context, icmptype string) error {
	return z.removeElement(ctx, "removeIcmpBlock", icmptype)
}
func (z *RuntimeZone) QueryIcmpBlock(ctx context.Context, icmptype string) (bool, error) {
	return z.queryElement(ctx, "queryIcmpBlock", icmptype)
}

// IcmpBlockInversion operations. Add takes a timeout; the others do not.
func (z *RuntimeZone) AddIcmpBlockInversion(ctx context.Context, timeout time.Duration) error {
	return z.addElement(ctx, "addIcmpBlockInversion", timeout)
}
func (z *RuntimeZone) RemoveIcmpBlockInversion(ctx context.Context) error {
	return z.removeElement(ctx, "removeIcmpBlockInversion")
}
func (z *RuntimeZone) QueryIcmpBlockInversion(ctx context.Context) (bool, error) {
	return z.queryElement(ctx, "queryIcmpBlockInversion")
}

// Interface operations bind and unbind network interfaces to the zone at runtime.
func (z *RuntimeZone) AddInterface(ctx context.Context, iface string) error {
	return z.removeElement(ctx, "addInterface", iface) // no timeout arg on interface add
}
func (z *RuntimeZone) RemoveInterface(ctx context.Context, iface string) error {
	return z.removeElement(ctx, "removeInterface", iface)
}
func (z *RuntimeZone) QueryInterface(ctx context.Context, iface string) (bool, error) {
	return z.queryElement(ctx, "queryInterface", iface)
}

// ChangeInterface moves an interface into this zone, detaching it from whatever
// zone currently owns it. Unlike AddInterface, it does not fail if the interface
// is already bound elsewhere (firewall-cmd --change-interface).
func (z *RuntimeZone) ChangeInterface(ctx context.Context, iface string) error {
	return z.removeElement(ctx, "changeZoneOfInterface", iface)
}

// ChangeSource moves a source into this zone, detaching it from its current zone.
func (z *RuntimeZone) ChangeSource(ctx context.Context, source string) error {
	return z.removeElement(ctx, "changeZoneOfSource", source)
}

// Getters for the current runtime element lists.
func (z *RuntimeZone) Services(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getServices")
}
func (z *RuntimeZone) Interfaces(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getInterfaces")
}
func (z *RuntimeZone) Sources(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getSources")
}
func (z *RuntimeZone) Protocols(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getProtocols")
}
func (z *RuntimeZone) RichRules(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getRichRules")
}
func (z *RuntimeZone) ICMPBlocks(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getIcmpBlocks")
}

// Ports returns the runtime ports as typed pairs.
func (z *RuntimeZone) Ports(ctx context.Context) ([]Port, error) {
	var raw [][]any
	err := z.c.call(ctx, basePath, ifaceZone, "getPorts", []any{&raw}, z.name)
	if err != nil {
		return nil, err
	}
	return asPorts(toAnySlice(raw)), nil
}

// SourcePorts returns the runtime source ports as typed pairs.
func (z *RuntimeZone) SourcePorts(ctx context.Context) ([]Port, error) {
	var raw [][]any
	err := z.c.call(ctx, basePath, ifaceZone, "getSourcePorts", []any{&raw}, z.name)
	if err != nil {
		return nil, err
	}
	return asPorts(toAnySlice(raw)), nil
}

// ForwardPorts returns the runtime forward ports as typed values.
func (z *RuntimeZone) ForwardPorts(ctx context.Context) ([]ForwardPort, error) {
	var raw [][]any
	err := z.c.call(ctx, basePath, ifaceZone, "getForwardPorts", []any{&raw}, z.name)
	if err != nil {
		return nil, err
	}
	return asForwardPorts(toAnySlice(raw)), nil
}

// toAnySlice re-wraps a [][]any as []any so the shared tuple
// helpers (asPorts/asForwardPorts) can consume it.
func toAnySlice(raw [][]any) []any {
	out := make([]any, len(raw))
	for i := range raw {
		out[i] = raw[i]
	}
	return out
}
