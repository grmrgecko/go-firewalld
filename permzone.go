package firewalld

import (
	"context"
	"sync"

	"github.com/godbus/dbus/v5"
)

// PermZone is a handle for permanent edits to a single zone, operating on the
// zone's config child object (/config/zone/N). The object path is resolved once
// from the zone name and cached. Permanent element methods take no timeout and
// return nothing; changes apply after a Reload.
type PermZone struct {
	c    *Conn
	name string

	mu   sync.Mutex
	path dbus.ObjectPath // cached; resolved lazily via getZoneByName
}

// Name returns the zone name this handle targets.
func (z *PermZone) Name() string { return z.name }

// resolve returns the cached config object path, looking it up on first use.
func (z *PermZone) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.path != "" {
		return z.path, nil
	}
	var path dbus.ObjectPath
	if err := z.c.call(ctx, configPath, ifaceConfig, "getZoneByName", []any{&path}, z.name); err != nil {
		return "", err
	}
	z.path = path
	return path, nil
}

// callOn resolves the zone path and invokes a config.zone method against it.
func (z *PermZone) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := z.resolve(ctx)
	if err != nil {
		return err
	}
	return z.c.call(ctx, path, ifaceConfigZone, method, rets, args...)
}

func (z *PermZone) add(ctx context.Context, method string, args ...any) error {
	return z.callOn(ctx, method, nil, args...)
}

func (z *PermZone) query(ctx context.Context, method string, args ...any) (bool, error) {
	var ok bool
	err := z.callOn(ctx, method, []any{&ok}, args...)
	return ok, err
}

func (z *PermZone) getStrings(ctx context.Context, method string) ([]string, error) {
	var xs []string
	err := z.callOn(ctx, method, []any{&xs})
	return xs, err
}

// Settings reads the zone's permanent settings, choosing the dict transport
// (getSettings2) when supported and falling back to the v1 tuple (getSettings).
func (z *PermZone) Settings(ctx context.Context) (ZoneSettings, error) {
	if z.c.caps[DictZoneSettings] {
		var d map[string]dbus.Variant
		if err := z.callOn(ctx, "getSettings2", []any{&d}); err != nil {
			return ZoneSettings{}, err
		}
		return zoneSettingsFromDict(d), nil
	}
	var raw []any
	if err := z.callOn(ctx, "getSettings", []any{&raw}); err != nil {
		return ZoneSettings{}, err
	}
	return zoneSettingsFromTuple(raw), nil
}

// Update replaces the zone's permanent settings wholesale, using update2 (dict)
// when supported and update (v1 tuple) otherwise.
func (z *PermZone) Update(ctx context.Context, settings ZoneSettings) error {
	if z.c.caps[DictZoneSettings] {
		return z.callOn(ctx, "update2", nil, settings.toDict())
	}
	return z.callOn(ctx, "update", nil, settings.toTuple())
}

// Port operations.
func (z *PermZone) AddPort(ctx context.Context, p Port) error {
	return z.add(ctx, "addPort", p.Port, p.Protocol)
}
func (z *PermZone) RemovePort(ctx context.Context, p Port) error {
	return z.add(ctx, "removePort", p.Port, p.Protocol)
}
func (z *PermZone) QueryPort(ctx context.Context, p Port) (bool, error) {
	return z.query(ctx, "queryPort", p.Port, p.Protocol)
}

// Protocol operations.
func (z *PermZone) AddProtocol(ctx context.Context, proto string) error {
	return z.add(ctx, "addProtocol", proto)
}
func (z *PermZone) RemoveProtocol(ctx context.Context, proto string) error {
	return z.add(ctx, "removeProtocol", proto)
}
func (z *PermZone) QueryProtocol(ctx context.Context, proto string) (bool, error) {
	return z.query(ctx, "queryProtocol", proto)
}

// SourcePort operations.
func (z *PermZone) AddSourcePort(ctx context.Context, p Port) error {
	return z.add(ctx, "addSourcePort", p.Port, p.Protocol)
}
func (z *PermZone) RemoveSourcePort(ctx context.Context, p Port) error {
	return z.add(ctx, "removeSourcePort", p.Port, p.Protocol)
}
func (z *PermZone) QuerySourcePort(ctx context.Context, p Port) (bool, error) {
	return z.query(ctx, "querySourcePort", p.Port, p.Protocol)
}

// Service operations.
func (z *PermZone) AddService(ctx context.Context, service string) error {
	return z.add(ctx, "addService", service)
}
func (z *PermZone) RemoveService(ctx context.Context, service string) error {
	return z.add(ctx, "removeService", service)
}
func (z *PermZone) QueryService(ctx context.Context, service string) (bool, error) {
	return z.query(ctx, "queryService", service)
}

// Source operations.
func (z *PermZone) AddSource(ctx context.Context, source string) error {
	return z.add(ctx, "addSource", source)
}
func (z *PermZone) RemoveSource(ctx context.Context, source string) error {
	return z.add(ctx, "removeSource", source)
}
func (z *PermZone) QuerySource(ctx context.Context, source string) (bool, error) {
	return z.query(ctx, "querySource", source)
}

// RichRule operations.
func (z *PermZone) AddRichRule(ctx context.Context, rule string) error {
	return z.add(ctx, "addRichRule", rule)
}
func (z *PermZone) RemoveRichRule(ctx context.Context, rule string) error {
	return z.add(ctx, "removeRichRule", rule)
}
func (z *PermZone) QueryRichRule(ctx context.Context, rule string) (bool, error) {
	return z.query(ctx, "queryRichRule", rule)
}

// ForwardPort operations.
func (z *PermZone) AddForwardPort(ctx context.Context, fp ForwardPort) error {
	return z.add(ctx, "addForwardPort", fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}
func (z *PermZone) RemoveForwardPort(ctx context.Context, fp ForwardPort) error {
	return z.add(ctx, "removeForwardPort", fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}
func (z *PermZone) QueryForwardPort(ctx context.Context, fp ForwardPort) (bool, error) {
	return z.query(ctx, "queryForwardPort", fp.Port, fp.Protocol, fp.ToPort, fp.ToAddr)
}

// Masquerade operations.
func (z *PermZone) AddMasquerade(ctx context.Context) error {
	return z.add(ctx, "addMasquerade")
}
func (z *PermZone) RemoveMasquerade(ctx context.Context) error {
	return z.add(ctx, "removeMasquerade")
}
func (z *PermZone) QueryMasquerade(ctx context.Context) (bool, error) {
	return z.query(ctx, "queryMasquerade")
}

// IcmpBlock operations.
func (z *PermZone) AddIcmpBlock(ctx context.Context, icmptype string) error {
	return z.add(ctx, "addIcmpBlock", icmptype)
}
func (z *PermZone) RemoveIcmpBlock(ctx context.Context, icmptype string) error {
	return z.add(ctx, "removeIcmpBlock", icmptype)
}
func (z *PermZone) QueryIcmpBlock(ctx context.Context, icmptype string) (bool, error) {
	return z.query(ctx, "queryIcmpBlock", icmptype)
}

// IcmpBlockInversion operations.
func (z *PermZone) AddIcmpBlockInversion(ctx context.Context) error {
	return z.add(ctx, "addIcmpBlockInversion")
}
func (z *PermZone) RemoveIcmpBlockInversion(ctx context.Context) error {
	return z.add(ctx, "removeIcmpBlockInversion")
}
func (z *PermZone) QueryIcmpBlockInversion(ctx context.Context) (bool, error) {
	return z.query(ctx, "queryIcmpBlockInversion")
}

// Interface operations.
func (z *PermZone) AddInterface(ctx context.Context, iface string) error {
	return z.add(ctx, "addInterface", iface)
}
func (z *PermZone) RemoveInterface(ctx context.Context, iface string) error {
	return z.add(ctx, "removeInterface", iface)
}
func (z *PermZone) QueryInterface(ctx context.Context, iface string) (bool, error) {
	return z.query(ctx, "queryInterface", iface)
}

// Scalar setters for zone metadata and default policy.
func (z *PermZone) SetTarget(ctx context.Context, target Target) error {
	return z.callOn(ctx, "setTarget", nil, string(target))
}
func (z *PermZone) SetShort(ctx context.Context, short string) error {
	return z.callOn(ctx, "setShort", nil, short)
}
func (z *PermZone) SetDescription(ctx context.Context, description string) error {
	return z.callOn(ctx, "setDescription", nil, description)
}
func (z *PermZone) SetVersion(ctx context.Context, version string) error {
	return z.callOn(ctx, "setVersion", nil, version)
}

// Getters for the current permanent element lists.
func (z *PermZone) Services(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getServices")
}
func (z *PermZone) Interfaces(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getInterfaces")
}
func (z *PermZone) Sources(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getSources")
}
func (z *PermZone) Protocols(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getProtocols")
}
func (z *PermZone) RichRules(ctx context.Context) ([]string, error) {
	return z.getStrings(ctx, "getRichRules")
}
func (z *PermZone) Target(ctx context.Context) (Target, error) {
	var t string
	err := z.callOn(ctx, "getTarget", []any{&t})
	return Target(t), err
}

// LoadDefaults resets the zone to its built-in defaults.
func (z *PermZone) LoadDefaults(ctx context.Context) error {
	return z.callOn(ctx, "loadDefaults", nil)
}

// Rename changes the zone's name. The cached path is invalidated so subsequent
// calls re-resolve under the new name.
func (z *PermZone) Rename(ctx context.Context, newName string) error {
	if err := z.callOn(ctx, "rename", nil, newName); err != nil {
		return err
	}
	z.mu.Lock()
	z.name = newName
	z.path = ""
	z.mu.Unlock()
	return nil
}

// Remove deletes the zone from the permanent configuration.
func (z *PermZone) Remove(ctx context.Context) error {
	return z.callOn(ctx, "remove", nil)
}
