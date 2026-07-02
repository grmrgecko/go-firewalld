package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// Permanent is the entry point for operations on firewalld's on-disk permanent
// configuration, mirroring firewall-cmd --permanent. Changes take effect after a
// Reload. It also exposes the config-object management methods (listing and
// creating zones, ipsets, services, and so on).
type Permanent struct{ c *Conn }

// Permanent returns the permanent configuration namespace.
func (c *Conn) Permanent() *Permanent { return &Permanent{c: c} }

// Config is an alias for Permanent, matching the firewalld config object naming
// used by callers that think in terms of "the config interface".
func (c *Conn) Config() *Permanent { return &Permanent{c: c} }

// Zone returns a handle for permanent operations on the named zone. The object
// path is resolved lazily on first use via getZoneByName.
func (p *Permanent) Zone(name string) *PermZone {
	return &PermZone{c: p.c, name: name}
}

// ZoneNames lists the names of all permanently configured zones.
func (p *Permanent) ZoneNames(ctx context.Context) ([]string, error) {
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getZoneNames", []any{&names})
	return names, err
}

// ZonePaths lists the object paths of all permanent zones (listZones -> ao).
func (p *Permanent) ZonePaths(ctx context.Context) ([]dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "listZones", []any{&paths})
	return paths, err
}

// AddZone creates a new permanent zone from the given settings and returns its
// object path. On dict-capable servers it uses addZone2; otherwise addZone with
// the v1 tuple.
func (p *Permanent) AddZone(ctx context.Context, name string, settings ZoneSettings) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	if p.c.caps[AddZone2] {
		err := p.c.call(ctx, configPath, ifaceConfig, "addZone2", []any{&path}, name, settings.toDict())
		return path, err
	}
	tuple := settings.toTuple()
	err := p.c.call(ctx, configPath, ifaceConfig, "addZone", []any{&path}, name, tuple)
	return path, err
}

// ZoneOfInterface returns the permanent zone bound to an interface, or "" if none.
func (p *Permanent) ZoneOfInterface(ctx context.Context, iface string) (string, error) {
	var zone string
	err := p.c.call(ctx, configPath, ifaceConfig, "getZoneOfInterface", []any{&zone}, iface)
	return zone, err
}

// ZoneOfSource returns the permanent zone bound to a source, or "" if none.
func (p *Permanent) ZoneOfSource(ctx context.Context, source string) (string, error) {
	var zone string
	err := p.c.call(ctx, configPath, ifaceConfig, "getZoneOfSource", []any{&zone}, source)
	return zone, err
}
