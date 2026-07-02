// Package firewalld is a comprehensive Go client for the firewalld D-Bus API.
//
// It exposes both runtime (transient) and permanent configuration operations,
// mirroring firewall-cmd's default and --permanent modes, and adapts to the
// connected server's version so a single binary serves both old (EL7 0.6.x) and
// new (EL9 1.x) firewalld. Compound values are encoded as concrete Go structs so
// godbus emits the D-Bus tuples firewalld requires (see CLAUDE.md).
package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// D-Bus names for the firewalld service and its well-known object paths.
const (
	dest       = "org.fedoraproject.FirewallD1"
	basePath   = dbus.ObjectPath("/org/fedoraproject/FirewallD1")
	configPath = dbus.ObjectPath("/org/fedoraproject/FirewallD1/config")

	// Interface names.
	ifaceMain          = "org.fedoraproject.FirewallD1"
	ifaceZone          = "org.fedoraproject.FirewallD1.zone"
	ifaceIPSet         = "org.fedoraproject.FirewallD1.ipset"
	ifaceDirect        = "org.fedoraproject.FirewallD1.direct"
	ifacePolicy        = "org.fedoraproject.FirewallD1.policy"
	ifaceLockdown      = "org.fedoraproject.FirewallD1.policies"
	ifaceConfig        = "org.fedoraproject.FirewallD1.config"
	ifaceConfigZone    = "org.fedoraproject.FirewallD1.config.zone"
	ifaceConfigIPSet   = "org.fedoraproject.FirewallD1.config.ipset"
	ifaceConfigPolicy  = "org.fedoraproject.FirewallD1.config.policy"
	ifaceConfigService = "org.fedoraproject.FirewallD1.config.service"
	ifaceConfigICMP    = "org.fedoraproject.FirewallD1.config.icmptype"
	ifaceConfigHelper  = "org.fedoraproject.FirewallD1.config.helper"
	ifaceConfigDirect  = "org.fedoraproject.FirewallD1.config.direct"
	ifaceProperties    = "org.freedesktop.DBus.Properties"
)

// Conn is a connection to the firewalld service on the system bus. It caches the
// server version and derived capabilities so callers can branch on Supports and
// internal code can pick the tuple or dict transport. A Conn is safe for
// concurrent use to the extent godbus's connection is.
type Conn struct {
	conn    *dbus.Conn
	version Version
	caps    map[Capability]bool

	// ownConn records whether we dialed the bus (and must close it) or adopted a
	// caller-provided connection (and must leave it open).
	ownConn bool
}

// Connect dials the system bus, reads the firewalld version property, and derives
// the capability set. The context bounds the connection and initial version read.
func Connect(ctx context.Context) (*Conn, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	c, err := newConn(ctx, conn, true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Open builds a Conn on a caller-supplied bus connection. The caller retains
// ownership: Close will not tear the bus down. Useful for sharing a bus or for
// tests against a private connection.
func Open(ctx context.Context, bus *dbus.Conn) (*Conn, error) {
	return newConn(ctx, bus, false)
}

// newConn wires up the object handles and probes the version/caps.
func newConn(ctx context.Context, bus *dbus.Conn, own bool) (*Conn, error) {
	c := &Conn{
		conn:    bus,
		ownConn: own,
	}
	v, err := c.readVersion(ctx)
	if err != nil {
		return nil, err
	}
	c.version = v
	c.caps = capsFor(v)
	return c, nil
}

// readVersion reads the "version" property on the main interface via a
// context-bounded Properties.Get call.
func (c *Conn) readVersion(ctx context.Context) (Version, error) {
	var variant dbus.Variant
	err := c.call(ctx, basePath, ifaceProperties, "Get", []any{&variant}, ifaceMain, "version")
	if err != nil {
		return Version{}, err
	}
	s, _ := variant.Value().(string)
	return parseVersion(s), nil
}

// Version returns the firewalld version reported by the server.
func (c *Conn) Version() Version { return c.version }

// Supports reports whether the connected server provides a capability.
func (c *Conn) Supports(cap Capability) bool { return c.caps[cap] }

// Close releases the connection. If the bus was dialed by Connect it is closed;
// a bus adopted via Open is left open for its owner.
func (c *Conn) Close() error {
	if c.ownConn && c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// call invokes a method on an arbitrary object path/interface and decodes the
// return values into rets. It is the single choke point through which every typed
// method flows, so error mapping happens in exactly one place.
func (c *Conn) call(ctx context.Context, path dbus.ObjectPath, iface, method string, rets []any, args ...any) error {
	obj := c.conn.Object(dest, path)
	call := obj.CallWithContext(ctx, iface+"."+method, 0, args...)
	if call.Err != nil {
		return mapError(call.Err)
	}
	if len(rets) == 0 {
		return nil
	}
	return mapError(call.Store(rets...))
}

// Call is the low-level escape hatch for any method not yet wrapped by a typed
// helper. It targets the given object path and interface, passes args verbatim,
// and stores results into rets (pointers). Errors are mapped to sentinels.
func (c *Conn) Call(ctx context.Context, path dbus.ObjectPath, iface, method string, rets []any, args ...any) error {
	return c.call(ctx, path, iface, method, rets, args...)
}

// Reload reloads firewalld's permanent configuration into the runtime, keeping
// active bindings where possible.
func (c *Conn) Reload(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "reload", nil)
}

// CompleteReload reloads and also re-reads interface-to-zone bindings, dropping
// active runtime state. Heavier than Reload; use when the permanent set changed
// structurally.
func (c *Conn) CompleteReload(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "completeReload", nil)
}

// RuntimeToPermanent persists the current runtime configuration as permanent.
func (c *Conn) RuntimeToPermanent(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "runtimeToPermanent", nil)
}

// ResetToDefaults resets the permanent configuration to firewalld's defaults.
// Requires firewalld >= 1.0; returns ErrUnsupported on older servers.
func (c *Conn) ResetToDefaults(ctx context.Context) error {
	if !c.caps[ResetToDefaults] {
		return ErrUnsupported
	}
	return c.call(ctx, basePath, ifaceMain, "resetToDefaults", nil)
}

// CheckPermanentConfig validates the on-disk permanent configuration, returning a
// firewalld error if it is inconsistent.
func (c *Conn) CheckPermanentConfig(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "checkPermanentConfig", nil)
}

// Panic-mode controls. Panic mode drops all traffic; callers on a remote bus must
// take care not to lock themselves out.

// EnablePanicMode drops all inbound and outbound packets.
func (c *Conn) EnablePanicMode(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "enablePanicMode", nil)
}

// DisablePanicMode restores normal packet processing.
func (c *Conn) DisablePanicMode(ctx context.Context) error {
	return c.call(ctx, basePath, ifaceMain, "disablePanicMode", nil)
}

// QueryPanicMode reports whether panic mode is active.
func (c *Conn) QueryPanicMode(ctx context.Context) (bool, error) {
	var on bool
	err := c.call(ctx, basePath, ifaceMain, "queryPanicMode", []any{&on})
	return on, err
}

// LogDenied returns the current LogDenied setting ("off", "all", "unicast", ...).
func (c *Conn) LogDenied(ctx context.Context) (string, error) {
	var s string
	err := c.call(ctx, basePath, ifaceMain, "getLogDenied", []any{&s})
	return s, err
}

// SetLogDenied sets the LogDenied value.
func (c *Conn) SetLogDenied(ctx context.Context, value string) error {
	return c.call(ctx, basePath, ifaceMain, "setLogDenied", nil, value)
}

// DefaultZone returns the name of the default zone.
func (c *Conn) DefaultZone(ctx context.Context) (string, error) {
	var s string
	err := c.call(ctx, basePath, ifaceMain, "getDefaultZone", []any{&s})
	return s, err
}

// SetDefaultZone sets the default zone by name.
func (c *Conn) SetDefaultZone(ctx context.Context, zone string) error {
	return c.call(ctx, basePath, ifaceMain, "setDefaultZone", nil, zone)
}
