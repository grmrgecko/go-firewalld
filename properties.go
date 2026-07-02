package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// This file exposes firewalld's D-Bus properties: read-only runtime state on the
// main object, and the read/write daemon settings (firewalld.conf knobs) on the
// config object. Both are read through org.freedesktop.DBus.Properties.

// getProperty reads a single property via Properties.Get.
func (c *Conn) getProperty(ctx context.Context, path dbus.ObjectPath, iface, name string) (dbus.Variant, error) {
	var v dbus.Variant
	err := c.call(ctx, path, ifaceProperties, "Get", []any{&v}, iface, name)
	return v, err
}

// getAllProperties reads every property of an interface via Properties.GetAll.
func (c *Conn) getAllProperties(ctx context.Context, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	var m map[string]dbus.Variant
	err := c.call(ctx, path, ifaceProperties, "GetAll", []any{&m}, iface)
	return m, err
}

// setProperty writes a property via Properties.Set.
func (c *Conn) setProperty(ctx context.Context, path dbus.ObjectPath, iface, name string, value any) error {
	return c.call(ctx, path, ifaceProperties, "Set", nil, iface, name, dbus.MakeVariant(value))
}

// State returns firewalld's runtime state, e.g. "RUNNING".
func (c *Conn) State(ctx context.Context) (string, error) {
	v, err := c.getProperty(ctx, basePath, ifaceMain, "state")
	if err != nil {
		return "", err
	}
	return asString(v.Value()), nil
}

// MainProperty reads a single read-only property from the main object (e.g.
// "IPv4", "IPSetTypes", "nf_conntrack_helpers") for values not covered by a typed
// accessor.
func (c *Conn) MainProperty(ctx context.Context, name string) (dbus.Variant, error) {
	return c.getProperty(ctx, basePath, ifaceMain, name)
}

// RuntimeInfo captures the main object's read-only capability and state
// properties, describing what the running firewalld supports.
type RuntimeInfo struct {
	State         string
	InterfaceVer  string
	IPv4          bool
	IPv6          bool
	IPv6RPFilter  bool
	Bridge        bool
	IPSet         bool
	IPSetTypes    []string
	IPv4ICMPTypes []string
	IPv6ICMPTypes []string
}

// RuntimeInfo reads the main object's runtime properties in one round-trip.
func (c *Conn) RuntimeInfo(ctx context.Context) (RuntimeInfo, error) {
	m, err := c.getAllProperties(ctx, basePath, ifaceMain)
	if err != nil {
		return RuntimeInfo{}, err
	}
	get := func(k string) any {
		if v, ok := m[k]; ok {
			return v.Value()
		}
		return nil
	}
	return RuntimeInfo{
		State:         asString(get("state")),
		InterfaceVer:  asString(get("interface_version")),
		IPv4:          asBool(get("IPv4")),
		IPv6:          asBool(get("IPv6")),
		IPv6RPFilter:  asBool(get("IPv6_rpfilter")),
		Bridge:        asBool(get("BRIDGE")),
		IPSet:         asBool(get("IPSet")),
		IPSetTypes:    asStrings(get("IPSetTypes")),
		IPv4ICMPTypes: asStrings(get("IPv4ICMPTypes")),
		IPv6ICMPTypes: asStrings(get("IPv6ICMPTypes")),
	}, nil
}

// DaemonConfig holds firewalld's permanent daemon settings (the firewalld.conf
// knobs). Fields absent on the connected version read as empty. Most values are
// firewalld's "yes"/"no" strings or an enum ("iptables"/"nftables"); they are
// exposed verbatim rather than coerced, since firewalld's own semantics vary.
type DaemonConfig struct {
	DefaultZone          string
	MinimalMark          int32
	CleanupOnExit        string
	CleanupModulesOnExit string
	Lockdown             string
	IPv6RPFilter         string
	IPv6RPFilter2        string // finer-grained rp_filter (newer firewalld)
	IndividualCalls      string
	LogDenied            string
	AutomaticHelpers     string
	FirewallBackend      string
	FlushAllOnReload     string
	RFC3964IPv4          string
	AllowZoneDrifting    string
	NftablesTableOwner   string
	NftablesCounters     string // nftables rule counters (firewalld >= 2.0)
	NftablesFlowtable    string // nftables flowtable offload (firewalld >= 2.0)
	StrictForwardPorts   string // strict forward-port handling (firewalld >= 2.0)
}

// DaemonConfig reads the config object's daemon-settings properties.
func (p *Permanent) DaemonConfig(ctx context.Context) (DaemonConfig, error) {
	m, err := p.c.getAllProperties(ctx, configPath, ifaceConfig)
	if err != nil {
		return DaemonConfig{}, err
	}
	get := func(k string) any {
		if v, ok := m[k]; ok {
			return v.Value()
		}
		return nil
	}
	return DaemonConfig{
		DefaultZone:          asString(get("DefaultZone")),
		MinimalMark:          asInt32(get("MinimalMark")),
		CleanupOnExit:        asString(get("CleanupOnExit")),
		CleanupModulesOnExit: asString(get("CleanupModulesOnExit")),
		Lockdown:             asString(get("Lockdown")),
		IPv6RPFilter:         asString(get("IPv6_rpfilter")),
		IPv6RPFilter2:        asString(get("IPv6_rpfilter2")),
		IndividualCalls:      asString(get("IndividualCalls")),
		LogDenied:            asString(get("LogDenied")),
		AutomaticHelpers:     asString(get("AutomaticHelpers")),
		FirewallBackend:      asString(get("FirewallBackend")),
		FlushAllOnReload:     asString(get("FlushAllOnReload")),
		RFC3964IPv4:          asString(get("RFC3964_IPv4")),
		AllowZoneDrifting:    asString(get("AllowZoneDrifting")),
		NftablesTableOwner:   asString(get("NftablesTableOwner")),
		NftablesCounters:     asString(get("NftablesCounters")),
		NftablesFlowtable:    asString(get("NftablesFlowtable")),
		StrictForwardPorts:   asString(get("StrictForwardPorts")),
	}, nil
}

// ConfigProperty reads a single daemon-config property by its firewalld name
// (e.g. "FirewallBackend", "IPv6_rpfilter").
func (p *Permanent) ConfigProperty(ctx context.Context, name string) (dbus.Variant, error) {
	return p.c.getProperty(ctx, configPath, ifaceConfig, name)
}

// SetConfigProperty writes a daemon-config property. Changes are permanent and
// take effect after a reload; most require privilege.
func (p *Permanent) SetConfigProperty(ctx context.Context, name string, value any) error {
	return p.c.setProperty(ctx, configPath, ifaceConfig, name, value)
}

// SetFirewallBackend selects the packet backend ("nftables" or "iptables").
func (p *Permanent) SetFirewallBackend(ctx context.Context, backend string) error {
	return p.SetConfigProperty(ctx, "FirewallBackend", backend)
}
