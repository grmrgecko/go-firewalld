package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// ICMPTypeSettings is the transport-neutral representation of an ICMP type. It
// maps to the tuple "(sssas)": version, short, description, destinations. The
// destinations list holds the IP families the type applies to ("ipv4", "ipv6").
type ICMPTypeSettings struct {
	Version      string
	Short        string
	Description  string
	Destinations []string
}

// icmpTuple is the concrete struct godbus encodes to "(sssas)".
type icmpTuple struct {
	Version      string
	Short        string
	Description  string
	Destinations []string
}

func (s *ICMPTypeSettings) toTuple() icmpTuple {
	dst := s.Destinations
	if dst == nil {
		dst = []string{}
	}
	return icmpTuple{
		Version:      s.Version,
		Short:        s.Short,
		Description:  s.Description,
		Destinations: dst,
	}
}

func icmpSettingsFromTuple(raw []any) ICMPTypeSettings {
	return ICMPTypeSettings{
		Version:      asString(tupleField(raw, 0)),
		Short:        asString(tupleField(raw, 1)),
		Description:  asString(tupleField(raw, 2)),
		Destinations: asStrings(tupleField(raw, 3)),
	}
}

// ICMPTypes lists the names of all ICMP types known to the runtime.
func (c *Conn) ICMPTypes(ctx context.Context) ([]string, error) {
	var names []string
	err := c.call(ctx, basePath, ifaceMain, "listIcmpTypes", []any{&names})
	return names, err
}

// ICMPTypeSettings reads an ICMP type definition from the running firewall.
func (c *Conn) ICMPTypeSettings(ctx context.Context, icmptype string) (ICMPTypeSettings, error) {
	var raw []any
	if err := c.call(ctx, basePath, ifaceMain, "getIcmpTypeSettings", []any{&raw}, icmptype); err != nil {
		return ICMPTypeSettings{}, err
	}
	return icmpSettingsFromTuple(raw), nil
}

// ICMPTypeNames lists the names of all permanent ICMP types.
func (p *Permanent) ICMPTypeNames(ctx context.Context) ([]string, error) {
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getIcmpTypeNames", []any{&names})
	return names, err
}

// AddICMPType creates a new permanent ICMP type and returns its config path.
func (p *Permanent) AddICMPType(ctx context.Context, name string, settings ICMPTypeSettings) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "addIcmpType", []any{&path}, name, settings.toTuple())
	return path, err
}

// ICMPType returns a handle for permanent operations on the named ICMP type.
func (p *Permanent) ICMPType(name string) *PermICMPType {
	return &PermICMPType{c: p.c, name: name}
}

// PermICMPType is a handle for permanent edits to a single ICMP type, operating
// on the icmptype's config child object (/config/icmptype/N).
type PermICMPType struct {
	c    *Conn
	name string
	path dbus.ObjectPath
}

func (s *PermICMPType) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	if s.path != "" {
		return s.path, nil
	}
	var path dbus.ObjectPath
	if err := s.c.call(ctx, configPath, ifaceConfig, "getIcmpTypeByName", []any{&path}, s.name); err != nil {
		return "", err
	}
	s.path = path
	return path, nil
}

func (s *PermICMPType) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return s.c.call(ctx, path, ifaceConfigICMP, method, rets, args...)
}

// Settings reads the ICMP type's permanent settings.
func (s *PermICMPType) Settings(ctx context.Context) (ICMPTypeSettings, error) {
	var raw []any
	if err := s.callOn(ctx, "getSettings", []any{&raw}); err != nil {
		return ICMPTypeSettings{}, err
	}
	return icmpSettingsFromTuple(raw), nil
}

// Update replaces the ICMP type's permanent settings.
func (s *PermICMPType) Update(ctx context.Context, settings ICMPTypeSettings) error {
	return s.callOn(ctx, "update", nil, settings.toTuple())
}

// AddDestination adds an IP family ("ipv4"/"ipv6") the type applies to.
func (s *PermICMPType) AddDestination(ctx context.Context, family string) error {
	return s.callOn(ctx, "addDestination", nil, family)
}

// RemoveDestination removes an IP family from the type.
func (s *PermICMPType) RemoveDestination(ctx context.Context, family string) error {
	return s.callOn(ctx, "removeDestination", nil, family)
}

// QueryDestination reports whether the type applies to an IP family.
func (s *PermICMPType) QueryDestination(ctx context.Context, family string) (bool, error) {
	var ok bool
	err := s.callOn(ctx, "queryDestination", []any{&ok}, family)
	return ok, err
}

// SetDescription sets the permanent ICMP type description.
func (s *PermICMPType) SetDescription(ctx context.Context, description string) error {
	return s.callOn(ctx, "setDescription", nil, description)
}

// Remove deletes the ICMP type from the permanent configuration.
func (s *PermICMPType) Remove(ctx context.Context) error {
	return s.callOn(ctx, "remove", nil)
}
