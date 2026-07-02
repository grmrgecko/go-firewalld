package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// HelperSettings is the transport-neutral representation of a conntrack helper. It
// maps to the tuple "(sssssa(ss))": version, short, description, family, module,
// ports.
type HelperSettings struct {
	Version     string
	Short       string
	Description string
	Family      string // "", "ipv4", or "ipv6"
	Module      string // e.g. "nf_conntrack_ftp"
	Ports       []Port
}

// helperTuple is the concrete struct godbus encodes to "(sssssa(ss))".
type helperTuple struct {
	Version     string
	Short       string
	Description string
	Family      string
	Module      string
	Ports       []Port
}

func (s *HelperSettings) toTuple() helperTuple {
	return helperTuple{
		Version:     s.Version,
		Short:       s.Short,
		Description: s.Description,
		Family:      s.Family,
		Module:      s.Module,
		Ports:       s.Ports,
	}
}

func helperSettingsFromTuple(raw []any) HelperSettings {
	return HelperSettings{
		Version:     asString(tupleField(raw, 0)),
		Short:       asString(tupleField(raw, 1)),
		Description: asString(tupleField(raw, 2)),
		Family:      asString(tupleField(raw, 3)),
		Module:      asString(tupleField(raw, 4)),
		Ports:       asPorts(tupleField(raw, 5)),
	}
}

// Helpers lists the names of all conntrack helpers known to the runtime.
func (c *Conn) Helpers(ctx context.Context) ([]string, error) {
	var names []string
	err := c.call(ctx, basePath, ifaceMain, "getHelpers", []any{&names})
	return names, err
}

// HelperSettings reads a conntrack helper definition from the running firewall.
func (c *Conn) HelperSettings(ctx context.Context, helper string) (HelperSettings, error) {
	var raw []any
	if err := c.call(ctx, basePath, ifaceMain, "getHelperSettings", []any{&raw}, helper); err != nil {
		return HelperSettings{}, err
	}
	return helperSettingsFromTuple(raw), nil
}

// HelperNames lists the names of all permanent conntrack helpers.
func (p *Permanent) HelperNames(ctx context.Context) ([]string, error) {
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getHelperNames", []any{&names})
	return names, err
}

// HelperPaths lists the config object paths of all permanent helpers.
func (p *Permanent) HelperPaths(ctx context.Context) ([]dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "listHelpers", []any{&paths})
	return paths, err
}

// AddHelper creates a new permanent conntrack helper and returns its config path.
func (p *Permanent) AddHelper(ctx context.Context, name string, settings HelperSettings) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "addHelper", []any{&path}, name, settings.toTuple())
	return path, err
}

// Helper returns a handle for permanent operations on the named helper.
func (p *Permanent) Helper(name string) *PermHelper {
	return &PermHelper{c: p.c, name: name}
}

// PermHelper is a handle for permanent edits to a single conntrack helper,
// operating on the helper's config child object (/config/helper/N).
type PermHelper struct {
	c    *Conn
	name string
	path dbus.ObjectPath
}

func (s *PermHelper) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	if s.path != "" {
		return s.path, nil
	}
	var path dbus.ObjectPath
	if err := s.c.call(ctx, configPath, ifaceConfig, "getHelperByName", []any{&path}, s.name); err != nil {
		return "", err
	}
	s.path = path
	return path, nil
}

func (s *PermHelper) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return s.c.call(ctx, path, ifaceConfigHelper, method, rets, args...)
}

// Settings reads the helper's permanent settings.
func (s *PermHelper) Settings(ctx context.Context) (HelperSettings, error) {
	var raw []any
	if err := s.callOn(ctx, "getSettings", []any{&raw}); err != nil {
		return HelperSettings{}, err
	}
	return helperSettingsFromTuple(raw), nil
}

// Update replaces the helper's permanent settings.
func (s *PermHelper) Update(ctx context.Context, settings HelperSettings) error {
	return s.callOn(ctx, "update", nil, settings.toTuple())
}

// SetFamily sets the helper's IP family ("", "ipv4", "ipv6").
func (s *PermHelper) SetFamily(ctx context.Context, family string) error {
	return s.callOn(ctx, "setFamily", nil, family)
}

// SetModule sets the helper's netfilter module name.
func (s *PermHelper) SetModule(ctx context.Context, module string) error {
	return s.callOn(ctx, "setModule", nil, module)
}

// AddPort adds a port to the permanent helper.
func (s *PermHelper) AddPort(ctx context.Context, p Port) error {
	return s.callOn(ctx, "addPort", nil, p.Port, p.Protocol)
}

// RemovePort removes a port from the permanent helper.
func (s *PermHelper) RemovePort(ctx context.Context, p Port) error {
	return s.callOn(ctx, "removePort", nil, p.Port, p.Protocol)
}

// SetDescription sets the permanent helper description.
func (s *PermHelper) SetDescription(ctx context.Context, description string) error {
	return s.callOn(ctx, "setDescription", nil, description)
}

// Remove deletes the helper from the permanent configuration.
func (s *PermHelper) Remove(ctx context.Context) error {
	return s.callOn(ctx, "remove", nil)
}
