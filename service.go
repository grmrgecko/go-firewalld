package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// ServiceSettings is the transport-neutral representation of a firewalld service.
// It maps to the v1 tuple "(sssa(ss)asa{ss}asa(ss))": version, short,
// description, ports, modules, destinations, protocols, source_ports. Newer
// firewalld also exposes includes/helpers via the dict form (getSettings2), which
// are modelled here and populated when the dict transport is available.
type ServiceSettings struct {
	Version      string
	Short        string
	Description  string
	Ports        []Port
	Modules      []string          // netfilter helper modules
	Destinations map[string]string // family -> address, e.g. {"ipv4": "224.0.0.0/8"}
	Protocols    []string
	SourcePorts  []Port
	Includes     []string // dict-only (firewalld >= 1.0)
	Helpers      []string // dict-only (firewalld >= 1.0)
}

// serviceTuple is the concrete struct godbus encodes to the v1 service signature.
type serviceTuple struct {
	Version      string
	Short        string
	Description  string
	Ports        []Port
	Modules      []string
	Destinations map[string]string
	Protocols    []string
	SourcePorts  []Port
}

func (s *ServiceSettings) toTuple() serviceTuple {
	dst := s.Destinations
	if dst == nil {
		dst = map[string]string{}
	}
	return serviceTuple{
		Version:      s.Version,
		Short:        s.Short,
		Description:  s.Description,
		Ports:        s.Ports,
		Modules:      s.Modules,
		Destinations: dst,
		Protocols:    s.Protocols,
		SourcePorts:  s.SourcePorts,
	}
}

// serviceSettingsFromTuple decodes a raw v1 service tuple, length-tolerant.
func serviceSettingsFromTuple(raw []any) ServiceSettings {
	return ServiceSettings{
		Version:      asString(tupleField(raw, 0)),
		Short:        asString(tupleField(raw, 1)),
		Description:  asString(tupleField(raw, 2)),
		Ports:        asPorts(tupleField(raw, 3)),
		Modules:      asStrings(tupleField(raw, 4)),
		Destinations: asStringMap(tupleField(raw, 5)),
		Protocols:    asStrings(tupleField(raw, 6)),
		SourcePorts:  asPorts(tupleField(raw, 7)),
	}
}

// serviceSettingsFromDict decodes the a{sv} service form, including the
// dict-only includes/helpers keys. Missing keys read as zero values.
func serviceSettingsFromDict(d map[string]dbus.Variant) ServiceSettings {
	var s ServiceSettings
	if v, ok := dictValue(d, "version"); ok {
		s.Version = asString(v)
	}
	if v, ok := dictValue(d, "short"); ok {
		s.Short = asString(v)
	}
	if v, ok := dictValue(d, "description"); ok {
		s.Description = asString(v)
	}
	if v, ok := dictValue(d, "ports"); ok {
		s.Ports = asPorts(v)
	}
	if v, ok := dictValue(d, "module"); ok {
		s.Modules = asStrings(v)
	} else if v, ok := dictValue(d, "modules"); ok {
		s.Modules = asStrings(v)
	}
	if v, ok := dictValue(d, "destination"); ok {
		s.Destinations = asStringMap(v)
	} else if v, ok := dictValue(d, "destinations"); ok {
		s.Destinations = asStringMap(v)
	}
	if v, ok := dictValue(d, "protocols"); ok {
		s.Protocols = asStrings(v)
	}
	if v, ok := dictValue(d, "source_ports"); ok {
		s.SourcePorts = asPorts(v)
	}
	if v, ok := dictValue(d, "includes"); ok {
		s.Includes = asStrings(v)
	}
	if v, ok := dictValue(d, "helpers"); ok {
		s.Helpers = asStrings(v)
	}
	return s
}

// Services lists the names of all services known to the runtime.
func (c *Conn) Services(ctx context.Context) ([]string, error) {
	var names []string
	err := c.call(ctx, basePath, ifaceMain, "listServices", []any{&names})
	return names, err
}

// ServiceSettings reads a service definition from the running firewall, choosing
// the dict transport (getServiceSettings2) when available so includes/helpers are
// populated, and falling back to the v1 tuple otherwise.
func (c *Conn) ServiceSettings(ctx context.Context, service string) (ServiceSettings, error) {
	if c.caps[ServiceSettings2] {
		var d map[string]dbus.Variant
		if err := c.call(ctx, basePath, ifaceMain, "getServiceSettings2", []any{&d}, service); err != nil {
			return ServiceSettings{}, err
		}
		return serviceSettingsFromDict(d), nil
	}
	var raw []any
	if err := c.call(ctx, basePath, ifaceMain, "getServiceSettings", []any{&raw}, service); err != nil {
		return ServiceSettings{}, err
	}
	return serviceSettingsFromTuple(raw), nil
}

// ServiceNames lists the names of all permanent services.
func (p *Permanent) ServiceNames(ctx context.Context) ([]string, error) {
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getServiceNames", []any{&names})
	return names, err
}

// AddService creates a new permanent service and returns its config object path.
func (p *Permanent) AddService(ctx context.Context, name string, settings ServiceSettings) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "addService", []any{&path}, name, settings.toTuple())
	return path, err
}

// Service returns a handle for permanent operations on the named service.
func (p *Permanent) Service(name string) *PermService {
	return &PermService{c: p.c, name: name}
}

// PermService is a handle for permanent edits to a single service definition,
// operating on the service's config child object (/config/service/N).
type PermService struct {
	c    *Conn
	name string
	path dbus.ObjectPath
}

func (s *PermService) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	if s.path != "" {
		return s.path, nil
	}
	var path dbus.ObjectPath
	if err := s.c.call(ctx, configPath, ifaceConfig, "getServiceByName", []any{&path}, s.name); err != nil {
		return "", err
	}
	s.path = path
	return path, nil
}

func (s *PermService) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return s.c.call(ctx, path, ifaceConfigService, method, rets, args...)
}

// Settings reads the service's permanent settings via the v1 tuple.
func (s *PermService) Settings(ctx context.Context) (ServiceSettings, error) {
	var raw []any
	if err := s.callOn(ctx, "getSettings", []any{&raw}); err != nil {
		return ServiceSettings{}, err
	}
	return serviceSettingsFromTuple(raw), nil
}

// Update replaces the service's permanent settings via the v1 tuple.
func (s *PermService) Update(ctx context.Context, settings ServiceSettings) error {
	return s.callOn(ctx, "update", nil, settings.toTuple())
}

// Port operations.
func (s *PermService) AddPort(ctx context.Context, p Port) error {
	return s.callOn(ctx, "addPort", nil, p.Port, p.Protocol)
}
func (s *PermService) RemovePort(ctx context.Context, p Port) error {
	return s.callOn(ctx, "removePort", nil, p.Port, p.Protocol)
}

// Protocol operations.
func (s *PermService) AddProtocol(ctx context.Context, proto string) error {
	return s.callOn(ctx, "addProtocol", nil, proto)
}
func (s *PermService) RemoveProtocol(ctx context.Context, proto string) error {
	return s.callOn(ctx, "removeProtocol", nil, proto)
}

// Module (netfilter helper) operations.
func (s *PermService) AddModule(ctx context.Context, module string) error {
	return s.callOn(ctx, "addModule", nil, module)
}
func (s *PermService) RemoveModule(ctx context.Context, module string) error {
	return s.callOn(ctx, "removeModule", nil, module)
}

// SetDestination sets the destination address for an IP family ("ipv4"/"ipv6").
func (s *PermService) SetDestination(ctx context.Context, family, address string) error {
	return s.callOn(ctx, "setDestination", nil, family, address)
}

// RemoveDestination clears the destination for an IP family.
func (s *PermService) RemoveDestination(ctx context.Context, family string) error {
	return s.callOn(ctx, "removeDestination", nil, family)
}

// Include operations compose other services into this one (firewalld >= 1.0).
func (s *PermService) AddInclude(ctx context.Context, service string) error {
	return s.callOn(ctx, "addInclude", nil, service)
}
func (s *PermService) RemoveInclude(ctx context.Context, service string) error {
	return s.callOn(ctx, "removeInclude", nil, service)
}
func (s *PermService) QueryInclude(ctx context.Context, service string) (bool, error) {
	var ok bool
	err := s.callOn(ctx, "queryInclude", []any{&ok}, service)
	return ok, err
}
func (s *PermService) Includes(ctx context.Context) ([]string, error) {
	var xs []string
	err := s.callOn(ctx, "getIncludes", []any{&xs})
	return xs, err
}

// SetDescription sets the permanent service description.
func (s *PermService) SetDescription(ctx context.Context, description string) error {
	return s.callOn(ctx, "setDescription", nil, description)
}

// Remove deletes the service from the permanent configuration.
func (s *PermService) Remove(ctx context.Context) error {
	return s.callOn(ctx, "remove", nil)
}
