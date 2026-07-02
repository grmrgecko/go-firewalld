package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// PolicySettings is the transport-neutral representation of a zone-to-zone policy
// (firewalld >= 0.9). Policies have no v1 tuple form; they are exchanged only as
// an a{sv} dict. Ingress and egress zones define the traffic the policy governs;
// the remaining fields mirror a zone's filtering elements.
type PolicySettings struct {
	Version      string
	Short        string
	Description  string
	Target       string // CONTINUE, ACCEPT, DROP, REJECT
	Priority     int32
	IngressZones []string
	EgressZones  []string
	Services     []string
	Ports        []Port
	SourcePorts  []Port
	ICMPBlocks   []string
	Masquerade   bool
	ForwardPorts []ForwardPort
	RichRules    []string
	Protocols    []string
}

// toDict builds the a{sv} policy dict with concrete typed values so godbus emits
// the tuple signatures firewalld requires.
func (s *PolicySettings) toDict() map[string]dbus.Variant {
	target := s.Target
	if target == "" {
		target = "CONTINUE"
	}
	return map[string]dbus.Variant{
		"version":       dbus.MakeVariant(s.Version),
		"short":         dbus.MakeVariant(s.Short),
		"description":   dbus.MakeVariant(s.Description),
		"target":        dbus.MakeVariant(target),
		"priority":      dbus.MakeVariant(s.Priority),
		"ingress_zones": dbus.MakeVariant(nonNilStrings(s.IngressZones)),
		"egress_zones":  dbus.MakeVariant(nonNilStrings(s.EgressZones)),
		"services":      dbus.MakeVariant(nonNilStrings(s.Services)),
		"ports":         dbus.MakeVariant(nonNilPorts(s.Ports)),
		"source_ports":  dbus.MakeVariant(nonNilPorts(s.SourcePorts)),
		"icmp_blocks":   dbus.MakeVariant(nonNilStrings(s.ICMPBlocks)),
		"masquerade":    dbus.MakeVariant(s.Masquerade),
		"forward_ports": dbus.MakeVariant(nonNilForwardPorts(s.ForwardPorts)),
		// Policies name rich rules "rich_rules" in their dict (zones use
		// "rules_str"); firewalld rejects the wrong key with INVALID_OPTION.
		"rich_rules": dbus.MakeVariant(nonNilStrings(s.RichRules)),
		"protocols":  dbus.MakeVariant(nonNilStrings(s.Protocols)),
	}
}

// policySettingsFromDict decodes an a{sv} policy dict, tolerating omitted keys.
func policySettingsFromDict(d map[string]dbus.Variant) PolicySettings {
	var s PolicySettings
	if v, ok := dictValue(d, "version"); ok {
		s.Version = asString(v)
	}
	if v, ok := dictValue(d, "short"); ok {
		s.Short = asString(v)
	}
	if v, ok := dictValue(d, "description"); ok {
		s.Description = asString(v)
	}
	if v, ok := dictValue(d, "target"); ok {
		s.Target = asString(v)
	}
	if v, ok := dictValue(d, "priority"); ok {
		s.Priority = asInt32(v)
	}
	if v, ok := dictValue(d, "ingress_zones"); ok {
		s.IngressZones = asStrings(v)
	}
	if v, ok := dictValue(d, "egress_zones"); ok {
		s.EgressZones = asStrings(v)
	}
	if v, ok := dictValue(d, "services"); ok {
		s.Services = asStrings(v)
	}
	if v, ok := dictValue(d, "ports"); ok {
		s.Ports = asPorts(v)
	}
	if v, ok := dictValue(d, "source_ports"); ok {
		s.SourcePorts = asPorts(v)
	}
	if v, ok := dictValue(d, "icmp_blocks"); ok {
		s.ICMPBlocks = asStrings(v)
	}
	if v, ok := dictValue(d, "masquerade"); ok {
		s.Masquerade = asBool(v)
	}
	if v, ok := dictValue(d, "forward_ports"); ok {
		s.ForwardPorts = asForwardPorts(v)
	}
	if v, ok := dictValue(d, "rules_str"); ok {
		s.RichRules = asStrings(v)
	} else if v, ok := dictValue(d, "rich_rules"); ok {
		s.RichRules = asStrings(v)
	}
	if v, ok := dictValue(d, "protocols"); ok {
		s.Protocols = asStrings(v)
	}
	return s
}

// Policies lists the names of all policies known to the runtime. Returns
// ErrUnsupported on servers that predate policy support (firewalld < 0.9).
func (r *Runtime) Policies(ctx context.Context) ([]string, error) {
	if !r.c.caps[Policies] {
		return nil, ErrUnsupported
	}
	var names []string
	err := r.c.call(ctx, basePath, ifacePolicy, "getPolicies", []any{&names})
	return names, err
}

// ActivePolicies returns the policies that currently have zones bound.
func (r *Runtime) ActivePolicies(ctx context.Context) ([]string, error) {
	if !r.c.caps[Policies] {
		return nil, ErrUnsupported
	}
	var active map[string]map[string][]string
	if err := r.c.call(ctx, basePath, ifacePolicy, "getActivePolicies", []any{&active}); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(active))
	for name := range active {
		names = append(names, name)
	}
	return names, nil
}

// PolicySettings reads a policy definition from the running firewall.
func (r *Runtime) PolicySettings(ctx context.Context, policy string) (PolicySettings, error) {
	if !r.c.caps[Policies] {
		return PolicySettings{}, ErrUnsupported
	}
	var d map[string]dbus.Variant
	if err := r.c.call(ctx, basePath, ifacePolicy, "getPolicySettings", []any{&d}, policy); err != nil {
		return PolicySettings{}, err
	}
	return policySettingsFromDict(d), nil
}

// SetPolicySettings replaces a policy's runtime settings wholesale.
func (r *Runtime) SetPolicySettings(ctx context.Context, policy string, settings PolicySettings) error {
	if !r.c.caps[Policies] {
		return ErrUnsupported
	}
	return r.c.call(ctx, basePath, ifacePolicy, "setPolicySettings", nil, policy, settings.toDict())
}

// PolicyNames lists the names of all permanent policies.
func (p *Permanent) PolicyNames(ctx context.Context) ([]string, error) {
	if !p.c.caps[Policies] {
		return nil, ErrUnsupported
	}
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getPolicyNames", []any{&names})
	return names, err
}

// PolicyPaths lists the config object paths of all permanent policies.
func (p *Permanent) PolicyPaths(ctx context.Context) ([]dbus.ObjectPath, error) {
	if !p.c.caps[Policies] {
		return nil, ErrUnsupported
	}
	var paths []dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "listPolicies", []any{&paths})
	return paths, err
}

// AddPolicy creates a new permanent policy and returns its config object path.
func (p *Permanent) AddPolicy(ctx context.Context, name string, settings PolicySettings) (dbus.ObjectPath, error) {
	if !p.c.caps[Policies] {
		return "", ErrUnsupported
	}
	var path dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "addPolicy", []any{&path}, name, settings.toDict())
	return path, err
}

// Policy returns a handle for permanent operations on the named policy.
func (p *Permanent) Policy(name string) *PermPolicy {
	return &PermPolicy{c: p.c, name: name}
}

// PermPolicy is a handle for permanent edits to a single policy, operating on the
// policy's config child object (/config/policy/N).
type PermPolicy struct {
	c    *Conn
	name string
	path dbus.ObjectPath
}

func (s *PermPolicy) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	if !s.c.caps[Policies] {
		return "", ErrUnsupported
	}
	if s.path != "" {
		return s.path, nil
	}
	var path dbus.ObjectPath
	if err := s.c.call(ctx, configPath, ifaceConfig, "getPolicyByName", []any{&path}, s.name); err != nil {
		return "", err
	}
	s.path = path
	return path, nil
}

func (s *PermPolicy) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return s.c.call(ctx, path, ifaceConfigPolicy, method, rets, args...)
}

// Settings reads the policy's permanent settings.
func (s *PermPolicy) Settings(ctx context.Context) (PolicySettings, error) {
	var d map[string]dbus.Variant
	if err := s.callOn(ctx, "getSettings", []any{&d}); err != nil {
		return PolicySettings{}, err
	}
	return policySettingsFromDict(d), nil
}

// Update replaces the policy's permanent settings wholesale.
func (s *PermPolicy) Update(ctx context.Context, settings PolicySettings) error {
	return s.callOn(ctx, "update", nil, settings.toDict())
}

// Rename changes the policy's name and invalidates the cached path.
func (s *PermPolicy) Rename(ctx context.Context, newName string) error {
	if err := s.callOn(ctx, "rename", nil, newName); err != nil {
		return err
	}
	s.name = newName
	s.path = ""
	return nil
}

// Remove deletes the policy from the permanent configuration.
func (s *PermPolicy) Remove(ctx context.Context) error {
	return s.callOn(ctx, "remove", nil)
}
