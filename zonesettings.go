package firewalld

import "github.com/godbus/dbus/v5"

// ZoneSettings is the complete, transport-neutral representation of a zone's
// configuration. It is populated from either the v1 tuple (EL7 and up) or the v2
// dict (firewalld >= 0.9) and encodes back through whichever transport the server
// supports. The final three fields exist only in the v2 dict; on the tuple path
// they are ignored on write and left zero on read.
type ZoneSettings struct {
	Version            string
	Short              string
	Description        string
	Target             Target
	Services           []string
	Ports              []Port
	ICMPBlocks         []string
	Masquerade         bool
	ForwardPorts       []ForwardPort
	Interfaces         []string
	Sources            []string
	RichRules          []string
	Protocols          []string
	SourcePorts        []Port
	ICMPBlockInversion bool

	// v2-only (dict) fields.
	Forward         bool  // intra-zone forwarding (firewalld >= 0.9)
	EgressPriority  int32 // zone egress priority (newer firewalld)
	IngressPriority int32 // zone ingress priority (newer firewalld)
}

// zoneTuple is the concrete Go struct godbus encodes to the v1 zone-settings
// signature "(sssbsasa(ss)asba(ssss)asasasasa(ss)b)". Field order is load-bearing:
// it must match firewalld's tuple exactly. The Unused bool is firewalld's dead
// field 3 (historically "immutable").
type zoneTuple struct {
	Version            string
	Short              string
	Description        string
	Unused             bool
	Target             string
	Services           []string
	Ports              []Port
	ICMPBlocks         []string
	Masquerade         bool
	ForwardPorts       []ForwardPort
	Interfaces         []string
	Sources            []string
	RichRules          []string
	Protocols          []string
	SourcePorts        []Port
	ICMPBlockInversion bool
}

// toTuple builds the v1 tuple struct from settings. Nil slices encode as empty
// D-Bus arrays, which is what firewalld expects for "no entries".
func (s *ZoneSettings) toTuple() zoneTuple {
	target := string(s.Target)
	if target == "" {
		target = string(TargetDefault)
	}
	return zoneTuple{
		Version:            s.Version,
		Short:              s.Short,
		Description:        s.Description,
		Target:             target,
		Services:           s.Services,
		Ports:              s.Ports,
		ICMPBlocks:         s.ICMPBlocks,
		Masquerade:         s.Masquerade,
		ForwardPorts:       s.ForwardPorts,
		Interfaces:         s.Interfaces,
		Sources:            s.Sources,
		RichRules:          s.RichRules,
		Protocols:          s.Protocols,
		SourcePorts:        s.SourcePorts,
		ICMPBlockInversion: s.ICMPBlockInversion,
	}
}

// zoneSettingsFromTuple decodes a raw v1 tuple (godbus []any) into
// ZoneSettings. Every field is read through the length-tolerant helpers so a
// short tuple from an old firewalld yields zero values instead of a panic.
func zoneSettingsFromTuple(raw []any) ZoneSettings {
	return ZoneSettings{
		Version:     asString(tupleField(raw, 0)),
		Short:       asString(tupleField(raw, 1)),
		Description: asString(tupleField(raw, 2)),
		// field 3 is the unused bool
		Target:             Target(asString(tupleField(raw, 4))),
		Services:           asStrings(tupleField(raw, 5)),
		Ports:              asPorts(tupleField(raw, 6)),
		ICMPBlocks:         asStrings(tupleField(raw, 7)),
		Masquerade:         asBool(tupleField(raw, 8)),
		ForwardPorts:       asForwardPorts(tupleField(raw, 9)),
		Interfaces:         asStrings(tupleField(raw, 10)),
		Sources:            asStrings(tupleField(raw, 11)),
		RichRules:          asStrings(tupleField(raw, 12)),
		Protocols:          asStrings(tupleField(raw, 13)),
		SourcePorts:        asPorts(tupleField(raw, 14)),
		ICMPBlockInversion: asBool(tupleField(raw, 15)),
	}
}

// toDict builds the a{sv} dict for the v2 transport. Every modelled field is sent
// with a concrete typed value so godbus emits the tuple signatures firewalld
// requires (ports as a(ss), forward_ports as a(ssss)). The egress/ingress
// priority keys are only included when non-zero, so we never send a key an
// intermediate 0.9.x server would reject.
func (s *ZoneSettings) toDict() map[string]dbus.Variant {
	target := string(s.Target)
	if target == "" {
		target = string(TargetDefault)
	}
	d := map[string]dbus.Variant{
		"version":              dbus.MakeVariant(s.Version),
		"short":                dbus.MakeVariant(s.Short),
		"description":          dbus.MakeVariant(s.Description),
		"target":               dbus.MakeVariant(target),
		"services":             dbus.MakeVariant(nonNilStrings(s.Services)),
		"ports":                dbus.MakeVariant(nonNilPorts(s.Ports)),
		"icmp_blocks":          dbus.MakeVariant(nonNilStrings(s.ICMPBlocks)),
		"masquerade":           dbus.MakeVariant(s.Masquerade),
		"forward_ports":        dbus.MakeVariant(nonNilForwardPorts(s.ForwardPorts)),
		"interfaces":           dbus.MakeVariant(nonNilStrings(s.Interfaces)),
		"sources":              dbus.MakeVariant(nonNilStrings(s.Sources)),
		"rules_str":            dbus.MakeVariant(nonNilStrings(s.RichRules)),
		"protocols":            dbus.MakeVariant(nonNilStrings(s.Protocols)),
		"source_ports":         dbus.MakeVariant(nonNilPorts(s.SourcePorts)),
		"icmp_block_inversion": dbus.MakeVariant(s.ICMPBlockInversion),
		"forward":              dbus.MakeVariant(s.Forward),
	}
	if s.EgressPriority != 0 {
		d["egress_priority"] = dbus.MakeVariant(s.EgressPriority)
	}
	if s.IngressPriority != 0 {
		d["ingress_priority"] = dbus.MakeVariant(s.IngressPriority)
	}
	return d
}

// zoneSettingsFromDict decodes an a{sv} dict into ZoneSettings. Keys firewalld
// omitted (unset fields) fall through to zero values.
func zoneSettingsFromDict(d map[string]dbus.Variant) ZoneSettings {
	var s ZoneSettings
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
		s.Target = Target(asString(v))
	}
	if v, ok := dictValue(d, "services"); ok {
		s.Services = asStrings(v)
	}
	if v, ok := dictValue(d, "ports"); ok {
		s.Ports = asPorts(v)
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
	if v, ok := dictValue(d, "interfaces"); ok {
		s.Interfaces = asStrings(v)
	}
	if v, ok := dictValue(d, "sources"); ok {
		s.Sources = asStrings(v)
	}
	// firewalld names rich rules "rules_str" in the dict; accept "rich_rules" too
	// for forward compatibility.
	if v, ok := dictValue(d, "rules_str"); ok {
		s.RichRules = asStrings(v)
	} else if v, ok := dictValue(d, "rich_rules"); ok {
		s.RichRules = asStrings(v)
	}
	if v, ok := dictValue(d, "protocols"); ok {
		s.Protocols = asStrings(v)
	}
	if v, ok := dictValue(d, "source_ports"); ok {
		s.SourcePorts = asPorts(v)
	}
	if v, ok := dictValue(d, "icmp_block_inversion"); ok {
		s.ICMPBlockInversion = asBool(v)
	}
	if v, ok := dictValue(d, "forward"); ok {
		s.Forward = asBool(v)
	}
	if v, ok := dictValue(d, "egress_priority"); ok {
		s.EgressPriority = asInt32(v)
	}
	if v, ok := dictValue(d, "ingress_priority"); ok {
		s.IngressPriority = asInt32(v)
	}
	return s
}

// nonNilStrings returns an empty, non-nil slice for a nil input so godbus emits an
// empty typed array (as) rather than a nil that could confuse the dict encoding.
func nonNilStrings(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func nonNilPorts(xs []Port) []Port {
	if xs == nil {
		return []Port{}
	}
	return xs
}

func nonNilForwardPorts(xs []ForwardPort) []ForwardPort {
	if xs == nil {
		return []ForwardPort{}
	}
	return xs
}
