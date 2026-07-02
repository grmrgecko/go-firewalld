package firewalld

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// IPSetSettings is the transport-neutral representation of an ipset. It maps to
// the D-Bus tuple "(ssssa{ss}as)": version, name, description, type, options,
// entries. ipsets have no dict form; the tuple is used on every server.
type IPSetSettings struct {
	Version     string
	Name        string
	Description string
	Type        string            // e.g. "hash:ip", "hash:net"
	Options     map[string]string // e.g. {"family": "inet"}
	Entries     []string
}

// ipsetTuple is the concrete struct godbus encodes to "(ssssa{ss}as)". Field
// order matches firewalld's ipset settings tuple exactly.
type ipsetTuple struct {
	Version     string
	Name        string
	Description string
	Type        string
	Options     map[string]string
	Entries     []string
}

// toTuple builds the wire tuple, defaulting nil maps/slices to empty.
func (s *IPSetSettings) toTuple() ipsetTuple {
	opts := s.Options
	if opts == nil {
		opts = map[string]string{}
	}
	entries := s.Entries
	if entries == nil {
		entries = []string{}
	}
	return ipsetTuple{
		Version:     s.Version,
		Name:        s.Name,
		Description: s.Description,
		Type:        s.Type,
		Options:     opts,
		Entries:     entries,
	}
}

// ipsetSettingsFromTuple decodes a raw ipset tuple, length-tolerant throughout.
func ipsetSettingsFromTuple(raw []any) IPSetSettings {
	return IPSetSettings{
		Version:     asString(tupleField(raw, 0)),
		Name:        asString(tupleField(raw, 1)),
		Description: asString(tupleField(raw, 2)),
		Type:        asString(tupleField(raw, 3)),
		Options:     asStringMap(tupleField(raw, 4)),
		Entries:     asStrings(tupleField(raw, 5)),
	}
}

// IPSetNames lists the names of all permanent ipsets.
func (p *Permanent) IPSetNames(ctx context.Context) ([]string, error) {
	var names []string
	err := p.c.call(ctx, configPath, ifaceConfig, "getIPSetNames", []any{&names})
	return names, err
}

// AddIPSet creates a new permanent ipset from the given settings and returns its
// config object path.
func (p *Permanent) AddIPSet(ctx context.Context, name string, settings IPSetSettings) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "addIPSet", []any{&path}, name, settings.toTuple())
	return path, err
}

// IPSet returns a handle for permanent operations on the named ipset.
func (p *Permanent) IPSet(name string) *PermIPSet {
	return &PermIPSet{c: p.c, name: name}
}

// IPSets lists the names of ipsets known to the runtime.
func (r *Runtime) IPSets(ctx context.Context) ([]string, error) {
	var names []string
	err := r.c.call(ctx, basePath, ifaceIPSet, "getIPSets", []any{&names})
	return names, err
}

// IPSetExists reports whether an ipset of the given name exists at runtime.
func (r *Runtime) IPSetExists(ctx context.Context, name string) (bool, error) {
	var ok bool
	err := r.c.call(ctx, basePath, ifaceIPSet, "queryIPSet", []any{&ok}, name)
	return ok, err
}

// IPSetPaths lists the config object paths of all permanent ipsets (listIPSets).
func (p *Permanent) IPSetPaths(ctx context.Context) ([]dbus.ObjectPath, error) {
	var paths []dbus.ObjectPath
	err := p.c.call(ctx, configPath, ifaceConfig, "listIPSets", []any{&paths})
	return paths, err
}

// IPSet returns a handle for runtime operations on the named ipset.
func (r *Runtime) IPSet(name string) *RuntimeIPSet {
	return &RuntimeIPSet{c: r.c, name: name}
}

// RuntimeIPSet is a handle for transient ipset entry operations on the running
// firewall. ipset runtime methods live on the main object's .ipset interface.
type RuntimeIPSet struct {
	c    *Conn
	name string
}

// Settings reads the runtime settings of the ipset.
func (s *RuntimeIPSet) Settings(ctx context.Context) (IPSetSettings, error) {
	var raw []any
	if err := s.c.call(ctx, basePath, ifaceIPSet, "getIPSetSettings", []any{&raw}, s.name); err != nil {
		return IPSetSettings{}, err
	}
	return ipsetSettingsFromTuple(raw), nil
}

// AddEntry adds a single entry to the ipset at runtime.
func (s *RuntimeIPSet) AddEntry(ctx context.Context, entry string) error {
	return s.c.call(ctx, basePath, ifaceIPSet, "addEntry", nil, s.name, entry)
}

// RemoveEntry removes a single entry from the ipset at runtime.
func (s *RuntimeIPSet) RemoveEntry(ctx context.Context, entry string) error {
	return s.c.call(ctx, basePath, ifaceIPSet, "removeEntry", nil, s.name, entry)
}

// QueryEntry reports whether an entry is present at runtime.
func (s *RuntimeIPSet) QueryEntry(ctx context.Context, entry string) (bool, error) {
	var ok bool
	err := s.c.call(ctx, basePath, ifaceIPSet, "queryEntry", []any{&ok}, s.name, entry)
	return ok, err
}

// Entries returns all entries of the ipset at runtime.
func (s *RuntimeIPSet) Entries(ctx context.Context) ([]string, error) {
	var entries []string
	err := s.c.call(ctx, basePath, ifaceIPSet, "getEntries", []any{&entries}, s.name)
	return entries, err
}

// SetEntries replaces all entries of the ipset at runtime.
func (s *RuntimeIPSet) SetEntries(ctx context.Context, entries []string) error {
	if entries == nil {
		entries = []string{}
	}
	return s.c.call(ctx, basePath, ifaceIPSet, "setEntries", nil, s.name, entries)
}

// PermIPSet is a handle for permanent edits to a single ipset, operating on the
// ipset's config child object (/config/ipset/N).
type PermIPSet struct {
	c    *Conn
	name string
	path dbus.ObjectPath
}

// resolve looks up and caches the config object path for the ipset.
func (s *PermIPSet) resolve(ctx context.Context) (dbus.ObjectPath, error) {
	if s.path != "" {
		return s.path, nil
	}
	var path dbus.ObjectPath
	if err := s.c.call(ctx, configPath, ifaceConfig, "getIPSetByName", []any{&path}, s.name); err != nil {
		return "", err
	}
	s.path = path
	return path, nil
}

// callOn resolves the ipset path and invokes a config.ipset method.
func (s *PermIPSet) callOn(ctx context.Context, method string, rets []any, args ...any) error {
	path, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return s.c.call(ctx, path, ifaceConfigIPSet, method, rets, args...)
}

// Settings reads the ipset's permanent settings.
func (s *PermIPSet) Settings(ctx context.Context) (IPSetSettings, error) {
	var raw []any
	if err := s.callOn(ctx, "getSettings", []any{&raw}); err != nil {
		return IPSetSettings{}, err
	}
	return ipsetSettingsFromTuple(raw), nil
}

// Update replaces the ipset's permanent settings wholesale.
func (s *PermIPSet) Update(ctx context.Context, settings IPSetSettings) error {
	return s.callOn(ctx, "update", nil, settings.toTuple())
}

// AddEntry adds an entry to the permanent ipset.
func (s *PermIPSet) AddEntry(ctx context.Context, entry string) error {
	return s.callOn(ctx, "addEntry", nil, entry)
}

// RemoveEntry removes an entry from the permanent ipset.
func (s *PermIPSet) RemoveEntry(ctx context.Context, entry string) error {
	return s.callOn(ctx, "removeEntry", nil, entry)
}

// QueryEntry reports whether an entry is present in the permanent ipset.
func (s *PermIPSet) QueryEntry(ctx context.Context, entry string) (bool, error) {
	var ok bool
	err := s.callOn(ctx, "queryEntry", []any{&ok}, entry)
	return ok, err
}

// Entries returns all entries of the permanent ipset.
func (s *PermIPSet) Entries(ctx context.Context) ([]string, error) {
	var entries []string
	err := s.callOn(ctx, "getEntries", []any{&entries})
	return entries, err
}

// SetEntries replaces all entries of the permanent ipset.
func (s *PermIPSet) SetEntries(ctx context.Context, entries []string) error {
	if entries == nil {
		entries = []string{}
	}
	return s.callOn(ctx, "setEntries", nil, entries)
}

// AddOption sets an option (key/value) on the permanent ipset.
func (s *PermIPSet) AddOption(ctx context.Context, key, value string) error {
	return s.callOn(ctx, "addOption", nil, key, value)
}

// RemoveOption removes an option from the permanent ipset.
func (s *PermIPSet) RemoveOption(ctx context.Context, key string) error {
	return s.callOn(ctx, "removeOption", nil, key)
}

// SetDescription sets the permanent ipset description.
func (s *PermIPSet) SetDescription(ctx context.Context, description string) error {
	return s.callOn(ctx, "setDescription", nil, description)
}

// Remove deletes the ipset from the permanent configuration.
func (s *PermIPSet) Remove(ctx context.Context) error {
	return s.callOn(ctx, "remove", nil)
}
