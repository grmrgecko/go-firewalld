package firewalld

import "context"

// Direct is the entry point for firewalld's direct interface, which passes rules
// straight to the underlying iptables/nftables backend. It is a low-level escape
// hatch: firewalld does not manage or reconcile direct rules the way it does
// zones. All operations here are runtime (the direct interface has no per-element
// permanent methods; the permanent form is a single config.direct blob).
type Direct struct{ c *Conn }

// Direct returns the direct-interface namespace.
func (c *Conn) Direct() *Direct { return &Direct{c: c} }

// DirectChain is a custom chain added through the direct interface.
type DirectChain struct {
	IPV   string // "ipv4", "ipv6", or "eb" (ebtables)
	Table string // e.g. "filter", "nat"
	Chain string
}

// DirectRule is a rule added through the direct interface, including the chain it
// belongs to, its priority, and the raw backend arguments.
type DirectRule struct {
	IPV      string
	Table    string
	Chain    string
	Priority int32
	Args     []string
}

// AddChain adds a custom chain (ipv, table, chain).
func (d *Direct) AddChain(ctx context.Context, ch DirectChain) error {
	return d.c.call(ctx, basePath, ifaceDirect, "addChain", nil, ch.IPV, ch.Table, ch.Chain)
}

// RemoveChain removes a custom chain.
func (d *Direct) RemoveChain(ctx context.Context, ch DirectChain) error {
	return d.c.call(ctx, basePath, ifaceDirect, "removeChain", nil, ch.IPV, ch.Table, ch.Chain)
}

// QueryChain reports whether a custom chain exists.
func (d *Direct) QueryChain(ctx context.Context, ch DirectChain) (bool, error) {
	var ok bool
	err := d.c.call(ctx, basePath, ifaceDirect, "queryChain", []any{&ok}, ch.IPV, ch.Table, ch.Chain)
	return ok, err
}

// Chains lists the custom chains in a table for an IP family.
func (d *Direct) Chains(ctx context.Context, ipv, table string) ([]string, error) {
	var chains []string
	err := d.c.call(ctx, basePath, ifaceDirect, "getChains", []any{&chains}, ipv, table)
	return chains, err
}

// AllChains lists every custom chain across all families and tables.
func (d *Direct) AllChains(ctx context.Context) ([]DirectChain, error) {
	var raw [][]any
	if err := d.c.call(ctx, basePath, ifaceDirect, "getAllChains", []any{&raw}); err != nil {
		return nil, err
	}
	out := make([]DirectChain, 0, len(raw))
	for _, e := range raw {
		ipv, table, chain, _ := quad(e)
		out = append(out, DirectChain{IPV: ipv, Table: table, Chain: chain})
	}
	return out, nil
}

// AddRule adds a direct rule at the given priority.
func (d *Direct) AddRule(ctx context.Context, r DirectRule) error {
	return d.c.call(ctx, basePath, ifaceDirect, "addRule", nil, r.IPV, r.Table, r.Chain, r.Priority, r.Args)
}

// RemoveRule removes a direct rule matching the given fields exactly.
func (d *Direct) RemoveRule(ctx context.Context, r DirectRule) error {
	return d.c.call(ctx, basePath, ifaceDirect, "removeRule", nil, r.IPV, r.Table, r.Chain, r.Priority, r.Args)
}

// RemoveRules removes all direct rules in a chain.
func (d *Direct) RemoveRules(ctx context.Context, ipv, table, chain string) error {
	return d.c.call(ctx, basePath, ifaceDirect, "removeRules", nil, ipv, table, chain)
}

// QueryRule reports whether a direct rule is present.
func (d *Direct) QueryRule(ctx context.Context, r DirectRule) (bool, error) {
	var ok bool
	err := d.c.call(ctx, basePath, ifaceDirect, "queryRule", []any{&ok}, r.IPV, r.Table, r.Chain, r.Priority, r.Args)
	return ok, err
}

// Rules lists the rules in a chain as (priority, args) pairs. The IPV/Table/Chain
// on each returned rule are filled in from the query arguments.
func (d *Direct) Rules(ctx context.Context, ipv, table, chain string) ([]DirectRule, error) {
	var raw [][]any
	if err := d.c.call(ctx, basePath, ifaceDirect, "getRules", []any{&raw}, ipv, table, chain); err != nil {
		return nil, err
	}
	out := make([]DirectRule, 0, len(raw))
	for _, e := range raw {
		r := DirectRule{IPV: ipv, Table: table, Chain: chain}
		if len(e) >= 1 {
			r.Priority = asInt32(e[0])
		}
		if len(e) >= 2 {
			r.Args = asStrings(e[1])
		}
		out = append(out, r)
	}
	return out, nil
}

// AllRules lists every direct rule across all families, tables, and chains.
func (d *Direct) AllRules(ctx context.Context) ([]DirectRule, error) {
	var raw [][]any
	if err := d.c.call(ctx, basePath, ifaceDirect, "getAllRules", []any{&raw}); err != nil {
		return nil, err
	}
	out := make([]DirectRule, 0, len(raw))
	for _, e := range raw {
		var r DirectRule
		if len(e) >= 1 {
			r.IPV = asString(e[0])
		}
		if len(e) >= 2 {
			r.Table = asString(e[1])
		}
		if len(e) >= 3 {
			r.Chain = asString(e[2])
		}
		if len(e) >= 4 {
			r.Priority = asInt32(e[3])
		}
		if len(e) >= 5 {
			r.Args = asStrings(e[4])
		}
		out = append(out, r)
	}
	return out, nil
}

// Passthrough sends a raw command straight to the backend for an IP family and
// returns the backend's output.
func (d *Direct) Passthrough(ctx context.Context, ipv string, args []string) (string, error) {
	var out string
	err := d.c.call(ctx, basePath, ifaceDirect, "passthrough", []any{&out}, ipv, args)
	return out, err
}

// AddPassthrough persists a passthrough rule for an IP family.
func (d *Direct) AddPassthrough(ctx context.Context, ipv string, args []string) error {
	return d.c.call(ctx, basePath, ifaceDirect, "addPassthrough", nil, ipv, args)
}

// RemovePassthrough removes a passthrough rule.
func (d *Direct) RemovePassthrough(ctx context.Context, ipv string, args []string) error {
	return d.c.call(ctx, basePath, ifaceDirect, "removePassthrough", nil, ipv, args)
}

// QueryPassthrough reports whether a passthrough rule is present.
func (d *Direct) QueryPassthrough(ctx context.Context, ipv string, args []string) (bool, error) {
	var ok bool
	err := d.c.call(ctx, basePath, ifaceDirect, "queryPassthrough", []any{&ok}, ipv, args)
	return ok, err
}

// Passthroughs lists the passthrough rules for an IP family, each as an argv.
func (d *Direct) Passthroughs(ctx context.Context, ipv string) ([][]string, error) {
	var raw [][]string
	err := d.c.call(ctx, basePath, ifaceDirect, "getPassthroughs", []any{&raw}, ipv)
	return raw, err
}

// DirectPassthrough is a passthrough rule tagged with its IP family, as returned
// by AllPassthroughs.
type DirectPassthrough struct {
	IPV  string
	Args []string
}

// AllPassthroughs lists every passthrough rule across all IP families.
func (d *Direct) AllPassthroughs(ctx context.Context) ([]DirectPassthrough, error) {
	var raw [][]any
	if err := d.c.call(ctx, basePath, ifaceDirect, "getAllPassthroughs", []any{&raw}); err != nil {
		return nil, err
	}
	out := make([]DirectPassthrough, 0, len(raw))
	for _, e := range raw {
		var pt DirectPassthrough
		if len(e) >= 1 {
			pt.IPV = asString(e[0])
		}
		if len(e) >= 2 {
			pt.Args = asStrings(e[1])
		}
		out = append(out, pt)
	}
	return out, nil
}

// RemoveAllPassthroughs clears all passthrough rules.
func (d *Direct) RemoveAllPassthroughs(ctx context.Context) error {
	return d.c.call(ctx, basePath, ifaceDirect, "removeAllPassthroughs", nil)
}

// DirectConfig is the complete permanent direct configuration: all custom chains,
// rules, and passthroughs. It maps to the config.direct tuple
// "(a(sss)a(sssias)a(sas))".
type DirectConfig struct {
	Chains       []DirectChain
	Rules        []DirectRule
	Passthroughs []DirectPassthrough
}

// The concrete encoder structs for the permanent direct tuple. Field order is
// load-bearing and must match firewalld's signatures exactly.
type directChainTuple struct {
	IPV, Table, Chain string // (sss)
}
type directRuleTuple struct {
	IPV, Table, Chain string
	Priority          int32
	Args              []string // (sssias)
}
type directPassthroughTuple struct {
	IPV  string
	Args []string // (sas)
}
type directConfigTuple struct {
	Chains       []directChainTuple
	Rules        []directRuleTuple
	Passthroughs []directPassthroughTuple
}

func (c DirectConfig) toTuple() directConfigTuple {
	t := directConfigTuple{
		Chains:       make([]directChainTuple, 0, len(c.Chains)),
		Rules:        make([]directRuleTuple, 0, len(c.Rules)),
		Passthroughs: make([]directPassthroughTuple, 0, len(c.Passthroughs)),
	}
	for _, ch := range c.Chains {
		t.Chains = append(t.Chains, directChainTuple{ch.IPV, ch.Table, ch.Chain})
	}
	for _, r := range c.Rules {
		args := r.Args
		if args == nil {
			args = []string{}
		}
		t.Rules = append(t.Rules, directRuleTuple{r.IPV, r.Table, r.Chain, r.Priority, args})
	}
	for _, pt := range c.Passthroughs {
		args := pt.Args
		if args == nil {
			args = []string{}
		}
		t.Passthroughs = append(t.Passthroughs, directPassthroughTuple{pt.IPV, args})
	}
	return t
}

// directConfigFromTuple decodes the raw config.direct tuple, length-tolerant.
func directConfigFromTuple(raw []any) DirectConfig {
	var c DirectConfig
	for _, e := range sliceElems(tupleField(raw, 0)) {
		ipv, table, chain, _ := quad(e)
		c.Chains = append(c.Chains, DirectChain{IPV: ipv, Table: table, Chain: chain})
	}
	for _, e := range sliceElems(tupleField(raw, 1)) {
		els := sliceElems(e)
		var r DirectRule
		if len(els) >= 1 {
			r.IPV = asString(els[0])
		}
		if len(els) >= 2 {
			r.Table = asString(els[1])
		}
		if len(els) >= 3 {
			r.Chain = asString(els[2])
		}
		if len(els) >= 4 {
			r.Priority = asInt32(els[3])
		}
		if len(els) >= 5 {
			r.Args = asStrings(els[4])
		}
		c.Rules = append(c.Rules, r)
	}
	for _, e := range sliceElems(tupleField(raw, 2)) {
		els := sliceElems(e)
		var pt DirectPassthrough
		if len(els) >= 1 {
			pt.IPV = asString(els[0])
		}
		if len(els) >= 2 {
			pt.Args = asStrings(els[1])
		}
		c.Passthroughs = append(c.Passthroughs, pt)
	}
	return c
}

// Direct returns a handle for the permanent direct configuration.
func (p *Permanent) Direct() *PermDirect { return &PermDirect{c: p.c} }

// PermDirect reads and writes firewalld's permanent direct configuration as a
// single blob (the config.direct object), the permanent counterpart to the
// runtime Direct interface.
type PermDirect struct{ c *Conn }

// Settings reads the whole permanent direct configuration.
func (p *PermDirect) Settings(ctx context.Context) (DirectConfig, error) {
	var raw []any
	if err := p.c.call(ctx, configPath, ifaceConfigDirect, "getSettings", []any{&raw}); err != nil {
		return DirectConfig{}, err
	}
	return directConfigFromTuple(raw), nil
}

// Update replaces the whole permanent direct configuration.
func (p *PermDirect) Update(ctx context.Context, cfg DirectConfig) error {
	return p.c.call(ctx, configPath, ifaceConfigDirect, "update", nil, cfg.toTuple())
}
