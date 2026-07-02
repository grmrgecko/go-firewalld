package firewalld

// This file defines the concrete Go structs used for every compound D-Bus value
// firewalld exchanges. Encoding compound values as Go structs (not []any)
// is mandatory: godbus encodes a struct as a D-Bus struct/tuple "(...)", which is
// what firewalld's Python side requires. A []any would encode as "av" and
// firewalld rejects it with INVALID_TYPE. See CLAUDE.md for the full rationale.

// Port is a port-or-range with its protocol. Encodes to the D-Bus tuple "(ss)".
type Port struct {
	Port     string // single port "80" or range "1000-2000"
	Protocol string // "tcp" | "udp" | "sctp" | "dccp"
}

// ForwardPort describes a port-forward rule. Encodes to the tuple "(ssss)" in the
// field order firewalld expects: port, protocol, toport, toaddr.
type ForwardPort struct {
	Port     string // incoming port or range
	Protocol string // "tcp" | "udp"
	ToPort   string // destination port; empty keeps the same port
	ToAddr   string // destination address; empty forwards locally
}

// Target is a zone's default packet policy for unmatched traffic.
type Target string

const (
	TargetDefault Target = "default"
	TargetACCEPT  Target = "ACCEPT"
	TargetDROP    Target = "DROP"
	TargetReject  Target = "%%REJECT%%"
)

// Family selects the IP family for ipsets, rich rules, and helpers.
type Family string

const (
	FamilyIPv4 Family = "inet"
	FamilyIPv6 Family = "inet6"
)
