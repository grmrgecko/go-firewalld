# go-firewalld

[![Go Reference](https://pkg.go.dev/badge/github.com/grmrgecko/go-firewalld.svg)](https://pkg.go.dev/github.com/grmrgecko/go-firewalld)

A comprehensive Go client for the [firewalld](https://firewalld.org) D-Bus API,
built on [`github.com/godbus/dbus/v5`](https://github.com/godbus/dbus).

- **Runtime + permanent** operations, mirroring `firewall-cmd` (transient vs `--permanent`).
- **Version/capability aware:** one binary serves both old (EL7, firewalld 0.6.x)
  and new (EL9+, firewalld 1.x/2.x) servers. The dict (`a{sv}`) settings path and
  zone-to-zone policies are used where supported and transparently fall back to
  the v1 tuple path where they are not.
- **Typed, `errors.Is`-able errors** mapped from firewalld exceptions
  (`ErrAlreadyEnabled`, `ErrNotEnabled`, `ErrInvalidZone`, …).

## Install

```sh
go get github.com/grmrgecko/go-firewalld
```

## Usage

```go
ctx := context.Background()
conn, err := firewalld.Connect(ctx)
if err != nil {
	log.Fatal(err)
}
defer conn.Close()

fmt.Println(conn.Version())                      // e.g. "1.3.4"
fmt.Println(conn.Supports(firewalld.Policies))   // false on EL7, true on EL9+

// Permanent edits (apply after a reload).
zone := conn.Permanent().Zone("public")
if err := zone.AddPort(ctx, firewalld.Port{Port: "4242", Protocol: "udp"}); err != nil {
	if errors.Is(err, firewalld.ErrAlreadyEnabled) {
		// idempotent no-op
	} else {
		log.Fatal(err)
	}
}
_ = zone.SetTarget(ctx, firewalld.TargetDROP)
_ = conn.Reload(ctx)

// Read settings (transport chosen automatically by server capability).
s, _ := conn.Permanent().Zone("public").Settings(ctx)
fmt.Println(s.Services, s.Ports, s.Forward)

// Runtime (transient) edits, with an optional timeout.
_ = conn.Runtime().Zone("public").AddRichRule(ctx,
	`rule family="ipv4" source address="10.0.0.0/8" reject`, 30*time.Second)

// Low-level escape hatch for anything not yet wrapped.
var out []string
_ = conn.Call(ctx, "/org/fedoraproject/FirewallD1",
	"org.fedoraproject.FirewallD1.zone", "getZones", []any{&out})
```

## Coverage

| Area | Types / handles |
|---|---|
| Connection & lifecycle | `Connect`, `Open`, `Version`, `Supports`, `Reload`, `CompleteReload`, `RuntimeToPermanent`, `ResetToDefaults`, `CheckPermanentConfig`, panic mode, log-denied, default zone |
| Zones (permanent) | `Permanent().Zone(name)`: settings, update, add/remove/query for port/source/source-port/service/protocol/forward-port/masquerade/icmp-block/icmp-block-inversion/interface/rich-rule, target/short/description/version, rename, remove, load-defaults |
| Zones (runtime) | `Runtime().Zone(name)`: same element set with timeouts; change-interface/change-source (move between zones); active zones, zone-of-interface/source; wholesale `Runtime().SetSettings` (dict servers) |
| Config management | zone names/paths, add-zone, zone-of-interface/source |
| Daemon properties | `RuntimeInfo` (state, IPv4/IPv6/IPSet/bridge support, ipset & icmp types), `DaemonConfig` (backend, rp-filter, cleanup, …) get/set |
| IPSets | runtime + permanent: settings, entries, options, existence query |
| Services | list, read (tuple/dict), permanent editor incl. includes |
| ICMP types | list, read, permanent editor |
| Helpers (conntrack) | list, read, permanent editor |
| Policies (≥ 0.9) | runtime + permanent, capability-gated |
| Direct interface | runtime chains/rules/passthroughs + permanent direct config blob |
| Lockdown | enable/disable/query + whitelist (command/context/user/uid) |
| Signals | `WatchSignals`, `WatchReloaded` |

Deliberately omitted as redundant with `Settings()`/`Update()`: the per-field bulk
`setX` list-setters and scalar `getX` getters on config objects. Legacy/no-op
methods (`authorizeAll`, `isImmutable`, `*AutomaticHelpers`, the `changeZone`
alias) are also skipped.

## Testing

Unit tests need no bus and cover encode/decode round-trips plus
`dbus.SignatureOf` assertions for every compound type:

```sh
go test ./...
```

Integration tests run against a live firewalld and are gated behind a build tag.
They operate only on throwaway zones/ipsets/policies they create and remove, so a
failure cannot disturb the default zone or an SSH session. Build a test binary and
run it on the target host (no Go toolchain needed there):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go test -c -tags firewalld_integration -o firewalld.itest .
scp firewalld.itest root@host:/tmp/
ssh root@host '/tmp/firewalld.itest -test.v'
```

Verified against firewalld **0.6.3** (CentOS 7, iptables backend) and **1.3.4**
(Rocky 9, nftables backend); signature tests additionally cover **2.4.3**.
