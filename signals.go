package firewalld

import (
	"context"
	"strings"

	"github.com/godbus/dbus/v5"
)

// Signal is a firewalld D-Bus signal delivered to a watcher. Member is the short
// signal name (e.g. "Reloaded", "PortAdded"); Interface is the emitting interface;
// Body carries the signal's arguments in firewalld's declared order.
type Signal struct {
	Member    string
	Interface string
	Path      dbus.ObjectPath
	Body      []any
}

// signalInterfaces are the firewalld interfaces whose signals a watcher subscribes
// to. Matching by interface keeps unrelated bus traffic out of the channel.
var signalInterfaces = []string{
	ifaceMain, ifaceZone, ifaceIPSet, ifaceDirect, ifacePolicy, ifaceLockdown,
	ifaceConfig, ifaceConfigZone, ifaceConfigIPSet, ifaceConfigPolicy,
	ifaceConfigService, ifaceConfigICMP, ifaceConfigHelper, ifaceConfigDirect,
}

// WatchSignals subscribes to firewalld's signals and returns a channel of typed
// events. The subscription and channel are torn down when ctx is cancelled. The
// channel is buffered; a slow consumer that lets it fill will drop no earlier
// events but may block delivery of later ones until drained.
func (c *Conn) WatchSignals(ctx context.Context) (<-chan Signal, error) {
	for _, iface := range signalInterfaces {
		if err := c.conn.AddMatchSignal(dbus.WithMatchInterface(iface)); err != nil {
			return nil, err
		}
	}

	raw := make(chan *dbus.Signal, 64)
	c.conn.Signal(raw)

	out := make(chan Signal, 64)
	go func() {
		defer close(out)
		defer c.removeSignalMatches(raw)
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-raw:
				if !ok {
					return
				}
				iface, member := splitSignalName(sig.Name)
				// Ignore anything outside firewalld's namespace.
				if !strings.HasPrefix(iface, ifaceMain) {
					continue
				}
				ev := Signal{Member: member, Interface: iface, Path: sig.Path, Body: sig.Body}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// WatchReloaded returns a channel that receives an empty struct each time
// firewalld emits its Reloaded signal, a convenience for callers that only need to
// re-read state after a reload.
func (c *Conn) WatchReloaded(ctx context.Context) (<-chan struct{}, error) {
	signals, err := c.WatchSignals(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan struct{}, 4)
	go func() {
		defer close(out)
		for sig := range signals {
			if sig.Member == "Reloaded" {
				select {
				case out <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// removeSignalMatches unregisters the channel and drops the match rules added by
// WatchSignals. Best-effort: match removal errors are ignored during teardown.
func (c *Conn) removeSignalMatches(raw chan *dbus.Signal) {
	c.conn.RemoveSignal(raw)
	for _, iface := range signalInterfaces {
		_ = c.conn.RemoveMatchSignal(dbus.WithMatchInterface(iface))
	}
}

// splitSignalName splits a fully-qualified signal name "iface.Member" into its
// interface and member parts.
func splitSignalName(full string) (iface, member string) {
	i := strings.LastIndex(full, ".")
	if i < 0 {
		return "", full
	}
	return full[:i], full[i+1:]
}
