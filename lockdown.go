package firewalld

import "context"

// Lockdown controls firewalld's lockdown feature and its whitelist. Lockdown, when
// enabled, restricts which applications may change the firewall; the whitelist
// names the commands, contexts, users, and uids that remain allowed. These live on
// the main object's .policies interface (distinct from zone-to-zone policies).
type Lockdown struct{ c *Conn }

// Lockdown returns the lockdown namespace.
func (c *Conn) Lockdown() *Lockdown { return &Lockdown{c: c} }

// Enable turns lockdown on.
func (l *Lockdown) Enable(ctx context.Context) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "enableLockdown", nil)
}

// Disable turns lockdown off.
func (l *Lockdown) Disable(ctx context.Context) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "disableLockdown", nil)
}

// Query reports whether lockdown is currently enabled.
func (l *Lockdown) Query(ctx context.Context) (bool, error) {
	var on bool
	err := l.c.call(ctx, basePath, ifaceLockdown, "queryLockdown", []any{&on})
	return on, err
}

// Whitelist command operations. A command entry may end in "*" to match a prefix.
func (l *Lockdown) AddCommand(ctx context.Context, command string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "addLockdownWhitelistCommand", nil, command)
}
func (l *Lockdown) RemoveCommand(ctx context.Context, command string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "removeLockdownWhitelistCommand", nil, command)
}
func (l *Lockdown) QueryCommand(ctx context.Context, command string) (bool, error) {
	var ok bool
	err := l.c.call(ctx, basePath, ifaceLockdown, "queryLockdownWhitelistCommand", []any{&ok}, command)
	return ok, err
}
func (l *Lockdown) Commands(ctx context.Context) ([]string, error) {
	var xs []string
	err := l.c.call(ctx, basePath, ifaceLockdown, "getLockdownWhitelistCommands", []any{&xs})
	return xs, err
}

// Whitelist context (SELinux) operations.
func (l *Lockdown) AddContext(ctx context.Context, selinuxContext string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "addLockdownWhitelistContext", nil, selinuxContext)
}
func (l *Lockdown) RemoveContext(ctx context.Context, selinuxContext string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "removeLockdownWhitelistContext", nil, selinuxContext)
}
func (l *Lockdown) QueryContext(ctx context.Context, selinuxContext string) (bool, error) {
	var ok bool
	err := l.c.call(ctx, basePath, ifaceLockdown, "queryLockdownWhitelistContext", []any{&ok}, selinuxContext)
	return ok, err
}
func (l *Lockdown) Contexts(ctx context.Context) ([]string, error) {
	var xs []string
	err := l.c.call(ctx, basePath, ifaceLockdown, "getLockdownWhitelistContexts", []any{&xs})
	return xs, err
}

// Whitelist user operations (by user name).
func (l *Lockdown) AddUser(ctx context.Context, user string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "addLockdownWhitelistUser", nil, user)
}
func (l *Lockdown) RemoveUser(ctx context.Context, user string) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "removeLockdownWhitelistUser", nil, user)
}
func (l *Lockdown) QueryUser(ctx context.Context, user string) (bool, error) {
	var ok bool
	err := l.c.call(ctx, basePath, ifaceLockdown, "queryLockdownWhitelistUser", []any{&ok}, user)
	return ok, err
}
func (l *Lockdown) Users(ctx context.Context) ([]string, error) {
	var xs []string
	err := l.c.call(ctx, basePath, ifaceLockdown, "getLockdownWhitelistUsers", []any{&xs})
	return xs, err
}

// Whitelist uid operations (by numeric uid).
func (l *Lockdown) AddUID(ctx context.Context, uid int32) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "addLockdownWhitelistUid", nil, uid)
}
func (l *Lockdown) RemoveUID(ctx context.Context, uid int32) error {
	return l.c.call(ctx, basePath, ifaceLockdown, "removeLockdownWhitelistUid", nil, uid)
}
func (l *Lockdown) QueryUID(ctx context.Context, uid int32) (bool, error) {
	var ok bool
	err := l.c.call(ctx, basePath, ifaceLockdown, "queryLockdownWhitelistUid", []any{&ok}, uid)
	return ok, err
}
func (l *Lockdown) UIDs(ctx context.Context) ([]int32, error) {
	var xs []int32
	err := l.c.call(ctx, basePath, ifaceLockdown, "getLockdownWhitelistUids", []any{&xs})
	return xs, err
}
