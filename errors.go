package firewalld

import (
	"errors"
	"strings"

	"github.com/godbus/dbus/v5"
)

// exceptionName is the D-Bus error name firewalld raises for all of its domain
// errors. The specific condition (ALREADY_ENABLED, INVALID_ZONE, ...) arrives as
// the leading token of the error message, not as a distinct D-Bus name.
const exceptionName = "org.fedoraproject.FirewallD1.Exception"

// Sentinel errors mapped from firewalld exception messages. Callers match with
// errors.Is. ErrAlreadyEnabled/ErrNotEnabled are the idempotency signals: an
// add of something already present, or a remove of something absent.
var (
	ErrAlreadyEnabled   = errors.New("firewalld: already enabled")
	ErrNotEnabled       = errors.New("firewalld: not enabled")
	ErrInvalidZone      = errors.New("firewalld: invalid zone")
	ErrInvalidPort      = errors.New("firewalld: invalid port")
	ErrInvalidProtocol  = errors.New("firewalld: invalid protocol")
	ErrInvalidService   = errors.New("firewalld: invalid service")
	ErrInvalidICMPType  = errors.New("firewalld: invalid icmptype")
	ErrInvalidIPSet     = errors.New("firewalld: invalid ipset")
	ErrInvalidInterface = errors.New("firewalld: invalid interface")
	ErrInvalidSource    = errors.New("firewalld: invalid source")
	ErrInvalidPolicy    = errors.New("firewalld: invalid policy")
	ErrInvalidHelper    = errors.New("firewalld: invalid helper")
	ErrInvalidCommand   = errors.New("firewalld: invalid command")
	ErrNameConflict     = errors.New("firewalld: name conflict")
	ErrZoneConflict     = errors.New("firewalld: zone conflict")
	ErrBuiltinZone      = errors.New("firewalld: builtin zone")
	ErrAlreadySet       = errors.New("firewalld: already set")
	ErrMissingName      = errors.New("firewalld: missing name")
	ErrNotRunning       = errors.New("firewalld: not running")
	ErrNotApplicable    = errors.New("firewalld: not applicable")
	// ErrUnsupported is returned by this library (not firewalld) when a caller
	// asks for a feature the connected server's version does not provide.
	ErrUnsupported = errors.New("firewalld: operation not supported by this server version")
)

// exceptionMap keys the leading token of a firewalld exception message to a
// sentinel. Tokens are the firewalld INVALID_*/ALREADY_*/... error codes.
var exceptionMap = map[string]error{
	"ALREADY_ENABLED":   ErrAlreadyEnabled,
	"NOT_ENABLED":       ErrNotEnabled,
	"ZONE_ALREADY_SET":  ErrAlreadySet,
	"ALREADY_SET":       ErrAlreadySet,
	"INVALID_ZONE":      ErrInvalidZone,
	"INVALID_PORT":      ErrInvalidPort,
	"INVALID_PROTOCOL":  ErrInvalidProtocol,
	"INVALID_SERVICE":   ErrInvalidService,
	"INVALID_ICMPTYPE":  ErrInvalidICMPType,
	"INVALID_IPSET":     ErrInvalidIPSet,
	"INVALID_INTERFACE": ErrInvalidInterface,
	"INVALID_SOURCE":    ErrInvalidSource,
	"INVALID_POLICY":    ErrInvalidPolicy,
	"INVALID_HELPER":    ErrInvalidHelper,
	"INVALID_COMMAND":   ErrInvalidCommand,
	"NAME_CONFLICT":     ErrNameConflict,
	"ZONE_CONFLICT":     ErrZoneConflict,
	"BUILTIN_ZONE":      ErrBuiltinZone,
	"MISSING_NAME":      ErrMissingName,
	"NOT_RUNNING":       ErrNotRunning,
	"NOT_APPLICABLE":    ErrNotApplicable,
}

// Error wraps a firewalld D-Bus exception, preserving the raw code and message
// while chaining to a sentinel (via Unwrap) so errors.Is works. Errors that are
// not firewalld exceptions are returned unchanged by mapError.
type Error struct {
	Code     string // firewalld token, e.g. "INVALID_ZONE"; empty if none parsed
	Message  string // full exception message from firewalld
	sentinel error
}

// Error renders the underlying firewalld message.
func (e *Error) Error() string { return "firewalld: " + e.Message }

// Unwrap exposes the mapped sentinel so errors.Is matches (e.g. ErrInvalidZone).
func (e *Error) Unwrap() error { return e.sentinel }

// mapError converts a raw error from a D-Bus call into a typed *Error when it is a
// firewalld exception, chaining to the matching sentinel. Non-exception errors
// (transport failures, unknown names) are returned unchanged.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var derr dbus.Error
	if !errors.As(err, &derr) || derr.Name != exceptionName {
		return err
	}
	msg := dbusErrorMessage(derr)
	code := leadingToken(msg)
	return &Error{Code: code, Message: msg, sentinel: exceptionMap[code]}
}

// dbusErrorMessage extracts the string body of a firewalld D-Bus error, whose
// first body element is the human-readable message.
func dbusErrorMessage(derr dbus.Error) string {
	if len(derr.Body) > 0 {
		if s, ok := derr.Body[0].(string); ok {
			return s
		}
	}
	return derr.Error()
}

// leadingToken returns the leading UPPER_SNAKE code of a firewalld message, e.g.
// "INVALID_ZONE" from "INVALID_ZONE: 'bogus'". Returns "" when the message does
// not start with such a token.
func leadingToken(msg string) string {
	msg = strings.TrimSpace(msg)
	end := 0
	for end < len(msg) {
		c := msg[end]
		if (c >= 'A' && c <= 'Z') || c == '_' || (c >= '0' && c <= '9') {
			end++
			continue
		}
		break
	}
	token := msg[:end]
	// A real firewalld code is an all-caps run of two or more characters. This
	// rejects a stray leading capital from a plain-sentence error message; an
	// unmapped-but-well-formed token still round-trips harmlessly (sentinel nil).
	if len(token) < 2 {
		return ""
	}
	return token
}
