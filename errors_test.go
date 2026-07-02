package firewalld

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

// makeException builds a dbus.Error shaped like a firewalld exception with the
// given message body.
func makeException(msg string) dbus.Error {
	return dbus.Error{Name: exceptionName, Body: []any{msg}}
}

func TestMapErrorSentinels(t *testing.T) {
	cases := []struct {
		msg  string
		want error
	}{
		{"ALREADY_ENABLED", ErrAlreadyEnabled},
		{"NOT_ENABLED", ErrNotEnabled},
		{"INVALID_ZONE: 'bogus'", ErrInvalidZone},
		{"INVALID_PORT: '99999'", ErrInvalidPort},
		{"INVALID_ICMPTYPE: 'nope'", ErrInvalidICMPType},
		{"NAME_CONFLICT: 'dup'", ErrNameConflict},
		{"INVALID_IPSET: 'x'", ErrInvalidIPSet},
	}
	for _, tc := range cases {
		err := mapError(makeException(tc.msg))
		assert.ErrorIs(t, err, tc.want, "message %q", tc.msg)

		var fe *Error
		if assert.ErrorAs(t, err, &fe) {
			assert.Equal(t, tc.msg, fe.Message)
		}
	}
}

// TestMapErrorPassthrough leaves non-firewalld errors untouched.
func TestMapErrorPassthrough(t *testing.T) {
	assert.Nil(t, mapError(nil))

	plain := errors.New("connection reset")
	assert.Equal(t, plain, mapError(plain))

	// A D-Bus error that is not a firewalld exception passes through unchanged.
	other := dbus.Error{Name: "org.freedesktop.DBus.Error.NoReply", Body: []any{"timeout"}}
	assert.Equal(t, other, mapError(other))
}

// TestMapErrorUnknownCode maps an unrecognised firewalld code to a typed *Error
// with no sentinel, so errors.Is against a known sentinel is false but the code
// and message are preserved.
func TestMapErrorUnknownCode(t *testing.T) {
	err := mapError(makeException("SOMETHING_NEW: detail"))
	var fe *Error
	assert.ErrorAs(t, err, &fe)
	assert.Equal(t, "SOMETHING_NEW", fe.Code)
	assert.False(t, errors.Is(err, ErrInvalidZone))
}

func TestLeadingToken(t *testing.T) {
	assert.Equal(t, "INVALID_ZONE", leadingToken("INVALID_ZONE: 'x'"))
	assert.Equal(t, "ALREADY_ENABLED", leadingToken("ALREADY_ENABLED"))
	assert.Equal(t, "", leadingToken("Firewall is not running"))
	assert.Equal(t, "", leadingToken(""))
}

func TestPolicyDictSignature(t *testing.T) {
	s := PolicySettings{
		IngressZones: []string{"public"},
		EgressZones:  []string{"HOST"},
		Ports:        []Port{{Port: "80", Protocol: "tcp"}},
		ForwardPorts: []ForwardPort{{Port: "22", Protocol: "tcp"}},
		Priority:     -1,
	}
	d := s.toDict()
	assert.Equal(t, "a{sv}", sigOf(d))
	assert.Equal(t, "a(ss)", d["ports"].Signature().String())
	assert.Equal(t, "a(ssss)", d["forward_ports"].Signature().String())
	assert.Equal(t, "i", d["priority"].Signature().String())

	// Round-trip the dict back through the decoder.
	out := policySettingsFromDict(d)
	assert.Equal(t, s.IngressZones, out.IngressZones)
	assert.Equal(t, s.EgressZones, out.EgressZones)
	assert.Equal(t, s.Ports, out.Ports)
	assert.Equal(t, int32(-1), out.Priority)
}
