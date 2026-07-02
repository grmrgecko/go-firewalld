package firewalld

import (
	"reflect"

	"github.com/godbus/dbus/v5"
)

// This file holds the length-tolerant decode helpers shared by every settings
// decoder. Two facts make the coercion messy and force the tolerance here:
//
//  1. firewalld returns compound values either as a positional tuple (godbus hands
//     these back as []any) or as an a{sv} dict that OMITS unset keys.
//  2. Inside the dict, firewalld's Python side serializes port/forward-port lists
//     as "aav" (array of array of variant), NOT the "a(ss)"/"a(ssss)" tuple it
//     accepts on the way in. So a decoded port element may be []any{Variant,
//     Variant} rather than a clean string pair.
//
// Every helper therefore unwraps variants and reads through reflection so it
// tolerates []string, []any, [][]any, and []dbus.Variant interchangeably, and
// never indexes a fixed tuple offset without a bounds check.

// unwrap peels dbus.Variant wrappers off a decoded value, recursively, so callers
// see the underlying Go value regardless of how deeply firewalld boxed it.
func unwrap(v any) any {
	for {
		vr, ok := v.(dbus.Variant)
		if !ok {
			return v
		}
		v = vr.Value()
	}
}

// sliceElems returns the elements of any slice-shaped value as a []any, with each
// element unwrapped from a variant. It handles the whole zoo of concrete slice
// types godbus may produce (including nested [][]any) via reflection.
func sliceElems(v any) []any {
	v = unwrap(v)
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = unwrap(rv.Index(i).Interface())
	}
	return out
}

// tupleField returns element i of a decoded D-Bus tuple, or nil if the tuple is
// shorter than i+1. This is the guard that keeps a short EL7 tuple from panicking.
func tupleField(raw []any, i int) any {
	if i < 0 || i >= len(raw) {
		return nil
	}
	return raw[i]
}

// asString coerces a decoded value to a string, unwrapping variants first.
func asString(v any) string {
	s, _ := unwrap(v).(string)
	return s
}

// asBool coerces a decoded value to a bool, unwrapping variants first.
func asBool(v any) bool {
	b, _ := unwrap(v).(bool)
	return b
}

// asInt32 coerces a decoded integer value to int32, tolerating the several
// integer widths godbus may hand back.
func asInt32(v any) int32 {
	switch n := unwrap(v).(type) {
	case int32:
		return n
	case int:
		return int32(n)
	case int64:
		return int32(n)
	case uint32:
		return int32(n)
	default:
		return 0
	}
}

// asStrings coerces a decoded "as" value to []string.
func asStrings(v any) []string {
	els := sliceElems(v)
	if els == nil {
		return nil
	}
	out := make([]string, 0, len(els))
	for _, e := range els {
		out = append(out, asString(e))
	}
	return out
}

// pair extracts the first two string elements of a decoded "(ss)" tuple, however
// it was serialized (string pair or variant pair).
func pair(v any) (string, string) {
	els := sliceElems(v)
	var a, b string
	if len(els) > 0 {
		a = asString(els[0])
	}
	if len(els) > 1 {
		b = asString(els[1])
	}
	return a, b
}

// quad extracts the four string elements of a decoded "(ssss)" tuple.
func quad(v any) (string, string, string, string) {
	els := sliceElems(v)
	var a [4]string
	for i := 0; i < len(els) && i < 4; i++ {
		a[i] = asString(els[i])
	}
	return a[0], a[1], a[2], a[3]
}

// asPorts coerces a decoded "a(ss)" (or its "aav" dict form) to []Port.
func asPorts(v any) []Port {
	if ps, ok := v.([]Port); ok {
		return ps
	}
	els := sliceElems(v)
	if els == nil {
		return nil
	}
	out := make([]Port, 0, len(els))
	for _, e := range els {
		p, proto := pair(e)
		out = append(out, Port{Port: p, Protocol: proto})
	}
	return out
}

// asForwardPorts coerces a decoded "a(ssss)" (or "aav") value to []ForwardPort.
func asForwardPorts(v any) []ForwardPort {
	if fs, ok := v.([]ForwardPort); ok {
		return fs
	}
	els := sliceElems(v)
	if els == nil {
		return nil
	}
	out := make([]ForwardPort, 0, len(els))
	for _, e := range els {
		p, proto, toport, toaddr := quad(e)
		out = append(out, ForwardPort{Port: p, Protocol: proto, ToPort: toport, ToAddr: toaddr})
	}
	return out
}

// asStringMap coerces a decoded "a{ss}" value to map[string]string, unwrapping
// variant values (firewalld may hand back a{sv} in the dict forms).
func asStringMap(v any) map[string]string {
	switch m := unwrap(v).(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, e := range m {
			out[k] = asString(e)
		}
		return out
	case map[string]dbus.Variant:
		out := make(map[string]string, len(m))
		for k, e := range m {
			out[k] = asString(e)
		}
		return out
	default:
		return nil
	}
}

// dictValue reads key k from an a{sv} settings dict, returning the unwrapped value
// and whether it was present. A missing key means firewalld left the field at its
// default, so callers treat !ok as the zero value.
func dictValue(d map[string]dbus.Variant, k string) (any, bool) {
	v, ok := d[k]
	if !ok {
		return nil, false
	}
	return v.Value(), true
}
