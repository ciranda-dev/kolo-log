// Package strictjson decodes the strict JSON views of kololog types: exact keys, lowercase hex and canonical decimals.
// Its errors describe the field only; kololog wraps them with its ErrMalformed.
package strictjson

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

func fail(what string, err error) error {
	if err != nil {
		return fmt.Errorf("json %s: %v", what, err)
	}
	return errors.New("json " + what)
}

type decoder struct{ *json.Decoder }

func newDecoder(b []byte) decoder {
	return decoder{json.NewDecoder(bytes.NewReader(b))}
}

func (d decoder) end() error {
	if _, err := d.Token(); err != io.EOF {
		return fail("trailing data", nil)
	}
	return nil
}

// CheckRaw rejects input over max bytes and any backslash: no valid encoding has an escape, and escapes would allow many spellings of one value.
func CheckRaw(b []byte, max int) error {
	if len(b) > max {
		return fail("input too large", nil)
	}
	if bytes.IndexByte(b, '\\') >= 0 {
		return fail("escape sequence", nil)
	}
	return nil
}

// Value returns the single JSON value in b, named what in errors, with nothing after it.
func Value(b []byte, max int, what string) (json.RawMessage, error) {
	if err := CheckRaw(b, max); err != nil {
		return nil, err
	}
	dec := newDecoder(b)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fail(what, err)
	}
	if err := dec.end(); err != nil {
		return nil, err
	}
	return raw, nil
}

// Object returns the fields of the JSON object in b, which must have exactly keys, each once.
// It walks the tokens itself because encoding/json matches keys case-insensitively and lets a duplicate key overwrite the first.
func Object(b []byte, max int, keys ...string) (map[string]json.RawMessage, error) {
	return ObjectWith(b, max, keys, nil)
}

// ObjectWith is [Object] for an object that must have every key in keys and may have those in optional, each at most once.
func ObjectWith(b []byte, max int, keys, optional []string) (map[string]json.RawMessage, error) {
	if err := CheckRaw(b, max); err != nil {
		return nil, err
	}
	dec := newDecoder(b)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fail("expected an object", nil)
	}
	out := make(map[string]json.RawMessage, len(keys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fail("object", err)
		}
		key, _ := tok.(string)
		known := false
		for _, k := range keys {
			known = known || k == key
		}
		for _, k := range optional {
			known = known || k == key
		}
		if !known {
			return nil, fail("unknown field", nil)
		}
		if _, dup := out[key]; dup {
			return nil, fail("duplicate field "+key, nil)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fail(key, err)
		}
		out[key] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, fail("unterminated object", nil)
	}
	if err := dec.end(); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, fail("missing field "+k, nil)
		}
	}
	return out, nil
}

// String decodes a JSON string; null and other types are errors.
func String(raw json.RawMessage, name string) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' {
		return "", fail(name+" is not a string", nil)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fail(name, err)
	}
	return s, nil
}

// Hex accepts exactly n bytes as lowercase hex, since hex.DecodeString also takes uppercase.
func Hex(raw json.RawMessage, name string, n int) ([]byte, error) {
	s, err := String(raw, name)
	if err != nil {
		return nil, err
	}
	if len(s) != 2*n {
		return nil, fail(name+" has the wrong length", nil)
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, fail(name+" is not lowercase hex", nil)
		}
	}
	return hex.DecodeString(s)
}

// HexInto decodes exactly len(dst) bytes of lowercase hex into dst.
func HexInto(raw json.RawMessage, name string, dst []byte) error {
	b, err := Hex(raw, name, len(dst))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

// Uint decodes a uint64 written as a canonical decimal string.
func Uint(raw json.RawMessage, name string) (uint64, error) {
	s, err := String(raw, name)
	if err != nil {
		return 0, err
	}
	if s == "" || (s[0] == '0' && len(s) > 1) {
		return 0, fail(name+" is not canonical decimal", nil)
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fail(name+" is not canonical decimal", nil)
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fail(name+" does not fit in uint64", nil)
	}
	return v, nil
}

// Path decodes an array of at most max 32-byte hex hashes, counting before each allocation.
func Path(raw json.RawMessage, max int) ([][32]byte, error) {
	dec := newDecoder(raw)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, fail("path is not an array", nil)
	}
	var out [][32]byte
	for dec.More() {
		if len(out) == max {
			return nil, fail("path is too long", nil)
		}
		var item json.RawMessage
		if err := dec.Decode(&item); err != nil {
			return nil, fail("path", err)
		}
		var h [32]byte
		if err := HexInto(item, "path item", h[:]); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fail("path", err)
	}
	return out, nil
}
