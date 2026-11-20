package kololog

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"
)

// ValueEncoding is how [Log.Append] encodes values and [Log.Read] decodes them.
type ValueEncoding uint8

const (
	// Bytes stores []byte values unchanged; it is the default.
	Bytes ValueEncoding = iota
	// UTF8 stores string values, which must be valid UTF-8.
	UTF8
	// JSON stores any value as its encoding/json form.
	JSON
)

var (
	// ErrWrongValueType is returned when a value or output does not match the log's value encoding.
	ErrWrongValueType = errors.New("kololog: wrong value type")
	// ErrInvalidUTF8 is returned by a UTF8 log for a string that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("kololog: invalid UTF-8")
	// ErrUnknownEncoding is returned for a value encoding other than Bytes, UTF8 or JSON.
	ErrUnknownEncoding = errors.New("kololog: unknown value encoding")
)

// String returns "bytes", "utf8" or "json".
func (e ValueEncoding) String() string {
	switch e {
	case Bytes:
		return "bytes"
	case UTF8:
		return "utf8"
	case JSON:
		return "json"
	}
	return fmt.Sprintf("ValueEncoding(%d)", uint8(e))
}

func (e ValueEncoding) valid() bool { return e <= JSON }

func parseEncoding(s string) (ValueEncoding, bool) {
	for e := Bytes; e <= JSON; e++ {
		if e.String() == s {
			return e, true
		}
	}
	return 0, false
}

// Option configures [New] and [Restore].
type Option func(*options)

type options struct {
	encoding    ValueEncoding
	keys        KeyMode
	secret      *EntrySecret // the copy WithDerivedKeys made
	epoch       uint64
	trusted     []Head
	reservation *reservation
}

// WithValueEncoding sets the value encoding of the log; the default is [Bytes].
func WithValueEncoding(e ValueEncoding) Option {
	return func(o *options) { o.encoding = e }
}

// WithTrustedHead makes [Restore] reject a snapshot that does not extend h; [New] ignores it.
// Every trusted head given is checked.
func WithTrustedHead(h Head) Option {
	h = h.clone()
	return func(o *options) { o.trusted = append(o.trusted, h) }
}

func buildOptions(opts []Option) (options, error) {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if !o.encoding.valid() {
		return o, fmt.Errorf("%w: %d", ErrUnknownEncoding, uint8(o.encoding))
	}
	if o.keys == DerivedKeys && o.secret == nil {
		return o, ErrMissingSecret
	}
	return o, nil
}

func wrongType(want string, got any) error {
	return fmt.Errorf("%w: want %s, got %T", ErrWrongValueType, want, got)
}

// encodeValue reports whether it made a copy, which the caller then clears after sealing.
func encodeValue(e ValueEncoding, v any) (data []byte, copied bool, err error) {
	switch e {
	case Bytes:
		b, ok := v.([]byte)
		if !ok {
			return nil, false, wrongType("[]byte", v)
		}
		return b, false, nil
	case UTF8:
		s, ok := v.(string)
		if !ok {
			return nil, false, wrongType("string", v)
		}
		if !utf8.ValidString(s) {
			return nil, false, ErrInvalidUTF8
		}
		return []byte(s), true, nil
	case JSON:
		b, err := json.Marshal(v)
		if err != nil {
			// The json error text can quote the value, so only the type is reported.
			return nil, false, fmt.Errorf("%w: JSON encode of %T failed", ErrWrongValueType, v)
		}
		return b, true, nil
	}
	return nil, false, ErrUnknownEncoding
}

func checkOut(e ValueEncoding, out any) error {
	switch e {
	case Bytes:
		if p, ok := out.(*[]byte); !ok || p == nil {
			return wrongType("*[]byte", out)
		}
	case UTF8:
		if p, ok := out.(*string); !ok || p == nil {
			return wrongType("*string", out)
		}
	case JSON:
		if rv := reflect.ValueOf(out); rv.Kind() != reflect.Pointer || rv.IsNil() {
			return wrongType("a non-nil pointer", out)
		}
	default:
		return ErrUnknownEncoding
	}
	return nil
}

// decodeFrame clears the plaintext frame unless out keeps it, as with Bytes.
func decodeFrame(e ValueEncoding, f, data []byte, out any) error {
	err := decodeValue(e, data, out)
	if e != Bytes {
		clear(f)
	}
	return err
}

// decodeValue expects out to have passed checkOut.
func decodeValue(e ValueEncoding, data []byte, out any) error {
	switch e {
	case Bytes:
		*out.(*[]byte) = data
	case UTF8:
		if !utf8.Valid(data) {
			return ErrInvalidUTF8
		}
		*out.(*string) = string(data)
	case JSON:
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: JSON decode into %T failed", ErrWrongValueType, out)
		}
	}
	return nil
}
