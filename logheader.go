package kololog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
)

// HeaderContext is the signing context of log headers.
const HeaderContext = "kolo-log/header/v0"

var (
	// ErrBadLogHeader is returned when a log header is not signed by the expected key.
	ErrBadLogHeader = errors.New("kololog: bad log header")
	// ErrMissingHeader is returned by [Restore] and [RestoreReplica] for a nil or empty header.
	ErrMissingHeader = errors.New("kololog: missing log header")
	// ErrEncodingMismatch is returned by [Restore] when the header's value encoding differs from the options.
	ErrEncodingMismatch = errors.New("kololog: value encoding mismatch")
)

// LogHeader is the signed description of a log, persisted next to its data by the storage layer.
// A header with [RandomKeys] and one with [DerivedKeys] have their own tag and signing context.
type LogHeader struct {
	LogKey    ed25519.PublicKey
	LogID     LogID
	Encoding  ValueEncoding
	Keys      KeyMode
	Epoch     uint64 // 0 with RandomKeys
	Signature []byte
}

// VerifyLogHeader returns [ErrBadLogHeader] unless h is signed by pub under the context of its key mode; it refuses an unknown
// key mode and a header with [RandomKeys] and a nonzero epoch. It never panics on untrusted input.
func VerifyLogHeader(pub ed25519.PublicKey, h LogHeader) error {
	if !keysEqual(pub, h.LogKey) || !h.Encoding.valid() || !h.Keys.valid() || (h.Keys == RandomKeys && h.Epoch != 0) ||
		!koloid.Verify(pub, h.context(), h.signed(), h.Signature) {
		return ErrBadLogHeader
	}
	return nil
}

// context is the tag and signing context of h's form.
func (h LogHeader) context() string {
	if h.Keys == DerivedKeys {
		return DerivedHeaderContext
	}
	return HeaderContext
}

// Encode returns the canonical encoding of h.
func (h LogHeader) Encode() []byte {
	return append(h.signed(), h.Signature...)
}

// DecodeLogHeader parses an encoding made by [LogHeader.Encode].
func DecodeLogHeader(b []byte) (LogHeader, error) {
	d := kolocodec.NewDecoder(b)
	// One read of at most the longer tag, so either form decodes and a tag of any other length is malformed.
	tag, err := d.String(len(DerivedHeaderContext))
	if err != nil {
		return LogHeader{}, malformed(err)
	}
	var h LogHeader
	switch tag {
	case HeaderContext:
	case DerivedHeaderContext:
		h.Keys = DerivedKeys
	default:
		return LogHeader{}, fmt.Errorf("%w: unknown tag", ErrMalformed)
	}
	if h.LogKey, err = d.Fixed(ed25519.PublicKeySize); err != nil {
		return LogHeader{}, malformed(err)
	}
	if err := readArray(d, h.LogID[:]); err != nil {
		return LogHeader{}, err
	}
	e, err := d.Uvarint()
	if err != nil {
		return LogHeader{}, malformed(err)
	}
	if e > uint64(JSON) {
		return LogHeader{}, malformed(ErrUnknownEncoding)
	}
	h.Encoding = ValueEncoding(e)
	if h.Keys == DerivedKeys {
		if h.Epoch, err = d.Uvarint(); err != nil {
			return LogHeader{}, malformed(err)
		}
	}
	if h.Signature, err = d.Fixed(ed25519.SignatureSize); err != nil {
		return LogHeader{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return LogHeader{}, malformed(err)
	}
	return h, nil
}

func (h LogHeader) signed() []byte {
	var e kolocodec.Encoder
	e.PutString(h.context())
	e.PutFixed(h.LogKey)
	e.PutFixed(h.LogID[:])
	e.PutUvarint(uint64(h.Encoding))
	if h.Keys == DerivedKeys {
		e.PutUvarint(h.Epoch)
	}
	return e.Bytes()
}

func (h LogHeader) clone() LogHeader {
	h.LogKey = append(ed25519.PublicKey(nil), h.LogKey...)
	h.Signature = append([]byte(nil), h.Signature...)
	return h
}

// logHeaderJSON leaves keys and epoch out of a header with random keys, so its JSON is the four fields logKey, logId, encoding and signature.
type logHeaderJSON struct {
	LogKey    string `json:"logKey"`
	LogID     string `json:"logId"`
	Encoding  string `json:"encoding"`
	Keys      string `json:"keys,omitempty"`
	Epoch     string `json:"epoch,omitempty"`
	Signature string `json:"signature"`
}

// MarshalJSON encodes h as a JSON view; the binary encoding is the only one that is signed.
// A header with [DerivedKeys] adds "keys": "derived" and "epoch".
func (h LogHeader) MarshalJSON() ([]byte, error) {
	if !h.Encoding.valid() {
		return nil, ErrUnknownEncoding
	}
	v := logHeaderJSON{
		LogKey:    hex.EncodeToString(h.LogKey),
		LogID:     h.LogID.String(),
		Encoding:  h.Encoding.String(),
		Signature: hex.EncodeToString(h.Signature),
	}
	switch {
	case h.Keys == DerivedKeys:
		v.Keys, v.Epoch = h.Keys.String(), strconv.FormatUint(h.Epoch, 10)
	case h.Keys != RandomKeys:
		return nil, fmt.Errorf("%w: unknown key mode %d", ErrMalformed, uint8(h.Keys))
	case h.Epoch != 0:
		return nil, fmt.Errorf("%w: a header with random keys has epoch %d", ErrMalformed, h.Epoch)
	}
	return json.Marshal(v)
}

// UnmarshalJSON strictly decodes the view made by [LogHeader.MarshalJSON]: the four fields of a header with random keys,
// or those and both "keys": "derived" and "epoch".
func (h *LogHeader) UnmarshalJSON(b []byte) error {
	f, err := readObjectWith(b, []string{"logKey", "logId", "encoding", "signature"}, "keys", "epoch")
	if err != nil {
		return err
	}
	var out LogHeader
	keys, hasKeys := f["keys"]
	epoch, hasEpoch := f["epoch"]
	if hasKeys != hasEpoch {
		return malformedJSON("keys and epoch go together")
	}
	if hasKeys {
		name, err := stringField(keys, "keys")
		if err != nil {
			return err
		}
		if name != DerivedKeys.String() {
			return malformedJSON("keys is not derived")
		}
		out.Keys = DerivedKeys
		if out.Epoch, err = uintField(epoch, "epoch"); err != nil {
			return err
		}
	}
	if out.LogKey, err = hexField(f["logKey"], "logKey", ed25519.PublicKeySize); err != nil {
		return err
	}
	if err := hexArray(f["logId"], "logId", out.LogID[:]); err != nil {
		return err
	}
	name, err := stringField(f["encoding"], "encoding")
	if err != nil {
		return err
	}
	var ok bool
	if out.Encoding, ok = parseEncoding(name); !ok {
		return malformedJSON("unknown encoding")
	}
	if out.Signature, err = hexField(f["signature"], "signature", ed25519.SignatureSize); err != nil {
		return err
	}
	*h = out
	return nil
}

// String returns a short summary of h.
func (h LogHeader) String() string {
	if h.Keys == RandomKeys && h.Epoch == 0 {
		return fmt.Sprintf("kololog.LogHeader{log=%s, encoding=%s}", abbrev(h.LogID[:]), h.Encoding)
	}
	return fmt.Sprintf("kololog.LogHeader{log=%s, encoding=%s, keys=%s, epoch=%d}", abbrev(h.LogID[:]), h.Encoding, h.Keys, h.Epoch)
}

// LogValue returns h as a slog group with full hex values.
func (h LogHeader) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("logKey", hex.EncodeToString(h.LogKey)),
		slog.String("logId", h.LogID.String()),
		slog.String("encoding", h.Encoding.String()),
	}
	if h.Keys != RandomKeys || h.Epoch != 0 {
		attrs = append(attrs, slog.String("keys", h.Keys.String()), slog.Uint64("epoch", h.Epoch))
	}
	return slog.GroupValue(append(attrs, slog.String("signature", hex.EncodeToString(h.Signature)))...)
}
