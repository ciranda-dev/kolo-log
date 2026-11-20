package kololog

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

const (
	// DerivedHeaderContext is the signing context of the header of a log with [DerivedKeys].
	DerivedHeaderContext = "kolo-log/derived-header/v0"
	// EntryKeyContext starts the HKDF info of a derived entry key.
	EntryKeyContext = "kolo-log/entry-key/v0"
)

var (
	// ErrNotDerived is returned by [NewKeyDeriver] for a header with [RandomKeys].
	ErrNotDerived = errors.New("kololog: log does not use derived keys")
	// ErrKeyModeMismatch is returned by [Restore] when the header's key mode or epoch differs from the options.
	ErrKeyModeMismatch = errors.New("kololog: key mode mismatch")
	// ErrSecretMismatch is returned by [Restore] when the entry secret does not derive the newest entry's key.
	ErrSecretMismatch = errors.New("kololog: entry secret mismatch")
	// ErrMissingSecret is returned by [New], [Restore] and [NewKeyDeriver] for a nil entry secret.
	ErrMissingSecret = errors.New("kololog: missing entry secret")
	// ErrDeriverClosed is returned by [KeyDeriver.Key] after [KeyDeriver.Close].
	ErrDeriverClosed = errors.New("kololog: key deriver closed")
)

// KeyMode is how a log makes its entry keys.
type KeyMode uint8

const (
	// RandomKeys gives every entry a fresh random key that only the writer holds; it is the default.
	RandomKeys KeyMode = iota
	// DerivedKeys derives every entry key from an [EntrySecret], the log and the entry's index.
	DerivedKeys
)

// String returns "random" or "derived".
func (m KeyMode) String() string {
	switch m {
	case RandomKeys:
		return "random"
	case DerivedKeys:
		return "derived"
	}
	return fmt.Sprintf("KeyMode(%d)", uint8(m))
}

func (m KeyMode) valid() bool { return m <= DerivedKeys }

// EntrySecretSize is the size in bytes of an [EntrySecret].
const EntrySecretSize = 32

// EntrySecret is the group secret of a log with [DerivedKeys]: 32 uniformly random bytes used for nothing else.
// A guessable secret can be found offline from any record, because a record's KeyCommit is public.
// Every copy of the array is another copy of the secret. fmt, slog and JSON show it as [redacted], but it prints raw
// inside an unexported struct field (by value or behind one pointer), with %p of a value, and in encoding/gob.
type EntrySecret [EntrySecretSize]byte

// String returns [redacted].
func (EntrySecret) String() string { return redacted }

// GoString returns [redacted].
func (EntrySecret) GoString() string { return redacted }

// Format writes [redacted] for every verb.
func (EntrySecret) Format(f fmt.State, _ rune) { fmt.Fprint(f, redacted) }

// LogValue returns [redacted].
func (EntrySecret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON returns "[redacted]".
func (EntrySecret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// WithDerivedKeys makes [New] derive entry keys from secret under epoch, and makes [Restore] require a log that does.
// It copies secret when called; the copy lives as long as the Option. A nil secret makes New and Restore return [ErrMissingSecret].
func WithDerivedKeys(secret *EntrySecret, epoch uint64) Option {
	var s *EntrySecret
	if secret != nil {
		s = new(EntrySecret)
		*s = *secret
	}
	return func(o *options) { o.keys, o.secret, o.epoch = DerivedKeys, s, epoch }
}

// prk is the HKDF pseudorandom key of one secret. Its bytes live only in a closure: fmt on its bad-verb path (such as %s on a
// pointer) prints a pointer's target and calls no method, and dumpers that bypass methods read unexported fields, but neither
// can enter a function.
type prk struct{ key func() *[sha256.Size]byte }

func (prk) String() string             { return redacted }
func (prk) GoString() string           { return redacted }
func (prk) Format(f fmt.State, _ rune) { fmt.Fprint(f, redacted) }
func (prk) LogValue() slog.Value       { return slog.StringValue(redacted) }

// hkdfExtract and hkdfExpand are HKDF-SHA256 (RFC 5869) from the standard library.
func hkdfExtract(ikm, salt []byte) ([]byte, error) { return hkdf.Extract(sha256.New, ikm, salt) }

func hkdfExpand(prk, info []byte, n int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(info), n)
}

// newPRK runs HKDF-Extract once per log, with an empty salt (RFC 5869, 2.2: 32 zero bytes).
func newPRK(secret *EntrySecret) (*prk, error) {
	b, err := hkdfExtract(secret[:], nil)
	if err != nil {
		return nil, fmt.Errorf("kololog: derive: %w", err)
	}
	k := new([sha256.Size]byte)
	copy(k[:], b)
	clear(b)
	return &prk{key: func() *[sha256.Size]byte { return k }}, nil
}

// keyInfo is the HKDF info of an entry key; the length-prefixed context and the fixed-size keys keep it unambiguous.
func keyInfo(logKey ed25519.PublicKey, logID LogID, epoch, index uint64) []byte {
	var e kolocodec.Encoder
	e.PutString(EntryKeyContext)
	e.PutFixed(logKey)
	e.PutFixed(logID[:])
	e.PutUvarint(epoch)
	e.PutUvarint(index)
	return e.Bytes()
}

// entryKey derives the key of entry index of a log; the caller clears it.
func (p *prk) entryKey(logKey ed25519.PublicKey, logID LogID, epoch, index uint64) (*[keySize]byte, error) {
	b, err := hkdfExpand(p.key()[:], keyInfo(logKey, logID, epoch, index), keySize)
	if err != nil {
		return nil, fmt.Errorf("kololog: derive: %w", err)
	}
	k := new([keySize]byte)
	copy(k[:], b)
	clear(b)
	return k, nil
}

// KeyDeriver derives the entry keys of one log with [DerivedKeys]; it is safe for concurrent use.
// fmt and slog show a *KeyDeriver as [redacted]; a KeyDeriver value prints its log key, log ID and epoch, never the PRK.
type KeyDeriver struct {
	mu     sync.RWMutex
	prk    *prk // nil after Close
	logKey ed25519.PublicKey
	logID  LogID
	epoch  uint64
}

// NewKeyDeriver checks h with [VerifyLogHeader](owner, h) and returns its deriver, or [ErrNotDerived] for a header with [RandomKeys].
func NewKeyDeriver(secret *EntrySecret, owner ed25519.PublicKey, h LogHeader) (*KeyDeriver, error) {
	if secret == nil {
		return nil, ErrMissingSecret
	}
	if err := VerifyLogHeader(owner, h); err != nil {
		return nil, err
	}
	if h.Keys != DerivedKeys {
		return nil, ErrNotDerived
	}
	p, err := newPRK(secret)
	if err != nil {
		return nil, err
	}
	return &KeyDeriver{prk: p, logKey: slices.Clone(h.LogKey), logID: h.LogID, epoch: h.Epoch}, nil
}

// Key returns the key of entry index, or [ErrDeriverClosed] after Close; the caller should clear it.
func (d *KeyDeriver) Key(index uint64) (EntryKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.prk == nil {
		return nil, ErrDeriverClosed
	}
	k, err := d.prk.entryKey(d.logKey, d.logID, d.epoch, index)
	if err != nil {
		return nil, err
	}
	return k[:], nil
}

// Close clears the PRK; Key calls that hold the read lock finish first. HMAC's own copies stay in memory until the runtime reuses them.
func (d *KeyDeriver) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prk != nil {
		clear(d.prk.key()[:])
		d.prk = nil
	}
}

// String returns [redacted].
func (*KeyDeriver) String() string { return redacted }

// GoString returns [redacted].
func (*KeyDeriver) GoString() string { return redacted }

// Format writes [redacted] for every verb.
func (*KeyDeriver) Format(f fmt.State, _ rune) { fmt.Fprint(f, redacted) }

// LogValue returns [redacted].
func (*KeyDeriver) LogValue() slog.Value { return slog.StringValue(redacted) }
