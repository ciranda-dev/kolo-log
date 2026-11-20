// Package entrycrypt frames, pads (Padmé) and encrypts log entries with XChaCha20-Poly1305 under per-entry keys.
package entrycrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math"
	"math/bits"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// Errors that kololog maps to its own exported errors.
var (
	// ErrAuth means the key, nonce or associated data does not open the ciphertext, or the key has the wrong size.
	ErrAuth = errors.New("entrycrypt: authentication failed")
	// ErrFrame means the decrypted frame is not the exact output of Frame.
	ErrFrame = errors.New("entrycrypt: bad length or padding")
	// ErrTooLarge means the entry pads to a frame over FrameLimit.
	ErrTooLarge = errors.New("entrycrypt: entry too large")
)

const (
	// KeySize is the size of a per-entry key.
	KeySize = chacha20poly1305.KeySize
	// MinFrame hides the exact size of short entries.
	MinFrame = 256
	// MaxFrame is the XChaCha20-Poly1305 limit; Seal panics above it.
	MaxFrame = 1<<38 - 64
	// SealOverhead is the nonce and tag around a frame.
	SealOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	// FrameLimit is MaxFrame, or on 32-bit a quarter of an int so Append's three buffers fit the address space.
	FrameLimit = min(MaxFrame, (math.MaxInt-SealOverhead)/4)
)

// entryTag starts the associated data of every entry ciphertext.
const entryTag = "kolo-log/entry/v0"

// keyTag starts the hashed input of a key commitment; kololog exports it as KeyContext.
const keyTag = "kolo-log/key/v0"

// CheckSize returns ErrTooLarge if n bytes of data would pad to a frame over FrameLimit.
func CheckSize(n uint64) error {
	if n > FrameLimit { // also keeps the sum below from overflowing
		return ErrTooLarge
	}
	var e kolocodec.Encoder
	e.PutUvarint(n)
	if FrameLen(uint64(len(e.Bytes()))+n) > FrameLimit {
		return ErrTooLarge
	}
	return nil
}

// NewKey returns a fresh random key and the entry's only cipher, so there is one key copy to manage.
func NewKey() (*[KeySize]byte, cipher.AEAD, error) {
	key := new([KeySize]byte)
	if _, err := rand.Read(key[:]); err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		clear(key[:])
		return nil, nil, err
	}
	return key, aead, nil
}

// FromKey copies a stored key and returns its cipher; it returns ErrAuth for a key of the wrong size.
func FromKey(k []byte) (*[KeySize]byte, cipher.AEAD, error) {
	if len(k) != KeySize {
		return nil, nil, ErrAuth
	}
	key := new([KeySize]byte)
	copy(key[:], k)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		clear(key[:])
		return nil, nil, err
	}
	return key, aead, nil
}

// Commit returns the BLAKE2b-256 commitment to a key that a signed record carries.
// XChaCha20-Poly1305 is not key-committing, so without it one ciphertext could open under two keys to two plaintexts.
func Commit(key []byte) [32]byte {
	var e kolocodec.Encoder
	e.PutString(keyTag)
	e.PutFixed(key)
	b := e.Bytes()
	defer clear(b)
	return blake2b.Sum256(b)
}

// AD binds a ciphertext to its log key, log ID and index.
func AD(logKey []byte, logID [32]byte, index uint64) []byte {
	var e kolocodec.Encoder
	e.PutString(entryTag)
	e.PutFixed(logKey)
	e.PutFixed(logID[:])
	e.PutUvarint(index)
	return e.Bytes()
}

// Padme is the Padmé length from Nikitin et al., PURBs (2019).
func Padme(n uint64) uint64 {
	if n < 2 {
		return n
	}
	e := uint64(bits.Len64(n) - 1) // floor(log2 n)
	s := uint64(bits.Len64(e))     // floor(log2 e) + 1
	mask := uint64(1)<<(e-s) - 1
	return (n + mask) &^ mask
}

// FrameLen returns the padded length of a frame whose header and data take n bytes.
func FrameLen(n uint64) uint64 {
	return max(MinFrame, Padme(n))
}

// Frame returns uvarint(len(data)) || data || zero padding up to FrameLen.
func Frame(data []byte) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(uint64(len(data)))
	hdr := e.Bytes()
	out := make([]byte, FrameLen(uint64(len(hdr))+uint64(len(data))))
	copy(out[copy(out, hdr):], data)
	return out
}

// Unframe accepts only the exact output of Frame, so frames are canonical.
func Unframe(f []byte) ([]byte, error) {
	n, err := kolocodec.NewDecoder(f).Uvarint()
	if err != nil {
		return nil, ErrFrame
	}
	var e kolocodec.Encoder
	e.PutUvarint(n)
	hdr := uint64(len(e.Bytes()))
	if n > uint64(len(f))-hdr || uint64(len(f)) != FrameLen(hdr+n) {
		return nil, ErrFrame
	}
	end := hdr + n
	var nonzero byte
	for _, b := range f[end:] {
		nonzero |= b
	}
	if nonzero != 0 {
		return nil, ErrFrame
	}
	return f[hdr:end:end], nil
}

// Seal frames data and encrypts it under a random nonce, returning nonce || ciphertext.
func Seal(aead cipher.AEAD, ad, data []byte) ([]byte, error) {
	f := Frame(data)
	defer clear(f)
	return SealFrame(aead, ad, f)
}

// SealFrame encrypts an already built frame under a random nonce.
func SealFrame(aead cipher.AEAD, ad, f []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(f)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, f, ad), nil
}

// Open reverses Seal and returns the data.
func Open(aead cipher.AEAD, ad, sealed []byte) ([]byte, error) {
	_, data, err := OpenFrame(aead, ad, sealed)
	return data, err
}

// OpenFrame also returns the whole decrypted frame, so the caller can clear it.
func OpenFrame(aead cipher.AEAD, ad, sealed []byte) (f, data []byte, err error) {
	n := aead.NonceSize()
	if len(sealed) < n+aead.Overhead() {
		return nil, nil, ErrAuth
	}
	f, err = aead.Open(nil, sealed[:n], sealed[n:], ad)
	if err != nil {
		return nil, nil, ErrAuth
	}
	if data, err = Unframe(f); err != nil {
		clear(f)
		return nil, nil, err
	}
	return f, data, nil
}
