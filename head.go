package kololog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
)

const (
	// HeadContext is the signing context of tree heads.
	HeadContext = "kolo-log/tree-head/v0"
	// RecordContext is the signing context of entry records.
	RecordContext = "kolo-log/record/v1"
	// KeyContext starts the hashed input of an entry key commitment.
	KeyContext = "kolo-log/key/v0"
)

var (
	// ErrInvalidHead is returned by [VerifyHead] for any rejected head; the errors below wrap it.
	ErrInvalidHead = errors.New("kololog: invalid head")
	// ErrBadHeadSignature is returned when a head is not signed by the given key or names another key.
	ErrBadHeadSignature error = &headError{"kololog: invalid head signature"}
	// ErrWrongLogID is returned when a correctly signed head belongs to another log.
	ErrWrongLogID error = &headError{"kololog: head belongs to another log"}
)

type headError struct{ msg string }

func (e *headError) Error() string { return e.msg }
func (e *headError) Unwrap() error { return ErrInvalidHead }

// Head is a signed statement of the size and root hash of a log, as sent over the network.
type Head struct {
	LogKey    ed25519.PublicKey
	LogID     LogID
	Size      uint64
	Root      [HashSize]byte
	Signature []byte
}

// VerifiedHead is a [Head] whose signature and log ID [VerifyHead] has checked.
// Only VerifyHead can build one; the zero value verifies nothing.
type VerifiedHead struct {
	head Head
}

// VerifyHead checks that h is signed by pub and belongs to the log logID.
// It never panics on untrusted input.
func VerifyHead(pub ed25519.PublicKey, logID LogID, h Head) (VerifiedHead, error) {
	// Authenticity first, so ErrWrongLogID always means a genuine head of another log.
	if !keysEqual(pub, h.LogKey) || !koloid.Verify(pub, HeadContext, h.signed(), h.Signature) {
		return VerifiedHead{}, ErrBadHeadSignature
	}
	if h.LogID != logID {
		return VerifiedHead{}, ErrWrongLogID
	}
	return VerifiedHead{head: h.clone()}, nil
}

// LogKey returns the public key that signed the head.
func (v VerifiedHead) LogKey() ed25519.PublicKey { return slices.Clone(v.head.LogKey) }

// LogID returns the ID of the log the head belongs to.
func (v VerifiedHead) LogID() LogID { return v.head.LogID }

// Size returns the number of entries in the tree.
func (v VerifiedHead) Size() uint64 { return v.head.Size }

// Root returns the root hash of the tree.
func (v VerifiedHead) Root() [HashSize]byte { return v.head.Root }

// Head returns a copy of the signed head, for sending it on.
func (v VerifiedHead) Head() Head { return v.head.clone() }

// valid reports whether v came from VerifyHead.
func (v VerifiedHead) valid() bool { return len(v.head.LogKey) == ed25519.PublicKeySize }

func (h Head) clone() Head {
	h.LogKey = slices.Clone(h.LogKey)
	h.Signature = slices.Clone(h.Signature)
	return h
}

// Encode returns the canonical encoding of h.
func (h Head) Encode() []byte {
	return append(h.signed(), h.Signature...)
}

// DecodeHead parses an encoding made by [Head.Encode].
func DecodeHead(b []byte) (Head, error) {
	d := kolocodec.NewDecoder(b)
	if err := readTag(d, HeadContext); err != nil {
		return Head{}, err
	}
	var h Head
	var err error
	if h.LogKey, err = d.Fixed(ed25519.PublicKeySize); err != nil {
		return Head{}, malformed(err)
	}
	if err := readArray(d, h.LogID[:]); err != nil {
		return Head{}, err
	}
	if h.Size, err = d.Uvarint(); err != nil {
		return Head{}, malformed(err)
	}
	if err := readArray(d, h.Root[:]); err != nil {
		return Head{}, err
	}
	if h.Signature, err = d.Fixed(ed25519.SignatureSize); err != nil {
		return Head{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return Head{}, malformed(err)
	}
	return h, nil
}

func (h Head) signed() []byte {
	var e kolocodec.Encoder
	e.PutString(HeadContext)
	e.PutFixed(h.LogKey)
	e.PutFixed(h.LogID[:])
	e.PutUvarint(h.Size)
	e.PutFixed(h.Root[:])
	return e.Bytes()
}

// Record is the signed public metadata of one entry; its encoding is the Merkle leaf.
type Record struct {
	LogKey      ed25519.PublicKey
	LogID       LogID
	Index       uint64
	Size        uint64         // padded ciphertext length in bytes
	ContentHash [HashSize]byte // BLAKE2b-256 of the ciphertext
	KeyCommit   [HashSize]byte // BLAKE2b-256 of KeyContext and the entry key, so one record opens to one plaintext only
	Signature   []byte
}

// VerifyRecord reports whether r is signed by pub and belongs to the log logID.
// It never panics on untrusted input.
func VerifyRecord(pub ed25519.PublicKey, logID LogID, r Record) bool {
	return keysEqual(pub, r.LogKey) && r.LogID == logID && koloid.Verify(pub, RecordContext, r.signed(), r.Signature)
}

// Encode returns the canonical encoding of r.
func (r Record) Encode() []byte {
	return append(r.signed(), r.Signature...)
}

// DecodeRecord parses an encoding made by [Record.Encode].
func DecodeRecord(b []byte) (Record, error) {
	d := kolocodec.NewDecoder(b)
	if err := readTag(d, RecordContext); err != nil {
		return Record{}, err
	}
	var r Record
	var err error
	if r.LogKey, err = d.Fixed(ed25519.PublicKeySize); err != nil {
		return Record{}, malformed(err)
	}
	if err := readArray(d, r.LogID[:]); err != nil {
		return Record{}, err
	}
	if r.Index, err = d.Uvarint(); err != nil {
		return Record{}, malformed(err)
	}
	if r.Size, err = d.Uvarint(); err != nil {
		return Record{}, malformed(err)
	}
	if err := readArray(d, r.ContentHash[:]); err != nil {
		return Record{}, err
	}
	if err := readArray(d, r.KeyCommit[:]); err != nil {
		return Record{}, err
	}
	if r.Signature, err = d.Fixed(ed25519.SignatureSize); err != nil {
		return Record{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return Record{}, malformed(err)
	}
	return r, nil
}

func (r Record) signed() []byte {
	var e kolocodec.Encoder
	e.PutString(RecordContext)
	e.PutFixed(r.LogKey)
	e.PutFixed(r.LogID[:])
	e.PutUvarint(r.Index)
	e.PutUvarint(r.Size)
	e.PutFixed(r.ContentHash[:])
	e.PutFixed(r.KeyCommit[:])
	return e.Bytes()
}

func readTag(d *kolocodec.Decoder, tag string) error {
	got, err := d.String(len(tag))
	if err != nil {
		return malformed(err)
	}
	if got != tag {
		return fmt.Errorf("%w: unknown tag", ErrMalformed)
	}
	return nil
}

func readArray(d *kolocodec.Decoder, dst []byte) error {
	b, err := d.Fixed(len(dst))
	if err != nil {
		return malformed(err)
	}
	copy(dst, b)
	return nil
}

func malformed(err error) error {
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

func keysEqual(a, b ed25519.PublicKey) bool {
	return len(a) == ed25519.PublicKeySize && bytes.Equal(a, b)
}
