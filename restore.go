package kololog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrRestoreMismatch is returned by [Restore] when stored data does not match the signed head or records.
	ErrRestoreMismatch = errors.New("kololog: restored data does not match the signed head or records")
	// ErrRollback is returned by [Restore] when the snapshot is older than or forks from a trusted head, and by [Replica.Update]
	// for a head of the held history smaller than the verified one, or, unchecked, smaller than a pending target.
	ErrRollback = errors.New("kololog: snapshot or head is older than a known head or forks from it")
	// ErrKeyUnavailable is returned when an entry's ciphertext is present but its key is not in this log.
	ErrKeyUnavailable = errors.New("kololog: entry key not available")
)

// restoreHook runs after entry i of l is verified and kept; tests use it to change caller data at that point.
var restoreHook func(l *Log, i int)

// Entry is the stored form of one entry: its signed record, either its ciphertext or its delete marker, and its key when known.
// encoding/json leaves Key out; an encoder that ignores MarshalJSON, such as encoding/gob, writes the key in clear.
type Entry struct {
	Record     []byte   // Record.Encode() of the entry, exactly as hashed into the tree
	Ciphertext []byte   // nonce || sealed padded frame; nil after Delete
	Marker     []byte   // DeleteMarker.Encode() of a deleted entry; nil otherwise
	Key        EntryKey `json:"-"` // the entry key; nil when unknown or deleted
}

// EntryKey is the encryption key of one entry; formatted or logged on its own, or as a field fmt and slog can reach, it shows only as [redacted].
type EntryKey []byte

const redacted = "[redacted]"

// String returns [redacted].
func (EntryKey) String() string { return redacted }

// Format writes [redacted] for every verb, so no fmt verb prints the key.
func (EntryKey) Format(f fmt.State, _ rune) { fmt.Fprint(f, redacted) }

// LogValue returns [redacted].
func (EntryKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON returns "[redacted]"; send a key only in a binary encoding over a secure channel.
func (EntryKey) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Restore rebuilds a writable log from its persisted header and head and the entries in s, verifying all of it.
// It reads the head's entries from s once each in increasing order, checks them in parallel and keeps only their records;
// the error is the first bad entry in log order. A live entry without its key returns [ErrRestoreMismatch].
func Restore(id *koloid.Identity, header, head []byte, s Storage, opts ...Option) (*Log, error) {
	pub, err := identityKey(id)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrNoStorage
	}
	o, err := buildOptions(opts)
	if err != nil {
		return nil, err
	}
	if len(header) == 0 {
		return nil, ErrMissingHeader
	}
	lh, err := DecodeLogHeader(header)
	if err != nil {
		return nil, err
	}
	if err := VerifyLogHeader(pub, lh); err != nil {
		return nil, err
	}
	if lh.Encoding != o.encoding {
		return nil, fmt.Errorf("%w: header has %s, options have %s", ErrEncodingMismatch, lh.Encoding, o.encoding)
	}
	if lh.Keys != o.keys || lh.Epoch != o.epoch {
		return nil, fmt.Errorf("%w: header has %s keys at epoch %d, options have %s keys at epoch %d",
			ErrKeyModeMismatch, lh.Keys, lh.Epoch, o.keys, o.epoch)
	}
	h, err := DecodeHead(head)
	if err != nil {
		return nil, err
	}
	if _, err := VerifyHead(pub, lh.LogID, h); err != nil {
		return nil, err
	}
	l := &Log{id: id, pub: pub, logID: lh.LogID, header: lh, s: s}
	if _, err := l.grow(ErrRestoreMismatch, h.Size, nil, true); err != nil {
		return nil, err
	}
	if o.keys == DerivedKeys {
		if err := l.checkSecret(o.secret); err != nil {
			return nil, err
		}
	}
	if err := l.finishRestore(h, o); err != nil {
		if l.prk != nil {
			clear(l.prk.key()[:])
		}
		return nil, err
	}
	return l, nil
}

// checkSecret keeps the PRK of secret if it derives the key the newest record commits to; that commitment survives a delete.
// An empty log has no record to check it against.
func (l *Log) checkSecret(secret *EntrySecret) error {
	p, err := newPRK(secret)
	if err != nil {
		return err
	}
	if n := uint64(len(l.records)); n > 0 {
		k, err := p.entryKey(l.pub, l.logID, l.header.Epoch, n-1)
		if err != nil {
			clear(p.key()[:])
			return err
		}
		ok := merkle.Equal(entrycrypt.Commit(k[:]), l.records[n-1].keyCommit)
		clear(k[:])
		if !ok {
			clear(p.key()[:])
			return fmt.Errorf("%w: it does not derive the key of entry %d", ErrSecretMismatch, n-1)
		}
	}
	l.prk = p
	return nil
}

func (l *Log) finishRestore(h Head, o options) error {
	if !merkle.Equal(l.tree.Root(h.Size), h.Root) {
		return fmt.Errorf("%w: rebuilt root differs from the head", ErrRestoreMismatch)
	}
	for _, t := range o.trusted {
		if _, err := VerifyHead(l.pub, l.logID, t); err != nil {
			return err
		}
		if t.Size > h.Size || !merkle.Equal(l.tree.Root(t.Size), t.Root) {
			return ErrRollback
		}
	}
	return l.register(o.reservation)
}

// grow checks n entries from Len on, read from storage or else taken from entries, and appends their leaves and records; errors wrap base.
// For entries it returns the verified copies, to commit. On error it drops what it appended. It needs l.mu held, or l not shared yet.
// Stored entries are verified by several goroutines (see growStored), but the error is the lowest failing index, as if run in turn.
func (l *Log) grow(base error, n uint64, entries []Entry, fromStorage bool) ([]Entry, error) {
	if fromStorage && n >= 2 {
		return nil, l.growStored(base, n, verifyWorkers(n))
	}
	start := uint64(len(l.records))
	var kept []Entry
	for i := range n {
		index := start + i
		var in Entry
		if fromStorage {
			var err error
			if in, err = l.s.Entry(index); err != nil {
				l.truncate(start)
				return nil, storageReadError(base, index, err)
			}
		} else {
			in = entries[i]
		}
		var c checked
		var err error
		if fromStorage {
			c, err = l.checkStored(base, index, in)
		} else {
			c, err = checkEntry(base, l.pub, l.logID, index, in, true)
		}
		if err != nil {
			for _, e := range kept {
				clear(e.Key)
			}
			l.truncate(start)
			return nil, err
		}
		l.tree.Append(c.leaf)
		l.records = append(l.records, c.rec)
		if !fromStorage {
			kept = append(kept, c.entry)
		}
		if restoreHook != nil {
			restoreHook(l, int(index))
		}
	}
	return kept, nil
}

func storageReadError(base error, index uint64, err error) error {
	if errors.Is(err, ErrOutOfRange) {
		// The head covers this entry, so storage that has none lost it.
		return fmt.Errorf("%w: entry %d missing from storage", base, index)
	}
	return fmt.Errorf("kololog: entry %d: %w", index, err)
}

// checkStored verifies entry index as read from storage, clears the storage's copy of its key, and refuses a live entry
// of an own log that has no key. It reads only fields of l that never change, so goroutines may call it together.
func (l *Log) checkStored(base error, index uint64, in Entry) (checked, error) {
	c, err := checkEntry(base, l.pub, l.logID, index, in, false)
	clear(in.Key) // the storage's own copy
	if err == nil && !l.replica && c.rec.flags == 0 {
		err = fmt.Errorf("%w: entry %d: a live entry of an own log is stored without its key", base, index)
	}
	return c, err
}

// truncate drops every entry from index n on; it needs l.mu held.
func (l *Log) truncate(n uint64) {
	l.tree.Truncate(n)
	l.records = l.records[:n]
}

type checked struct {
	leaf  [HashSize]byte
	rec   recordCore
	entry Entry // the verified copy, when kept
}

// checkEntry verifies entry index against its signed record and returns its leaf hash and record; errors wrap base.
// With keep it copies in first and also returns the copy, so what is kept is exactly what was verified.
func checkEntry(base error, pub ed25519.PublicKey, logID LogID, index uint64, in Entry, keep bool) (checked, error) {
	fail := func(err error) (checked, error) {
		return checked{}, fmt.Errorf("%w: entry %d: %w", base, index, err)
	}
	e := Entry{Record: in.Record, Ciphertext: absent(in.Ciphertext), Marker: absent(in.Marker), Key: in.Key}
	if len(e.Key) == 0 {
		e.Key = nil
	}
	if keep {
		e = cloneEntry(e)
	}
	r, encoded, err := checkRecord(pub, logID, index, e.Record)
	if err == nil {
		err = checkParts(pub, logID, r, e)
	}
	if err == nil && e.Key != nil {
		var o opened
		if o, err = openKey(pub, logID, r, e.Ciphertext, e.Key); err == nil {
			clear(o.frame)
			clear(o.key[:])
		}
	}
	if err != nil {
		if keep {
			clear(e.Key)
		}
		return fail(err)
	}
	var flags uint8
	switch {
	case e.Marker != nil:
		flags = flagDeleted
	case e.Key != nil:
		flags = flagKeyed
	}
	c := checked{leaf: merkle.LeafHash(encoded), rec: compact(r, flags)}
	if keep {
		c.entry = e
	}
	return c, nil
}

// checkRecord decodes b and checks that it is the canonical signed record of entry index of the log; it also returns b's encoding.
func checkRecord(pub ed25519.PublicKey, logID LogID, index uint64, b []byte) (Record, []byte, error) {
	r, err := DecodeRecord(b)
	if err != nil {
		return Record{}, nil, err
	}
	encoded := r.Encode()
	switch {
	case !bytes.Equal(encoded, b):
		return Record{}, nil, errors.New("record is not canonical")
	case !VerifyRecord(pub, logID, r):
		return Record{}, nil, errors.New("record signature or log does not match")
	case r.Index != index:
		return Record{}, nil, fmt.Errorf("record has index %d", r.Index)
	}
	return r, encoded, nil
}

// checkParts checks e's ciphertext or delete marker, nil when absent, against its verified record r; openKey checks the key.
func checkParts(pub ed25519.PublicKey, logID LogID, r Record, e Entry) error {
	switch {
	case (e.Marker == nil) == (e.Ciphertext == nil):
		return errors.New("needs exactly one of a ciphertext or a delete marker")
	case e.Marker != nil && len(e.Key) > 0:
		return errors.New("a deleted entry has a key")
	}
	if e.Marker != nil {
		m, err := DecodeDeleteMarker(e.Marker)
		if err != nil {
			return err
		}
		if !VerifyDeleteMarker(pub, logID, r, m) {
			return errors.New("delete marker does not match the record")
		}
		return nil
	}
	if uint64(len(e.Ciphertext)) != r.Size {
		return errors.New("ciphertext size differs from the record")
	}
	if sum := blake2b.Sum256(e.Ciphertext); !merkle.Equal(sum, r.ContentHash) {
		return errors.New("ciphertext hash differs from the record")
	}
	return nil
}

// opened is an entry key that opened its ciphertext: the caller zeroes key and frame when done.
type opened struct {
	key         *[keySize]byte
	frame, data []byte
}

// openKey checks k against the record's key commitment, then that it opens ciphertext, and returns its own copy and the plaintext.
func openKey(pub ed25519.PublicKey, logID LogID, r Record, ciphertext, k []byte) (opened, error) {
	// Checked before decrypting: the cipher is not key-committing, so a second key could open the same ciphertext.
	if len(k) != keySize || !merkle.Equal(entrycrypt.Commit(k), r.KeyCommit) {
		return opened{}, errors.New("key does not match the record's key commitment")
	}
	key, aead, err := entrycrypt.FromKey(k)
	var f, data []byte
	if err == nil {
		f, data, err = entrycrypt.OpenFrame(aead, entryAD(pub, logID, r.Index), ciphertext)
	}
	if err != nil {
		if key != nil {
			clear(key[:])
		}
		return opened{}, errors.New("key does not open the ciphertext")
	}
	return opened{key: key, frame: f, data: data}, nil
}

// OpenEntry checks an entry received on its own against a verified head and the entry's inclusion proof in it, then returns its stored bytes as [Log.Get] does.
// Its record, ciphertext or marker, and key are checked by the same code as in [Replica.Update]. It returns [ErrInvalidHead] for a zero head,
// [ErrBadProof] for a proof that does not put the record in h, [ErrBadEntry] for a part that does not match the record,
// and, after those checks, [ErrDeleted] for an entry with a valid delete marker and [ErrKeyUnavailable] for one without its key.
func OpenEntry(h VerifiedHead, p InclusionProof, e Entry) ([]byte, error) {
	if !h.valid() {
		return nil, ErrInvalidHead
	}
	pub, logID := h.head.LogKey, h.head.LogID
	fail := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("%w: entry %d: %w", ErrBadEntry, p.Index, err)
	}
	e.Ciphertext, e.Marker = absent(e.Ciphertext), absent(e.Marker)
	r, encoded, err := checkRecord(pub, logID, p.Index, e.Record)
	if err != nil {
		return fail(err)
	}
	if p.Size != h.head.Size || !merkle.VerifyInclusion(merkle.LeafHash(encoded), p.Index, p.Size, p.Path, h.head.Root) {
		return nil, fmt.Errorf("%w: inclusion of entry %d in a head of size %d", ErrBadProof, p.Index, h.head.Size)
	}
	if err := checkParts(pub, logID, r, e); err != nil {
		return fail(err)
	}
	switch {
	case e.Marker != nil:
		return nil, ErrDeleted
	case len(e.Key) == 0:
		return nil, ErrKeyUnavailable
	}
	o, err := openKey(pub, logID, r, e.Ciphertext, e.Key)
	if err != nil {
		return fail(err)
	}
	clear(o.key[:])
	return o.data, nil
}

// absent treats nil and empty alike as absent.
func absent(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
