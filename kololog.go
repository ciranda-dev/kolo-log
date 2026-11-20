package kololog

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrDeleted is returned by [Log.Get] for an entry whose key was destroyed by [Log.Delete].
	ErrDeleted = errors.New("kololog: entry deleted")
	// ErrOutOfRange is returned for an index or tree size the log does not have.
	ErrOutOfRange = errors.New("kololog: index out of range")
	// ErrMalformed is returned when an encoding cannot be parsed.
	ErrMalformed = errors.New("kololog: malformed encoding")
)

// LogIDSize is the size in bytes of a log ID.
const LogIDSize = 32

// LogID is the random ID that separates logs under the same identity.
type LogID [LogIDSize]byte

// Log is a signed append-only log owned by one writer; it is safe for concurrent use.
// It keeps its tree hashes and a compact copy of each record in memory, and its entries in its [Storage].
type Log struct {
	mu      sync.RWMutex
	id      *koloid.Identity
	pub     ed25519.PublicKey
	logID   LogID
	header  LogHeader
	prk     *prk // with DerivedKeys on a writable log; a pointer, so fmt of a Log shows an address
	replica bool // a Replica's log: never signs and never registers
	closed  bool
	tree    merkle.Tree
	records []recordCore
	s       Storage
}

// recordCore is what a Record holds beyond the log key, log ID and index, which are the log's own, plus what is stored of the entry.
type recordCore struct {
	size      uint64
	content   [HashSize]byte
	keyCommit [HashSize]byte
	sig       [ed25519.SignatureSize]byte
	flags     uint8
}

const (
	flagDeleted uint8 = 1 << iota // a delete marker is stored in place of the ciphertext
	flagKeyed                     // the entry key is stored
)

func compact(r Record, flags uint8) recordCore {
	c := recordCore{size: r.Size, content: r.ContentHash, keyCommit: r.KeyCommit, flags: flags}
	copy(c.sig[:], r.Signature)
	return c
}

// record returns a copy of the record of entry index; it needs l.mu held.
func (l *Log) record(index uint64) Record {
	c := &l.records[index]
	return Record{
		LogKey:      slices.Clone(l.pub),
		LogID:       l.logID,
		Index:       index,
		Size:        c.size,
		ContentHash: c.content,
		KeyCommit:   c.keyCommit,
		Signature:   slices.Clone(c.sig[:]),
	}
}

// New returns an empty Log with a random log ID and a signed [LogHeader], which keeps its entries in s.
// s must belong to this log only. New stores nothing: the caller stores the header if it keeps the log.
// It returns [koloid.ErrInvalidIdentity] for a nil or zero identity instead of panicking, [ErrNoStorage] for a nil s,
// [ErrStorageNotEmpty] for an s that returns an entry at index 0, and the storage's error if it fails to read index 0.
func New(id *koloid.Identity, s Storage, opts ...Option) (*Log, error) {
	pub, err := identityKey(id)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrNoStorage
	}
	if err := checkEmpty(s); err != nil {
		return nil, err
	}
	o, err := buildOptions(opts)
	if err != nil {
		return nil, err
	}
	l := &Log{id: id, pub: pub, s: s}
	if _, err := rand.Read(l.logID[:]); err != nil {
		return nil, err
	}
	l.header = LogHeader{LogKey: slices.Clone(pub), LogID: l.logID, Encoding: o.encoding, Keys: o.keys, Epoch: o.epoch}
	if l.header.Signature, err = id.Sign(l.header.context(), l.header.signed()); err != nil {
		return nil, err
	}
	if o.keys == DerivedKeys {
		if l.prk, err = newPRK(o.secret); err != nil {
			return nil, err
		}
	}
	if err := l.register(nil); err != nil {
		if l.prk != nil {
			clear(l.prk.key()[:])
		}
		return nil, err
	}
	return l, nil
}

func identityKey(id *koloid.Identity) (ed25519.PublicKey, error) {
	var pub ed25519.PublicKey
	if id != nil {
		pub = id.PublicKey()
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("kololog: %w", koloid.ErrInvalidIdentity)
	}
	return pub, nil
}

// String returns a short summary of l: its log ID, value encoding, key mode and epoch.
func (l *Log) String() string { return summary("kololog.Log", l.header) }

// GoString returns l.String().
func (l *Log) GoString() string { return l.String() }

// Format writes l.String() for every verb, so no verb prints the log's storage and the entry keys in it.
func (l *Log) Format(f fmt.State, _ rune) { fmt.Fprint(f, l.String()) }

// LogValue returns l's log ID, value encoding, key mode and epoch as a slog group.
func (l *Log) LogValue() slog.Value { return summaryValue(l.header) }

func summary(name string, h LogHeader) string {
	return fmt.Sprintf("%s{log=%s, encoding=%s, keys=%s, epoch=%d}", name, abbrev(h.LogID[:]), h.Encoding, h.Keys, h.Epoch)
}

func summaryValue(h LogHeader) slog.Value {
	return slog.GroupValue(slog.String("logId", h.LogID.String()), slog.String("encoding", h.Encoding.String()),
		slog.String("keys", h.Keys.String()), slog.Uint64("epoch", h.Epoch))
}

// Header returns a copy of the signed log header.
func (l *Log) Header() LogHeader {
	return l.header.clone()
}

// ID returns the random ID of the log.
func (l *Log) ID() LogID {
	return l.logID
}

// Append encodes v with the log's value encoding, encrypts it, stores it with a head signed over it in one [Storage.Commit] and returns its index.
// If the commit fails, the log is unchanged and the error wraps the storage's. With JSON, encoding/json keeps its own internal buffers,
// which kololog cannot clear.
func (l *Log) Append(v any) (uint64, error) {
	data, copied, err := encodeValue(l.header.Encoding, v)
	if err != nil {
		return 0, err
	}
	if copied {
		defer clear(data)
	}
	if err := checkEntrySize(uint64(len(data))); err != nil {
		return 0, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, ErrLogClosed
	}
	index := uint64(len(l.records))
	key, aead, err := l.newKey(index)
	if err != nil {
		return 0, err
	}
	defer clear(key[:])
	ciphertext, err := entrycrypt.Seal(aead, entryAD(l.pub, l.logID, index), data)
	if err != nil {
		return 0, err
	}
	r := Record{
		LogKey:      l.pub,
		LogID:       l.logID,
		Index:       index,
		Size:        uint64(len(ciphertext)),
		ContentHash: blake2b.Sum256(ciphertext),
		KeyCommit:   entrycrypt.Commit(key[:]),
	}
	if r.Signature, err = l.id.Sign(RecordContext, r.signed()); err != nil {
		return 0, err
	}
	l.tree.Append(merkle.LeafHash(r.Encode()))
	h, err := l.signHead()
	if err == nil {
		e := Entry{Record: r.Encode(), Ciphertext: ciphertext, Key: key[:]}
		err = l.commit(Change{Start: index, Entries: []Entry{e}, Heads: &Heads{Head: &h}})
	}
	if err != nil {
		l.tree.Truncate(index)
		return 0, err
	}
	l.records = append(l.records, compact(r, flagKeyed))
	return index, nil
}

// newKey returns the key of a new entry at index and its cipher: a random one, or with DerivedKeys the derived one.
// It needs l.mu held for writing, so index is the one the entry gets.
func (l *Log) newKey(index uint64) (*[keySize]byte, cipher.AEAD, error) {
	if l.header.Keys != DerivedKeys {
		return entrycrypt.NewKey()
	}
	k, err := l.prk.entryKey(l.pub, l.logID, l.header.Epoch, index)
	if err != nil {
		return nil, nil, err
	}
	defer clear(k[:])
	return entrycrypt.FromKey(k[:])
}

// commit stores c; it needs l.mu held for writing.
func (l *Log) commit(c Change) error {
	if err := l.s.Commit(c); err != nil {
		return fmt.Errorf("kololog: storage: %w", err)
	}
	return nil
}

// Read decodes the entry at index into out with the log's value encoding.
// With JSON, encoding/json keeps its own internal buffers, which kololog cannot clear.
func (l *Log) Read(index uint64, out any) error {
	if err := checkOut(l.header.Encoding, out); err != nil {
		return err
	}
	f, data, err := l.getFrame(index)
	if err != nil {
		return err
	}
	if readHook != nil {
		defer readHook(f)
	}
	return decodeFrame(l.header.Encoding, f, data, out)
}

// readHook sees the decrypted frame after Read is done with it; tests use it to check it was cleared.
var readHook func(f []byte)

// Get returns the stored bytes of the entry at index, [ErrDeleted] after [Log.Delete], or [ErrKeyUnavailable] for an entry stored without its key.
// It reads the entry from storage and checks it against the entry's record first.
func (l *Log) Get(index uint64) ([]byte, error) {
	_, data, err := l.getFrame(index)
	return data, err
}

func (l *Log) getFrame(index uint64) (f, data []byte, err error) {
	e, err := l.load(index, func(flags uint8) error {
		switch {
		case flags&flagDeleted != 0:
			return ErrDeleted
		case flags&flagKeyed == 0:
			return ErrKeyUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	defer clear(e.Key)
	key, aead, err := entrycrypt.FromKey(e.Key)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key[:])
	return openFrame(aead, entryAD(l.pub, l.logID, index), e.Ciphertext)
}

// Delete signs a [DeleteMarker] for each entry at indexes and stores them in place of the entries' ciphertexts and keys in one
// [Storage.Commit], so deleting many entries costs one durable write; the records and every proof stay valid.
// An index out of range returns [ErrOutOfRange] and deletes nothing. Entries already deleted, and repeated indexes, are skipped;
// if the commit fails, every entry stays as it was.
func (l *Log) Delete(indexes ...uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	n := uint64(len(l.records))
	var del []Deletion
	seen := make(map[uint64]bool, len(indexes))
	for _, index := range indexes {
		if index >= n {
			return fmt.Errorf("%w: entry %d of %d", ErrOutOfRange, index, n)
		}
		if seen[index] || l.records[index].flags&flagDeleted != 0 {
			continue
		}
		seen[index] = true
		r := l.record(index)
		m := DeleteMarker{LogKey: l.pub, LogID: l.logID, Index: index, LeafHash: merkle.LeafHash(r.Encode())}
		sig, err := l.id.Sign(DeleteContext, m.signed())
		if err != nil {
			return err
		}
		m.Signature = sig
		del = append(del, Deletion{Index: index, Record: r.Encode(), Marker: m.Encode()})
	}
	return l.commitDeletions(del)
}

// commitDeletions stores del in one commit and marks the entries deleted; it needs l.mu held for writing.
func (l *Log) commitDeletions(del []Deletion) error {
	if len(del) == 0 {
		return nil
	}
	if err := l.commit(Change{Start: uint64(len(l.records)), Deleted: del}); err != nil {
		return err
	}
	for _, d := range del {
		l.records[d.Index].flags = flagDeleted
	}
	return nil
}

// Len returns the number of entries in the log, deleted ones included.
func (l *Log) Len() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.records))
}

// Head returns a signed head for the current tree.
func (l *Log) Head() (Head, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return Head{}, ErrLogClosed
	}
	return l.signHead()
}

// signHead needs l.mu held.
func (l *Log) signHead() (Head, error) {
	h := Head{
		LogKey: slices.Clone(l.pub),
		LogID:  l.logID,
		Size:   l.tree.Size(),
		Root:   l.tree.Root(l.tree.Size()),
	}
	sig, err := l.id.Sign(HeadContext, h.signed())
	if err != nil {
		return Head{}, err
	}
	h.Signature = sig
	return h, nil
}

// Record returns the public record of the entry at index, which stays available after [Log.Delete].
func (l *Log) Record(index uint64) (Record, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= uint64(len(l.records)) {
		return Record{}, ErrOutOfRange
	}
	return l.record(index), nil
}

// InclusionProof returns a proof that the entry at index is in the tree of the first size entries.
func (l *Log) InclusionProof(index, size uint64) (InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if size > l.tree.Size() || index >= size {
		return InclusionProof{}, ErrOutOfRange
	}
	return InclusionProof{Index: index, Size: size, Path: l.tree.InclusionPath(index, size)}, nil
}

// ConsistencyProof returns a proof that the tree of oldSize entries is a prefix of the tree of newSize entries.
func (l *Log) ConsistencyProof(oldSize, newSize uint64) (ConsistencyProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if newSize > l.tree.Size() || oldSize > newSize {
		return ConsistencyProof{}, ErrOutOfRange
	}
	p := ConsistencyProof{OldSize: oldSize, NewSize: newSize}
	if oldSize > 0 && oldSize < newSize {
		p.Path = l.tree.ConsistencyPath(oldSize, newSize)
	}
	return p, nil
}
