package kololog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

var (
	// ErrNoStorage is returned by [New], [Restore], [NewReplica] and [RestoreReplica] for a nil [Storage].
	ErrNoStorage = errors.New("kololog: nil storage")
	// ErrStorageMismatch is returned by a read whose [Storage] returns an entry or key that does not match the entry's verified record.
	ErrStorageMismatch = errors.New("kololog: stored entry does not match its verified record")
	// ErrStorageNotEmpty is returned by [New] and [NewReplica] for a [Storage] that already holds an entry.
	ErrStorageNotEmpty = errors.New("kololog: storage already holds entries")
)

// Storage keeps one log's entries and heads. A log or replica keeps only tree hashes and a compact copy of each record in memory,
// reads entries from its Storage and checks them against the record, and makes every change through Commit.
// The log calls Storage with its own lock held: Commit never runs at the same time as another call, reads may run together.
type Storage interface {
	// Entry returns the stored form of the entry at index, its key included, as copies the log may keep or clear.
	// For an index that holds no entry it returns an error wrapping [ErrOutOfRange]; any other error means the storage failed.
	// Restore and RestoreReplica ask for each index once, in increasing order, from one goroutine at a time that is not the caller's,
	// and after a bad entry may still ask for a few more.
	Entry(index uint64) (Entry, error)
	// Key returns the stored key of the entry at index, nil if it has none, as a copy the log clears.
	Key(index uint64) (EntryKey, error)
	// Commit stores c atomically and durably, or nothing at all when it returns an error. It must copy what it keeps:
	// the log zeroes the keys in c after Commit returns.
	Commit(c Change) error
}

// Change is one atomic change a log makes to its [Storage].
type Change struct {
	Start   uint64     // the log's length before the change, in every Change: Entries are stored from this index on
	Entries []Entry    // new entries, each with its key when it has one
	Deleted []Deletion // entries whose ciphertext and key are replaced by their delete marker
	Keys    []KeyAt    // keys of entries stored without one, in ascending index order
	Heads   *Heads     // when not nil, replaces the stored heads
}

// KeyAt is the key of entry Index, in a [Change].
type KeyAt struct {
	Index uint64
	Key   EntryKey
}

// Deletion is the stored form of a deleted entry: its record and its delete marker.
type Deletion struct {
	Index  uint64
	Record []byte
	Marker []byte
}

// Heads is what a log stores about its heads.
type Heads struct {
	Head   *Head            // the last head whose every entry is stored; nil for a replica with no head yet
	Target *Head            // a replica's catch-up target, past Head; nil when none is pending
	Proof  ConsistencyProof // with Target: the proof that the stored entries are a prefix of it
}

// EntryInfo is what the log keeps in memory about the stored form of an entry.
type EntryInfo struct {
	Deleted bool // a delete marker is stored in place of the ciphertext and key
	Keyed   bool // the entry key is stored
}

// NewMemory returns an empty in-memory [Storage], for one log or replica that is not persisted.
func NewMemory() Storage {
	return &memory{}
}

// memory keeps each entry behind a pointer, so fmt's bad-verb path, which prints one pointer's target, stops at addresses.
type memory struct {
	mu      sync.RWMutex
	entries []*Entry
}

func (m *memory) String() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return fmt.Sprintf("kololog.memory{entries=%d}", len(m.entries))
}

func (m *memory) GoString() string           { return m.String() }
func (m *memory) Format(f fmt.State, _ rune) { fmt.Fprint(f, m.String()) }
func (m *memory) LogValue() slog.Value       { return slog.StringValue(m.String()) }

func (m *memory) Entry(index uint64) (Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if index >= uint64(len(m.entries)) {
		return Entry{}, ErrOutOfRange
	}
	return cloneEntry(*m.entries[index]), nil
}

func (m *memory) Key(index uint64) (EntryKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if index >= uint64(len(m.entries)) {
		return nil, ErrOutOfRange
	}
	return slices.Clone(m.entries[index].Key), nil
}

func (m *memory) Commit(c Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(c.Entries) > 0 && c.Start != uint64(len(m.entries)) {
		return fmt.Errorf("%w: entries from %d, the storage holds %d", ErrOutOfRange, c.Start, len(m.entries))
	}
	for _, e := range c.Entries {
		c := cloneEntry(e)
		m.entries = append(m.entries, &c)
	}
	for _, d := range c.Deleted {
		clear(m.entries[d.Index].Key)
		m.entries[d.Index] = &Entry{Record: slices.Clone(d.Record), Marker: slices.Clone(d.Marker)}
	}
	for _, k := range c.Keys {
		m.entries[k.Index].Key = slices.Clone(k.Key)
	}
	return nil
}

func cloneEntry(e Entry) Entry {
	return Entry{Record: slices.Clone(e.Record), Ciphertext: slices.Clone(e.Ciphertext), Marker: slices.Clone(e.Marker), Key: slices.Clone(e.Key)}
}

// EntryInfo returns whether the entry at index is deleted and whether its key is stored, without reading storage.
func (l *Log) EntryInfo(index uint64) (EntryInfo, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= uint64(len(l.records)) {
		return EntryInfo{}, ErrOutOfRange
	}
	f := l.records[index].flags
	return EntryInfo{Deleted: f&flagDeleted != 0, Keyed: f&flagKeyed != 0}, nil
}

// Entry returns the stored form of the entry at index, its key included; clear Key when done with it.
// It reads the entry from storage and checks it against the entry's record: a deleted entry must come with its marker only.
func (l *Log) Entry(index uint64) (Entry, error) {
	return l.load(index, nil)
}

// Key returns the key of the entry at index, read from storage without its ciphertext and checked against the record's key commitment;
// clear it when done. A deleted entry returns [ErrDeleted], one stored without its key [ErrKeyUnavailable].
func (l *Log) Key(index uint64) (EntryKey, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= uint64(len(l.records)) {
		return nil, ErrOutOfRange
	}
	c := &l.records[index]
	switch {
	case c.flags&flagDeleted != 0:
		return nil, ErrDeleted
	case c.flags&flagKeyed == 0:
		return nil, ErrKeyUnavailable
	}
	k, err := l.s.Key(index)
	if err != nil {
		return nil, storageErr(index, err)
	}
	if len(k) != keySize || !merkle.Equal(entrycrypt.Commit(k), c.keyCommit) {
		clear(k)
		return nil, fmt.Errorf("%w: entry %d: key does not match the record's key commitment", ErrStorageMismatch, index)
	}
	return k, nil
}

// load reads entry index from storage, after check accepts its flags, and checks it against its record and flags.
func (l *Log) load(index uint64, check func(flags uint8) error) (Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= uint64(len(l.records)) {
		return Entry{}, ErrOutOfRange
	}
	if check != nil {
		if err := check(l.records[index].flags); err != nil {
			return Entry{}, err
		}
	}
	return l.fetch(index)
}

// fetch reads entry index from storage and checks it against its record and flags; it needs l.mu held. The caller clears Key.
func (l *Log) fetch(index uint64) (Entry, error) {
	e, err := l.s.Entry(index)
	if err != nil {
		return Entry{}, storageErr(index, err)
	}
	e.Ciphertext, e.Marker = absent(e.Ciphertext), absent(e.Marker)
	if len(e.Key) == 0 {
		e.Key = nil
	}
	if err := checkStored(l.pub, l.logID, l.record(index), l.records[index].flags, e); err != nil {
		clear(e.Key)
		return Entry{}, fmt.Errorf("%w: entry %d: %w", ErrStorageMismatch, index, err)
	}
	return e, nil
}

// checkStored checks an entry read back from storage against its record, which was verified when the entry was added, and its flags.
// The ciphertext hash is checked on every read: the key is stored next to it, so other data sealed under that key would open too.
func checkStored(pub ed25519.PublicKey, logID LogID, r Record, flags uint8, e Entry) error {
	switch {
	case !bytes.Equal(e.Record, r.Encode()):
		return errors.New("record differs")
	case (flags&flagDeleted != 0) != (e.Marker != nil):
		return errors.New("deleted in the log but not in storage, or the other way round")
	case (flags&flagKeyed != 0) != (e.Key != nil):
		return errors.New("key stored in the log but not in storage, or the other way round")
	}
	if err := checkParts(pub, logID, r, e); err != nil {
		return err
	}
	if e.Key != nil && (len(e.Key) != keySize || !merkle.Equal(entrycrypt.Commit(e.Key), r.KeyCommit)) {
		return errors.New("key does not match the record's key commitment")
	}
	return nil
}

// checkEmpty returns [ErrStorageNotEmpty] if s holds an entry at index 0, and the error of a storage that fails to say it holds none.
func checkEmpty(s Storage) error {
	e, err := s.Entry(0)
	switch {
	case errors.Is(err, ErrOutOfRange):
		return nil
	case err != nil:
		return fmt.Errorf("kololog: storage: %w", err)
	}
	clear(e.Key)
	return ErrStorageNotEmpty
}

// storageErr wraps an error from reading entry index, which the log holds: storage that says it has no such entry lost it.
func storageErr(index uint64, err error) error {
	if errors.Is(err, ErrOutOfRange) {
		return fmt.Errorf("%w: entry %d missing from storage", ErrStorageMismatch, index)
	}
	return fmt.Errorf("kololog: entry %d: %w", index, err)
}
