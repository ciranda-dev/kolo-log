package kololog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

var (
	// ErrDiverged is returned by [Replica.Update] when the owner signed two histories: a head whose root differs from the held
	// entries at its size, a head of the target's size with another root, or entries toward a newer head that miss the target's root.
	ErrDiverged = errors.New("kololog: head diverges from the held entries or the pending target")
	// ErrBadProof is returned by [Replica.Update] when the consistency proof does not verify, and by [OpenEntry] when the inclusion proof does not.
	ErrBadProof = errors.New("kololog: consistency proof does not verify")
	// ErrBadEntry is returned by [Replica.Update], [Replica.AddKey], [Replica.ApplyDelete] and [OpenEntry] for an entry, key or marker that does not match its signed record or the head, and wrapped by [BadKeyError].
	ErrBadEntry = errors.New("kololog: entry does not match its signed record or the head")
	// ErrNoHead is returned by [Replica.Head] before the replica has a verified head.
	ErrNoHead = errors.New("kololog: replica has no verified head")
)

// Replica is a read-only copy of a log, opened from the owner's public key; it is safe for concurrent use.
// It grows only through [Replica.Update], which verifies everything before it commits any of it to its [Storage].
type Replica struct {
	log    *Log             // replica: never signs and never registers
	head   VerifiedHead     // the last head whose every entry is held; zero until the first head
	target VerifiedHead     // the head a catch-up is filling, past head; zero otherwise
	proof  ConsistencyProof // from Len to target
}

// NewReplica returns an empty replica of the log logID owned by pub, from the log's signed header, keeping its entries in s.
// s must belong to this replica only: one that returns an entry at index 0 gives [ErrStorageNotEmpty], and a failed read of
// index 0 the storage's error. NewReplica stores nothing: the caller stores the header if it keeps the replica.
func NewReplica(pub ed25519.PublicKey, logID LogID, header []byte, s Storage) (*Replica, error) {
	if s != nil {
		if err := checkEmpty(s); err != nil {
			return nil, err
		}
	}
	return RestoreReplica(pub, logID, header, Heads{}, s)
}

// RestoreReplica rebuilds a replica from its persisted header and heads and the entries in s, verifying all of it like [Restore],
// then replays a pending heads.Target through the checks of [Replica.Update]. Zero heads are a replica that has not grown yet.
// Errors in the stored data wrap [ErrRestoreMismatch].
func RestoreReplica(pub ed25519.PublicKey, logID LogID, header []byte, heads Heads, s Storage) (*Replica, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: log key of %d bytes", ErrMalformed, len(pub))
	}
	if s == nil {
		return nil, ErrNoStorage
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
	if lh.LogID != logID {
		return nil, fmt.Errorf("%w: header belongs to log %s", ErrBadLogHeader, lh.LogID)
	}
	r := &Replica{log: &Log{pub: slices.Clone(pub), logID: logID, header: lh, replica: true, s: s}}
	l := r.log
	if heads.Head != nil {
		v, err := VerifyHead(pub, logID, *heads.Head)
		if err != nil {
			return nil, err
		}
		if _, err := l.grow(ErrRestoreMismatch, v.Size(), nil, true); err != nil {
			return nil, err
		}
		if !merkle.Equal(l.tree.Root(v.Size()), v.Root()) {
			return nil, fmt.Errorf("%w: entries do not rebuild the head's root", ErrRestoreMismatch)
		}
		r.head = v
	}
	if heads.Target != nil {
		p, n := heads.Proof, l.Len()
		if p.OldSize < n || p.OldSize >= p.NewSize || p.NewSize != heads.Target.Size {
			return nil, fmt.Errorf("%w: catch-up from %d to %d after %d entries", ErrRestoreMismatch, p.OldSize, p.NewSize, n)
		}
		if err := r.update(*heads.Target, p, p.OldSize-n, nil, true); err != nil {
			return nil, fmt.Errorf("%w: pending target: %w", ErrRestoreMismatch, err)
		}
	}
	return r, nil
}

// Update verifies h, the entries from Len on and a consistency proof p, then commits them all in one [Storage.Commit]; on any
// error the replica is unchanged. The entries may stop at any size m up to h's size, so a replica far behind catches up in
// chunks; p then proves the tree of m entries, rebuilt from every verified leaf, is a prefix of h (RFC 9162). When the entries
// reach h's size, p may also be the proof from Len, or anything for an empty replica, and the rebuilt root must equal h's root.
// Until a chunk reaches h, h is the target ([Replica.Target]) and [Replica.Head] stays the last head whose every entry is held.
// A head whose entries the replica already holds becomes its head or is a no-op; an older one returns [ErrRollback] if it
// matches the held entries and [ErrDiverged] if not, as does a head of the size of the head or target with another root.
// While a target is pending, a head between Len and the target's size is refused unchecked with [ErrRollback], a chunk toward a
// larger head must reach the target's size ([ErrBadEntry] otherwise), and the rebuilt root there must equal the target's root
// ([ErrDiverged] otherwise). An entry may come without a key and then reads as [ErrKeyUnavailable]; a deleted one carries its marker.
func (r *Replica) Update(h Head, p ConsistencyProof, entries []Entry) error {
	return r.update(h, p, uint64(len(entries)), entries, false)
}

// update checks count entries, read from storage to replay a stored target or else taken from entries, and commits what changed unless it replays.
func (r *Replica) update(h Head, p ConsistencyProof, count uint64, entries []Entry, replay bool) error {
	l := r.log
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	v, err := VerifyHead(l.pub, l.logID, h)
	if err != nil {
		return err
	}
	n := l.tree.Size()
	if v.Size() <= n {
		switch {
		case !merkle.Equal(l.tree.Root(v.Size()), v.Root()):
			return ErrDiverged
		case r.head.valid() && v.Size() < r.head.Size():
			return fmt.Errorf("%w: head size %d is below the verified size %d", ErrRollback, v.Size(), r.head.Size())
		}
		if !r.head.valid() || v.Size() > r.head.Size() {
			if err := l.commit(Change{Start: n, Heads: r.heads(v, r.target, r.proof)}); err != nil {
				return err
			}
			r.head = v
		}
		return nil
	}
	t := r.target
	switch {
	case t.valid() && v.Size() == t.Size() && !merkle.Equal(v.Root(), t.Root()):
		return ErrDiverged
	case t.valid() && v.Size() < t.Size():
		return fmt.Errorf("%w: head size %d is below the target size %d being filled", ErrRollback, v.Size(), t.Size())
	case count > v.Size()-n:
		return fmt.Errorf("%w: %d entries after %d go past a head of size %d", ErrBadEntry, count, n, v.Size())
	}
	m := n + count
	if t.valid() && v.Size() > t.Size() && m < t.Size() {
		// Dropping the target here would lose the only check that it and v are one history.
		return fmt.Errorf("%w: a chunk toward a newer head must reach the target size %d being filled", ErrBadEntry, t.Size())
	}
	from := m
	if m == v.Size() && p.OldSize == n {
		from = n
	}
	// An empty replica given every entry of h has nothing to prove: the rebuilt root is checked below.
	whole := n == 0 && m == v.Size()
	if !whole && (p.OldSize != from || p.NewSize != v.Size()) {
		return fmt.Errorf("%w: proof from %d to %d, want from %d to %d", ErrBadProof, p.OldSize, p.NewSize, from, v.Size())
	}
	kept, err := l.grow(ErrBadEntry, count, entries, replay)
	if err != nil {
		return err
	}
	defer func() {
		for _, e := range kept {
			clear(e.Key)
		}
	}()
	if err := r.checkGrown(v, p, from, m, whole); err != nil {
		l.truncate(n)
		return err
	}
	head, target, proof := r.head, v, ConsistencyProof{OldSize: p.OldSize, NewSize: p.NewSize, Path: slices.Clone(p.Path)}
	if m == v.Size() {
		head, target, proof = v, VerifiedHead{}, ConsistencyProof{}
	}
	if !replay {
		if err := l.commit(Change{Start: n, Entries: kept, Heads: r.heads(head, target, proof)}); err != nil {
			l.truncate(n)
			return err
		}
	}
	r.head, r.target, r.proof = head, target, proof
	return nil
}

// checkGrown checks the tree grown to m entries against v, p and the pending target; the log's lock must be held.
func (r *Replica) checkGrown(v VerifiedHead, p ConsistencyProof, from, m uint64, whole bool) error {
	l, t := r.log, r.target
	if !whole && !merkle.VerifyConsistency(from, v.Size(), l.tree.Root(from), v.Root(), p.Path) {
		if from == m {
			return fmt.Errorf("%w: entries and proof do not lead to the head's root", ErrBadProof)
		}
		return ErrBadProof
	}
	if m == v.Size() && !merkle.Equal(l.tree.Root(m), v.Root()) {
		return fmt.Errorf("%w: entries do not rebuild the head's root", ErrBadEntry)
	}
	if t.valid() && m >= t.Size() && !merkle.Equal(l.tree.Root(t.Size()), t.Root()) {
		return fmt.Errorf("%w: the entries do not rebuild the root of the target of size %d", ErrDiverged, t.Size())
	}
	return nil
}

func (r *Replica) heads(head, target VerifiedHead, proof ConsistencyProof) *Heads {
	out := &Heads{}
	if head.valid() {
		h := head.Head()
		out.Head = &h
	}
	if target.valid() {
		h := target.Head()
		out.Target, out.Proof = &h, ConsistencyProof{OldSize: proof.OldSize, NewSize: proof.NewSize, Path: slices.Clone(proof.Path)}
	}
	return out
}

// Target returns the head an unfinished catch-up is filling and the proof that the first Len entries are a prefix of it, or ok false.
// The replica commits both with each chunk, and [RestoreReplica] replays them.
func (r *Replica) Target() (h Head, p ConsistencyProof, ok bool) {
	r.log.mu.RLock()
	defer r.log.mu.RUnlock()
	if !r.target.valid() {
		return Head{}, ConsistencyProof{}, false
	}
	return r.target.Head(), ConsistencyProof{OldSize: r.proof.OldSize, NewSize: r.proof.NewSize, Path: slices.Clone(r.proof.Path)}, true
}

// AddKey gives a held entry that came without its key the key, after checking it against the record's key commitment and that it opens
// the ciphertext read from storage, and commits it. The key an entry already has does nothing; another key returns [ErrBadEntry].
// The caller should clear key.
func (r *Replica) AddKey(index uint64, key []byte) error {
	l := r.log
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	if index >= uint64(len(l.records)) {
		return ErrOutOfRange
	}
	c := &l.records[index]
	switch {
	case c.flags&flagDeleted != 0:
		return ErrDeleted
	case c.flags&flagKeyed != 0:
		// The commitment binds the record to one key, so a key that matches it is the one stored.
		if len(key) != keySize || !merkle.Equal(entrycrypt.Commit(key), c.keyCommit) {
			return fmt.Errorf("%w: entry %d already has another key", ErrBadEntry, index)
		}
		return nil
	}
	e, err := l.fetch(index)
	if err != nil {
		return err
	}
	o, err := openKey(l.pub, l.logID, l.record(index), e.Ciphertext, key)
	if err != nil {
		return fmt.Errorf("%w: entry %d: %w", ErrBadEntry, index, err)
	}
	clear(o.frame)
	defer clear(o.key[:])
	if err := l.commit(Change{Start: uint64(len(l.records)), Keys: []KeyAt{{Index: index, Key: o.key[:]}}}); err != nil {
		return err
	}
	c.flags |= flagKeyed
	return nil
}

// MaxAddKeys is the most keys one [Replica.AddKeys] call takes: as many entries as one kolo-sync answer can carry,
// its 4 MiB message bound over the 128-byte smallest signed record (kolo-sync wire.go, MaxMessageSize and minSigned).
const MaxAddKeys = 32768

// ErrTooManyKeys is returned by [Replica.AddKeys] for more than [MaxAddKeys] keys.
var ErrTooManyKeys = errors.New("kololog: too many keys in one call")

// BadKeyError is the error of [Replica.AddKeys] for the keys that do not belong to their entries; it wraps [ErrBadEntry].
type BadKeyError struct {
	Indexes []uint64 // ascending
}

// Error returns how many keys were refused and the first refused index.
func (e *BadKeyError) Error() string {
	if len(e.Indexes) == 0 {
		return "kololog: no bad keys"
	}
	return fmt.Sprintf("kololog: %d keys do not belong to their entries, the first at index %d", len(e.Indexes), e.Indexes[0])
}

// Unwrap returns [ErrBadEntry].
func (e *BadKeyError) Unwrap() error { return ErrBadEntry }

// addKeysHook runs after AddKeys checked every key and before it takes the lock to commit them; tests use it.
var addKeysHook func()

// AddKeys checks every key in keys against the held entries from start on, and stores every key that passes in one
// [Storage.Commit]. A nil or empty key skips its entry, and so does an entry that is deleted or already keyed. Keys the signed
// record proves wrong are refused together in one [*BadKeyError], and the keys that passed are still stored. A storage error or
// [ErrStorageMismatch] stores nothing. More than [MaxAddKeys] keys is [ErrTooManyKeys], and keys past Len [ErrOutOfRange].
// The caller should clear keys.
func (r *Replica) AddKeys(start uint64, keys []EntryKey) error {
	if len(keys) > MaxAddKeys {
		return fmt.Errorf("%w: %d keys, at most %d", ErrTooManyKeys, len(keys), MaxAddKeys)
	}
	l := r.log
	l.mu.RLock()
	closed, n := l.closed, uint64(len(l.records))
	l.mu.RUnlock()
	switch {
	case closed:
		return ErrLogClosed
	case start > n || uint64(len(keys)) > n-start:
		return fmt.Errorf("%w: %d keys from %d, the replica holds %d", ErrOutOfRange, len(keys), start, n)
	}
	var passed []KeyAt
	defer func() {
		for _, k := range passed {
			clear(k.Key)
		}
	}()
	var refused []uint64
	for i, k := range keys {
		if len(k) == 0 {
			continue
		}
		index := start + uint64(i)
		key, bad, err := r.checkKey(index, k)
		switch {
		case err != nil:
			return err
		case bad:
			refused = append(refused, index)
		case key != nil:
			passed = append(passed, KeyAt{Index: index, Key: key[:]})
		}
	}
	if addKeysHook != nil {
		addKeysHook()
	}
	if err := r.commitKeys(passed); err != nil {
		return err
	}
	if len(refused) > 0 {
		return &BadKeyError{Indexes: refused}
	}
	return nil
}

// checkKey checks key k for entry index: it returns the replica's own copy of a key that opens the entry, bad for a key the
// signed record proves wrong, or neither for an entry that is deleted or keyed. It holds the read lock only to read storage,
// since a Commit never runs at the same time as another Storage call.
func (r *Replica) checkKey(index uint64, k []byte) (key *[keySize]byte, bad bool, err error) {
	l := r.log
	l.mu.RLock()
	c := l.records[index]
	if c.flags != 0 {
		l.mu.RUnlock()
		return nil, false, nil
	}
	// Checked before reading or decrypting anything: the cipher is not key-committing.
	if len(k) != keySize || !merkle.Equal(entrycrypt.Commit(k), c.keyCommit) {
		l.mu.RUnlock()
		return nil, true, nil
	}
	e, err := l.fetch(index)
	rec := l.record(index)
	l.mu.RUnlock()
	if err != nil {
		return nil, false, err
	}
	// fetch checked the ciphertext against the record's hash, so a key that does not open it is wrong for the record.
	o, err := openKey(l.pub, l.logID, rec, e.Ciphertext, k)
	if err != nil {
		return nil, true, nil
	}
	clear(o.frame)
	return o.key, false, nil
}

func (r *Replica) commitKeys(keys []KeyAt) error {
	l := r.log
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	var keep []KeyAt
	for _, k := range keys {
		if l.records[k.Index].flags == 0 {
			keep = append(keep, k)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	if err := l.commit(Change{Start: uint64(len(l.records)), Keys: keep}); err != nil {
		return err
	}
	for _, k := range keep {
		l.records[k.Index].flags |= flagKeyed
	}
	return nil
}

// ApplyDelete verifies encoded [DeleteMarker]s for entries the replica holds, then commits them in place of those entries'
// ciphertexts and keys in one [Storage.Commit]. The records and the markers stay, and reads return [ErrDeleted].
// A marker that does not decode, is out of range or does not match its entry returns an error and applies none of them;
// a marker for an entry already deleted, or repeated, is skipped.
func (r *Replica) ApplyDelete(markers ...[]byte) error {
	ms := make([]DeleteMarker, len(markers))
	for i, b := range markers {
		var err error
		if ms[i], err = DecodeDeleteMarker(b); err != nil {
			return err
		}
	}
	l := r.log
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	n := uint64(len(l.records))
	var del []Deletion
	seen := make(map[uint64]bool, len(ms))
	for _, m := range ms {
		if m.Index >= n {
			return fmt.Errorf("%w: entry %d of %d", ErrOutOfRange, m.Index, n)
		}
		rec := l.record(m.Index)
		if !VerifyDeleteMarker(l.pub, l.logID, rec, m) {
			return fmt.Errorf("%w: delete marker does not match entry %d", ErrBadEntry, m.Index)
		}
		if seen[m.Index] || l.records[m.Index].flags&flagDeleted != 0 {
			continue
		}
		seen[m.Index] = true
		del = append(del, Deletion{Index: m.Index, Record: rec.Encode(), Marker: m.Encode()})
	}
	return l.commitDeletions(del)
}

// Head returns the last verified head whose every entry the replica holds, exactly as received, or [ErrNoHead].
func (r *Replica) Head() (Head, error) {
	r.log.mu.RLock()
	defer r.log.mu.RUnlock()
	if !r.head.valid() {
		return Head{}, ErrNoHead
	}
	return r.head.Head(), nil
}

// Close stops Update, AddKey, AddKeys and ApplyDelete, which then return [ErrLogClosed]; reads keep working.
func (r *Replica) Close() error {
	r.log.mu.Lock()
	defer r.log.mu.Unlock()
	r.log.closed = true
	return nil
}

// Header returns a copy of the signed log header.
func (r *Replica) Header() LogHeader { return r.log.Header() }

// String returns a short summary of r: its log ID, value encoding, key mode and epoch.
func (r *Replica) String() string { return summary("kololog.Replica", r.log.header) }

// GoString returns r.String().
func (r *Replica) GoString() string { return r.String() }

// Format writes r.String() for every verb.
func (r *Replica) Format(f fmt.State, _ rune) { fmt.Fprint(f, r.String()) }

// LogValue returns r's log ID, value encoding, key mode and epoch as a slog group.
func (r *Replica) LogValue() slog.Value { return summaryValue(r.log.header) }

// ID returns the log ID.
func (r *Replica) ID() LogID { return r.log.ID() }

// Len returns the number of verified entries, deleted ones included; during a catch-up it can exceed Head's size.
func (r *Replica) Len() uint64 { return r.log.Len() }

// Read decodes the entry at index into out with the log's value encoding.
func (r *Replica) Read(index uint64, out any) error { return r.log.Read(index, out) }

// Get returns the stored bytes of the entry at index, [ErrKeyUnavailable] without its key, or [ErrDeleted].
func (r *Replica) Get(index uint64) ([]byte, error) { return r.log.Get(index) }

// Record returns the public record of the entry at index.
func (r *Replica) Record(index uint64) (Record, error) { return r.log.Record(index) }

// Entry returns the stored form of the entry at index, its key included; clear Key when done with it.
func (r *Replica) Entry(index uint64) (Entry, error) { return r.log.Entry(index) }

// Key returns the key of the entry at index without reading its ciphertext, as [Log.Key] does.
func (r *Replica) Key(index uint64) (EntryKey, error) { return r.log.Key(index) }

// EntryInfo returns whether the entry at index is deleted and whether its key is stored, without reading storage.
func (r *Replica) EntryInfo(index uint64) (EntryInfo, error) { return r.log.EntryInfo(index) }

// InclusionProof returns a proof that the entry at index is in the tree of the first size entries.
func (r *Replica) InclusionProof(index, size uint64) (InclusionProof, error) {
	return r.log.InclusionProof(index, size)
}

// ConsistencyProof returns a proof that the tree of oldSize entries is a prefix of the tree of newSize entries.
func (r *Replica) ConsistencyProof(oldSize, newSize uint64) (ConsistencyProof, error) {
	return r.log.ConsistencyProof(oldSize, newSize)
}
