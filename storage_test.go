package kololog

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

func storeOf(entries []Entry) Storage {
	s := NewMemory()
	if err := s.Commit(Change{Entries: entries}); err != nil {
		panic(err)
	}
	return s
}

// restoreReplica restores a replica from an encoded head, or none when head is empty, and entries.
func restoreReplica(t testing.TB, pub []byte, logID LogID, header, head []byte, entries []Entry) (*Replica, error) {
	t.Helper()
	var heads Heads
	if len(head) > 0 {
		h, err := DecodeHead(head)
		if err != nil {
			return nil, err
		}
		heads.Head = &h
	}
	return RestoreReplica(pub, logID, header, heads, storeOf(entries))
}

// testStorage wraps a memory storage: it counts reads, can fail commits, and lets a test change what is stored.
type testStorage struct {
	*memory
	mu         sync.Mutex
	reads      []uint64 // indexes passed to Entry
	keys       int      // calls to Key
	fail       error    // returned by Commit and reads when set
	failCommit error    // returned by Commit when set
	commits    int
}

func newTestStorage() *testStorage { return &testStorage{memory: &memory{}} }

func (s *testStorage) Entry(index uint64) (Entry, error) {
	s.mu.Lock()
	s.reads = append(s.reads, index)
	err := s.fail
	s.mu.Unlock()
	if err != nil {
		return Entry{}, err
	}
	return s.memory.Entry(index)
}

func (s *testStorage) Key(index uint64) (EntryKey, error) {
	s.mu.Lock()
	s.keys++
	err := s.fail
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.memory.Key(index)
}

func (s *testStorage) Commit(c Change) error {
	s.mu.Lock()
	err := cmp.Or(s.fail, s.failCommit)
	s.commits++
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.memory.Commit(c)
}

func (s *testStorage) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func (s *testStorage) takeReads() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reads
	s.reads = nil
	return r
}

// change edits the stored form of entry index in place, as a change on disk would.
func (s *testStorage) change(index uint64, fn func(*Entry)) {
	s.memory.mu.Lock()
	defer s.memory.mu.Unlock()
	fn(s.memory.entries[index])
}

func (s *testStorage) stored(index uint64) Entry {
	e, err := s.memory.Entry(index)
	if err != nil {
		panic(err)
	}
	return e
}

func newStorageLog(t testing.TB, n int) (*Log, *testStorage) {
	t.Helper()
	s := newTestStorage()
	l, err := New(newID(t), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	appendN(t, l, 0, n)
	return l, s
}

var errDisk = errors.New("test storage: disk failed")

func TestNilStorage(t *testing.T) {
	l, _ := newLog(t, 1)
	if _, err := New(newID(t), nil); !errors.Is(err, ErrNoStorage) {
		t.Errorf("New with a nil storage: %v", err)
	}
	if _, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), nil); !errors.Is(err, ErrNoStorage) {
		t.Errorf("NewReplica with a nil storage: %v", err)
	}
}

func TestEntryInfoAndKey(t *testing.T) {
	l, s := newStorageLog(t, 3)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	s.takeReads()
	want := []EntryInfo{{Keyed: true}, {Deleted: true}, {Keyed: true}}
	for i, w := range want {
		if got, err := l.EntryInfo(uint64(i)); err != nil || got != w {
			t.Fatalf("EntryInfo(%d) = %+v, %v, want %+v", i, got, err, w)
		}
	}
	k, err := l.Key(2)
	if err != nil || !bytes.Equal(k, s.stored(2).Key) {
		t.Fatalf("Key(2) = %v", err)
	}
	if _, err := l.Key(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Key of a deleted entry: %v", err)
	}
	if _, err := l.Get(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get of a deleted entry: %v", err)
	}
	if reads := s.takeReads(); len(reads) != 0 {
		t.Fatalf("EntryInfo, Key and Get of a deleted entry read entries %v from storage", reads)
	}
	if _, err := l.EntryInfo(3); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("EntryInfo past the end: %v", err)
	}
	if _, err := l.Key(3); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Key past the end: %v", err)
	}

	r, rs := newStorageReplica(t, l)
	u := updateFrom(t, l, 0)
	key := u.entries[2].Key
	u.entries[2].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.EntryInfo(2); got != (EntryInfo{}) {
		t.Fatalf("EntryInfo of an entry received without its key: %+v", got)
	}
	if _, err := r.Key(2); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Key of an entry without its key: %v", err)
	}
	if err := r.AddKey(2, key); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.EntryInfo(2); got != (EntryInfo{Keyed: true}) {
		t.Fatalf("EntryInfo after AddKey: %+v", got)
	}
	rs.takeReads()
	if err := r.AddKey(2, key); err != nil {
		t.Fatalf("AddKey of the key it has: %v", err)
	}
	if err := r.AddKey(2, mustEntry(t, l, 0).Key); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("AddKey of another key over the one it has: %v", err)
	}
	if reads := rs.takeReads(); len(reads) != 0 {
		t.Fatalf("AddKey of an entry that has its key read %v", reads)
	}
	if k, err := r.Key(2); err != nil || !bytes.Equal(k, key) {
		t.Fatalf("Key after AddKey: %v", err)
	}
	if got, _ := r.EntryInfo(1); got != (EntryInfo{Deleted: true}) {
		t.Fatalf("EntryInfo of a replicated deleted entry: %+v", got)
	}
}

func newStorageReplica(t testing.TB, l *Log) (*Replica, *testStorage) {
	t.Helper()
	s := newTestStorage()
	r, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), s)
	if err != nil {
		t.Fatal(err)
	}
	return r, s
}

// Every read is checked against the record and flags in memory, so a change on disk is refused.
func TestStoredEntryChecked(t *testing.T) {
	l, s := newStorageLog(t, 3)
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	other, _ := newLog(t, 1)
	good := []Entry{s.stored(0), s.stored(1), s.stored(2)}
	tests := []struct {
		name   string
		index  uint64
		change func(*Entry)
	}{
		{"tampered ciphertext", 0, func(e *Entry) { e.Ciphertext = flip(e.Ciphertext, 40) }},
		{"ciphertext cut", 0, func(e *Entry) { e.Ciphertext = e.Ciphertext[:len(e.Ciphertext)-1] }},
		{"record of another entry", 0, func(e *Entry) { e.Record = good[1].Record }},
		{"record of another log", 0, func(e *Entry) { e.Record = mustEntry(t, other, 0).Record }},
		{"key of another entry", 0, func(e *Entry) { e.Key = good[1].Key }},
		{"key cut", 0, func(e *Entry) { e.Key = e.Key[:keySize-1] }},
		{"key removed", 0, func(e *Entry) { e.Key = nil }},
		{"ciphertext and marker", 0, func(e *Entry) { e.Marker = good[2].Marker }},
		{"neither ciphertext nor marker", 0, func(e *Entry) { e.Ciphertext = nil }},
		{"marker of another entry", 1, func(e *Entry) { e.Ciphertext, e.Key, e.Marker = nil, nil, good[2].Marker }},
		{"tampered marker", 2, func(e *Entry) { e.Marker = flip(e.Marker, len(e.Marker)-1) }},
		{"marker cut", 2, func(e *Entry) { e.Marker = e.Marker[:len(e.Marker)-1] }},
		{"marker with a key", 2, func(e *Entry) { e.Key = good[0].Key }},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			for i, e := range good {
				s.change(uint64(i), func(x *Entry) { *x = cloneEntry(e) })
			}
			s.change(c.index, c.change)
			if _, err := l.Entry(c.index); !errors.Is(err, ErrStorageMismatch) {
				t.Errorf("Entry = %v, want ErrStorageMismatch", err)
			}
			if c.index == 2 {
				return
			}
			if _, err := l.Get(c.index); !errors.Is(err, ErrStorageMismatch) {
				t.Errorf("Get = %v, want ErrStorageMismatch", err)
			}
			var out []byte
			if err := l.Read(c.index, &out); !errors.Is(err, ErrStorageMismatch) {
				t.Errorf("Read = %v, want ErrStorageMismatch", err)
			}
		})
	}
	for i, e := range good {
		s.change(uint64(i), func(x *Entry) { *x = cloneEntry(e) })
	}
	s.change(1, func(e *Entry) { e.Key = good[0].Key })
	if _, err := l.Key(1); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("Key of another entry stored as entry 1's: %v", err)
	}
	s.change(1, func(e *Entry) { e.Key = nil })
	if _, err := l.Key(1); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("Key removed from storage: %v", err)
	}
	s.change(1, func(e *Entry) { *e = cloneEntry(good[1]) })
	s.setFail(errDisk)
	if _, err := l.Get(0); !errors.Is(err, errDisk) || errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("Get with a failing storage: %v", err)
	}
	if _, err := l.Key(0); !errors.Is(err, errDisk) {
		t.Fatalf("Key with a failing storage: %v", err)
	}
}

// An old stored value of a deleted entry, put back on disk, is refused: the log knows the entry is deleted.
func TestDeletedEntryComesBack(t *testing.T) {
	l, s := newStorageLog(t, 2)
	old := s.stored(1)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	s.change(1, func(e *Entry) { *e = cloneEntry(old) })
	if _, err := l.Get(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get of a deleted entry whose old value is back: %v", err)
	}
	if _, err := l.Key(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Key of a deleted entry whose old value is back: %v", err)
	}
	if _, err := l.Entry(1); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("Entry of a deleted entry whose old value is back: %v", err)
	}

	src, _ := newLog(t, 2)
	r, rs := newStorageReplica(t, src)
	if err := updateFrom(t, src, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	old = rs.stored(0)
	if err := src.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, src, 0).Marker); err != nil {
		t.Fatal(err)
	}
	rs.change(0, func(e *Entry) { *e = cloneEntry(old) })
	if _, err := r.Get(0); !errors.Is(err, ErrDeleted) {
		t.Fatalf("replica Get of a deleted entry whose old value is back: %v", err)
	}
	if _, err := r.Entry(0); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("replica Entry of a deleted entry whose old value is back: %v", err)
	}
	if err := r.AddKey(0, old.Key); !errors.Is(err, ErrDeleted) {
		t.Fatalf("AddKey on a deleted entry: %v", err)
	}
}

// A failed commit leaves the log or replica exactly as it was, and the next one works.
func TestFailedCommitChangesNothing(t *testing.T) {
	l, s := newStorageLog(t, 2)
	before := head(t, l)
	s.setFail(errDisk)
	if _, err := l.Append([]byte("lost")); !errors.Is(err, errDisk) {
		t.Fatalf("Append with a failing commit: %v", err)
	}
	if err := l.Delete(0); !errors.Is(err, errDisk) {
		t.Fatalf("Delete with a failing commit: %v", err)
	}
	if h := head(t, l); l.Len() != 2 || h.Root != before.Root || h.Size != before.Size {
		t.Fatal("a failed commit changed the log")
	}
	if info, _ := l.EntryInfo(0); info.Deleted {
		t.Fatal("a failed Delete marked the entry deleted")
	}
	s.setFail(nil)
	if got, err := l.Get(0); err != nil || string(got) != "entry 0" {
		t.Fatalf("Get after a failed Delete: %q, %v", got, err)
	}
	if index, err := l.Append([]byte("entry 2")); err != nil || index != 2 {
		t.Fatalf("Append after a failed commit: %d, %v", index, err)
	}
	if got, err := l.Get(2); err != nil || string(got) != "entry 2" {
		t.Fatalf("Get(2) = %q, %v", got, err)
	}

	r, rs := newStorageReplica(t, l)
	u := updateFrom(t, l, 0)
	key := u.entries[1].Key
	u.entries[1].Key = nil
	rs.setFail(errDisk)
	if err := u.apply(r); !errors.Is(err, errDisk) || r.Len() != 0 {
		t.Fatalf("Update with a failing commit: %v, Len %d", err, r.Len())
	}
	if _, err := r.Head(); !errors.Is(err, ErrNoHead) {
		t.Fatalf("a failed Update set the head: %v", err)
	}
	rs.setFail(nil)
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	before = mustReplicaHead(t, r)
	rs.setFail(nil)
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	marker := mustEntry(t, l, 2).Marker
	rs.setFail(errDisk)
	if err := r.AddKey(1, key); !errors.Is(err, errDisk) {
		t.Fatalf("AddKey with a failing storage: %v", err)
	}
	if err := r.ApplyDelete(marker); !errors.Is(err, errDisk) {
		t.Fatalf("ApplyDelete with a failing commit: %v", err)
	}
	appendN(t, l, 3, 1)
	newer := head(t, l)
	if err := r.Update(newer, proofOf(t, l, 3, 4), nil); !errors.Is(err, errDisk) {
		t.Fatalf("Update to a target with a failing commit: %v", err)
	}
	if _, _, ok := r.Target(); ok {
		t.Fatal("a failed Update set the target")
	}
	rs.setFail(nil)
	if got := mustReplicaHead(t, r); got.Size != before.Size {
		t.Fatal("a failed commit changed the replica head")
	}
	for i, want := range []EntryInfo{{Keyed: true}, {}, {Keyed: true}} {
		if got, _ := r.EntryInfo(uint64(i)); got != want {
			t.Fatalf("EntryInfo(%d) after failed commits = %+v, want %+v", i, got, want)
		}
	}
	if err := r.AddKey(1, key); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(marker); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(2); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get after ApplyDelete: %v", err)
	}
}

func proofOf(t testing.TB, l *Log, from, to uint64) ConsistencyProof {
	t.Helper()
	p, err := l.ConsistencyProof(from, to)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// recordingHeads is a test storage that also keeps the heads of its last commit that had any, as a storage layer does.
type recordingHeads struct {
	*testStorage
	heads Heads
}

func (s *recordingHeads) Commit(c Change) error {
	if err := s.testStorage.Commit(c); err != nil {
		return err
	}
	if c.Heads != nil {
		s.heads = *c.Heads
	}
	return nil
}

func TestRestoreReplicaReplaysTarget(t *testing.T) {
	l, _ := newLog(t, 10)
	header := l.Header().Encode()
	s := &recordingHeads{testStorage: newTestStorage()}
	a, err := NewReplica(l.pub, l.ID(), header, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := chunk(t, l, 0, 4).apply(a); err != nil {
		t.Fatal(err)
	}
	if s.heads.Head != nil || s.heads.Target == nil || s.heads.Proof.OldSize != 4 {
		t.Fatalf("a chunk committed heads %+v", s.heads)
	}
	s.takeReads()
	b, err := RestoreReplica(l.pub, l.ID(), header, s.heads, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.takeReads(); !slices.Equal(got, []uint64{0, 1, 2, 3}) {
		t.Fatalf("RestoreReplica read %v, want each stored entry once in order", got)
	}
	if state(t, b) != state(t, a) {
		t.Fatal("the restored replica differs from the one that received the chunk")
	}
	if err := chunk(t, l, 4, 10).apply(b); err != nil {
		t.Fatalf("finishing the restored catch-up: %v", err)
	}
	if s.heads.Head == nil || s.heads.Head.Size != 10 || s.heads.Target != nil {
		t.Fatalf("the last chunk committed heads %+v", s.heads)
	}

	c := &recordingHeads{testStorage: newTestStorage()}
	a, err = NewReplica(l.pub, l.ID(), header, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := chunk(t, l, 0, 3).apply(a); err != nil {
		t.Fatal(err)
	}
	h3 := c.heads
	wrong := func(fn func(*Heads)) Heads {
		h := Heads{Target: h3.Target, Proof: ConsistencyProof{OldSize: h3.Proof.OldSize, NewSize: h3.Proof.NewSize, Path: slices.Clone(h3.Proof.Path)}}
		fn(&h)
		return h
	}
	for name, h := range map[string]Heads{
		"proof from past the stored entries": wrong(func(h *Heads) { h.Proof.OldSize = 4 }),
		"proof to another size":              wrong(func(h *Heads) { h.Proof.NewSize = 9 }),
		"proof from the target size":         wrong(func(h *Heads) { h.Proof.OldSize = 10 }),
		"tampered proof":                     wrong(func(h *Heads) { h.Proof.Path[0][0] ^= 1 }),
	} {
		if _, err := RestoreReplica(l.pub, l.ID(), header, h, c); !errors.Is(err, ErrRestoreMismatch) {
			t.Errorf("%s: RestoreReplica = %v, want ErrRestoreMismatch", name, err)
		}
	}
	h4 := head(t, l)
	h4.Signature = flip(h4.Signature, 0)
	if _, err := RestoreReplica(l.pub, l.ID(), header, Heads{Target: &h4, Proof: h3.Proof}, c); !errors.Is(err, ErrRestoreMismatch) {
		t.Errorf("forged target: %v", err)
	}
	c.change(1, func(e *Entry) { e.Ciphertext = flip(e.Ciphertext, 40) })
	if _, err := RestoreReplica(l.pub, l.ID(), header, h3, c); !errors.Is(err, ErrRestoreMismatch) || !errors.Is(err, ErrBadEntry) {
		t.Errorf("changed stored entry under a target: %v", err)
	}
	if _, err := RestoreReplica(l.pub, l.ID(), header, Heads{}, nil); !errors.Is(err, ErrNoStorage) {
		t.Errorf("nil storage: %v", err)
	}
}

func TestRestoreReadsEachEntryOnce(t *testing.T) {
	l, id := newLog(t, 5)
	if err := l.Delete(3); err != nil {
		t.Fatal(err)
	}
	h := head(t, l)
	header := l.Header().Encode()
	s := newTestStorage()
	for i := range uint64(5) {
		if err := s.Commit(Change{Start: i, Entries: []Entry{mustEntry(t, l, i)}}); err != nil {
			t.Fatal(err)
		}
	}
	want := make([]string, 5)
	for i := range want {
		v, err := l.Get(uint64(i))
		want[i] = fmt.Sprintf("%q %v", v, err)
	}
	l.Close()
	r, err := Restore(id, header, h.Encode(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := s.takeReads(); !slices.Equal(got, []uint64{0, 1, 2, 3, 4}) {
		t.Fatalf("Restore read %v, want each entry once in order", got)
	}
	for i := range want {
		v, err := r.Get(uint64(i))
		if got := fmt.Sprintf("%q %v", v, err); got != want[i] {
			t.Fatalf("restored Get(%d) = %s, want %s", i, got, want[i])
		}
	}
	s.setFail(errDisk)
	r.Close()
	if _, err := Restore(id, header, h.Encode(), s); !errors.Is(err, errDisk) {
		t.Fatalf("Restore with a failing storage: %v", err)
	}
}

// keyKeeper is a storage that remembers every key it hands out, to check that the log clears them.
type keyKeeper struct {
	*testStorage
	keys []EntryKey
}

func (k *keyKeeper) Entry(index uint64) (Entry, error) {
	e, err := k.testStorage.Entry(index)
	k.keys = append(k.keys, e.Key)
	return e, err
}

func TestStorageKeysCleared(t *testing.T) {
	l, id := newLog(t, 3)
	h := head(t, l)
	header := l.Header().Encode()
	k := &keyKeeper{testStorage: newTestStorage()}
	for i := range uint64(3) {
		if err := k.Commit(Change{Start: i, Entries: []Entry{mustEntry(t, l, i)}}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	r, err := Restore(id, header, h.Encode(), k)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Get(1); err != nil {
		t.Fatal(err)
	}
	var out []byte
	if err := r.Read(2, &out); err != nil {
		t.Fatal(err)
	}
	k.change(0, func(e *Entry) { e.Ciphertext = flip(e.Ciphertext, 40) })
	if _, err := r.Get(0); !errors.Is(err, ErrStorageMismatch) {
		t.Fatal(err)
	}
	if len(k.keys) != 6 {
		t.Fatalf("%d keys handed out, want 6", len(k.keys))
	}
	for i, key := range k.keys {
		if !bytes.Equal(key, make([]byte, keySize)) {
			t.Errorf("key %d handed to the log was not cleared", i)
		}
	}
}

// Readers never see an entry before its commit returns, and see every committed one.
func TestStorageConcurrentUse(t *testing.T) {
	l, _ := newStorageLog(t, 1)
	r, _ := newStorageReplica(t, l)
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 1; i < 40; i++ {
			if _, err := l.Append([]byte(fmt.Sprintf("entry %d", i))); err != nil {
				t.Error(err)
			}
			if i%5 == 0 {
				if err := l.Delete(uint64(i - 3)); err != nil {
					t.Error(err)
				}
			}
		}
	})
	wg.Go(func() {
		for range 20 {
			if err := updateFrom(t, l, r.Len()).apply(r); err != nil {
				t.Error(err)
			}
		}
	})
	for range 4 {
		wg.Go(func() {
			for i := range 300 {
				for _, rd := range []interface {
					Len() uint64
					Get(uint64) ([]byte, error)
					EntryInfo(uint64) (EntryInfo, error)
				}{l, r} {
					n := rd.Len()
					if n == 0 {
						continue
					}
					index := uint64(i) % n
					if _, err := rd.Get(index); err != nil && !errors.Is(err, ErrDeleted) {
						t.Error(err)
					}
					if _, err := rd.EntryInfo(index); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestFailedCommitAfterChecks(t *testing.T) {
	l, _ := newLog(t, 3)
	r, rs := newStorageReplica(t, l)
	u := updateFrom(t, l, 0)
	key := u.entries[1].Key
	u.entries[1].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	rs.mu.Lock()
	rs.failCommit = errDisk
	rs.mu.Unlock()
	if err := r.AddKey(1, key); !errors.Is(err, errDisk) {
		t.Fatalf("AddKey with a failing commit: %v", err)
	}
	if info, _ := r.EntryInfo(1); info.Keyed {
		t.Fatal("a failed AddKey marked the key stored")
	}
	// A held head newer than the replica's head is committed before it is kept.
	appendN(t, l, 3, 2)
	r3, rs3 := newStorageReplica(t, l)
	if err := chunk(t, l, 0, 3).apply(r3); err != nil {
		t.Fatal(err)
	}
	if _, err := r3.Head(); !errors.Is(err, ErrNoHead) {
		t.Fatalf("a chunk set the head: %v", err)
	}
	held, err := restoreHead(t, l, 3)
	if err != nil {
		t.Fatal(err)
	}
	rs3.mu.Lock()
	rs3.failCommit = errDisk
	rs3.mu.Unlock()
	if err := r3.Update(held, ConsistencyProof{}, nil); !errors.Is(err, errDisk) {
		t.Fatalf("held head with a failing commit: %v", err)
	}
	if _, err := r3.Head(); !errors.Is(err, ErrNoHead) {
		t.Fatalf("a failed commit set the head: %v", err)
	}
}

func restoreHead(t testing.TB, l *Log, n uint64) (Head, error) {
	t.Helper()
	h := Head{LogKey: l.pub, LogID: l.logID, Size: n, Root: l.tree.Root(n)}
	var err error
	h.Signature, err = l.id.Sign(HeadContext, h.signed())
	return h, err
}

func TestMemoryStorageOutOfRange(t *testing.T) {
	s := NewMemory()
	if _, err := s.Entry(0); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("Entry of an empty storage: %v", err)
	}
	if _, err := s.Key(0); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("Key of an empty storage: %v", err)
	}
}

func TestRestoreRootMismatchFromStorage(t *testing.T) {
	l, id := newLog(t, 3)
	header := l.Header().Encode()
	snap := fill(t, l)
	h3 := head(t, l)
	appendN(t, l, 3, 1)
	all := fill(t, l)
	l.Close()
	fork, err := Restore(id, header, h3.Encode(), storeOf(snap))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fork.Append([]byte("forked entry 3")); err != nil {
		t.Fatal(err)
	}
	forked := head(t, fork)
	fork.Close()
	// Every stored entry is signed by the owner, but they do not rebuild the forked head's root.
	if _, err := Restore(id, header, forked.Encode(), storeOf(all)); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("Restore of a forked head: %v, want ErrRestoreMismatch", err)
	}
	if _, err := RestoreReplica(id.PublicKey(), forked.LogID, header, Heads{Head: &forked}, storeOf(all)); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("RestoreReplica of a forked head: %v, want ErrRestoreMismatch", err)
	}
}

func fill(t testing.TB, l *Log) []Entry {
	t.Helper()
	var out []Entry
	for i := range l.Len() {
		out = append(out, mustEntry(t, l, i))
	}
	return out
}

// Deleting or applying a marker again commits nothing.
func TestDeleteAgainCommitsNothing(t *testing.T) {
	l, s := newStorageLog(t, 2)
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	n := s.commits
	if err := l.Delete(0); err != nil || s.commits != n {
		t.Fatalf("second Delete: %v, %d commits", err, s.commits-n)
	}
	r, rs := newStorageReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	m := mustEntry(t, l, 0).Marker
	if err := r.ApplyDelete(m); err != nil {
		t.Fatal(err)
	}
	n = rs.commits
	if err := r.ApplyDelete(m); err != nil || rs.commits != n {
		t.Fatalf("ApplyDelete of an entry received deleted: %v, %d commits", err, rs.commits-n)
	}
}

// A stored form that disagrees with whether the log knows the entry as deleted is refused, even when each part is valid.
func TestStoredDeletionMustMatch(t *testing.T) {
	l, _ := newLog(t, 2)
	r, rs := newStorageReplica(t, l)
	u := updateFrom(t, l, 0)
	old := cloneEntry(u.entries[0])
	u.entries[0].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	// A valid marker on disk for an entry the replica holds live, without its key.
	rs.change(0, func(e *Entry) { *e = mustEntry(t, l, 0) })
	if _, err := r.Entry(0); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("a marker stored for a live entry: %v", err)
	}
	// An old live value without its key back on disk for an entry the replica holds deleted.
	if err := r.ApplyDelete(mustEntry(t, l, 0).Marker); err != nil {
		t.Fatal(err)
	}
	old.Key = nil
	rs.change(0, func(e *Entry) { *e = cloneEntry(old) })
	if _, err := r.Entry(0); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("an old value stored for a deleted entry: %v", err)
	}
}

// A stored target must lie past the stored entries; a signed head of size 0 as the target is refused and nothing is committed.
func TestRestoreReplicaEmptyTarget(t *testing.T) {
	s := newTestStorage()
	l, err := New(newID(t), NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	empty := head(t, l)
	if _, err := RestoreReplica(l.pub, l.ID(), l.Header().Encode(), Heads{Target: &empty}, s); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("a target of size 0: %v", err)
	}
	if s.commits != 0 {
		t.Fatalf("RestoreReplica committed %d changes", s.commits)
	}
}

func TestMemoryDeleteZeroesKey(t *testing.T) {
	l, s := newStorageLog(t, 1)
	key := s.memory.entries[0].Key
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, make([]byte, keySize)) {
		t.Fatal("the memory storage kept the deleted entry's key")
	}
}

// changeLog is a memory storage that keeps a deep copy of every change committed to it.
type changeLog struct {
	*memory
	changes []Change
}

func (s *changeLog) Commit(c Change) error {
	if err := s.memory.Commit(c); err != nil {
		return err
	}
	d := Change{Start: c.Start}
	for _, k := range c.Keys {
		d.Keys = append(d.Keys, KeyAt{Index: k.Index, Key: slices.Clone(k.Key)})
	}
	for _, e := range c.Entries {
		d.Entries = append(d.Entries, cloneEntry(e))
	}
	for _, x := range c.Deleted {
		d.Deleted = append(d.Deleted, Deletion{Index: x.Index, Record: slices.Clone(x.Record), Marker: slices.Clone(x.Marker)})
	}
	if c.Heads != nil {
		h := *c.Heads
		d.Heads = &h
	}
	s.changes = append(s.changes, d)
	return nil
}

func (s *changeLog) last(t testing.TB) Change {
	t.Helper()
	if len(s.changes) == 0 {
		t.Fatal("no change committed")
	}
	return s.changes[len(s.changes)-1]
}

// Every kind of change carries the log's length before it in Start, and only its own fields.
func TestChangeShapes(t *testing.T) {
	s := &changeLog{memory: &memory{}}
	l, err := New(newID(t), s)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 0, 3)
	c := s.last(t)
	if c.Start != 2 || len(c.Entries) != 1 || c.Entries[0].Key == nil || c.Entries[0].Ciphertext == nil ||
		c.Heads == nil || c.Heads.Head == nil || c.Heads.Head.Size != 3 || c.Heads.Target != nil || c.Deleted != nil || c.Keys != nil {
		t.Fatalf("Append committed %+v", c)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	c = s.last(t)
	if c.Start != 3 || c.Entries != nil || c.Keys != nil || c.Heads != nil || len(c.Deleted) != 1 || c.Deleted[0].Index != 1 ||
		c.Deleted[0].Marker == nil || !bytes.Equal(c.Deleted[0].Record, record(t, l, 1).Encode()) {
		t.Fatalf("Delete committed %+v", c)
	}

	rs := &changeLog{memory: &memory{}}
	r, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), rs)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3, 2)
	u := chunk(t, l, 0, 3)
	key := u.entries[2].Key
	u.entries[2].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	c = rs.last(t)
	if c.Start != 0 || len(c.Entries) != 3 || c.Entries[2].Key != nil || c.Deleted != nil || c.Keys != nil ||
		c.Heads == nil || c.Heads.Head != nil || c.Heads.Target == nil || c.Heads.Target.Size != 5 || c.Heads.Proof.OldSize != 3 {
		t.Fatalf("a chunk committed %+v", c)
	}
	if err := chunk(t, l, 3, 5).apply(r); err != nil {
		t.Fatal(err)
	}
	c = rs.last(t)
	if c.Start != 3 || len(c.Entries) != 2 || c.Heads == nil || c.Heads.Head == nil || c.Heads.Head.Size != 5 || c.Heads.Target != nil {
		t.Fatalf("the last chunk committed %+v", c)
	}
	if err := r.AddKey(2, key); err != nil {
		t.Fatal(err)
	}
	c = rs.last(t)
	if c.Start != 5 || len(c.Keys) != 1 || c.Keys[0].Index != 2 || !bytes.Equal(c.Keys[0].Key, key) || c.Entries != nil || c.Deleted != nil || c.Heads != nil {
		t.Fatalf("AddKey committed %+v", c)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, l, 0).Marker); err != nil {
		t.Fatal(err)
	}
	c = rs.last(t)
	if c.Start != 5 || len(c.Deleted) != 1 || c.Deleted[0].Index != 0 || c.Deleted[0].Marker == nil || c.Entries != nil || c.Keys != nil || c.Heads != nil {
		t.Fatalf("ApplyDelete committed %+v", c)
	}
	// A held head newer than the replica's head commits only the heads.
	r2s := &changeLog{memory: &memory{}}
	r2, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), r2s)
	if err != nil {
		t.Fatal(err)
	}
	if err := chunk(t, l, 0, 3).apply(r2); err != nil {
		t.Fatal(err)
	}
	held, err := restoreHead(t, l, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Update(held, ConsistencyProof{}, nil); err != nil {
		t.Fatal(err)
	}
	c = r2s.last(t)
	if c.Start != 3 || c.Entries != nil || c.Deleted != nil || c.Keys != nil || c.Heads == nil || c.Heads.Head == nil ||
		c.Heads.Head.Size != 3 || c.Heads.Target == nil || c.Heads.Target.Size != 5 {
		t.Fatalf("a held head committed %+v", c)
	}
}

// keeper is a storage that keeps the Change slices it is given, which the Storage contract forbids.
type keeper struct {
	*memory
	keys []EntryKey
}

func (k *keeper) Commit(c Change) error {
	for _, e := range c.Entries {
		if e.Key != nil {
			k.keys = append(k.keys, e.Key)
		}
	}
	for _, x := range c.Keys {
		k.keys = append(k.keys, x.Key)
	}
	return k.memory.Commit(c)
}

// The log zeroes the keys of a Change after Commit returns, so a storage must copy what it keeps.
func TestCommitKeysZeroedAfterCommit(t *testing.T) {
	l, _ := newLog(t, 2)
	k := &keeper{memory: &memory{}}
	r, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), k)
	if err != nil {
		t.Fatal(err)
	}
	u := updateFrom(t, l, 0)
	key := u.entries[1].Key
	u.entries[1].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKey(1, key); err != nil {
		t.Fatal(err)
	}
	k2 := &keeper{memory: &memory{}}
	l2, err := New(newID(t), k2)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	appendN(t, l2, 0, 1)
	all := append(k.keys, k2.keys...)
	if len(all) != 3 {
		t.Fatalf("%d keys committed, want 3", len(all))
	}
	for i, key := range all {
		if !bytes.Equal(key, make([]byte, keySize)) {
			t.Errorf("committed key %d was not zeroed after Commit", i)
		}
	}
}

func TestStorageNotEmpty(t *testing.T) {
	l, s := newStorageLog(t, 2)
	if _, err := New(newID(t), s); !errors.Is(err, ErrStorageNotEmpty) {
		t.Fatalf("New on a storage with entries: %v", err)
	}
	if _, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), s); !errors.Is(err, ErrStorageNotEmpty) {
		t.Fatalf("NewReplica on a storage with entries: %v", err)
	}
	m := NewMemory()
	if err := m.Commit(Change{Start: 1, Entries: []Entry{mustEntry(t, l, 0)}}); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("memory Commit of entries past its length: %v", err)
	}
	if err := m.Commit(Change{Start: 0, Entries: []Entry{mustEntry(t, l, 0)}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Commit(Change{Start: 0, Entries: []Entry{mustEntry(t, l, 1)}}); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("memory Commit over a stored entry: %v", err)
	}
	if e, err := m.Entry(0); err != nil || !bytes.Equal(e.Record, mustEntry(t, l, 0).Record) {
		t.Fatalf("a refused Commit changed the memory storage: %v", err)
	}
	if _, err := m.Entry(1); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("a refused Commit stored an entry: %v", err)
	}
}

func infos(t testing.TB, rd interface {
	Len() uint64
	EntryInfo(uint64) (EntryInfo, error)
}) []bool {
	t.Helper()
	var out []bool
	for i := range rd.Len() {
		info, err := rd.EntryInfo(i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, info.Deleted)
	}
	return out
}

// Delete of several indexes signs every marker and stores them in one commit, or changes nothing.
func TestDeleteMany(t *testing.T) {
	l, s := newStorageLog(t, 10)
	n := s.commits
	if err := l.Delete(1, 3, 3, 5, 9); err != nil {
		t.Fatal(err)
	}
	if s.commits != n+1 {
		t.Fatalf("Delete of 4 entries made %d commits, want 1", s.commits-n)
	}
	want := []bool{false, true, false, true, false, true, false, false, false, true}
	if got := infos(t, l); !slices.Equal(got, want) {
		t.Fatalf("deleted %v, want %v", got, want)
	}
	for _, i := range []uint64{1, 3, 5, 9} {
		e := s.stored(i)
		m, err := DecodeDeleteMarker(e.Marker)
		if err != nil || e.Key != nil || e.Ciphertext != nil || !VerifyDeleteMarker(l.pub, l.ID(), record(t, l, i), m) {
			t.Fatalf("entry %d is not stored as its record and a valid marker: %v", i, err)
		}
	}
	n = s.commits
	if err := l.Delete(); err != nil || s.commits != n {
		t.Fatalf("Delete of nothing: %v, %d commits", err, s.commits-n)
	}
	if err := l.Delete(1, 9); err != nil || s.commits != n {
		t.Fatalf("Delete of deleted entries: %v, %d commits", err, s.commits-n)
	}
	if err := l.Delete(2, 10); !errors.Is(err, ErrOutOfRange) || s.commits != n {
		t.Fatalf("Delete with an index out of range: %v, %d commits", err, s.commits-n)
	}
	s.setFail(errDisk)
	if err := l.Delete(0, 2, 4); !errors.Is(err, errDisk) {
		t.Fatalf("Delete with a failing commit: %v", err)
	}
	s.setFail(nil)
	if got := infos(t, l); !slices.Equal(got, want) {
		t.Fatalf("a refused or failed Delete changed the log: %v", got)
	}
	for _, i := range []uint64{0, 2, 4} {
		if got, err := l.Get(i); err != nil || string(got) != fmt.Sprintf("entry %d", i) {
			t.Fatalf("Get(%d) after a failed Delete = %q, %v", i, got, err)
		}
	}
	if err := l.Delete(0, 1, 2); err != nil {
		t.Fatal(err)
	}
	if got := infos(t, l); !got[0] || !got[2] {
		t.Fatalf("Delete with a deleted entry among them: %v", got)
	}
}

// ApplyDelete of several markers verifies all of them first and stores them in one commit, or changes nothing.
func TestApplyDeleteMany(t *testing.T) {
	l, _ := newLog(t, 6)
	r, rs := newStorageReplica(t, l)
	if err := chunk(t, l, 0, 6).apply(r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0, 2, 4); err != nil {
		t.Fatal(err)
	}
	ms := [][]byte{mustEntry(t, l, 0).Marker, mustEntry(t, l, 2).Marker, mustEntry(t, l, 4).Marker}
	appendN(t, l, 6, 1)
	if err := l.Delete(6); err != nil {
		t.Fatal(err)
	}
	past := mustEntry(t, l, 6).Marker
	n := rs.commits
	for name, bad := range map[string][]byte{
		"tampered marker":         flip(ms[1], len(ms[1])-1),
		"malformed marker":        ms[1][:10],
		"marker past the entries": past,
	} {
		if err := r.ApplyDelete(ms[0], bad, ms[2]); err == nil || rs.commits != n {
			t.Fatalf("%s: ApplyDelete = %v, %d commits", name, err, rs.commits-n)
		}
	}
	rs.setFail(errDisk)
	if err := r.ApplyDelete(ms...); !errors.Is(err, errDisk) {
		t.Fatalf("ApplyDelete with a failing commit: %v", err)
	}
	rs.setFail(nil)
	if got := infos(t, r); slices.Contains(got, true) {
		t.Fatalf("a refused or failed ApplyDelete changed the replica: %v", got)
	}
	n = rs.commits
	if err := r.ApplyDelete(ms[0], ms[2], ms[0], ms[1]); err != nil || rs.commits != n+1 {
		t.Fatalf("ApplyDelete of 3 markers: %v, %d commits", err, rs.commits-n)
	}
	if got := infos(t, r); !slices.Equal(got, []bool{true, false, true, false, true, false}) {
		t.Fatalf("deleted %v", got)
	}
	if err := r.ApplyDelete(ms...); err != nil || rs.commits != n+1 {
		t.Fatalf("ApplyDelete of applied markers: %v, %d commits", err, rs.commits-n-1)
	}
}

// A repeated index or marker is deleted once, in one Deletion.
func TestDeleteRepeatedOnce(t *testing.T) {
	s := &changeLog{memory: &memory{}}
	l, err := New(newID(t), s)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 0, 3)
	if err := l.Delete(2, 0, 2, 0); err != nil {
		t.Fatal(err)
	}
	if c := s.last(t); len(c.Deleted) != 2 || c.Deleted[0].Index != 2 || c.Deleted[1].Index != 0 {
		t.Fatalf("Delete(2, 0, 2, 0) committed %+v", c.Deleted)
	}
	l2, _ := newLog(t, 3)
	rs2 := &changeLog{memory: &memory{}}
	r2, err := NewReplica(l2.pub, l2.ID(), l2.Header().Encode(), rs2)
	if err != nil {
		t.Fatal(err)
	}
	if err := chunk(t, l2, 0, 3).apply(r2); err != nil {
		t.Fatal(err)
	}
	if err := l2.Delete(1); err != nil {
		t.Fatal(err)
	}
	m := mustEntry(t, l2, 1).Marker
	if err := r2.ApplyDelete(m, m); err != nil {
		t.Fatal(err)
	}
	if c := rs2.last(t); len(c.Deleted) != 1 || c.Deleted[0].Index != 1 {
		t.Fatalf("ApplyDelete(m, m) committed %+v", c.Deleted)
	}
}

// ApplyDelete checks every marker before it skips one for a deleted or repeated entry, so a bad marker always fails the batch.
func TestApplyDeleteChecksEveryMarker(t *testing.T) {
	l, _ := newLog(t, 4)
	r, rs := newStorageReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete(0, 1); err != nil {
		t.Fatal(err)
	}
	m0, m1 := mustEntry(t, l, 0).Marker, mustEntry(t, l, 1).Marker
	if err := r.ApplyDelete(m0); err != nil {
		t.Fatal(err)
	}
	n := rs.commits
	if err := r.ApplyDelete(flip(m0, len(m0)-1)); !errors.Is(err, ErrBadEntry) {
		t.Errorf("a bad marker for a deleted entry: %v", err)
	}
	if err := r.ApplyDelete(m1, flip(m1, len(m1)-1)); !errors.Is(err, ErrBadEntry) {
		t.Errorf("a good then a bad marker for one entry: %v", err)
	}
	l2, err := New(l.id, NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, 0, 4)
	if err := l2.Delete(2); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, l2, 2).Marker); !errors.Is(err, ErrBadEntry) {
		t.Errorf("a marker of another log of the same owner: %v", err)
	}
	if info, _ := r.EntryInfo(1); info.Deleted || rs.commits != n {
		t.Errorf("refused batches changed the replica: entry 1 deleted %v, %d commits", info.Deleted, rs.commits-n)
	}
	r.Close()
	if err := r.ApplyDelete(); !errors.Is(err, ErrLogClosed) {
		t.Errorf("ApplyDelete of nothing on a closed replica: %v", err)
	}
	l.Close()
	if err := l.Delete(); !errors.Is(err, ErrLogClosed) {
		t.Errorf("Delete of nothing on a closed log: %v", err)
	}
}

// New and NewReplica take only the answer "no entry at index 0" as an empty storage; a storage that fails to read refuses them.
func TestNewChecksStorageReadFails(t *testing.T) {
	l, _ := newLog(t, 1)
	s := newTestStorage()
	s.setFail(errDisk)
	if _, err := New(newID(t), s); !errors.Is(err, errDisk) {
		t.Fatalf("New on a failing storage: %v", err)
	}
	if _, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), s); !errors.Is(err, errDisk) {
		t.Fatalf("NewReplica on a failing storage: %v", err)
	}
	s.setFail(nil)
	if _, err := s.Entry(0); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("an empty memory storage answers %v for index 0, want ErrOutOfRange", err)
	}
	n, err := New(newID(t), s)
	if err != nil {
		t.Fatalf("New on an empty storage: %v", err)
	}
	n.Close()
}

// An entry the log holds that the storage answers as out of range is lost, and reads say so without ErrOutOfRange.
func TestLostEntryIsMismatch(t *testing.T) {
	l, s := newStorageLog(t, 3)
	s.memory.mu.Lock()
	s.memory.entries = s.memory.entries[:1]
	s.memory.mu.Unlock()
	var out []byte
	_, gerr := l.Get(2)
	_, eerr := l.Entry(1)
	_, kerr := l.Key(2)
	rerr := l.Read(1, &out)
	for name, err := range map[string]error{"Get": gerr, "Entry": eerr, "Key": kerr, "Read": rerr} {
		if !errors.Is(err, ErrStorageMismatch) || errors.Is(err, ErrOutOfRange) {
			t.Errorf("%s of a lost entry: %v, want ErrStorageMismatch and not ErrOutOfRange", name, err)
		}
	}
	if _, err := l.Get(3); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("Get past the end: %v, want ErrOutOfRange", err)
	}
}
