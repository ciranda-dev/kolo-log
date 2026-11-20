package kololog

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
)

type exported struct {
	id      *koloid.Identity
	log     *Log
	header  []byte
	head    Head
	entries []Entry
}

func export(t testing.TB, e ValueEncoding, values []any, deleted ...uint64) exported {
	t.Helper()
	id := newID(t)
	l, err := New(id, NewMemory(), WithValueEncoding(e))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for _, v := range values {
		if _, err := l.Append(v); err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range deleted {
		if err := l.Delete(i); err != nil {
			t.Fatal(err)
		}
	}
	x := exported{id: id, log: l, header: l.Header().Encode(), head: head(t, l)}
	for i := range l.Len() {
		en, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		x.entries = append(x.entries, en)
	}
	return x
}

func cloneEntries(entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		out[i] = Entry{Record: bytes.Clone(e.Record), Ciphertext: bytes.Clone(e.Ciphertext), Marker: bytes.Clone(e.Marker), Key: bytes.Clone(e.Key)}
	}
	return out
}

func TestEntry(t *testing.T) {
	l, _ := newLog(t, 3)
	e, err := l.Entry(1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.Record, record(t, l, 1).Encode()) || len(e.Ciphertext) != int(record(t, l, 1).Size) {
		t.Fatal("Entry does not match the record")
	}
	e.Ciphertext[0] ^= 1
	if got, err := l.Get(1); err != nil || string(got) != "entry 1" {
		t.Fatalf("changing a returned entry changed the log: %q, %v", got, err)
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if e, err := l.Entry(1); err != nil || e.Ciphertext != nil || e.Record == nil {
		t.Fatalf("Entry after Delete = %v, %v", e, err)
	}
	if _, err := l.Entry(3); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Entry past the end returned %v", err)
	}
}

func TestRestore(t *testing.T) {
	x := export(t, UTF8, []any{"a", "b", "c", "d", "e"}, 1, 3)
	entries := cloneEntries(x.entries)
	x.log.Close()
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries), WithValueEncoding(UTF8))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	entries[0].Record[len(entries[0].Record)-1] ^= 1
	entries[0].Ciphertext[0] ^= 1

	old, err := VerifyHead(x.id.PublicKey(), x.log.ID(), head(t, l))
	if err != nil {
		t.Fatal(err)
	}
	if old.Size() != x.head.Size || old.Root() != x.head.Root || l.ID() != x.log.ID() || l.Len() != 5 {
		t.Fatal("restored log does not match the exported one")
	}
	if !bytes.Equal(l.Header().Encode(), x.header) {
		t.Fatal("restored header differs")
	}
	for i := range l.Len() {
		var s string
		err := l.Read(i, &s)
		if i == 1 || i == 3 {
			if !errors.Is(err, ErrDeleted) {
				t.Errorf("Read(%d) of a deleted entry returned %v, want ErrDeleted", i, err)
			}
		} else if want := string(rune('a' + i)); err != nil || s != want {
			t.Errorf("Read(%d) on a restored entry = %q, %v, want %q", i, s, err, want)
		}
		e, err := l.Entry(i)
		if err != nil || !bytes.Equal(e.Record, x.entries[i].Record) || !bytes.Equal(e.Ciphertext, x.entries[i].Ciphertext) || !bytes.Equal(e.Key, x.entries[i].Key) {
			t.Errorf("Entry(%d) differs after Restore: %v", i, err)
		}
		p, err := l.InclusionProof(i, old.Size())
		if err != nil || !VerifyInclusion(old, record(t, l, i), p) {
			t.Errorf("inclusion proof %d after Restore: %v", i, err)
		}
	}

	i, err := l.Append("f")
	if err != nil || i != 5 {
		t.Fatalf("Append after Restore = %d, %v", i, err)
	}
	var s string
	if err := l.Read(5, &s); err != nil || s != "f" {
		t.Fatalf("Read of a new entry = %q, %v", s, err)
	}
	cur, err := VerifyHead(x.id.PublicKey(), l.ID(), head(t, l))
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.ConsistencyProof(old.Size(), cur.Size())
	if err != nil || !VerifyConsistency(old, cur, c) {
		t.Fatalf("consistency from the exported head: %v", err)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := l.Read(0, &s); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Read after deleting a restored entry returned %v", err)
	}
	if e, _ := l.Entry(0); e.Ciphertext != nil {
		t.Fatal("Delete kept the ciphertext of a restored entry")
	}
}

func TestRestoreEmpty(t *testing.T) {
	x := export(t, Bytes, nil)
	x.log.Close()
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(nil))
	if err != nil || l.Len() != 0 {
		t.Fatalf("Restore of an empty log: %v", err)
	}
	defer l.Close()
	if _, err := l.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreErrors(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b"), []byte("c")}, 2)
	headBytes := x.head.Encode()
	other := export(t, Bytes, []any{[]byte("a"), []byte("b"), []byte("c")})
	sameID := newLogFor(t, x.id, 3)
	sameIDEntry, err := sameID.Entry(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.log.Append([]byte("d")); err != nil {
		t.Fatal(err)
	}
	larger := head(t, x.log)

	type change func(id **koloid.Identity, header, head *[]byte, entries *[]Entry, opts *[]Option)
	cases := []struct {
		name   string
		change change
		want   error
	}{
		{"nil identity", func(id **koloid.Identity, _, _ *[]byte, _ *[]Entry, _ *[]Option) { *id = nil }, koloid.ErrInvalidIdentity},
		{"zero identity", func(id **koloid.Identity, _, _ *[]byte, _ *[]Entry, _ *[]Option) { *id = &koloid.Identity{} }, koloid.ErrInvalidIdentity},
		{"unknown encoding", func(_ **koloid.Identity, _, _ *[]byte, _ *[]Entry, o *[]Option) {
			*o = []Option{WithValueEncoding(JSON + 1)}
		}, ErrUnknownEncoding},
		{"empty header", func(_ **koloid.Identity, h, _ *[]byte, _ *[]Entry, _ *[]Option) { *h = nil }, ErrMissingHeader},
		{"malformed header", func(_ **koloid.Identity, h, _ *[]byte, _ *[]Entry, _ *[]Option) { *h = (*h)[:10] }, ErrMalformed},
		{"header of another key", func(_ **koloid.Identity, h, _ *[]byte, _ *[]Entry, _ *[]Option) { *h = other.header }, ErrBadLogHeader},
		{"encoding mismatch", func(_ **koloid.Identity, _, _ *[]byte, _ *[]Entry, o *[]Option) {
			*o = []Option{WithValueEncoding(JSON)}
		}, ErrEncodingMismatch},
		{"malformed head", func(_ **koloid.Identity, _, hd *[]byte, _ *[]Entry, _ *[]Option) { *hd = (*hd)[:10] }, ErrMalformed},
		{"head signed by another key", func(_ **koloid.Identity, _, hd *[]byte, _ *[]Entry, _ *[]Option) {
			*hd = other.head.Encode()
		}, ErrBadHeadSignature},
		{"head of another log", func(_ **koloid.Identity, _, hd *[]byte, _ *[]Entry, _ *[]Option) {
			*hd = head(t, sameID).Encode()
		}, ErrWrongLogID},
		// The head covers an entry the storage does not hold: damage, not an index past the end.
		{"head larger than the stored entries", func(_ **koloid.Identity, _, hd *[]byte, _ *[]Entry, _ *[]Option) {
			*hd = larger.Encode()
		}, ErrRestoreMismatch},
		{"missing entry", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) { *e = (*e)[:2] }, ErrRestoreMismatch},
		{"entry past the head in its place", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[2] = (*e)[0]
		}, ErrRestoreMismatch},
		{"tampered record byte", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[1].Record[len((*e)[1].Record)-70] ^= 1
		}, ErrRestoreMismatch},
		{"tampered record signature", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[1].Record[len((*e)[1].Record)-1] ^= 1
		}, ErrRestoreMismatch},
		{"record of another log", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[1] = sameIDEntry
		}, ErrRestoreMismatch},
		{"wrong index order", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[0], (*e)[1] = (*e)[1], (*e)[0]
		}, ErrRestoreMismatch},
		{"tampered ciphertext", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[0].Ciphertext[5] ^= 1
		}, ErrRestoreMismatch},
		{"short ciphertext", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[0].Ciphertext = (*e)[0].Ciphertext[:len((*e)[0].Ciphertext)-1]
		}, ErrRestoreMismatch},
		{"empty ciphertext", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			(*e)[0].Ciphertext = []byte{}
		}, ErrRestoreMismatch},
		{"non-canonical record bytes", func(_ **koloid.Identity, _, _ *[]byte, e *[]Entry, _ *[]Option) {
			r := (*e)[1].Record
			at := 1 + len(RecordContext) + 32 + LogIDSize // the 1-byte uvarint index
			(*e)[1].Record = append(append(bytes.Clone(r[:at]), r[at]|0x80, 0x00), r[at+1:]...)
		}, ErrRestoreMismatch},
	}
	for _, c := range cases {
		id, header, hd, entries, opts := x.id, bytes.Clone(x.header), bytes.Clone(headBytes), cloneEntries(x.entries), []Option(nil)
		c.change(&id, &header, &hd, &entries, &opts)
		l, err := Restore(id, header, hd, storeOf(entries), opts...)
		if !errors.Is(err, c.want) || l != nil || errors.Is(err, ErrOutOfRange) {
			t.Errorf("%s: Restore = %v, %v; want nil, %v", c.name, l, err, c.want)
		}
	}
}

// Only the final root check can catch a correctly signed head over another root.
func TestRestoreRootMismatch(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b")})
	h := x.head
	h.Root[0] ^= 1
	var err error
	if h.Signature, err = x.id.Sign(HeadContext, h.signed()); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(x.id, x.header, h.Encode(), storeOf(x.entries)); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("Restore with a signed wrong root returned %v, want %v", err, ErrRestoreMismatch)
	}
}

func TestRestoreRollback(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a")})
	older := x.head
	if _, err := x.log.Append([]byte("b")); err != nil {
		t.Fatal(err)
	}
	x = reexport(t, x)
	if _, err := x.log.Append([]byte("c")); err != nil {
		t.Fatal(err)
	}
	newer := head(t, x.log)

	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), WithTrustedHead(newer)); !errors.Is(err, ErrRollback) {
		t.Fatalf("snapshot older than the trusted head: %v, want %v", err, ErrRollback)
	}

	fork := &Log{id: x.id, pub: x.id.PublicKey(), logID: x.log.ID(), s: NewMemory()}
	for _, v := range []string{"x", "y"} {
		if _, err := fork.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), WithTrustedHead(head(t, fork))); !errors.Is(err, ErrRollback) {
		t.Fatalf("same-size fork: %v, want %v", err, ErrRollback)
	}

	other := newLogFor(t, x.id, 2)
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), WithTrustedHead(head(t, other))); !errors.Is(err, ErrWrongLogID) {
		t.Fatalf("trusted head of another log: %v, want %v", err, ErrWrongLogID)
	}

	x.log.Close()
	for _, trusted := range []Head{older, x.head} {
		l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), WithTrustedHead(trusted))
		if err != nil {
			t.Fatalf("trusted head of size %d that the snapshot extends: %v", trusted.Size, err)
		}
		l.Close()
	}
}

func reexport(t testing.TB, x exported) exported {
	t.Helper()
	x.head = head(t, x.log)
	x.entries = nil
	for i := range x.log.Len() {
		en, err := x.log.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		x.entries = append(x.entries, en)
	}
	return x
}

func TestOneWritableLogPerID(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b")})
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Restore while the New log is open: %v, want %v", err, ErrLogOpen)
	}
	if err := x.log.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("second Restore of one snapshot: %v, want %v", err, ErrLogOpen)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := first.Append([]byte("c")); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("Append after Close: %v, want %v", err, ErrLogClosed)
	}
	if _, err := first.Head(); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("Head after Close: %v, want %v", err, ErrLogClosed)
	}
	if err := first.Delete(0); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("Delete after Close: %v, want %v", err, ErrLogClosed)
	}
	if _, err := first.Record(0); err != nil {
		t.Fatalf("Record after Close: %v", err)
	}
	second, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries))
	if err != nil {
		t.Fatalf("Restore after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// recording is a memory storage that keeps a copy of every change committed to it.
type recording struct {
	Storage
	mu      sync.Mutex
	changes []Change
}

func (r *recording) Commit(c Change) error {
	if err := r.Storage.Commit(c); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, Change{Start: c.Start, Entries: cloneEntries(c.Entries), Heads: c.Heads})
	return nil
}

// Concurrent appends each commit one entry with the head signed right after it, so every stored prefix restores.
func TestAppendCommitsEntryWithItsHead(t *testing.T) {
	id := newID(t)
	rec := &recording{Storage: NewMemory()}
	l, err := New(id, rec)
	if err != nil {
		t.Fatal(err)
	}
	header := l.Header().Encode()
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 10 {
				if _, err := l.Append([]byte(fmt.Sprintf("w%d e%d", w, i))); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	l.Close()
	if len(rec.changes) != 40 {
		t.Fatalf("%d commits, want 40", len(rec.changes))
	}
	var entries []Entry
	for i, c := range rec.changes {
		if c.Start != uint64(i) || len(c.Entries) != 1 || c.Heads == nil || c.Heads.Head == nil || c.Heads.Head.Size != c.Start+1 || c.Heads.Target != nil {
			t.Fatalf("commit %d: start %d, %d entries, heads %+v", i, c.Start, len(c.Entries), c.Heads)
		}
		entries = append(entries, c.Entries[0])
		restored, err := Restore(id, header, c.Heads.Head.Encode(), storeOf(entries))
		if err != nil {
			t.Fatalf("entry %d and its head do not restore: %v", c.Start, err)
		}
		restored.Close()
	}
}

func TestRestoreRejectsDroppedCiphertext(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b")})
	x.log.Close()
	entries := cloneEntries(x.entries)
	entries[1].Ciphertext = nil
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries))
	if !errors.Is(err, ErrRestoreMismatch) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("live entry with its ciphertext dropped: %v, want %v", err, ErrRestoreMismatch)
	}
}

func TestRestoreChecksEveryTrustedHead(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a")})
	older := x.head
	if _, err := x.log.Append([]byte("b")); err != nil {
		t.Fatal(err)
	}
	x = reexport(t, x)
	if _, err := x.log.Append([]byte("c")); err != nil {
		t.Fatal(err)
	}
	newer := head(t, x.log)
	x.log.Close()
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), WithTrustedHead(newer), WithTrustedHead(older))
	if !errors.Is(err, ErrRollback) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("newer then older trusted head: %v, want %v", err, ErrRollback)
	}
}

func TestRestoreStoresWhatItVerified(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b"), []byte("c")}, 1)
	x.log.Close()
	entries := cloneEntries(x.entries)
	restoreHook = func(_ *Log, i int) {
		for _, b := range [][]byte{entries[i].Ciphertext, entries[i].Marker, entries[i].Record} {
			if len(b) > 0 {
				b[len(b)-1] ^= 1
			}
		}
	}
	defer func() { restoreHook = nil }()
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		want := x.entries[i]
		if !bytes.Equal(e.Ciphertext, want.Ciphertext) || !bytes.Equal(e.Marker, want.Marker) || !bytes.Equal(e.Record, want.Record) {
			t.Fatalf("entry %d holds data changed after it was verified", i)
		}
	}
}

func TestRestoreEmptyMeansAbsent(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b")}, 1)
	x.log.Close()
	entries := cloneEntries(x.entries)
	entries[0].Marker = []byte{}
	entries[1].Ciphertext = []byte{}
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries))
	if err != nil {
		t.Fatalf("empty slices as absent: %v", err)
	}
	defer l.Close()
	live, _ := l.Entry(0)
	deleted, _ := l.Entry(1)
	if live.Marker != nil || deleted.Ciphertext != nil {
		t.Fatal("empty slices were stored as present")
	}
	if _, err := l.Get(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get of a deleted entry: %v, want %v", err, ErrDeleted)
	}
}

func TestRestoreKeys(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b"), []byte("c")}, 2)
	x.log.Close()
	if x.entries[0].Key == nil || x.entries[2].Key != nil {
		t.Fatal("Entry must carry the key of a live entry and none for a deleted one")
	}
	noKey := cloneEntries(x.entries)
	noKey[1].Key = nil
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(noKey)); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("Restore of an own log with a live entry stored without its key: %v, want ErrRestoreMismatch", err)
	}
	r, err := restoreReplica(t, x.id.PublicKey(), x.log.ID(), x.header, x.head.Encode(), noKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Get(0); err != nil || string(got) != "a" {
		t.Fatalf("Get(0) with its stored key = %q, %v", got, err)
	}
	if _, err := r.Get(1); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Get(1) stored without a key: %v, want ErrKeyUnavailable", err)
	}

	other := export(t, Bytes, []any{[]byte("z")})
	for name, change := range map[string]func([]Entry){
		"wrong key":            func(e []Entry) { e[0].Key = other.entries[0].Key },
		"key of another index": func(e []Entry) { e[0].Key = e[1].Key },
		"short key":            func(e []Entry) { e[0].Key = e[0].Key[:31] },
		"key on deleted entry": func(e []Entry) { e[2].Key = e[0].Key },
	} {
		entries := cloneEntries(x.entries)
		change(entries)
		if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries)); !errors.Is(err, ErrRestoreMismatch) {
			t.Errorf("%s: Restore returned %v, want ErrRestoreMismatch", name, err)
		}
	}
}
