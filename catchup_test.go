package kololog

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// chunk is entries [from, to) of l with the proof from to up to l's current head.
func chunk(t testing.TB, l *Log, from, to uint64) update {
	t.Helper()
	u := update{head: head(t, l)}
	var err error
	if u.proof, err = l.ConsistencyProof(to, u.head.Size); err != nil {
		t.Fatal(err)
	}
	for i := from; i < to; i++ {
		u.entries = append(u.entries, mustEntry(t, l, i))
	}
	return u
}

func TestReplicaCatchUpInChunks(t *testing.T) {
	l, _ := newLog(t, 20)
	r := newReplica(t, l)
	h := head(t, l)
	for _, to := range []uint64{5, 12} {
		before := state(t, r)
		bad := chunk(t, l, r.Len(), to)
		bad.proof.Path[0][0] ^= 1
		if err := bad.apply(r); !errors.Is(err, ErrBadProof) || state(t, r) != before {
			t.Fatalf("chunk to %d with a bad proof: %v, or the replica changed", to, err)
		}
		if err := chunk(t, l, r.Len(), to).apply(r); err != nil {
			t.Fatalf("chunk to %d: %v", to, err)
		}
		if r.Len() != to {
			t.Fatalf("Len = %d after a chunk to %d", r.Len(), to)
		}
		if _, err := r.Head(); !errors.Is(err, ErrNoHead) {
			t.Fatalf("Head during the first catch-up: %v, want ErrNoHead", err)
		}
		th, tp, ok := r.Target()
		if !ok || !bytes.Equal(th.Encode(), h.Encode()) || tp.OldSize != to || tp.NewSize != h.Size {
			t.Fatalf("Target = %v, %v, %v", th, tp, ok)
		}
		if got, err := r.Get(to - 1); err != nil || string(got) != fmt.Sprintf("entry %d", to-1) {
			t.Fatalf("Get(%d) during the catch-up: %q, %v", to-1, got, err)
		}
	}

	// Restart in the middle: restore what has a head (nothing yet), then replay the target.
	th, tp, _ := r.Target()
	var held []Entry
	for i := range r.Len() {
		held = append(held, mustEntry(t, r.log, i))
	}
	r2, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Update(th, tp, held); err != nil {
		t.Fatalf("replaying the target after a restart: %v", err)
	}
	if state(t, r2) != state(t, r) {
		t.Fatal("replayed replica differs")
	}

	if err := chunk(t, l, 12, 20).apply(r2); err != nil {
		t.Fatalf("last chunk: %v", err)
	}
	if got, err := r2.Head(); err != nil || !bytes.Equal(got.Encode(), h.Encode()) {
		t.Fatalf("Head after the catch-up: %v", err)
	}
	if _, _, ok := r2.Target(); ok {
		t.Fatal("Target still set after the catch-up")
	}
	for i := range r2.Len() {
		if got, err := r2.Get(i); err != nil || string(got) != fmt.Sprintf("entry %d", i) {
			t.Fatalf("Get(%d) = %q, %v", i, got, err)
		}
	}
}

func TestReplicaCatchUpTargetMoves(t *testing.T) {
	l, _ := newLog(t, 10)
	r := newReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 10, 10)
	if err := chunk(t, l, 10, 14).apply(r); err != nil {
		t.Fatal(err)
	}
	if h, err := r.Head(); err != nil || h.Size != 10 {
		t.Fatalf("Head while filling a target = %v, %v, want the head of size 10", h.Size, err)
	}
	// The writer grew again: the next chunk fills the newer head.
	appendN(t, l, 20, 5)
	if err := chunk(t, l, 14, 25).apply(r); err != nil {
		t.Fatalf("chunk toward a newer head: %v", err)
	}
	if h, err := r.Head(); err != nil || h.Size != 25 {
		t.Fatalf("Head = %d, %v, want 25", h.Size, err)
	}
	// A head the replica holds every entry of, newer than its head, becomes the head.
	appendN(t, l, 25, 3)
	mid := head(t, l)
	appendN(t, l, 28, 3)
	if err := chunk(t, l, 25, 30).apply(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(mid, ConsistencyProof{}, nil); err != nil {
		t.Fatalf("a held head: %v", err)
	}
	if h, _ := r.Head(); h.Size != 28 {
		t.Fatalf("Head = %d, want the held head of size 28", h.Size)
	}
}

func TestReplicaOlderForkDiverges(t *testing.T) {
	l, id := newLog(t, 3)
	r := newReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	snap := mustReplicaHead(t, r)
	snapEntries := updateFrom(t, l, 0).entries
	appendN(t, l, 3, 2)
	h5 := head(t, l)
	appendN(t, l, 5, 3)
	if err := updateFrom(t, l, 3).apply(r); err != nil {
		t.Fatal(err)
	}
	l.Close()
	fork, err := Restore(id, l.Header().Encode(), snap.Encode(), storeOf(snapEntries))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fork.Close() })
	appendN(t, fork, 50, 2)
	forked5 := head(t, fork)
	before := state(t, r)
	if err := r.Update(forked5, ConsistencyProof{}, nil); !errors.Is(err, ErrDiverged) {
		t.Fatalf("an older head of another history: %v, want ErrDiverged", err)
	}
	if err := r.Update(h5, ConsistencyProof{}, nil); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older head of the same history: %v, want ErrRollback", err)
	}
	if state(t, r) != before {
		t.Fatal("a refused older head changed the replica")
	}
}

func TestReplicaAddKey(t *testing.T) {
	l, _ := newLog(t, 3)
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	r := newReplica(t, l)
	u := updateFrom(t, l, 0)
	keys := []EntryKey{u.entries[0].Key, u.entries[1].Key}
	u.entries[0].Key, u.entries[1].Key = nil, nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	before := state(t, r)
	for name, c := range map[string]struct {
		index uint64
		key   []byte
		want  error
	}{
		"wrong key":     {0, keys[1], ErrBadEntry},
		"oversized key": {0, append(bytes.Clone(keys[0]), 0), ErrBadEntry},
		"short key":     {0, keys[0][:31], ErrBadEntry},
		"deleted entry": {2, keys[0], ErrDeleted},
		"out of range":  {3, keys[0], ErrOutOfRange},
	} {
		if err := r.AddKey(c.index, c.key); !errors.Is(err, c.want) {
			t.Errorf("%s: AddKey = %v, want %v", name, err, c.want)
		}
		if state(t, r) != before {
			t.Errorf("%s: a refused AddKey changed the replica", name)
		}
	}
	k := bytes.Clone(keys[0])
	if err := r.AddKey(0, k); err != nil {
		t.Fatal(err)
	}
	clear(k)
	if got, err := r.Get(0); err != nil || string(got) != "entry 0" {
		t.Fatalf("Get after AddKey = %q, %v", got, err)
	}
	if e := mustEntry(t, r.log, 0); !bytes.Equal(e.Key, keys[0]) {
		t.Fatal("Entry does not return the added key")
	}
	if err := r.AddKey(0, keys[0]); err != nil {
		t.Fatalf("AddKey of the key the entry has: %v", err)
	}
	if err := r.AddKey(0, keys[1]); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("AddKey of another key for an entry that has one: %v, want ErrBadEntry", err)
	}
	if e := mustEntry(t, r.log, 0); !bytes.Equal(e.Key, keys[0]) {
		t.Fatal("a refused AddKey changed the key")
	}
	r.Close()
	if err := r.AddKey(1, keys[1]); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("AddKey after Close: %v", err)
	}
}

func TestOversizedKeyRefused(t *testing.T) {
	l, _ := newLog(t, 1)
	u := updateFrom(t, l, 0)
	u.entries[0].Key = append(bytes.Clone(u.entries[0].Key), make([]byte, 1<<20)...)
	if err := u.apply(newReplica(t, l)); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("Update with an oversized key: %v, want ErrBadEntry", err)
	}
}

func TestReplicaTargetForkDiverges(t *testing.T) {
	l, id := newLog(t, 3)
	snap := head(t, l)
	snapEntries := updateFrom(t, l, 0).entries
	appendN(t, l, 3, 7)
	r := newReplica(t, l)
	if err := chunk(t, l, 0, 6).apply(r); err != nil {
		t.Fatal(err)
	}
	l.Close()
	fork, err := Restore(id, l.Header().Encode(), snap.Encode(), storeOf(snapEntries))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fork.Close() })
	appendN(t, fork, 50, 7)
	before := state(t, r)
	if err := chunk(t, fork, 6, 8).apply(r); !errors.Is(err, ErrDiverged) {
		t.Fatalf("a head of the target's size with another root: %v, want ErrDiverged", err)
	}
	if state(t, r) != before {
		t.Fatal("a refused fork changed the replica")
	}
}

// TestReplicaForkAgainstTarget has the owner sign a target of size 10 and a fork that shares the 6 held entries.
func TestReplicaForkAgainstTarget(t *testing.T) {
	for _, c := range []struct {
		size int
		want error
	}{{8, ErrRollback}, {12, ErrDiverged}} {
		l, id := newLog(t, 6)
		snap := head(t, l)
		snapEntries := updateFrom(t, l, 0).entries
		appendN(t, l, 6, 4)
		r := newReplica(t, l)
		if err := chunk(t, l, 0, 6).apply(r); err != nil {
			t.Fatal(err)
		}
		l.Close()
		fork, err := Restore(id, l.Header().Encode(), snap.Encode(), storeOf(snapEntries))
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, fork, 50, c.size-6)
		before := state(t, r)
		if err := updateFrom(t, fork, 6).apply(r); !errors.Is(err, c.want) {
			t.Errorf("fork of size %d against a target of size 10: %v, want %v", c.size, err, c.want)
		}
		if c.size > 10 {
			if err := chunk(t, fork, 6, 8).apply(r); !errors.Is(err, ErrBadEntry) {
				t.Errorf("chunk toward a larger fork that stops short of the target: %v, want ErrBadEntry", err)
			}
		}
		if state(t, r) != before {
			t.Errorf("fork of size %d changed the replica", c.size)
		}
		fork.Close()
	}
}

func TestReplicaHeldHeadAtLenKeepsTarget(t *testing.T) {
	l, _ := newLog(t, 5)
	h5 := head(t, l)
	appendN(t, l, 5, 5)
	r := newReplica(t, l)
	if err := chunk(t, l, 0, 5).apply(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(h5, ConsistencyProof{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.Target(); !ok {
		t.Fatal("a head of size Len dropped the pending target")
	}
	if h, err := r.Head(); err != nil || h.Size != 5 {
		t.Fatalf("Head = %v, %v", h.Size, err)
	}
	if err := updateFrom(t, l, 5).apply(r); err != nil {
		t.Fatalf("finishing after the held head: %v", err)
	}
}

// TestReplicaForkAfterHeldHead has a held head of size Len arrive before a fork of the pending target.
func TestReplicaForkAfterHeldHead(t *testing.T) {
	l, id := newLog(t, 6)
	snap := head(t, l)
	snapEntries := updateFrom(t, l, 0).entries
	appendN(t, l, 6, 4)
	r := newReplica(t, l)
	if err := chunk(t, l, 0, 6).apply(r); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := r.Update(snap, ConsistencyProof{}, nil); err != nil {
		t.Fatal(err)
	}
	fork, err := Restore(id, l.Header().Encode(), snap.Encode(), storeOf(snapEntries))
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Close()
	appendN(t, fork, 50, 4)
	before := state(t, r)
	if err := updateFrom(t, fork, 6).apply(r); !errors.Is(err, ErrDiverged) {
		t.Fatalf("fork of the target after a held head: %v, want ErrDiverged", err)
	}
	if state(t, r) != before {
		t.Fatal("a refused fork changed the replica")
	}
}

func TestReplicaTargetWithoutEntries(t *testing.T) {
	l, _ := newLog(t, 4)
	r := newReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 4, 3)
	h := head(t, l)
	p, _ := l.ConsistencyProof(4, 7)
	bad := p
	bad.Path = append([][HashSize]byte{{1}}, p.Path[1:]...)
	before := state(t, r)
	for name, q := range map[string]ConsistencyProof{"bad proof": bad, "proof from another size": {OldSize: 3, NewSize: 7}} {
		if err := r.Update(h, q, nil); !errors.Is(err, ErrBadProof) || state(t, r) != before {
			t.Errorf("%s: %v, or the replica changed", name, err)
		}
	}
	if err := r.Update(h, p, nil); err != nil {
		t.Fatalf("a head with the proof from Len and no entries: %v", err)
	}
	if th, tp, ok := r.Target(); !ok || th.Size != 7 || tp.OldSize != 4 || r.Len() != 4 {
		t.Fatalf("Target = %v, %v, %v", th.Size, tp.OldSize, ok)
	}
}
