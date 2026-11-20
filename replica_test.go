package kololog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
)

func newReplica(t testing.TB, l *Log) *Replica {
	t.Helper()
	r, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// update is what a sync layer sends: the writer's head, a proof from the replica's size and the missing entries.
type update struct {
	head    Head
	proof   ConsistencyProof
	entries []Entry
}

func updateFrom(t testing.TB, l *Log, from uint64) update {
	t.Helper()
	u := update{head: head(t, l)}
	var err error
	if u.proof, err = l.ConsistencyProof(from, u.head.Size); err != nil {
		t.Fatal(err)
	}
	for i := from; i < u.head.Size; i++ {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		u.entries = append(u.entries, e)
	}
	return u
}

func (u update) apply(r *Replica) error { return r.Update(u.head, u.proof, u.entries) }

func appendN(t testing.TB, l *Log, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if _, err := l.Append([]byte(fmt.Sprintf("entry %d", i))); err != nil {
			t.Fatal(err)
		}
	}
}

// state is everything a reader can see of a replica, to check that a failed Update changed nothing.
func state(t testing.TB, r *Replica) string {
	t.Helper()
	var b bytes.Buffer
	if h, err := r.Head(); err == nil {
		b.Write(h.Encode())
	}
	if h, p, ok := r.Target(); ok {
		fmt.Fprintf(&b, "|target %x %x", h.Encode(), p.Encode())
	}
	for i := range r.Len() {
		e, err := r.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "|%x|%x|%x|%x", e.Record, e.Ciphertext, e.Marker, []byte(e.Key))
		got, err := r.Get(i)
		fmt.Fprintf(&b, "|%q|%v", got, err)
	}
	return b.String()
}

func TestReplicaGrowsInSteps(t *testing.T) {
	l, _ := newLog(t, 0)
	r := newReplica(t, l)
	if _, err := r.Head(); !errors.Is(err, ErrNoHead) {
		t.Fatalf("Head of a new replica: %v, want ErrNoHead", err)
	}
	if r.ID() != l.ID() || !bytes.Equal(r.Header().Encode(), l.Header().Encode()) {
		t.Fatal("replica has another ID or header")
	}
	for _, n := range []int{0, 3, 0, 1, 12} {
		appendN(t, l, int(l.Len()), n)
		if err := updateFrom(t, l, r.Len()).apply(r); err != nil {
			t.Fatalf("Update to size %d: %v", l.Len(), err)
		}
		h, err := r.Head()
		if err != nil || !bytes.Equal(h.Encode(), head(t, l).Encode()) || r.Len() != l.Len() {
			t.Fatalf("replica at %d entries, head differs from the writer's: %v", r.Len(), err)
		}
	}
	v, err := VerifyHead(l.pub, l.ID(), mustReplicaHead(t, r))
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Len() {
		got, err := r.Get(i)
		if err != nil || string(got) != fmt.Sprintf("entry %d", i) {
			t.Fatalf("Get(%d) = %q, %v", i, got, err)
		}
		rec, err := r.Record(i)
		if err != nil {
			t.Fatal(err)
		}
		p, err := r.InclusionProof(i, v.Size())
		if err != nil || !VerifyInclusion(v, rec, p) {
			t.Fatalf("inclusion proof %d from the replica: %v", i, err)
		}
	}
	old, err := VerifyHead(l.pub, l.ID(), updateFrom(t, l, 0).head)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, int(l.Len()), 2)
	if err := updateFrom(t, l, r.Len()).apply(r); err != nil {
		t.Fatal(err)
	}
	cur, _ := VerifyHead(l.pub, l.ID(), mustReplicaHead(t, r))
	p, err := r.ConsistencyProof(old.Size(), cur.Size())
	if err != nil || !VerifyConsistency(old, cur, p) {
		t.Fatalf("consistency proof from the replica: %v", err)
	}
	var s []byte
	if err := r.Read(0, &s); err != nil || string(s) != "entry 0" {
		t.Fatalf("Read(0) = %q, %v", s, err)
	}
}

func mustReplicaHead(t testing.TB, r *Replica) Head {
	t.Helper()
	h, err := r.Head()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestReplicaRejectsAndStaysUnchanged(t *testing.T) {
	l, id := newLog(t, 3)
	r := newReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 3, 4)
	good := updateFrom(t, l, 3)

	other := newLogFor(t, id, 7) // same owner, another log ID
	otherKey := updateFrom(t, other, 3)

	// A fork: the same log restored at size 3 and grown with other entries, all validly signed.
	snap := updateFrom(t, l, 0)
	snap.head = mustReplicaHead(t, r)
	snap.entries = snap.entries[:3]
	l.Close()
	fork, err := Restore(id, l.Header().Encode(), snap.head.Encode(), storeOf(snap.entries))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fork.Close() })
	appendN(t, fork, 30, 4)
	forked := updateFrom(t, fork, 3)
	fork.Close()

	tampered := func(change func(u *update)) update {
		u := update{head: good.head.clone(), proof: good.proof, entries: cloneEntries(good.entries)}
		u.proof.Path = append([][HashSize]byte(nil), good.proof.Path...)
		change(&u)
		return u
	}
	cases := []struct {
		name string
		u    update
		want error
	}{
		{"tampered head", tampered(func(u *update) { u.head.Root[0] ^= 1 }), ErrBadHeadSignature},
		{"tampered head signature", tampered(func(u *update) { u.head.Signature[0] ^= 1 }), ErrBadHeadSignature},
		{"head of another log", otherKey, ErrWrongLogID},
		{"tampered record", tampered(func(u *update) { u.entries[1].Record[len(u.entries[1].Record)-1] ^= 1 }), ErrBadEntry},
		{"tampered ciphertext", tampered(func(u *update) { u.entries[2].Ciphertext[40] ^= 1 }), ErrBadEntry},
		{"wrong key", tampered(func(u *update) { u.entries[0].Key = u.entries[1].Key }), ErrBadEntry},
		{"key on a marker", tampered(func(u *update) { u.entries[0].Ciphertext, u.entries[0].Marker = nil, []byte("x") }), ErrBadEntry},
		{"bogus marker", tampered(func(u *update) {
			u.entries[0].Ciphertext, u.entries[0].Marker, u.entries[0].Key = nil, []byte("x"), nil
		}), ErrMalformed},
		{"bad inclusion", update{head: good.head, proof: good.proof, entries: forked.entries}, ErrBadEntry},
		{"missing entry", tampered(func(u *update) { u.entries = u.entries[:3] }), ErrBadProof},
		{"entries past the head", tampered(func(u *update) { u.entries = append(u.entries, u.entries[0]) }), ErrBadEntry},
		{"entries out of order", tampered(func(u *update) { u.entries[0], u.entries[1] = u.entries[1], u.entries[0] }), ErrBadEntry},
		{"bad consistency", tampered(func(u *update) { u.proof.Path[0][0] ^= 1 }), ErrBadProof},
		{"consistency of other sizes", tampered(func(u *update) { u.proof.OldSize = 2 }), ErrBadProof},
	}
	before := state(t, r)
	for _, c := range cases {
		err := c.u.apply(r)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: Update returned %v, want %v", c.name, err, c.want)
		}
		if got := state(t, r); got != before {
			t.Errorf("%s: a failed Update changed the replica", c.name)
		}
	}
	if err := good.apply(r); err != nil {
		t.Fatalf("a valid Update after the failures: %v", err)
	}
	before = state(t, r)

	// The forked log at size 7 has a validly signed head of the replica's size but another root.
	if err := forked.apply(r); !errors.Is(err, ErrDiverged) {
		t.Errorf("same size, other root: %v, want ErrDiverged", err)
	}
	rollback := update{head: snap.head}
	if err := rollback.apply(r); !errors.Is(err, ErrRollback) {
		t.Errorf("smaller head: %v, want ErrRollback", err)
	}
	if err := good.apply(r); err != nil {
		t.Errorf("the current head again: %v, want nil", err)
	}
	if got := state(t, r); got != before {
		t.Error("a refused or repeated head changed the replica")
	}
}

func TestReplicaEntryWithoutKey(t *testing.T) {
	l, _ := newLog(t, 3)
	r := newReplica(t, l)
	u := updateFrom(t, l, 0)
	u.entries[1].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(1); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Get of an entry received without its key: %v, want ErrKeyUnavailable", err)
	}
	if got, err := r.Get(2); err != nil || string(got) != "entry 2" {
		t.Fatalf("Get(2) = %q, %v", got, err)
	}
}

func TestReplicaDelete(t *testing.T) {
	l, _ := newLog(t, 4)
	r := newReplica(t, l)
	if err := l.Delete(3); err != nil {
		t.Fatal(err)
	}
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(3); !errors.Is(err, ErrDeleted) {
		t.Fatalf("entry received as a delete marker: %v, want ErrDeleted", err)
	}

	rec := record(t, l, 1)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	e, _ := l.Entry(1)
	m := e.Marker

	other, _ := newLog(t, 4)
	if err := other.Delete(1); err != nil {
		t.Fatal(err)
	}
	oe, _ := other.Entry(1)
	before := state(t, r)
	for name, c := range map[string]struct {
		m    []byte
		want error
	}{
		"malformed":         {m[:len(m)-1], ErrMalformed},
		"tampered":          {flip(m, len(m)-1), ErrBadEntry},
		"another log":       {oe.Marker, ErrBadEntry},
		"marker of entry 3": {mustEntry(t, l, 3).Marker, nil},
	} {
		if err := r.ApplyDelete(c.m); !errors.Is(err, c.want) {
			t.Errorf("%s: ApplyDelete returned %v, want %v", name, err, c.want)
		}
		if state(t, r) != before {
			t.Errorf("%s: ApplyDelete changed the replica", name)
		}
	}
	appendN(t, l, 4, 1)
	if err := l.Delete(4); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, l, 4).Marker); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("marker for an entry the replica lacks: %v, want ErrOutOfRange", err)
	}

	if err := r.ApplyDelete(m); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get after ApplyDelete: %v, want ErrDeleted", err)
	}
	got, err := r.Entry(1)
	if err != nil || got.Key != nil || got.Ciphertext != nil || !bytes.Equal(got.Marker, m) || !bytes.Equal(got.Record, rec.Encode()) {
		t.Fatalf("entry after ApplyDelete keeps a key or ciphertext, or lost its record or marker: %v", err)
	}
	if r2, err := r.Record(1); err != nil || !bytes.Equal(r2.Encode(), rec.Encode()) {
		t.Fatalf("record after ApplyDelete: %v", err)
	}
	if err := r.ApplyDelete(m); err != nil {
		t.Fatalf("applying a marker twice: %v", err)
	}
	if err := updateFrom(t, l, r.Len()).apply(r); err != nil {
		t.Fatalf("Update after ApplyDelete: %v", err)
	}
}

func mustEntry(t testing.TB, l *Log, i uint64) Entry {
	t.Helper()
	e, err := l.Entry(i)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func flip(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 1
	return b
}

func TestRestoreReplica(t *testing.T) {
	l, _ := newLog(t, 5)
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	r := newReplica(t, l)
	u := updateFrom(t, l, 0)
	u.entries[4].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	for i := range r.Len() {
		entries = append(entries, mustEntry(t, r.log, i))
	}
	h := mustReplicaHead(t, r)
	got, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h.Encode(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if state(t, got) != state(t, r) {
		t.Fatal("restored replica differs")
	}
	if err := updateFrom(t, l, 5).apply(got); err != nil {
		t.Fatal(err)
	}
	empty, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), nil, nil)
	if err != nil || empty.Len() != 0 {
		t.Fatalf("RestoreReplica without a head: %v", err)
	}

	otherLog, _ := newLog(t, 1)
	for name, c := range map[string]struct {
		header, head []byte
		entries      []Entry
		want         error
	}{
		"no header":          {nil, h.Encode(), entries, ErrMissingHeader},
		"header of another":  {otherLog.Header().Encode(), h.Encode(), entries, ErrBadLogHeader},
		"tampered head":      {l.Header().Encode(), flip(h.Encode(), 70), entries, ErrInvalidHead},
		"missing entry":      {l.Header().Encode(), h.Encode(), entries[:4], ErrRestoreMismatch},
		"tampered entry":     {l.Header().Encode(), h.Encode(), tamperEntry(entries, 0), ErrRestoreMismatch},
		"key on deleted one": {l.Header().Encode(), h.Encode(), keyOnDeleted(entries), ErrRestoreMismatch},
	} {
		if _, err := restoreReplica(t, l.pub, l.ID(), c.header, c.head, c.entries); !errors.Is(err, c.want) {
			t.Errorf("%s: RestoreReplica returned %v, want %v", name, err, c.want)
		}
	}
	if _, err := NewReplica(l.pub[:31], l.ID(), l.Header().Encode(), NewMemory()); !errors.Is(err, ErrMalformed) {
		t.Errorf("short public key: %v", err)
	}
	if _, err := NewReplica(l.pub, LogID{1}, l.Header().Encode(), NewMemory()); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("header of another log ID: %v", err)
	}
}

func tamperEntry(entries []Entry, i int) []Entry {
	out := cloneEntries(entries)
	out[i].Ciphertext[0] ^= 1
	return out
}

func keyOnDeleted(entries []Entry) []Entry {
	out := cloneEntries(entries)
	out[2].Key = out[0].Key
	return out
}

func TestReplicaClose(t *testing.T) {
	l, _ := newLog(t, 2)
	r := newReplica(t, l)
	if err := updateFrom(t, l, 0).apply(r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2, 1)
	if err := updateFrom(t, l, 2).apply(r); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("Update after Close: %v", err)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, l, 0).Marker); !errors.Is(err, ErrLogClosed) {
		t.Fatalf("ApplyDelete after Close: %v", err)
	}
	if got, err := r.Get(0); err != nil || string(got) != "entry 0" {
		t.Fatalf("reads after Close: %q, %v", got, err)
	}
}

// TestReplicaOwnLogStaysWritable checks that a replica never touches the writer registry.
func TestReplicaOwnLogStaysWritable(t *testing.T) {
	l, id := newLog(t, 1)
	r := newReplica(t, l)
	r.Close()
	if _, err := l.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(id.PublicKey(), l.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("closing a replica released the writer's registration: %v", err)
	}
}

func TestThreeOwnersReplicateEachOther(t *testing.T) {
	logs := make([]*Log, 3)
	for i := range logs {
		logs[i], _ = newLog(t, 0)
	}
	// replicas[i][j] is owner i's replica of owner j's log.
	replicas := make([][]*Replica, 3)
	for i := range replicas {
		replicas[i] = make([]*Replica, 3)
		for j := range logs {
			if i != j {
				replicas[i][j] = newReplica(t, logs[j])
			}
		}
	}
	for round := range 3 {
		for j, l := range logs {
			if _, err := l.Append([]byte(fmt.Sprintf("owner %d message %d", j, round))); err != nil {
				t.Fatal(err)
			}
		}
		for i := range replicas {
			for j, r := range replicas[i] {
				if r == nil {
					continue
				}
				if err := updateFrom(t, logs[j], r.Len()).apply(r); err != nil {
					t.Fatalf("owner %d syncing log %d: %v", i, j, err)
				}
			}
		}
	}
	for i := range replicas {
		for j, r := range replicas[i] {
			if r == nil {
				continue
			}
			for k := range uint64(3) {
				got, err := r.Get(k)
				if want := fmt.Sprintf("owner %d message %d", j, k); err != nil || string(got) != want {
					t.Errorf("owner %d reads log %d entry %d = %q, %v, want %q", i, j, k, got, err, want)
				}
			}
		}
	}
}

func TestReplicaConcurrentUse(t *testing.T) {
	l, _ := newLog(t, 0)
	r := newReplica(t, l)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			r.Len()
			r.Head()
			if n := r.Len(); n > 0 {
				r.Get(n - 1)
				r.Entry(n - 1)
				r.InclusionProof(n-1, n)
			}
		}
	}()
	for i := range 20 {
		appendN(t, l, i, 1)
		if err := updateFrom(t, l, r.Len()).apply(r); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

func TestEntryKeyNeverPrinted(t *testing.T) {
	l, _ := newLog(t, 1)
	e := mustEntry(t, l, 0)
	if len(e.Key) != keySize {
		t.Fatalf("Entry has a key of %d bytes", len(e.Key))
	}
	var out bytes.Buffer
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d", "%T %v"} {
		fmt.Fprintf(&out, verb+"\n", e)
		fmt.Fprintf(&out, verb+"\n", e.Key)
		fmt.Fprintf(&out, verb+"\n", &e)
	}
	out.WriteString(e.Key.String())
	j, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	out.Write(j)
	var back Entry
	if err := json.Unmarshal(j, &back); err != nil || back.Key != nil || !bytes.Equal(back.Record, e.Record) || !bytes.Equal(back.Ciphertext, e.Ciphertext) {
		t.Fatalf("Entry JSON round trip: %v, key %d bytes", err, len(back.Key))
	}
	j, _ = json.Marshal(e.Key)
	out.Write(j)
	slog.New(slog.NewTextHandler(&out, nil)).Info("entry", "e", e, "key", e.Key)
	slog.New(slog.NewJSONHandler(&out, nil)).Info("entry", "e", e, "key", e.Key, slog.Any("p", &e))
	s := out.String()
	b64, _ := json.Marshal([]byte(e.Key))
	for _, form := range []string{hex.EncodeToString(e.Key), fmt.Sprintf("%X", []byte(e.Key)), string(b64[1 : len(b64)-1]), fmt.Sprint([]byte(e.Key))} {
		if bytes.Contains([]byte(s), []byte(form)) {
			t.Fatalf("entry key printed as %q in:\n%s", form, s)
		}
	}
	if !bytes.Contains(out.Bytes(), []byte(redacted)) {
		t.Fatal("key is not shown as redacted")
	}
}
