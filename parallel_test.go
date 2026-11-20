package kololog

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
)

// oracleGrow is the sequential verifier, the reference for the parallel one.
func oracleGrow(l *Log, base error, n uint64) error {
	start := uint64(len(l.records))
	for i := range n {
		index := start + i
		in, err := l.s.Entry(index)
		if err != nil {
			l.truncate(start)
			if errors.Is(err, ErrOutOfRange) {
				return fmt.Errorf("%w: entry %d missing from storage", base, index)
			}
			return fmt.Errorf("kololog: entry %d: %w", index, err)
		}
		c, err := checkEntry(base, l.pub, l.logID, index, in, false)
		clear(in.Key)
		if err == nil && !l.replica && c.rec.flags == 0 {
			err = fmt.Errorf("%w: entry %d: a live entry of an own log is stored without its key", base, index)
		}
		if err != nil {
			l.truncate(start)
			return err
		}
		l.tree.Append(c.leaf)
		l.records = append(l.records, c.rec)
		if restoreHook != nil {
			restoreHook(l, int(index))
		}
	}
	return nil
}

func setWorkers(t testing.TB, w int) {
	t.Helper()
	verifyWorkersSet.Store(int32(w))
	t.Cleanup(func() { verifyWorkersSet.Store(0) })
}

// setHook sets a package hook for the rest of the test; hooks are nil in production.
func setHook[T any](t testing.TB, hook *T, v T) {
	t.Helper()
	*hook = v
	t.Cleanup(func() { var zero T; *hook = zero })
}

// freshLog is the state Restore has before it calls grow: a log with no entry over s.
func freshLog(t testing.TB, x exported, replica bool, entries []Entry) *Log {
	t.Helper()
	lh, err := DecodeLogHeader(x.header)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := identityKey(x.id)
	if err != nil {
		t.Fatal(err)
	}
	return &Log{id: x.id, pub: pub, logID: lh.LogID, header: lh, replica: replica, s: storeOf(cloneEntries(entries))}
}

// sameState fails the test unless a and b hold the same tree and records and ended with the same error.
func sameState(t testing.TB, label string, a, b *Log, ea, eb error) {
	t.Helper()
	if (ea == nil) != (eb == nil) || ea != nil && ea.Error() != eb.Error() {
		t.Fatalf("%s: error %v, sequential %v", label, eb, ea)
	}
	if ea != nil {
		for _, base := range []error{ErrRestoreMismatch, ErrOutOfRange} {
			if errors.Is(ea, base) != errors.Is(eb, base) {
				t.Fatalf("%s: errors.Is(%v) differs: %v and %v", label, base, eb, ea)
			}
		}
	}
	if a.tree.Size() != b.tree.Size() || len(a.records) != len(b.records) || uint64(len(a.records)) != a.tree.Size() {
		t.Fatalf("%s: %d records and %d leaves, sequential %d and %d", label, len(b.records), b.tree.Size(), len(a.records), a.tree.Size())
	}
	if !reflect.DeepEqual(a.records, b.records) {
		t.Fatalf("%s: records differ from the sequential ones", label)
	}
	if n := a.tree.Size(); a.tree.Root(n) != b.tree.Root(n) {
		t.Fatalf("%s: root differs from the sequential one", label)
	}
	if ea != nil && len(a.records) != 0 {
		t.Fatalf("%s: %d records kept after an error", label, len(a.records))
	}
}

// compareGrow runs the sequential verifier and growStored on copies of entries and requires the same error and the same state.
func compareGrow(t testing.TB, label string, x exported, replica bool, entries []Entry, workers ...int) (err error) {
	t.Helper()
	n := x.head.Size
	seq := freshLog(t, x, replica, entries)
	errSeq := oracleGrow(seq, ErrRestoreMismatch, n)
	for _, w := range workers {
		verifyWorkersSet.Store(int32(w))
		par := freshLog(t, x, replica, entries)
		_, errPar := par.grow(ErrRestoreMismatch, n, nil, true)
		verifyWorkersSet.Store(0)
		sameState(t, fmt.Sprintf("%s, %d workers", label, w), seq, par, errSeq, errPar)
	}
	return errSeq
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func randomLog(t testing.TB, rng *rand.Rand, n int, derived bool) exported {
	t.Helper()
	id := newID(t)
	var opts []Option
	if derived {
		opts = append(opts, WithDerivedKeys(testSecret(byte(rng.Uint32())), 4))
	}
	l, err := New(id, NewMemory(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		size := rng.IntN(300)
		switch r := rng.IntN(40); {
		case r == 0:
			size = 100_000 + rng.IntN(200_000)
		case r < 8:
			size = rng.IntN(20_000)
		}
		if _, err := l.Append(randomBytes(rng, size)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range uint64(n) {
		if rng.IntN(7) == 0 {
			if err := l.Delete(i); err != nil {
				t.Fatal(err)
			}
		}
	}
	x := exported{id: id, log: l, header: l.Header().Encode(), head: head(t, l)}
	for i := range l.Len() {
		x.entries = append(x.entries, mustEntry(t, l, i))
	}
	l.Close()
	return x
}

type corruption struct {
	name  string
	apply func(entries []Entry, i int) []Entry
}

func flipLast(b []byte) []byte { return flip(b, len(b)-1) }

var corruptions = []corruption{
	{"signature", func(e []Entry, i int) []Entry { e[i].Record = flipLast(e[i].Record); return e }},
	{"record garbage", func(e []Entry, i int) []Entry { e[i].Record = []byte("junk"); return e }},
	{"key commitment in the record", func(e []Entry, i int) []Entry {
		r, err := DecodeRecord(e[i].Record)
		if err != nil {
			panic(err)
		}
		r.KeyCommit[0] ^= 1
		e[i].Record = r.Encode()
		return e
	}},
	{"ciphertext bit", func(e []Entry, i int) []Entry {
		if len(e[i].Ciphertext) > 0 {
			e[i].Ciphertext = flip(e[i].Ciphertext, len(e[i].Ciphertext)/2)
		}
		return e
	}},
	{"ciphertext short", func(e []Entry, i int) []Entry {
		if len(e[i].Ciphertext) > 0 {
			e[i].Ciphertext = e[i].Ciphertext[:len(e[i].Ciphertext)-1]
		}
		return e
	}},
	{"key bit", func(e []Entry, i int) []Entry {
		if len(e[i].Key) > 0 {
			e[i].Key = flip(e[i].Key, 0)
		}
		return e
	}},
	{"key short", func(e []Entry, i int) []Entry {
		if len(e[i].Key) > 0 {
			e[i].Key = e[i].Key[:5]
		}
		return e
	}},
	{"key missing", func(e []Entry, i int) []Entry { e[i].Key = nil; return e }},
	{"ciphertext and marker", func(e []Entry, i int) []Entry { e[i].Marker = []byte{1}; return e }},
	{"marker bit", func(e []Entry, i int) []Entry {
		if len(e[i].Marker) > 0 {
			e[i].Marker = flipLast(e[i].Marker)
		}
		return e
	}},
	{"entry missing from storage", func(e []Entry, i int) []Entry { return e[:i] }},
	{"entries swapped", func(e []Entry, i int) []Entry {
		if i+1 < len(e) {
			e[i], e[i+1] = e[i+1], e[i]
		}
		return e
	}},
}

// The parallel verifier gives the sequential one's error and state on random logs of many shapes with random damage.
func TestGrowStoredMatchesSequential(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	sizes := []int{0, 1, 2, 3, 4, 7, 16, 17, 33, 64, 100}
	runs, failures := 0, 0
	for round := range 3 {
		for _, n := range sizes {
			x := randomLog(t, rng, n, rng.IntN(2) == 0)
			for variant := range 8 {
				entries := cloneEntries(x.entries)
				replica := rng.IntN(3) == 0
				if replica && rng.IntN(2) == 0 {
					for i := range entries {
						entries[i].Key = nil
					}
				}
				label := fmt.Sprintf("round %d, %d entries, variant %d", round, n, variant)
				if n > 0 {
					for range variant % 3 {
						c := corruptions[rng.IntN(len(corruptions))]
						i := rng.IntN(len(entries))
						label += fmt.Sprintf(", %s at %d", c.name, i)
						entries = c.apply(entries, i)
						if len(entries) == 0 {
							break
						}
					}
				}
				runs++
				if compareGrow(t, label, x, replica, entries, 1, 2, 3, 8) != nil {
					failures++
				}
			}
		}
	}
	if failures < runs/4 || failures > runs*4/5 {
		t.Fatalf("%d of %d runs failed: the damage is not exercised", failures, runs)
	}
}

// Every kind of damage, at the first, a middle and the last entry, gives the same error, naming the same entry, as the sequential verifier.
func TestGrowStoredDamageAtEveryPosition(t *testing.T) {
	const n = 25
	rng := rand.New(rand.NewPCG(3, 5))
	live := randomLog(t, rng, n, false)
	derived := randomLog(t, rng, n, true)
	for _, x := range []exported{live, derived} {
		if x.head.Size != n {
			t.Fatalf("log has %d entries", x.head.Size)
		}
	}
	for _, c := range corruptions {
		for _, pos := range []int{0, 1, n / 2, n - 2, n - 1} {
			for name, x := range map[string]exported{"random keys": live, "derived keys": derived} {
				entries := c.apply(cloneEntries(x.entries), pos)
				label := fmt.Sprintf("%s at %d, %s", c.name, pos, name)
				err := compareGrow(t, label, x, false, entries, 1, 8)
				damaged := !reflect.DeepEqual(entries, x.entries)
				if damaged != (err != nil) {
					t.Fatalf("%s: error %v for damaged=%v", label, err, damaged)
				}
				if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("entry %d", pos)) && c.name != "entries swapped" {
					t.Fatalf("%s: error %q does not name entry %d", label, err, pos)
				}
			}
		}
	}
}

// Restore and RestoreReplica of every damaged shape end with ErrRestoreMismatch for the first damaged entry, with 1 and 8 workers.
func TestRestoreReportsFirstDamagedEntry(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 9))
	x := randomLog(t, rng, 30, false)
	for _, w := range []int{1, 8} {
		setWorkers(t, w)
		for _, c := range corruptions {
			for _, pos := range []int{0, 14, 29} {
				entries := c.apply(cloneEntries(x.entries), pos)
				if reflect.DeepEqual(entries, x.entries) {
					continue
				}
				l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries))
				if l != nil || !errors.Is(err, ErrRestoreMismatch) {
					t.Fatalf("%d workers, %s at %d: Restore = %v, %v", w, c.name, pos, l, err)
				}
				if want := fmt.Sprintf("entry %d", pos); !strings.Contains(err.Error(), want) && c.name != "entries swapped" {
					t.Fatalf("%d workers, %s at %d: %q does not name %s", w, c.name, pos, err, want)
				}
				if c.name == "key missing" {
					continue
				}
				r, err := restoreReplica(t, x.id.PublicKey(), x.head.LogID, x.header, x.head.Encode(), stripKeys(entries))
				if c.name == "key bit" || c.name == "key short" {
					if err != nil || r == nil {
						t.Fatalf("%d workers, %s at %d: replica without keys: %v", w, c.name, pos, err)
					}
					r.Close()
					continue
				}
				if r != nil || !errors.Is(err, ErrRestoreMismatch) {
					t.Fatalf("%d workers, %s at %d: RestoreReplica = %v, %v", w, c.name, pos, r, err)
				}
			}
		}
	}
}

func stripKeys(entries []Entry) []Entry {
	out := cloneEntries(entries)
	for i := range out {
		out[i].Key = nil
	}
	return out
}

// Two damaged entries: the lower index is reported even when a worker finds the higher one first.
func TestRestoreReportsLowestIndexNotFirstFound(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	x := randomLog(t, rng, 60, false)
	entries := cloneEntries(x.entries)
	entries[3].Ciphertext = flip(entries[3].Ciphertext, 0)
	entries[5].Record = []byte("junk")
	// The worker of the lower entry is slow and entry 5 is inside the read-ahead window, so the higher one is found first.
	setHook(t, &verifyHook, func(index uint64) {
		if index == 3 {
			time.Sleep(40 * time.Millisecond)
		}
	})
	for _, w := range []int{2, 8} {
		setWorkers(t, w)
		for range 3 {
			_, err := Restore(x.id, x.header, x.head.Encode(), storeOf(cloneEntries(entries)))
			if !errors.Is(err, ErrRestoreMismatch) || !strings.Contains(err.Error(), "entry 3:") || !strings.Contains(err.Error(), "ciphertext hash") {
				t.Fatalf("%d workers: %v, want the ciphertext hash error of entry 3", w, err)
			}
		}
	}
}

// The results are applied in index order whatever order the workers finish in.
func TestRestoreAppliesInIndexOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	x := randomLog(t, rng, 80, true)
	// The first entries are the slowest, so the last ones finish first.
	setHook(t, &verifyHook, func(index uint64) { time.Sleep(time.Duration(8-index%8) * time.Millisecond) })
	for _, w := range []int{1, 2, 8} {
		setWorkers(t, w)
		seq := freshLog(t, x, false, x.entries)
		if err := oracleGrow(seq, ErrRestoreMismatch, x.head.Size); err != nil {
			t.Fatal(err)
		}
		par := freshLog(t, x, false, x.entries)
		var order []int
		setHook(t, &restoreHook, func(l *Log, i int) { order = append(order, i) })
		if _, err := par.grow(ErrRestoreMismatch, x.head.Size, nil, true); err != nil {
			t.Fatal(err)
		}
		restoreHook = nil
		for i, got := range order {
			if got != i {
				t.Fatalf("%d workers: restoreHook order %v", w, order)
			}
		}
		sameState(t, fmt.Sprintf("%d workers", w), seq, par, nil, nil)
	}
}

// Thousands of entries restore to the same log with 1 and 8 workers and the default, and storage is read once per index, in order.
func TestRestoreManyEntries(t *testing.T) {
	rng := rand.New(rand.NewPCG(2, 4))
	x := randomLog(t, rng, 1500, false)
	for _, w := range []int{1, 8, 0} {
		setWorkers(t, w)
		ps := newProbe(storeOf(cloneEntries(x.entries)))
		l, err := Restore(x.id, x.header, x.head.Encode(), ps)
		if err != nil {
			t.Fatalf("%d workers: %v", w, err)
		}
		ps.requireKeysCleared(t)
		if got := head(t, l); got.Size != x.head.Size || got.Root != x.head.Root {
			t.Fatalf("%d workers: restored size %d root %x, want %d %x", w, got.Size, got.Root, x.head.Size, x.head.Root)
		}
		for i := range l.Len() {
			if e, err := l.Entry(i); err != nil || !bytes.Equal(e.Record, x.entries[i].Record) {
				t.Fatalf("%d workers: entry %d: %v", w, i, err)
			}
		}
		l.Close()
		reads := ps.takeReads()
		reads = reads[:x.head.Size]
		for i, r := range reads {
			if r != uint64(i) {
				t.Fatalf("%d workers: read %d at position %d", w, r, i)
			}
		}
	}
}

// A replica restores the same with many workers, then takes the rest by a catch-up replay.
func TestRestoreReplicaParallel(t *testing.T) {
	rng := rand.New(rand.NewPCG(8, 1))
	x := randomLog(t, rng, 200, false)
	setWorkers(t, 8)
	r, err := restoreReplica(t, x.id.PublicKey(), x.head.LogID, x.header, x.head.Encode(), x.entries)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Len() != x.head.Size {
		t.Fatalf("replica has %d entries, want %d", r.Len(), x.head.Size)
	}
	h, err := r.Head()
	if err != nil || h.Root != x.head.Root {
		t.Fatalf("replica root %x, %v, want %x", h.Root, err, x.head.Root)
	}
}

// probeStorage wraps a Storage: it records reads and the key copies it handed out, and can fail or panic at an index.
type probeStorage struct {
	Storage
	mu      sync.Mutex
	reads   []uint64
	keys    []EntryKey
	failAt  int
	failErr error
	panicAt int
}

func newProbe(s Storage) *probeStorage { return &probeStorage{Storage: s, failAt: -1, panicAt: -1} }

func (p *probeStorage) Entry(index uint64) (Entry, error) {
	p.mu.Lock()
	p.reads = append(p.reads, index)
	fail, boom, doPanic := int(index) == p.failAt, p.failErr, int(index) == p.panicAt
	p.mu.Unlock()
	if doPanic {
		panic("storage panic")
	}
	if fail {
		return Entry{}, boom
	}
	e, err := p.Storage.Entry(index)
	if err == nil && len(e.Key) > 0 {
		p.mu.Lock()
		p.keys = append(p.keys, e.Key)
		p.mu.Unlock()
	}
	return e, err
}

func (p *probeStorage) takeReads() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.reads
	p.reads = nil
	return r
}

func (p *probeStorage) readCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reads)
}

// requireKeysCleared fails unless every key copy the storage handed out was zeroed, read or not.
func (p *probeStorage) requireKeysCleared(t testing.TB) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) == 0 {
		t.Fatal("storage handed out no keys")
	}
	for i, k := range p.keys {
		if !bytes.Equal(k, make([]byte, len(k))) {
			t.Fatalf("key copy %d of %d was not cleared", i, len(p.keys))
		}
	}
}

func requireNoLeak(t testing.TB, before int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("%d goroutines, %d before:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

// When storage fails in the middle, Restore returns that error at once, with no goroutine left, every key cleared and nothing registered.
func TestRestoreStorageFailureInTheMiddle(t *testing.T) {
	rng := rand.New(rand.NewPCG(4, 4))
	x := randomLog(t, rng, 120, false)
	boom := errors.New("disk gone")
	for _, w := range []int{1, 8} {
		setWorkers(t, w)
		before := runtime.NumGoroutine()
		ps := newProbe(storeOf(cloneEntries(x.entries)))
		ps.failAt, ps.failErr = 50, boom
		// Slow workers keep read entries queued and unverified when the failure comes.
		setHook(t, &verifyHook, func(index uint64) { time.Sleep(time.Millisecond) })
		l, err := Restore(x.id, x.header, x.head.Encode(), ps)
		if l != nil || !errors.Is(err, boom) || err.Error() != "kololog: entry 50: disk gone" {
			t.Fatalf("%d workers: Restore = %v, %v", w, l, err)
		}
		requireNoLeak(t, before)
		ps.requireKeysCleared(t)
		if reads := ps.takeReads(); len(reads) != 51 {
			t.Fatalf("%d workers: %d reads, want 51", w, len(reads))
		}
		verifyHook = nil
		l, err = Restore(x.id, x.header, x.head.Encode(), storeOf(cloneEntries(x.entries)))
		if err != nil {
			t.Fatalf("%d workers: Restore after the failure: %v", w, err)
		}
		l.Close()
		requireNoLeak(t, before)
	}
}

// A bad entry in the middle stops the reader after a bounded number of entries, and every key it read is cleared.
func TestRestoreStopsReadingAfterTheFirstFailure(t *testing.T) {
	rng := rand.New(rand.NewPCG(6, 6))
	x := randomLog(t, rng, 200, false)
	const bad = 30
	entries := cloneEntries(x.entries)
	entries[bad].Record = []byte("junk")
	for _, w := range []int{1, 4, 8} {
		setWorkers(t, w)
		before := runtime.NumGoroutine()
		ps := newProbe(storeOf(entries))
		setHook(t, &verifyHook, func(index uint64) { time.Sleep(200 * time.Microsecond) })
		_, err := Restore(x.id, x.header, x.head.Encode(), ps)
		if !errors.Is(err, ErrRestoreMismatch) || !strings.Contains(err.Error(), "entry 30:") {
			t.Fatalf("%d workers: %v", w, err)
		}
		reads := ps.takeReads()
		for i, r := range reads {
			if r != uint64(i) {
				t.Fatalf("%d workers: reads %v are not increasing from 0, once each", w, reads)
			}
		}
		if last := int(reads[len(reads)-1]); last < bad || last > bad+2*w+1 {
			t.Fatalf("%d workers: read up to entry %d for a bad entry %d, at most %d allowed", w, last, bad, bad+2*w+1)
		}
		ps.requireKeysCleared(t)
		requireNoLeak(t, before)
	}
}

// With the oldest entry stuck in its worker, the reader stops at 2*workers+2 entries read (2 with one worker): the queue is bounded.
func TestRestoreQueueIsBounded(t *testing.T) {
	rng := rand.New(rand.NewPCG(10, 10))
	x := randomLog(t, rng, 100, false)
	for _, w := range []int{1, 2, 3, 8} {
		setWorkers(t, w)
		before := runtime.NumGoroutine()
		gate := make(chan struct{})
		setHook(t, &verifyHook, func(index uint64) {
			if index == 0 {
				<-gate
			}
		})
		ps := newProbe(storeOf(cloneEntries(x.entries)))
		done := make(chan error, 1)
		go func() {
			l, err := Restore(x.id, x.header, x.head.Encode(), ps)
			if l != nil {
				l.Close()
			}
			done <- err
		}()
		prev, stable := -1, 0
		for stable < 10 {
			time.Sleep(10 * time.Millisecond)
			if n := ps.readCount(); n == prev {
				stable++
			} else {
				prev, stable = n, 0
			}
		}
		want := 2*w + 2
		if w == 1 {
			want = 2 // the only worker is the stuck one
		}
		if prev != want {
			t.Fatalf("%d workers: %d entries read with entry 0 stuck, want %d", w, prev, want)
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatalf("%d workers: %v", w, err)
		}
		verifyHook = nil
		requireNoLeak(t, before)
	}
}

// A panic in storage, in a worker or in restoreHook reaches the caller of Restore with its value, and leaves no goroutine and no key behind.
func TestRestorePanicsReachTheCaller(t *testing.T) {
	rng := rand.New(rand.NewPCG(12, 12))
	x := randomLog(t, rng, 80, false)
	recoverValue := func(f func()) (v any) {
		defer func() { v = recover() }()
		f()
		return nil
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, ps *probeStorage)
		want  any
	}{
		{"storage", func(t *testing.T, ps *probeStorage) { ps.panicAt = 40 }, "storage panic"},
		{"worker", func(t *testing.T, ps *probeStorage) {
			setHook(t, &verifyHook, func(index uint64) {
				if index == 25 {
					panic("worker panic")
				}
			})
		}, "worker panic"},
		{"restoreHook", func(t *testing.T, ps *probeStorage) {
			setHook(t, &restoreHook, func(_ *Log, i int) {
				if i == 30 {
					panic("hook panic")
				}
			})
		}, "hook panic"},
	}
	for _, w := range []int{1, 8} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s %d workers", c.name, w), func(t *testing.T) {
				setWorkers(t, w)
				before := runtime.NumGoroutine()
				ps := newProbe(storeOf(cloneEntries(x.entries)))
				c.setup(t, ps)
				var l *Log
				var err error
				if v := recoverValue(func() { l, err = Restore(x.id, x.header, x.head.Encode(), ps) }); v != c.want {
					t.Fatalf("panic value %v, want %v (Restore = %v, %v)", v, c.want, l, err)
				}
				requireNoLeak(t, before)
				ps.requireKeysCleared(t)
			})
		}
	}
}

// A Restore of a log the caller does not own releases its reservation: a second Restore of the same log works.
func TestRestoreTwiceParallel(t *testing.T) {
	rng := rand.New(rand.NewPCG(13, 13))
	x := randomLog(t, rng, 40, false)
	setWorkers(t, 8)
	for range 2 {
		l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(cloneEntries(x.entries)))
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
	}
}

func restoreBench(b *testing.B, count, size int) (*koloid.Identity, []byte, []byte, []Entry) {
	b.Helper()
	id := newID(b)
	l, err := New(id, NewMemory())
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, size)
	for i := range count {
		data[0] = byte(i)
		if _, err := l.Append(data); err != nil {
			b.Fatal(err)
		}
	}
	x := exported{id: id, header: l.Header().Encode(), head: head(b, l)}
	for i := range l.Len() {
		x.entries = append(x.entries, mustEntry(b, l, i))
	}
	l.Close()
	return id, x.header, x.head.Encode(), x.entries
}

// BenchmarkRestore compares one worker with the default, GOMAXPROCS up to 16.
func BenchmarkRestore(b *testing.B) {
	for _, c := range []struct {
		name        string
		count, size int
	}{{"1MiBx200", 200, 1 << 20}, {"100Bx20000", 20000, 100}} {
		id, header, hd, entries := restoreBench(b, c.count, c.size)
		s := storeOf(entries)
		for _, w := range []int{1, 0} {
			name := fmt.Sprintf("%s/workers=%d", c.name, w)
			if w == 0 {
				name = fmt.Sprintf("%s/workers=default(%d)", c.name, verifyWorkers(1<<20))
			}
			b.Run(name, func(b *testing.B) {
				verifyWorkersSet.Store(int32(w))
				defer verifyWorkersSet.Store(0)
				b.SetBytes(int64(c.count) * int64(c.size))
				for b.Loop() {
					l, err := Restore(id, header, hd, s)
					if err != nil {
						b.Fatal(err)
					}
					l.Close()
				}
			})
		}
	}
}
