package kololog

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// maxVerifyWorkers caps the goroutines that verify stored entries in Restore and RestoreReplica.
const maxVerifyWorkers = 16

// verifyWorkersSet, when above 0, replaces the default worker count; tests set it.
var verifyWorkersSet atomic.Int32

// verifyHook runs in a worker before it verifies entry index; tests use it to delay or break one worker.
var verifyHook func(index uint64)

// verifyWorkers returns the workers to verify n stored entries: GOMAXPROCS, at most maxVerifyWorkers, and never more than n.
func verifyWorkers(n uint64) int {
	w := int(verifyWorkersSet.Load())
	if w <= 0 {
		w = min(runtime.GOMAXPROCS(0), maxVerifyWorkers)
	}
	return int(min(uint64(w), n))
}

// slot is one stored entry on its way through growStored: res receives exactly one outcome, unless growStored has already stopped.
type slot struct {
	index uint64
	in    Entry
	res   chan outcome
}

// outcome is what the reader or a worker found for one slot; a panic is carried to the goroutine that called growStored.
type outcome struct {
	c        checked
	err      error
	panicked bool
	value    any
}

func newSlot(index uint64, in Entry) *slot {
	return &slot{index: index, in: in, res: make(chan outcome, 1)}
}

// growStored is grow for n entries from storage: one reader asks storage for each index once, in increasing order, workers verify
// the slots in any order, and the calling goroutine applies them in queue order, so it stops at the lowest failing index.
// A verified slot holds no entry data, so at most workers+1 entries are in memory at once. The queue is 2*workers deep so a slow
// entry only delays the applier while the workers verify the next ones.
// After the first failure, or a panic in storage, a worker or restoreHook, it stops the reader, waits for every goroutine, clears every
// key it read and drops what it appended. Storage may be asked for up to 2*workers+1 entries past the first failing one.
func (l *Log) growStored(base error, n uint64, workers int) error {
	start := uint64(len(l.records))
	stop := make(chan struct{})
	jobs := make(chan *slot)
	order := make(chan *slot, 2*workers)
	var wg sync.WaitGroup
	wg.Add(workers + 1)
	go l.readEntries(base, start, n, order, jobs, stop, &wg)
	for range workers {
		go l.verifyEntries(base, jobs, &wg)
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for s := range order {
		o := <-s.res
		switch {
		case o.panicked:
			l.truncate(start)
			panic(o.value)
		case o.err != nil:
			l.truncate(start)
			return o.err
		}
		l.tree.Append(o.c.leaf)
		l.records = append(l.records, o.c.rec)
		if restoreHook != nil {
			restoreHook(l, int(s.index))
		}
	}
	return nil
}

// readEntries reads entries start to start+n-1 from storage and queues each slot on order, then on jobs. It ends with a slot that holds the
// error of a failed read, or the panic of storage, or after stop is closed.
func (l *Log) readEntries(base error, start, n uint64, order, jobs chan *slot, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(order)
	defer close(jobs)
	defer func() {
		if v := recover(); v != nil {
			s := newSlot(0, Entry{})
			s.res <- outcome{panicked: true, value: v}
			select {
			case order <- s:
			case <-stop:
			}
		}
	}()
	for i := range n {
		select {
		case <-stop:
			return
		default:
		}
		index := start + i
		in, err := l.s.Entry(index)
		s := newSlot(index, in)
		if err != nil {
			s.res <- outcome{err: storageReadError(base, index, err)}
			select {
			case order <- s:
			case <-stop:
			}
			return
		}
		select {
		case order <- s:
		case <-stop:
			clear(in.Key)
			return
		}
		select {
		case jobs <- s:
		case <-stop:
			clear(in.Key)
			return
		}
	}
}

func (l *Log) verifyEntries(base error, jobs <-chan *slot, wg *sync.WaitGroup) {
	defer wg.Done()
	for s := range jobs {
		s.res <- l.verifySlot(base, s)
	}
}

// verifySlot checks one slot and drops its entry, so a queued slot holds no ciphertext once it is verified.
func (l *Log) verifySlot(base error, s *slot) (o outcome) {
	in := s.in
	s.in = Entry{}
	defer func() {
		if v := recover(); v != nil {
			clear(in.Key)
			o = outcome{panicked: true, value: v}
		}
	}()
	if verifyHook != nil {
		verifyHook(s.index)
	}
	o.c, o.err = l.checkStored(base, s.index, in)
	return o
}
