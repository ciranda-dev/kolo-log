package kololog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrLogOpen is returned by [New], [Restore] and the Reserve functions when a writable log with the same author key and log ID
	// is already open in this process, or that pair or log ID is reserved.
	ErrLogOpen = errors.New("kololog: log already open in this process")
	// ErrLogClosed is returned by writes and Head after [Log.Close].
	ErrLogClosed = errors.New("kololog: log closed")
)

// Logs, reservations and takeovers are all keyed by the pair (log key, log ID).
type registryKey struct {
	pub   [ed25519.PublicKeySize]byte
	logID LogID
}

var registry = struct {
	sync.Mutex
	open     map[registryKey]bool
	reserved map[registryKey]*reservation
	openIDs  map[LogID]int // open logs per ID, any key
	keyedIDs map[LogID]int // keyed reservations per ID
	idOnly   map[LogID]*reservation
}{
	open:     map[registryKey]bool{},
	reserved: map[registryKey]*reservation{},
	openIDs:  map[LogID]int{},
	keyedIDs: map[LogID]int{},
	idOnly:   map[LogID]*reservation{},
}

type reservation struct {
	key    registryKey
	idOnly bool
}

func (l *Log) registryKey() registryKey {
	k := registryKey{logID: l.logID}
	copy(k.pub[:], l.pub)
	return k
}

// register takes over res if it is the reservation held on l's key and log ID.
func (l *Log) register(res *reservation) error {
	registry.Lock()
	defer registry.Unlock()
	k := l.registryKey()
	if registry.open[k] || registry.idOnly[k.logID] != nil || (res != nil && res.key != k) {
		return ErrLogOpen
	}
	if held, ok := registry.reserved[k]; ok {
		if held != res {
			return ErrLogOpen
		}
		removeKeyed(held)
	}
	registry.open[k] = true
	registry.openIDs[k.logID]++
	return nil
}

func (l *Log) unregister() {
	registry.Lock()
	defer registry.Unlock()
	k := l.registryKey()
	if registry.open[k] {
		delete(registry.open, k)
		if registry.openIDs[k.logID]--; registry.openIDs[k.logID] <= 0 {
			delete(registry.openIDs, k.logID)
		}
	}
}

// removeKeyed needs the registry lock.
func removeKeyed(r *reservation) {
	delete(registry.reserved, r.key)
	if registry.keyedIDs[r.key.logID]--; registry.keyedIDs[r.key.logID] <= 0 {
		delete(registry.keyedIDs, r.key.logID)
	}
}

// Reserve keeps New and Restore from opening a writable log with this key and ID until release is called.
// It returns [ErrLogOpen] if such a log is open or the pair is already reserved.
func Reserve(logKey ed25519.PublicKey, id LogID) (release func(), err error) {
	r, err := reserve(logKey, id)
	if err != nil {
		return nil, err
	}
	return r.release, nil
}

// ReserveForRestore reserves like [Reserve]; passing opt to [Restore] of that key and ID lets it take the reservation over.
// release is idempotent and does nothing after a takeover; after a failed Restore the reservation stays until release.
func ReserveForRestore(logKey ed25519.PublicKey, id LogID) (opt Option, release func(), err error) {
	r, err := reserve(logKey, id)
	if err != nil {
		return nil, nil, err
	}
	return func(o *options) { o.reservation = r }, r.release, nil
}

func reserve(logKey ed25519.PublicKey, id LogID) (*reservation, error) {
	if len(logKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: log key of %d bytes", ErrMalformed, len(logKey))
	}
	k := registryKey{logID: id}
	copy(k.pub[:], logKey)
	registry.Lock()
	defer registry.Unlock()
	if registry.open[k] || registry.reserved[k] != nil || registry.idOnly[id] != nil {
		return nil, ErrLogOpen
	}
	r := &reservation{key: k}
	registry.reserved[k] = r
	registry.keyedIDs[id]++
	return r, nil
}

// ReserveID reserves a log ID under every key, for storage that cannot trust which key a log belongs to.
// It returns [ErrLogOpen] if a log with that ID is open or reserved under any key; release is idempotent.
func ReserveID(id LogID) (release func(), err error) {
	registry.Lock()
	defer registry.Unlock()
	if registry.openIDs[id] > 0 || registry.keyedIDs[id] > 0 || registry.idOnly[id] != nil {
		return nil, ErrLogOpen
	}
	r := &reservation{key: registryKey{logID: id}, idOnly: true}
	registry.idOnly[id] = r
	return r.release, nil
}

func (r *reservation) release() {
	registry.Lock()
	defer registry.Unlock()
	switch {
	case r.idOnly && registry.idOnly[r.key.logID] == r:
		delete(registry.idOnly, r.key.logID)
	case !r.idOnly && registry.reserved[r.key] == r:
		removeKeyed(r)
	}
}

// Close releases the log ID for another writable log in this process and clears a derived log's PRK; reads keep working.
// Append, Head and Delete then return [ErrLogClosed]. Closing twice is not an error.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.prk != nil {
		clear(l.prk.key()[:])
		l.prk = nil
	}
	if !l.replica {
		l.unregister()
	}
	return nil
}
