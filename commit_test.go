package kololog

import (
	"crypto/cipher"
	"errors"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

// appendUncommitted lets the owner sign a record that commits to one key while the ciphertext opens under another,
// the shape of a ciphertext crafted to open under two keys to two plaintexts.
// It returns the entry it stored, since the log's own reads refuse its key.
func appendUncommitted(t testing.TB, l *Log) Entry {
	t.Helper()
	committed, _, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, aead, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	index := uint64(len(l.records))
	ct, err := entrycrypt.Seal(aead, entryAD(l.pub, l.logID, index), []byte("second plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	r := Record{LogKey: l.pub, LogID: l.logID, Index: index, Size: uint64(len(ct)), ContentHash: blake2b.Sum256(ct), KeyCommit: entrycrypt.Commit(committed[:])}
	if r.Signature, err = l.id.Sign(RecordContext, r.signed()); err != nil {
		t.Fatal(err)
	}
	l.tree.Append(merkle.LeafHash(r.Encode()))
	e := Entry{Record: r.Encode(), Ciphertext: ct, Key: key[:]}
	if err := l.s.Commit(Change{Start: index, Entries: []Entry{e}}); err != nil {
		t.Fatal(err)
	}
	l.records = append(l.records, compact(r, flagKeyed))
	return e
}

func TestKeyCommitment(t *testing.T) {
	l, id := newLog(t, 2)
	e := mustEntry(t, l, 0)
	rec := record(t, l, 0)
	var enc kolocodec.Encoder
	enc.PutString(KeyContext)
	enc.PutFixed(e.Key)
	if rec.KeyCommit != blake2b.Sum256(enc.Bytes()) {
		t.Fatal("record does not commit to BLAKE2b-256 of KeyContext and the entry key")
	}

	bad := appendUncommitted(t, l)
	if got, err := entrycrypt.Open(mustAEAD(t, bad.Key), entryAD(l.pub, l.logID, 2), bad.Ciphertext); err != nil || string(got) != "second plaintext" {
		t.Fatalf("the uncommitted key does not open its ciphertext: %q, %v", got, err)
	}
	if _, err := l.Get(2); !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("Get of an entry stored with a key the record does not commit to: %v, want ErrStorageMismatch", err)
	}
	r := newReplica(t, l)
	u := update{head: head(t, l), entries: []Entry{mustEntry(t, l, 0), mustEntry(t, l, 1), bad}}
	if err := u.apply(r); !errors.Is(err, ErrBadEntry) || r.Len() != 0 {
		t.Fatalf("Update with a key the record does not commit to: %v, want ErrBadEntry", err)
	}
	h := head(t, l)
	l.Close()
	entries := cloneEntries(u.entries)
	if _, err := Restore(id, l.Header().Encode(), h.Encode(), storeOf(entries)); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("Restore with an uncommitted key: %v, want ErrRestoreMismatch", err)
	}
	if _, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h.Encode(), entries); !errors.Is(err, ErrRestoreMismatch) {
		t.Fatalf("RestoreReplica with an uncommitted key: %v, want ErrRestoreMismatch", err)
	}

	u.entries[2].Key = nil
	if err := u.apply(r); err != nil {
		t.Fatalf("the same entry without its key: %v", err)
	}
	if _, err := r.Get(2); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Get of the entry received without a key: %v", err)
	}
}

func TestTamperedCiphertextWithoutKey(t *testing.T) {
	l, _ := newLog(t, 2)
	u := updateFrom(t, l, 0)
	u.entries[1].Key = nil
	u.entries[1].Ciphertext = flip(u.entries[1].Ciphertext, 40)
	if err := u.apply(newReplica(t, l)); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("tampered ciphertext without a key: %v, want ErrBadEntry", err)
	}
}

// TestCommittedKeyThatDoesNotOpen has the owner commit to one key and encrypt under another; the committed key must not be kept.
func TestCommittedKeyThatDoesNotOpen(t *testing.T) {
	l, _ := newLog(t, 0)
	committed, _, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	_, aead, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	ct, err := entrycrypt.Seal(aead, entryAD(l.pub, l.logID, 0), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	r := Record{LogKey: l.pub, LogID: l.logID, Size: uint64(len(ct)), ContentHash: blake2b.Sum256(ct), KeyCommit: entrycrypt.Commit(committed[:])}
	if r.Signature, err = l.id.Sign(RecordContext, r.signed()); err != nil {
		t.Fatal(err)
	}
	l.tree.Append(merkle.LeafHash(r.Encode()))
	e := Entry{Record: r.Encode(), Ciphertext: ct}
	if err := l.s.Commit(Change{Entries: []Entry{e}}); err != nil {
		t.Fatal(err)
	}
	l.records = append(l.records, compact(r, 0))
	l.mu.Unlock()
	u := updateFrom(t, l, 0)
	u.entries[0].Key = committed[:]
	if err := u.apply(newReplica(t, l)); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("a committed key that does not open the ciphertext: %v, want ErrBadEntry", err)
	}
}

func mustAEAD(t testing.TB, key []byte) cipher.AEAD {
	t.Helper()
	_, aead, err := entrycrypt.FromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}
