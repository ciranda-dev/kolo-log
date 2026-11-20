package kololog

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

func TestSameSizeBucket(t *testing.T) {
	l, _ := newLog(t, 0)
	for _, n := range []int{10, 200} {
		if _, err := l.Append(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	a, b := record(t, l, 0), record(t, l, 1)
	if a.Size != b.Size {
		t.Fatalf("10-byte entry has Size %d, 200-byte entry has Size %d", a.Size, b.Size)
	}
	if want := uint64(entrycrypt.MinFrame + 40); a.Size != want {
		t.Fatalf("Size = %d, want %d", a.Size, want)
	}
}

func TestGetRejectsMalformedFrames(t *testing.T) {
	l, _ := newLog(t, 0)
	valid := entrycrypt.Frame([]byte("hello kolo")) // 1-byte length, 10 bytes of data, 245 zeros
	with := func(f []byte, i int, b byte) []byte {
		f = bytes.Clone(f)
		f[i] = b
		return f
	}
	padded := func(n int) []byte { return append(bytes.Clone(valid), make([]byte, n)...) }
	tests := map[string][]byte{
		"non-zero last padding byte":  with(valid, len(valid)-1, 1),
		"non-zero first padding byte": with(valid, 11, 0x80),
		"padding too long":            padded(16),
		"padding far too long":        padded(256),
		"padding too short":           valid[:len(valid)-1],
		"no padding":                  valid[:11],
		"length past the frame":       append([]byte{0xac, 0x02}, valid[2:]...), // 300
		"length of the whole frame":   with(valid, 0, 0xff),
		"length shorter than data":    with(valid, 0, 9),
		"non-canonical length":        append([]byte{0x8a, 0x00}, valid[1:len(valid)-1]...),
		"empty":                       {},
	}
	for name, f := range tests {
		if _, err := l.Get(appendFrame(t, l, f)); !errors.Is(err, ErrMalformedEntry) || !errors.Is(err, errFrame) {
			t.Errorf("%s: Get returned %v, want %v", name, err, errFrame)
		}
	}
	if got, err := l.Get(appendFrame(t, l, valid)); err != nil || string(got) != "hello kolo" {
		t.Fatalf("valid frame: Get = %q, %v", got, err)
	}
}

// appendFrame has the owner sign and store an entry whose ciphertext seals the frame f as given, as a buggy or hostile writer could.
func appendFrame(t testing.TB, l *Log, f []byte) uint64 {
	t.Helper()
	key, aead, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	index := uint64(len(l.records))
	ct, err := entrycrypt.SealFrame(aead, entryAD(l.pub, l.logID, index), f)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{LogKey: l.pub, LogID: l.logID, Index: index, Size: uint64(len(ct)), ContentHash: blake2b.Sum256(ct), KeyCommit: entrycrypt.Commit(key[:])}
	if r.Signature, err = l.id.Sign(RecordContext, r.signed()); err != nil {
		t.Fatal(err)
	}
	l.tree.Append(merkle.LeafHash(r.Encode()))
	if err := l.s.Commit(Change{Start: index, Entries: []Entry{{Record: r.Encode(), Ciphertext: ct, Key: key[:]}}}); err != nil {
		t.Fatal(err)
	}
	l.records = append(l.records, compact(r, flagKeyed))
	return index
}

func TestEntryErrorsMap(t *testing.T) {
	if err := checkEntrySize(1<<64 - 1); !errors.Is(err, ErrEntryTooLarge) {
		t.Errorf("checkEntrySize(max) = %v, want %v", err, ErrEntryTooLarge)
	}
	if err := checkEntrySize(0); err != nil {
		t.Errorf("checkEntrySize(0) = %v", err)
	}
	_, aead, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := openFrame(aead, nil, make([]byte, 100)); !errors.Is(err, errDecrypt) || !errors.Is(err, ErrMalformedEntry) {
		t.Errorf("openFrame of garbage = %v, want %v", err, errDecrypt)
	}
	if errDecrypt.Error() != "kololog: malformed entry: authentication failed" || errFrame.Error() != "kololog: malformed entry: bad length or padding" {
		t.Errorf("messages changed: %q, %q", errDecrypt, errFrame)
	}
}
