package kololog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	xhkdf "golang.org/x/crypto/hkdf"
)

func testSecret(b byte) *EntrySecret {
	var s EntrySecret
	for i := range s {
		s[i] = b
	}
	return &s
}

func newDerivedLog(t testing.TB, s Storage, secret *EntrySecret, epoch uint64, n int) (*Log, *koloid.Identity) {
	t.Helper()
	id := newID(t)
	l, err := New(id, s, WithDerivedKeys(secret, epoch))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	appendN(t, l, 0, n)
	return l, id
}

func deriverOf(t testing.TB, l *Log, secret *EntrySecret) *KeyDeriver {
	t.Helper()
	d, err := NewKeyDeriver(secret, l.pub, l.Header())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func derivedKeys(t testing.TB, d *KeyDeriver, from, n uint64) []EntryKey {
	t.Helper()
	var out []EntryKey
	for i := from; i < from+n; i++ {
		k, err := d.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

// appendHostile has the owner sign and store an entry whose record commits to commitKey while its ciphertext is sealed under
// sealKey, as a hostile writer could; the log stores it without a key.
func appendHostile(t testing.TB, l *Log, commitKey, sealKey []byte) uint64 {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	index := uint64(len(l.records))
	ct, err := entrycrypt.Seal(mustAEAD(t, sealKey), entryAD(l.pub, l.logID, index), []byte("hostile"))
	if err != nil {
		t.Fatal(err)
	}
	r := Record{LogKey: l.pub, LogID: l.logID, Index: index, Size: uint64(len(ct)), ContentHash: blake2b.Sum256(ct), KeyCommit: entrycrypt.Commit(commitKey)}
	if r.Signature, err = l.id.Sign(RecordContext, r.signed()); err != nil {
		t.Fatal(err)
	}
	l.tree.Append(merkle.LeafHash(r.Encode()))
	if err := l.s.Commit(Change{Start: index, Entries: []Entry{{Record: r.Encode(), Ciphertext: ct}}}); err != nil {
		t.Fatal(err)
	}
	l.records = append(l.records, compact(r, 0))
	return index
}

func randomKey(t testing.TB) []byte {
	t.Helper()
	k, _, err := entrycrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k[:]
}

func keylessReplica(t testing.TB, l *Log, s Storage) *Replica {
	t.Helper()
	r, err := NewReplica(l.pub, l.ID(), l.Header().Encode(), s)
	if err != nil {
		t.Fatal(err)
	}
	u := updateFrom(t, l, 0)
	for i := range u.entries {
		u.entries[i].Key = nil
	}
	if err := u.apply(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// The known answers below were computed by four independent HKDF implementations.
var derivedVectors = []struct {
	epoch, index uint64
	key, commit  string
}{
	{0, 0, "8dbf533f49eca1008f640858f2af2ce3f28c112d65a5f82b77b3a84cb98444dd", "eb98765f127b0ff9f051cca069e188eb65487d4a786fef8d978c4125d981d70d"},
	{0, 1, "1cdbab42d2b7a2fcb28bef541a44827c5cd56dfc87b920b96eb599da38f8cf7e", "0fbf77554300e1929fc58b02c24e2bf5a61585017e5b702803ecb2ebf65ce7f6"},
	{1, 0, "33092e8be7445d4ff8e9acf22909690e2c3996cd0d5e776631564db5eefaa866", "dc62caaa042fe41d4aa3319ba06fa9315c00b57d57a7a2ebba4800c8e4aed62a"},
	{0, 1 << 63, "a2f7ccecc65c5e6f119f4539bcefa83524b6a592e9a8ed725a3975e5d7317878", "f975eb7ec0e24f980561b02d223d1a3f97c052837786e8f9d2ebc09a779a2948"},
	{0, math.MaxUint64, "585ae58b84a4c4d3ac9f27ff4deb4ac656400d888b5d20d84b1eed78dfcf1897", "8d8eb4cd4e1030c85896f1663fb1628ae7ac9508f523855c914ba524a33dd514"},
}

func vectorLog() (ed25519.PublicKey, LogID) {
	var id LogID
	for i := range id {
		id[i] = 0x33
	}
	return bytes.Repeat([]byte{0x22}, 32), id
}

func TestDerivedKeyVectors(t *testing.T) {
	secret := testSecret(0x11)
	p, err := newPRK(secret)
	if err != nil {
		t.Fatal(err)
	}
	logKey, logID := vectorLog()
	wantInfo := "156b6f6c6f2d6c6f672f656e7472792d6b65792f7630" + strings.Repeat("22", 32) + strings.Repeat("33", 32) + "0000"
	if got := hex.EncodeToString(keyInfo(logKey, logID, 0, 0)); got != wantInfo {
		t.Fatalf("info (0, 0)\n got %s\nwant %s", got, wantInfo)
	}
	for _, v := range derivedVectors {
		k, err := p.entryKey(logKey, logID, v.epoch, v.index)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(k[:]); got != v.key {
			t.Errorf("key (%d, %d) = %s, want %s", v.epoch, v.index, got, v.key)
		}
		if c := entrycrypt.Commit(k[:]); hex.EncodeToString(c[:]) != v.commit {
			t.Errorf("KeyCommit (%d, %d) = %x, want %s", v.epoch, v.index, c, v.commit)
		}
		// The same key from golang.org/x/crypto/hkdf and from crypto/hkdf in one call.
		info := keyInfo(logKey, logID, v.epoch, v.index)
		x := make([]byte, 32)
		if _, err := io.ReadFull(xhkdf.New(sha256.New, secret[:], nil, info), x); err != nil || hex.EncodeToString(x) != v.key {
			t.Errorf("x/crypto/hkdf key (%d, %d) = %x, %v", v.epoch, v.index, x, err)
		}
		if s, err := hkdf.Key(sha256.New, secret[:], nil, string(info), 32); err != nil || hex.EncodeToString(s) != v.key {
			t.Errorf("crypto/hkdf key (%d, %d) = %x, %v", v.epoch, v.index, s, err)
		}
	}

	// RFC 5869 appendix A.1 to A.3 through the same helpers.
	seq := func(from, n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(from + i)
		}
		return b
	}
	rfc := []struct {
		name            string
		ikm, salt, info []byte
		n               int
		prk, okm        string
	}{
		{"A.1", bytes.Repeat([]byte{0x0b}, 22), seq(0, 13), seq(0xf0, 10), 42,
			"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"A.2", seq(0, 80), seq(0x60, 80), seq(0xb0, 80), 82,
			"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
		{"A.3", bytes.Repeat([]byte{0x0b}, 22), nil, nil, 42,
			"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	}
	for _, v := range rfc {
		prk, err := hkdfExtract(v.ikm, v.salt)
		if err != nil || hex.EncodeToString(prk) != v.prk {
			t.Errorf("RFC 5869 %s PRK = %x, %v", v.name, prk, err)
		}
		okm, err := hkdfExpand(prk, v.info, v.n)
		if err != nil || hex.EncodeToString(okm) != v.okm {
			t.Errorf("RFC 5869 %s OKM = %x, %v", v.name, okm, err)
		}
	}
	// An empty salt is a salt of 32 zero bytes (RFC 5869, 2.2).
	a, _ := hkdfExtract(secret[:], nil)
	b, _ := hkdfExtract(secret[:], make([]byte, 32))
	if !bytes.Equal(a, b) {
		t.Error("an empty salt differs from 32 zero bytes")
	}

	// The chat's chain: an entry secret derived from a conversation key, then entry key (0, 0).
	conv := bytes.Repeat([]byte{0x44}, 32)
	prk, err := hkdfExtract(conv, nil)
	if err != nil {
		t.Fatal(err)
	}
	es, err := hkdfExpand(prk, []byte("kolochat/entry-secret/v1"), EntrySecretSize)
	if err != nil || hex.EncodeToString(es) != "0fe3e1f118c5efdb7f9c8ce52b8376dd66c086335c07728dda38f3dacda78662" {
		t.Fatalf("chat entry secret = %x, %v", es, err)
	}
	cp, err := newPRK((*EntrySecret)(es))
	if err != nil {
		t.Fatal(err)
	}
	k, err := cp.entryKey(logKey, logID, 0, 0)
	if err != nil || hex.EncodeToString(k[:]) != "853b5e02ec30542c8c2d40e4674e4f6ecbe7792f94f8f4e76c7f0c521f66999d" {
		t.Fatalf("chat key (0, 0) = %x, %v", k, err)
	}
}

// Changing any one input of the derivation changes the key.
func TestDerivedKeysDistinct(t *testing.T) {
	logKey, logID := vectorLog()
	otherKey := bytes.Clone(logKey)
	otherKey[31] ^= 1
	otherID := logID
	otherID[0] ^= 1
	seen := map[[32]byte]string{}
	add := func(secret *EntrySecret, key ed25519.PublicKey, id LogID, epoch, index uint64) {
		p, err := newPRK(secret)
		if err != nil {
			t.Fatal(err)
		}
		k, err := p.entryKey(key, id, epoch, index)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("secret %x key %x id %x epoch %d index %d", secret[0], key[31], id[0], epoch, index)
		if prev, dup := seen[*k]; dup {
			t.Fatalf("%s gives the key of %s", name, prev)
		}
		seen[*k] = name
	}
	values := []uint64{0, 1, 2, 127, 128, 1 << 63, math.MaxUint64}
	for _, epoch := range values {
		for _, index := range values {
			add(testSecret(0x11), logKey, logID, epoch, index)
		}
	}
	add(testSecret(0x12), logKey, logID, 0, 0)
	add(testSecret(0x11), otherKey, logID, 0, 0)
	add(testSecret(0x11), logKey, otherID, 0, 0)
}

func TestKeyModeString(t *testing.T) {
	for m, want := range map[KeyMode]string{RandomKeys: "random", DerivedKeys: "derived", 2: "KeyMode(2)"} {
		if m.String() != want {
			t.Errorf("KeyMode(%d).String() = %q, want %q", uint8(m), m.String(), want)
		}
	}
}

func TestDerivedLog(t *testing.T) {
	secret := testSecret(5)
	callers := *secret
	opt := WithDerivedKeys(&callers, 7)
	clear(callers[:]) // the option copied the secret when called
	id := newID(t)
	l, err := New(id, NewMemory(), WithDerivedKeys(testSecret(4), 7), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	h := l.Header()
	if h.Keys != DerivedKeys || h.Epoch != 7 || VerifyLogHeader(id.PublicKey(), h) != nil {
		t.Fatalf("header %+v", h)
	}
	enc := h.Encode()
	if !bytes.HasPrefix(enc, append([]byte{byte(len(DerivedHeaderContext))}, DerivedHeaderContext...)) {
		t.Fatalf("derived header starts with %x", enc[:27])
	}
	got, err := DecodeLogHeader(enc)
	if err != nil || !bytes.Equal(got.Encode(), enc) || got.Keys != DerivedKeys || got.Epoch != 7 {
		t.Fatalf("binary round trip: %+v, %v", got, err)
	}
	j := mustJSON(t, h)
	if !strings.Contains(string(j), `"encoding":"bytes","keys":"derived","epoch":"7","signature":`) {
		t.Fatalf("derived header JSON: %s", j)
	}
	var fromJSON LogHeader
	if err := json.Unmarshal(j, &fromJSON); err != nil || !bytes.Equal(fromJSON.Encode(), enc) {
		t.Fatalf("JSON round trip: %v", err)
	}
	if s := h.String(); !strings.HasSuffix(s, "encoding=bytes, keys=derived, epoch=7}") {
		t.Fatalf("String() = %s", s)
	}

	appendN(t, l, 0, 5)
	d := deriverOf(t, l, secret)
	for i := range uint64(5) {
		k, err := d.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := l.Key(i)
		if err != nil || !bytes.Equal(k, stored) || record(t, l, i).KeyCommit != entrycrypt.Commit(k) {
			t.Fatalf("entry %d is not keyed by its derived key: %v", i, err)
		}
	}

	// A replica that got only ciphertexts reads every entry once it derives the keys.
	r := keylessReplica(t, l, NewMemory())
	if r.Header().Keys != DerivedKeys {
		t.Fatal("replica header lost the key mode")
	}
	if err := r.AddKeys(0, derivedKeys(t, d, 0, 5)); err != nil {
		t.Fatal(err)
	}
	for i := range uint64(5) {
		got, err := r.Get(i)
		if err != nil || string(got) != fmt.Sprintf("entry %d", i) {
			t.Fatalf("replica entry %d: %q, %v", i, got, err)
		}
	}

	// Restore derives too: the restored log appends under derived keys.
	hd := head(t, l)
	s := NewMemory()
	for i := range uint64(5) {
		if err := s.Commit(Change{Start: i, Entries: []Entry{mustEntry(t, l, i)}}); err != nil {
			t.Fatal(err)
		}
	}
	p := l.prk
	l.Close()
	if l.prk != nil || *p.key() != [32]byte{} {
		t.Fatal("Close did not clear the log's PRK")
	}
	back, err := Restore(id, enc, hd.Encode(), s, WithDerivedKeys(secret, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	i, err := back.Append([]byte("after restore"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := d.Key(i)
	if err != nil || record(t, back, i).KeyCommit != entrycrypt.Commit(k) {
		t.Fatalf("restored log appended under another key: %v", err)
	}
}

// Concurrent Appends each derive the key of the index they get.
func TestConcurrentDerivedAppend(t *testing.T) {
	secret := testSecret(6)
	l, _ := newDerivedLog(t, NewMemory(), secret, 3, 0)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 25 {
				if _, err := l.Append([]byte(fmt.Sprintf("%d/%d", g, i))); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	d := deriverOf(t, l, secret)
	for i := range l.Len() {
		k, err := d.Key(i)
		if err != nil || record(t, l, i).KeyCommit != entrycrypt.Commit(k) {
			t.Fatalf("entry %d does not commit to its derived key: %v", i, err)
		}
	}
}

// Entry kinds of a hostile writer's log.
const (
	kindGood     = iota
	kindRandom   // the record commits to a random key, not the derived one
	kindSealedBy // the record commits to the derived key, the ciphertext is sealed under another key
)

// hostileLog writes one entry of each kind in kinds under a derived header.
func hostileLog(t testing.TB, secret *EntrySecret, kinds []int) (*Log, *KeyDeriver) {
	t.Helper()
	l, _ := newDerivedLog(t, NewMemory(), secret, 0, 0)
	d := deriverOf(t, l, secret)
	for i, kind := range kinds {
		switch kind {
		case kindGood:
			appendN(t, l, i, 1)
		case kindRandom:
			k := randomKey(t)
			appendHostile(t, l, k, k)
		case kindSealedBy:
			k, err := d.Key(uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			appendHostile(t, l, k, randomKey(t))
		}
	}
	return l, d
}

func TestHostileWriter(t *testing.T) {
	g, rk, ws := kindGood, kindRandom, kindSealedBy
	cases := map[string][]int{
		"one random key":              {g, g, rk, g, g},
		"one ciphertext sealed apart": {g, g, g, ws, g},
		"every record bad":            {rk, ws, rk, ws, rk, ws},
		"first, last and alternate":   {rk, g, ws, g, rk, g, ws},
		"all good":                    {g, g, g},
	}
	for name, kinds := range cases {
		t.Run(name, func(t *testing.T) {
			l, d := hostileLog(t, testSecret(8), kinds)
			s := newTestStorage()
			r := keylessReplica(t, l, s)
			s.takeReads()
			commits := s.commits
			err := r.AddKeys(0, derivedKeys(t, d, 0, uint64(len(kinds))))

			var wantBad []uint64
			wantCommits := 0
			for i, k := range kinds {
				if k == kindGood {
					wantCommits = 1
				} else {
					wantBad = append(wantBad, uint64(i))
				}
			}
			var bad *BadKeyError
			switch {
			case wantBad == nil && err != nil:
				t.Fatalf("AddKeys: %v", err)
			case wantBad != nil && (!errors.As(err, &bad) || !slices.Equal(bad.Indexes, wantBad) || !errors.Is(err, ErrBadEntry)):
				t.Fatalf("AddKeys returned %v, want a BadKeyError for %v", err, wantBad)
			}
			if got := s.commits - commits; got != wantCommits {
				t.Fatalf("%d commits, want %d", got, wantCommits)
			}
			reads := map[uint64]int{}
			for _, i := range s.takeReads() {
				reads[i]++
			}
			for i, k := range kinds {
				// A key that fails its commitment is refused without reading or decrypting anything.
				n := reads[uint64(i)]
				if (k == kindRandom && n != 0) || (k != kindRandom && n != 1) {
					t.Errorf("entry %d (kind %d) read %d times", i, k, n)
				}
				got, err := r.Get(uint64(i))
				if k == kindGood && (err != nil || string(got) != fmt.Sprintf("entry %d", i)) {
					t.Errorf("good entry %d: %q, %v", i, got, err)
				}
				if k != kindGood && !errors.Is(err, ErrKeyUnavailable) {
					t.Errorf("bad entry %d: %v, want ErrKeyUnavailable", i, err)
				}
			}
			// Asking again refuses the same entries and stores nothing.
			commits = s.commits
			err = r.AddKeys(0, derivedKeys(t, d, 0, uint64(len(kinds))))
			if (wantBad == nil) != (err == nil) || s.commits != commits {
				t.Fatalf("second AddKeys: %v, %d commits", err, s.commits-commits)
			}
		})
	}
}

// flakyStorage fails the Entry read after failAfter successful ones; -1 never fails.
type flakyStorage struct {
	*testStorage
	fmu       sync.Mutex
	failAfter int
	err       error
}

func (s *flakyStorage) Entry(index uint64) (Entry, error) {
	s.fmu.Lock()
	n := s.failAfter
	if n >= 0 {
		s.failAfter--
	}
	s.fmu.Unlock()
	if n == 0 {
		return Entry{}, s.err
	}
	return s.testStorage.Entry(index)
}

func (s *flakyStorage) setFailAfter(n int, err error) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.failAfter, s.err = n, err
}

func TestAddKeysStorageFailure(t *testing.T) {
	g, rk := kindGood, kindRandom
	kinds := []int{g, rk, g, g, g}
	l, d := hostileLog(t, testSecret(9), kinds)
	s := &flakyStorage{testStorage: newTestStorage(), failAfter: -1}
	r := keylessReplica(t, l, s)
	keys := derivedKeys(t, d, 0, uint64(len(kinds)))
	noKeys := func(what string, err error) {
		t.Helper()
		var bad *BadKeyError
		if errors.As(err, &bad) {
			t.Fatalf("%s: a storage fault refused keys: %v", what, err)
		}
		for i := range r.Len() {
			if info, _ := r.EntryInfo(i); info.Keyed {
				t.Fatalf("%s: entry %d was keyed", what, i)
			}
		}
	}

	s.setFailAfter(2, errDisk)
	err := r.AddKeys(0, keys)
	if !errors.Is(err, errDisk) {
		t.Fatalf("failing third read: %v", err)
	}
	noKeys("failing read", err)

	s.setFailAfter(1, fmt.Errorf("lost: %w", ErrOutOfRange))
	err = r.AddKeys(0, keys)
	if !errors.Is(err, ErrStorageMismatch) || errors.Is(err, ErrOutOfRange) {
		t.Fatalf("an entry lost from storage: %v", err)
	}
	noKeys("lost entry", err)

	s.setFailAfter(-1, nil)
	s.failCommit = errDisk
	err = r.AddKeys(0, keys)
	if !errors.Is(err, errDisk) {
		t.Fatalf("failing commit: %v", err)
	}
	noKeys("failing commit", err)
	s.failCommit = nil

	orig := s.stored(3).Ciphertext
	s.change(3, func(e *Entry) { e.Ciphertext = flip(e.Ciphertext, 30) })
	err = r.AddKeys(0, keys)
	if !errors.Is(err, ErrStorageMismatch) {
		t.Fatalf("changed ciphertext: %v", err)
	}
	noKeys("changed ciphertext", err)
	s.change(3, func(e *Entry) { e.Ciphertext = orig })

	// Once the fault is gone, the same call stores every good key and refuses only the bad one.
	var bad *BadKeyError
	if err := r.AddKeys(0, keys); !errors.As(err, &bad) || !slices.Equal(bad.Indexes, []uint64{1}) {
		t.Fatalf("after the faults: %v", err)
	}
	for _, i := range []uint64{0, 2, 3, 4} {
		if _, err := r.Get(i); err != nil {
			t.Fatalf("entry %d after the faults: %v", i, err)
		}
	}
}

func TestAddKeysSkips(t *testing.T) {
	secret := testSecret(10)
	l, _ := newDerivedLog(t, NewMemory(), secret, 0, 6)
	d := deriverOf(t, l, secret)
	r := keylessReplica(t, l, NewMemory())
	keys := derivedKeys(t, d, 0, 6)
	if err := l.Delete(4); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyDelete(mustEntry(t, l, 4).Marker); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKey(5, keys[5]); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKeys(0, nil); err != nil {
		t.Fatalf("no keys: %v", err)
	}
	// Index 0 nil and index 1 empty skip their entries; 4 is deleted and 5 keyed, so their wrong keys are skipped, not refused.
	in := []EntryKey{nil, {}, keys[2], keys[3], randomKey(t), randomKey(t)}
	if err := r.AddKeys(0, in); err != nil {
		t.Fatalf("AddKeys: %v", err)
	}
	for i, want := range []EntryInfo{{}, {}, {Keyed: true}, {Keyed: true}, {Deleted: true}, {Keyed: true}} {
		if got, _ := r.EntryInfo(uint64(i)); got != want {
			t.Errorf("entry %d: %+v, want %+v", i, got, want)
		}
	}
	var bad *BadKeyError
	if err := r.AddKeys(0, []EntryKey{keys[0][:31], randomKey(t)}); !errors.As(err, &bad) || !slices.Equal(bad.Indexes, []uint64{0, 1}) {
		t.Fatalf("short and wrong keys: %v", err)
	}
	for _, c := range []struct {
		start uint64
		n     int
	}{{0, 7}, {6, 1}, {7, 0}, {math.MaxUint64, 1}, {math.MaxUint64, 2}} {
		if err := r.AddKeys(c.start, make([]EntryKey, c.n)); !errors.Is(err, ErrOutOfRange) {
			t.Errorf("AddKeys(%d, %d keys): %v, want ErrOutOfRange", c.start, c.n, err)
		}
	}
	if err := r.AddKeys(0, make([]EntryKey, MaxAddKeys)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("MaxAddKeys keys: %v, want ErrOutOfRange", err)
	}
	if err := r.AddKeys(0, make([]EntryKey, MaxAddKeys+1)); !errors.Is(err, ErrTooManyKeys) {
		t.Errorf("MaxAddKeys+1 keys: %v, want ErrTooManyKeys", err)
	}
	r.Close()
	if err := r.AddKeys(0, []EntryKey{keys[0]}); !errors.Is(err, ErrLogClosed) {
		t.Errorf("closed replica: %v", err)
	}

	// AddKeys also takes the keys of a log with random keys, from its writer.
	rl, _ := newLog(t, 3)
	rr := keylessReplica(t, rl, NewMemory())
	var rkeys []EntryKey
	for i := range uint64(3) {
		rkeys = append(rkeys, mustEntry(t, rl, i).Key)
	}
	if err := rr.AddKeys(0, rkeys); err != nil {
		t.Fatal(err)
	}
	if got, err := rr.Get(2); err != nil || string(got) != "entry 2" {
		t.Fatalf("random-key replica: %q, %v", got, err)
	}
}

func TestAddKeysConcurrent(t *testing.T) {
	secret := testSecret(11)
	l, _ := newDerivedLog(t, NewMemory(), secret, 0, 6)
	d := deriverOf(t, l, secret)
	keys := derivedKeys(t, d, 0, 6)
	s := &changeLog{memory: &memory{}}
	r := keylessReplica(t, l, s)
	if err := l.Delete(4); err != nil {
		t.Fatal(err)
	}
	// An entry keyed or deleted between the checks and the commit is dropped without an error.
	addKeysHook = func() {
		if err := r.AddKey(2, keys[2]); err != nil {
			t.Error(err)
		}
		if err := r.ApplyDelete(mustEntry(t, l, 4).Marker); err != nil {
			t.Error(err)
		}
	}
	err := r.AddKeys(0, keys)
	addKeysHook = nil
	if err != nil {
		t.Fatalf("AddKeys: %v", err)
	}
	c := s.last(t)
	var stored []uint64
	for _, k := range c.Keys {
		stored = append(stored, k.Index)
	}
	if !slices.Equal(stored, []uint64{0, 1, 3, 5}) || c.Start != 6 || c.Entries != nil || c.Deleted != nil || c.Heads != nil {
		t.Fatalf("AddKeys committed %+v, keys for %v", c, stored)
	}

	// Under -race: AddKeys with Update, AddKey, ApplyDelete and reads on one replica.
	l2, _ := newDerivedLog(t, NewMemory(), secret, 0, 40)
	d2 := deriverOf(t, l2, secret)
	r2 := keylessReplica(t, l2, NewMemory())
	all := derivedKeys(t, d2, 0, 80)
	grow := func() error {
		for range 10 {
			if _, err := l2.Append([]byte("more")); err != nil {
				return err
			}
		}
		h, err := l2.Head()
		if err != nil {
			return err
		}
		p, err := l2.ConsistencyProof(r2.Len(), h.Size)
		if err != nil {
			return err
		}
		var entries []Entry
		for i := r2.Len(); i < h.Size; i++ {
			e, err := l2.Entry(i)
			if err != nil {
				return err
			}
			e.Key = nil
			entries = append(entries, e)
		}
		return r2.Update(h, p, entries)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 4 {
			if err := grow(); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Go(func() {
		for i := uint64(0); i < 40; i += 7 {
			if err := l2.Delete(i); err != nil {
				t.Error(err)
			}
			e, err := l2.Entry(i)
			if err == nil {
				err = r2.ApplyDelete(e.Marker)
			}
			if err != nil {
				t.Error(err)
			}
		}
	})
	wg.Go(func() {
		for i := uint64(39); i < 40; i-- {
			if err := r2.AddKey(i, all[i]); err != nil && !errors.Is(err, ErrDeleted) {
				t.Error(err)
			}
		}
	})
	for range 3 {
		wg.Go(func() {
			for start := uint64(0); start < 80; start += 20 {
				n := r2.Len()
				if start > n {
					break
				}
				if err := r2.AddKeys(start, all[start:start+min(n-start, 20)]); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(func() {
		for range 200 {
			i := r2.Len() - 1
			r2.EntryInfo(i)
			r2.Get(i)
		}
	})
	wg.Wait()
	if err := r2.AddKeys(0, all[:r2.Len()]); err != nil {
		t.Fatal(err)
	}
	for i := range r2.Len() {
		info, _ := r2.EntryInfo(i)
		if info.Deleted == info.Keyed {
			t.Fatalf("entry %d after the race: %+v", i, info)
		}
	}
}

func TestDowngrade(t *testing.T) {
	secret := testSecret(12)
	dl, did := newDerivedLog(t, NewMemory(), secret, 2, 3)
	rl, rid := newLog(t, 3)
	verifyFails := func(name string, pub ed25519.PublicKey, h LogHeader) {
		t.Helper()
		if err := VerifyLogHeader(pub, h); !errors.Is(err, ErrBadLogHeader) {
			t.Errorf("%s: VerifyLogHeader returned %v", name, err)
		}
	}
	h := dl.Header()
	h.Signature, _ = did.Sign(HeaderContext, h.signed())
	verifyFails("derived header signed under the v0 context", did.PublicKey(), h)
	h = rl.Header()
	h.Signature, _ = rid.Sign(DerivedHeaderContext, h.signed())
	verifyFails("random header signed under the derived context", rid.PublicKey(), h)
	h = dl.Header()
	h.Keys, h.Epoch = RandomKeys, 0
	verifyFails("derived header read as random", did.PublicKey(), h)
	h = dl.Header()
	h.Epoch = 3
	verifyFails("derived header with another epoch", did.PublicKey(), h)
	h = rl.Header()
	h.Keys, h.Epoch = DerivedKeys, 0
	verifyFails("random header read as derived", rid.PublicKey(), h)
	h = rl.Header()
	h.Epoch = 1
	h.Signature, _ = rid.Sign(HeaderContext, h.signed())
	verifyFails("random header with an epoch", rid.PublicKey(), h)
	h = dl.Header()
	h.Keys = DerivedKeys + 1
	h.Signature, _ = did.Sign(DerivedHeaderContext, h.signed())
	verifyFails("unknown key mode", did.PublicKey(), h)
	// Signed correctly for the bytes it encodes: only the key mode check refuses it.
	h = rl.Header()
	h.Keys = DerivedKeys + 1
	h.Signature, _ = rid.Sign(HeaderContext, h.signed())
	verifyFails("unknown key mode signed under the v0 context", rid.PublicKey(), h)

	// snapshot closes l and returns its header, head and stored entries.
	type snapshot struct {
		header, head []byte
		entries      []Entry
	}
	snap := func(l *Log) snapshot {
		t.Helper()
		x := snapshot{header: l.Header().Encode(), head: head(t, l).Encode()}
		for i := range l.Len() {
			x.entries = append(x.entries, mustEntry(t, l, i))
		}
		l.Close()
		return x
	}
	restore := func(x snapshot, id *koloid.Identity, opts ...Option) (*Log, error) {
		t.Helper()
		back, err := Restore(id, x.header, x.head, storeOf(cloneEntries(x.entries)), opts...)
		if err == nil {
			t.Cleanup(func() { back.Close() })
		}
		return back, err
	}
	refused := func(name string, x snapshot, id *koloid.Identity, want error, opts ...Option) {
		t.Helper()
		if back, err := restore(x, id, opts...); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		} else if back != nil {
			back.Close()
		}
	}
	dx, rx := snap(dl), snap(rl)
	refused("derived log restored without the option", dx, did, ErrKeyModeMismatch)
	refused("random log restored with the option", rx, rid, ErrKeyModeMismatch, WithDerivedKeys(secret, 0))
	refused("derived log restored with another epoch", dx, did, ErrKeyModeMismatch, WithDerivedKeys(secret, 1))
	refused("derived log restored with another secret", dx, did, ErrSecretMismatch, WithDerivedKeys(testSecret(13), 2))
	refused("Restore with a nil secret", dx, did, ErrMissingSecret, WithDerivedKeys(nil, 2))
	back, err := restore(dx, did, WithDerivedKeys(secret, 2))
	if err != nil {
		t.Fatalf("derived log restored with its secret: %v", err)
	}
	if err := back.Delete(2); err != nil {
		t.Fatal(err)
	}
	deleted := snap(back)
	refused("newest entry deleted, another secret", deleted, did, ErrSecretMismatch, WithDerivedKeys(testSecret(13), 2))
	if _, err := restore(deleted, did, WithDerivedKeys(secret, 2)); err != nil {
		t.Errorf("newest entry deleted, its secret: %v", err)
	}
	// An empty log has no record to check the secret against.
	el, eid := newDerivedLog(t, NewMemory(), secret, 0, 0)
	if _, err := restore(snap(el), eid, WithDerivedKeys(testSecret(13), 0)); err != nil {
		t.Errorf("empty derived log: %v", err)
	}
	if _, err := New(newID(t), NewMemory(), WithDerivedKeys(nil, 0)); !errors.Is(err, ErrMissingSecret) {
		t.Errorf("New with a nil secret: %v", err)
	}
}

func TestDecodeDerivedHeader(t *testing.T) {
	l, _ := newDerivedLog(t, NewMemory(), testSecret(14), 300, 0)
	valid := l.Header().Encode()
	rl, _ := newLog(t, 0)
	v0 := rl.Header().Encode()
	malformed := func(name string, b []byte) {
		t.Helper()
		if _, err := DecodeLogHeader(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
	for n := range len(valid) {
		malformed(fmt.Sprintf("truncated to %d bytes", n), valid[:n])
	}
	malformed("trailing byte", append(bytes.Clone(valid), 0))
	body := valid[1+len(DerivedHeaderContext):]
	tag := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	malformed("v0 tag followed by derived fields", append(tag(HeaderContext), body...))
	malformed("derived tag followed by v0 fields", append(tag(DerivedHeaderContext), v0[1+len(HeaderContext):]...))
	for n := len(HeaderContext) + 1; n < len(DerivedHeaderContext); n++ {
		malformed(fmt.Sprintf("tag of %d bytes", n), append(tag(DerivedHeaderContext[:n]), body...))
		malformed(fmt.Sprintf("tag of %d bytes from the v0 tag", n), append(tag(HeaderContext+strings.Repeat("x", n-len(HeaderContext))), body...))
	}
	malformed("tag of 27 bytes", append(tag(DerivedHeaderContext+"x"), body...))
	malformed("derived tag with another letter", append(tag("kolo-log/derived-header/v1"), body...))
	epochAt := 1 + len(DerivedHeaderContext) + 32 + LogIDSize + 1
	if valid[epochAt] != 0xac || valid[epochAt+1] != 0x02 {
		t.Fatalf("epoch 300 is not at %d: %x", epochAt, valid[epochAt:epochAt+2])
	}
	malformed("non-minimal epoch", slices.Concat(valid[:epochAt], []byte{0xac, 0x82, 0x00}, valid[epochAt+2:]))
	malformed("overlong epoch", slices.Concat(valid[:epochAt], bytes.Repeat([]byte{0xff}, 10), []byte{0x01}, valid[epochAt+2:]))
	if _, err := DecodeLogHeader(valid); err != nil {
		t.Fatal(err)
	}
	// A decoded header with a changed epoch decodes but no longer verifies.
	changed := slices.Concat(valid[:epochAt], []byte{0xad}, valid[epochAt+1:])
	h, err := DecodeLogHeader(changed)
	if err != nil || h.Epoch != 301 {
		t.Fatalf("changed epoch: %+v, %v", h, err)
	}
	if err := VerifyLogHeader(l.pub, h); !errors.Is(err, ErrBadLogHeader) {
		t.Fatalf("changed epoch verified: %v", err)
	}
	if _, err := NewReplica(l.pub, l.ID(), changed, NewMemory()); !errors.Is(err, ErrBadLogHeader) {
		t.Fatalf("NewReplica with a changed epoch: %v", err)
	}
}

func TestDerivedHeaderJSON(t *testing.T) {
	l, _ := newDerivedLog(t, NewMemory(), testSecret(15), math.MaxUint64, 0)
	valid := mustJSON(t, l.Header())
	var back LogHeader
	if err := json.Unmarshal(valid, &back); err != nil || back.Epoch != math.MaxUint64 || !bytes.Equal(back.Encode(), l.Header().Encode()) {
		t.Fatalf("round trip: %v", err)
	}
	rl, _ := newLog(t, 0)
	random := mustJSON(t, rl.Header())
	bad := map[string][]byte{
		"random with epoch":          mutate(t, random, func(m map[string]any) { m["epoch"] = "0" }),
		"random with keys":           mutate(t, random, func(m map[string]any) { m["keys"] = "random" }),
		"random with keys and epoch": mutate(t, random, func(m map[string]any) { m["keys"], m["epoch"] = "random", "0" }),
		"derived keys without epoch": mutate(t, valid, func(m map[string]any) { delete(m, "epoch") }),
		"derived epoch without keys": mutate(t, valid, func(m map[string]any) { delete(m, "keys") }),
		"keys Derived":               mutate(t, valid, func(m map[string]any) { m["keys"] = "Derived" }),
		"keys KeyMode(2)":            mutate(t, valid, func(m map[string]any) { m["keys"] = "KeyMode(2)" }),
		"keys as a number":           mutate(t, valid, func(m map[string]any) { m["keys"] = 1 }),
		"epoch as a number":          mutate(t, valid, func(m map[string]any) { m["epoch"] = 1 }),
		"epoch with a leading zero":  mutate(t, valid, func(m map[string]any) { m["epoch"] = "01" }),
		"epoch over uint64":          mutate(t, valid, func(m map[string]any) { m["epoch"] = "18446744073709551616" }),
		"duplicate epoch":            append([]byte(`{"epoch":"1",`), valid[1:]...),
		"capitalized Keys":           bytes.Replace(valid, []byte(`"keys"`), []byte(`"Keys"`), 1),
		"derived without its fields": mutate(t, valid, func(m map[string]any) { delete(m, "keys"); delete(m, "epoch") }),
	}
	for name, b := range bad {
		var h LogHeader
		err := h.UnmarshalJSON(b)
		if name == "derived without its fields" {
			// That is a random header now, whose signature no longer verifies.
			if err != nil || h.Keys != RandomKeys || VerifyLogHeader(l.pub, h) == nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: UnmarshalJSON returned %v, want ErrMalformed", name, err)
		}
	}
	for name, h := range map[string]LogHeader{
		"random with an epoch": {Epoch: 1},
		"unknown key mode":     {Keys: DerivedKeys + 1},
	} {
		if _, err := json.Marshal(h); err == nil {
			t.Errorf("%s was marshaled", name)
		}
	}
}

func TestKeyDeriverClose(t *testing.T) {
	secret := testSecret(16)
	l, id := newDerivedLog(t, NewMemory(), secret, 0, 1)
	d, err := NewKeyDeriver(secret, id.PublicKey(), l.Header())
	if err != nil {
		t.Fatal(err)
	}
	p := d.prk
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for i := range uint64(100) {
				if _, err := d.Key(i); err != nil && !errors.Is(err, ErrDeriverClosed) {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(d.Close)
	wg.Wait()
	d.Close()
	if _, err := d.Key(0); !errors.Is(err, ErrDeriverClosed) {
		t.Fatalf("Key after Close: %v", err)
	}
	if *p.key() != [32]byte{} || d.prk != nil {
		t.Fatal("Close did not clear the PRK")
	}

	if _, err := NewKeyDeriver(secret, newID(t).PublicKey(), l.Header()); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("another owner: %v", err)
	}
	rl, rid := newLog(t, 0)
	if _, err := NewKeyDeriver(secret, rid.PublicKey(), rl.Header()); !errors.Is(err, ErrNotDerived) {
		t.Errorf("random header: %v", err)
	}
	if _, err := NewKeyDeriver(nil, id.PublicKey(), l.Header()); !errors.Is(err, ErrMissingSecret) {
		t.Errorf("nil secret: %v", err)
	}
	h := l.Header()
	h.Epoch++
	if _, err := NewKeyDeriver(secret, id.PublicKey(), h); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("changed epoch: %v", err)
	}
}

// failOnce is a memory storage whose next Commit fails after keeping a copy of the entries it was given.
type failOnce struct {
	*memory
	fail   bool
	failed []Entry
}

func (s *failOnce) Commit(c Change) error {
	if s.fail {
		s.fail = false
		for _, e := range c.Entries {
			s.failed = append(s.failed, cloneEntry(e))
		}
		return errDisk
	}
	return s.memory.Commit(c)
}

// A failed commit makes the next Append seal index 0 again under the same derived key; a fresh random nonce keeps both safe.
func TestSameIndexTwoSeals(t *testing.T) {
	secret := testSecret(17)
	s := &failOnce{memory: &memory{}, fail: true}
	l, _ := newDerivedLog(t, s, secret, 0, 0)
	if _, err := l.Append([]byte("first")); !errors.Is(err, errDisk) {
		t.Fatalf("failing Append: %v", err)
	}
	i, err := l.Append([]byte("second"))
	if err != nil || i != 0 {
		t.Fatalf("Append after the failure: %d, %v", i, err)
	}
	k, err := deriverOf(t, l, secret).Key(0)
	if err != nil {
		t.Fatal(err)
	}
	first, second := s.failed[0], mustEntry(t, l, 0)
	if !bytes.Equal(first.Key, k) || !bytes.Equal(second.Key, k) {
		t.Fatal("the two seals of index 0 used different keys")
	}
	n := chacha20poly1305.NonceSizeX
	if bytes.Equal(first.Ciphertext[:n], second.Ciphertext[:n]) {
		t.Fatal("the two seals of index 0 share a nonce")
	}
	for want, ct := range map[string][]byte{"first": first.Ciphertext, "second": second.Ciphertext} {
		got, err := entrycrypt.Open(mustAEAD(t, k), entryAD(l.pub, l.logID, 0), ct)
		if err != nil || string(got) != want {
			t.Fatalf("seal %q opens to %q, %v", want, got, err)
		}
	}
}

// lockChecker is a memory storage that counts calls made while the log's lock is free, and Commits that overlap another call.
type lockChecker struct {
	*memory
	log        atomic.Pointer[Log] // checked once set
	mu         sync.Mutex
	inFlight   int
	committing bool
	unlocked   int
	overlaps   int
}

func (s *lockChecker) enter(commit bool) func() {
	if l := s.log.Load(); l != nil && l.mu.TryLock() {
		l.mu.Unlock()
		s.mu.Lock()
		s.unlocked++
		s.mu.Unlock()
	}
	s.mu.Lock()
	if (commit && s.inFlight > 0) || s.committing {
		s.overlaps++
	}
	s.inFlight++
	s.committing = s.committing || commit
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.inFlight--
		if commit {
			s.committing = false
		}
		s.mu.Unlock()
	}
}

func (s *lockChecker) Entry(index uint64) (Entry, error) {
	defer s.enter(false)()
	return s.memory.Entry(index)
}

func (s *lockChecker) Key(index uint64) (EntryKey, error) {
	defer s.enter(false)()
	return s.memory.Key(index)
}

func (s *lockChecker) Commit(c Change) error {
	defer s.enter(true)()
	return s.memory.Commit(c)
}

func (s *lockChecker) counts() (unlocked, overlaps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlocked, s.overlaps
}

// AddKeys calls its Storage only with the replica's lock held, so a Commit never overlaps another call (Storage's contract).
func TestAddKeysStorageLocking(t *testing.T) {
	secret := testSecret(18)
	l, d := hostileLog(t, secret, []int{kindGood, kindSealedBy, kindGood, kindRandom, kindGood, kindGood})
	s := &lockChecker{memory: &memory{}}
	r := keylessReplica(t, l, s)
	s.log.Store(r.log)
	var bad *BadKeyError
	if err := r.AddKeys(0, derivedKeys(t, d, 0, 6)); !errors.As(err, &bad) {
		t.Fatalf("AddKeys: %v", err)
	}
	if u, o := s.counts(); u != 0 || o != 0 {
		t.Fatalf("one AddKeys: %d storage calls without the lock, %d overlapping commits", u, o)
	}

	// The same with Update, ApplyDelete, AddKey and reads running at once.
	appendN(t, l, 6, 30)
	all := derivedKeys(t, d, 0, 36)
	var wg sync.WaitGroup
	wg.Go(func() {
		h, err := l.Head()
		if err != nil {
			t.Error(err)
			return
		}
		p, err := l.ConsistencyProof(r.Len(), h.Size)
		if err != nil {
			t.Error(err)
			return
		}
		var entries []Entry
		for i := r.Len(); i < h.Size; i++ {
			e, err := l.Entry(i)
			if err != nil {
				t.Error(err)
				return
			}
			e.Key = nil
			entries = append(entries, e)
		}
		if err := r.Update(h, p, entries); err != nil {
			t.Error(err)
		}
	})
	wg.Go(func() {
		if err := l.Delete(5); err != nil {
			t.Error(err)
			return
		}
		e, err := l.Entry(5)
		if err == nil {
			err = r.ApplyDelete(e.Marker)
		}
		if err != nil {
			t.Error(err)
		}
	})
	for range 3 {
		wg.Go(func() {
			for range 5 {
				var bad *BadKeyError
				if err := r.AddKeys(0, all[:r.Len()]); err != nil && !errors.As(err, &bad) {
					t.Error(err)
				}
			}
		})
	}
	wg.Go(func() {
		for i := range uint64(6) {
			r.Get(i)
			r.Key(i)
			r.AddKey(i, all[i])
		}
	})
	wg.Wait()
	if u, o := s.counts(); u != 0 || o != 0 {
		t.Fatalf("under load: %d storage calls without the lock, %d overlapping commits", u, o)
	}
}
