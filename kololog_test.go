package kololog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

func newID(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newLogFor(t testing.TB, id *koloid.Identity, n int) *Log {
	t.Helper()
	l, err := New(id, NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for i := range n {
		if _, err := l.Append([]byte(fmt.Sprintf("entry %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func newLog(t testing.TB, n int) (*Log, *koloid.Identity) {
	t.Helper()
	id := newID(t)
	return newLogFor(t, id, n), id
}

func head(t testing.TB, l *Log) Head {
	t.Helper()
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func verified(t testing.TB, l *Log) VerifiedHead {
	t.Helper()
	v, err := VerifyHead(l.pub, l.logID, head(t, l))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func record(t testing.TB, l *Log, i uint64) Record {
	t.Helper()
	r, err := l.Record(i)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewUnusableIdentity(t *testing.T) {
	for name, id := range map[string]*koloid.Identity{"nil": nil, "zero": {}} {
		l, err := New(id, NewMemory())
		if !errors.Is(err, koloid.ErrInvalidIdentity) || l != nil {
			t.Errorf("New(%s identity, NewMemory()) = %v, %v; want nil, %v", name, l, err, koloid.ErrInvalidIdentity)
		}
	}
}

func TestAppendGet(t *testing.T) {
	l, _ := newLog(t, 0)
	inputs := [][]byte{[]byte("hello kolo"), {}, bytes.Repeat([]byte{0xab}, 10000)}
	for i, in := range inputs {
		index, err := l.Append(in)
		if err != nil {
			t.Fatal(err)
		}
		if index != uint64(i) {
			t.Fatalf("Append returned index %d, want %d", index, i)
		}
		if got := l.Len(); got != uint64(i+1) {
			t.Fatalf("Len() = %d, want %d", got, i+1)
		}
	}
	for i, in := range inputs {
		got, err := l.Get(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("Get(%d) = %q, want %q", i, got, in)
		}
	}
	if _, err := l.Get(uint64(len(inputs))); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Get past the end returned %v, want %v", err, ErrOutOfRange)
	}
}

func TestRecordHidesPlaintext(t *testing.T) {
	l, id := newLog(t, 0)
	data := []byte("a secret that must not appear in the record")
	if _, err := l.Append(data); err != nil {
		t.Fatal(err)
	}
	r := record(t, l, 0)
	if !VerifyRecord(id.PublicKey(), l.ID(), r) {
		t.Fatal("valid record rejected")
	}
	if bytes.Contains(r.Encode(), data) {
		t.Fatal("record encoding contains the plaintext")
	}
	if r.Size <= uint64(len(data)) {
		t.Fatalf("record size %d does not cover nonce and tag", r.Size)
	}
}

func TestHeadVerify(t *testing.T) {
	for _, n := range []int{0, 1, 5} {
		l, id := newLog(t, n)
		pub := id.PublicKey()
		h := head(t, l)
		v, err := VerifyHead(pub, l.ID(), h)
		if err != nil {
			t.Fatalf("size %d: valid head rejected: %v", n, err)
		}
		if v.Size() != uint64(n) || v.LogID() != l.ID() || v.Root() != h.Root || !v.LogKey().Equal(pub) {
			t.Fatalf("size %d: verified head does not match the head", n)
		}
		if !bytes.Equal(v.Head().Encode(), h.Encode()) {
			t.Fatalf("size %d: VerifiedHead.Head changed the head", n)
		}

		tampered := map[string]Head{}
		th := h
		th.Size++
		tampered["size"] = th
		th = h
		th.Root[0] ^= 1
		tampered["root"] = th
		th = h
		th.LogID[0] ^= 1
		tampered["log ID"] = th
		th = h.clone()
		th.LogKey[0] ^= 1
		tampered["log key"] = th
		th = h.clone()
		th.Signature[0] ^= 1
		tampered["signature"] = th
		for name, th := range tampered {
			// The signature is checked before the log ID, so every tamper is a bad signature.
			_, err := VerifyHead(pub, l.ID(), th)
			if !errors.Is(err, ErrBadHeadSignature) || !errors.Is(err, ErrInvalidHead) {
				t.Errorf("size %d: tampered %s returned %v, want %v", n, name, err, ErrBadHeadSignature)
			}
		}
		// The signature covers the log ID, not only the expected-ID check.
		th = h
		th.LogID[0] ^= 1
		if _, err := VerifyHead(pub, th.LogID, th); !errors.Is(err, ErrBadHeadSignature) {
			t.Errorf("size %d: head with a rewritten log ID returned %v", n, err)
		}
		if _, err := VerifyHead(newID(t).PublicKey(), l.ID(), h); err == nil {
			t.Errorf("size %d: head accepted under another key", n)
		}
	}
}

func TestVerifyHeadChecksLogID(t *testing.T) {
	id := newID(t)
	a, b := newLogFor(t, id, 3), newLogFor(t, id, 3)
	ha, hb := head(t, a), head(t, b)
	if _, err := VerifyHead(id.PublicKey(), a.ID(), ha); err != nil {
		t.Fatalf("head of log A rejected against A's ID: %v", err)
	}
	if _, err := VerifyHead(id.PublicKey(), b.ID(), hb); err != nil {
		t.Fatalf("head of log B rejected against B's ID: %v", err)
	}
	_, err := VerifyHead(id.PublicKey(), a.ID(), hb)
	if !errors.Is(err, ErrWrongLogID) || !errors.Is(err, ErrInvalidHead) || errors.Is(err, ErrBadHeadSignature) {
		t.Fatalf("signed head of log B verified against A's ID: %v, want %v", err, ErrWrongLogID)
	}
}

func TestVerifyHeadErrors(t *testing.T) {
	l, id := newLog(t, 2)
	pub := id.PublicKey()
	h := head(t, l)
	other := newID(t).PublicKey()
	badSig := h.clone()
	badSig.Signature[0] ^= 1
	otherLog := newLogFor(t, id, 2)

	tests := []struct {
		name  string
		pub   ed25519.PublicKey
		logID LogID
		h     Head
		want  error
	}{
		{"bad signature", pub, l.ID(), badSig, ErrBadHeadSignature},
		{"wrong log key", other, l.ID(), h, ErrBadHeadSignature},
		{"short log key", pub[:31], l.ID(), h, ErrBadHeadSignature},
		{"wrong log ID", pub, otherLog.ID(), h, ErrWrongLogID},
	}
	for _, tt := range tests {
		_, err := VerifyHead(tt.pub, tt.logID, tt.h)
		if !errors.Is(err, tt.want) || !errors.Is(err, ErrInvalidHead) {
			t.Errorf("%s: VerifyHead returned %v, want %v wrapping %v", tt.name, err, tt.want, ErrInvalidHead)
		}
	}
	for _, err := range []error{ErrBadHeadSignature, ErrWrongLogID} {
		if errors.Is(err, ErrBadHeadSignature) && errors.Is(err, ErrWrongLogID) {
			t.Errorf("%v matches both causes", err)
		}
	}
	if ErrBadHeadSignature.Error() != "kololog: invalid head signature" || ErrWrongLogID.Error() != "kololog: head belongs to another log" {
		t.Errorf("unexpected messages %q and %q", ErrBadHeadSignature, ErrWrongLogID)
	}
}

func TestVerifyRecordChecksLogID(t *testing.T) {
	id := newID(t)
	a, b := newLogFor(t, id, 3), newLogFor(t, id, 3)
	rb := record(t, b, 1)
	if !VerifyRecord(id.PublicKey(), b.ID(), rb) {
		t.Fatal("record of log B rejected against B's ID")
	}
	if VerifyRecord(id.PublicKey(), a.ID(), rb) {
		t.Fatal("signed record of log B accepted against A's ID")
	}
	rewritten := rb
	rewritten.LogID = a.ID()
	if VerifyRecord(id.PublicKey(), a.ID(), rewritten) {
		t.Fatal("record with a rewritten log ID accepted")
	}
}

func TestVerifiedHeadIsACopy(t *testing.T) {
	l, id := newLog(t, 2)
	h := head(t, l)
	v, err := VerifyHead(id.PublicKey(), l.ID(), h)
	if err != nil {
		t.Fatal(err)
	}
	h.LogKey[0] ^= 1
	v.LogKey()[0] ^= 1
	v.Head().LogKey[0] ^= 1
	if !v.LogKey().Equal(id.PublicKey()) {
		t.Fatal("changing a head changed the verified head")
	}
}

func TestZeroVerifiedHead(t *testing.T) {
	l, _ := newLog(t, 3)
	r := record(t, l, 0)
	var zero VerifiedHead
	empty, err := l.ConsistencyProof(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The zero head has size 0 and the zero root, so it must fail on its own.
	if VerifyInclusion(zero, r, InclusionProof{}) {
		t.Fatal("zero head verified an inclusion proof")
	}
	if VerifyConsistency(zero, zero, empty) {
		t.Fatal("two zero heads verified as consistent")
	}
	v := verified(t, l)
	all, err := l.ConsistencyProof(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyConsistency(zero, v, all) || VerifyConsistency(v, zero, all) {
		t.Fatal("a zero head verified as consistent with a real one")
	}
}

func TestSignaturesUseContexts(t *testing.T) {
	l, id := newLog(t, 1)
	pub := id.PublicKey()
	h, r := head(t, l), record(t, l, 0)
	if !koloid.Verify(pub, HeadContext, h.signed(), h.Signature) {
		t.Fatal("head is not signed under HeadContext")
	}
	if !koloid.Verify(pub, RecordContext, r.signed(), r.Signature) {
		t.Fatal("record is not signed under RecordContext")
	}
	if koloid.Verify(pub, RecordContext, h.signed(), h.Signature) {
		t.Fatal("head signature valid under RecordContext")
	}
	other, err := id.Sign("another-protocol/v0", h.signed())
	if err != nil {
		t.Fatal(err)
	}
	forged := h
	forged.Signature = other
	if _, err := VerifyHead(pub, l.ID(), forged); err == nil {
		t.Fatal("head signed under another context accepted")
	}
}

func TestVerifyBadKeySizes(t *testing.T) {
	l, id := newLog(t, 3)
	pub := id.PublicKey()
	h := head(t, l)
	r := record(t, l, 1)
	bad := []ed25519.PublicKey{nil, {}, pub[:31], append(bytes.Clone(pub), 0), make([]byte, 64)}
	for _, key := range bad {
		if _, err := VerifyHead(key, l.ID(), h); err == nil {
			t.Errorf("VerifyHead accepted a %d-byte public key", len(key))
		}
		if VerifyRecord(key, l.ID(), r) {
			t.Errorf("VerifyRecord accepted a %d-byte public key", len(key))
		}
		hk, rk := h, r
		hk.LogKey, rk.LogKey = key, key
		if _, err := VerifyHead(key, l.ID(), hk); err == nil || VerifyRecord(key, l.ID(), rk) {
			t.Errorf("a %d-byte key in the head or record was accepted", len(key))
		}
	}
	h.Signature = h.Signature[:10]
	if _, err := VerifyHead(pub, l.ID(), h); err == nil {
		t.Error("short signature accepted")
	}
}

func TestInclusionProofs(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 8, 9, 100} {
		l, _ := newLog(t, n)
		v := verified(t, l)
		for i := range uint64(n) {
			r := record(t, l, i)
			p, err := l.InclusionProof(i, v.Size())
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyInclusion(v, r, p) {
				t.Fatalf("size %d index %d: valid proof rejected", n, i)
			}
			decoded, err := DecodeInclusionProof(p.Encode())
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyInclusion(v, r, decoded) {
				t.Fatalf("size %d index %d: decoded proof rejected", n, i)
			}
			checkInclusionTampering(t, v, r, p)
		}
	}
}

func checkInclusionTampering(t *testing.T, v VerifiedHead, r Record, p InclusionProof) {
	t.Helper()
	at := fmt.Sprintf("size %d index %d", p.Size, p.Index)
	for i := range p.Path {
		q := p
		q.Path = append([][HashSize]byte(nil), p.Path...)
		q.Path[i][HashSize-1] ^= 1
		if VerifyInclusion(v, r, q) {
			t.Fatalf("%s: tampered path hash %d accepted", at, i)
		}
	}
	q := p
	q.Path = append(append([][HashSize]byte(nil), p.Path...), [HashSize]byte{})
	if VerifyInclusion(v, r, q) {
		t.Fatalf("%s: extended path accepted", at)
	}
	if len(p.Path) > 0 {
		q.Path = p.Path[:len(p.Path)-1]
		if VerifyInclusion(v, r, q) {
			t.Fatalf("%s: truncated path accepted", at)
		}
	}
	q = p
	q.Size++
	if VerifyInclusion(v, r, q) {
		t.Fatalf("%s: wrong proof size accepted", at)
	}
	rr := r
	rr.Index++
	if VerifyInclusion(v, rr, p) {
		t.Fatalf("%s: tampered record index accepted", at)
	}
	rr = r
	rr.LogID[0] ^= 1
	if VerifyInclusion(v, rr, p) {
		t.Fatalf("%s: tampered record log ID accepted", at)
	}
	rr = r
	rr.ContentHash[0] ^= 1
	if VerifyInclusion(v, rr, p) {
		t.Fatalf("%s: tampered content hash accepted", at)
	}
}

func TestVerifyInclusionChecksRecordSignature(t *testing.T) {
	l, _ := newLog(t, 4)
	v := verified(t, l)
	p, err := l.InclusionProof(2, v.Size())
	if err != nil {
		t.Fatal(err)
	}
	r := record(t, l, 2)
	r.Signature = make([]byte, ed25519.SignatureSize)
	if VerifyInclusion(v, r, p) {
		t.Fatal("record with a bad signature accepted")
	}
}

func TestInclusionProofOlderHead(t *testing.T) {
	l, _ := newLog(t, 5)
	old := verified(t, l)
	for range 6 {
		if _, err := l.Append([]byte("more")); err != nil {
			t.Fatal(err)
		}
	}
	p, err := l.InclusionProof(3, old.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(old, record(t, l, 3), p) {
		t.Fatal("proof against an older head rejected")
	}
}

func TestConsistencyProofs(t *testing.T) {
	l, _ := newLog(t, 0)
	var heads []VerifiedHead
	for i := range 20 {
		heads = append(heads, verified(t, l))
		if _, err := l.Append([]byte(fmt.Sprintf("entry %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	heads = append(heads, verified(t, l))
	for _, old := range heads {
		for _, cur := range heads[old.Size():] {
			p, err := l.ConsistencyProof(old.Size(), cur.Size())
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeConsistencyProof(p.Encode())
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyConsistency(old, cur, decoded) {
				t.Fatalf("%d -> %d: valid proof rejected", old.Size(), cur.Size())
			}
			if old.Size() > 0 && old.Size() < cur.Size() {
				q := p
				q.Path = append([][HashSize]byte(nil), p.Path...)
				q.Path[0][0] ^= 1
				if VerifyConsistency(old, cur, q) {
					t.Fatalf("%d -> %d: tampered proof accepted", old.Size(), cur.Size())
				}
			}
		}
	}
	if _, err := l.ConsistencyProof(3, 2); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("shrinking ConsistencyProof returned %v, want %v", err, ErrOutOfRange)
	}
	if _, err := l.ConsistencyProof(0, l.Len()+1); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("ConsistencyProof past the end returned %v, want %v", err, ErrOutOfRange)
	}
}

func TestLogsAreSeparated(t *testing.T) {
	id := newID(t)
	pub := id.PublicKey()
	a, b := newLogFor(t, id, 0), newLogFor(t, id, 0)
	if a.ID() == b.ID() {
		t.Fatal("two logs got the same ID")
	}

	// Empty logs have the same size and root, but their heads differ.
	va0, vb0 := verified(t, a), verified(t, b)
	if bytes.Equal(va0.Head().Encode(), vb0.Head().Encode()) {
		t.Fatal("empty heads of two logs are interchangeable")
	}

	for _, l := range []*Log{a, b} {
		for range 5 {
			if _, err := l.Append([]byte("same data")); err != nil {
				t.Fatal(err)
			}
		}
	}
	va, vb := verified(t, a), verified(t, b)
	ra, rb := record(t, a, 2), record(t, b, 2)
	pa, err := a.InclusionProof(2, va.Size())
	if err != nil {
		t.Fatal(err)
	}
	pb, err := b.InclusionProof(2, vb.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(va, ra, pa) || !VerifyInclusion(vb, rb, pb) {
		t.Fatal("valid proof rejected")
	}
	if VerifyInclusion(va, rb, pa) || VerifyInclusion(va, rb, pb) || VerifyInclusion(vb, ra, pb) {
		t.Fatal("record of one log accepted in the other")
	}

	ca, err := a.ConsistencyProof(0, va.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConsistency(va0, va, ca) {
		t.Fatal("valid consistency proof rejected")
	}
	if VerifyConsistency(vb0, va, ca) || VerifyConsistency(va0, vb, ca) {
		t.Fatal("heads of two logs accepted as consistent")
	}

	ea := mustEntry(t, a, 2)
	aead := mustAEAD(t, ea.Key)
	if _, _, err := openFrame(aead, entryAD(pub, a.ID(), 2), ea.Ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openFrame(aead, entryAD(pub, b.ID(), 2), ea.Ciphertext); !errors.Is(err, errDecrypt) {
		t.Fatalf("ciphertext opened under another log ID: %v", err)
	}
}

func TestOutOfRange(t *testing.T) {
	l, _ := newLog(t, 3)
	checks := map[string]error{}
	_, checks["Get"] = l.Get(3)
	_, checks["Record"] = l.Record(3)
	_, checks["InclusionProof index"] = l.InclusionProof(3, 3)
	_, checks["InclusionProof size"] = l.InclusionProof(0, 4)
	_, checks["InclusionProof empty"] = l.InclusionProof(0, 0)
	checks["Delete"] = l.Delete(3)
	for name, err := range checks {
		if !errors.Is(err, ErrOutOfRange) {
			t.Errorf("%s returned %v, want %v", name, err, ErrOutOfRange)
		}
	}
}

func TestDelete(t *testing.T) {
	l, id := newLog(t, 9)
	pub := id.PublicKey()
	before := verified(t, l)

	if err := l.Delete(4); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(4); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Get after Delete returned %v, want %v", err, ErrDeleted)
	}
	if _, err := l.Key(4); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Key after Delete returned %v, want %v", err, ErrDeleted)
	}
	e := mustEntry(t, l, 4)
	if e.Key != nil || e.Ciphertext != nil || e.Marker == nil {
		t.Fatal("the stored entry kept its key or ciphertext, or has no marker")
	}
	if err := l.Delete(4); err != nil {
		t.Fatalf("second Delete returned %v", err)
	}
	if got, err := l.Get(5); err != nil || string(got) != "entry 5" {
		t.Fatalf("Get(5) = %q, %v after deleting entry 4", got, err)
	}

	after := verified(t, l)
	if after.Size() != before.Size() || after.Root() != before.Root() {
		t.Fatal("Delete changed the tree head")
	}
	if l.Len() != 9 {
		t.Fatalf("Len() = %d after Delete, want 9", l.Len())
	}
	for i := range l.Len() {
		r := record(t, l, i)
		if !VerifyRecord(pub, l.ID(), r) {
			t.Fatalf("record %d rejected after Delete", i)
		}
		p, err := l.InclusionProof(i, after.Size())
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(before, r, p) || !VerifyInclusion(after, r, p) {
			t.Fatalf("inclusion proof %d rejected after Delete", i)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	l, id := newLog(t, 4)
	pub := id.PublicKey()
	start := verified(t, l)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(4)
		go func() {
			defer wg.Done()
			for i := range 50 {
				if _, err := l.Append([]byte(fmt.Sprintf("w%d e%d", w, i))); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 200 {
				_, err := l.Get(uint64(i) % l.Len())
				if err != nil && !errors.Is(err, ErrDeleted) {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 50 {
				if err := l.Delete(uint64(w*50+i) % l.Len()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				h, err := l.Head()
				if err != nil {
					t.Error(err)
					return
				}
				v, err := VerifyHead(pub, l.ID(), h)
				if err != nil {
					t.Error(err)
					return
				}
				i := v.Size() / 2
				r, err := l.Record(i)
				if err != nil {
					t.Error(err)
					return
				}
				p, err := l.InclusionProof(i, v.Size())
				if err != nil {
					t.Error(err)
					return
				}
				c, err := l.ConsistencyProof(start.Size(), v.Size())
				if err != nil {
					t.Error(err)
					return
				}
				if !VerifyInclusion(v, r, p) || !VerifyConsistency(start, v, c) {
					t.Error("proof rejected during concurrent use")
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := l.Len(); got != 4+4*50 {
		t.Fatalf("Len() = %d, want %d", got, 4+4*50)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	l, _ := newLog(t, 3)
	h := head(t, l)
	gotH, err := DecodeHead(h.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotH.Encode(), h.Encode()) || gotH.LogID != h.LogID {
		t.Fatal("head changed after a round trip")
	}
	r := record(t, l, 2)
	gotR, err := DecodeRecord(r.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotR.Encode(), r.Encode()) || gotR.LogID != r.LogID {
		t.Fatal("record changed after a round trip")
	}
}

func TestDecodeMalformed(t *testing.T) {
	l, _ := newLog(t, 3)
	r := record(t, l, 0)
	p, err := l.InclusionProof(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	c, err := l.ConsistencyProof(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	decoders := map[string]struct {
		valid  []byte
		decode func([]byte) error
	}{
		"head":        {head(t, l).Encode(), func(b []byte) error { _, err := DecodeHead(b); return err }},
		"record":      {r.Encode(), func(b []byte) error { _, err := DecodeRecord(b); return err }},
		"inclusion":   {p.Encode(), func(b []byte) error { _, err := DecodeInclusionProof(b); return err }},
		"consistency": {c.Encode(), func(b []byte) error { _, err := DecodeConsistencyProof(b); return err }},
	}
	for name, d := range decoders {
		for n := range len(d.valid) {
			if err := d.decode(d.valid[:n]); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s truncated to %d bytes: %v, want %v", name, n, err, ErrMalformed)
			}
		}
		if err := d.decode(append(bytes.Clone(d.valid), 0)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s with a trailing byte: %v, want %v", name, err, ErrMalformed)
		}
	}

	wrongTag := bytes.Clone(r.Encode())
	wrongTag[1] ^= 1
	if _, err := DecodeRecord(wrongTag); !errors.Is(err, ErrMalformed) {
		t.Errorf("record with a wrong tag: %v, want %v", err, ErrMalformed)
	}
	if _, err := DecodeHead(r.Encode()); !errors.Is(err, ErrMalformed) {
		t.Errorf("record decoded as a head: %v, want %v", err, ErrMalformed)
	}

	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutUvarint(1)
	e.PutUvarint(merkle.MaxPathLen + 1)
	if _, err := DecodeInclusionProof(e.Bytes()); !errors.Is(err, ErrMalformed) || !errors.Is(err, kolocodec.ErrTooLarge) {
		t.Errorf("over-long path: %v, want %v and %v", err, ErrMalformed, kolocodec.ErrTooLarge)
	}
}

func TestReturnedValuesAreCopies(t *testing.T) {
	l, id := newLog(t, 2)
	r := record(t, l, 0)
	r.LogKey[0] ^= 1
	r.Signature[0] ^= 1
	h := head(t, l)
	h.LogKey[0] ^= 1
	if _, err := VerifyHead(id.PublicKey(), l.ID(), head(t, l)); err != nil {
		t.Fatal("changing a returned head corrupted the log")
	}
	if !VerifyRecord(id.PublicKey(), l.ID(), record(t, l, 0)) {
		t.Fatal("changing a returned record corrupted the log")
	}
}
