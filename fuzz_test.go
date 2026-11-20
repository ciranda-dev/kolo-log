package kololog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

const fixtureLeaves = 70

type fixture struct {
	log  *Log
	pub  ed25519.PublicKey
	old  VerifiedHead // head at size 30
	head VerifiedHead // head at size fixtureLeaves
	rec  Record
}

// newFixture uses a fixed identity so every fuzz worker shares the log key.
func newFixture(f *testing.F) fixture {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	l := newLogFor(f, id, 30)
	old := verified(f, l)
	for range fixtureLeaves - 30 {
		if _, err := l.Append([]byte("fuzz")); err != nil {
			f.Fatal(err)
		}
	}
	return fixture{log: l, pub: id.PublicKey(), old: old, head: verified(f, l), rec: record(f, l, 4)}
}

// shapes is identical in every fuzz worker, so seeded honest proofs stay valid.
type shapes struct {
	leaves [][]byte
	tree   *merkle.Tree
	roots  [][HashSize]byte // roots[n] is the root of the first n leaves

	leaf0Path  [][HashSize]byte // honest inclusion path of leaf 0 at size fixtureLeaves
	leaf69Path [][HashSize]byte // honest inclusion path of leaf 69, through the fn == sn branch
	path30to70 [][HashSize]byte // honest consistency path from 30 to fixtureLeaves
}

func newShapes() shapes {
	s := shapes{leaves: testLeaves(fixtureLeaves)}
	s.tree = buildTree(s.leaves)
	for n := range uint64(fixtureLeaves + 1) {
		s.roots = append(s.roots, s.tree.Root(n))
	}
	s.leaf0Path = s.tree.InclusionPath(0, fixtureLeaves)
	s.leaf69Path = s.tree.InclusionPath(69, fixtureLeaves)
	s.path30to70 = s.tree.ConsistencyPath(30, fixtureLeaves)
	return s
}

func pathsEqual(a, b [][HashSize]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FuzzDecodeHead(f *testing.F) {
	x := newFixture(f)
	f.Add(x.head.Head().Encode(), []byte(x.pub))
	f.Add(x.rec.Encode(), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b, pub []byte) {
		VerifyHead(pub, LogID{}, Head{LogKey: pub, Signature: b})
		got, err := DecodeHead(b)
		if err != nil {
			return
		}
		if !bytes.Equal(got.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, got.Encode())
		}
		VerifyHead(pub, got.LogID, got)
		VerifyHead(got.LogKey, got.LogID, got)
		v, err := VerifyHead(x.pub, x.head.LogID(), got)
		if err != nil {
			return
		}
		// Seeds from the fuzz coordinator carry another log ID and fail above.
		if !bytes.Equal(b, x.head.Head().Encode()) && !bytes.Equal(b, x.old.Head().Encode()) {
			t.Fatal("a forged head verified")
		}
		VerifyInclusion(v, x.rec, InclusionProof{Index: x.rec.Index, Size: v.Size()})
		VerifyConsistency(v, x.head, ConsistencyProof{OldSize: v.Size(), NewSize: x.head.Size()})
		VerifyConsistency(x.head, v, ConsistencyProof{OldSize: x.head.Size(), NewSize: v.Size()})
	})
}

func FuzzDecodeRecord(f *testing.F) {
	x := newFixture(f)
	p, err := x.log.InclusionProof(x.rec.Index, x.head.Size())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(x.rec.Encode())
	f.Add(x.head.Head().Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeRecord(b)
		if err != nil {
			return
		}
		if !bytes.Equal(got.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, got.Encode())
		}
		VerifyRecord(got.LogKey, got.LogID, got)
		VerifyRecord(x.pub, x.head.LogID(), got)
		if VerifyInclusion(x.head, got, p) && !bytes.Equal(b, x.rec.Encode()) {
			t.Fatal("a different record verified against a real proof")
		}
	})
}

func FuzzDecodeInclusionProof(f *testing.F) {
	x := newFixture(f)
	p, err := x.log.InclusionProof(x.rec.Index, x.head.Size())
	if err != nil {
		f.Fatal(err)
	}
	s := newShapes()
	f.Add(p.Encode())
	for _, c := range [][2]uint64{{0, 1}, {1, 2}, {4, 9}, {31, 64}, {0, 70}, {13, 70}, {69, 70}} {
		f.Add(InclusionProof{Index: c[0], Size: c[1], Path: s.tree.InclusionPath(c[0], c[1])}.Encode())
	}
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x40})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeInclusionProof(b)
		if err != nil {
			return
		}
		if !bytes.Equal(got.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, got.Encode())
		}
		if VerifyInclusion(x.head, x.rec, got) && !bytes.Equal(b, p.Encode()) {
			t.Fatal("a forged proof verified")
		}

		i, n := got.Index, got.Size
		if i < n && n <= fixtureLeaves {
			honest := s.tree.InclusionPath(i, n)
			ok := merkle.VerifyInclusion(merkle.LeafHash(s.leaves[i]), i, n, got.Path, s.roots[n])
			if ok != pathsEqual(got.Path, honest) {
				t.Fatalf("index %d size %d: verify = %v for a path that is honest = %v", i, n, ok, !ok)
			}
		}
		// Any claimed size is allowed: RFC 9162 binds size only together with the root.
		for _, c := range []struct {
			leaf   int
			honest [][HashSize]byte
		}{{0, s.leaf0Path}, {69, s.leaf69Path}} {
			if merkle.VerifyInclusion(merkle.LeafHash(s.leaves[c.leaf]), i, n, got.Path, s.roots[fixtureLeaves]) &&
				!pathsEqual(got.Path, c.honest) {
				t.Fatalf("index %d size %d: a forged path proved leaf %d", i, n, c.leaf)
			}
		}
	})
}

func FuzzDecodeConsistencyProof(f *testing.F) {
	x := newFixture(f)
	p, err := x.log.ConsistencyProof(x.old.Size(), x.head.Size())
	if err != nil {
		f.Fatal(err)
	}
	s := newShapes()
	f.Add(p.Encode())
	for _, c := range [][2]uint64{{1, 2}, {3, 7}, {4, 8}, {30, 70}, {64, 70}, {69, 70}} {
		f.Add(ConsistencyProof{OldSize: c[0], NewSize: c[1], Path: s.tree.ConsistencyPath(c[0], c[1])}.Encode())
	}
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeConsistencyProof(b)
		if err != nil {
			return
		}
		if !bytes.Equal(got.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, got.Encode())
		}
		if VerifyConsistency(x.old, x.head, got) && !bytes.Equal(b, p.Encode()) {
			t.Fatal("a forged proof verified")
		}

		m, n := got.OldSize, got.NewSize
		if m <= n && n <= fixtureLeaves {
			var honest [][HashSize]byte
			if m > 0 && m < n {
				honest = s.tree.ConsistencyPath(m, n)
			}
			ok := merkle.VerifyConsistency(m, n, s.roots[m], s.roots[n], got.Path)
			if ok != pathsEqual(got.Path, honest) {
				t.Fatalf("%d -> %d: verify = %v for a path that is honest = %v", m, n, ok, !ok)
			}
		}
		if merkle.VerifyConsistency(m, n, s.roots[30], s.roots[fixtureLeaves], got.Path) &&
			!pathsEqual(got.Path, s.path30to70) {
			t.Fatalf("%d -> %d: a forged path linked the real roots", m, n)
		}
	})
}

func FuzzJSONRoundTrip(f *testing.F) {
	x := newJSONFixture(f)
	for _, b := range [][]byte{x.head.Encode(), x.rec.Encode(), x.inc.Encode(), x.con.Encode(), x.log.Header().Encode(), x.marker.Encode()} {
		f.Add(b)
	}
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range fuzzDerivedHeaders(f, id) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := DecodeHead(b); err == nil {
			var got Head
			if err := json.Unmarshal(mustJSON(t, h), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("head JSON round trip: %v", err)
			}
		}
		if r, err := DecodeRecord(b); err == nil {
			var got Record
			if err := json.Unmarshal(mustJSON(t, r), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("record JSON round trip: %v", err)
			}
		}
		if p, err := DecodeInclusionProof(b); err == nil {
			var got InclusionProof
			if err := json.Unmarshal(mustJSON(t, p), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("inclusion proof JSON round trip: %v", err)
			}
		}
		if p, err := DecodeConsistencyProof(b); err == nil {
			var got ConsistencyProof
			if err := json.Unmarshal(mustJSON(t, p), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("consistency proof JSON round trip: %v", err)
			}
		}
		if m, err := DecodeDeleteMarker(b); err == nil {
			var got DeleteMarker
			if err := json.Unmarshal(mustJSON(t, m), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("delete marker JSON round trip: %v", err)
			}
		}
		if h, err := DecodeLogHeader(b); err == nil {
			var got LogHeader
			if err := json.Unmarshal(mustJSON(t, h), &got); err != nil || !bytes.Equal(got.Encode(), b) {
				t.Fatalf("log header JSON round trip: %v", err)
			}
		}
		if len(b) >= LogIDSize {
			id := LogID(b[:LogIDSize])
			var got LogID
			if err := json.Unmarshal(mustJSON(t, id), &got); err != nil || got != id {
				t.Fatalf("log ID JSON round trip: %v", err)
			}
		}
	})
}

func FuzzJSONDecode(f *testing.F) {
	x := newJSONFixture(f)
	for _, v := range []any{x.head, x.rec, x.inc, x.con, x.log.ID(), x.log.Header(), x.marker} {
		f.Add(mustJSON(f, v))
	}
	f.Add([]byte(`{"index":"01","size":"1","path":[]}`))
	f.Add([]byte(`null`))
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range fuzzDerivedHeaders(f, id) {
		h, err := DecodeLogHeader(b)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(mustJSON(f, h))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var h Head
		if h.UnmarshalJSON(b) == nil {
			var again Head
			if err := json.Unmarshal(mustJSON(t, h), &again); err != nil || !bytes.Equal(again.Encode(), h.Encode()) {
				t.Fatalf("accepted head does not round trip: %v", err)
			}
		}
		var r Record
		if r.UnmarshalJSON(b) == nil {
			var again Record
			if err := json.Unmarshal(mustJSON(t, r), &again); err != nil || !bytes.Equal(again.Encode(), r.Encode()) {
				t.Fatalf("accepted record does not round trip: %v", err)
			}
		}
		var p InclusionProof
		if p.UnmarshalJSON(b) == nil {
			var again InclusionProof
			if err := json.Unmarshal(mustJSON(t, p), &again); err != nil || !bytes.Equal(again.Encode(), p.Encode()) {
				t.Fatalf("accepted inclusion proof does not round trip: %v", err)
			}
		}
		var c ConsistencyProof
		if c.UnmarshalJSON(b) == nil {
			var again ConsistencyProof
			if err := json.Unmarshal(mustJSON(t, c), &again); err != nil || !bytes.Equal(again.Encode(), c.Encode()) {
				t.Fatalf("accepted consistency proof does not round trip: %v", err)
			}
		}
		var dm DeleteMarker
		if dm.UnmarshalJSON(b) == nil {
			var again DeleteMarker
			if err := json.Unmarshal(mustJSON(t, dm), &again); err != nil || !bytes.Equal(again.Encode(), dm.Encode()) {
				t.Fatalf("accepted delete marker does not round trip: %v", err)
			}
		}
		var lh LogHeader
		if lh.UnmarshalJSON(b) == nil {
			var again LogHeader
			if err := json.Unmarshal(mustJSON(t, lh), &again); err != nil || !bytes.Equal(again.Encode(), lh.Encode()) {
				t.Fatalf("accepted log header does not round trip: %v", err)
			}
		}
		var id LogID
		if id.UnmarshalJSON(b) == nil {
			var again LogID
			if err := json.Unmarshal(mustJSON(t, id), &again); err != nil || again != id {
				t.Fatalf("accepted log ID does not round trip: %v", err)
			}
		}
		var v VerifiedHead
		if !errors.Is(v.UnmarshalJSON(b), ErrNotDecodable) || json.Unmarshal(b, &v) == nil {
			t.Fatal("a VerifiedHead was decoded")
		}
	})
}

func FuzzDecodeLogHeader(f *testing.F) {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range []ValueEncoding{Bytes, UTF8, JSON} {
		l, err := New(id, NewMemory(), WithValueEncoding(e))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(l.Header().Encode())
		l.Close()
	}
	for _, epoch := range []uint64{0, 1, 300, 1<<64 - 1} {
		l, err := New(id, NewMemory(), WithDerivedKeys(testSecret(1), epoch))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(l.Header().Encode())
		l.Close()
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeLogHeader(b)
		if err != nil {
			return
		}
		if !bytes.Equal(h.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, h.Encode())
		}
		VerifyLogHeader(h.LogKey, h)
		VerifyLogHeader(id.PublicKey(), h)
		NewReplica(id.PublicKey(), h.LogID, b, NewMemory())
	})
}

// FuzzRestore restores two fuzzed entries under a fuzzed header and head, with no option, the right derived secret and epoch,
// another secret, or another epoch (mask bits 4 and 5).
func FuzzRestore(f *testing.F) {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	secret := testSecret(5)
	const epoch = 3
	seed := func(opts ...Option) {
		l, err := New(id, NewMemory(), opts...)
		if err != nil {
			f.Fatal(err)
		}
		for _, v := range []string{"a", "b"} {
			if _, err := l.Append([]byte(v)); err != nil {
				f.Fatal(err)
			}
		}
		mode := uint8(0)
		if len(opts) > 0 {
			mode = 1 << 4
		}
		h := head(f, l)
		e0, e1 := mustEntry(f, l, 0), mustEntry(f, l, 1)
		for _, m := range []uint8{0, 1 << 4, 2 << 4, 3 << 4} {
			f.Add(l.Header().Encode(), h.Encode(), e0.Record, e0.Ciphertext, []byte(e0.Key), e1.Record, e1.Ciphertext, []byte(e1.Key), []byte(nil), uint8(2)|m)
		}
		if err := l.Delete(1); err != nil {
			f.Fatal(err)
		}
		e1 = mustEntry(f, l, 1)
		l.Close()
		f.Add(l.Header().Encode(), h.Encode(), e0.Record, e0.Ciphertext, []byte(e0.Key), e1.Record, []byte(nil), []byte(nil), e1.Marker, uint8(2|1<<3)|mode)
	}
	seed()
	seed(WithDerivedKeys(secret, epoch))
	f.Fuzz(func(t *testing.T, header, hd, r0, c0, k0, r1, c1, k1, mk []byte, mask uint8) {
		all := []Entry{{Record: r0, Ciphertext: c0, Key: k0}, {Record: r1, Ciphertext: c1, Key: k1}}
		if mask&(1<<2) != 0 {
			all[0].Ciphertext, all[0].Marker, all[0].Key = nil, mk, nil
		}
		if mask&(1<<3) != 0 {
			all[1].Ciphertext, all[1].Marker, all[1].Key = nil, mk, nil
		}
		var opts []Option
		switch mask >> 4 & 3 {
		case 1:
			opts = append(opts, WithDerivedKeys(secret, epoch))
		case 2:
			opts = append(opts, WithDerivedKeys(testSecret(6), epoch))
		case 3:
			opts = append(opts, WithDerivedKeys(secret, epoch+1))
		}
		restored, err := Restore(id, header, hd, storeOf(all[:int(mask&3)%3]), opts...)
		if err != nil {
			if restored != nil {
				t.Fatal("Restore returned a log with an error")
			}
			return
		}
		defer restored.Close()
		want, err := DecodeHead(hd)
		if err != nil {
			t.Fatal(err)
		}
		got := head(t, restored)
		if got.Size != want.Size || got.Root != want.Root || restored.Len() != want.Size {
			t.Fatalf("restored size %d root %x, head says %d %x", got.Size, got.Root, want.Size, want.Root)
		}
		lh := restored.Header()
		switch m := mask >> 4 & 3; {
		case m == 0 && lh.Keys != RandomKeys:
			t.Fatal("a derived log restored without the option")
		case m != 0 && (lh.Keys != DerivedKeys || lh.Epoch != epoch):
			t.Fatalf("restored %s keys at epoch %d with the option", lh.Keys, lh.Epoch)
		case m == 2 && restored.Len() > 0:
			t.Fatal("a non-empty log restored with another secret")
		}
	})
}

func FuzzDecodeDeleteMarker(f *testing.F) {
	x := newJSONFixture(f)
	f.Add(x.marker.Encode())
	f.Add(x.rec.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeDeleteMarker(b)
		if err != nil {
			return
		}
		if !bytes.Equal(m.Encode(), b) {
			t.Fatalf("round trip changed %x into %x", b, m.Encode())
		}
		if VerifyDeleteMarker(x.log.pub, x.log.ID(), x.rec, m) {
			t.Fatal("a marker for a live entry verified")
		}
		VerifyDeleteMarker(m.LogKey, m.LogID, Record{LogKey: m.LogKey, LogID: m.LogID, Index: m.Index}, m)
	})
}

func testLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf %d", i))
	}
	return out
}

func buildTree(leaves [][]byte) *merkle.Tree {
	t := &merkle.Tree{}
	for _, l := range leaves {
		t.Append(merkle.LeafHash(l))
	}
	return t
}

// fuzzReplicaLog returns a log of four entries under the fixed fuzz identity, entry 3 deleted, with its heads at sizes 2 and 4.
func fuzzReplicaLog(f *testing.F) (l *Log, entries []Entry, h2, h4 Head) {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	l = newLogFor(f, id, 2)
	h2 = head(f, l)
	appendN(f, l, 2, 2)
	if err := l.Delete(3); err != nil {
		f.Fatal(err)
	}
	for i := range l.Len() {
		entries = append(entries, mustEntry(f, l, i))
	}
	return l, entries, h2, head(f, l)
}

// FuzzReplicaUpdate grows a replica at size 2 from untrusted input; a failed Update must leave it unchanged.
func FuzzReplicaUpdate(f *testing.F) {
	l, entries, h2, h4 := fuzzReplicaLog(f)
	p, err := l.ConsistencyProof(2, 4)
	if err != nil {
		f.Fatal(err)
	}
	e2, e3 := entries[2], entries[3]
	f.Add(h4.Encode(), p.Encode(), e2.Record, e2.Ciphertext, []byte(e2.Key), e3.Record, e3.Marker, uint8(2))
	f.Add(h2.Encode(), []byte{2, 2, 0}, []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil), uint8(0))
	p3, err := l.ConsistencyProof(3, 4)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h4.Encode(), p3.Encode(), e2.Record, e2.Ciphertext, []byte(e2.Key), e3.Record, e3.Marker, uint8(1))
	f.Fuzz(func(t *testing.T, hd, proof, r0, c0, k0, r1, m1 []byte, mask uint8) {
		r, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h2.Encode(), cloneEntries(entries[:2]))
		if err != nil {
			t.Fatal(err)
		}
		h, err := DecodeHead(hd)
		if err != nil {
			return
		}
		cp, _ := DecodeConsistencyProof(proof)
		in := []Entry{{Record: r0, Ciphertext: c0, Key: k0}, {Record: r1, Marker: m1}}
		if mask&4 != 0 {
			in[1].Ciphertext, in[1].Marker = m1, nil
		}
		before := state(t, r)
		if err := r.Update(h, cp, in[:int(mask&3)%3]); err != nil {
			if state(t, r) != before {
				t.Fatalf("failed Update changed the replica: %v", err)
			}
			return
		}
		if th, _, ok := r.Target(); ok {
			if th.Size != h.Size || th.Root != h.Root || r.Len() >= h.Size {
				t.Fatalf("Update to a target of size %d holds %d entries", th.Size, r.Len())
			}
			return
		}
		got, err := r.Head()
		if err != nil || r.Len() != got.Size || got.Size > h.Size {
			t.Fatalf("Update kept %d entries for a head of size %d: %v", r.Len(), got.Size, err)
		}
	})
}

// FuzzReplicaAddKey gives untrusted keys to an entry received without one; only its own key may be kept.
func FuzzReplicaAddKey(f *testing.F) {
	l, entries, _, h4 := fuzzReplicaLog(f)
	f.Add(uint64(0), []byte(entries[0].Key))
	f.Add(uint64(1), []byte(entries[0].Key))
	f.Add(uint64(3), []byte(entries[0].Key))
	f.Fuzz(func(t *testing.T, index uint64, key []byte) {
		in := cloneEntries(entries)
		for i := range in {
			in[i].Key = nil
		}
		r, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h4.Encode(), in)
		if err != nil {
			t.Fatal(err)
		}
		before := state(t, r)
		if err := r.AddKey(index, key); err != nil {
			if state(t, r) != before {
				t.Fatalf("failed AddKey changed the replica: %v", err)
			}
			return
		}
		if !bytes.Equal(key, entries[index].Key) {
			t.Fatalf("AddKey kept a key that is not entry %d's", index)
		}
	})
}

// FuzzReplicaApplyDelete applies an untrusted marker to a replica of four entries; a failed one must change nothing.
func FuzzReplicaApplyDelete(f *testing.F) {
	l, entries, _, h4 := fuzzReplicaLog(f)
	if err := l.Delete(1); err != nil {
		f.Fatal(err)
	}
	f.Add(mustEntry(f, l, 1).Marker)
	f.Add(entries[3].Marker)
	f.Add([]byte(DeleteContext))
	f.Fuzz(func(t *testing.T, m []byte) {
		r, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h4.Encode(), cloneEntries(entries))
		if err != nil {
			t.Fatal(err)
		}
		before := state(t, r)
		if err := r.ApplyDelete(m); err != nil {
			if state(t, r) != before {
				t.Fatalf("failed ApplyDelete changed the replica: %v", err)
			}
			return
		}
		d, err := DecodeDeleteMarker(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Get(d.Index); !errors.Is(err, ErrDeleted) {
			t.Fatalf("entry %d readable after ApplyDelete: %v", d.Index, err)
		}
	})
}

// FuzzRestoreReplica restores a replica from untrusted stored data; it must never panic and only return verified state.
func FuzzRestoreReplica(f *testing.F) {
	l, entries, _, h4 := fuzzReplicaLog(f)
	e0, e3 := entries[0], entries[3]
	f.Add(l.Header().Encode(), h4.Encode(), e0.Record, e0.Ciphertext, []byte(e0.Key), e3.Marker, uint8(1))
	f.Add(l.Header().Encode(), []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil), uint8(0))
	f.Fuzz(func(t *testing.T, header, hd, r0, c0, k0, m []byte, mask uint8) {
		in := cloneEntries(entries)
		in[0] = Entry{Record: r0, Ciphertext: c0, Key: k0}
		if mask&4 != 0 {
			in[0].Ciphertext, in[0].Marker = nil, m
		}
		n := int(mask & 3)
		if n == 3 {
			n = 4
		}
		r, err := restoreReplica(t, l.pub, l.ID(), header, hd, in[:n])
		if err != nil {
			if r != nil {
				t.Fatal("RestoreReplica returned a replica with an error")
			}
			return
		}
		if len(hd) == 0 {
			if r.Len() != 0 {
				t.Fatal("replica without a head has entries")
			}
			return
		}
		want, err := DecodeHead(hd)
		if err != nil {
			t.Fatal(err)
		}
		got := mustReplicaHead(t, r)
		if got.Size != want.Size || got.Root != want.Root || r.Len() != want.Size {
			t.Fatalf("restored size %d, head says %d", r.Len(), want.Size)
		}
	})
}

// FuzzApplyDeleteBatch applies up to three fuzzed markers at once: all of them or none.
func FuzzApplyDeleteBatch(f *testing.F) {
	l, entries, _, h := fuzzReplicaLog(f)
	if err := l.Delete(0, 1); err != nil {
		f.Fatal(err)
	}
	m0, m1, m3 := mustEntry(f, l, 0).Marker, mustEntry(f, l, 1).Marker, entries[3].Marker
	f.Add(m0, m1, m3, uint8(3))
	f.Add(m0, m0, m1, uint8(3))
	f.Add(m1, flip(m0, 5), m3, uint8(3))
	f.Add(m1, flip(m0, len(m0)-1), m3, uint8(3))
	f.Add(m1, flip(m3, len(m3)-1), []byte(nil), uint8(2))
	f.Fuzz(func(t *testing.T, a, b, c []byte, n uint8) {
		r, err := restoreReplica(t, l.pub, l.ID(), l.Header().Encode(), h.Encode(), cloneEntries(entries))
		if err != nil {
			t.Fatal(err)
		}
		ms := [][]byte{a, b, c}[:n%4]
		before := state(t, r)
		if err := r.ApplyDelete(ms...); err != nil {
			if state(t, r) != before {
				t.Fatalf("a refused batch changed the replica: %v", err)
			}
			return
		}
		for _, m := range ms {
			d, err := DecodeDeleteMarker(m)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyDeleteMarker(l.pub, l.ID(), record(t, l, d.Index), d) {
				t.Fatalf("an invalid marker for entry %d was accepted", d.Index)
			}
			if _, err := r.Get(d.Index); !errors.Is(err, ErrDeleted) {
				t.Fatalf("entry %d still reads after its marker was applied: %v", d.Index, err)
			}
		}
	})
}

// fuzzDerivedHeaders returns the headers of derived logs under a fixed identity, so every fuzz worker shares them.
func fuzzDerivedHeaders(f *testing.F, id *koloid.Identity) [][]byte {
	var out [][]byte
	for _, epoch := range []uint64{0, 9, 1<<64 - 1} {
		l, err := New(id, NewMemory(), WithDerivedKeys(testSecret(3), epoch))
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, l.Header().Encode())
		l.Close()
	}
	return out
}

// FuzzKeyDeriver builds a deriver from an untrusted header: only a derived header signed by the owner gives one,
// and its keys are the log's.
func FuzzKeyDeriver(f *testing.F) {
	id, err := koloid.FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range fuzzDerivedHeaders(f, id) {
		f.Add(b, uint64(0))
		f.Add(b, uint64(1<<64-1))
	}
	rl, err := New(id, NewMemory())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rl.Header().Encode(), uint64(3))
	rl.Close()
	secret := testSecret(3)
	f.Fuzz(func(t *testing.T, b []byte, index uint64) {
		h, err := DecodeLogHeader(b)
		if err != nil {
			return
		}
		NewKeyDeriver(secret, h.LogKey, h)
		d, err := NewKeyDeriver(secret, id.PublicKey(), h)
		if err != nil {
			if h.Keys == DerivedKeys && VerifyLogHeader(id.PublicKey(), h) == nil {
				t.Fatalf("a signed derived header was refused: %v", err)
			}
			return
		}
		if h.Keys != DerivedKeys || VerifyLogHeader(id.PublicKey(), h) != nil {
			t.Fatalf("a deriver for a header that is not a signed derived one: %v", h)
		}
		k, err := d.Key(index)
		p, perr := newPRK(secret)
		if err != nil || perr != nil {
			t.Fatal(err, perr)
		}
		want, err := p.entryKey(h.LogKey, h.LogID, h.Epoch, index)
		if err != nil || !bytes.Equal(k, want[:]) {
			t.Fatalf("Key(%d) is not the derived key: %v", index, err)
		}
		d.Close()
		if _, err := d.Key(index); !errors.Is(err, ErrDeriverClosed) {
			t.Fatalf("Key after Close: %v", err)
		}
	})
}

// FuzzAddKeys gives untrusted key slices to a replica of a hostile writer's log: exactly the right keys of good entries are
// stored, and exactly the other non-nil keys for entries without one are refused.
func FuzzAddKeys(f *testing.F) {
	secret := testSecret(4)
	kinds := []int{kindGood, kindRandom, kindGood, kindSealedBy, kindGood, kindGood}
	l, d := hostileLog(f, secret, kinds)
	if err := l.Delete(4); err != nil {
		f.Fatal(err)
	}
	keys := derivedKeys(f, d, 0, uint64(len(kinds)))
	header, h := l.Header().Encode(), head(f, l)
	var entries []Entry
	for i := range l.Len() {
		e := mustEntry(f, l, i)
		e.Key = nil
		entries = append(entries, e)
	}
	f.Add(uint64(0), []byte{1, 1, 1, 1, 1, 1})
	f.Add(uint64(1), []byte{1, 0, 2, 1})
	f.Add(uint64(5), []byte{33, 7})
	f.Add(uint64(2), []byte{})
	f.Fuzz(func(t *testing.T, start uint64, raw []byte) {
		// Each key is a tag byte: 0 nil, 1 the derived key of its index, 2 that key with one bit changed,
		// anything else that many bytes of raw, mod 40.
		var in []EntryKey
		for len(raw) > 0 && len(in) < 2*len(kinds) {
			tag := raw[0]
			raw = raw[1:]
			index := start + uint64(len(in))
			switch {
			case tag == 0:
				in = append(in, nil)
			case (tag == 1 || tag == 2) && index < uint64(len(keys)):
				k := bytes.Clone(keys[index])
				if tag == 2 {
					k[0] ^= 1
				}
				in = append(in, k)
			default:
				n := min(int(tag)%40, len(raw))
				in = append(in, bytes.Clone(raw[:n]))
				raw = raw[n:]
			}
		}
		r, err := RestoreReplica(l.pub, l.ID(), header, Heads{Head: &h}, storeOf(cloneEntries(entries)))
		if err != nil {
			t.Fatal(err)
		}
		before := state(t, r)
		err = r.AddKeys(start, in)
		n := uint64(len(kinds))
		if start > n || uint64(len(in)) > n-start {
			if !errors.Is(err, ErrOutOfRange) || state(t, r) != before {
				t.Fatalf("AddKeys past the end: %v", err)
			}
			return
		}
		var wantBad []uint64
		for i, k := range in {
			index := start + uint64(i)
			info, _ := r.EntryInfo(index)
			right := bytes.Equal(k, keys[index]) && kinds[index] == kindGood
			switch {
			case index == 4:
				if info != (EntryInfo{Deleted: true}) {
					t.Fatalf("deleted entry 4 is %+v", info)
				}
			case len(k) == 0:
				if info.Keyed {
					t.Fatalf("entry %d keyed from a nil key", index)
				}
			case right != info.Keyed:
				t.Fatalf("entry %d: keyed %v from a key that is right %v", index, info.Keyed, right)
			case !right:
				wantBad = append(wantBad, index)
			}
		}
		var bad *BadKeyError
		switch {
		case wantBad == nil && err != nil:
			t.Fatalf("AddKeys: %v", err)
		case wantBad != nil && (!errors.As(err, &bad) || !slices.Equal(bad.Indexes, wantBad)):
			t.Fatalf("AddKeys returned %v, want refusals %v", err, wantBad)
		}
	})
}
