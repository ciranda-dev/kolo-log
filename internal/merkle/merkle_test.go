package merkle

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// refRoot transcribes MTH from RFC 9162, section 2.1.1, without the Tree type.
func refRoot(leaves [][]byte) [HashSize]byte {
	switch len(leaves) {
	case 0:
		return blake2b.Sum256(nil)
	case 1:
		return blake2b.Sum256(append([]byte{0x00}, leaves[0]...))
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := refRoot(leaves[:k]), refRoot(leaves[k:])
	return blake2b.Sum256(append(append([]byte{0x01}, l[:]...), r[:]...))
}

func testLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf %d", i))
	}
	return out
}

func buildTree(leaves [][]byte) *Tree {
	t := &Tree{}
	for _, l := range leaves {
		t.Append(LeafHash(l))
	}
	return t
}

func TestMerkleKnownAnswers(t *testing.T) {
	// BLAKE2b-256 of the empty string.
	const empty = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
	var tr Tree
	if got := tr.Root(0); hex.EncodeToString(got[:]) != empty {
		t.Fatalf("empty root = %x, want %s", got, empty)
	}

	h := func(parts ...[]byte) [HashSize]byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return blake2b.Sum256(b)
	}
	d := testLeaves(5)
	l := make([][HashSize]byte, len(d))
	for i := range d {
		l[i] = h([]byte{0}, d[i])
	}
	n01 := h([]byte{1}, l[0][:], l[1][:])
	n23 := h([]byte{1}, l[2][:], l[3][:])
	n0123 := h([]byte{1}, n01[:], n23[:])
	want := map[int][HashSize]byte{
		1: l[0],
		2: n01,
		3: h([]byte{1}, n01[:], l[2][:]),
		4: n0123,
		5: h([]byte{1}, n0123[:], l[4][:]),
	}
	full := buildTree(d)
	for n, w := range want {
		if got := full.Root(uint64(n)); got != w {
			t.Errorf("root(%d) = %x, want %x", n, got, w)
		}
	}
}

func TestMerkleRootMatchesReference(t *testing.T) {
	d := testLeaves(130)
	tr := buildTree(d)
	for n := 0; n <= len(d); n++ {
		if got, want := tr.Root(uint64(n)), refRoot(d[:n]); got != want {
			t.Fatalf("root(%d) = %x, want %x", n, got, want)
		}
	}
}

func TestInclusionPathAllSizes(t *testing.T) {
	d := testLeaves(70)
	tr := buildTree(d)
	for n := uint64(1); n <= uint64(len(d)); n++ {
		root := tr.Root(n)
		for i := uint64(0); i < n; i++ {
			path := tr.inclusionPath(i, 0, n)
			leaf := LeafHash(d[i])
			if !VerifyInclusion(leaf, i, n, path, root) {
				t.Fatalf("size %d index %d: valid proof rejected", n, i)
			}
			if VerifyInclusion(LeafHash([]byte("other")), i, n, path, root) {
				t.Fatalf("size %d index %d: wrong leaf accepted", n, i)
			}
			if n > 1 && VerifyInclusion(leaf, (i+1)%n, n, path, root) {
				t.Fatalf("size %d index %d: wrong index accepted", n, i)
			}
		}
	}
}

func TestConsistencyPathAllSizes(t *testing.T) {
	d := testLeaves(40)
	tr := buildTree(d)
	for n := uint64(0); n <= uint64(len(d)); n++ {
		for m := uint64(0); m <= n; m++ {
			var path [][HashSize]byte
			if m > 0 && m < n {
				path = tr.consistencyPath(m, 0, n, true)
			}
			oldRoot, newRoot := tr.Root(m), tr.Root(n)
			if !VerifyConsistency(m, n, oldRoot, newRoot, path) {
				t.Fatalf("%d -> %d: valid proof rejected", m, n)
			}
			if m < n {
				bad := LeafHash([]byte("other"))
				if VerifyConsistency(m, n, bad, newRoot, path) {
					t.Fatalf("%d -> %d: wrong old root accepted", m, n)
				}
				// Every Tree extends the empty tree, so m == 0 accepts any new root.
				if m > 0 && VerifyConsistency(m, n, oldRoot, bad, path) {
					t.Fatalf("%d -> %d: wrong new root accepted", m, n)
				}
			}
			for i := range path {
				tampered := append([][HashSize]byte(nil), path...)
				tampered[i][0] ^= 1
				if VerifyConsistency(m, n, oldRoot, newRoot, tampered) {
					t.Fatalf("%d -> %d: tampered hash %d accepted", m, n, i)
				}
			}
			if len(path) > 0 && VerifyConsistency(m, n, oldRoot, newRoot, path[:len(path)-1]) {
				t.Fatalf("%d -> %d: truncated proof accepted", m, n)
			}
		}
	}
}

func TestVerifyRejectsHugeValues(t *testing.T) {
	root := LeafHash(nil)
	long := make([][HashSize]byte, MaxPathLen+1)
	const max = ^uint64(0)
	if VerifyInclusion(root, 0, 1, long, root) {
		t.Error("over-long inclusion path accepted")
	}
	if VerifyInclusion(root, max, max, nil, root) {
		t.Error("index equal to size accepted")
	}
	if VerifyInclusion(root, max-1, max, make([][HashSize]byte, 64), root) {
		t.Error("forged proof for a huge Tree accepted")
	}
	if VerifyConsistency(1, max, root, root, long) {
		t.Error("over-long consistency path accepted")
	}
	if VerifyConsistency(max, 1, root, root, nil) {
		t.Error("shrinking Tree accepted")
	}
}

// RFC 9162 binds size only together with the root, which is why heads are signed.
func TestProofDoesNotBindSizeWithoutRoot(t *testing.T) {
	d := testLeaves(4)
	tr := buildTree(d)
	path := tr.inclusionPath(0, 0, 3)
	if !VerifyInclusion(LeafHash(d[0]), 0, 4, path, tr.Root(3)) {
		t.Fatal("expected the RFC 9162 verifier to accept a mismatched size and root")
	}
	if VerifyInclusion(LeafHash(d[0]), 0, 4, path, tr.Root(4)) {
		t.Fatal("size-3 proof accepted against the size-4 root")
	}
}

func TestInclusionPathLastLeaf(t *testing.T) {
	d := testLeaves(70)
	tr := buildTree(d)
	want := [][HashSize]byte{LeafHash(d[68]), refRoot(d[64:68]), refRoot(d[0:64])}
	if got := tr.inclusionPath(69, 0, 70); !slices.Equal(got, want) {
		t.Fatalf("path of leaf 69 = %x, want %x", got, want)
	}
}

func TestTruncate(t *testing.T) {
	leaves := testLeaves(40)
	for _, n := range []int{0, 1, 2, 3, 7, 8, 9, 16, 31, 40} {
		tr := buildTree(leaves)
		tr.Truncate(uint64(n))
		if tr.Size() != uint64(n) || tr.Root(uint64(n)) != refRoot(leaves[:n]) {
			t.Fatalf("Truncate(%d): size %d, root differs", n, tr.Size())
		}
		for _, l := range leaves[n:] {
			tr.Append(LeafHash(l))
		}
		if tr.Root(40) != refRoot(leaves) {
			t.Fatalf("appending after Truncate(%d) gives another root", n)
		}
	}
}

// Proofs of any size, index and path never panic, a proof from the tree verifies, and one flipped bit in it does not.
func FuzzVerify(f *testing.F) {
	f.Add(uint8(7), uint8(3), uint8(2), uint8(0), ^uint64(0), ^uint64(0)-1, []byte("seed path"))
	f.Add(uint8(64), uint8(0), uint8(63), uint8(9), uint64(1)<<63, uint64(1), make([]byte, 3*HashSize))
	f.Fuzz(func(t *testing.T, n, i, j, flip uint8, hugeSize, hugeIndex uint64, raw []byte) {
		size := uint64(n)%64 + 1
		leaves := testLeaves(int(size))
		tr := buildTree(leaves)
		root := tr.Root(size)
		index := uint64(i) % size
		path := tr.InclusionPath(index, size)
		if !VerifyInclusion(LeafHash(leaves[index]), index, size, path, root) {
			t.Fatalf("inclusion proof of %d in %d rejected", index, size)
		}
		old := uint64(j)%size + 1
		var cons [][HashSize]byte
		if old < size {
			cons = tr.ConsistencyPath(old, size)
		}
		oldRoot := tr.Root(old)
		if !VerifyConsistency(old, size, oldRoot, root, cons) {
			t.Fatalf("consistency proof from %d to %d rejected", old, size)
		}
		if len(path) > 0 {
			bad := slices.Clone(path)
			bad[int(flip)%len(bad)][int(flip)%HashSize] ^= 1 << (flip % 8)
			if VerifyInclusion(LeafHash(leaves[index]), index, size, bad, root) {
				t.Fatal("inclusion proof with a flipped bit accepted")
			}
		}
		if len(cons) > 0 {
			bad := slices.Clone(cons)
			bad[int(flip)%len(bad)][int(flip)%HashSize] ^= 1 << (flip % 8)
			if VerifyConsistency(old, size, oldRoot, root, bad) {
				t.Fatal("consistency proof with a flipped bit accepted")
			}
		}
		var hostile [][HashSize]byte
		for ; len(raw) >= HashSize && len(hostile) <= MaxPathLen; raw = raw[HashSize:] {
			hostile = append(hostile, [HashSize]byte(raw[:HashSize]))
		}
		VerifyInclusion(root, hugeIndex, hugeSize, hostile, root)
		VerifyConsistency(hugeIndex, hugeSize, root, root, hostile)
		VerifyConsistency(old, hugeSize, oldRoot, root, hostile)
	})
}
