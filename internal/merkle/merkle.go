// Package merkle implements RFC 9162 tree hashing, proofs and their verification with BLAKE2b-256.
package merkle

import (
	"crypto/subtle"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

// HashSize is the size in bytes of a tree hash.
const HashSize = blake2b.Size256

// MaxPathLen bounds proof paths; no valid proof for a 64-bit tree size is longer.
const MaxPathLen = 65

// Domain separation prefixes from RFC 9162, section 2.1.1.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// EmptyRoot is the root of an empty tree: the hash of the empty string (RFC 9162).
var EmptyRoot = blake2b.Sum256(nil)

// LeafHash returns the RFC 9162 leaf hash of data.
func LeafHash(data []byte) [HashSize]byte {
	h, _ := blake2b.New256(nil) // never fails without a key
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out [HashSize]byte
	h.Sum(out[:0])
	return out
}

func nodeHash(left, right [HashSize]byte) [HashSize]byte {
	var buf [1 + 2*HashSize]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return blake2b.Sum256(buf[:])
}

// split is k from RFC 9162: the largest power of two smaller than n.
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// Tree keeps every complete subtree root, so past roots and proofs cost O(log² n).
type Tree struct {
	// levels[h][i] is the root of the 2^h leaves starting at leaf i<<h.
	levels [][][HashSize]byte
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// Append adds a leaf hash.
func (t *Tree) Append(leaf [HashSize]byte) {
	if len(t.levels) == 0 {
		t.levels = append(t.levels, nil)
	}
	t.levels[0] = append(t.levels[0], leaf)
	for h := 0; len(t.levels[h])%2 == 0; h++ {
		n := len(t.levels[h])
		parent := nodeHash(t.levels[h][n-2], t.levels[h][n-1])
		if h+1 == len(t.levels) {
			t.levels = append(t.levels, nil)
		}
		t.levels[h+1] = append(t.levels[h+1], parent)
	}
}

// Truncate drops every leaf from index n on, n <= Size(), so a failed batch of appends can be undone.
func (t *Tree) Truncate(n uint64) {
	for h := range t.levels {
		t.levels[h] = t.levels[h][:n>>h]
	}
	for len(t.levels) > 0 && len(t.levels[len(t.levels)-1]) == 0 {
		t.levels = t.levels[:len(t.levels)-1]
	}
}

// hash relies on the RFC 9162 split keeping start aligned, so power-of-two ranges are stored.
func (t *Tree) hash(start, n uint64) [HashSize]byte {
	if n&(n-1) == 0 {
		h := bits.TrailingZeros64(n)
		return t.levels[h][start>>h]
	}
	k := split(n)
	return nodeHash(t.hash(start, k), t.hash(start+k, n-k))
}

// Root returns the root of the first n leaves, n <= Size().
func (t *Tree) Root(n uint64) [HashSize]byte {
	if n == 0 {
		return EmptyRoot
	}
	return t.hash(0, n)
}

// InclusionPath returns the audit path of leaf m in the tree of the first n leaves.
func (t *Tree) InclusionPath(m, n uint64) [][HashSize]byte {
	return t.inclusionPath(m, 0, n)
}

// ConsistencyPath returns the proof that the first m leaves are a prefix of the first n, 0 < m < n.
func (t *Tree) ConsistencyPath(m, n uint64) [][HashSize]byte {
	return t.consistencyPath(m, 0, n, true)
}

// inclusionPath is PATH(m, D[start:start+n]) from RFC 9162, section 2.1.3.1.
func (t *Tree) inclusionPath(m, start, n uint64) [][HashSize]byte {
	if n <= 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(t.inclusionPath(m, start, k), t.hash(start+k, n-k))
	}
	return append(t.inclusionPath(m-k, start+k, n-k), t.hash(start, k))
}

// consistencyPath is SUBPROOF(m, D[start:start+n], b) from RFC 9162, section 2.1.4.1.
func (t *Tree) consistencyPath(m, start, n uint64, b bool) [][HashSize]byte {
	if m == n {
		if b {
			return nil
		}
		return [][HashSize]byte{t.hash(start, n)}
	}
	k := split(n)
	if m <= k {
		return append(t.consistencyPath(m, start, k, b), t.hash(start+k, n-k))
	}
	return append(t.consistencyPath(m-k, start+k, n-k, false), t.hash(start, k))
}

// VerifyInclusion is the algorithm of RFC 9162, section 2.1.3.2.
func VerifyInclusion(leaf [HashSize]byte, index, size uint64, path [][HashSize]byte, root [HashSize]byte) bool {
	if index >= size || len(path) > MaxPathLen {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && Equal(r, root)
}

// VerifyConsistency is RFC 9162, section 2.1.4.2, plus the empty and equal-size cases.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot [HashSize]byte, path [][HashSize]byte) bool {
	switch {
	case oldSize > newSize || len(path) > MaxPathLen:
		return false
	case oldSize == 0:
		return len(path) == 0 && Equal(oldRoot, EmptyRoot)
	case oldSize == newSize:
		return len(path) == 0 && Equal(oldRoot, newRoot)
	case len(path) == 0:
		return false
	}
	if oldSize&(oldSize-1) == 0 {
		path = append([][HashSize]byte{oldRoot}, path...)
	}
	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && Equal(fr, oldRoot) && Equal(sr, newRoot)
}

// Equal compares two hashes in constant time.
func Equal(a, b [HashSize]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
