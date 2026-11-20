package kololog

import (
	"fmt"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"golang.org/x/crypto/blake2b"
)

// HashSize is the size in bytes of a tree hash.
const HashSize = blake2b.Size256

// InclusionProof shows that the entry at Index is in the tree of Size entries.
type InclusionProof struct {
	Index uint64
	Size  uint64
	Path  [][HashSize]byte
}

// ConsistencyProof shows that the tree of OldSize entries is a prefix of the tree of NewSize entries.
type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
	Path    [][HashSize]byte
}

// VerifyInclusion reports whether r is signed by h's log key, belongs to h's log, and p proves r is in h.
func VerifyInclusion(h VerifiedHead, r Record, p InclusionProof) bool {
	if !h.valid() || !VerifyRecord(h.head.LogKey, h.head.LogID, r) {
		return false
	}
	if p.Index != r.Index || p.Size != h.head.Size {
		return false
	}
	return merkle.VerifyInclusion(merkle.LeafHash(r.Encode()), p.Index, p.Size, p.Path, h.head.Root)
}

// VerifyConsistency reports whether old and new belong to the same log and p proves old is a prefix of new.
func VerifyConsistency(old, new VerifiedHead, p ConsistencyProof) bool {
	if !old.valid() || !new.valid() || !keysEqual(old.head.LogKey, new.head.LogKey) || old.head.LogID != new.head.LogID {
		return false
	}
	if p.OldSize != old.head.Size || p.NewSize != new.head.Size {
		return false
	}
	return merkle.VerifyConsistency(p.OldSize, p.NewSize, old.head.Root, new.head.Root, p.Path)
}

// Encode returns the canonical encoding of p.
func (p InclusionProof) Encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(p.Index)
	e.PutUvarint(p.Size)
	putPath(&e, p.Path)
	return e.Bytes()
}

// DecodeInclusionProof parses an encoding made by [InclusionProof.Encode].
func DecodeInclusionProof(b []byte) (InclusionProof, error) {
	d := kolocodec.NewDecoder(b)
	var p InclusionProof
	var err error
	if p.Index, err = d.Uvarint(); err != nil {
		return InclusionProof{}, malformed(err)
	}
	if p.Size, err = d.Uvarint(); err != nil {
		return InclusionProof{}, malformed(err)
	}
	if p.Path, err = path(d); err != nil {
		return InclusionProof{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return InclusionProof{}, malformed(err)
	}
	return p, nil
}

// Encode returns the canonical encoding of p.
func (p ConsistencyProof) Encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(p.OldSize)
	e.PutUvarint(p.NewSize)
	putPath(&e, p.Path)
	return e.Bytes()
}

// DecodeConsistencyProof parses an encoding made by [ConsistencyProof.Encode].
func DecodeConsistencyProof(b []byte) (ConsistencyProof, error) {
	d := kolocodec.NewDecoder(b)
	var p ConsistencyProof
	var err error
	if p.OldSize, err = d.Uvarint(); err != nil {
		return ConsistencyProof{}, malformed(err)
	}
	if p.NewSize, err = d.Uvarint(); err != nil {
		return ConsistencyProof{}, malformed(err)
	}
	if p.Path, err = path(d); err != nil {
		return ConsistencyProof{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return ConsistencyProof{}, malformed(err)
	}
	return p, nil
}

func putPath(e *kolocodec.Encoder, path [][HashSize]byte) {
	e.PutUvarint(uint64(len(path)))
	for _, h := range path {
		e.PutFixed(h[:])
	}
}

// path bounds the hash count by merkle.MaxPathLen before allocating.
func path(d *kolocodec.Decoder) ([][HashSize]byte, error) {
	n, err := d.Uvarint()
	if err != nil {
		return nil, err
	}
	if n > merkle.MaxPathLen {
		return nil, fmt.Errorf("%w: path of %d hashes", kolocodec.ErrTooLarge, n)
	}
	if n == 0 {
		return nil, nil
	}
	out := make([][HashSize]byte, n)
	for i := range out {
		b, err := d.Fixed(HashSize)
		if err != nil {
			return nil, err
		}
		copy(out[i][:], b)
	}
	return out, nil
}
