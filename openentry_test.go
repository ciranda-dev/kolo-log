package kololog

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

func inclusion(t testing.TB, l *Log, i, size uint64) InclusionProof {
	t.Helper()
	p, err := l.InclusionProof(i, size)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenEntry(t *testing.T) {
	l, _ := newLog(t, 7)
	if err := l.Delete(5); err != nil {
		t.Fatal(err)
	}
	v := verified(t, l)
	for i := range uint64(7) {
		got, err := OpenEntry(v, inclusion(t, l, i, 7), mustEntry(t, l, i))
		want, wantErr := l.Get(i)
		if !bytes.Equal(got, want) || !errors.Is(err, wantErr) || (err == nil) != (wantErr == nil) {
			t.Fatalf("OpenEntry(%d) = %q, %v; Get = %q, %v", i, got, err, want, wantErr)
		}
	}

	good, p := mustEntry(t, l, 2), inclusion(t, l, 2, 7)
	other, _ := newLog(t, 3)
	tests := []struct {
		name   string
		change func(e *Entry, p *InclusionProof)
		want   error
	}{
		{"tampered record", func(e *Entry, _ *InclusionProof) { e.Record = flip(e.Record, len(e.Record)-1) }, ErrBadEntry},
		{"record cut", func(e *Entry, _ *InclusionProof) { e.Record = e.Record[:len(e.Record)-1] }, ErrBadEntry},
		{"record of another entry", func(e *Entry, _ *InclusionProof) { e.Record = mustEntry(t, l, 3).Record }, ErrBadEntry},
		{"record of another log", func(e *Entry, _ *InclusionProof) { e.Record = mustEntry(t, other, 2).Record }, ErrBadEntry},
		{"tampered ciphertext", func(e *Entry, _ *InclusionProof) { e.Ciphertext = flip(e.Ciphertext, 40) }, ErrBadEntry},
		{"ciphertext of another entry", func(e *Entry, _ *InclusionProof) { e.Ciphertext = mustEntry(t, l, 3).Ciphertext }, ErrBadEntry},
		{"key of another entry", func(e *Entry, _ *InclusionProof) { e.Key = mustEntry(t, l, 3).Key }, ErrBadEntry},
		{"key cut", func(e *Entry, _ *InclusionProof) { e.Key = e.Key[:keySize-1] }, ErrBadEntry},
		{"no ciphertext", func(e *Entry, _ *InclusionProof) { e.Ciphertext = nil }, ErrBadEntry},
		{"ciphertext and marker", func(e *Entry, _ *InclusionProof) { e.Marker = mustEntry(t, l, 5).Marker }, ErrBadEntry},
		{"marker of another entry", func(e *Entry, _ *InclusionProof) {
			e.Ciphertext, e.Key, e.Marker = nil, nil, mustEntry(t, l, 5).Marker
		}, ErrBadEntry},
		{"no key", func(e *Entry, _ *InclusionProof) { e.Key = nil }, ErrKeyUnavailable},
		{"tampered path", func(_ *Entry, p *InclusionProof) { p.Path[0][0] ^= 1 }, ErrBadProof},
		{"path cut", func(_ *Entry, p *InclusionProof) { p.Path = p.Path[1:] }, ErrBadProof},
		{"proof of another index", func(_ *Entry, p *InclusionProof) { *p = inclusion(t, l, 3, 7) }, ErrBadEntry},
		{"proof for an older head", func(_ *Entry, p *InclusionProof) { *p = inclusion(t, l, 2, 6) }, ErrBadProof},
		{"proof index past the head", func(_ *Entry, p *InclusionProof) { p.Index = 9 }, ErrBadEntry},
		{"proof size past the head", func(_ *Entry, p *InclusionProof) { p.Size = 8 }, ErrBadProof},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := cloneEntries([]Entry{good})[0]
			q := InclusionProof{Index: p.Index, Size: p.Size, Path: slices.Clone(p.Path)}
			c.change(&e, &q)
			got, err := OpenEntry(v, q, e)
			if got != nil || !errors.Is(err, c.want) {
				t.Fatalf("OpenEntry = %q, %v, want %v", got, err, c.want)
			}
		})
	}

	d, dp := mustEntry(t, l, 5), inclusion(t, l, 5, 7)
	if _, err := OpenEntry(v, dp, d); !errors.Is(err, ErrDeleted) {
		t.Fatalf("OpenEntry of a deleted entry: %v", err)
	}
	d.Marker = flip(d.Marker, len(d.Marker)-1)
	if _, err := OpenEntry(v, dp, d); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("OpenEntry with a tampered marker: %v", err)
	}
	if _, err := OpenEntry(VerifiedHead{}, p, good); !errors.Is(err, ErrInvalidHead) {
		t.Fatalf("OpenEntry with a zero head: %v", err)
	}
	if _, err := OpenEntry(verified(t, other), inclusion(t, other, 2, 3), good); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("OpenEntry against another log's head: %v", err)
	}
	if got, err := OpenEntry(v, p, good); err != nil || string(got) != "entry 2" {
		t.Fatalf("the good entry no longer opens: %q, %v", got, err)
	}
}

func TestOpenEntryUncommittedKey(t *testing.T) {
	l, _ := newLog(t, 2)
	bad := appendUncommitted(t, l)
	v := verified(t, l)
	if _, err := OpenEntry(v, inclusion(t, l, 2, 3), bad); !errors.Is(err, ErrBadEntry) {
		t.Fatalf("OpenEntry with a key the record does not commit to: %v, want ErrBadEntry", err)
	}
}

func FuzzOpenEntry(f *testing.F) {
	l, _ := newLog(f, 4)
	if err := l.Delete(3); err != nil {
		f.Fatal(err)
	}
	v := verified(f, l)
	for i := range uint64(4) {
		e := mustEntry(f, l, i)
		f.Add(e.Record, e.Ciphertext, e.Marker, []byte(e.Key), inclusion(f, l, i, 4).Encode())
	}
	f.Fuzz(func(t *testing.T, rec, ciphertext, marker, key, proof []byte) {
		p, err := DecodeInclusionProof(proof)
		if err != nil {
			return
		}
		got, err := OpenEntry(v, p, Entry{Record: rec, Ciphertext: ciphertext, Marker: marker, Key: key})
		if err != nil {
			if got != nil {
				t.Fatal("OpenEntry returned bytes and an error")
			}
			return
		}
		if want, werr := l.Get(p.Index); werr != nil || !bytes.Equal(got, want) {
			t.Fatalf("OpenEntry accepted %q for entry %d, which holds %q (%v)", got, p.Index, want, werr)
		}
	})
}

// For index 0 the path in a tree of 8 entries has the shape of one in a tree of 7, so only the size check refuses a proof labelled 7.
func TestOpenEntryProofSizeLabel(t *testing.T) {
	l, _ := newLog(t, 8)
	p := inclusion(t, l, 0, 8)
	p.Size = 7
	if !merkleVerifies(t, l, p) {
		t.Fatal("the relabelled path no longer verifies on its own, so this test checks nothing")
	}
	if _, err := OpenEntry(verified(t, l), p, mustEntry(t, l, 0)); !errors.Is(err, ErrBadProof) {
		t.Fatalf("OpenEntry with a proof labelled with another size: %v", err)
	}
}

func merkleVerifies(t testing.TB, l *Log, p InclusionProof) bool {
	v := verified(t, l)
	r := record(t, l, p.Index)
	return merkle.VerifyInclusion(merkle.LeafHash(r.Encode()), p.Index, p.Size, p.Path, v.Root())
}
