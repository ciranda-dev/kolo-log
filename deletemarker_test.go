package kololog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
)

func marker(t testing.TB, l *Log, i uint64) DeleteMarker {
	t.Helper()
	e, err := l.Entry(i)
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeDeleteMarker(e.Marker)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDeleteSignsMarker(t *testing.T) {
	l, id := newLog(t, 3)
	if e, _ := l.Entry(1); e.Marker != nil {
		t.Fatal("live entry has a marker")
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	m := marker(t, l, 1)
	r := record(t, l, 1)
	if !VerifyDeleteMarker(id.PublicKey(), l.ID(), r, m) {
		t.Fatal("marker of a deleted entry rejected")
	}
	if !koloid.Verify(id.PublicKey(), DeleteContext, m.signed(), m.Signature) || koloid.Verify(id.PublicKey(), RecordContext, m.signed(), m.Signature) {
		t.Fatal("marker is not signed under DeleteContext only")
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if again := marker(t, l, 1); !bytes.Equal(again.Encode(), m.Encode()) {
		t.Fatal("second Delete changed the marker")
	}

	got, err := DecodeDeleteMarker(m.Encode())
	if err != nil || !bytes.Equal(got.Encode(), m.Encode()) {
		t.Fatalf("binary round trip: %v", err)
	}
	var fromJSON DeleteMarker
	if err := json.Unmarshal(mustJSON(t, m), &fromJSON); err != nil || !bytes.Equal(fromJSON.Encode(), m.Encode()) {
		t.Fatalf("JSON round trip: %v", err)
	}
	if !strings.HasPrefix(m.String(), "kololog.DeleteMarker{log=") {
		t.Errorf("String() = %s", m)
	}
}

func TestVerifyDeleteMarkerRejects(t *testing.T) {
	id := newID(t)
	l := newLogFor(t, id, 3)
	other := newLogFor(t, id, 3)
	for _, x := range []*Log{l, other} {
		if err := x.Delete(1); err != nil {
			t.Fatal(err)
		}
	}
	pub := id.PublicKey()
	r, m := record(t, l, 1), marker(t, l, 1)

	forged := m.clone()
	forged.Signature[0] ^= 1
	reindexed := m
	reindexed.Index = 2
	relabeled := m
	relabeled.LogID = other.ID()
	cases := map[string]struct {
		pub   ed25519.PublicKey
		logID LogID
		r     Record
		m     DeleteMarker
	}{
		"forged signature":    {pub, l.ID(), r, forged},
		"another index":       {pub, l.ID(), record(t, l, 2), reindexed},
		"another log ID":      {pub, l.ID(), r, marker(t, other, 1)},
		"rewritten log ID":    {pub, other.ID(), r, relabeled},
		"different leaf hash": {pub, l.ID(), record(t, l, 0), m},
		"another key":         {newID(t).PublicKey(), l.ID(), r, m},
		"short key":           {pub[:31], l.ID(), r, m},
		"record of other log": {pub, l.ID(), record(t, other, 1), m},
		"zero marker":         {pub, l.ID(), r, DeleteMarker{}},
	}
	for name, c := range cases {
		if VerifyDeleteMarker(c.pub, c.logID, c.r, c.m) {
			t.Errorf("%s: marker accepted", name)
		}
	}
	if !VerifyDeleteMarker(pub, l.ID(), r, m) {
		t.Fatal("valid marker rejected")
	}
}

func TestDecodeDeleteMarkerMalformed(t *testing.T) {
	l, _ := newLog(t, 1)
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	valid := marker(t, l, 0).Encode()
	for n := range len(valid) {
		if _, err := DecodeDeleteMarker(valid[:n]); !errors.Is(err, ErrMalformed) {
			t.Errorf("truncated to %d bytes: %v", n, err)
		}
	}
	if _, err := DecodeDeleteMarker(append(bytes.Clone(valid), 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing byte: %v", err)
	}
	if _, err := DecodeDeleteMarker(record(t, l, 0).Encode()); !errors.Is(err, ErrMalformed) {
		t.Errorf("record decoded as a marker: %v", err)
	}
}

func TestRestoreDeleteMarkers(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}, 1, 3)
	x.log.Close()
	pub := x.id.PublicKey()
	m1, err := DecodeDeleteMarker(x.entries[1].Marker)
	if err != nil {
		t.Fatal(err)
	}

	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(cloneEntries(x.entries)))
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := l.Entry(1); !bytes.Equal(e.Marker, x.entries[1].Marker) || e.Ciphertext != nil {
		t.Fatal("restored deleted entry lost its marker")
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if !VerifyDeleteMarker(pub, x.log.ID(), record(t, l, 0), marker(t, l, 0)) {
		t.Fatal("deleting a restored entry did not sign a valid marker")
	}
	l.Close()

	other := newLogFor(t, x.id, 2)
	if err := other.Delete(1); err != nil {
		t.Fatal(err)
	}
	otherEntry, _ := other.Entry(1)

	wrongLeaf := m1.clone()
	wrongLeaf.LeafHash[0] ^= 1
	if wrongLeaf.Signature, err = x.id.Sign(DeleteContext, wrongLeaf.signed()); err != nil {
		t.Fatal(err)
	}
	forged := m1.clone()
	forged.Signature[0] ^= 1

	cases := map[string]func([]Entry){
		"forged marker":             func(e []Entry) { e[1].Marker = forged.Encode() },
		"marker for another index":  func(e []Entry) { e[1].Marker, e[3].Marker = e[3].Marker, e[1].Marker },
		"marker for another log ID": func(e []Entry) { e[1].Marker = otherEntry.Marker },
		"marker over another leaf":  func(e []Entry) { e[1].Marker = wrongLeaf.Encode() },
		"nil ciphertext, no marker": func(e []Entry) { e[1].Marker = nil },
		"marker and ciphertext":     func(e []Entry) { e[0].Marker = x.entries[1].Marker },
		"malformed marker":          func(e []Entry) { e[1].Marker = e[1].Marker[:10] },
	}
	for name, change := range cases {
		entries := cloneEntries(x.entries)
		change(entries)
		l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(entries))
		if !errors.Is(err, ErrRestoreMismatch) {
			if l != nil {
				l.Close()
			}
			t.Errorf("%s: Restore returned %v, want %v", name, err, ErrRestoreMismatch)
		}
	}
}
