package kololog

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"testing/cryptotest"

	koloid "github.com/ciranda-dev/kolo-id"
)

var goldenValues = [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte("kolo"), 75), []byte("fourth")}

func goldenIdentity(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.FromSeed(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenEntries(t testing.TB) []Entry {
	t.Helper()
	var out []Entry
	for _, g := range goldenDefaultLog.entries {
		e := Entry{Record: unhex(t, g.record), Ciphertext: unhex(t, g.ciphertext), Marker: unhex(t, g.marker), Key: unhex(t, g.key)}
		out = append(out, Entry{Record: e.Record, Ciphertext: absent(e.Ciphertext), Marker: absent(e.Marker), Key: EntryKey(absent(e.Key))})
	}
	return out
}

// A default log written now has exactly the golden bytes when written from the same randomness.
func TestDefaultLogBytesUnchanged(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 16)
	probe := make([]byte, 16)
	if _, err := rand.Read(probe); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(probe) != goldenDefaultLog.probe {
		t.Skip("this Go version's cryptotest stream differs from the one the golden log was written with; TestGoldenLogReads still checks it")
	}
	cryptotest.SetGlobalRandom(t, 16)
	l, err := New(goldenIdentity(t), NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, v := range goldenValues {
		if _, err := l.Append(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(l.Header().Encode()); got != goldenDefaultLog.header {
		t.Fatalf("header\n got %s\nwant %s", got, goldenDefaultLog.header)
	}
	if got := string(mustJSON(t, l.Header())); got != goldenDefaultLog.headerJSON {
		t.Fatalf("header JSON\n got %s\nwant %s", got, goldenDefaultLog.headerJSON)
	}
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h.Encode()); got != goldenDefaultLog.head {
		t.Fatalf("head\n got %s\nwant %s", got, goldenDefaultLog.head)
	}
	for i, want := range goldenEntries(t) {
		got := mustEntry(t, l, uint64(i))
		if !bytes.Equal(got.Record, want.Record) || !bytes.Equal(got.Ciphertext, want.Ciphertext) ||
			!bytes.Equal(got.Marker, want.Marker) || !bytes.Equal(got.Key, want.Key) {
			t.Fatalf("entry %d differs from the golden bytes", i)
		}
	}
}

// The golden log decodes and re-encodes byte for byte, in binary and JSON, restores, and reads the same values.
func TestGoldenLogReads(t *testing.T) {
	id := goldenIdentity(t)
	header, head := unhex(t, goldenDefaultLog.header), unhex(t, goldenDefaultLog.head)
	lh, err := DecodeLogHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if lh.Keys != RandomKeys || lh.Epoch != 0 || !bytes.Equal(lh.Encode(), header) || VerifyLogHeader(id.PublicKey(), lh) != nil {
		t.Fatalf("header decodes as %+v", lh)
	}
	if got := string(mustJSON(t, lh)); got != goldenDefaultLog.headerJSON {
		t.Fatalf("header JSON\n got %s\nwant %s", got, goldenDefaultLog.headerJSON)
	}
	var fromJSON LogHeader
	if err := json.Unmarshal([]byte(goldenDefaultLog.headerJSON), &fromJSON); err != nil || !bytes.Equal(fromJSON.Encode(), header) {
		t.Fatalf("header JSON: %v", err)
	}
	h, err := DecodeHead(head)
	if err != nil || !bytes.Equal(h.Encode(), head) || string(mustJSON(t, h)) != goldenDefaultLog.headJSON {
		t.Fatalf("head: %v", err)
	}
	for i, g := range goldenDefaultLog.entries {
		r, err := DecodeRecord(unhex(t, g.record))
		if err != nil || hex.EncodeToString(r.Encode()) != g.record || string(mustJSON(t, r)) != g.recordJSON {
			t.Fatalf("record %d: %v", i, err)
		}
		if g.marker != "" {
			m, err := DecodeDeleteMarker(unhex(t, g.marker))
			if err != nil || hex.EncodeToString(m.Encode()) != g.marker || string(mustJSON(t, m)) != g.markerJSON {
				t.Fatalf("marker %d: %v", i, err)
			}
		}
	}

	l, err := Restore(id, header, head, storeOf(goldenEntries(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := RestoreReplica(id.PublicKey(), lh.LogID, header, Heads{Head: &h}, storeOf(goldenEntries(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, rd := range []interface{ Get(uint64) ([]byte, error) }{l, r} {
		for i, want := range goldenValues {
			got, err := rd.Get(uint64(i))
			if i == 1 {
				if !errors.Is(err, ErrDeleted) {
					t.Fatalf("deleted entry: %v", err)
				}
				continue
			}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("entry %d reads %q, %v, want %q", i, got, err, want)
			}
		}
	}
}
