package kololog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

type jsonFixture struct {
	log    *Log
	head   Head
	rec    Record
	inc    InclusionProof
	con    ConsistencyProof
	marker DeleteMarker
}

func newJSONFixture(t testing.TB) jsonFixture {
	l, _ := newLog(t, 9)
	inc, err := l.InclusionProof(4, 9)
	if err != nil {
		t.Fatal(err)
	}
	con, err := l.ConsistencyProof(3, 9)
	if err != nil {
		t.Fatal(err)
	}
	x := jsonFixture{log: l, head: head(t, l), rec: record(t, l, 4), inc: inc, con: con}
	if err := l.Delete(8); err != nil {
		t.Fatal(err)
	}
	e, err := l.Entry(8)
	if err != nil {
		t.Fatal(err)
	}
	if x.marker, err = DecodeDeleteMarker(e.Marker); err != nil {
		t.Fatal(err)
	}
	return x
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJSONRoundTrip(t *testing.T) {
	x := newJSONFixture(t)

	var h Head
	if err := json.Unmarshal(mustJSON(t, x.head), &h); err != nil || !bytes.Equal(h.Encode(), x.head.Encode()) {
		t.Fatalf("head round trip: %v", err)
	}
	var r Record
	if err := json.Unmarshal(mustJSON(t, x.rec), &r); err != nil || !bytes.Equal(r.Encode(), x.rec.Encode()) {
		t.Fatalf("record round trip: %v", err)
	}
	var p InclusionProof
	if err := json.Unmarshal(mustJSON(t, x.inc), &p); err != nil || !bytes.Equal(p.Encode(), x.inc.Encode()) {
		t.Fatalf("inclusion proof round trip: %v", err)
	}
	var c ConsistencyProof
	if err := json.Unmarshal(mustJSON(t, x.con), &c); err != nil || !bytes.Equal(c.Encode(), x.con.Encode()) {
		t.Fatalf("consistency proof round trip: %v", err)
	}
	var id LogID
	if err := json.Unmarshal(mustJSON(t, x.log.ID()), &id); err != nil || id != x.log.ID() {
		t.Fatalf("log ID round trip: %v", err)
	}
}

func TestJSONShape(t *testing.T) {
	var h [HashSize]byte
	h[0] = 0xab
	p := InclusionProof{Index: 1, Size: 18446744073709551615, Path: [][HashSize]byte{h}}
	want := `{"index":"1","size":"18446744073709551615","path":["ab` + strings.Repeat("00", 31) + `"]}`
	if got := string(mustJSON(t, p)); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got := string(mustJSON(t, ConsistencyProof{})); got != `{"oldSize":"0","newSize":"0","path":[]}` {
		t.Fatalf("empty consistency proof: %s", got)
	}

	x := newJSONFixture(t)
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, x.head), &m); err != nil {
		t.Fatal(err)
	}
	wantHead := map[string]any{
		"logKey":    hex.EncodeToString(x.head.LogKey),
		"logId":     hex.EncodeToString(x.head.LogID[:]),
		"size":      "9",
		"root":      hex.EncodeToString(x.head.Root[:]),
		"signature": hex.EncodeToString(x.head.Signature),
	}
	if fmt.Sprint(m) != fmt.Sprint(wantHead) {
		t.Fatalf("head JSON = %v, want %v", m, wantHead)
	}
	if got := string(mustJSON(t, x.log.ID())); got != `"`+hex.EncodeToString(x.log.logID[:])+`"` {
		t.Fatalf("log ID JSON = %s", got)
	}
}

func mutate(t *testing.T, valid []byte, change func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(valid, &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	return mustJSON(t, m)
}

func TestJSONStrict(t *testing.T) {
	x := newJSONFixture(t)
	types := []struct {
		name    string
		valid   []byte
		hexes   []string
		uints   []string
		hasPath bool
		decode  func([]byte) error
	}{
		{"head", mustJSON(t, x.head), []string{"logKey", "logId", "root", "signature"}, []string{"size"}, false,
			func(b []byte) error { var v Head; return v.UnmarshalJSON(b) }},
		{"record", mustJSON(t, x.rec), []string{"logKey", "logId", "contentHash", "keyCommit", "signature"}, []string{"index", "size"}, false,
			func(b []byte) error { var v Record; return v.UnmarshalJSON(b) }},
		{"inclusion", mustJSON(t, x.inc), nil, []string{"index", "size"}, true,
			func(b []byte) error { var v InclusionProof; return v.UnmarshalJSON(b) }},
		{"consistency", mustJSON(t, x.con), nil, []string{"oldSize", "newSize"}, true,
			func(b []byte) error { var v ConsistencyProof; return v.UnmarshalJSON(b) }},
		{"delete marker", mustJSON(t, x.marker), []string{"logKey", "logId", "leafHash", "signature"}, []string{"index"}, false,
			func(b []byte) error { var v DeleteMarker; return v.UnmarshalJSON(b) }},
	}
	for _, tt := range types {
		if err := tt.decode(tt.valid); err != nil {
			t.Fatalf("%s: valid JSON rejected: %v", tt.name, err)
		}
		bad := map[string][]byte{
			"trailing object": append(bytes.Clone(tt.valid), []byte(" {}")...),
			"trailing byte":   append(bytes.Clone(tt.valid), 'x'),
			"not an object":   []byte(`[]`),
			"null":            []byte(`null`),
			"empty":           nil,
			"unknown field":   mutate(t, tt.valid, func(m map[string]any) { m["extra"] = "x" }),
			"duplicate field": append([]byte(`{"`+tt.uints[0]+`":"1",`), tt.valid[1:]...),
		}
		var m map[string]any
		if err := json.Unmarshal(tt.valid, &m); err != nil {
			t.Fatal(err)
		}
		for key := range m {
			bad["missing "+key] = mutate(t, tt.valid, func(m map[string]any) { delete(m, key) })
			bad["null "+key] = mutate(t, tt.valid, func(m map[string]any) { m[key] = nil })
			bad["capitalized "+key] = mutate(t, tt.valid, func(m map[string]any) {
				m[strings.ToUpper(key[:1])+key[1:]] = m[key]
				delete(m, key)
			})
		}
		for _, key := range tt.hexes {
			s := m[key].(string)
			bad["short "+key] = mutate(t, tt.valid, func(m map[string]any) { m[key] = s[:len(s)-2] })
			bad["long "+key] = mutate(t, tt.valid, func(m map[string]any) { m[key] = s + "00" })
			bad["uppercase "+key] = mutate(t, tt.valid, func(m map[string]any) { m[key] = strings.ToUpper(s) })
			bad["non-hex "+key] = mutate(t, tt.valid, func(m map[string]any) { m[key] = "zz" + s[2:] })
		}
		for _, key := range tt.uints {
			for _, v := range []any{"01", "+1", " 1", "1 ", "-1", "", "1.0", "1e3", "18446744073709551616", 1} {
				bad[fmt.Sprintf("%s=%q", key, v)] = mutate(t, tt.valid, func(m map[string]any) { m[key] = v })
			}
		}
		if tt.hasPath {
			item := strings.Repeat("ab", HashSize)
			long := make([]any, merkle.MaxPathLen+1)
			for i := range long {
				long[i] = item
			}
			bad["path of 66"] = mutate(t, tt.valid, func(m map[string]any) { m["path"] = long })
			bad["path short item"] = mutate(t, tt.valid, func(m map[string]any) { m["path"] = []any{item[:62]} })
			bad["path uppercase item"] = mutate(t, tt.valid, func(m map[string]any) { m["path"] = []any{strings.ToUpper(item)} })
			bad["path not array"] = mutate(t, tt.valid, func(m map[string]any) { m["path"] = item })
			bad["path null item"] = mutate(t, tt.valid, func(m map[string]any) { m["path"] = []any{nil} })
		}
		for name, b := range bad {
			if err := tt.decode(b); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s %s: UnmarshalJSON returned %v, want %v", tt.name, name, err, ErrMalformed)
			}
		}
	}

	item := strings.Repeat("ab", HashSize)
	ok := func(n int) []byte {
		p := make([]any, n)
		for i := range p {
			p[i] = item
		}
		return mustJSON(t, map[string]any{"index": "0", "size": "1", "path": p})
	}
	var p InclusionProof
	if err := p.UnmarshalJSON(ok(merkle.MaxPathLen)); err != nil || len(p.Path) != merkle.MaxPathLen {
		t.Fatalf("path of %d rejected: %v", merkle.MaxPathLen, err)
	}
}

func TestLogIDJSONStrict(t *testing.T) {
	valid := strings.Repeat("0f", LogIDSize)
	var id LogID
	if err := id.UnmarshalJSON([]byte(`"` + valid + `"`)); err != nil || id.String() != valid {
		t.Fatalf("valid log ID rejected: %v", err)
	}
	for _, b := range []string{
		`"` + valid[2:] + `"`,
		`"` + valid + `00"`,
		`"` + strings.ToUpper(valid) + `"`,
		`"` + valid + `" "x"`,
		`"` + valid + `"x`,
		`null`, `1`, `{}`, ``,
	} {
		var id LogID
		if err := id.UnmarshalJSON([]byte(b)); !errors.Is(err, ErrMalformed) {
			t.Errorf("UnmarshalJSON(%q) = %v, want %v", b, err, ErrMalformed)
		}
	}
}

func TestVerifiedHeadNotDecodable(t *testing.T) {
	l, id := newLog(t, 2)
	h := head(t, l)
	v, err := VerifyHead(id.PublicKey(), l.ID(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustJSON(t, v), mustJSON(t, h)) {
		t.Fatal("VerifiedHead JSON differs from Head JSON")
	}

	var direct VerifiedHead
	if err := json.Unmarshal(mustJSON(t, h), &direct); !errors.Is(err, ErrNotDecodable) {
		t.Fatalf("decoding into a VerifiedHead returned %v, want %v", err, ErrNotDecodable)
	}
	var field struct {
		H VerifiedHead `json:"h"`
	}
	in := []byte(`{"h":` + string(mustJSON(t, h)) + `}`)
	if err := json.Unmarshal(in, &field); !errors.Is(err, ErrNotDecodable) {
		t.Fatalf("decoding into a VerifiedHead field returned %v, want %v", err, ErrNotDecodable)
	}
	if err := json.Unmarshal([]byte(`null`), &direct); !errors.Is(err, ErrNotDecodable) {
		t.Fatalf("decoding null into a VerifiedHead returned %v, want %v", err, ErrNotDecodable)
	}
}

func TestJSONHeadMustVerify(t *testing.T) {
	l, id := newLog(t, 3)
	valid := mustJSON(t, head(t, l))
	var h Head
	if err := json.Unmarshal(valid, &h); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHead(id.PublicKey(), l.ID(), h); err != nil {
		t.Fatalf("real head from JSON rejected: %v", err)
	}
	tampered := map[string]func(map[string]any){
		"size": func(m map[string]any) { m["size"] = "4" },
		"root": func(m map[string]any) { m["root"] = strings.Repeat("00", HashSize) },
	}
	for name, change := range tampered {
		var th Head
		if err := json.Unmarshal(mutate(t, valid, change), &th); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyHead(id.PublicKey(), l.ID(), th); !errors.Is(err, ErrBadHeadSignature) {
			t.Errorf("head with tampered %s from JSON returned %v, want %v", name, err, ErrBadHeadSignature)
		}
	}
}

func TestStringAndLogValue(t *testing.T) {
	x := newJSONFixture(t)
	h := x.head
	short := func(b []byte) string { return hex.EncodeToString(b[:8]) + "..." }

	if got, want := x.log.ID().String(), hex.EncodeToString(x.log.logID[:]); got != want || len(got) != 64 {
		t.Errorf("LogID.String() = %s, want %s", got, want)
	}
	strs := map[string]string{
		h.String():     fmt.Sprintf("kololog.Head{log=%s, size=9, root=%s}", short(h.LogID[:]), short(h.Root[:])),
		x.rec.String(): fmt.Sprintf("kololog.Record{log=%s, index=4, size=%d, content=%s}", short(x.rec.LogID[:]), x.rec.Size, short(x.rec.ContentHash[:])),
		x.inc.String(): fmt.Sprintf("kololog.InclusionProof{index=4, size=9, path=%d hashes}", len(x.inc.Path)),
		x.con.String(): fmt.Sprintf("kololog.ConsistencyProof{old=3, new=9, path=%d hashes}", len(x.con.Path)),
	}
	for got, want := range strs {
		if got != want {
			t.Errorf("String() = %s, want %s", got, want)
		}
	}
	v, err := VerifyHead(x.log.pub, x.log.ID(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.String(), "kololog.VerifiedHead{log=") {
		t.Errorf("VerifiedHead.String() = %s", v)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("x", "head", h, "verified", v, "record", x.rec, "inc", x.inc, "con", x.con, "id", x.log.ID())
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"head", "verified"} {
		g := out[k].(map[string]any)
		if g["size"] != float64(9) || g["root"] != hex.EncodeToString(h.Root[:]) || g["signature"] != hex.EncodeToString(h.Signature) {
			t.Errorf("slog %s = %v", k, g)
		}
	}
	if rec := out["record"].(map[string]any); rec["index"] != float64(4) || rec["contentHash"] != hex.EncodeToString(x.rec.ContentHash[:]) {
		t.Errorf("slog record = %v", rec)
	}
	if inc := out["inc"].(map[string]any); inc["size"] != float64(9) || len(inc["path"].([]any)) != len(x.inc.Path) {
		t.Errorf("slog inclusion proof = %v", inc)
	}
	if con := out["con"].(map[string]any); con["oldSize"] != float64(3) || len(con["path"].([]any)) != len(x.con.Path) {
		t.Errorf("slog consistency proof = %v", con)
	}
	if out["id"] != x.log.ID().String() {
		t.Errorf("slog log ID = %v", out["id"])
	}
}

func TestJSONRejectsEscapesAndOversize(t *testing.T) {
	x := newJSONFixture(t)
	types := []struct {
		name   string
		valid  []byte
		key    string
		decode func([]byte) error
	}{
		{"head", mustJSON(t, x.head), "logKey", func(b []byte) error { var v Head; return v.UnmarshalJSON(b) }},
		{"record", mustJSON(t, x.rec), "contentHash", func(b []byte) error { var v Record; return v.UnmarshalJSON(b) }},
		{"inclusion", mustJSON(t, x.inc), "index", func(b []byte) error { var v InclusionProof; return v.UnmarshalJSON(b) }},
		{"consistency", mustJSON(t, x.con), "oldSize", func(b []byte) error { var v ConsistencyProof; return v.UnmarshalJSON(b) }},
		{"log header", mustJSON(t, x.log.Header()), "encoding", func(b []byte) error { var v LogHeader; return v.UnmarshalJSON(b) }},
		{"log ID", mustJSON(t, x.log.ID()), "", func(b []byte) error { var v LogID; return v.UnmarshalJSON(b) }},
		{"delete marker", mustJSON(t, x.marker), "leafHash", func(b []byte) error { var v DeleteMarker; return v.UnmarshalJSON(b) }},
	}
	for _, tt := range types {
		bad := map[string][]byte{
			"oversized": append(bytes.Clone(tt.valid), bytes.Repeat([]byte(" "), 16<<10)...),
		}
		if tt.key != "" {
			escaped := tt.key[:1] + `\u00` + hex.EncodeToString([]byte{tt.key[1]}) + tt.key[2:]
			bad["escaped key"] = bytes.Replace(tt.valid, []byte(`"`+tt.key+`"`), []byte(`"`+escaped+`"`), 1)
		}
		// The first hex or digit character inside a string value, escaped.
		at := bytes.Index(tt.valid, []byte(`":"`)) + 3
		if tt.key == "" {
			at = 1
		} else if tt.name == "inclusion" || tt.name == "consistency" {
			at = bytes.Index(tt.valid, []byte(`["`)) + 2
		}
		bad["escaped value char"] = append(append(bytes.Clone(tt.valid[:at]), []byte(`\u00`+hex.EncodeToString(tt.valid[at:at+1]))...), tt.valid[at+1:]...)
		for name, b := range bad {
			if err := tt.decode(b); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s %s: UnmarshalJSON returned %v, want %v", tt.name, name, err, ErrMalformed)
			}
		}
	}
}
