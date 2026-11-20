package kololog

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
)

func newEncodedLog(t *testing.T, e ValueEncoding) (*Log, *koloid.Identity) {
	t.Helper()
	id := newID(t)
	l, err := New(id, NewMemory(), WithValueEncoding(e))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, id
}

func TestValueEncodingString(t *testing.T) {
	for e, want := range map[ValueEncoding]string{Bytes: "bytes", UTF8: "utf8", JSON: "json"} {
		if e.String() != want {
			t.Errorf("%d.String() = %q, want %q", e, e.String(), want)
		}
	}
	if _, err := New(newID(t), NewMemory(), WithValueEncoding(JSON+1)); !errors.Is(err, ErrUnknownEncoding) {
		t.Fatalf("New with an unknown encoding returned %v, want %v", err, ErrUnknownEncoding)
	}
	l, err := New(newID(t), NewMemory(), nil)
	if err != nil || l.Header().Encoding != Bytes {
		t.Fatalf("default encoding: %v, %v", l.Header().Encoding, err)
	}
}

func TestBytesValues(t *testing.T) {
	l, _ := newEncodedLog(t, Bytes)
	in := []byte{0, 1, 0xff, 0x80, 'k'}
	i, err := l.Append(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	if err := l.Read(i, &out); err != nil || !bytes.Equal(out, in) {
		t.Fatalf("Read = %x, %v", out, err)
	}
	if raw, err := l.Get(i); err != nil || !bytes.Equal(raw, in) {
		t.Fatalf("Get = %x, %v", raw, err)
	}
}

func TestUTF8Values(t *testing.T) {
	l, _ := newEncodedLog(t, UTF8)
	in := "olá, kolo, 日本語, 🎉"
	i, err := l.Append(in)
	if err != nil {
		t.Fatal(err)
	}
	var out string
	if err := l.Read(i, &out); err != nil || out != in {
		t.Fatalf("Read = %q, %v", out, err)
	}
	if raw, err := l.Get(i); err != nil || string(raw) != in {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	if _, err := l.Append("bad \xff utf8"); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("Append of invalid UTF-8 returned %v, want %v", err, ErrInvalidUTF8)
	}
	if l.Len() != 1 {
		t.Fatalf("Len() = %d after a rejected Append", l.Len())
	}
}

func TestJSONValues(t *testing.T) {
	type point struct {
		X, Y int
		Name string `json:"name"`
	}
	l, _ := newEncodedLog(t, JSON)
	values := []struct{ in, out any }{
		{point{1, -2, "a"}, &point{}},
		{map[string]any{"k": "v", "n": 1.5}, &map[string]any{}},
		{[]string{"x", "y"}, &[]string{}},
	}
	for _, v := range values {
		i, err := l.Append(v.in)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Read(i, v.out); err != nil {
			t.Fatal(err)
		}
		if got := reflect.ValueOf(v.out).Elem().Interface(); !reflect.DeepEqual(got, v.in) {
			t.Fatalf("Read = %#v, want %#v", got, v.in)
		}
		raw, err := l.Get(i)
		if err != nil {
			t.Fatal(err)
		}
		if want, _ := json.Marshal(v.in); !bytes.Equal(raw, want) {
			t.Fatalf("Get = %s, want %s", raw, want)
		}
	}
	if _, err := l.Append(func() {}); !errors.Is(err, ErrWrongValueType) {
		t.Fatalf("Append of a func returned %v, want %v", err, ErrWrongValueType)
	}
}

func TestWrongValueTypes(t *testing.T) {
	var s string
	var b []byte
	var nilPoint *struct{}
	cases := []struct {
		e      ValueEncoding
		values []any
		outs   []any
	}{
		{Bytes, []any{"text", 1, nil, [4]byte{}}, []any{nil, &s, b, (*[]byte)(nil), 1}},
		{UTF8, []any{[]byte("text"), 1, nil}, []any{nil, &b, s, (*string)(nil), 1}},
		{JSON, []any{make(chan int)}, []any{nil, s, 1, nilPoint}},
	}
	for _, c := range cases {
		l, _ := newEncodedLog(t, c.e)
		for _, v := range c.values {
			_, err := l.Append(v)
			if c.e == JSON {
				if err == nil {
					t.Errorf("%s: Append(%T) succeeded", c.e, v)
				}
				continue
			}
			if !errors.Is(err, ErrWrongValueType) {
				t.Errorf("%s: Append(%T) returned %v, want %v", c.e, v, err, ErrWrongValueType)
			}
		}
		good := map[ValueEncoding]any{Bytes: []byte("x"), UTF8: "x", JSON: 1}[c.e]
		if _, err := l.Append(good); err != nil {
			t.Fatal(err)
		}
		for _, out := range c.outs {
			if err := l.Read(0, out); !errors.Is(err, ErrWrongValueType) {
				t.Errorf("%s: Read into %T returned %v, want %v", c.e, out, err, ErrWrongValueType)
			}
		}
	}
}

func TestReadMissingEntries(t *testing.T) {
	l, _ := newEncodedLog(t, UTF8)
	if _, err := l.Append("x"); err != nil {
		t.Fatal(err)
	}
	var out string
	if err := l.Read(1, &out); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Read past the end returned %v", err)
	}
	if err := l.Delete(0); err != nil {
		t.Fatal(err)
	}
	if err := l.Read(0, &out); !errors.Is(err, ErrDeleted) {
		t.Fatalf("Read of a deleted entry returned %v", err)
	}
}

func TestLogHeader(t *testing.T) {
	l, id := newEncodedLog(t, JSON)
	h := l.Header()
	if !h.LogKey.Equal(id.PublicKey()) || h.LogID != l.ID() || h.Encoding != JSON {
		t.Fatalf("header = %v", h)
	}
	if err := VerifyLogHeader(id.PublicKey(), h); err != nil {
		t.Fatal(err)
	}
	h.LogKey[0] ^= 1
	if err := VerifyLogHeader(id.PublicKey(), l.Header()); err != nil {
		t.Fatal("changing a returned header changed the log")
	}

	got, err := DecodeLogHeader(l.Header().Encode())
	if err != nil || !bytes.Equal(got.Encode(), l.Header().Encode()) {
		t.Fatalf("binary round trip: %v", err)
	}
	var fromJSON LogHeader
	if err := json.Unmarshal(mustJSON(t, l.Header()), &fromJSON); err != nil || !bytes.Equal(fromJSON.Encode(), l.Header().Encode()) {
		t.Fatalf("JSON round trip: %v", err)
	}
	if want := `"encoding":"json"`; !strings.Contains(string(mustJSON(t, l.Header())), want) {
		t.Fatalf("header JSON lacks %s", want)
	}

	tampered := map[string]func(*LogHeader){
		"log ID":    func(h *LogHeader) { h.LogID[0] ^= 1 },
		"encoding":  func(h *LogHeader) { h.Encoding = Bytes },
		"log key":   func(h *LogHeader) { h.LogKey[0] ^= 1 },
		"signature": func(h *LogHeader) { h.Signature[0] ^= 1 },
		"unknown":   func(h *LogHeader) { h.Encoding = JSON + 1 },
	}
	for name, change := range tampered {
		th := l.Header()
		change(&th)
		if err := VerifyLogHeader(id.PublicKey(), th); !errors.Is(err, ErrBadLogHeader) {
			t.Errorf("tampered %s returned %v, want %v", name, err, ErrBadLogHeader)
		}
	}
	for _, key := range [][]byte{newID(t).PublicKey(), nil, id.PublicKey()[:31]} {
		if err := VerifyLogHeader(key, l.Header()); !errors.Is(err, ErrBadLogHeader) {
			t.Errorf("a %d-byte wrong key returned %v", len(key), err)
		}
	}
	if !strings.HasPrefix(l.Header().String(), "kololog.LogHeader{log=") || !strings.HasSuffix(l.Header().String(), "encoding=json}") {
		t.Errorf("String() = %s", l.Header())
	}
}

func TestDecodeLogHeaderMalformed(t *testing.T) {
	l, _ := newEncodedLog(t, UTF8)
	valid := l.Header().Encode()
	for n := range len(valid) {
		if _, err := DecodeLogHeader(valid[:n]); !errors.Is(err, ErrMalformed) {
			t.Errorf("truncated to %d bytes: %v", n, err)
		}
	}
	if _, err := DecodeLogHeader(append(bytes.Clone(valid), 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing byte: %v", err)
	}
	encAt := 1 + len(HeaderContext) + 32 + LogIDSize
	unknown := bytes.Clone(valid)
	unknown[encAt] = 3
	if _, err := DecodeLogHeader(unknown); !errors.Is(err, ErrMalformed) || !errors.Is(err, ErrUnknownEncoding) {
		t.Errorf("unknown encoding: %v", err)
	}
	nonCanonical := append(append(bytes.Clone(valid[:encAt]), 0x81, 0x00), valid[encAt+1:]...)
	if _, err := DecodeLogHeader(nonCanonical); !errors.Is(err, ErrMalformed) {
		t.Errorf("non-canonical encoding: %v", err)
	}
	if _, err := DecodeLogHeader(head(t, newLogFor(t, newID(t), 0)).Encode()); !errors.Is(err, ErrMalformed) {
		t.Errorf("tree head decoded as a log header: %v", err)
	}
}

func TestLogHeaderJSONStrict(t *testing.T) {
	l, _ := newEncodedLog(t, UTF8)
	valid := mustJSON(t, l.Header())
	var m map[string]any
	if err := json.Unmarshal(valid, &m); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"trailing":        append(bytes.Clone(valid), 'x'),
		"unknown field":   mutate(t, valid, func(m map[string]any) { m["extra"] = "x" }),
		"duplicate field": append([]byte(`{"encoding":"utf8",`), valid[1:]...),
		"not an object":   []byte(`"x"`),
	}
	for key := range m {
		bad["missing "+key] = mutate(t, valid, func(m map[string]any) { delete(m, key) })
		bad["capitalized "+key] = mutate(t, valid, func(m map[string]any) {
			m[strings.ToUpper(key[:1])+key[1:]] = m[key]
			delete(m, key)
		})
	}
	for _, key := range []string{"logKey", "logId", "signature"} {
		s := m[key].(string)
		bad["short "+key] = mutate(t, valid, func(m map[string]any) { m[key] = s[:len(s)-2] })
		bad["uppercase "+key] = mutate(t, valid, func(m map[string]any) { m[key] = strings.ToUpper(s) })
	}
	for _, e := range []any{"UTF8", "Utf8", "text", "", "ValueEncoding(3)", 1, nil} {
		bad["encoding "+string(mustJSON(t, e))] = mutate(t, valid, func(m map[string]any) { m["encoding"] = e })
	}
	for name, b := range bad {
		var h LogHeader
		if err := h.UnmarshalJSON(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: UnmarshalJSON returned %v, want %v", name, err, ErrMalformed)
		}
	}
	if _, err := json.Marshal(LogHeader{Encoding: JSON + 1}); err == nil {
		t.Error("a header with an unknown encoding was marshaled")
	}
}

func TestRestoreHeader(t *testing.T) {
	for _, e := range []ValueEncoding{Bytes, UTF8, JSON} {
		orig, id := newEncodedLog(t, e)
		header := orig.Header().Encode()
		hd := head(t, orig).Encode()
		orig.Close()

		for _, other := range []ValueEncoding{Bytes, UTF8, JSON} {
			if other == e {
				continue
			}
			_, err := Restore(id, header, hd, NewMemory(), WithValueEncoding(other))
			if !errors.Is(err, ErrEncodingMismatch) || !strings.Contains(err.Error(), e.String()) || !strings.Contains(err.Error(), other.String()) {
				t.Errorf("header %s restored as %s: %v", e, other, err)
			}
		}
		l, err := Restore(id, header, hd, NewMemory(), WithValueEncoding(e))
		if err != nil {
			t.Fatalf("%s: Restore returned %v", e, err)
		}
		if l.ID() != orig.ID() || l.Len() != 0 || !bytes.Equal(l.Header().Encode(), header) {
			t.Fatalf("%s: restored log does not match its header", e)
		}
		good := map[ValueEncoding]any{Bytes: []byte("x"), UTF8: "x", JSON: 1}[e]
		if _, err := l.Append(good); err != nil {
			t.Errorf("%s: Append after Restore returned %v", e, err)
		}
		l.Close()
	}

	jsonLog, id := newEncodedLog(t, JSON)
	if _, err := Restore(id, jsonLog.Header().Encode(), head(t, jsonLog).Encode(), NewMemory()); !errors.Is(err, ErrEncodingMismatch) {
		t.Errorf("default Bytes against a JSON header: %v", err)
	}

	byteLog, id := newEncodedLog(t, Bytes)
	header := byteLog.Header().Encode()
	hd := head(t, byteLog).Encode()
	byteLog.Close()
	for name, h := range map[string][]byte{"nil": nil, "empty": {}} {
		if _, err := Restore(id, h, hd, NewMemory()); !errors.Is(err, ErrMissingHeader) {
			t.Errorf("%s header: %v, want %v", name, err, ErrMissingHeader)
		}
	}
	if _, err := Restore(id, header[:len(header)-1], hd, NewMemory()); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated header: %v, want %v", err, ErrMalformed)
	}
	if _, err := Restore(newID(t), header, hd, NewMemory()); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("other identity: %v, want %v", err, ErrBadLogHeader)
	}
	tampered := bytes.Clone(header)
	tampered[len(tampered)-1] ^= 1
	if _, err := Restore(id, tampered, hd, NewMemory()); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("tampered signature: %v, want %v", err, ErrBadLogHeader)
	}
	tampered = bytes.Clone(header)
	tampered[1+len(HeaderContext)+32] ^= 1
	if _, err := Restore(id, tampered, hd, NewMemory()); !errors.Is(err, ErrBadLogHeader) {
		t.Errorf("tampered log ID: %v, want %v", err, ErrBadLogHeader)
	}
	for name, bad := range map[string]*koloid.Identity{"nil": nil, "zero": {}} {
		if _, err := Restore(bad, header, hd, NewMemory()); !errors.Is(err, koloid.ErrInvalidIdentity) {
			t.Errorf("%s identity: %v, want %v", name, err, koloid.ErrInvalidIdentity)
		}
	}
	if _, err := Restore(id, header, hd, NewMemory(), WithValueEncoding(JSON+1)); !errors.Is(err, ErrUnknownEncoding) {
		t.Errorf("unknown encoding option: %v", err)
	}
	if _, err := Restore(id, header, hd, nil); !errors.Is(err, ErrNoStorage) {
		t.Errorf("nil storage: %v, want %v", err, ErrNoStorage)
	}
}

func TestJSONErrorsHideContent(t *testing.T) {
	l, _ := newEncodedLog(t, JSON)
	i, err := l.Append(map[string]any{"n": 300, "s": "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	var small struct{ N uint8 }
	var quoted struct {
		S int `json:"s,string"`
	}
	for _, out := range []any{&small, &quoted} {
		err := l.Read(i, out)
		if err == nil || !errors.Is(err, ErrWrongValueType) {
			t.Fatalf("Read into %T: %v, want %v", out, err, ErrWrongValueType)
		}
		if strings.Contains(err.Error(), "300") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("Read into %T leaks content: %v", out, err)
		}
	}
	_, err = l.Append(math.NaN())
	if err == nil || strings.Contains(err.Error(), "NaN") {
		t.Errorf("Append(NaN) error leaks the value: %v", err)
	}
}

func TestReadClearsPlaintext(t *testing.T) {
	var s string
	f := entrycrypt.Frame([]byte("secret text"))
	data, err := entrycrypt.Unframe(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeFrame(UTF8, f, data, &s); err != nil || s != "secret text" {
		t.Fatalf("UTF8 decode = %q, %v", s, err)
	}
	if !bytes.Equal(f, make([]byte, len(f))) {
		t.Fatal("UTF8 decode left the plaintext frame in memory")
	}

	var m map[string]string
	f = entrycrypt.Frame([]byte(`{"a":"secret"}`))
	data, _ = entrycrypt.Unframe(f)
	if err := decodeFrame(JSON, f, data, &m); err != nil || m["a"] != "secret" {
		t.Fatalf("JSON decode = %v, %v", m, err)
	}
	if !bytes.Equal(f, make([]byte, len(f))) {
		t.Fatal("JSON decode left the plaintext frame in memory")
	}

	var b []byte
	f = entrycrypt.Frame([]byte("kept"))
	data, _ = entrycrypt.Unframe(f)
	if err := decodeFrame(Bytes, f, data, &b); err != nil || string(b) != "kept" {
		t.Fatalf("Bytes decode = %q, %v", b, err)
	}
}

func TestReadClearsFrame(t *testing.T) {
	var frames [][]byte
	readHook = func(f []byte) { frames = append(frames, f) }
	defer func() { readHook = nil }()

	u, _ := newEncodedLog(t, UTF8)
	if _, err := u.Append("secret text"); err != nil {
		t.Fatal(err)
	}
	var s string
	if err := u.Read(0, &s); err != nil || s != "secret text" {
		t.Fatalf("UTF8 Read = %q, %v", s, err)
	}
	j, _ := newEncodedLog(t, JSON)
	if _, err := j.Append(map[string]string{"a": "secret"}); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := j.Read(0, &m); err != nil || m["a"] != "secret" {
		t.Fatalf("JSON Read = %v, %v", m, err)
	}
	if len(frames) != 2 {
		t.Fatalf("hook saw %d frames, want 2", len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(f, make([]byte, len(f))) {
			t.Errorf("Read %d left the plaintext frame in memory", i)
		}
	}
}
